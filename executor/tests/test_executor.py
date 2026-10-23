import json
import re

import httpx
import pytest
from app.config import Settings, get_settings
from app.main import app
from fastapi.testclient import TestClient


class FakeKong:
    """Kong Admin API mínimo en memoria + Vault KV v2."""

    def __init__(self):
        self.plugins: dict[str, dict] = {}
        self.creds: dict[str, dict[str, dict]] = {"agent1": {"old1": {"id": "old1", "key": "OLD"}}}
        self.vault: dict[str, dict] = {}
        self.n = 0
        self.calls: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.calls.append(f"{method} {path}")
        body = json.loads(request.content) if request.content else {}
        if path.startswith("/v1/"):  # vault
            self.vault[path] = body["data"]
            return httpx.Response(200, json={"data": {"version": len([k for k in self.vault])}})
        m = re.match(r"^(?:/services/[^/]+)?/plugins$", path)
        if m and method == "GET":
            tag = request.url.params.get("tags")
            return httpx.Response(200, json={"data": [p for p in self.plugins.values() if tag in p["tags"]]})
        if m and method == "POST":
            self.n += 1
            self.plugins[f"p{self.n}"] = {**body, "id": f"p{self.n}", "scope": path}
            return httpx.Response(201, json=self.plugins[f"p{self.n}"])
        m = re.match(r"^/plugins/(\w+)$", path)
        if m and method == "PATCH":
            self.plugins[m.group(1)].update(body)
            return httpx.Response(200, json=self.plugins[m.group(1)])
        m = re.match(r"^/consumers/(\w+)/key-auth$", path)
        if m and method == "GET":
            return httpx.Response(200, json={"data": list(self.creds.get(m.group(1), {}).values())})
        if m and method == "POST":
            self.n += 1
            self.creds.setdefault(m.group(1), {})[f"k{self.n}"] = {"id": f"k{self.n}", "key": body["key"]}
            return httpx.Response(201, json={})
        m = re.match(r"^/consumers/(\w+)/key-auth/(\w+)$", path)
        if m and method == "DELETE":
            self.creds[m.group(1)].pop(m.group(2))
            return httpx.Response(204)
        return httpx.Response(404, json={"message": "not found"})


@pytest.fixture
def env(tmp_path):
    kong = FakeKong()
    settings = Settings(token="tok-12345678", live=True, connectors=["kong", "nginx", "vault"], state_dir=str(tmp_path / "state"), nginx_dir=str(tmp_path / "ng"), nginx_reload_cmd="true", vault_token="vt")
    app.dependency_overrides[get_settings] = lambda: settings
    app.state.client_factory = lambda: httpx.AsyncClient(transport=httpx.MockTransport(kong.handler))
    yield TestClient(app), kong, settings
    app.dependency_overrides.clear()


H = {"x-internal-token": "tok-12345678"}


def body(action, **params):
    return {"approvalId": "appr-0001-xyz", "action": action, "agentId": "agent1", "params": params, "signatures": [{"role": "SECOPS"}]}


def test_requires_token(env):
    c, *_ = env
    assert c.post("/v1/execute", json=body("PAUSE_AGENT")).status_code == 401
    assert c.post("/v1/execute", json=body("PAUSE_AGENT"), headers={"x-internal-token": "bad"}).status_code == 401


def test_dry_run_changes_nothing(env, tmp_path):
    c, kong, settings = env
    settings.live = False
    r = c.post("/v1/execute", json=body("BLOCK_IP", ip="6.6.6.6"), headers=H).json()
    assert r["mode"] == "dry-run" and all(s["status"] in ("planned", "skipped") for s in r["steps"])
    assert kong.calls == [] and not (tmp_path / "ng").exists()


def test_block_ip_merges_deny_list_in_kong_and_nginx(env, tmp_path):
    c, kong, _ = env
    c.post("/v1/execute", json={**body("BLOCK_IP", ip="6.6.6.6"), "approvalId": "appr-aaaa-0001"}, headers=H).raise_for_status()
    c.post("/v1/execute", json={**body("BLOCK_IP", ip="7.7.7.7"), "approvalId": "appr-aaaa-0002"}, headers=H).raise_for_status()
    ip_plugins = [p for p in kong.plugins.values() if p["name"] == "ip-restriction"]
    assert len(ip_plugins) == 1 and ip_plugins[0]["config"]["deny"] == ["6.6.6.6", "7.7.7.7"]
    assert (tmp_path / "ng" / "blocked_ips.conf").read_text().split("\n")[:2] == ["6.6.6.6 1;", "7.7.7.7 1;"]


def test_pause_and_rule(env, tmp_path):
    c, kong, _ = env
    c.post("/v1/execute", json={**body("PAUSE_AGENT"), "approvalId": "appr-bbbb-0001"}, headers=H).raise_for_status()
    assert any(p["name"] == "request-termination" and p["config"]["status_code"] == 423 for p in kong.plugins.values())
    assert '"agent1" 1;' in (tmp_path / "ng" / "paused_agents.conf").read_text()
    c.post("/v1/execute", json={**body("PATCH_GATEWAY_RULE", pattern="(system prompt|secret)"), "approvalId": "appr-bbbb-0002"}, headers=H).raise_for_status()
    pf = [p for p in kong.plugins.values() if p["name"] == "pre-function"][0]
    assert "(system prompt|secret)" in pf["config"]["access"][0] and "kong.response.exit(403" in pf["config"]["access"][0]


def test_rotate_keys_revokes_old_and_stores_new_in_vault_without_leaking(env):
    c, kong, _ = env
    r = c.post("/v1/execute", json=body("ROTATE_KEYS"), headers=H)
    r.raise_for_status()
    keys = kong.creds["agent1"]
    assert "old1" not in keys and len(keys) == 1
    new_key = next(iter(keys.values()))["key"]
    assert new_key != "OLD"
    vault_val = next(iter(kong.vault.values()))
    assert vault_val["api_key"] == new_key  # misma clave en gateway y vault
    assert new_key not in r.text  # nunca se devuelve al control plane


def test_idempotent_by_approval_id(env):
    c, kong, _ = env
    b = body("PAUSE_AGENT")
    c.post("/v1/execute", json=b, headers=H).raise_for_status()
    n = len(kong.calls)
    again = c.post("/v1/execute", json=b, headers=H).json()
    assert again["ok"] and len(kong.calls) == n


@pytest.mark.parametrize(
    "payload",
    [body("BLOCK_IP", ip="not-an-ip"), body("BLOCK_IP", ip="1.1.1.1; rm -rf /"), body("PATCH_GATEWAY_RULE", pattern="(unclosed"), body("PATCH_GATEWAY_RULE", pattern="x]=] os.execute('id') --[=[")],
)
def test_rejects_malicious_params(env, payload):
    c, kong, _ = env
    assert c.post("/v1/execute", json=payload, headers=H).status_code == 422
    assert not kong.plugins


def test_rejects_bad_agent_id_and_missing_signatures(env):
    c, *_ = env
    assert c.post("/v1/execute", json={**body("PAUSE_AGENT"), "agentId": "../etc"}, headers=H).status_code == 422
    assert c.post("/v1/execute", json={**body("BLOCK_IP", ip="1.1.1.1"), "signatures": []}, headers=H).status_code == 422


def test_connector_failure_is_reported_not_marked_done(env, tmp_path):
    c, kong, settings = env
    app.state.client_factory = lambda: httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500, text="boom")))
    r = c.post("/v1/execute", json=body("BLOCK_IP", ip="2.2.2.2"), headers=H)
    assert r.status_code == 502
    assert not (tmp_path / "state").exists()  # no se marca como hecha: se puede reintentar
