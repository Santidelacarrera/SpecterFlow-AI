"""Conectores hacia gateways y gestores de secretos reales.

Cada conector traduce una mitigación aprobada en operaciones idempotentes sobre un sistema concreto:
  - kong:  API Gateway Kong (Admin API): ip-restriction, request-termination, pre-function (regla regex), key-auth.
  - nginx: ficheros incluibles (deny / mapas) + recarga controlada.
  - vault: HashiCorp Vault KV v2 para la rotación de secretos del agente.
En modo dry-run no se ejecuta nada: se devuelve el plan.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

import httpx

from .config import Settings
from .models import ExecuteRequest, StepResult, valid_ip, valid_pattern

ClientFactory = Callable[[], httpx.AsyncClient]


def _digest(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]


# ----------------------------------------------------------------------------- Kong
class KongConnector:
    name = "kong"

    def __init__(self, cfg: Settings, client: ClientFactory):
        self.cfg, self.client = cfg, client

    def _headers(self) -> dict[str, str]:
        return {"Kong-Admin-Token": self.cfg.kong_admin_token} if self.cfg.kong_admin_token else {}

    async def _req(self, c: httpx.AsyncClient, method: str, path: str, **kw) -> httpx.Response:
        r = await c.request(method, f"{self.cfg.kong_admin_url.rstrip('/')}{path}", headers=self._headers(), **kw)
        if r.status_code >= 400 and not (method == "GET" and r.status_code == 404):
            raise RuntimeError(f"kong {method} {path} -> {r.status_code}: {r.text[:200]}")
        return r

    async def _upsert_plugin(self, c: httpx.AsyncClient, name: str, config: dict, service: str | None, instance: str) -> None:
        """PUT /plugins/{id} con id determinista por (plugin, ámbito): idempotente."""
        scope = f"/services/{service}" if service else ""
        existing = (await self._req(c, "GET", f"{scope}/plugins", params={"tags": instance})).json()
        found = [p for p in existing.get("data", []) if p["name"] == name]
        body = {"name": name, "config": config, "tags": [instance, "specterflow"], "enabled": True}
        if found:
            await self._req(c, "PATCH", f"/plugins/{found[0]['id']}", json=body)
        else:
            await self._req(c, "POST", f"{scope}/plugins", json=body)

    async def run(self, req: ExecuteRequest, live: bool) -> list[StepResult]:
        a, svc = req.action, req.agentId
        if a == "BLOCK_IP":
            ip = valid_ip(req.params.get("ip"))
            return await self._block_ip(ip, live)
        if a == "PAUSE_AGENT":
            return await self._plugin_step("request-termination", {"status_code": 423, "message": "agent paused by SpecterFlow containment"}, svc, f"sf-pause-{svc}", live, f"pausar servicio {svc} (423)")
        if a == "PATCH_GATEWAY_RULE":
            pattern = valid_pattern(req.params.get("pattern"))
            lua = (
                "local body = kong.request.get_raw_body() or ''\n"
                f"if ngx.re.find(body, [=[{pattern}]=], 'ijo') then\n"
                "  return kong.response.exit(403, { message = 'blocked by SpecterFlow gateway rule' })\n"
                "end"
            )
            return await self._plugin_step("pre-function", {"access": [lua]}, svc, f"sf-rule-{svc}-{_digest(pattern)}", live, f"regla regex en {svc}: /{pattern}/")
        if a == "ROTATE_KEYS":
            return await self._rotate(svc, live)
        return []

    async def _block_ip(self, ip: str, live: bool) -> list[StepResult]:
        op = f"añadir {ip} a ip-restriction.deny (global)"
        if not live:
            return [StepResult(connector=self.name, op=op, status="planned")]
        async with self.client() as c:
            existing = (await self._req(c, "GET", "/plugins", params={"tags": "sf-blocklist"})).json().get("data", [])
            found = [p for p in existing if p["name"] == "ip-restriction"]
            deny = sorted(set((found[0]["config"].get("deny") or []) if found else []) | {ip})
            body = {"name": "ip-restriction", "config": {"deny": deny}, "tags": ["sf-blocklist", "specterflow"], "enabled": True}
            if found:
                await self._req(c, "PATCH", f"/plugins/{found[0]['id']}", json=body)
            else:
                await self._req(c, "POST", "/plugins", json=body)
        return [StepResult(connector=self.name, op=op, status="applied", detail=f"deny={deny}")]

    async def _plugin_step(self, plugin: str, config: dict, service: str, instance: str, live: bool, op: str) -> list[StepResult]:
        if not live:
            return [StepResult(connector=self.name, op=op, status="planned")]
        async with self.client() as c:
            await self._upsert_plugin(c, plugin, config, service, instance)
        return [StepResult(connector=self.name, op=op, status="applied", detail=f"plugin={plugin} tag={instance}")]

    async def _rotate(self, consumer: str, live: bool) -> list[StepResult]:
        op = f"rotar credencial key-auth del consumer {consumer}"
        if not live:
            return [StepResult(connector=self.name, op=op, status="planned")]
        new_key = secrets.token_urlsafe(32)
        async with self.client() as c:
            old = (await self._req(c, "GET", f"/consumers/{consumer}/key-auth")).json().get("data", [])
            await self._req(c, "POST", f"/consumers/{consumer}/key-auth", json={"key": new_key})
            for cred in old:  # la nueva clave ya existe: se revocan las anteriores
                await self._req(c, "DELETE", f"/consumers/{consumer}/key-auth/{cred['id']}")
        # La clave nueva NO se devuelve: la entrega el conector de secretos (vault) o se recupera del gateway.
        self.last_rotated_key = new_key
        return [StepResult(connector=self.name, op=op, status="applied", detail=f"{len(old)} credencial(es) revocada(s)")]


# ----------------------------------------------------------------------------- NGINX
class NginxConnector:
    """Genera ficheros para `include` en nginx. En tu nginx.conf:

        geo $sf_blocked { default 0; include /etc/sf-gateway/blocked_ips.conf; }
        map $sf_agent $sf_paused { default 0; include /etc/sf-gateway/paused_agents.conf; }
        # reglas: include /etc/sf-gateway/rules.conf dentro de un `map $request_body $sf_rule_hit { ... }`
    """

    name = "nginx"

    def __init__(self, cfg: Settings):
        self.cfg = cfg
        self.dir = Path(cfg.nginx_dir)

    def _read(self, f: str) -> list[str]:
        p = self.dir / f
        return [l for l in p.read_text().splitlines() if l.strip()] if p.exists() else []

    def _write(self, f: str, lines: list[str]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(sorted(set(lines))) + "\n")
        os.replace(tmp, self.dir / f)

    def _reload(self) -> str:
        if not self.cfg.nginx_reload_cmd:
            return "sin NGINX_RELOAD_CMD (recarga manual)"
        r = subprocess.run(self.cfg.nginx_reload_cmd.split(), capture_output=True, text=True, timeout=20)  # noqa: S603
        if r.returncode != 0:
            raise RuntimeError(f"reload failed: {r.stderr[:200]}")
        return "nginx recargado"

    async def run(self, req: ExecuteRequest, live: bool) -> list[StepResult]:
        a = req.action
        if a == "BLOCK_IP":
            ip = valid_ip(req.params.get("ip"))
            file, line, op = "blocked_ips.conf", f"{ip} 1;", f"bloquear {ip}"
        elif a == "PAUSE_AGENT":
            file, line, op = "paused_agents.conf", f'"{req.agentId}" 1;', f"pausar {req.agentId}"
        elif a == "PATCH_GATEWAY_RULE":
            pattern = valid_pattern(req.params.get("pattern"))
            safe = pattern.replace("\\", "\\\\").replace('"', '\\"')
            file, line, op = "rules.conf", f'"~*{safe}" 1;  # {req.agentId}', f"regla /{pattern}/ para {req.agentId}"
        else:
            return [StepResult(connector=self.name, op=a, status="skipped", detail="acción no aplicable a nginx")]
        if not live:
            return [StepResult(connector=self.name, op=op, status="planned", detail=f"{file}: {line}")]
        self._write(file, self._read(file) + [line])
        return [StepResult(connector=self.name, op=op, status="applied", detail=f"{file}; {self._reload()}")]


# ----------------------------------------------------------------------------- Vault
class VaultConnector:
    name = "vault"

    def __init__(self, cfg: Settings, client: ClientFactory, kong: KongConnector | None = None):
        self.cfg, self.client, self.kong = cfg, client, kong

    async def run(self, req: ExecuteRequest, live: bool) -> list[StepResult]:
        if req.action != "ROTATE_KEYS":
            return [StepResult(connector=self.name, op=req.action, status="skipped", detail="solo ROTATE_KEYS")]
        path = f"{self.cfg.vault_mount}/data/{self.cfg.vault_prefix}/{req.agentId}"
        op = f"escribir nueva versión del secreto en {path}"
        if not live:
            return [StepResult(connector=self.name, op=op, status="planned")]
        key = (getattr(self.kong, "last_rotated_key", None) if self.kong else None) or secrets.token_urlsafe(32)
        async with self.client() as c:
            r = await c.post(
                f"{self.cfg.vault_addr.rstrip('/')}/v1/{path}",
                headers={"X-Vault-Token": self.cfg.vault_token},
                json={"data": {"api_key": key, "rotated_by": "specterflow", "approval": req.approvalId}},
            )
            if r.status_code >= 400:
                raise RuntimeError(f"vault write -> {r.status_code}: {r.text[:200]}")
            version = r.json().get("data", {}).get("version")
        return [StepResult(connector=self.name, op=op, status="applied", detail=f"versión {version}")]


def build_connectors(cfg: Settings, client: ClientFactory) -> list:
    out: list = []
    kong = KongConnector(cfg, client) if "kong" in cfg.connectors else None
    if kong:
        out.append(kong)
    if "nginx" in cfg.connectors:
        out.append(NginxConnector(cfg))
    if "vault" in cfg.connectors:
        out.append(VaultConnector(cfg, client, kong))
    return out
