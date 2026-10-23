import importlib.util
import pathlib
import socket
import threading
import time

import pytest
import uvicorn
from app.models import CampaignRequest, Severity
from app.runner import run_campaign

SANDBOX = pathlib.Path(__file__).resolve().parents[2] / "sandbox" / "vulnerable-agent" / "main.py"


def _serve(vulnerable: bool, monkeypatch):
    monkeypatch.setenv("VULNERABLE", "true" if vulnerable else "false")
    spec = importlib.util.spec_from_file_location(f"sandbox_{vulnerable}", SANDBOX)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(mod.app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    while not server.started:
        time.sleep(0.05)
    return server, f"http://127.0.0.1:{port}"


@pytest.fixture
def vulnerable(monkeypatch):
    server, url = _serve(True, monkeypatch)
    yield url
    server.should_exit = True


@pytest.fixture
def hardened(monkeypatch):
    server, url = _serve(False, monkeypatch)
    yield url
    server.should_exit = True


async def test_vulnerable_agent_is_exploited(vulnerable):
    report = await run_campaign(CampaignRequest(target_url=vulnerable, budget_usd=5))
    assert report.exploited_count >= 5
    assert report.max_severity == Severity.CRITICAL
    exploited = [r for r in report.results if r.classification.exploited]
    assert all(r.snapshot and len(r.snapshot.sha256) == 64 for r in exploited)
    assert "Post-mortem" in report.postmortem
    assert {"prompt_injection", "secret_exfiltration", "privilege_escalation"} <= {r.category for r in exploited}


async def test_hardened_agent_resists(hardened):
    report = await run_campaign(CampaignRequest(target_url=hardened))
    assert report.exploited_count == 0
    assert report.max_severity == Severity.NONE


async def test_budget_stops_campaign(vulnerable):
    report = await run_campaign(CampaignRequest(target_url=vulnerable, budget_usd=0.0001))
    assert report.budget_exceeded
    assert len(report.results) < 10


async def test_unreachable_target_reports_error():
    report = await run_campaign(CampaignRequest(target_url="http://127.0.0.1:1", attack_ids=["PI-001"], timeout_sec=2))
    assert all(r.error for r in report.results)
    assert report.exploited_count == 0
