from __future__ import annotations

import hmac
import json
import logging
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException

from .config import Settings, get_settings
from .connectors import build_connectors
from .models import ExecuteRequest, ExecuteResponse, StepResult

log = logging.getLogger("executor")
app = FastAPI(title="SpecterFlow Mitigation Executor", version="0.1.0")


def http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=10)


app.state.client_factory = http_client


def _auth(x_internal_token: str = Header(default=""), cfg: Settings = Depends(get_settings)) -> Settings:
    if not cfg.token:
        raise HTTPException(503, "EXECUTOR_TOKEN no configurado")
    if not hmac.compare_digest(x_internal_token, cfg.token):
        raise HTTPException(401, "token inválido")
    return cfg


def _done_file(cfg: Settings, approval_id: str) -> Path:
    safe = "".join(ch for ch in approval_id if ch.isalnum() or ch in "-_")
    return Path(cfg.state_dir) / f"{safe}.json"


@app.get("/health")
def health(cfg: Settings = Depends(get_settings)) -> dict:
    return {"status": "ok", "mode": "live" if cfg.live else "dry-run", "connectors": cfg.connectors}


@app.post("/v1/execute", response_model=ExecuteResponse)
async def execute(req: ExecuteRequest, cfg: Settings = Depends(_auth)) -> ExecuteResponse:
    """Ejecuta una mitigación ya aprobada por humanos. Idempotente por approvalId."""
    if req.action != "PAUSE_AGENT" and req.action != "ROTATE_KEYS" and not req.signatures:
        raise HTTPException(422, "se requieren firmas de aprobación")
    mode = "live" if cfg.live else "dry-run"
    done = _done_file(cfg, req.approvalId)
    if cfg.live and done.exists():
        return ExecuteResponse(**json.loads(done.read_text()))

    steps: list[StepResult] = []
    connectors = build_connectors(cfg, app.state.client_factory)
    if not connectors:
        steps.append(StepResult(connector="-", op=req.action, status="skipped", detail="sin conectores configurados (CONNECTORS)"))
    for c in connectors:
        try:
            steps += await c.run(req, cfg.live)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - un conector caído no oculta el resultado de los demás
            log.exception("connector %s failed", c.name)
            steps.append(StepResult(connector=c.name, op=req.action, status="failed", detail=str(exc)[:300]))
    resp = ExecuteResponse(approvalId=req.approvalId, mode=mode, ok=all(s.status != "failed" for s in steps), steps=steps)
    if cfg.live and resp.ok:
        done.parent.mkdir(parents=True, exist_ok=True)
        done.write_text(resp.model_dump_json())
    if not resp.ok:
        raise HTTPException(502, resp.model_dump())
    return resp
