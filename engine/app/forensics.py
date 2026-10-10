from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from .models import ForensicSnapshot


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def fetch_container_state(client: httpx.AsyncClient, target_url: str) -> dict[str, Any]:
    """Estado del contenedor/agente expuesto por el endpoint opcional /_state."""
    try:
        r = await client.get(f"{target_url.rstrip('/')}/_state")
        if r.status_code == 200:
            return r.json()
    except Exception as exc:  # noqa: BLE001
        return {"unavailable": True, "error": str(exc)}
    return {"unavailable": True}


async def capture_snapshot(
    client: httpx.AsyncClient,
    target_url: str,
    session_id: str,
    prompt_history: list[dict[str, Any]],
    logs: list[str],
    metrics: dict[str, Any],
) -> ForensicSnapshot:
    state = await fetch_container_state(client, target_url)
    body = {
        "captured_at": now_iso(),
        "target": target_url,
        "session_id": session_id,
        "prompt_history": prompt_history,
        "logs": logs,
        "container_state": state,
        "metrics": metrics,
    }
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
    return ForensicSnapshot(**body, sha256=digest)
