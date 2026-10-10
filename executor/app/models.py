from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

AGENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,40}$")
Action = Literal["PAUSE_AGENT", "BLOCK_IP", "ROTATE_KEYS", "PATCH_GATEWAY_RULE"]


class ExecuteRequest(BaseModel):
    approvalId: str = Field(min_length=8, max_length=64)
    action: Action
    agentId: str
    params: dict[str, Any] = {}
    signatures: list[dict[str, Any]] = []

    @field_validator("agentId")
    @classmethod
    def _agent(cls, v: str) -> str:
        if not AGENT_RE.match(v):
            raise ValueError("invalid agentId")
        return v


def valid_ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value).replace("::ffff:", "")))
    except ValueError as exc:
        raise ValueError(f"invalid ip: {value!r}") from exc


def valid_pattern(value: Any) -> str:
    p = str(value)
    if not p or len(p) > 500:
        raise ValueError("pattern must be 1..500 chars")
    try:
        re.compile(p)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc
    if "]=]" in p or "\x00" in p:
        raise ValueError("pattern contains forbidden sequence")
    return p


class StepResult(BaseModel):
    connector: str
    op: str
    status: Literal["planned", "applied", "skipped", "failed"]
    detail: str = ""


class ExecuteResponse(BaseModel):
    approvalId: str
    mode: Literal["dry-run", "live"]
    ok: bool
    steps: list[StepResult]
