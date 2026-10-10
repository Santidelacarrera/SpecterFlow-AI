from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = [Severity.NONE, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Attack(BaseModel):
    id: str
    category: str  # prompt_injection | secret_exfiltration | privilege_escalation | malicious_api | token_dos
    title: str
    payloads: list[str]
    base_severity: Severity
    description: str = ""


class TokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


class Classification(BaseModel):
    severity: Severity
    intent: str
    rationale: str
    exploited: bool
    indicators: list[str] = Field(default_factory=list)
    source: str = "heuristic"  # heuristic | llm


class ForensicSnapshot(BaseModel):
    captured_at: str
    target: str
    session_id: str
    prompt_history: list[dict[str, Any]]
    logs: list[str]
    container_state: dict[str, Any]
    metrics: dict[str, Any]
    sha256: str


class AttackResult(BaseModel):
    attack_id: str
    category: str
    title: str
    payload: str
    reply: str
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    usage: TokenUsage
    classification: Classification
    snapshot: ForensicSnapshot | None = None
    error: str | None = None
    duration_ms: int = 0


class CampaignRequest(BaseModel):
    target_url: str
    attack_ids: list[str] | None = None
    budget_usd: float = 1.0
    timeout_sec: float = 15.0


class CampaignReport(BaseModel):
    target_url: str
    started_at: str
    finished_at: str
    results: list[AttackResult]
    total_usage: TokenUsage
    budget_exceeded: bool = False
    exploited_count: int
    max_severity: Severity
    postmortem: str
