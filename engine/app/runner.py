from __future__ import annotations

import time
import uuid

import httpx

from .attacks import get_attacks
from .classifier import classify
from .forensics import capture_snapshot, now_iso
from .models import (
    SEVERITY_ORDER,
    Attack,
    AttackResult,
    CampaignReport,
    CampaignRequest,
    Severity,
    TokenUsage,
)
from .postmortem import build_postmortem
from .tokens import add_usage, build_usage, estimate_tokens


async def run_attack(client: httpx.AsyncClient, target: str, attack: Attack, payload: str) -> AttackResult:
    session_id = f"sf-{uuid.uuid4().hex[:12]}"
    t0 = time.monotonic()
    reply, tool_calls, logs, error = "", [], [], None
    in_tok, out_tok = estimate_tokens(payload), 0
    try:
        r = await client.post(f"{target.rstrip('/')}/chat", json={"message": payload, "session_id": session_id})
        r.raise_for_status()
        data = r.json()
        reply = str(data.get("reply", ""))
        tool_calls = data.get("tool_calls", []) or []
        logs = [str(x) for x in data.get("logs", [])]
        tokens = data.get("tokens") or {}
        in_tok = int(tokens.get("input", in_tok))
        out_tok = int(tokens.get("output", estimate_tokens(reply)))
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"
    usage = build_usage(in_tok, out_tok)
    classification = await classify(attack, payload, reply, tool_calls, out_tok)
    duration_ms = int((time.monotonic() - t0) * 1000)

    snapshot = None
    if classification.exploited:
        # Evidencia congelada en el segundo exacto en que se detecta el ataque exitoso.
        snapshot = await capture_snapshot(
            client,
            target,
            session_id,
            prompt_history=[
                {"role": "user", "content": payload},
                {"role": "assistant", "content": reply, "tool_calls": tool_calls},
            ],
            logs=logs,
            metrics={"latency_ms": duration_ms, **usage.model_dump()},
        )
    return AttackResult(
        attack_id=attack.id,
        category=attack.category,
        title=attack.title,
        payload=payload,
        reply=reply,
        tool_calls=tool_calls,
        usage=usage,
        classification=classification,
        snapshot=snapshot,
        error=error,
        duration_ms=duration_ms,
    )


async def run_campaign(req: CampaignRequest) -> CampaignReport:
    attacks = get_attacks(req.attack_ids)
    started = now_iso()
    results: list[AttackResult] = []
    total = TokenUsage()
    budget_exceeded = False
    async with httpx.AsyncClient(timeout=req.timeout_sec) as client:
        for attack in attacks:
            for payload in attack.payloads:
                if total.cost_usd >= req.budget_usd:
                    budget_exceeded = True
                    break
                res = await run_attack(client, req.target_url, attack, payload)
                results.append(res)
                total = add_usage(total, res.usage)
            if budget_exceeded:
                break
    max_sev = Severity.NONE
    for r in results:
        if SEVERITY_ORDER.index(r.classification.severity) > SEVERITY_ORDER.index(max_sev):
            max_sev = r.classification.severity
    return CampaignReport(
        target_url=req.target_url,
        started_at=started,
        finished_at=now_iso(),
        results=results,
        total_usage=total,
        budget_exceeded=budget_exceeded,
        exploited_count=sum(1 for r in results if r.classification.exploited),
        max_severity=max_sev,
        postmortem=build_postmortem(req.target_url, results, total, max_sev),
    )
