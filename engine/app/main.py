from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .attacks import CATALOG
from .classifier import classify_heuristic
from .models import Attack, CampaignReport, CampaignRequest, Classification
from .runner import run_campaign
from .tokens import build_usage, estimate_tokens

app = FastAPI(title="SpecterFlow Agent Engine", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "engine"}


@app.get("/v1/attacks", response_model=list[Attack])
def list_attacks() -> list[Attack]:
    return CATALOG


@app.post("/v1/campaigns/run", response_model=CampaignReport)
async def campaign(req: CampaignRequest) -> CampaignReport:
    try:
        return await run_campaign(req)
    except KeyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


class TrafficSample(BaseModel):
    prompt: str
    reply: str = ""
    tool_calls: list[dict] = []


class TrafficVerdict(BaseModel):
    classification: Classification
    input_tokens: int
    output_tokens: int
    cost_usd: float


@app.post("/v1/classify", response_model=TrafficVerdict)
def classify_traffic(sample: TrafficSample) -> TrafficVerdict:
    """Evaluación de intención + tokens sobre tráfico real del proxy (análisis síncrono, heurístico)."""
    probe = Attack(id="LIVE", category="live_traffic", title="Live traffic", payloads=[], base_severity="low")
    out = estimate_tokens(sample.reply)
    cls = classify_heuristic(probe, sample.reply, sample.tool_calls, out)
    u = build_usage(estimate_tokens(sample.prompt), out)
    return TrafficVerdict(classification=cls, input_tokens=u.input_tokens, output_tokens=u.output_tokens, cost_usd=u.cost_usd)
