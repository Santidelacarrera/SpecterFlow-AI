from __future__ import annotations

import os

from .models import TokenUsage

# USD por 1M de tokens (configurable). Valores por defecto orientativos.
PRICE_IN = float(os.getenv("PRICE_IN_PER_MTOK", "3.0"))
PRICE_OUT = float(os.getenv("PRICE_OUT_PER_MTOK", "15.0"))


def estimate_tokens(text: str) -> int:
    """Aproximación ~4 caracteres por token; suficiente para FinOps en tiempo real."""
    return max(1, (len(text) + 3) // 4) if text else 0


def cost_usd(input_tokens: int, output_tokens: int) -> float:
    return round(input_tokens * PRICE_IN / 1_000_000 + output_tokens * PRICE_OUT / 1_000_000, 6)


def build_usage(input_tokens: int, output_tokens: int) -> TokenUsage:
    return TokenUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=cost_usd(input_tokens, output_tokens),
    )


def add_usage(a: TokenUsage, b: TokenUsage) -> TokenUsage:
    return build_usage(a.input_tokens + b.input_tokens, a.output_tokens + b.output_tokens)
