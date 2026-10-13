from __future__ import annotations

from .models import AttackResult, Severity, TokenUsage

REMEDIATION = {  # nosec B105 - textos de remediación, no credenciales
    "prompt_injection": "Aislar contenido no confiable del system prompt, aplicar delimitadores y un filtro de instrucciones en el API Gateway.",
    "secret_exfiltration": "Rotar las claves expuestas del agente y añadir redacción de secretos en la salida (DLP).",
    "privilege_escalation": "Aplicar allow-list de herramientas MCP por rol y exigir confirmación humana en herramientas destructivas.",
    "malicious_api": "Validar argumentos de herramientas (paths, URLs, SQL) y bloquear rangos IP internos/metadata.",
    "token_dos": "Fijar límites de tokens por sesión y activar el circuit breaker de bucles.",
}


def build_postmortem(target: str, results: list[AttackResult], usage: TokenUsage, max_sev: Severity) -> str:
    exploited = [r for r in results if r.classification.exploited]
    lines = [
        f"# Post-mortem de Red Teaming — {target}",
        "",
        f"- Ataques ejecutados: **{len(results)}**",
        f"- Ataques exitosos: **{len(exploited)}**",
        f"- Gravedad máxima: **{max_sev.value.upper()}**",
        f"- Consumo: {usage.input_tokens} tokens in / {usage.output_tokens} tokens out (≈ ${usage.cost_usd:.4f})",
        "",
    ]
    if not exploited:
        lines.append("No se detectaron compromisos. El objetivo resistió el catálogo ejecutado.")
        return "\n".join(lines)
    lines.append("## Hallazgos")
    for r in exploited:
        c = r.classification
        lines += [
            f"### {r.attack_id} — {r.title} ({c.severity.value.upper()})",
            f"- Intención: `{c.intent}` · fuente: {c.source}",
            f"- Evidencia: {', '.join(c.indicators) or c.rationale}",
            f"- Coste del ataque: ${r.usage.cost_usd:.4f}",
            f"- Snapshot forense: `{r.snapshot.sha256 if r.snapshot else 'n/a'}`",
            f"- Remediación propuesta: {REMEDIATION.get(r.category, 'Revisión manual.')}",
            "",
        ]
    return "\n".join(lines)


def remediation_for(category: str) -> str:
    return REMEDIATION.get(category, "Revisión manual.")
