# Evidencia del flujo principal — SpecterFlow AI (Nexus Security & AI Lab)

Ejecución: 2026-10-13T16:22:01Z · datos 100 % sintéticos (ver docs/DATOS.md)

- ✅ **Paso 1** — RBAC: sin clave → 401; rol VIEWER lanzando campaña → 403
- ✅ **Paso 2** — Agentes registrados: vulnerable (9300) y hardened (9301)
- ✅ **Paso 3** — Campaña contra objetivo externo (example.com) rechazada: solo agentes registrados o TARGET_ALLOWLIST
- ✅ **Paso 4** — Campaña vs agente endurecido: 0 ataques exitosos (el catálogo completo fue rechazado)
- ✅ **Paso 5** — Campaña vs agente vulnerable: 11 ataques exitosos, gravedad máxima critical, 11 incidentes, 11 con snapshot forense SHA-256
- ✅ **Paso 6** — Post-mortem generado con hallazgos y remediación propuesta
- ✅ **Paso 7** — Proxy: coste/tokens por petición informados y tráfico real malicioso detectado en vivo (incidente 'live')
- ✅ **Paso 8** — Regla de gateway aprobada por SECOPS → el proxy responde 403 al mismo prompt
- ✅ **Paso 9** — Circuit breaker: 4 prompts idénticos → breaker ABIERTO → siguiente petición 503 (interrupción temporal automática)
- ✅ **Paso 10** — Pausa permanente: una firma SECOPS → sigue pendiente; la misma clave firmando otra vez → 409
- ✅ **Paso 11** — Con la firma FINOPS la mitigación se aplica: agente pausado → 423 incluso tras resetear el breaker
- ✅ **Paso 12** — Auditoría con cadena de hashes íntegra (40 entradas) y métricas Prometheus con el trip del breaker
- ✅ **Paso 13** — Estado y auditoría persistidos en disco (STATE_FILE / AUDIT_FILE)

Resultado: **13 pasos verificados, 0 fallos.**
