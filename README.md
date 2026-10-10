# SpecterFlow AI

**Plataforma de Red Teaming Autónomo, Orquestación de Incidencias y Gobernanza Financiera de Agentes**

```
                  +---------------------------------------+
                  |         Módulo de Red Teaming         |
                  |   (Simulación de Ataques y Prompts)   |
                  +-------------------+-------------------+
                                      |
                                      v
                  +-------------------+-------------------+
                  |        SpecterFlow Agent Engine       |
                  |  (Evaluación de Intención y Tokens)   |
                  +-------------------+-------------------+
                                      |
                                      v
                  +-------------------+-------------------+
                  |         Módulo SOAR & FinOps          |
                  |   Respuesta a Incidentes + Circuit    |
                  |              Breaker                  |
                  +-------------------+-------------------+
                                      |
                                      v
                  +-------------------+-------------------+
                  |     Bandeja de Aprobación Unificada   |
                  |       (SecOps + FinOps Lead)          |
                  +---------------------------------------+
```

## Resumen

SpecterFlow AI simula ataques contra ecosistemas de Agentes de IA y microservicios (inyección de prompts, exfiltración de credenciales, invocación no autorizada de herramientas MCP, peticiones maliciosas a APIs, Token DoS), mide el gasto de tokens que provoca cada ataque, congela la evidencia forense en el momento de la brecha y contiene el incidente con un flujo de aprobación explícita.

**Problema:** los agentes autónomos abren un vector nuevo (Prompt Injection, tool-calling no autorizado) y un bucle infinito puede exfiltrar datos y agotar miles de dólares en créditos en minutos.
**Propuesta:** unir simulación ofensiva, contención defensiva y control de gasto.

## Qué hay implementado

| Módulo | Dónde | Estado |
|---|---|---|
| Red Teaming: catálogo de 7 ataques / 10 payloads en 5 categorías | `engine/app/attacks.py` | ✅ |
| Clasificación semántica de gravedad (heurística + LLM restringido opcional) | `engine/app/classifier.py` | ✅ |
| SOAR forense: snapshot (prompts, logs, estado del contenedor, métricas, SHA-256) y post-mortem | `engine/app/forensics.py`, `postmortem.py` | ✅ |
| Circuit breaker: presupuesto, bucles (prompt repetido), tasa de fallos; estados CLOSED/OPEN/HALF_OPEN | `control-plane/src/breaker` | ✅ |
| Proxy de tráfico con coste por petición, reglas de gateway y bloqueo de IP | `control-plane/src/proxy` | ✅ |
| Bandeja de aprobación con firma por rol (SecOps/FinOps) y aplicación de la mitigación | `control-plane/src/approvals` | ✅ |
| Auditoría inmutable (cadena de hashes SHA-256, endpoint de verificación) | `control-plane/src/audit` | ✅ |
| Cola de trabajos BullMQ + Redis y worker separado | `control-plane/src/campaigns`, `worker.ts` | ✅ |
| Frontend React + TS: resumen con diagrama de flujo, campañas, incidentes/evidencia, aprobaciones, auditoría | `frontend/` | ✅ |
| Sandbox con agente vulnerable / endurecido | `sandbox/vulnerable-agent` | ✅ |
| Executor de mitigaciones (Kong / NGINX / Vault) | `executor/` | ✅ (probado con dobles) |
| Estado en Postgres, multi-réplica | `control-plane/src/common/persistence.service.ts` | ✅ |

### Producción y operación

| Capacidad | Detalle |
|---|---|
| Persistencia / HA | Con `DATABASE_URL` (Postgres) el estado se guarda por entidades y **varias réplicas del control plane comparten estado**: sincronización por secuencia global, firmas de aprobación serializadas con advisory locks (no se pierden firmas concurrentes), una única cadena de auditoría compartida y estado del breaker (abierto/cerrado) propagado. Sin Postgres: `STATE_FILE` (una sola instancia) o memoria. Las ventanas de coste/bucle del breaker son locales a cada réplica → enruta por agente de forma *sticky* si escalas el proxy. |
| Executor de mitigaciones | Servicio `executor/` que recibe las mitigaciones aprobadas y las aplica en sistemas reales mediante conectores: **Kong** (ip-restriction, request-termination, pre-function con la regla regex, rotación key-auth), **NGINX** (ficheros `include` + recarga) y **Vault KV v2** (secreto rotado). Dry-run por defecto, idempotente por `approvalId`, validación estricta de parámetros, reintentos y estado visible en la bandeja (con reintento manual). |
| Arranque seguro | Con `NODE_ENV=production` el control plane rechaza claves de ejemplo, claves < 24 caracteres y `INTERNAL_TOKEN` por defecto. Usa `docker-compose.prod.yml`. |
| Hardening HTTP | Cabeceras de seguridad, rate limit por clave (`RATE_LIMIT_PER_MIN`), límite de body (`BODY_LIMIT`), CORS cerrado por defecto (`CORS_ORIGIN`). |
| Métricas | `GET /metrics` (Prometheus; `Authorization: Bearer $METRICS_TOKEN`): peticiones, tokens, coste, trips del breaker, incidentes, mitigaciones, aprobaciones pendientes. |
| Alertas | `ALERT_WEBHOOK_URL` (formato Slack/Mattermost/Teams) en breaker abierto, incidente y aprobación pendiente. |
| Mitigación real | `MITIGATION_WEBHOOK_URL` (→ `executor`, ver abajo) recibe cada mitigación aprobada con sus firmas. Sin él, solo se aplica dentro del proxy de SpecterFlow. |
| Tiempo real | `GET /api/events` (SSE) alimenta la UI. |
| Tráfico real | `LIVE_CLASSIFY=true` clasifica en vivo (vía engine) las respuestas del proxy y abre incidentes ante secretos o herramientas privilegiadas. |
| Bucles | Detección por prompt idéntico y por prompts casi idénticos (similitud Jaccard, `LOOP_SIMILARITY`). |
| Ataques propios | JSON en `ATTACKS_DIR` (ver `engine/attacks.d/example.json.disabled`). |
| Contenedores | Usuarios no root, healthchecks, `cap_drop: ALL`, `no-new-privileges`, límites de memoria/PIDs y FS de solo lectura en el sandbox. |
| CI | `.github/workflows/ci.yml`: tests (con Postgres real), typecheck, build, integración con Redis + worker + executor (`scripts/integration.sh`), integración HA con 2 réplicas (`scripts/integration-ha.sh`) y build de imágenes. |

### Executor de mitigaciones (gateway real)

```bash
# 1) Variables (.env): INTERNAL_TOKEN, EXECUTOR_CONNECTORS=kong,vault (o nginx), KONG_ADMIN_URL, VAULT_ADDR/VAULT_TOKEN...
# 2) Arranca con el perfil y apunta el control plane al executor
MITIGATION_WEBHOOK_URL=http://mitigation-executor:8200/v1/execute docker compose --profile gateway up
# 3) EXECUTOR_MODE=dry-run (por defecto) solo muestra el plan; pasa a live cuando lo hayas revisado
```

Cada acción se traduce así: `BLOCK_IP` → `ip-restriction.deny` global (Kong) / `blocked_ips.conf` (NGINX); `PAUSE_AGENT` → `request-termination` 423 / `paused_agents.conf`; `PATCH_GATEWAY_RULE` → plugin `pre-function` con la regex / `rules.conf`; `ROTATE_KEYS` → nueva credencial key-auth, revocación de las antiguas y escritura de la nueva en Vault (la clave nunca viaja al control plane). Los snippets de `include` para nginx están documentados en `executor/app/connectors.py`.

> Los conectores están probados contra dobles de la Admin API de Kong y de Vault y contra ficheros reales de nginx; no he podido probarlos contra una instancia real de Kong/Vault. Pruébalos en dry-run y en un entorno de staging antes de activarlos.

## Arranque rápido

```bash
cp .env.example .env
docker compose up --build
# UI y API:  http://localhost:8080   (API keys de ejemplo: secops-key, finops-key, admin-key, viewer-key)
# Alta disponibilidad:  docker compose up --build --scale control-plane=2
```

1. Entra con `secops-key`, registra el agente `demo` → `http://vulnerable-agent:9000`.
2. En **Red Teaming**, lanza una campaña: el agente vulnerable es explotado y se crean incidentes con evidencia y propuestas de remediación.
3. Envía tráfico por el proxy (`POST /proxy/demo/chat`, cabecera `x-api-key`). Repite el mismo prompt ≥ 5 veces (o supera el presupuesto) y el breaker se abre (`503` + `Retry-After`).
4. En **Aprobaciones**, firma con `secops-key` y `finops-key`; solo entonces se aplica la mitigación permanente (pausa del agente, regla de gateway, bloqueo de IP, rotación de claves).

## Arquitectura

* **Frontend** — React + TypeScript (Vite).
* **Control Plane** — Node.js (NestJS): API, autenticación por API key con roles, proxy, circuit breaker, incidentes, aprobaciones, auditoría.
* **Engine** — Python (FastAPI): catálogo ofensivo, ejecución de campañas, clasificación, forense, post-mortem. `POST /v1/classify` evalúa intención y tokens de tráfico real.
* **Workers** — BullMQ + Redis. Sin `REDIS_URL` las campañas se ejecutan en el propio proceso (desarrollo/tests).
* **Simulación** — Docker Compose con red `internal` aislada; los objetivos de campaña deben ser agentes registrados o estar en `TARGET_ALLOWLIST`.

### API principal (`x-api-key`)

| Método | Ruta | Rol |
|---|---|---|
| `POST/GET` | `/api/agents` | SECOPS, FINOPS / todos |
| `ANY` | `/proxy/:agentId/*` | cualquier clave válida |
| `POST/GET` | `/api/campaigns` | SECOPS / todos |
| `GET` | `/api/incidents` | todos |
| `GET` | `/api/approvals`, `POST …/:id/approve\|reject` | todos / SECOPS, FINOPS (ADMIN firma el rol pendiente) |
| `GET` | `/api/audit`, `/api/audit/verify` | todos |

### Reglas del circuit breaker

| Condición | Variable | Por defecto |
|---|---|---|
| Gasto en ventana > presupuesto | `BUDGET_USD`, `BUDGET_WINDOW_SEC` | $5 / 60 s |
| Mismo prompt repetido N veces (bucle) | `LOOP_REPEAT_THRESHOLD` | 5 |
| Tasa de fallos ≥ umbral (mín. 10 peticiones) | `FAILURE_RATE_THRESHOLD` | 0.5 |
| Cooldown antes de half-open | `BREAKER_COOLDOWN_SEC` | 60 s |

La interrupción es **temporal y automática**; la mitigación **permanente** requiere firmas: pausa por presupuesto/bucle → SECOPS + FINOPS; el resto → SECOPS.

## Tests

```bash
cd engine && pip install -r requirements.txt && pytest          # engine + sandbox end-to-end
cd control-plane && npm ci && npm test                          # breaker, auditoría, proxy, aprobaciones, campañas
cd frontend && npm ci && npm run build                          # typecheck + build
cd executor && pip install -r requirements.txt && pytest        # conectores (Kong/Vault/NGINX)
PYBIN=python3 scripts/integration.sh                            # Redis + worker + executor (requiere redis-server)
DATABASE_URL=postgres://... scripts/integration-ha.sh           # 2 réplicas + Postgres
TEST_DATABASE_URL=postgres://... npm test                       # incluye los tests HA contra Postgres
```

## Uso responsable

Los payloads son canarios inofensivos y las herramientas del agente de prueba son simuladas. Ejecuta campañas **solo contra sistemas propios o con autorización expresa**. Las API keys de ejemplo son para desarrollo: cámbialas antes de exponer el servicio. El estado vive en Postgres (o en un JSON/memoria en modo de una sola instancia). La identidad sigue siendo por API key; para producción conviene SSO/OIDC.
