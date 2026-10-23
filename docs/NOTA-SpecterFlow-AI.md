# Nota de proyecto — SpecterFlow AI

*Nexus Security & AI Lab · rama `feat/specterflow-ai-autonomo-2026-10-12` · base `main`*

## Tareas (rama autónoma)
| # | Tarea | Estado | Evidencia |
|---|---|---|---|
| T1 | Terminar el flujo principal con pruebas | ✅ | `scripts/e2e-main-flow.sh` (13 pasos) → `docs/evidence/main-flow-run.md`; tests unitarios/integración en `docs/evidence/verification.md` |
| T2 | Documentar la ejecución y los datos usados | ✅ | `README.md` (instalación, pruebas, uso), `docs/DATOS.md`, `docs/evidence/` |

## Definición de terminado
| # | Condición | Estado | Evidencia (comando → resultado) |
|---|---|---|---|
| 1 | Tareas cumplidas con evidencia | ✅ | `scripts/e2e-main-flow.sh` → `OK: flujo principal completo (13 pasos)` |
| 2 | Pruebas automatizadas pasando | ✅ | engine `pytest -q` → 12 passed · executor `pytest -q` → 12 passed · control plane `npx jest` → 24 passed (con Postgres real) · integración Redis+worker+executor OK · HA 2 réplicas+Postgres OK |
| 3 | Seguridad y lint sin errores altos | ✅ | `ruff check` → All checks passed · `bandit -r … -ll` → sin hallazgos · `pip-audit` → No known vulnerabilities · `npm audit --omit=dev` (control plane) → 0 · `npm audit --audit-level=high` → exit 0 (quedan 20 *moderate* solo en herramientas de desarrollo) · frontend `npm audit` → 0 |
| 4 | README reproducible | ✅ | `README.md` (secciones *Arranque rápido*, *Tests*, *Verificación completa*) |
| 5 | Bitácora de decisiones | ✅ | sección siguiente |
| 6 | Pendientes para Santiago | ✅ | al final de este documento |

Reproducir todo con un comando: `PYBIN=python3 TEST_DATABASE_URL=postgres://… scripts/verify-all.sh` (escribe `docs/evidence/verification.md`).

## Bitácora de decisiones
| Fecha | Decisión | Motivo |
|---|---|---|
| 2026-10-13 | Rama de trabajo `feat/specterflow-ai-autonomo-2026-10-12` desde `origin/main`; nombre fijado por la instrucción aunque la fecha real sea 13-oct | Respetar la convención indicada por Santiago. |
| 2026-10-13 | Subir `@nestjs/*` a 11.2.7 (Express 5) y `jest` a 30 | `npm audit` marcaba 31 vulnerabilidades altas (multer, body-parser, braces…). Resultado: 0 en dependencias de producción y ninguna alta en desarrollo. La ruta comodín del proxy pasó a `:agentId/*path` (sintaxis Express 5). |
| 2026-10-13 | Subir FastAPI 0.143 / Starlette y fijar versiones | `pip-audit` reportaba CVEs de Starlette 0.41. |
| 2026-10-13 | SHA-1 → SHA-256 en el executor; `# nosec` justificado solo en `subprocess` (comando del operador, sin shell) y en canarios sintéticos | Bandit marcaba B324 (alto). Los otros avisos son falsos positivos documentados en el código. |
| 2026-10-13 | `ruff.toml` con reglas E,F,I,B,UP (ignora B008 de FastAPI) y `Severity` como `StrEnum` | Lint reproducible con criterios razonables. |
| 2026-10-13 | Nuevo `scripts/e2e-main-flow.sh` (RBAC, objetivo externo rechazado, vulnerable vs endurecido, post-mortem, proxy, regla de gateway, breaker, doble firma, pausa, auditoría, persistencia) | El flujo principal solo estaba cubierto por partes; ahora hay una prueba única y un informe de evidencia reproducible. |
| 2026-10-13 | `scripts/verify-all.sh` + `requirements-dev.txt` | Un solo comando deja constancia de pruebas, lint y seguridad (condiciones 2 y 3). |
| 2026-10-13 | Corregida una condición de carrera real en alta disponibilidad: la campaña se persiste (`await flush()`) antes de encolar el job y los estados finales (`done`/`failed`) no retroceden al sincronizar | `scripts/integration-ha.sh` falló una vez con `campaña status=queued`: el worker terminaba antes de la escritura diferida y otra réplica pisaba `done` con `queued`. Test de regresión en `control-plane/test/postgres.spec.ts`; 6/6 ejecuciones seguidas del script en verde. |
| 2026-10-13 | Los scripts de integración usan `curl -m 15` y el HA cierra conexiones residuales con `lock_timeout` | Una ejecución se colgó >120 s (causa probable: conexión residual de una ejecución anterior bloqueando el `DROP TABLE`); ahora fallan rápido y con log en vez de colgarse. |
| 2026-10-13 | Clasificador LLM opcional y apagado por defecto | Regla de costo $0: sin API key se usa el clasificador heurístico. |
| 2026-10-13 | No se escribió un archivo de autorización ofensiva | Solo el dueño del sistema puede firmarlo; las pruebas usan únicamente agentes sintéticos propios del repo. Se anota como pendiente. |

## Pendientes para Santiago
1. **Aprobar el PR** (no se hizo merge ni se cambió ningún estado de aprobación).
2. **Autorización escrita** si se quiere ejecutar Red Teaming contra sistemas reales (propios o de clientes); hoy solo se atacan agentes sintéticos del sandbox.
3. **Conectores reales de Kong y Vault**: probados contra dobles de sus APIs; falta una prueba en staging propio (dry-run primero).
4. **SSO/OIDC**: la identidad sigue siendo por API key (firmas de aprobación por clave, no por persona).
5. **Clasificador con LLM**: implementado pero no probado con una API key real (costo > $0, por eso no se activó).
6. **Dependencias de desarrollo**: quedan 20 avisos *moderate* de `npm audit` en la cadena de herramientas de pruebas (no se publican en producción); se resuelven al actualizar `istanbul`/`sprintf-js` upstream.
7. **Despliegue**: `docker compose up` no se pudo ejecutar en el entorno de desarrollo (sin demonio Docker), aunque el CI de GitHub sí construye las imágenes.

## Riesgos conocidos
- Ventanas de coste/bucle del circuit breaker locales a cada réplica (usar enrutado sticky por agente al escalar).
- El estado en Postgres está pensado para una carga moderada (sincronización por sondeo cada 1,5 s).
- Los payloads del catálogo son un conjunto fijo y pequeño; no sustituyen una auditoría completa.

## Texto del PR
Ver la descripción del Pull Request (se mantiene en sincronía con esta nota).
