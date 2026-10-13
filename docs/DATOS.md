# Datos utilizados — SpecterFlow AI

*Nexus Security & AI Lab · costo $0 · sin datos reales de clientes ni de personas.*

Todo el flujo se ejecuta con **datos sintéticos** generados por el propio repositorio. No hay datasets externos, credenciales reales ni llamadas a APIs de pago.

| Dato | Origen | Dónde está | Notas |
|---|---|---|---|
| Catálogo de ataques (7 ataques, 10 payloads, 5 categorías) | Escrito a mano | `engine/app/attacks.py` | Payloads inofensivos: usan canarios, rutas de prueba y marcadores (`PWNED`). Ampliable con JSON en `ATTACKS_DIR` (`engine/attacks.d/`). |
| Canario `SF-CANARY-sk-test-0000000000000000` | Sintético | `sandbox/vulnerable-agent/main.py` | Falso secreto para detectar exfiltración. No corresponde a ningún sistema real. |
| Agente vulnerable / endurecido | Simulación por reglas (sin LLM) | `sandbox/vulnerable-agent/` | `VULNERABLE=true/false`. Las "herramientas" (`read_file`, `delete_records`, `http_get`, `query_db`) son simuladas: no tocan el sistema. |
| Tráfico del proxy (prompts repetidos, prompts con inyección) | Generado por `scripts/e2e-main-flow.sh` | — | Mensajes de texto de prueba. |
| Claves de API de ejemplo (`secops-key`, `finops-key`, …) | Valores de desarrollo | `.env.example`, `docker-compose.yml` | Solo desarrollo. En producción el control plane **se niega a arrancar** con ellas (`NODE_ENV=production`). |
| Precios por token | Configurables (`PRICE_IN_PER_MTOK`, `PRICE_OUT_PER_MTOK`) | `control-plane/src/common/config.ts`, `engine/app/tokens.py` | Valores orientativos para estimar coste; no provienen de una factura. |
| Estado generado en ejecución | Producido por la propia app | `STATE_FILE`, `AUDIT_FILE`, Postgres | En las pruebas se escribe en directorios temporales y se borra al terminar. |

## Qué NO se usa
- Sin datos reales de clientes o personas, sin correos reales, sin redes sociales.
- Sin servicios de pago: el clasificador con LLM (`ANTHROPIC_API_KEY`) es **opcional** y está **desactivado por defecto**; sin clave se usa el clasificador heurístico (costo $0).
- Sin exposición a Internet: todos los puertos de las pruebas son `localhost` y `docker-compose.yml` mantiene el sandbox en una red interna.

## Autorización de las pruebas ofensivas
Las campañas de Red Teaming solo pueden apuntar a **agentes registrados o a la allow-list del sandbox** (`TARGET_ALLOWLIST`); un objetivo externo se rechaza con HTTP 400 (comprobado en el paso 3 del flujo e2e). Los únicos objetivos usados son los agentes sintéticos de este repositorio, propiedad de Nexus Security & AI Lab. **Cualquier prueba contra un sistema real requiere un archivo de autorización escrita del dueño del sistema**, que no existe todavía (ver *Pendientes para Santiago*).
