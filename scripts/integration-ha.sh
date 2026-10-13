#!/usr/bin/env bash
# Alta disponibilidad: dos réplicas del control plane sobre Postgres + Redis, un worker.
# Requiere DATABASE_URL (Postgres accesible), redis-server, PYBIN y control-plane con npm ci.
set -euo pipefail
: "${DATABASE_URL:?define DATABASE_URL}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYBIN="${PYBIN:-python3}"
TMP="$(mktemp -d)"
PIDS=()
cleanup() { rc=$?; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$TMP" 2>/dev/null || true; exit "$rc"; }
trap cleanup EXIT
# BD de pruebas: cierra conexiones residuales de ejecuciones anteriores y recrea el esquema (con timeout para no colgarse)
PGOPTIONS="-c lock_timeout=20s" psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 \
  -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()" >/dev/null
PGOPTIONS="-c lock_timeout=20s" psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 \
  -c "DROP TABLE IF EXISTS sf_entities, sf_audit; DROP SEQUENCE IF EXISTS sf_entity_seq" >/dev/null 2>&1

redis-server --port 6391 --save "" --appendonly no >"$TMP/redis.log" 2>&1 & PIDS+=($!)
(cd "$ROOT/sandbox/vulnerable-agent" && exec env VULNERABLE=true $PYBIN -m uvicorn main:app --port 9101 >"$TMP/sbx.log" 2>&1) & PIDS+=($!)
(cd "$ROOT/engine" && exec $PYBIN -m uvicorn app.main:app --port 8101 >"$TMP/eng.log" 2>&1) & PIDS+=($!)
(cd "$ROOT/control-plane" && npm run build >/dev/null)
export REDIS_URL=redis://localhost:6391 ENGINE_URL=http://localhost:8101 INTERNAL_TOKEN=it-token-for-tests SYNC_INTERVAL_MS=300
(cd "$ROOT/control-plane" && exec env PORT=3101 node dist/main.js >"$TMP/cpA.log" 2>&1) & PIDS+=($!)
(cd "$ROOT/control-plane" && exec env PORT=3102 node dist/main.js >"$TMP/cpB.log" 2>&1) & PIDS+=($!)
(cd "$ROOT/control-plane" && exec env CONTROL_PLANE_URL=http://localhost:3102 node dist/worker.js >"$TMP/worker.log" 2>&1) & PIDS+=($!)
for port in 3101 3102; do for i in $(seq 1 60); do curl -sf -m 15 localhost:$port/health >/dev/null && break; sleep 0.5; done; done

SEC=(-H "x-api-key: secops-key" -H "content-type: application/json")
FIN=(-H "x-api-key: finops-key" -H "content-type: application/json")
j() { $PYBIN -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

# 1) Registro en A, visible en B
curl -sf -m 15 "${SEC[@]}" -X POST localhost:3101/api/agents -d '{"id":"demo","url":"http://localhost:9101"}' >/dev/null
sleep 1
curl -sf -m 15 "${SEC[@]}" localhost:3102/api/agents | grep -q '"id":"demo"' || { echo "FAIL: agente no replicado"; exit 1; }

# 2) Campaña lanzada en A; el worker reporta a B; ambas réplicas ven los incidentes
curl -sf -m 15 "${SEC[@]}" -X POST localhost:3101/api/campaigns -d '{"targetUrl":"http://localhost:9101"}' >/dev/null
for i in $(seq 1 60); do
  S=$(curl -sf -m 15 "${SEC[@]}" localhost:3101/api/campaigns | j "d[0]['status'] if d else ''")
  [ "$S" = "done" ] && break; sleep 0.5
done
[ "$S" = "done" ] || { echo "FAIL: campaña status=$S"; for f in cpA cpB worker; do echo "== $f"; tail -n 20 "$TMP/$f.log"; done; exit 1; }
sleep 1
NA=$(curl -sf -m 15 "${SEC[@]}" localhost:3101/api/incidents | j "len(d)"); NB=$(curl -sf -m 15 "${SEC[@]}" localhost:3102/api/incidents | j "len(d)")
[ "$NA" = "$NB" ] && [ "$NA" -ge 5 ] || { echo "FAIL: incidentes A=$NA B=$NB"; exit 1; }

# 3) Aprobación con firma repartida entre réplicas (SECOPS en A, FINOPS en B)
curl -sf -m 15 "${SEC[@]}" -X POST localhost:3101/proxy/demo/chat -d '{"message":"x"}' >/dev/null
ID=$(curl -sf -m 15 "${SEC[@]}" localhost:3101/api/approvals | j "[a['id'] for a in d if a['action']=='ROTATE_KEYS'][0]")
curl -sf -m 15 "${SEC[@]}" -X POST localhost:3101/api/approvals/$ID/approve -d '{}' | grep -q '"status":"approved"' || { echo "FAIL: ROTATE_KEYS no aprobada"; exit 1; }
sleep 1
curl -sf -m 15 "${SEC[@]}" localhost:3102/api/approvals | j "[a['status'] for a in d if a['id']=='$ID'][0]" | grep -q approved || { echo "FAIL: estado no replicado"; exit 1; }
KV=$(curl -sf -m 15 "${SEC[@]}" localhost:3102/api/agents | j "d[0]['keyVersion']")
[ "$KV" = "2" ] || { echo "FAIL: keyVersion=$KV"; exit 1; }

# 4) Una sola cadena de auditoría válida vista desde ambas réplicas
for port in 3101 3102; do curl -sf -m 15 "${SEC[@]}" localhost:$port/api/audit/verify | grep -q '"valid":true' || { echo "FAIL: auditoría inválida en $port"; exit 1; }; done
LA=$(curl -sf -m 15 "${SEC[@]}" localhost:3101/api/audit/verify | j "d['length']"); LB=$(curl -sf -m 15 "${SEC[@]}" localhost:3102/api/audit/verify | j "d['length']")
[ "$LA" = "$LB" ] || { echo "FAIL: longitud de auditoría A=$LA B=$LB"; exit 1; }
echo "OK HA: 2 réplicas + Postgres + worker; $NA incidentes replicados, firma/mitigación replicadas, auditoría única ($LA entradas)"
