#!/usr/bin/env bash
# Prueba de integración sin Docker: Redis + sandbox + engine + control plane + worker BullMQ separado.
# Requiere: redis-server, python con requirements instalados (PYBIN), node 22 y control-plane con npm ci.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYBIN="${PYBIN:-python3}"
TMP="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT

redis-server --port 6390 --save "" --appendonly no >"$TMP/redis.log" 2>&1 & PIDS+=($!)
(cd "$ROOT/sandbox/vulnerable-agent" && VULNERABLE=true $PYBIN -m uvicorn main:app --port 9100 >"$TMP/sbx.log" 2>&1) & PIDS+=($!)
(cd "$ROOT/engine" && $PYBIN -m uvicorn app.main:app --port 8100 >"$TMP/eng.log" 2>&1) & PIDS+=($!)
(cd "$ROOT/control-plane" && npm run build >/dev/null)
export REDIS_URL=redis://localhost:6390 ENGINE_URL=http://localhost:8100 INTERNAL_TOKEN=it-token-for-tests STATE_FILE="$TMP/state.json" AUDIT_FILE="$TMP/audit.jsonl"
(cd "$ROOT/control-plane" && PORT=3100 node dist/main.js >"$TMP/cp.log" 2>&1) & PIDS+=($!)
(cd "$ROOT/control-plane" && CONTROL_PLANE_URL=http://localhost:3100 node dist/worker.js >"$TMP/worker.log" 2>&1) & PIDS+=($!)

for i in $(seq 1 40); do curl -sf localhost:3100/health >/dev/null && break; sleep 0.5; done
H=(-H "x-api-key: secops-key" -H "content-type: application/json")
curl -sf "${H[@]}" -X POST localhost:3100/api/agents -d '{"id":"demo","url":"http://localhost:9100"}' >/dev/null
curl -sf "${H[@]}" -X POST localhost:3100/api/campaigns -d '{"targetUrl":"http://localhost:9100"}' >/dev/null

for i in $(seq 1 40); do
  STATUS=$(curl -sf "${H[@]}" localhost:3100/api/campaigns | $PYBIN -c "import json,sys; c=json.load(sys.stdin); print(c[0]['status'] if c else '')")
  [ "$STATUS" = "done" ] && break
  sleep 0.5
done
[ "$STATUS" = "done" ] || { echo "FAIL: campaign status=$STATUS"; cat "$TMP/worker.log" "$TMP/cp.log"; exit 1; }
N=$(curl -sf "${H[@]}" localhost:3100/api/incidents | $PYBIN -c "import json,sys; print(len(json.load(sys.stdin)))")
[ "$N" -ge 5 ] || { echo "FAIL: incidents=$N"; exit 1; }
curl -sf "${H[@]}" localhost:3100/api/audit/verify | grep -q '"valid":true' || { echo "FAIL: audit chain"; exit 1; }
curl -sf "${H[@]}" localhost:3100/metrics | grep -q specterflow_incidents_total || { echo "FAIL: metrics"; exit 1; }
echo "OK: campaña vía BullMQ + worker separado, $N incidentes, auditoría íntegra"
