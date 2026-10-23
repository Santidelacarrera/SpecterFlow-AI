#!/usr/bin/env bash
# Prueba de integración sin Docker: Redis + sandbox + engine + control plane + worker BullMQ separado.
# Requiere: redis-server, python con requirements instalados (PYBIN), node 22 y control-plane con npm ci.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYBIN="${PYBIN:-python3}"
TMP="$(mktemp -d)"
PIDS=()
cleanup() { rc=$?; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$TMP" 2>/dev/null || true; exit "$rc"; }
trap cleanup EXIT

redis-server --port 6390 --save "" --appendonly no >"$TMP/redis.log" 2>&1 & PIDS+=($!)
(cd "$ROOT/sandbox/vulnerable-agent" && exec env VULNERABLE=true $PYBIN -m uvicorn main:app --port 9100 >"$TMP/sbx.log" 2>&1) & PIDS+=($!)
(cd "$ROOT/engine" && exec $PYBIN -m uvicorn app.main:app --port 8100 >"$TMP/eng.log" 2>&1) & PIDS+=($!)
(cd "$ROOT/executor" && exec env EXECUTOR_TOKEN=it-token-for-tests EXECUTOR_MODE=live CONNECTORS=nginx NGINX_CONF_DIR="$TMP/ng" EXECUTOR_STATE_DIR="$TMP/exec" $PYBIN -m uvicorn app.main:app --port 8200 >"$TMP/exec.log" 2>&1) & PIDS+=($!)
(cd "$ROOT/control-plane" && npm run build >/dev/null)
export MITIGATION_WEBHOOK_URL=http://localhost:8200/v1/execute
export REDIS_URL=redis://localhost:6390 ENGINE_URL=http://localhost:8100 INTERNAL_TOKEN=it-token-for-tests STATE_FILE="$TMP/state.json" AUDIT_FILE="$TMP/audit.jsonl"
(cd "$ROOT/control-plane" && exec env PORT=3100 node dist/main.js >"$TMP/cp.log" 2>&1) & PIDS+=($!)
(cd "$ROOT/control-plane" && exec env CONTROL_PLANE_URL=http://localhost:3100 node dist/worker.js >"$TMP/worker.log" 2>&1) & PIDS+=($!)

for i in $(seq 1 40); do curl -sf -m 15 localhost:3100/health >/dev/null && break; sleep 0.5; done
H=(-H "x-api-key: secops-key" -H "content-type: application/json")
curl -sf -m 15 "${H[@]}" -X POST localhost:3100/api/agents -d '{"id":"demo","url":"http://localhost:9100"}' >/dev/null
curl -sf -m 15 "${H[@]}" -X POST localhost:3100/api/campaigns -d '{"targetUrl":"http://localhost:9100"}' >/dev/null

for i in $(seq 1 40); do
  STATUS=$(curl -sf -m 15 "${H[@]}" localhost:3100/api/campaigns | $PYBIN -c "import json,sys; c=json.load(sys.stdin); print(c[0]['status'] if c else '')")
  [ "$STATUS" = "done" ] && break
  sleep 0.5
done
[ "$STATUS" = "done" ] || { echo "FAIL: campaign status=$STATUS"; cat "$TMP/worker.log" "$TMP/cp.log"; exit 1; }
N=$(curl -sf -m 15 "${H[@]}" localhost:3100/api/incidents | $PYBIN -c "import json,sys; print(len(json.load(sys.stdin)))")
[ "$N" -ge 5 ] || { echo "FAIL: incidents=$N"; exit 1; }
curl -sf -m 15 "${H[@]}" localhost:3100/api/audit/verify | grep -q '"valid":true' || { echo "FAIL: audit chain"; exit 1; }
curl -sf -m 15 "${H[@]}" localhost:3100/metrics | grep -q specterflow_incidents_total || { echo "FAIL: metrics"; exit 1; }
# Mitigación aprobada → executor → fichero real del gateway (nginx)
AID=$(curl -sf -m 15 "${H[@]}" localhost:3100/api/approvals | $PYBIN -c "import json,sys; print([a['id'] for a in json.load(sys.stdin) if a['action']=='PATCH_GATEWAY_RULE'][0])")
curl -sf -m 15 "${H[@]}" -X POST localhost:3100/api/approvals/$AID/approve -d '{}' >/dev/null
for i in $(seq 1 20); do [ -s "$TMP/ng/rules.conf" ] && break; sleep 0.5; done
[ -s "$TMP/ng/rules.conf" ] || { echo "FAIL: executor no escribió rules.conf"; cat "$TMP/exec.log"; exit 1; }
sleep 0.5
curl -sf -m 15 "${H[@]}" localhost:3100/api/approvals | grep -q '"execution":{"status":"ok"' || { echo "FAIL: execution no registrada"; exit 1; }
echo "OK: campaña vía BullMQ + worker separado, $N incidentes, auditoría íntegra, mitigación ejecutada por el executor"
