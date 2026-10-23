#!/usr/bin/env bash
# Verificación completa (pruebas + lint + seguridad + flujo principal). Escribe docs/evidence/verification.md.
# Requiere: node 22, python 3.12+, redis-server. Opcional: TEST_DATABASE_URL (Postgres) para los tests de alta disponibilidad.
# Uso: PYBIN=python3 scripts/verify-all.sh      (PYBIN debe tener `pip install -r requirements-dev.txt`)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYBIN="${PYBIN:-python3}"
OUT="${VERIFY_FILE:-$ROOT/docs/evidence/verification.md}"
FAILS=0
printf "# Verificación — SpecterFlow AI (Nexus Security & AI Lab)\n\nFecha: %s\n\n| Comprobación | Comando | Resultado |\n|---|---|---|\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$OUT"
run() { # run "<nombre>" "<directorio>" "<comando>" "<regex que extrae el resumen>"
  local name="$1" dir="$2" cmd="$3" pat="$4" log; log="$(mktemp)"
  if (cd "$ROOT/$dir" && eval "$cmd") >"$log" 2>&1; then st="✅"; else st="❌"; FAILS=$((FAILS+1)); fi
  local shown="${cmd//$PYBIN/python}"; shown="${shown//${TEST_DATABASE_URL:-__none__}/\$TEST_DATABASE_URL}"
  local sum; sum="$(grep -E "$pat" "$log" | tail -n 1 | tr '|' '/' | sed "s#$ROOT/##g" | cut -c1-110)"
  printf "| %s | \`%s\` (en \`%s\`) | %s %s |\n" "$name" "$shown" "$dir" "$st" "${sum:-sin salida}" >>"$OUT"
  echo "$st $name: ${sum:-}"; [ "$st" = "❌" ] && tail -n 20 "$log"; rm -f "$log"
}
run "Tests engine"            engine        "$PYBIN -m pytest -q"                          "passed|failed|error"
run "Tests executor"          executor      "$PYBIN -m pytest -q"                          "passed|failed|error"
run "Tests control plane"     control-plane "npx jest"                                     "^Tests:"
run "Typecheck control plane" control-plane "npx tsc --noEmit"                             "."
run "Typecheck+build frontend" frontend     "npm run build"                                "built in"
run "Lint Python (ruff)"      .             "$PYBIN -m ruff check engine executor sandbox" "All checks passed|Found"
run "SAST Python (bandit)"    .             "$PYBIN -m bandit -q -r engine/app executor/app sandbox/vulnerable-agent -ll" "No issues|Issue"
run "Deps Python (pip-audit)" .             "$PYBIN -m pip_audit -r engine/requirements.txt -r executor/requirements.txt -r sandbox/vulnerable-agent/requirements.txt" "No known|vulnerab"
run "npm audit control plane (prod)" control-plane "npm audit --omit=dev"                  "found"
run "npm audit control plane (alto)" control-plane "npm audit --audit-level=high"          "found|vulnerabilities"
run "npm audit frontend"      frontend      "npm audit --audit-level=high"                 "found"
run "Flujo principal e2e"     .             "PYBIN=$PYBIN scripts/e2e-main-flow.sh"        "^OK:|FAIL"
run "Integración Redis+worker+executor" .   "PYBIN=$PYBIN scripts/integration.sh"          "^OK|FAIL"
if [ -n "${TEST_DATABASE_URL:-}" ]; then
  run "Alta disponibilidad (Postgres, 2 réplicas)" . "DATABASE_URL=$TEST_DATABASE_URL PYBIN=$PYBIN scripts/integration-ha.sh" "^OK|FAIL"
else
  echo "| Alta disponibilidad (Postgres) | \`scripts/integration-ha.sh\` | ⏭️ omitida (sin TEST_DATABASE_URL) |" >>"$OUT"
fi
printf "\n**Fallos: %s**\n" "$FAILS" >>"$OUT"
echo "Fallos: $FAILS · informe: $OUT"; exit "$FAILS"
