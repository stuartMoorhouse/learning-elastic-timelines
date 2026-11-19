#!/usr/bin/env bash
# Trigger the APT29 emulation on the Windows VM via `az vm run-command invoke`, then poll for
# alerts. Usage: scripts/attack.sh [--no-wait]
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd az jq curl
load_env

WAIT=true
[ "${1:-}" = "--no-wait" ] && WAIT=false
MIN_RULES="${MIN_RULES:-5}"
TIMEOUT_SECS="${TIMEOUT_SECS:-300}"

[ "$(env_get config_ready)" = "true" ] || log "warning: config_ready is not true; rules may not be enabled (run scripts/configure.sh)"

script="$PROJECT_ROOT/scripts/vm/Invoke-APT29.ps1"
[ -f "$script" ] || die "$script not found"

start_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Running Invoke-APT29.ps1 on VM (this takes several minutes)"
resp="$(vm_run_script "$script" Mode=Run)" || die "az vm run-command failed (is the VM running and the Azure login valid?)"

printf '%s' "$resp" | jq -r '.value[]? | .message' | tail -n 40
if printf '%s' "$resp" | jq -e '[.value[]? | select(.code | test("failed";"i"))] | length > 0' >/dev/null; then
  die "run-command reported a failure; see output above"
fi
env_set demo_executed true json

if [ "$WAIT" = false ]; then echo "ATTACK TRIGGERED (not waiting for alerts)"; exit 0; fi

log "Polling for alerts (need >= $MIN_RULES distinct rules, timeout ${TIMEOUT_SECS}s)"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
query="$(jq -nc --arg s "$start_iso" '{size:0,query:{bool:{filter:[{range:{"@timestamp":{gte:$s}}}]}},
  aggs:{rules:{terms:{field:"kibana.alert.rule.name",size:100}}}}')"
rules=""; count=0
while :; do
  body="$(try_api POST "${ES_URL}/.alerts-security.alerts-*/_search" -d "$query" || true)"
  rules="$(printf '%s' "$body" | jq -r '.aggregations.rules.buckets[]?.key' 2>/dev/null || true)"
  count="$(printf '%s' "$rules" | grep -c . || true)"
  [ "$count" -ge "$MIN_RULES" ] && break
  [ "$(date +%s)" -ge "$deadline" ] && break
  sleep 15
done

echo "Distinct rules alerted since $start_iso: $count"
printf '%s\n' "$rules" | sed 's/^/  - /'
[ "$count" -ge "$MIN_RULES" ] || die "only $count distinct rules alerted within ${TIMEOUT_SECS}s (need $MIN_RULES); check Elastic Defend health and rule schedules"
echo "ATTACK COMPLETE"
