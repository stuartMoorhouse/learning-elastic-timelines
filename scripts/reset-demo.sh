#!/usr/bin/env bash
# Reset the demo: close open security alerts, run APT29 cleanup on the VM, reset demo_executed.
# Rules and timelines are NOT touched. Set DELETE_ALERTS=1 to delete alert documents instead of
# closing them.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd az jq curl
load_env

if [ "${DELETE_ALERTS:-0}" = 1 ]; then
  log "Deleting alert documents"
  resp="$(es POST '/.alerts-security.alerts-*/_delete_by_query?conflicts=proceed&refresh=true' \
    -d '{"query":{"match_all":{}}}')"
  log "deleted: $(printf '%s' "$resp" | jq -r '.deleted // 0')"
else
  log "Closing open alerts"
  resp="$(kbn POST /api/detection_engine/signals/status \
    -d '{"status":"closed","query":{"bool":{"filter":[{"term":{"kibana.alert.workflow_status":"open"}}]}}}')"
  log "closed: $(printf '%s' "$resp" | jq -r '.updated // 0')"
fi

log "Running cleanup on the VM"
resp="$(vm_run_script "$PROJECT_ROOT/scripts/vm/Invoke-APT29.ps1" Mode=Cleanup)" \
  || die "az vm run-command failed (is the VM running and the Azure login valid?)"
printf '%s' "$resp" | jq -r '.value[]? | .message' | tail -n 15

env_set demo_executed false json
echo "RESET COMPLETE: run scripts/attack.sh to generate fresh alerts"
