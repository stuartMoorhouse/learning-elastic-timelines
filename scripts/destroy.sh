#!/usr/bin/env bash
# Destroy all demo infrastructure. Validates EC_API_KEY first: ec_stack/ec_deployment call the
# Elastic Cloud API during destroy, and an invalid key leaves a half-destroyed state.
# Do not work around a failure with -refresh=false or `terraform state rm`.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd terraform curl

check_ec_api_key
log "EC_API_KEY valid"

if command -v az >/dev/null 2>&1; then
  az account show --query '{name:name,id:id}' -o tsv 2>/dev/null \
    || die "not logged in to Azure: run 'az login'"
fi

if [ "${AUTO_APPROVE:-0}" = 1 ]; then
  terraform -chdir="$TF_DIR" destroy -auto-approve
else
  terraform -chdir="$TF_DIR" destroy
fi

env_set infra_ready false json
env_set config_ready false json
env_set demo_executed false json
env_set api_key ""
echo "DESTROY COMPLETE"
