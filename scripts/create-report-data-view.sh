#!/usr/bin/env bash
# Create the Kibana data view "Situation reports" over the situation-reports index, so the reports can be
# explored in Discover and used in Lens and dashboards. Idempotent: does nothing if it already exists.
# Time field: generated_at (when the workflow wrote the report).
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
load_env

ID="situation-reports"
if try_api GET "${KIBANA_URL}/api/data_views/data_view/${ID}" >/dev/null; then
  echo "DATA VIEW: '${ID}' already exists"
  exit 0
fi
try_api GET "${ES_URL}/situation-reports" >/dev/null || die "index situation-reports not found; run scripts/configure-reports.sh first"

kbn POST /api/data_views/data_view -d "$(jq -n --arg id "$ID" \
  '{data_view: {id: $id, title: "situation-reports", name: "Situation reports", timeFieldName: "generated_at"}}')" >/dev/null
echo "DATA VIEW: created '${ID}' (index pattern situation-reports, time field generated_at)"
