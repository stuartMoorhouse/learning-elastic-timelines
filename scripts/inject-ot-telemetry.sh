#!/usr/bin/env bash
# Inject synthetic OT telemetry into Elasticsearch as ECS data shaped like real Elastic integrations:
# Zeek (Modbus, connections), Windows Security, Elastic Defend and a PAN-OS firewall.
# Data streams are logs-<dataset>-ot (namespace "ot"), so the real demo VM streams in "default"
# are not touched. No custom index template: Elastic Defend and System streams use their package
# templates, the others use the built-in logs template with ECS mappings.
#
# Idempotent: the ot data streams are deleted and rebuilt on every run, with times relative to now,
# so run this shortly before the demo (scripts/demo-reset.sh does not call it).
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
load_env
require_cmd python3

TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
python3 "$(dirname "$0")/ot_telemetry.py" > "$TMP"
log "generated $(( $(wc -l < "$TMP") / 2 )) events"

# Remove the previous synthetic data (ignore "not found"), including the superseded
# logs-ot_synthetic-default stream and its custom template from an earlier version.
try_api DELETE "${ES_URL}/_data_stream/logs-ot_synthetic-default" >/dev/null 2>&1 || true
try_api DELETE "${ES_URL}/_index_template/ot_synthetic" >/dev/null 2>&1 || true
for ds in $(jq -r 'select(.create) | .create._index' "$TMP" | sort -u); do
  try_api DELETE "${ES_URL}/_data_stream/${ds}" >/dev/null 2>&1 || true
done

# The Endpoint package template does not map the ECS `labels` field, so labels.* would be stored but not
# searchable. Fleet's documented extension point is the stream's @custom component template; it did not
# exist, so this adds labels.bus_type and labels.dos_name (the device a USB-launched process ran from).
# It applies to the endpoint process stream in every namespace and only adds mappings.
api PUT "${ES_URL}/_component_template/logs-endpoint.events.process@custom" -H 'Content-Type: application/json' -d '{
  "template": {"mappings": {"properties": {"labels": {"properties": {
    "bus_type": {"type": "keyword"}, "dos_name": {"type": "keyword"}}}}}},
  "_meta": {"description": "labels.* custom fields for the OT demo (scripts/inject-ot-telemetry.sh)"}
}' >/dev/null

resp="$(api POST "${ES_URL}/_bulk?refresh=wait_for" -H 'Content-Type: application/x-ndjson' --data-binary "@${TMP}")"
errors="$(printf '%s' "$resp" | jq -r '.errors')"
if [ "$errors" != false ]; then
  printf '%s' "$resp" | jq -c '[.items[] | select(.create.error) | .create.error][0:3]' >&2
  die "bulk indexing reported errors"
fi
count="$(printf '%s' "$resp" | jq '.items | length')"
echo "OT TELEMETRY: indexed=${count} streams=$(jq -r 'select(.create) | .create._index' "$TMP" | sort -u | wc -l | tr -d ' ')"
