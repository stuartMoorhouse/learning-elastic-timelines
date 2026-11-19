#!/usr/bin/env bash
# Post-deploy configuration: terraform outputs -> shared/env.json, install prebuilt rules,
# enable the APT29 rule set. Idempotent: safe to re-run.
#
# Reads config/apt29-rules.json. Accepted shapes: [ {rule_id|name,alternates,...} ] or { "rules": [ ... ] }.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd terraform jq curl

[ -f "$ENV_FILE" ] || echo '{}' > "$ENV_FILE"

# --- 1. Terraform outputs -> env.json -------------------------------------
log "Reading Terraform outputs"
es_url="$(tf_out elasticsearch_url)"
kb_url="$(tf_out kibana_url)"
[ -n "$es_url" ] && [ -n "$kb_url" ] || die "terraform outputs elasticsearch_url/kibana_url empty; has 'terraform apply' completed?"
env_set elasticsearch_url "$es_url"
env_set kibana_url "$kb_url"
for k in fleet_url vm_public_ip vm_name resource_group_name vm_admin_username; do
  v="$(tf_out "$k")"
  [ -n "$v" ] && env_set "$k" "$v"
done
env_set infra_ready true json

ES_URL="${es_url%/}"; KIBANA_URL="${kb_url%/}"

# --- 2. API key (inherits the privileges of the elastic user at creation time) ---
valid_key=false
existing="$(env_get api_key)"
if [ -n "$existing" ]; then
  if printf 'header = "Authorization: ApiKey %s"\n' "$existing" | \
       curl -sf --max-time 20 -K - "$ES_URL/_security/_authenticate" >/dev/null 2>&1; then
    valid_key=true
    log "Existing API key still valid; reusing"
  fi
fi
if [ "$valid_key" = false ]; then
  user="$(tf_out elastic_username)"; pass="$(tf_out elastic_password)"
  [ -n "$user" ] && [ -n "$pass" ] || die "elastic_username/elastic_password outputs empty; cannot create an API key"
  log "Creating Elasticsearch API key 'timelines-demo'"
  resp="$(printf 'user = "%s:%s"\n' "$user" "$pass" | \
    curl -sS --connect-timeout 10 --max-time 60 -K - -X POST -H 'Content-Type: application/json' \
      -d '{"name":"timelines-demo","expiration":"30d"}' "$ES_URL/_security/api_key")" \
    || die "cannot reach $ES_URL"
  enc="$(printf '%s' "$resp" | jq -r '.encoded // empty')"
  [ -n "$enc" ] || die "API key creation failed: $(printf '%s' "$resp" | jq -c 'del(.api_key)' 2>/dev/null | head -c 400)"
  env_set api_key "$enc"
fi

load_env

# --- 3. Reachability -------------------------------------------------------
log "Checking Elasticsearch and Kibana"
es GET / >/dev/null
status="$(kbn GET /api/status | jq -r '.status.overall.level // "unknown"')"
log "Kibana status: $status"

# --- 4. Prebuilt detection rules ------------------------------------------
log "Installing/updating prebuilt detection rules (can take a minute)"
# try_api, not kbn/api: those call die (exit) on a non-2xx response, which would end the script
# here instead of reaching the fallback.
if ! try_api PUT "${KIBANA_URL}/api/detection_engine/rules/prepackaged" >/dev/null; then
  log "legacy prepackaged endpoint unavailable; trying internal bootstrap + install"
  try_api PUT "${KIBANA_URL}/internal/detection_engine/prebuilt_rules/_bootstrap" \
    -H 'elastic-api-version: 1' -H 'x-elastic-internal-origin: kibana' >/dev/null || true
  api POST "${KIBANA_URL}/internal/detection_engine/prebuilt_rules/installation/_perform" \
    -H 'Content-Type: application/json' -H 'elastic-api-version: 1' -H 'x-elastic-internal-origin: kibana' \
    -d '{"mode":"ALL_RULES"}' >/dev/null \
    || die "could not install prebuilt rules; install them once in Kibana (Security > Rules > Add Elastic rules) and re-run"
fi

# --- 5. Elastic Defend integration on the attack VM policy ------------------
# Terraform creates the agent policy and enrollment token; the Endpoint integration is added here
# (the elasticstack provider cannot set the Endpoint preset). Idempotent: skipped if present.
policy_id="$(tf_out agent_policy_id)"
[ -n "$policy_id" ] || die "terraform output agent_policy_id empty"
existing_pp="$(kbn GET "/api/fleet/package_policies?perPage=100&kuery=ingest-package-policies.package.name:endpoint" \
  | jq -r --arg p "$policy_id" '[.items[]? | select(.policy_ids // [.policy_id] | index($p))] | length')"
if [ "${existing_pp:-0}" -gt 0 ]; then
  log "Elastic Defend already on policy $policy_id"
else
  endpoint_ver="$(kbn GET /api/fleet/epm/packages/endpoint | jq -r '.item.version // .response.version // empty')"
  [ -n "$endpoint_ver" ] || die "could not determine the endpoint package version from Fleet"
  log "Adding Elastic Defend (endpoint $endpoint_ver, preset EDRComplete) to policy $policy_id"
  body="$(jq -nc --arg p "$policy_id" --arg v "$endpoint_ver" '{
    name: "elastic-defend-timelines-demo", namespace: "default", policy_ids: [$p],
    package: {name: "endpoint", title: "Elastic Defend", version: $v},
    inputs: [{type: "ENDPOINT_INTEGRATION_CONFIG", enabled: true, streams: [],
      config: {_config: {value: {type: "endpoint", endpointConfig: {preset: "EDRComplete"}}}}}]
  }')"
  kbn POST /api/fleet/package_policies -H 'elastic-api-version: 2023-10-31' -d "$body" >/dev/null \
    || die "failed to add Elastic Defend; add it once in Kibana (Fleet > Agent policies) and re-run"
fi

# --- 5a. Defend in detect-only mode ------------------------------------------
# The EDRComplete preset runs malware, behavior, memory and ransomware protection in prevent
# mode. Defend then kills the PowerShell process running the Atomic Red Team emulation within
# seconds ("Malicious Behavior Prevention Alert"), so most of the attack chain never runs. Detect
# mode keeps the Defend alerts but lets the chain finish. Idempotent: skipped if already detect.
pp="$(kbn GET "/api/fleet/package_policies?perPage=100&kuery=ingest-package-policies.package.name:endpoint" \
  | jq -c --arg p "$policy_id" '[.items[]? | select(.policy_ids // [.policy_id] | index($p))][0] // empty')"
if [ -n "$pp" ]; then
  pp_id="$(jq -r '.id' <<<"$pp")"
  n_prevent="$(jq '[.inputs[0].config.policy.value.windows | .malware.mode, .behavior_protection.mode, .memory_protection.mode, .ransomware.mode]
    | map(select(. == "prevent")) | length' <<<"$pp")"
  if [ "${n_prevent:-0}" -gt 0 ]; then
    log "Setting Elastic Defend protections to detect-only (was prevent on $n_prevent)"
    body="$(jq -c '{name, namespace, policy_ids,
        package: {name: .package.name, title: .package.title, version: .package.version},
        inputs: (.inputs | map(.config.policy.value.windows.malware.mode = "detect"
                              | .config.policy.value.windows.behavior_protection.mode = "detect"
                              | .config.policy.value.windows.memory_protection.mode = "detect"
                              | .config.policy.value.windows.ransomware.mode = "detect"))}
      + (if .description then {description: .description} else {} end)' <<<"$pp")"
    kbn PUT "/api/fleet/package_policies/$pp_id" -H 'elastic-api-version: 2023-10-31' -d "$body" >/dev/null \
      || die "could not set Defend to detect-only; in Kibana > Fleet > Agent policies > Elastic Defend set malware, ransomware, memory and behavior protection to Detect, then re-run"
  else
    log "Elastic Defend protections already detect-only"
  fi
fi

# --- 5b. Windows integration (PowerShell and other Windows event logs) --------
# The System integration (sys_monitoring in Terraform) already collects the Windows Security log
# (4624/4625). The Windows integration adds PowerShell and related channels for the hunts.
has_win="$(kbn GET "/api/fleet/package_policies?perPage=100&kuery=ingest-package-policies.package.name:windows" \
  | jq -r --arg p "$policy_id" '[.items[]? | select(.policy_ids // [.policy_id] | index($p))] | length')"
if [ "${has_win:-0}" -gt 0 ]; then
  log "Windows integration already on policy $policy_id"
else
  win_ver="$(kbn GET /api/fleet/epm/packages/windows | jq -r '.item.version // .response.version // empty')"
  [ -n "$win_ver" ] || die "could not determine the windows package version from Fleet"
  log "Installing Windows integration $win_ver and adding it to policy $policy_id"
  try_api POST "${KIBANA_URL}/api/fleet/epm/packages/windows" -H 'elastic-api-version: 2023-10-31' -d '{"force":true}' >/dev/null || true
  body="$(jq -nc --arg p "$policy_id" --arg v "$win_ver" '{
    name: "windows-timelines-demo", namespace: "default", policy_ids: [$p],
    package: {name: "windows", version: $v}}')"
  kbn POST /api/fleet/package_policies -H 'elastic-api-version: 2023-10-31' -d "$body" >/dev/null \
    || die "failed to add the Windows integration; add it once in Kibana (Fleet > Agent policies) and re-run"
fi

# --- 6. Enable APT29 rules by name (test one, then the rest) ----------------
rules_file="$CONFIG_DIR/apt29-rules.json"
[ -f "$rules_file" ] || die "$rules_file not found (generated by the config step)"

# Resolve a rule: rule_id if set, else each candidate name (name, then alternates) via _find.
find_rule_json() {  # args: rule_id name...
  local rid="$1" n body; shift
  if [ -n "$rid" ]; then
    try_api GET "${KIBANA_URL}/api/detection_engine/rules?rule_id=${rid}" 2>/dev/null && return 0
  fi
  for n in "$@"; do
    body="$(try_api GET "${KIBANA_URL}/api/detection_engine/rules/_find?per_page=5&filter=$(jq -rn --arg n "$n" '"alert.attributes.name: \"" + $n + "\"" | @uri')" 2>/dev/null || true)"
    if [ "$(printf '%s' "$body" | jq -r '.data | length' 2>/dev/null || echo 0)" -gt 0 ]; then
      printf '%s' "$body" | jq -c '.data[0]'; return 0
    fi
  done
  return 1
}

enable_rule() {  # returns 0 if enabled, 1 if rule not found
  local body id
  body="$(find_rule_json "$@" || true)"
  id="$(printf '%s' "$body" | jq -r '.id // empty' 2>/dev/null || true)"
  if [ -z "$id" ]; then log "rule not found in this stack version (tried: ${*:2}); skipping"; return 1; fi
  if [ "$(printf '%s' "$body" | jq -r '.enabled')" = "true" ]; then return 0; fi
  kbn POST /api/detection_engine/rules/_bulk_action \
    -d "$(jq -nc --arg id "$id" '{action:"enable",ids:[$id]}')" >/dev/null
  return 0
}

mapfile -t rule_lines < <(jq -c '(.rules // .)[] | [(.rule_id // ""), .name] + (.alternates // [])' "$rules_file")
[ "${#rule_lines[@]}" -gt 0 ] || die "no rules in $rules_file"

enabled=0; skipped=0; i=0
for line in "${rule_lines[@]}"; do
  mapfile -t args < <(printf '%s' "$line" | jq -r '.[]')
  [ "$i" -eq 0 ] && log "Enabling first rule as a test: ${args[1]}"
  if enable_rule "${args[@]}"; then enabled=$((enabled+1)); else skipped=$((skipped+1)); fi
  if [ "$i" -eq 0 ] && [ "$enabled" -eq 0 ]; then log "test rule not found; continuing with the rest"; fi
  i=$((i+1))
done
log "Rules enabled: $enabled, skipped (not found): $skipped"
[ "$enabled" -gt 0 ] || die "no APT29 rules could be enabled"

env_set config_ready true json
echo "CONFIGURE COMPLETE: env written to ${ENV_FILE#"$PROJECT_ROOT"/}"
