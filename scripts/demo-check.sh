#!/usr/bin/env bash
# Pre-demo readiness check: is everything built, loaded and working so the lessons will run?
# Read-only unless --build or --full is given. Exit code 1 if any check FAILs.
#
#   PASS  ok
#   FAIL  the demo will break; fix before presenting
#   WARN  the demo can run, but look at it
#   INFO  for your attention
#
# Usage: scripts/demo-check.sh [--full] [--build]
#   --full   also generates one report (calls the LLM, takes a few minutes) and runs
#            scripts/validate.sh (acceptance criteria, including an agent question)
#   --build  first builds everything that is missing, waiting for each step, then runs the
#            full check. Order: configure.sh, wait for the Fleet agent, attack.sh (skipped if
#            alerts already exist; FORCE_ATTACK=1 to re-run), load-timelines.sh,
#            configure-reports.sh (REPORT_PERIOD_DAYS, default 30). Stops at the first failing
#            step and shows the log tail. Implies --full. Changes Kibana and the VM; allow 20-40
#            minutes on a fresh deployment.
#
# Complements scripts/validate.sh (spec acceptance criteria). This script checks what the
# lessons actually click through: the named timelines, their notes and pins, the report
# pipeline and the fallback report.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd jq curl

FULL=false; BUILD=false
for a in "$@"; do
  case "$a" in
    --full) FULL=true ;;
    --build) BUILD=true; FULL=true ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) die "unknown option: $a (try --help)" ;;
  esac
done

fails=0; warns=0; passes=0
ok()      { printf '  PASS  %s\n' "$*"; passes=$((passes+1)); }
bad()     { printf '  FAIL  %s\n' "$*"; fails=$((fails+1)); }
warn()    { printf '  WARN  %s\n' "$*"; warns=$((warns+1)); }
info()    { printf '  INFO  %s\n' "$*"; }
section() { printf '\n%s\n' "$*"; }
rel()     { printf '%s' "${1#"$PROJECT_ROOT"/}"; }

# Number of online Fleet agents whose policy includes Elastic Defend.
defend_online() {
  local agents pkgs dp
  agents="$(try_api GET "$KIBANA_URL/api/fleet/agents?perPage=100" || true)"
  pkgs="$(try_api GET "$KIBANA_URL/api/fleet/package_policies?perPage=100" || true)"
  dp="$(jq -c '[.items[]? | select(.package.name=="endpoint") | (.policy_ids // [.policy_id])[]] | unique' <<<"$pkgs" 2>/dev/null || echo '[]')"
  jq --argjson dp "${dp:-[]}" '[.items[]? | select(.status=="online") | select(.policy_id as $p | $dp | index($p))] | length' <<<"$agents" 2>/dev/null || echo 0
}

# Number of distinct rules that have alerted.
alert_rule_count() {
  try_api POST "$ES_URL/.alerts-security.alerts-*/_search" \
    -d '{"size":0,"aggs":{"rules":{"terms":{"field":"kibana.alert.rule.name","size":100}}}}' \
    | jq '[.aggregations.rules.buckets[]?] | length' 2>/dev/null || echo 0
}

# ---------------------------------------------------------------------------
section "1. Repo files and syntax"
for f in config/workflows/situation-report.yaml config/report/situation-reports-mapping.json \
         config/agent-builder/agent.json config/apt29-rules.json config/apt29-atomics.json \
         scripts/vm/Invoke-APT29.ps1; do
  if [ -f "$PROJECT_ROOT/$f" ]; then ok "$f"; else bad "$f is missing"; fi
done

for f in "$CONFIG_DIR"/timelines/*.ndjson "$CONFIG_DIR"/agent-builder/agent.json \
         "$CONFIG_DIR"/agent-builder/tools/*.json "$CONFIG_DIR"/report/*.json \
         "$CONFIG_DIR"/apt29-*.json; do
  [ -f "$f" ] || continue
  if jq -e . "$f" >/dev/null 2>&1; then ok "valid JSON: $(rel "$f")"; else bad "invalid JSON: $(rel "$f")"; fi
done

bad_sh=0
for f in "$PROJECT_ROOT"/scripts/*.sh; do
  bash -n "$f" 2>/dev/null || { bad "shell syntax error: $(rel "$f")"; bad_sh=1; }
done
[ "$bad_sh" -eq 0 ] && ok "all scripts/*.sh parse"

wf_src="$CONFIG_DIR/workflows/situation-report.yaml"
if [ -f "$wf_src" ]; then
  if python3 -I -c 'import yaml' >/dev/null 2>&1; then
    if python3 -I -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$wf_src" 2>/dev/null; then
      ok "workflow YAML parses"
    else
      bad "workflow YAML does not parse: $(rel "$wf_src")"
    fi
  else
    info "PyYAML not installed; workflow YAML syntax not checked locally"
  fi
fi
rendered="$RESULTS_DIR/situation-report.rendered.yaml"
if [ -f "$rendered" ]; then
  if grep -q '__[A-Z_]*__' "$rendered"; then bad "rendered workflow still has __PLACEHOLDER__ tokens"; else ok "rendered workflow has no unresolved placeholders"; fi
  days="$(grep -Eo '[0-9]+ *(days?|d)\b' "$rendered" | head -1 || true)"
  [ -n "$days" ] && info "workflow look-back (first match in rendered YAML): $days (lessons assume REPORT_PERIOD_DAYS=30)"
else
  warn "no rendered workflow in results/ (scripts/configure-reports.sh not run yet)"
fi

# ---------------------------------------------------------------------------
if [ "$BUILD" = true ]; then
  section "Build (--build): configure, attack, load timelines, install the report pipeline"
  require_cmd terraform az
  mkdir -p "$RESULTS_DIR"
  blog="$RESULTS_DIR/demo-check-build-$(date -u +%Y%m%dT%H%M%SZ).log"
  info "full output: $(rel "$blog")"

  stage() {  # stage <label> <command...>; stops the whole run if the command fails
    local label="$1" t0; shift
    t0="$(date +%s)"
    printf '  ....  %s\n' "$label"
    printf '\n===== %s =====\n' "$label" >>"$blog"
    if "$@" >>"$blog" 2>&1; then
      ok "$label ($(( $(date +%s) - t0 ))s)"
    else
      bad "$label failed. Last lines of $(rel "$blog"):"
      tail -n 15 "$blog" | sed 's/^/          /'
      echo
      echo "RESULT: $passes passed, $fails failed, $warns warnings"
      echo "NOT READY: build stopped at: $label"
      exit 1
    fi
  }

  wait_fleet() {  # up to 20 minutes for the VM bootstrap to enrol the agent
    local i
    for i in $(seq 1 80); do
      [ "$(defend_online)" -ge 1 ] && return 0
      sleep 15
    done
    echo "no online Fleet agent with Elastic Defend after 20 minutes (check the VM bootstrap extension)"
    return 1
  }

  maybe_attack() {
    if [ "${FORCE_ATTACK:-0}" != 1 ] && [ "$(alert_rule_count)" -ge "${MIN_RULES:-5}" ]; then
      echo "alerts from $(alert_rule_count) distinct rules already exist; skipping the attack (FORCE_ATTACK=1 to re-run)"
      return 0
    fi
    TIMEOUT_SECS=600 "$PROJECT_ROOT/scripts/attack.sh"
  }

  stage "configure.sh (Terraform outputs, API key, detection rules)" "$PROJECT_ROOT/scripts/configure.sh"
  load_env
  stage "Fleet agent online with Elastic Defend" wait_fleet
  stage "inject-ot-telemetry.sh (synthetic OT telemetry)" "$PROJECT_ROOT/scripts/inject-ot-telemetry.sh"
  stage "load-timelines.sh (OT hunt timelines and templates)" "$PROJECT_ROOT/scripts/load-timelines.sh"
  stage "configure-reports.sh (index, workflow, agent)" \
    env REPORT_PERIOD_DAYS="${REPORT_PERIOD_DAYS:-30}" "$PROJECT_ROOT/scripts/configure-reports.sh"
  if grep -q 'CONFIGURE-REPORTS PARTIAL' "$blog"; then
    warn "configure-reports.sh needs manual steps (the checks below will show which):"
    sed -n '/CONFIGURE-REPORTS PARTIAL/,$p' "$blog" | head -12 | sed 's/^/          /'
  fi
fi

# ---------------------------------------------------------------------------
section "2. Elastic Cloud connection"
[ -f "$ENV_FILE" ] || { bad "shared/env.json missing; run scripts/configure.sh"; echo; echo "RESULT: $passes passed, $fails failed, $warns warnings"; exit 1; }
load_env
info "Elasticsearch: ${ES_URL}"
info "Kibana:        ${KIBANA_URL}"

root="$(try_api GET "$ES_URL/" || true)"
ver="$(jq -r '.version.number // empty' <<<"$root" 2>/dev/null || true)"
if [ -z "$ver" ]; then
  code="$(printf 'header = "Authorization: ApiKey %s"\n' "$API_KEY" | \
    curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 -K - "$ES_URL/" 2>/dev/null || true)"
  case "$code" in
    410) bad "Elasticsearch returned HTTP 410 (Deleted resource): the deployment in shared/env.json no longer exists. Run terraform apply, then scripts/configure.sh." ;;
    401|403) bad "Elasticsearch returned HTTP $code: the API key in shared/env.json is rejected. Run scripts/configure.sh." ;;
    *) bad "cannot reach Elasticsearch (HTTP ${code:-none}); check the deployment in the Elastic Cloud console." ;;
  esac
  echo
  echo "Stack unreachable: remaining checks skipped."
  echo "RESULT: $passes passed, $fails failed, $warns warnings"
  echo "NOT READY"
  exit 1
else
  case "$ver" in
    9.5.*) ok "Elasticsearch $ver" ;;
    9.*)   warn "Elasticsearch $ver; lessons and config were written for 9.5.x, check UI wording" ;;
    *)     bad "Elasticsearch $ver; need 9.x" ;;
  esac
fi
health="$(try_api GET "$ES_URL/_cluster/health" | jq -r '.status // empty' 2>/dev/null || true)"
case "$health" in green|yellow) ok "cluster health: $health" ;; *) bad "cluster health: ${health:-unreadable}" ;; esac
kb="$(try_api GET "$KIBANA_URL/api/status" | jq -r '.status.overall.level // empty' 2>/dev/null || true)"
if [ "$kb" = available ]; then ok "Kibana available"; else bad "Kibana status: ${kb:-unreachable}"; fi

cid="$(env_get llm_connector_id)"; cid="${cid:-Elastic-Managed-LLM}"
ctype="$(try_api GET "$KIBANA_URL/api/actions/connector/$cid" | jq -r '.connector_type_id // empty' 2>/dev/null || true)"
if [ -n "$ctype" ]; then ok "LLM connector '$cid' exists ($ctype)"; else bad "LLM connector '$cid' not found (Stack Management > Connectors)"; fi

# ---------------------------------------------------------------------------
section "3. Azure VM and Fleet"
rg="$(env_get resource_group_name)"; vmn="$(env_get vm_name)"
if ! command -v az >/dev/null 2>&1; then
  warn "az CLI not installed; VM state not checked"
elif ! az account show >/dev/null 2>&1; then
  bad "not logged in to Azure (az login); VM state unknown"
elif [ -z "$rg" ] || [ -z "$vmn" ]; then
  bad "resource_group_name/vm_name missing in shared/env.json"
else
  info "Azure subscription: $(az account show --query name -o tsv 2>/dev/null)"
  state="$(az vm get-instance-view -g "$rg" -n "$vmn" \
    --query "instanceView.statuses[?starts_with(code,'PowerState/')].code | [0]" -o tsv 2>/dev/null || true)"
  if [ "$state" = "PowerState/running" ]; then ok "VM $vmn is running"; else bad "VM $vmn state: ${state:-not found} (start it, or run terraform apply)"; fi
fi

online="$(defend_online)"
if [ "${online:-0}" -ge 1 ]; then ok "Fleet: $online online agent(s) with Elastic Defend"; else bad "Fleet: no online agent on a policy with Elastic Defend"; fi

# ---------------------------------------------------------------------------
section "4. OT synthetic telemetry"
body="$(try_api POST "$ES_URL/logs-*-ot/_search" \
  -d '{"size":0,"track_total_hits":true,"aggs":{"newest":{"max":{"field":"@timestamp"}}}}' || true)"
n_ot="$(jq -r '.hits.total.value // 0' <<<"$body" 2>/dev/null || echo 0)"
newest="$(jq -r '.aggregations.newest.value_as_string // empty' <<<"$body" 2>/dev/null || true)"
if [ "${n_ot:-0}" -ge 1000 ]; then ok "OT data streams (logs-*-ot) have $n_ot events"
else bad "OT data streams (logs-*-ot) have ${n_ot:-0} events: run scripts/inject-ot-telemetry.sh"; fi
[ -n "$newest" ] && info "newest synthetic event: $newest (times are relative to the last inject; re-run scripts/inject-ot-telemetry.sh before the demo for a current story)"

# ---------------------------------------------------------------------------
section "5. Timelines and notes (what the lessons click through)"
tls="$(try_api GET "$KIBANA_URL/api/saved_objects/_find?type=siem-ui-timeline&per_page=1000" || true)"
if ! jq -e '.saved_objects' >/dev/null 2>&1 <<<"$tls"; then
  bad "cannot list timelines via the saved objects API"
  tls='{"saved_objects":[]}'
fi

seed="$(cat "$CONFIG_DIR"/timelines/*.ndjson 2>/dev/null | jq -s '[.[] | select(type=="object" and .title != null)]' 2>/dev/null || echo '[]')"
exp_tmpl="$(jq '[.[] | select(.timelineType=="template")] | length' <<<"$seed")"
exp_def="$(jq '[.[] | select((.timelineType // "default")=="default")] | length' <<<"$seed")"
# Elastic ships its own immutable templates (Generic Process Timeline, ...); count only ours.
n_tmpl="$(jq '[.saved_objects[] | select(.attributes.timelineType=="template") | select(.attributes.title | startswith("TEMPLATE |"))] | length' <<<"$tls")"
n_def="$(jq '[.saved_objects[] | select((.attributes.timelineType // "default")=="default")] | length' <<<"$tls")"

compare_count() {  # compare_count <label> <have> <expected>
  if [ "$2" -eq "$3" ]; then ok "$1: $2 (matches the seed files)"
  elif [ "$2" -lt "$3" ]; then bad "$1: $2, seed files define $3 (run scripts/load-timelines.sh)"
  else warn "$1: $2, seed files define $3: extra timelines from rehearsal? (scripts/demo-reset.sh --yes)"; fi
}
compare_count "timeline templates" "$n_tmpl" "$exp_tmpl"
compare_count "default timelines" "$n_def" "$exp_def"

chk() {  # chk <template|default> <title regex> <min> <label>
  local n
  n="$(jq --arg t "$1" --arg re "$2" '[.saved_objects[] | select((.attributes.timelineType // "default")==$t)
      | select(.attributes.title | test($re;"i"))] | length' <<<"$tls")"
  if [ "${n:-0}" -ge "$3" ]; then ok "$4 (found $n)"; else bad "$4 (found ${n:-0}, need $3)"; fi
}
chk template 'controller writes'           1 "lesson 2/6: controller writes hunt template (T0836)"
chk template 'remote access'               1 "lesson 6: remote access hunt template (T0886)"
chk template 'scan of OT controllers'      1 "lesson 6: scan hunt template (T0846)"
chk template 'removable media'             1 "lesson 6: removable media hunt template (T0847)"
chk template 'OT alert'                    1 "lesson 6: OT alert template"
chk default  'Modbus writes.*Closed - True Positive.*TLP:AMBER' 1 "lesson 3: worked example investigation (Modbus writes)"
chk default  'C2 egress.*Closed - Clean'                       1 "lesson 4: clean negative-result hunt"
chk default  'Handover'                    1 "lesson 5: search 'Handover' returns 1 or more"
chk default  'CLIENT-B.*T0858.*Accepted Behaviour'             1 "lesson 5: accepted-behaviour hunt (engineering software sessions)"
chk default  'CLIENT-C.*unknown device scanning.*Open - Handover' 1 "lesson 5: open handover (unknown device scan)"
chk default  'TLP:AMBER'                   1 "lesson 5: search 'TLP:AMBER' returns results"

# Per-timeline contents: notes have the contract sections, no unresolved tokens, pins exist.
need_sections='Hypothesis Scope Queries Findings Handover Keywords: Report-ready summary:'
bad_notes=""; token_hits=""; with_pins=0; example_ok=""
ids="$(jq -r '.saved_objects[] | select((.attributes.timelineType // "default")=="default") | .id' <<<"$tls")"
for id in $ids; do
  t="$(try_api GET "$KIBANA_URL/api/timeline?id=$id" || true)"
  [ -n "$t" ] || { bad_notes="$bad_notes\n          - $id (could not read)"; continue; }
  # 9.5 returns the timeline at the top level; notes are in .notes (global ones have no eventId).
  title="$(jq -r '(.data.getOneTimeline // .) | .title // ""' <<<"$t")"
  gnote="$(jq -r '(.data.getOneTimeline // .) | [(.notes // [])[] | select((.eventId // "") == "") | .note] | join("\n")' <<<"$t")"
  pins="$(jq '(.data.getOneTimeline // .) | (.pinnedEventIds // []) | length' <<<"$t")"
  enotes="$(jq '(.data.getOneTimeline // .) | [(.notes // [])[] | select((.eventId // "") != "")] | length' <<<"$t")"
  [ "${pins:-0}" -ge 1 ] && with_pins=$((with_pins+1))
  missing=""
  for s in $need_sections; do
    grep -q -- "$s" <<<"$gnote" || missing="$missing $s"
  done
  [ -z "$missing" ] || bad_notes="$bad_notes\n          - $title: missing$missing"
  if grep -q '__[A-Z_]*__' <<<"$title$gnote"; then token_hits="$token_hits\n          - $title"; fi
  if grep -q 'Modbus writes' <<<"$title" && [ "${pins:-0}" -ge 3 ] && [ "${enotes:-0}" -ge 1 ]; then example_ok="$title ($pins pins, $enotes event notes)"; fi
done
if [ "$n_def" -eq 0 ]; then
  info "no default timelines to inspect; note and token checks skipped"
else
  if [ -z "$bad_notes" ]; then ok "every default timeline has a global note with the contract sections"
  else bad "global notes missing contract sections:$(printf '%b' "$bad_notes")"; fi
  if [ -z "$token_hits" ]; then ok "no unresolved __TOKENS__ in titles or notes"
  else bad "unresolved __TOKENS__ (re-run scripts/load-timelines.sh after the attack):$(printf '%b' "$token_hits")"; fi
fi
if [ -n "$example_ok" ]; then ok "lesson 3: example investigation has pins and event notes: $example_ok"
else bad "lesson 3: example investigation has fewer than 3 pins or no event notes (re-run scripts/load-timelines.sh)"; fi
if [ "$with_pins" -ge 4 ]; then ok "$with_pins timelines have pinned events"; else warn "only $with_pins timelines have pinned events (seed defines 4)"; fi

# ---------------------------------------------------------------------------
section "6. Situation report pipeline"
if try_api GET "$ES_URL/situation-reports" >/dev/null; then ok "index situation-reports exists"; else bad "index situation-reports missing (scripts/configure-reports.sh)"; fi

wf_id="$(env_get workflow_id)"
if [ -z "$wf_id" ]; then
  bad "no workflow_id in shared/env.json (scripts/configure-reports.sh not run, or the workflow needs a manual install)"
elif try_api GET "$KIBANA_URL/api/workflows/workflow/$wf_id" >/dev/null; then
  ok "workflow 'Weekly Situation Report' exists (id $wf_id)"
else
  bad "workflow $wf_id in shared/env.json not found in Kibana"
fi

if try_api GET "$KIBANA_URL/api/agent_builder/agents/situation-report-analyst" >/dev/null; then ok "agent situation-report-analyst exists"; else bad "agent situation-report-analyst missing"; fi
for f in "$CONFIG_DIR"/agent-builder/tools/*.json; do
  tid="$(jq -r '.id' "$f")"
  if try_api GET "$KIBANA_URL/api/agent_builder/tools/$tid" >/dev/null; then ok "agent tool $tid exists"; else bad "agent tool $tid missing"; fi
done

check_report() {
  rep="$(try_api POST "$ES_URL/situation-reports/_search" \
    -d '{"size":1,"sort":[{"generated_at":"desc"}],"query":{"term":{"no_data":false}}}' || true)"
  n_rep="$(jq '.hits.hits | length' <<<"$rep" 2>/dev/null || true)"
  if [ "${n_rep:-0}" -ge 1 ]; then
    gen="$(jq -r '.hits.hits[0]._source.generated_at // ""' <<<"$rep")"
    tlp="$(jq -r '.hits.hits[0]._source.tlp // ""' <<<"$rep")"
    ok "fallback report exists (generated $gen, $tlp)"
    # Sources must still exist as timelines, or the report cites records that are gone.
    gone=""
    while IFS= read -r s; do
      [ -n "$s" ] || continue
      jq -e --arg s "$s" '[.saved_objects[].attributes.title] | index($s)' <<<"$tls" >/dev/null 2>&1 || gone="$gone\n          - $s"
    done < <(jq -r '.hits.hits[0]._source.sources[]?' <<<"$rep")
    if [ -z "$gone" ]; then ok "every source timeline in the report still exists"
    else warn "report cites timelines that no longer exist (regenerate with scripts/run-report.sh):$(printf '%b' "$gone")"; fi
  else
    bad "no fallback report: run scripts/run-report.sh once before the demo (REPORT_PERIOD_DAYS=30 via configure-reports.sh)"
  fi
}

# With --full the report is generated in section 7, so check it there.
[ "$FULL" = true ] || check_report

# ---------------------------------------------------------------------------
if [ "$FULL" = true ]; then
  section "7. End to end (--full)"
  if "$PROJECT_ROOT/scripts/run-report.sh" >/dev/null 2>"$RESULTS_DIR/.demo-check-run.err"; then
    ok "workflow ran to completion and wrote a new report"
    check_report
  else
    bad "run-report.sh failed: $(tail -n 3 "$RESULTS_DIR/.demo-check-run.err" | tr '\n' ' ')"
  fi
  rm -f "$RESULTS_DIR/.demo-check-run.err"
  if "$PROJECT_ROOT/scripts/validate.sh" >/dev/null 2>&1; then ok "scripts/validate.sh passed"
  else bad "scripts/validate.sh reported FAIL (run it directly for details)"; fi
fi

# ---------------------------------------------------------------------------
section "Manual checks (cannot be scripted)"
info "Kibana > Elastic Inference Service > Region preferences: Geographies = eu"
info "Click through each Show step once; UI wording was written against 9.5.3 but not verified"
info "Synthetic data statement on screen at the start"
info "Keep scripts/run-report.sh output ready in case the live LLM call stalls"

echo
echo "RESULT: $passes passed, $fails failed, $warns warnings"
if [ "$fails" -gt 0 ]; then echo "NOT READY"; exit 1; fi
if [ "$warns" -gt 0 ]; then echo "READY WITH WARNINGS"; else echo "READY"; fi
