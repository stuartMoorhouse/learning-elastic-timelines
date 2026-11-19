#!/usr/bin/env bash
# Check the acceptance criteria from .claude/spec/spec.md that can be scripted.
# Writes results/validate-<timestamp>.json and prints PASS/FAIL/MANUAL per criterion.
# Exit code is 1 if any criterion is FAIL.
#
# Env overrides:
#   HIST_TITLE_REGEX  regex for historical timeline titles (default: ^[0-9]{4}-[0-9]{2}-[0-9]{2})
#   MIN_RULES         distinct alerting rules required (default 5)
#
# Criteria 1-9 are the original demo criteria. 10-12 cover situation reports:
#   10 situation-reports index has a report with a TLP header and sources
#   11 Agent Builder agent exists and answers a question from the report
#   12 Elastic Managed LLM connector exists
#   14 EU region preference set for EIS (MANUAL)
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd jq curl
load_env

# Not ${VAR:-default}: the } inside {4} would end the expansion early.
HIST_TITLE_REGEX="${HIST_TITLE_REGEX:-}"
[ -n "$HIST_TITLE_REGEX" ] || HIST_TITLE_REGEX='^[0-9]{4}-[0-9]{2}-[0-9]{2}'
MIN_RULES="${MIN_RULES:-5}"
mkdir -p "$RESULTS_DIR"
out="$RESULTS_DIR/validate-$(date -u +%Y%m%dT%H%M%SZ).json"

results='[]'
any_fail=0
record() {  # record <n> <PASS|FAIL|MANUAL> <description> <detail>
  results="$(jq -c --argjson n "$1" --arg s "$2" --arg d "$3" --arg x "$4" \
    '. + [{criterion:$n,status:$s,description:$d,detail:$x}]' <<<"$results")"
  printf '%-6s %d. %s%s\n' "$2" "$1" "$3" "${4:+ ($4)}"
  [ "$2" = FAIL ] && any_fail=1
  return 0
}

# --- 1. Cluster healthy, 9.x, ML node, Kibana available -------------------
c1_detail=""; c1=PASS
info="$(try_api GET "$ES_URL/" || true)"
ver="$(jq -r '.version.number // empty' <<<"$info" 2>/dev/null || true)"
health="$(try_api GET "$ES_URL/_cluster/health" | jq -r '.status // empty' 2>/dev/null || true)"
ml_nodes="$(try_api GET "$ES_URL/_nodes?filter_path=nodes.*.roles" | jq '[.nodes[]? | select(.roles | index("ml"))] | length' 2>/dev/null || echo 0)"
kb="$(try_api GET "$KIBANA_URL/api/status" | jq -r '.status.overall.level // empty' 2>/dev/null || true)"
c1_detail="version=${ver:-?} health=${health:-?} ml_nodes=${ml_nodes:-0} kibana=${kb:-?}"
case "$ver" in 9.*) ;; *) c1=FAIL ;; esac
{ [ "$health" = green ] || [ "$health" = yellow ]; } || c1=FAIL
[ "${ml_nodes:-0}" -ge 1 ] || c1=FAIL
[ "$kb" = available ] || c1=FAIL
record 1 "$c1" "Elastic Cloud healthy, 9.x, ML node present, Kibana available (RAM sizing: check terraform plan)" "$c1_detail"

# --- 2. Fleet agent healthy with Elastic Defend ----------------------------
agents="$(try_api GET "$KIBANA_URL/api/fleet/agents?perPage=100" || true)"
pkgs="$(try_api GET "$KIBANA_URL/api/fleet/package_policies?perPage=100" || true)"
defend_policies="$(jq -c '[.items[]? | select(.package.name=="endpoint") | (.policy_ids // [.policy_id])[]] | unique' <<<"$pkgs" 2>/dev/null || echo '[]')"
healthy_defend="$(jq --argjson dp "${defend_policies:-[]}" \
  '[.items[]? | select(.status=="online") | select(.policy_id as $p | $dp | index($p))] | length' <<<"$agents" 2>/dev/null || echo 0)"
if [ "${healthy_defend:-0}" -ge 1 ]; then
  record 2 PASS "Elastic Agent Healthy in Fleet with Elastic Defend" "healthy agents on Defend policy: $healthy_defend"
else
  record 2 FAIL "Elastic Agent Healthy in Fleet with Elastic Defend" "no online agent on a policy with the endpoint package"
fi

# --- 3. >= MIN_RULES distinct rules alerted --------------------------------
body="$(try_api POST "$ES_URL/.alerts-security.alerts-*/_search" \
  -d '{"size":0,"aggs":{"rules":{"terms":{"field":"kibana.alert.rule.name","size":200}}}}' || true)"
n_rules="$(jq '[.aggregations.rules.buckets[]?] | length' <<<"$body" 2>/dev/null || echo 0)"
if [ "${n_rules:-0}" -ge "$MIN_RULES" ]; then
  record 3 PASS "At least $MIN_RULES distinct prebuilt detection alerts" "distinct rules: $n_rules"
else
  record 3 FAIL "At least $MIN_RULES distinct prebuilt detection alerts" "distinct rules: ${n_rules:-0} (run scripts/attack.sh)"
fi

# --- 4. Re-runnable, same alert set (needs two runs) -----------------------
record 4 MANUAL "Script re-runnable with the same alert set each run" \
  "run scripts/reset-demo.sh then scripts/attack.sh twice and compare the rule lists printed"

# --- Timelines (5, 6, 7) ---------------------------------------------------
tls="$(try_api GET "$KIBANA_URL/api/saved_objects/_find?type=siem-ui-timeline&per_page=1000" || true)"
have_tls=true
jq -e '.saved_objects' >/dev/null 2>&1 <<<"$tls" || have_tls=false

if [ "$have_tls" = true ]; then
  n_tmpl="$(jq '[.saved_objects[] | select(.attributes.timelineType=="template")] | length' <<<"$tls")"
  tmpl_apt="$(jq '[.saved_objects[] | select(.attributes.timelineType=="template") | select(.attributes.title | test("apt29|OT alert";"i"))] | length' <<<"$tls")"
  if [ "$tmpl_apt" -ge 1 ]; then
    record 5 PASS "Alert-driven timeline template exists (applying it to an alert is a manual UI check)" "templates: $n_tmpl, APT29: $tmpl_apt"
  else
    record 5 FAIL "Alert-driven timeline template exists" "templates: $n_tmpl, none titled APT29 or OT alert"
  fi

  # 13: alert-free hunt template(s) exist (applying one without an alert is a manual UI check)
  n_hunt="$(jq '[.saved_objects[] | select(.attributes.timelineType=="template") | select(.attributes.title | test("hunt";"i"))] | length' <<<"$tls")"
  if [ "$n_hunt" -ge 1 ]; then
    record 13 PASS "Alert-free hunt template exists (applying it without an alert is a manual UI check)" "hunt templates: $n_hunt"
  else
    record 13 FAIL "Alert-free hunt template exists" "no template titled with 'hunt' (run scripts/load-timelines.sh)"
  fi

  # 6: some default timeline with pinned events and notes
  ids="$(jq -r '.saved_objects[] | select((.attributes.timelineType // "default")=="default") | .id' <<<"$tls")"
  example=""
  for id in $ids; do
    t="$(try_api GET "$KIBANA_URL/api/timeline?id=$id" || true)"
    # 9.5 returns the timeline at the top level, with all notes in .notes.
    pins="$(jq '(.data.getOneTimeline // .) | (.pinnedEventIds // []) | length' <<<"$t" 2>/dev/null || echo 0)"
    notes="$(jq '(.data.getOneTimeline // .) | (.notes // []) | length' <<<"$t" 2>/dev/null || echo 0)"
    if [ "${pins:-0}" -ge 1 ] && [ "${notes:-0}" -ge 1 ]; then
      example="$(jq -r '(.data.getOneTimeline // .) | .title' <<<"$t")"; break
    fi
  done
  if [ -n "$example" ]; then
    record 6 PASS "Example investigated timeline with pinned events and notes" "$example"
  else
    record 6 FAIL "Example investigated timeline with pinned events and notes" \
      "none found; if alerts did not exist at import time, run attack.sh then load-timelines.sh"
  fi

  n_hist="$(jq --arg re "$HIST_TITLE_REGEX" \
    '[.saved_objects[] | select((.attributes.timelineType // "default")=="default") | select(.attributes.title | test($re))] | length' <<<"$tls")"
  n_tlp="$(jq '[.saved_objects[] | select((.attributes.timelineType // "default")=="default")
      | select(.attributes.title | test("\\| TLP:(CLEAR|GREEN|AMBER\\+STRICT|AMBER|RED)$"))] | length' <<<"$tls")"
  if [ "$n_hist" -ge 5 ]; then
    record 7 PASS "At least 5 historical timelines following the naming convention (keywords: check in UI)" "matching '$HIST_TITLE_REGEX': $n_hist, with trailing '| TLP:<colour>': $n_tlp"
  else
    record 7 FAIL "At least 5 historical timelines following the naming convention" "matching '$HIST_TITLE_REGEX': $n_hist"
  fi
else
  for n in 5 6 7 13; do record "$n" FAIL "Timeline checks" "could not list timelines via saved objects API"; done
fi

# --- 8. NSG: RDP only from presenter IP ------------------------------------
rg="$(env_get resource_group_name)"
if ! command -v az >/dev/null 2>&1 || [ -z "$rg" ]; then
  record 8 MANUAL "RDP reachable only from presenter IP" "az CLI or resource_group_name unavailable; check the NSG in the portal"
else
  rules="$(az network nsg list -g "$rg" -o json 2>/dev/null | jq -c '[.[].securityRules[]?]' 2>/dev/null || true)"
  if [ -z "$rules" ]; then
    record 8 FAIL "RDP reachable only from presenter IP" "could not read NSG rules (az login?)"
  else
    rdp="$(jq -c '[.[] | select(.direction=="Inbound" and .access=="Allow")
        | select((.destinationPortRange // "") as $p | ($p=="3389" or $p=="*" or $p=="3000-4000")
                 or ((.destinationPortRanges // []) | index("3389")))]' <<<"$rules")"
    n_rdp="$(jq 'length' <<<"$rdp")"
    open="$(jq '[.[] | ([.sourceAddressPrefix] + (.sourceAddressPrefixes // []))[]
        | select(. != null and . != "") | select(. == "*" or . == "0.0.0.0/0" or . == "Internet" or . == "Any" or (test("/32$") | not))] | length' <<<"$rdp")"
    want=""
    for f in "$TF_DIR/terraform.tfvars" "$PROJECT_ROOT/terraform.tfvars"; do
      [ -f "$f" ] && want="$(sed -n 's/^[[:space:]]*presenter_ip_cidr[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' "$f" | head -1)" && break
    done
    want="${want:-${TF_VAR_presenter_ip_cidr:-}}"
    mismatch=0
    if [ -n "$want" ]; then
      mismatch="$(jq --arg w "$want" '[.[] | ([.sourceAddressPrefix] + (.sourceAddressPrefixes // []))[]
          | select(. != null and . != "") | select(. != $w)] | length' <<<"$rdp")"
    fi
    if [ "$n_rdp" -ge 1 ] && [ "$open" -eq 0 ] && [ "$mismatch" -eq 0 ]; then
      record 8 PASS "RDP reachable only from presenter IP" "allow rules: $n_rdp, source ${want:-/32 only}"
    else
      record 8 FAIL "RDP reachable only from presenter IP" "allow rules: $n_rdp, open/non-/32 sources: $open, differing from tfvars: $mismatch"
    fi
  fi
fi

# --- 9. Destroy ------------------------------------------------------------
record 9 MANUAL "terraform destroy removes everything cleanly" "run scripts/destroy.sh, then 'az group list' and the Elastic Cloud console"

# --- 10. Situation report generated, with TLP header and sources -----------
rep="$(try_api POST "$ES_URL/situation-reports/_search" \
  -d '{"size":1,"sort":[{"generated_at":"desc"}],"query":{"term":{"no_data":false}}}' || true)"
n_rep="$(jq '.hits.hits | length' <<<"$rep" 2>/dev/null || echo 0)"
if [ "${n_rep:-0}" -ge 1 ]; then
  tlp="$(jq -r '.hits.hits[0]._source.tlp // empty' <<<"$rep")"
  n_src="$(jq '(.hits.hits[0]._source.sources // []) | length' <<<"$rep")"
  first="$(jq -r '.hits.hits[0]._source.body // ""' <<<"$rep" | grep -m1 -o 'TLP:[A-Z+]*' || true)"
  rtitle="$(jq -r '.hits.hits[0]._source.title // ""' <<<"$rep")"
  if [ -n "$tlp" ] && [ -n "$first" ] && [ "${n_src:-0}" -ge 1 ]; then
    record 10 PASS "Situation report generated with TLP header and sources" "$rtitle, $tlp, sources: $n_src"
  else
    record 10 FAIL "Situation report generated with TLP header and sources" "tlp='${tlp:-}' body marker='${first:-}' sources=${n_src:-0}"
  fi
else
  record 10 FAIL "Situation report generated with TLP header and sources" "no report in situation-reports (run scripts/configure-reports.sh then scripts/run-report.sh)"
fi

# --- 11. Agent Builder agent answers from the report -----------------------
agent_id="situation-report-analyst"
if ! try_api GET "$KIBANA_URL/api/agent_builder/agents/$agent_id" >/dev/null; then
  record 11 FAIL "Agent Builder agent exists and answers from the report" "agent $agent_id not found (run scripts/configure-reports.sh, or create it in the UI)"
else
  q="Which TLP marking does the latest situation report carry, and which timelines are its sources?"
  cid="$(env_get llm_connector_id)"
  ans=""
  for body in \
    "$(jq -nc --arg i "$q" --arg a "$agent_id" --arg c "$cid" '{input:$i,agent_id:$a} + (if $c=="" then {} else {connector_id:$c} end)')" \
    "$(jq -nc --arg i "$q" --arg a "$agent_id" '{input:$i,agent_id:$a}')"; do
    ans="$(try_api POST "$KIBANA_URL/api/agent_builder/converse" -d "$body" || true)"
    [ -n "$ans" ] && break
  done
  text="$(jq -r '(.response.message // .response // .message // empty) | if type=="string" then . else tojson end' <<<"$ans" 2>/dev/null || true)"
  if [ -z "$ans" ]; then
    record 11 MANUAL "Agent Builder agent answers from the report" "agent exists but the converse call failed; ask the agent in Kibana: '$q'"
  elif grep -qi 'TLP' <<<"$text"; then
    record 11 PASS "Agent Builder agent exists and answers from the report" "answer mentions TLP ($(printf '%s' "$text" | wc -c | tr -d ' ') chars)"
  else
    record 11 FAIL "Agent Builder agent exists and answers from the report" "answer did not mention a TLP marking: $(printf '%s' "$text" | head -c 200)"
  fi
fi

# --- 12. Elastic Managed LLM connector exists ------------------------------
cid="$(env_get llm_connector_id)"
[ -n "$cid" ] || cid="Elastic-Managed-LLM"
con="$(try_api GET "$KIBANA_URL/api/actions/connector/$cid" || true)"
ctype="$(jq -r '.connector_type_id // empty' <<<"$con" 2>/dev/null || true)"
if [ -n "$ctype" ]; then
  record 12 PASS "Elastic Managed LLM connector exists (test call: ask the agent in Kibana)" "id=$cid, type=$ctype"
else
  record 12 FAIL "Elastic Managed LLM connector exists" "connector '$cid' not found (Stack Management > Connectors)"
fi

# --- 14. EU region preference (MANUAL) -------------------------------------
record 14 MANUAL "EIS inference restricted to EU" "Kibana > Elastic Inference Service > Region preferences: Geographies = eu; confirm the model's inference regions on the EIS supported-models page"

jq -n --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson r "$results" '{timestamp:$ts,results:$r}' > "$out"
echo
echo "Results written to ${out#"$PROJECT_ROOT"/}"
[ "$any_fail" -eq 0 ] || exit 1
