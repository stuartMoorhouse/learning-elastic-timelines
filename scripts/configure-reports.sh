#!/usr/bin/env bash
# Install the situation-report pieces: index, workflow, Agent Builder tools and agent.
# Idempotent: safe to re-run. Each stage is tolerant: if a Kibana API path is unavailable on this
# stack version it prints the manual UI steps and carries on. Never prints secrets.
#
# Needs: scripts/configure.sh already run (shared/env.json populated) and `terraform apply` done
# (default connector id: .anthropic-claude-5.5-sonnet-chat_completion, the preconfigured Claude Sonnet 5.5 EIS connector).
#
# Env overrides:
#   REPORT_PERIOD_DAYS  look-back window written into the workflow (default 7)
#   REPORT_MODEL        model label stored in each report (default: claude-sonnet-5.5 (Elastic Inference Service))
#   LLM_CONNECTOR_ID    use this connector id instead of the default
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd terraform jq curl sed
load_env

WF_SRC="$CONFIG_DIR/workflows/situation-report.yaml"
MAPPING="$CONFIG_DIR/report/situation-reports-mapping.json"
AB_DIR="$CONFIG_DIR/agent-builder"
for f in "$WF_SRC" "$MAPPING" "$AB_DIR/agent.json"; do
  [ -f "$f" ] || die "$f not found"
done

REPORT_PERIOD_DAYS="${REPORT_PERIOD_DAYS:-7}"
REPORT_MODEL="${REPORT_MODEL:-claude-sonnet-5.5 (Elastic Inference Service)}"
case "$REPORT_PERIOD_DAYS" in ''|*[!0-9]*) die "REPORT_PERIOD_DAYS must be a whole number of days" ;; esac

manual=()   # manual steps to print at the end
err="$(mktemp)"; trap 'rm -f "$err"' EXIT
warn() { log "WARN: $*"; }
# kbn calls die (exit) on a non-2xx response. Run it in a subshell so a failure returns non-zero
# instead, with the error text left in $err for the warning.
kbn_soft() { local m="$1" p="$2"; shift 2; ( kbn "$m" "$p" "$@" ) 2>"$err"; }

# --- 1. LLM connector id ---------------------------------------------------
# This deployment has no connector named Elastic-Managed-LLM; EIS exposes one preconfigured
# connector per model. Claude Sonnet 5.5 on EIS is the default; override with LLM_CONNECTOR_ID.
connector_id="${LLM_CONNECTOR_ID:-.anthropic-claude-5.5-sonnet-chat_completion}"
if ! try_api GET "${KIBANA_URL}/api/actions/connector/${connector_id}" >/dev/null; then
  die "connector '${connector_id}' not found. The preconfigured Elastic Managed LLM connector should exist on the deployment; check Stack Management > Connectors, or set LLM_CONNECTOR_ID to another connector id."
fi
env_set llm_connector_id "$connector_id"
log "Using LLM connector id: $connector_id"
manual+=("Restrict inference to EU: Kibana > Elastic Inference Service > Region preferences > Restrict inference to specific locations (9.5), Geographies = eu, Save. Needs Inference Endpoints: all and manage_inference. Then confirm the model's inference regions on the EIS supported-models page.")

# --- 2. situation-reports index -------------------------------------------
if try_api GET "$ES_URL/situation-reports" >/dev/null; then
  log "Index situation-reports already exists"
else
  log "Creating index situation-reports"
  es PUT /situation-reports -d @"$MAPPING" >/dev/null || die "could not create index situation-reports"
fi
# Add the keyword and filter fields to an index created before they existed (adding mappings is idempotent).
es PUT /situation-reports/_mapping -d '{"properties":{"keywords":{"type":"keyword"},"filter_client":{"type":"keyword"},"filter_keywords":{"type":"keyword"}}}' >/dev/null \
  || warn "could not add keyword fields to the situation-reports mapping"

# Data view over the index, for Discover, Lens and dashboards (idempotent).
"$(dirname "$0")/create-report-data-view.sh" || warn "could not create the Situation reports data view (scripts/create-report-data-view.sh)"

# --- 3. Workflow -----------------------------------------------------------
mkdir -p "$RESULTS_DIR"
rendered="$RESULTS_DIR/situation-report.rendered.yaml"
sed -e "s|__CONNECTOR_ID__|${connector_id}|g" \
    -e "s|__MODEL__|${REPORT_MODEL}|g" \
    -e "s|__PERIOD_DAYS__|${REPORT_PERIOD_DAYS}|g" "$WF_SRC" > "$rendered"
wf_body="$(jq -n --rawfile y "$rendered" '{yaml:$y}')"

install_workflow() {
  local wf_id resp
  wf_id="$(env_get workflow_id)"

  if [ -n "$wf_id" ] && try_api GET "$KIBANA_URL/api/workflows/workflow/$wf_id" >/dev/null; then
    if kbn_soft PUT "/api/workflows/workflow/$wf_id" -d "$wf_body" >/dev/null; then
      log "Workflow updated (id $wf_id)"; return 0
    fi
    warn "workflow update failed: $(head -c 300 "$err")"; return 1
  fi

  # Not in env.json: look for one with the same name before creating.
  resp="$(try_api GET "$KIBANA_URL/api/workflows?size=100" || true)"
  wf_id="$(jq -r '((.results // .workflows // .items // .data // .) | if type=="array" then . else [] end)
                  | map(select(.name=="Weekly Situation Report")) | .[0].id // empty' <<<"$resp" 2>/dev/null || true)"
  if [ -n "$wf_id" ]; then
    if kbn_soft PUT "/api/workflows/workflow/$wf_id" -d "$wf_body" >/dev/null; then
      env_set workflow_id "$wf_id"; log "Existing workflow updated (id $wf_id)"; return 0
    fi
    warn "workflow update failed: $(head -c 300 "$err")"; return 1
  fi

  if resp="$(kbn_soft POST /api/workflows/workflow -d "$wf_body")"; then
    wf_id="$(jq -r '.id // .workflow.id // empty' <<<"$resp" 2>/dev/null || true)"
    if [ -n "$wf_id" ]; then env_set workflow_id "$wf_id"; log "Workflow created (id $wf_id)"; return 0; fi
    warn "workflow created but no id found in the response"; return 1
  fi
  warn "workflow create failed: $(head -c 300 "$err")"
  return 1
}

if ! install_workflow; then
  manual+=("Workflow: open Kibana > Workflows > Create, paste ${rendered#"$PROJECT_ROOT"/}, save, then put its id in shared/env.json as workflow_id and re-run this script.")
fi
workflow_id="$(env_get workflow_id)"

# --- 4. Agent Builder tools and agent --------------------------------------
# Delete-then-create keeps this idempotent without depending on the PUT payload shape.
ab_upsert() {  # ab_upsert <tools|agents> <id> <json body>
  local kind="$1" id="$2" body="$3"
  if try_api GET "$KIBANA_URL/api/agent_builder/$kind/$id" >/dev/null; then
    kbn_soft DELETE "/api/agent_builder/$kind/$id" >/dev/null || { warn "$kind/$id delete failed: $(head -c 200 "$err")"; return 1; }
  fi
  if kbn_soft POST "/api/agent_builder/$kind" -d "$body" >/dev/null; then
    log "Agent Builder $kind/$id installed"; return 0
  fi
  warn "$kind/$id create failed: $(head -c 300 "$err")"
  return 1
}

# Remove the agent first: Agent Builder refuses to delete a tool that an agent still uses.
old_agent_id="$(jq -r '.id' "$AB_DIR/agent.json")"
if try_api GET "$KIBANA_URL/api/agent_builder/agents/$old_agent_id" >/dev/null; then
  kbn_soft DELETE "/api/agent_builder/agents/$old_agent_id" >/dev/null \
    || warn "agents/$old_agent_id delete failed: $(head -c 200 "$err")"
fi

ab_ok=true
tool_ids=()
for f in "$AB_DIR"/tools/*.json; do
  tid="$(jq -r '.id' "$f")"
  body="$(cat "$f")"
  if [ "$tid" = "generate-situation-report" ]; then
    if [ -z "$workflow_id" ]; then
      warn "no workflow id; skipping tool $tid (agent can still read reports)"; continue
    fi
    body="${body//__WORKFLOW_ID__/$workflow_id}"
  fi
  if ab_upsert tools "$tid" "$body"; then tool_ids+=("$tid"); else ab_ok=false; fi
done

if [ "${#tool_ids[@]}" -gt 0 ]; then
  # The agent only lists tools that were installed.
  base="$(jq --argjson ids "$(printf '%s\n' "${tool_ids[@]}" | jq -R . | jq -sc .)" \
          '.configuration.tools = [{tool_ids: $ids}]' "$AB_DIR/agent.json")"
  agent_id="$(jq -r '.id' <<<"$base")"
  # access_control (9.5+) -> visibility (9.4) -> neither (agent stays private)
  variants=("$base"
            "$(jq 'del(.access_control) | .visibility = "shared"' <<<"$base")"
            "$(jq 'del(.access_control)' <<<"$base")")
  agent_done=false
  for v in "${variants[@]}"; do
    if ab_upsert agents "$agent_id" "$v"; then agent_done=true; break; fi
  done
  [ "$agent_done" = true ] || ab_ok=false
else
  ab_ok=false
fi

if [ "$ab_ok" != true ]; then
  manual+=("Agent Builder: in Kibana > Agent Builder, create tools and the 'Situation Report Analyst' agent from config/agent-builder/ (agent.json instructions, tools/*.json). If the workflow tool type is unsupported, drop generate-situation-report and run scripts/run-report.sh instead.")
fi

# --- 5. Summary ------------------------------------------------------------
if [ "${#manual[@]}" -eq 0 ]; then
  env_set reports_ready true json
  echo "CONFIGURE-REPORTS COMPLETE: index, workflow and agent installed. Next: scripts/run-report.sh"
else
  env_set reports_ready false json
  echo "CONFIGURE-REPORTS PARTIAL: some stages need manual steps:"
  printf '  - %s\n' "${manual[@]}"
fi
