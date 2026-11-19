#!/usr/bin/env bash
# Return the demo to the clean "before the demo" state so you can rehearse again.
#
# What it removes (from the deployment named in shared/env.json):
#   - ALL timelines and timeline templates, and all timeline notes (rehearsal edits, renames,
#     new pins and notes disappear)
#   - all situation reports in the situation-reports index
#   - all Kibana cases tagged situation-report
# Then it re-imports the seed timelines from config/timelines/ (scripts/load-timelines.sh).
#
# What it does NOT touch: Fleet, detection rules, the Workflow, the agent and its tools, the
# VM (unless --full), Terraform resources.
#
# Usage: scripts/demo-reset.sh [--yes] [--full] [--keep-reports] [--regenerate]
#   (no flags)       DRY RUN: show what would be removed, change nothing
#   --yes            actually do it
#   --full           also delete alerts, clean up the VM and re-run the attack (several minutes),
#                    so the pinned events point at fresh alerts
#   --keep-reports   leave reports and cases alone
#   --regenerate     run scripts/run-report.sh at the end so a fallback report exists
#
# A normal rehearsal loop: demo-reset.sh --yes --regenerate, practise, repeat.
# Finish with scripts/demo-check.sh.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
require_cmd jq curl
load_env

YES=false; FULL=false; KEEP_REPORTS=false; REGEN=false
for a in "$@"; do
  case "$a" in
    --yes) YES=true ;;
    --full) FULL=true ;;
    --keep-reports) KEEP_REPORTS=true ;;
    --regenerate) REGEN=true ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) die "unknown option: $a (try --help)" ;;
  esac
done
[ "$FULL" = false ] || require_cmd az

[ -n "$(try_api GET "$ES_URL/" || true)" ] \
  || die "cannot reach the deployment in shared/env.json (deleted, stopped, or key rejected). Run scripts/demo-check.sh for the reason."

# --- Inventory -----------------------------------------------------------------
tls="$(kbn GET '/api/saved_objects/_find?type=siem-ui-timeline&per_page=1000')"
# Only our own: every default timeline, and templates titled "TEMPLATE | ...". Elastic's prebuilt
# (immutable) templates such as "Generic Process Timeline" are left alone.
tl_ids="$(jq -c '[.saved_objects[]
  | select((.attributes.timelineType // "default")=="default" or (.attributes.title | startswith("TEMPLATE |")))
  | select((.attributes.status // "") != "immutable") | .id]' <<<"$tls")"
n_tl="$(jq 'length' <<<"$tl_ids")"
n_tmpl="$(jq '[.saved_objects[] | select(.attributes.timelineType=="template") | select(.attributes.title | startswith("TEMPLATE |"))] | length' <<<"$tls")"

n_notes="$(try_api GET "$KIBANA_URL/api/note?perPage=1000&page=1" | jq '(.notes // []) | length' 2>/dev/null || echo '?')"

n_reports=0
if try_api GET "$ES_URL/situation-reports" >/dev/null; then
  n_reports="$(try_api POST "$ES_URL/situation-reports/_count" -d '{"query":{"match_all":{}}}' | jq -r '.count // 0' 2>/dev/null || echo 0)"
fi

cases="$(try_api GET "$KIBANA_URL/api/cases/_find?tags=situation-report&perPage=100" || true)"
case_ids="$(jq -c '[.cases[]?.id]' <<<"$cases" 2>/dev/null || echo '[]')"
n_cases="$(jq 'length' <<<"${case_ids:-[]}")"

echo "Target: ${KIBANA_URL}"
echo "Will remove:"
echo "  timelines:       $n_tl (of which templates: $n_tmpl), then re-import from config/timelines/"
echo "  timeline notes:  $n_notes"
if [ "$KEEP_REPORTS" = true ]; then
  echo "  reports, cases:  kept (--keep-reports)"
else
  echo "  reports:         $n_reports document(s) in situation-reports"
  echo "  cases:           $n_cases tagged situation-report"
fi
[ "$FULL" = true ] && echo "  alerts and VM:   delete all security alerts, run APT29 cleanup on the VM, re-run the attack"

if [ "$YES" != true ]; then
  echo
  echo "DRY RUN: nothing changed. Re-run with --yes to do it."
  exit 0
fi

# --- 1. Alerts and VM (only with --full) ---------------------------------------
if [ "$FULL" = true ]; then
  log "Resetting alerts and VM"
  DELETE_ALERTS=1 "$PROJECT_ROOT/scripts/reset-demo.sh"
fi

# --- 2. Timelines and notes ----------------------------------------------------
if [ "$n_tl" -gt 0 ]; then
  log "Deleting $n_tl timelines"
  kbn DELETE /api/timeline -d "$(jq -nc --argjson ids "$tl_ids" '{savedObjectIds:$ids}')" >/dev/null \
    || die "could not delete timelines (DELETE /api/timeline); delete them in Kibana > Timelines and re-run"
fi

# Notes should go with their timeline. Remove any that are left so they cannot leak into a report.
left="$(try_api GET "$KIBANA_URL/api/note?perPage=1000&page=1" | jq -c '[(.notes // [])[].noteId]' 2>/dev/null || echo '[]')"
n_left="$(jq 'length' <<<"$left")"
if [ "$n_left" -gt 0 ]; then
  log "Removing $n_left leftover notes"
  if ! kbn DELETE /api/note -d "$(jq -nc --argjson ids "$left" '{noteIds:$ids}')" >/dev/null 2>&1; then
    for id in $(jq -r '.[]' <<<"$left"); do
      kbn DELETE /api/note -d "$(jq -nc --arg id "$id" '{noteId:$id}')" >/dev/null 2>&1 || log "WARN: could not delete note $id"
    done
  fi
fi
n_after="$(try_api GET "$KIBANA_URL/api/note?perPage=1000&page=1" | jq '(.notes // []) | length' 2>/dev/null || echo '?')"
[ "$n_after" = 0 ] || log "WARN: $n_after notes still present; delete them in Kibana or the reports may include them"

# --- 3. Reports and cases ------------------------------------------------------
if [ "$KEEP_REPORTS" != true ]; then
  if [ "$n_reports" -gt 0 ]; then
    log "Deleting $n_reports situation reports"
    es POST '/situation-reports/_delete_by_query?refresh=true&conflicts=proceed' \
      -d '{"query":{"match_all":{}}}' >/dev/null || log "WARN: could not empty situation-reports"
  fi
  if [ "$n_cases" -gt 0 ]; then
    log "Deleting $n_cases cases"
    enc="$(jq -rn --argjson a "$case_ids" '$a | tojson | @uri')"
    kbn DELETE "/api/cases?ids=${enc}" >/dev/null || log "WARN: could not delete cases; delete them in Kibana > Cases"
  fi
fi

# --- 4. Attack (only with --full), then reload seeds ---------------------------
if [ "$FULL" = true ]; then
  log "Re-running the attack"
  "$PROJECT_ROOT/scripts/attack.sh"
fi

log "Importing seed timelines"
"$PROJECT_ROOT/scripts/load-timelines.sh"

# --- 5. Fallback report --------------------------------------------------------
if [ "$REGEN" = true ]; then
  log "Generating a fallback report"
  "$PROJECT_ROOT/scripts/run-report.sh" >/dev/null || log "WARN: run-report.sh failed; run it again before the demo"
fi

echo
echo "RESET COMPLETE. Next: scripts/demo-check.sh"
[ "$REGEN" = true ] || [ "$KEEP_REPORTS" = true ] || echo "No fallback report yet: run scripts/run-report.sh (or re-run this with --regenerate)."
