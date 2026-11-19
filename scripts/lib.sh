#!/usr/bin/env bash
# Common helpers. Source this file; do not execute it.
# shellcheck shell=bash

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/shared/env.json"
TF_DIR="${PROJECT_ROOT}/terraform"
CONFIG_DIR="${PROJECT_ROOT}/config"
RESULTS_DIR="${PROJECT_ROOT}/results"

log()  { printf '[%s] %s\n' "$(basename "$0")" "$*" >&2; }
die()  { printf '[%s] ERROR: %s\n' "$(basename "$0")" "$*" >&2; exit 1; }

require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"
  done
}

# env.json accessors
env_get() { jq -r --arg k "$1" '.[$k] // empty' "$ENV_FILE" 2>/dev/null; }

env_set() {
  # env_set key value [json]   (third arg "json" stores value as raw JSON, e.g. true)
  local tmp
  [ -f "$ENV_FILE" ] || echo '{}' > "$ENV_FILE"
  tmp="$(mktemp)"
  if [ "${3:-}" = "json" ]; then
    jq --arg k "$1" --argjson v "$2" '.[$k] = $v' "$ENV_FILE" > "$tmp"
  else
    jq --arg k "$1" --arg v "$2" '.[$k] = $v' "$ENV_FILE" > "$tmp"
  fi
  mv "$tmp" "$ENV_FILE"
}

tf_out() { terraform -chdir="$TF_DIR" output -raw "$1" 2>/dev/null || true; }

# Load connection details from shared/env.json. Run configure.sh first to populate it.
load_env() {
  require_cmd jq curl
  [ -f "$ENV_FILE" ] || die "$ENV_FILE not found; run scripts/configure.sh first"
  ES_URL="$(env_get elasticsearch_url)"
  KIBANA_URL="$(env_get kibana_url)"
  API_KEY="$(env_get api_key)"
  ES_URL="${ES_URL%/}"
  KIBANA_URL="${KIBANA_URL%/}"
  [ -n "$ES_URL" ] && [ -n "$KIBANA_URL" ] || die "elasticsearch_url/kibana_url empty in $ENV_FILE; run scripts/configure.sh"
  [ -n "$API_KEY" ] || die "api_key empty in $ENV_FILE; run scripts/configure.sh"
}

# curl wrapper: api METHOD URL [curl args...]; prints body, fails with clear error on non-2xx.
# Auth header is passed via a config on stdin so the key never appears in process args.
api() {
  local method="$1" url="$2"; shift 2
  local out code body
  out="$(printf 'header = "Authorization: ApiKey %s"\n' "$API_KEY" | \
    curl -sS --connect-timeout 10 --max-time 120 -K - -X "$method" -H 'kbn-xsrf: true' \
      -w '\n%{http_code}' "$@" "$url" 2>&1)" \
    || die "cannot reach $url (network error / endpoint unreachable)"
  code="${out##*$'\n'}"
  body="${out%$'\n'*}"
  case "$code" in
    2*) printf '%s' "$body" ;;
    *)  printf '%s\n' "$body" | head -c 1500 >&2; echo >&2
        die "$method $url returned HTTP $code" ;;
  esac
}

es()  { local m="$1" p="$2"; shift 2; api "$m" "${ES_URL}${p}" -H 'Content-Type: application/json' "$@"; }
kbn() { local m="$1" p="$2"; shift 2; api "$m" "${KIBANA_URL}${p}" -H 'Content-Type: application/json' "$@"; }

# Same as es/kbn but never dies; prints body or empty, returns curl status. Used for probes.
try_api() {
  local method="$1" url="$2"; shift 2
  printf 'header = "Authorization: ApiKey %s"\n' "$API_KEY" | \
    curl -sS --connect-timeout 10 --max-time 60 -f -K - -X "$method" -H 'kbn-xsrf: true' \
      -H 'Content-Type: application/json' "$@" "$url" 2>/dev/null
}

check_ec_api_key() {
  [ -n "${EC_API_KEY:-}" ] || die "EC_API_KEY is not set"
  local code
  code="$(printf 'header = "Authorization: ApiKey %s"\n' "$EC_API_KEY" | \
    curl -s -o /dev/null -w '%{http_code}' -K - https://api.elastic-cloud.com/api/v1/deployments)"
  [ "$code" = 200 ] || die "EC_API_KEY invalid (HTTP $code): create a new key in Elastic Cloud console > Organization > API keys, export EC_API_KEY, retry"
}

# VM run-command helper: vm_run_script <local .ps1 path> [Name=Value ...]
vm_run_script() {
  local script="$1"; shift
  local rg vm
  rg="$(env_get resource_group_name)"; vm="$(env_get vm_name)"
  [ -n "$rg" ] && [ -n "$vm" ] || die "resource_group_name/vm_name missing in $ENV_FILE; run scripts/configure.sh"
  local args=()
  if [ "$#" -gt 0 ]; then args=(--parameters "$@"); fi
  az vm run-command invoke -g "$rg" -n "$vm" --command-id RunPowerShellScript \
    --scripts @"$script" "${args[@]}" -o json
}
