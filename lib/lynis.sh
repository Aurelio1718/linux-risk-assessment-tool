#!/usr/bin/env bash
#
# lib/lynis.sh - Lynis module: runs an audit and turns its report into findings.
#
# Lynis writes a machine-readable report made of key=value lines.
# This module only uses:
#   warning[]=TEST-ID|text|details|solution|
#   suggestion[]=TEST-ID|text|details|solution|
#   lynis_version=...
#   hardening_index=...
#
# Depends on lib/common.sh (info, die, require_cmd, add_finding, WORK_DIR).

# Set by run_lynis; used later in the Markdown report header.
LYNIS_VERSION=""
LYNIS_HARDENING_INDEX=""

#######################################
# Print the value of a key=value line from a Lynis report.
# Arguments:
#   $1 - key (e.g. hardening_index)
#   $2 - report file
# Outputs:
#   The value to stdout, or nothing if the key is missing.
#######################################
lynis_report_value() {
  # -m1 stops at the first match; cut -f2- keeps everything after the
  # first '=' in case the value itself contains one.
  # A missing key is not an error: grep exits 1, pipefail propagates it,
  # `|| true` absorbs it.
  grep -m1 "^$1=" "$2" | cut -d= -f2- || true
}

#######################################
# Run a Lynis audit and record its warnings and suggestions.
# Globals:
#   WORK_DIR (read)
#   LYNIS_VERSION, LYNIS_HARDENING_INDEX (set)
#######################################
run_lynis() {
  require_cmd lynis --skip-lynis

  # Our own report and log inside WORK_DIR: independent of the daily
  # lynis.timer, and the system files under /var/log stay untouched.
  local report="${WORK_DIR}/lynis-report.dat"
  local log="${WORK_DIR}/lynis.log"

  info "Running Lynis audit (takes 1-2 minutes)..."
  # --cronjob: non-interactive, no colours, no pauses.
  # stdout is discarded: we read the report file, not the screen output.
  lynis audit system --cronjob --report-file "$report" --log-file "$log" \
    >/dev/null || die "Lynis audit failed (exit status $?)"

  LYNIS_VERSION="$(lynis_report_value lynis_version "$report")"
  LYNIS_HARDENING_INDEX="$(lynis_report_value hardening_index "$report")"
  info "Lynis ${LYNIS_VERSION}, hardening index ${LYNIS_HARDENING_INDEX}"

  parse_lynis_report "$report"
}

#######################################
# Turn the warning[] and suggestion[] lines of a Lynis report into findings.
# Each finding keeps its kind (warning or suggestion): lib/reconcile.sh
# uses it to merge a warning with the suggestions of the same test.
# Default scores, used when the test ID is not in data/scores.txt:
#   warning    -> impact 3, likelihood 3
#   suggestion -> impact 2, likelihood 2
# Arguments:
#   $1 - report file
#######################################
parse_lynis_report() {
  local report="$1"
  local line kind rest id text details impact likelihood

  while IFS= read -r line; do
    # "warning[]=PKGS-7392|text|details|solution|"
    #  ^^^^^^^ kind        ^^^^^^^^^^^^^^^^^^^^^^^^^ rest
    kind="${line%%'[]='*}"
    rest="${line#*=}"
    # The solution field is not used: it goes into `_` together with the
    # trailing '|'. Recommended actions come from the suggestions and
    # from data/scores.txt.
    IFS='|' read -r id text details _ <<< "$rest"

    case "$kind" in
      warning)    impact=3; likelihood=3 ;;
      suggestion) impact=2; likelihood=2 ;;
      *)          continue ;;   # defensive: grep only lets these two through
    esac

    # Lynis uses "-" for "no details".
    if [[ -n $details && $details != "-" ]]; then
      text="${text} (${details})"
    fi

    add_finding lynis "$id" "$text" "$impact" "$likelihood" "$kind"
  done < <(grep -E '^(warning|suggestion)\[\]=' "$report")
}
