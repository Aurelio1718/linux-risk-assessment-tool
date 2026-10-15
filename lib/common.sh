#!/usr/bin/env bash
#
# lib/common.sh - Shared helpers for all ra-tool modules.
#
# Provides: logging, a temporary work area, the findings store,
# risk level calculation and the final results table.
#
# Meant to be loaded with `source` by ra-tool.sh, not executed directly.
# Loading it only defines functions and variables; it has no side effects.

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
# All messages go to stderr: stdout is reserved for the results table,
# so the useful output can be redirected without mixing in log noise.

#######################################
# Print an informational, warning or error message.
# Arguments:
#   Message text (all arguments, joined by spaces).
# Outputs:
#   The message to stderr, prefixed with [*], [!] or [x].
#######################################
info() { printf '[*] %s\n' "$*" >&2; }
warn() { printf '[!] %s\n' "$*" >&2; }
err()  { printf '[x] %s\n' "$*" >&2; }

#######################################
# Print an error and exit.
# Arguments:
#   Message text.
# Returns:
#   Does not return: exits with status 1 (the EXIT trap cleans up).
#######################################
die() {
  err "$*"
  exit 1
}

#######################################
# Exit with an error if a required command is not installed.
# Arguments:
#   $1 - command name (e.g. lynis)
#   $2 - ra-tool option that skips that module (e.g. --skip-lynis)
#######################################
require_cmd() {
  command -v "$1" >/dev/null 2>&1 \
    || die "Command not found: $1 (install it or use $2)"
}

# ---------------------------------------------------------------------------
# Work area and findings store
# ---------------------------------------------------------------------------
# Each finding is one TSV line (TAB-separated fields) in FINDINGS_FILE:
#   source  id  text  impact  likelihood  risk
# Every module writes through add_finding; the table is printed once at
# the end, so sorting by risk is global across all sources.

# Initialised empty so that `set -u` does not fail in cleanup() if the
# script exits before init_findings runs.
WORK_DIR=""
FINDINGS_FILE=""

#######################################
# Create the temporary work directory and the findings file.
# Globals:
#   WORK_DIR, FINDINGS_FILE (set)
#######################################
init_findings() {
  # mktemp -d creates a randomly named directory with mode 700: reports
  # contain sensitive system details and the script runs as root.
  WORK_DIR="$(mktemp -d -t ra-tool.XXXXXX)"
  # Register cleanup right after creation: from here on, however the
  # script ends (normal exit, error, Ctrl+C), the directory is removed.
  trap cleanup EXIT
  FINDINGS_FILE="${WORK_DIR}/findings.tsv"
  : > "$FINDINGS_FILE"
}

#######################################
# Remove the temporary work directory. Called by the EXIT trap.
# Globals:
#   WORK_DIR
#######################################
cleanup() {
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR"
  fi
}

#######################################
# Record a finding.
# Globals:
#   FINDINGS_FILE
# Arguments:
#   $1 - source (lynis | rkhunter | native)
#   $2 - check ID (e.g. PKGS-7392)
#   $3 - description
#   $4 - impact, integer 1-5
#   $5 - likelihood, integer 1-5
#######################################
add_finding() {
  local src="$1" id="$2" text="$3" impact="$4" likelihood="$5"

  # A non-numeric value (e.g. a typo in scores.tsv) would make the
  # arithmetic produce nonsense: fail early with a clear message instead.
  [[ $impact =~ ^[1-5]$ && $likelihood =~ ^[1-5]$ ]] \
    || die "Invalid score for $id: I=$impact L=$likelihood (expected integers 1-5)"

  # TABs and newlines would break the line/column format of the file.
  text="${text//$'\t'/ }"
  text="${text//$'\n'/ }"
  # An empty field would shift columns when read back (see print_table).
  [[ -n $text ]] || text="(no description)"

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$src" "$id" "$text" "$impact" "$likelihood" "$(( impact * likelihood ))" \
    >> "$FINDINGS_FILE"
}

# ---------------------------------------------------------------------------
# Risk and output
# ---------------------------------------------------------------------------

#######################################
# Map a risk score (impact x likelihood, 1-25) to a level name.
# Arguments:
#   $1 - risk score
# Outputs:
#   The level to stdout: Low, Medium, High or Critical.
#######################################
risk_level() {
  local score="$1"
  if   (( score >= 16 )); then echo "Critical"
  elif (( score >= 10 )); then echo "High"
  elif (( score >= 5 ));  then echo "Medium"
  else                         echo "Low"
  fi
}

#######################################
# Print all findings as a table, highest risk first.
# Globals:
#   FINDINGS_FILE
# Outputs:
#   The table to stdout; the total count to stderr.
#######################################
print_table() {
  local count
  count="$(wc -l < "$FINDINGS_FILE")"
  if (( count == 0 )); then
    info "No findings."
    return 0
  fi

  # Fixed column widths: '-' aligns left, no '-' aligns right.
  local fmt='%-12s %-9s %-60s %2s %2s %4s  %-8s\n'
  local width=104   # sum of widths + separators, for the divider line

  # shellcheck disable=SC2059  # format is our own constant, not external input
  printf "$fmt" "ID" "Source" "Finding" "I" "L" "Risk" "Level"
  printf '%*s\n' "$width" '' | tr ' ' '-'

  local src id text impact likelihood score
  while IFS=$'\t' read -r src id text impact likelihood score; do
    # Full text goes into the Markdown report; truncate it on the terminal.
    if (( ${#text} > 60 )); then
      text="${text:0:57}..."
    fi
    # shellcheck disable=SC2059
    printf "$fmt" "$id" "$src" "$text" "$impact" "$likelihood" "$score" \
      "$(risk_level "$score")"
  done < <(sort -t $'\t' -k6,6nr -k2,2 "$FINDINGS_FILE")

  info "${count} findings in total."
}