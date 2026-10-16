#!/usr/bin/env bash
#
# lib/common.sh - Shared helpers for all ra-tool modules.
#
# Provides: logging, a temporary work area, the raw findings store,
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
# Each raw finding is one TSV line (TAB-separated fields) in FINDINGS_FILE:
#   source  id  kind  text  impact  likelihood
# Every module writes through add_finding. Raw findings are then grouped
# and scored by lib/reconcile.sh into RISKS_FILE, which the table and the
# report read: sorting by risk is global across all sources.

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
# Record a raw finding.
# Globals:
#   FINDINGS_FILE
# Arguments:
#   $1 - source (lynis | rkhunter | native)
#   $2 - check ID (e.g. PKGS-7392)
#   $3 - description, as reported by the source
#   $4 - default impact, integer 1-5
#   $5 - default likelihood, integer 1-5
#   $6 - kind (optional): warning | suggestion (Lynis); default: finding
#######################################
add_finding() {
  local src="$1" id="$2" text="$3" impact="$4" likelihood="$5"
  local kind="${6:-finding}"

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
    "$src" "$id" "$kind" "$text" "$impact" "$likelihood" >> "$FINDINGS_FILE"
}

# ---------------------------------------------------------------------------
# Risk and output
# ---------------------------------------------------------------------------

#######################################
# Map a risk score (likelihood x impact, 1-25) to a level name.
# Bands and meaning follow the course "Cybersecurity Risk Assessment"
# template:
#   Low       1-5   acceptable
#   Moderate  6-10  monitor
#   Medium   11-15  mitigate
#   High     16-25  act immediately
# Arguments:
#   $1 - risk score
# Outputs:
#   The level to stdout.
#######################################
risk_level() {
  local score="$1"
  if   (( score >= 16 )); then echo "High"
  elif (( score >= 11 )); then echo "Medium"
  elif (( score >= 6 ));  then echo "Moderate"
  else                         echo "Low"
  fi
}

#######################################
# Print the risk register as a table, highest risk first, followed by
# a count per level and the list of checks scored with generic defaults
# (candidates for data/scores.txt).
# Globals:
#   RISKS_FILE, FINDINGS_FILE
# Outputs:
#   The table to stdout; the totals to stderr.
#######################################
print_table() {
  local count raw
  count="$(wc -l < "$RISKS_FILE")"
  raw="$(wc -l < "$FINDINGS_FILE")"
  if (( count == 0 )); then
    info "No findings."
    return 0
  fi

  # Fixed column widths: '-' aligns left, no '-' aligns right.
  # Likelihood before impact, as in the course template (P x I).
  local fmt='%-14s %-8s %-56s %2s %2s %4s  %-8s\n'
  local width=101   # sum of widths + separators, for the divider line

  # shellcheck disable=SC2059  # format is our own constant, not external input
  printf "$fmt" "ID" "Source" "Risk" "L" "I" "Risk" "Level"
  printf '%*s\n' "$width" '' | tr ' ' '-'

  local src id risk impact likelihood score basis level
  local -A per_level=()
  local -a unscored=()
  # Fields: source id category risk action impact likelihood score basis ...
  while IFS=$'\t' read -r src id _ risk _ impact likelihood score basis _; do
    level="$(risk_level "$score")"
    per_level[$level]=$(( ${per_level[$level]:-0} + 1 ))
    if [[ $basis == default* ]]; then unscored+=("$id"); fi
    # Full text goes into the Markdown report; truncate it on the terminal.
    if (( ${#risk} > 56 )); then
      risk="${risk:0:53}..."
    fi
    # shellcheck disable=SC2059
    printf "$fmt" "$id" "$src" "$risk" "$likelihood" "$impact" "$score" "$level"
  done < <(sort -t $'\t' -k8,8nr -k2,2 "$RISKS_FILE")

  info "${count} risks from ${raw} raw findings:" \
       "High ${per_level[High]:-0}, Medium ${per_level[Medium]:-0}," \
       "Moderate ${per_level[Moderate]:-0}, Low ${per_level[Low]:-0}"
  if (( ${#unscored[@]} > 0 )); then
    warn "${#unscored[@]} risks use generic default scores" \
         "(not in data/scores.txt): ${unscored[*]}"
  fi
}
