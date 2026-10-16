#!/usr/bin/env bash
#
# lib/rkhunter.sh - rkhunter module: runs a scan and turns its warnings
# into findings.
#
# rkhunter has no machine-readable report, so this module reads its log.
# A warning starts on a line like
#   [10:37:30] Warning: The file properties have changed:
# and may continue on the following, deeply indented lines, with or
# without a timestamp:
#   [10:37:30]          File: /usr/sbin/sshd
#              The default value may be 'yes', to allow root access.
# Normal log lines are indented by at most two spaces after the timestamp.
#
# Each warning gets a stable ID derived from its text (RKH-PROPS,
# RKH-SSH-ROOT, RKH-HIDDEN, fallback RKH-WARN), so that it can later be
# mapped to scores and known false positives.
#
# Parsing assumes English messages (rkhunter's default language).
#
# Depends on lib/common.sh (info, err, die, require_cmd, add_finding, WORK_DIR).

# Set by run_rkhunter; used later in the Markdown report header.
RKH_VERSION=""
RKH_SUSPECT_FILES=""
RKH_POSSIBLE_ROOTKITS=""

# Hidden files that rkhunter reports on a stock Ubuntu Server but that
# are created by the system itself:
#   .resolv.conf.systemd-resolved.bak  backup made by systemd-resolved
#   .updated                           timestamp written by systemd-update-done
# Rule R6 (known false positives): these get a low score, with a note.
RKH_KNOWN_HIDDEN=(
  /etc/.resolv.conf.systemd-resolved.bak
  /etc/.updated
)

#######################################
# Run an rkhunter scan and record its warnings.
# Globals:
#   WORK_DIR (read)
#   RKH_VERSION, RKH_SUSPECT_FILES, RKH_POSSIBLE_ROOTKITS (set)
#######################################
run_rkhunter() {
  require_cmd rkhunter --skip-rkhunter

  local log="${WORK_DIR}/rkhunter.log"
  local out="${WORK_DIR}/rkhunter.out"
  local status=0

  # Captured into a variable and cut with parameter expansion instead of
  # `| head -n1`: no pipe, so no risk of a broken-pipe failure under
  # `set -o pipefail`. First line is "Rootkit Hunter 1.4.6".
  RKH_VERSION="$(rkhunter --version)"
  RKH_VERSION="${RKH_VERSION%%$'\n'*}"
  RKH_VERSION="${RKH_VERSION##* }"

  info "Running rkhunter ${RKH_VERSION} scan (takes 3-5 minutes)..."
  # --cronjob: non-interactive check, no colours, no key presses.
  # --nomow:   never send the warning e-mail, whatever rkhunter.conf says.
  # --logfile: our own log in WORK_DIR; /var/log/rkhunter.log is untouched.
  # Screen output is kept in a file only to show it if the scan fails.
  # `|| status=$?` stores the exit status instead of letting `set -e`
  # stop the script: rkhunter exits 1 whenever it finds a warning.
  rkhunter --cronjob --nomow --logfile "$log" >"$out" 2>&1 || status=$?

  # rkhunter also exits 1 on errors (tested with a missing config file),
  # so the exit status alone cannot tell "warnings found" from "failed".
  # A complete scan always ends its log with "Info: End date is ...".
  # If the log does not exist grep fails too, which is what we want.
  if (( status > 1 )) || ! grep -q 'Info: End date is' "$log" 2>/dev/null; then
    err "rkhunter output (last lines):"
    tail -n 5 "$out" >&2 || true
    die "rkhunter scan did not complete (exit status ${status})"
  fi

  RKH_SUSPECT_FILES="$(rkh_summary_value 'Suspect files' "$log")"
  RKH_POSSIBLE_ROOTKITS="$(rkh_summary_value 'Possible rootkits' "$log")"
  info "rkhunter: ${RKH_SUSPECT_FILES:-?} suspect files," \
       "${RKH_POSSIBLE_ROOTKITS:-?} possible rootkits"

  parse_rkhunter_log "$log"
}

#######################################
# Print a number from the summary at the end of the rkhunter log.
# Arguments:
#   $1 - label, e.g. "Suspect files" (matches "Suspect files: 3")
#   $2 - log file
# Outputs:
#   The value to stdout, or nothing if the label is missing.
#######################################
rkh_summary_value() {
  local line
  # A missing label is not an error: `|| true` absorbs grep's exit 1.
  line="$(grep -m1 "$1 *:" "$2" || true)"
  # Keep what follows the last ': ' ("...Possible rootkits: 0" -> "0").
  [[ -n $line ]] && echo "${line##*: }"
  return 0   # the test above returns 1 when the line is empty
}

#######################################
# Read the rkhunter log, join multi-line warnings and record each one.
# Arguments:
#   $1 - log file
#######################################
parse_rkhunter_log() {
  local log="$1"
  local line body current=""
  # Regexes kept in variables: inside [[ =~ ]] a quoted pattern would be
  # matched literally, an unquoted one needs every space escaped.
  local ts_re='^\[[0-9:]+\] ?(.*)$'   # "[10:37:30] text" -> "text"
  local cont_re='^ {5,}(.*)$'         # 5+ leading spaces = continuation

  while IFS= read -r line; do
    # Strip the timestamp if present; continuation lines may lack it.
    if [[ $line =~ $ts_re ]]; then
      body="${BASH_REMATCH[1]}"
    else
      body="$line"
    fi

    if [[ $body == "Warning: "* ]]; then
      # A new warning: the previous one, if any, is complete.
      if [[ -n $current ]]; then rkh_record "$current"; fi
      current="${body#Warning: }"
    elif [[ -n $current && $body =~ $cont_re ]]; then
      current+=" ${BASH_REMATCH[1]}"
    else
      # Any other line ends the warning being collected.
      if [[ -n $current ]]; then rkh_record "$current"; fi
      current=""
    fi
  done < "$log"

  # The log could end in the middle of a warning.
  if [[ -n $current ]]; then rkh_record "$current"; fi
}

#######################################
# Classify one warning, score it and record it as a finding.
# Default scores (data/scores.txt only adds risk and action texts):
#   RKH-PROPS     5/3  a changed system binary may be a trojan; the most
#                      common cause is a package update, hence L=3
#   RKH-SSH-ROOT  4/1  likely false positive (see text)
#   RKH-HIDDEN    3/3  unknown hidden file; 2/1 for known system files
#   RKH-WARN      3/3  anything else
# Arguments:
#   $1 - full warning text (continuation lines joined)
#######################################
rkh_record() {
  local text="$1" id impact likelihood path

  case "$text" in
    "The file properties have changed:"*)
      id="RKH-PROPS"; impact=5; likelihood=3
      text+=" -- check the file against its package (e.g. dpkg --verify);"
      text+=" if the change is legitimate, update the baseline: rkhunter --propupd"
      ;;
    *"'PermitRootLogin' has not been set"*)
      id="RKH-SSH-ROOT"; impact=4; likelihood=1
      text+=" -- likely false positive: rkhunter reads sshd_config only,"
      text+=" while the OpenSSH default is prohibit-password;"
      text+=" the effective value is checked by Lynis SSH-7408 (sshd -T)"
      ;;
    "Hidden file found: "* | "Hidden directory found: "*)
      id="RKH-HIDDEN"; impact=3; likelihood=3
      # "Hidden file found: /etc/.updated: ASCII text" -> "/etc/.updated"
      path="${text#Hidden * found: }"
      path="${path%%: *}"
      if rkh_is_known_hidden "$path"; then
        impact=2; likelihood=1
        text+=" -- known false positive: created by the system itself"
      fi
      ;;
    *)
      id="RKH-WARN"; impact=3; likelihood=3
      ;;
  esac

  add_finding rkhunter "$id" "$text" "$impact" "$likelihood"
}

#######################################
# Tell whether a path is in the list of known hidden system files.
# Globals:
#   RKH_KNOWN_HIDDEN
# Arguments:
#   $1 - path
# Returns:
#   0 if known, 1 otherwise.
#######################################
rkh_is_known_hidden() {
  local known
  for known in "${RKH_KNOWN_HIDDEN[@]}"; do
    [[ $1 == "$known" ]] && return 0
  done
  return 1
}
