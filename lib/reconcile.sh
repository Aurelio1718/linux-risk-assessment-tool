#!/usr/bin/env bash
#
# lib/reconcile.sh - Turn the raw findings of all sources into a risk
# register: one line per risk, with likelihood, impact and a reason for
# each number.
#
# Steps, in order:
#   1. Group (R1, R2): raw findings with the same source and ID become
#      one risk. Lynis may report a test several times (SSH-7408 once per
#      sshd option) or as both a warning and a suggestion (PKGS-7392):
#      the warning describes the problem, the suggestions the fix.
#   2. Score: impact and likelihood come from data/scores.txt when the
#      ID is listed there with numbers (basis "table"); IDs listed with
#      '-' keep the score their module computes (basis "module", e.g.
#      rkhunter and native checks); IDs not listed at all keep the
#      module's generic default (basis "default", to be reviewed).
#      Grouped findings keep the highest default of the group.
#   3. Context (R3, R4): rules that change a likelihood using the system
#      state or the findings of another source (basis gets "+R3"/"+R4").
#   (R6, known false positives, is applied in the modules themselves,
#   e.g. the known hidden files in lib/rkhunter.sh.)
#
# Output: RISKS_FILE, one TSV line per risk:
#   source id category risk action impact likelihood score basis evidence
#
# Depends on lib/common.sh (info, warn, die, FINDINGS_FILE, WORK_DIR) and
# on LYNIS_VERSION from lib/lynis.sh (empty if Lynis did not run).

RISKS_FILE=""

# Score table, filled by load_scores. Key: "source|id".
declare -A SCORE_I=() SCORE_L=() SCORE_RISK=() SCORE_ACTION=()

#######################################
# Load the score table.
# File format: one entry per line, fields separated by '|':
#   source | id | impact | likelihood | risk | action
# Spaces around fields are ignored; '-' means "not set" (keep the module
# default score, or the tool's own text). Empty lines and lines starting
# with '#' are ignored.
# Globals:
#   SCORE_I, SCORE_L, SCORE_RISK, SCORE_ACTION (set)
# Arguments:
#   $1 - score table file
#######################################
load_scores() {
  local file="$1"
  if [[ ! -f $file ]]; then
    warn "Score table not found: $file (module default scores used)"
    return 0
  fi

  local src id impact likelihood risk action key n=0
  # awk normalises each entry before bash reads it: it skips comments and
  # empty lines, trims spaces around every field, replaces empty fields
  # with '-' and joins the fields with TABs. Without the '-' an empty
  # field would vanish: `read` merges consecutive TABs.
  while IFS=$'\t' read -r src id impact likelihood risk action; do
    if [[ ! $impact =~ ^([1-5]|-)$ || ! $likelihood =~ ^([1-5]|-)$ ]]; then
      die "Invalid score in $file for $src $id: I=$impact L=$likelihood (expected 1-5 or -)"
    fi
    key="${src}|${id}"
    SCORE_I[$key]="$impact"
    SCORE_L[$key]="$likelihood"
    SCORE_RISK[$key]="$risk"
    SCORE_ACTION[$key]="$action"
    n=$(( n + 1 ))
  done < <(awk -F'|' '
    /^[[:space:]]*(#|$)/ { next }
    {
      out = ""
      for (i = 1; i <= 6; i++) {
        f = $i
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", f)
        if (f == "") f = "-"
        out = out (i > 1 ? "\t" : "") f
      }
      print out
    }' "$file")

  info "Score table: ${n} entries"
}

#######################################
# Print the category of a check, derived from its ID prefix.
# Arguments:
#   $1 - check ID
# Outputs:
#   Category name to stdout.
#######################################
category_of() {
  # Order matters: the first matching pattern wins (RKH-SSH-* is SSH,
  # every other RKH-* is integrity).
  case "$1" in
    SSH-* | NAT-SSH-* | RKH-SSH-*) echo "SSH" ;;
    AUTH-* | NAT-SUDO-*)           echo "Authentication" ;;
    PKGS-* | DEB-*)                echo "Packages" ;;
    FIRE-* | NETW-* | NAME-*)      echo "Network" ;;
    LOGG-* | ACCT-*)               echo "Logging" ;;
    KRNL-* | HRDN-* | USB-*)       echo "Kernel" ;;
    BOOT-*)                        echo "Boot" ;;
    FILE-* | FINT-* | RKH-*)       echo "Integrity" ;;
    *)                             echo "Other" ;;
  esac
}

#######################################
# List TCP/UDP ports listening on non-loopback addresses.
# Client sockets of DHCP (UDP 68, and 546 for DHCPv6) are not services
# and are skipped.
# Outputs:
#   Space-separated "proto/port" list to stdout (e.g. "tcp/22"), or
#   nothing.
#######################################
exposed_ports() {
  if ! command -v ss >/dev/null 2>&1; then
    warn "ss not found: exposed ports not checked"
    return 0
  fi

  local proto addr port ports=()
  # ss -H: no header; -t/-u: TCP and UDP; -l: listening; -n: numeric.
  # Columns: Netid State Recv-Q Send-Q Local:Port Peer:Port
  while read -r proto _ _ _ addr _; do
    case "$addr" in
      127.* | "[::1]"* | "::1"*) continue ;;   # loopback: not reachable from outside
    esac
    port="${addr##*:}"                          # what follows the last ':'
    if [[ $proto == "udp" && ( $port == "68" || $port == "546" ) ]]; then
      continue
    fi
    ports+=("${proto}/${port}")
  done < <(ss -H -tuln)

  if (( ${#ports[@]} > 0 )); then
    # sort -u removes duplicates (the same port on IPv4 and IPv6);
    # paste -sd' ' joins the lines with spaces.
    printf '%s\n' "${ports[@]}" | sort -u | paste -sd' ' -
  fi
}

#######################################
# Tell whether a raw finding with the given source and ID exists.
# Globals:
#   FINDINGS_FILE
# Arguments:
#   $1 - source, $2 - check ID
# Returns:
#   0 if found, 1 otherwise.
#######################################
has_finding() {
  grep -q "^${1}"$'\t'"${2}"$'\t' "$FINDINGS_FILE"
}

#######################################
# Apply the context rules to one risk.
# Works on the caller's local variables (bash functions see the locals
# of the function that called them): src, id, likelihood, basis,
# evidence.
# Globals:
#   LYNIS_VERSION
#######################################
apply_context_rules() {
  local exposed
  case "${src}|${id}" in
    "lynis|FIRE-4590")
      # R3: a missing firewall matters as much as what it would protect.
      exposed="$(exposed_ports)"
      if [[ -n $exposed ]]; then
        likelihood=3
        evidence+=" -- services exposed on the network: ${exposed}"
      else
        likelihood=1
        evidence+=" -- no service exposed on the network"
      fi
      basis+="+R3"
      ;;
    "native|NAT-SSH-EMPTY")
      # R4: SSH accepting empty passwords is exploitable only if some
      # account has an empty password (Lynis AUTH-9283). Without Lynis
      # the module default stays.
      if [[ -z $LYNIS_VERSION ]]; then
        evidence+=" -- Lynis not run: accounts without password not checked"
      elif has_finding lynis AUTH-9283; then
        likelihood=5
        evidence+=" -- accounts without password exist (Lynis AUTH-9283)"
        basis+="+R4"
      else
        likelihood=2
        evidence+=" -- no account without password (Lynis AUTH-9283)"
        basis+="+R4"
      fi
      ;;
  esac
}

#######################################
# Group, score and contextualise the raw findings into RISKS_FILE.
# Globals:
#   FINDINGS_FILE, WORK_DIR (read)
#   SCORE_I, SCORE_L, SCORE_RISK, SCORE_ACTION (read)
#   RISKS_FILE (set)
#######################################
reconcile_findings() {
  RISKS_FILE="${WORK_DIR}/risks.tsv"
  : > "$RISKS_FILE"

  # --- 1. Group by "source|id", keeping the first-seen order. ---------
  local -A warn_txt=() sugg_txt=() other_txt=() max_i=() max_l=()
  local -a order=()
  local src id kind text impact likelihood key

  while IFS=$'\t' read -r src id kind text impact likelihood; do
    key="${src}|${id}"
    if [[ -z ${max_i[$key]+set} ]]; then
      order+=("$key")
      max_i[$key]=0
      max_l[$key]=0
    fi
    # ${var:+; } adds the separator only when var is already non-empty.
    case "$kind" in
      warning)    warn_txt[$key]+="${warn_txt[$key]:+; }${text}" ;;
      suggestion) sugg_txt[$key]+="${sugg_txt[$key]:+; }${text}" ;;
      *)          other_txt[$key]+="${other_txt[$key]:+; }${text}" ;;
    esac
    if (( impact > max_i[$key] )); then max_i[$key]=$impact; fi
    if (( likelihood > max_l[$key] )); then max_l[$key]=$likelihood; fi
  done < "$FINDINGS_FILE"

  # --- 2 and 3. Score each group, apply the rules, write the risk. ----
  local risk action evidence basis
  for key in "${order[@]}"; do
    src="${key%%|*}"
    id="${key#*|}"

    # Evidence: everything the tools said, warnings first.
    evidence="${warn_txt[$key]:-}"
    evidence+="${other_txt[$key]:+${evidence:+; }${other_txt[$key]}}"
    evidence+="${sugg_txt[$key]:+${evidence:+; }${sugg_txt[$key]}}"

    # Risk description: the table's wording if any, else what the tool
    # said, preferring the warning (the problem) to the suggestion.
    risk="${SCORE_RISK[$key]:--}"
    if [[ $risk == "-" ]]; then
      risk="${warn_txt[$key]:-${other_txt[$key]:-${sugg_txt[$key]:-}}}"
    fi

    # Recommended action: the table's wording if any, else the Lynis
    # suggestions (they are actions), else nothing.
    action="${SCORE_ACTION[$key]:--}"
    if [[ $action == "-" ]]; then
      action="${sugg_txt[$key]:--}"
    fi

    # Scores: table first, module default otherwise.
    impact="${max_i[$key]}"
    likelihood="${max_l[$key]}"
    if [[ -n ${SCORE_I[$key]+set} ]]; then basis="module"; else basis="default"; fi
    if [[ ${SCORE_I[$key]:--} != "-" ]]; then impact="${SCORE_I[$key]}"; basis="table"; fi
    if [[ ${SCORE_L[$key]:--} != "-" ]]; then likelihood="${SCORE_L[$key]}"; basis="table"; fi

    apply_context_rules

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$src" "$id" "$(category_of "$id")" "$risk" "$action" \
      "$impact" "$likelihood" "$(( impact * likelihood ))" "$basis" "$evidence" \
      >> "$RISKS_FILE"
  done
}
