#!/usr/bin/env bash
#
# lib/report.sh - Write the Markdown report.
#
# A technical report to work from: the risks in order of priority, a
# checklist of actions and the full evidence of each finding. Its
# sections follow a standard risk assessment structure (introduction,
# context, analysis, risks, actions, conclusions, annexes); what only a
# person can know (business context) is marked "To be completed by the
# analyst".
#
# Depends on lib/common.sh (info, risk_level, FINDINGS_FILE, WORK_DIR),
# lib/reconcile.sh (RISKS_FILE, exposed_ports), the module globals
# (LYNIS_*, RKH_*) and ra-tool.sh (VERSION, SKIP_*).

# Set by write_report: path of the report just written.
REPORT_FILE=""

TO_COMPLETE="_To be completed by the analyst._"

# Risks sorted by rating, highest first: the line number is the risk
# number used in every section (register, actions, annex).
SORTED_RISKS=""
# Number of risks per level, filled by write_report.
declare -A LEVEL_COUNT=()

#######################################
# Print the treatment of a risk level (risk acceptance criteria).
# Arguments:
#   $1 - level (High, Medium, Moderate, Low)
#######################################
treatment_of() {
  case "$1" in
    High)     echo "Immediate action" ;;
    Medium)   echo "Mitigate" ;;
    Moderate) echo "Monitor" ;;
    *)        echo "Acceptable" ;;
  esac
}

#######################################
# Print the display name of a source.
# Arguments:
#   $1 - source (lynis | rkhunter | native)
#######################################
source_name() {
  case "$1" in
    lynis)  echo "Lynis" ;;
    native) echo "Native check" ;;
    *)      echo "$1" ;;
  esac
}

#######################################
# Print the rating basis in words.
# "table+R3" -> "score table, likelihood adjusted by R3"
# Arguments:
#   $1 - basis as written by lib/reconcile.sh
#######################################
basis_text() {
  local basis="$1" out
  case "${basis%%+*}" in
    table)  out="score table" ;;
    module) out="source module" ;;
    *)      out="generic default" ;;
  esac
  if [[ $basis == *+* ]]; then
    out+=", likelihood adjusted by ${basis#*+}"
  fi
  echo "$out"
}

#######################################
# Print text safe for a Markdown table cell: a '|' would end the cell.
# Arguments:
#   $1 - text
#######################################
md_cell() {
  printf '%s' "${1//|/\\|}"
}

#######################################
# Print the action of a risk, or a fallback when no source gave one.
# Arguments:
#   $1 - action field ("-" when empty)
#######################################
action_text() {
  if [[ $1 == "-" ]]; then
    echo "No action suggested by the scan: see the evidence in Annex A"
  else
    echo "$1"
  fi
}

#######################################
# Write the report to a new, timestamped file, mode 600.
# It describes the weaknesses of the system, so only root may read it.
# Globals:
#   RISKS_FILE, WORK_DIR (read)
#   REPORT_FILE, SORTED_RISKS, LEVEL_COUNT (set)
# Arguments:
#   $1 - output directory
#######################################
write_report() {
  local dir="$1" host stamp
  host="$(hostname)"
  stamp="$(date +%Y%m%d-%H%M%S)"

  # umask 077 makes new files 600 and new directories 700. It is set in
  # a subshell ( ), so it does not leak into the rest of the script.
  # An existing directory (e.g. given with -o) is left as it is.
  if [[ ! -d $dir ]]; then
    ( umask 077; mkdir -p -- "$dir" )
  fi

  REPORT_FILE="${dir}/ra-report-${host}-${stamp}.md"
  # Never overwrite an earlier report (two runs in the same second).
  local n=2
  while [[ -e $REPORT_FILE ]]; do
    REPORT_FILE="${dir}/ra-report-${host}-${stamp}-${n}.md"
    n=$(( n + 1 ))
  done

  SORTED_RISKS="${WORK_DIR}/risks-sorted.tsv"
  sort -t $'\t' -k8,8nr -k2,2 "$RISKS_FILE" > "$SORTED_RISKS"

  local score level
  LEVEL_COUNT=([High]=0 [Medium]=0 [Moderate]=0 [Low]=0)
  # Fields: source id category risk action impact likelihood score ...
  while IFS=$'\t' read -r _ _ _ _ _ _ _ score _; do
    level="$(risk_level "$score")"
    LEVEL_COUNT[$level]=$(( LEVEL_COUNT[$level] + 1 ))
  done < "$SORTED_RISKS"

  ( umask 077; report_markdown "$host" > "$REPORT_FILE" )
  info "Report written to ${REPORT_FILE}"
}


#######################################
# Print the whole report as Markdown, section by section.
# Arguments:
#   $1 - host name
#######################################
report_markdown() {
  local host="$1" os

  # PRETTY_NAME="Ubuntu 26.04 LTS" -> Ubuntu 26.04 LTS
  os="$(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null || true)"
  os="${os#*=}"
  os="${os//\"/}"
  os="${os:-unknown}"

  cat <<EOF
# Linux risk assessment: \`${host}\`

$(date '+%Y-%m-%d %H:%M %Z') · ${os} · Linux risk assessment script ${VERSION}

> This report describes security weaknesses of the system: keep it private.

## 1. Introduction

Automated technical risk assessment of the Linux host \`${host}\`: audit
tools and native checks were run on the host, and their findings were
consolidated into a list of risks rated by likelihood and impact.

## 2. Purpose

To find the security weaknesses of the system, rate the risk of each one
and list the technical actions to take, in order of priority.

EOF
  report_context "$host" "$os"
  report_analysis
  report_risks
  report_actions
  report_conclusions
  report_annexes
}

#######################################
# Section 3: what the tool detects about the system, plus the context
# only a person knows.
# Arguments:
#   $1 - host name, $2 - operating system
#######################################
report_context() {
  local host="$1" os="$2" kernel virt exposed
  kernel="$(uname -r)"
  # systemd-detect-virt prints "none" and exits 1 on physical hardware.
  virt="$(systemd-detect-virt 2>/dev/null || true)"
  exposed="$(exposed_ports)"

  cat <<EOF
## 3. Context

| | |
|---|---|
| Host | \`${host}\` |
| Operating system | ${os} |
| Kernel | ${kernel} |
| Virtualisation | ${virt:-unknown} |
| Services exposed on the network | ${exposed:-none} |

- **Network context**: ${TO_COMPLETE}
- **Function of the system**: ${TO_COMPLETE}
- **Data processed**: ${TO_COMPLETE}
- **Users**: ${TO_COMPLETE}

EOF
}

#######################################
# Count the raw findings of a source, optionally of one kind.
# Arguments:
#   $1 - source, $2 - kind (optional)
#######################################
count_findings() {
  awk -F'\t' -v s="$1" -v k="${2:-}" \
    '$1 == s && (k == "" || $3 == k) { n++ } END { print n + 0 }' "$FINDINGS_FILE"
}

#######################################
# Section 4: methods and tools (4.1), activities (4.2), results (4.3).
# Globals:
#   FINDINGS_FILE, SORTED_RISKS, LYNIS_*, RKH_*, SKIP_* (read)
#######################################
report_analysis() {
  local lynis_status rkh_status native_status raw total ids
  if [[ $SKIP_LYNIS -eq 0 ]]; then lynis_status="run"; else lynis_status="skipped (--skip-lynis)"; fi
  if [[ $SKIP_RKHUNTER -eq 0 ]]; then rkh_status="run"; else rkh_status="skipped (--skip-rkhunter)"; fi
  if [[ $SKIP_NATIVE -eq 0 ]]; then native_status="run"; else native_status="skipped (--skip-native)"; fi
  raw="$(wc -l < "$FINDINGS_FILE")"
  total="$(wc -l < "$SORTED_RISKS")"

  cat <<EOF
## 4. Analysis

### 4.1 Methods and tools

| Source | Version | Coverage |
|---|---|---|
| Lynis | ${LYNIS_VERSION:-n/a} | system audit: configuration, packages, services, hardening |
| rkhunter | ${RKH_VERSION:-n/a} | rootkits, changed system binaries, hidden files |
| Native checks | n/a | SSH password login, SSH empty passwords, sudo without password |

**Risk = Likelihood (L) × Impact (I)**, each on a 1-5 scale (risk 1-25).

| | Likelihood (L) | Impact (I) |
|---|---|---|
| 1 | Rare: needs physical access or unusual conditions | Negligible |
| 2 | Unlikely: needs local access with valid credentials | Minor: low-value information, local nuisance |
| 3 | Possible: reachable from the network, needs credentials or skill | Moderate: a service or an unprivileged account |
| 4 | Likely: exploitable from the network with known tools | Major: sensitive data or privileged functions |
| 5 | Almost certain: remote, no credentials needed | Critical: full control of the system (root) |

| Level | Risk | Treatment |
|---|---|---|
| High | 16-25 | Immediate action |
| Medium | 11-15 | Mitigate |
| Moderate | 6-10 | Monitor |
| Low | 1-5 | Acceptable |

Consolidation rules (how the tool outputs become risks):

- **R1** Findings with the same source and check ID form one risk.
- **R2** A Lynis warning describes the risk; its suggestions describe the action.
- **R3** The likelihood of a missing firewall depends on the services exposed on the network.
- **R4** The likelihood of SSH accepting empty passwords depends on the existence of accounts without a password.
- **R6** Known false positives (e.g. hidden files created by the operating system) are rated low, with a note.

Scores, risk descriptions and actions come from \`data/scores.txt\`
("score table"), from the source module itself ("source module") or
from a generic default to be reviewed ("generic default").

### 4.2 Activities

1. Lynis audit (\`lynis audit system\`): ${lynis_status}.
2. rkhunter scan (\`rkhunter --check\`): ${rkh_status}.
3. Native checks (\`sshd -T\`, sudoers): ${native_status}.
4. Consolidation: ${raw} raw findings grouped and rated into ${total} risks.

### 4.3 Results

EOF
  if [[ -n $LYNIS_VERSION ]]; then
    echo "- **Lynis**: hardening index ${LYNIS_HARDENING_INDEX:-?}/100;" \
         "$(count_findings lynis warning) warnings," \
         "$(count_findings lynis suggestion) suggestions."
  fi
  if [[ -n $RKH_VERSION ]]; then
    echo "- **rkhunter**: ${RKH_SUSPECT_FILES:-?} suspect files," \
         "${RKH_POSSIBLE_ROOTKITS:-?} possible rootkits;" \
         "$(count_findings rkhunter) warnings."
  fi
  if [[ $SKIP_NATIVE -eq 0 ]]; then
    # Unique IDs of the native findings, comma-separated.
    ids="$(awk -F'\t' '$1 == "native" { print $2 }' "$FINDINGS_FILE" | sort -u | paste -sd, -)"
    echo "- **Native checks**: ${ids:-no finding}."
  fi
  echo
  echo "The full evidence of each risk is in Annex A."
  echo
}

#######################################
# Section 5: count per level, likelihood x impact matrix, risk register.
# Globals:
#   SORTED_RISKS, LEVEL_COUNT (read)
#######################################
report_risks() {
  local level total=0
  echo "## 5. Risks"
  echo
  echo "| Level | Treatment | Risks |"
  echo "|---|---|---:|"
  for level in High Medium Moderate Low; do
    echo "| ${level} | $(treatment_of "$level") | ${LEVEL_COUNT[$level]} |"
    total=$(( total + LEVEL_COUNT[$level] ))
  done
  echo "| **Total** | | **${total}** |"
  echo

  if (( total == 0 )); then
    echo "No risks found."
    echo
    return 0
  fi

  # Matrix: number of risks per cell, likelihood on rows (5 at the top),
  # impact on columns. Key of a cell: "L,I".
  local -A cell=()
  local l i
  while IFS=$'\t' read -r _ _ _ _ _ i l _; do
    cell[$l,$i]=$(( ${cell[$l,$i]:-0} + 1 ))
  done < "$SORTED_RISKS"

  echo "Number of risks per likelihood (rows) and impact (columns):"
  echo
  echo '| L \ I | 1 | 2 | 3 | 4 | 5 |'
  echo "|---|:---:|:---:|:---:|:---:|:---:|"
  for l in 5 4 3 2 1; do
    printf '| **%s** ' "$l"
    for i in 1 2 3 4 5; do
      printf '| %s ' "${cell[$l,$i]:-·}"
    done
    echo "|"
  done
  echo

  # Register, highest risk first.
  local n=0 src id risk impact likelihood score
  echo "| # | Check | Source | Risk | L | I | R | Level |"
  echo "|---:|---|---|---|---:|---:|---:|---|"
  while IFS=$'\t' read -r src id _ risk _ impact likelihood score _; do
    n=$(( n + 1 ))
    echo "| ${n} | ${id} | $(source_name "$src") | $(md_cell "$risk") | ${likelihood} | ${impact}" \
         "| ${score} | $(risk_level "$score") |"
  done < "$SORTED_RISKS"
  echo
}

#######################################
# Print a checklist of the actions for one risk level, or "None.".
# Markdown "- [ ]" items render as tick boxes in most viewers.
# Globals:
#   SORTED_RISKS
# Arguments:
#   $1 - level
#######################################
actions_for_level() {
  local want="$1" n=0 found=0 id action score
  while IFS=$'\t' read -r _ id _ _ action _ _ score _; do
    n=$(( n + 1 ))
    [[ $(risk_level "$score") == "$want" ]] || continue
    echo "- [ ] **${n}. ${id}** (R=${score}): $(action_text "$action")"
    found=1
  done < "$SORTED_RISKS"
  if (( found == 0 )); then echo "None."; fi
  echo
}

#######################################
# Section 6: actions as a checklist, grouped by treatment.
#######################################
report_actions() {
  echo "## 6. Proposed actions"
  echo
  echo "### 6.1 Mitigations / Remediations"
  echo
  echo "**Immediate action (High)**"
  echo
  actions_for_level High
  echo "**Mitigate (Medium)**"
  echo
  actions_for_level Medium
  echo "### 6.2 Improvements"
  echo
  echo "**Monitor (Moderate)**"
  echo
  actions_for_level Moderate
  echo "**Acceptable (Low)**"
  echo
  actions_for_level Low
}

#######################################
# Section 7: generated summary of the risks.
# Globals:
#   SORTED_RISKS, LEVEL_COUNT (read)
#######################################
report_conclusions() {
  local total top
  total="$(wc -l < "$SORTED_RISKS")"
  # The three highest risks: "ID (R=n)", comma-separated.
  top="$(head -n 3 "$SORTED_RISKS" | awk -F'\t' '{ printf "%s%s (R=%s)", (NR > 1 ? ", " : ""), $2, $8 }')"

  cat <<EOF
## 7. Conclusions

${total} risks: High ${LEVEL_COUNT[High]}, Medium ${LEVEL_COUNT[Medium]}, Moderate ${LEVEL_COUNT[Moderate]}, Low ${LEVEL_COUNT[Low]}.
Highest risks: ${top:-none}.

EOF
}

#######################################
# Section 8: full evidence per risk (A), run details (B).
# One block per High, Medium and Moderate risk; Low risks in a compact
# table. Sorting puts Low risks last, so block A.N is always risk N.
# Globals:
#   FINDINGS_FILE, SORTED_RISKS, VERSION, SKIP_* (read)
#######################################
report_annexes() {
  local n=0 src id category risk action impact likelihood score basis evidence level
  local -a low_rows=() unscored=()

  echo "## 8. Annexes"
  echo
  echo "### A. Evidence per risk"
  echo
  while IFS=$'\t' read -r src id category risk action impact likelihood score basis evidence; do
    n=$(( n + 1 ))
    if [[ $basis == default* ]]; then unscored+=("$id"); fi
    level="$(risk_level "$score")"
    if [[ $level == "Low" ]]; then
      low_rows+=("| ${n} | ${id} | $(md_cell "$risk") | ${score} | $(md_cell "$evidence") |")
      continue
    fi
    cat <<EOF
#### A.${n} ${id} · ${score} ${level}

${risk}

| Source | Category | L × I | Treatment | Rating basis |
|---|---|---|---|---|
| $(source_name "$src") | ${category} | ${likelihood} × ${impact} = ${score} | $(treatment_of "$level") | $(basis_text "$basis") |

**Evidence**: ${evidence}

**Action**: $(action_text "$action")

EOF
  done < "$SORTED_RISKS"

  if (( ${#low_rows[@]} > 0 )); then
    echo "#### Low risks"
    echo
    echo "| # | Check | Risk | R | Evidence |"
    echo "|---:|---|---|---:|---|"
    printf '%s\n' "${low_rows[@]}"
    echo
  fi

  local raw skipped=()
  raw="$(wc -l < "$FINDINGS_FILE")"
  if [[ $SKIP_LYNIS -ne 0 ]]; then skipped+=("Lynis"); fi
  if [[ $SKIP_RKHUNTER -ne 0 ]]; then skipped+=("rkhunter"); fi
  if [[ $SKIP_NATIVE -ne 0 ]]; then skipped+=("native checks"); fi

  # With IFS="," ${arr[*]} joins the elements with commas; :-none
  # prints "none" for an empty list. local keeps the IFS change in here.
  local IFS=","
  cat <<EOF
### B. Run details

| | |
|---|---|
| Generated by | Linux risk assessment script ${VERSION} |
| Sources skipped | ${skipped[*]:-none} |
| Raw findings / risks | ${raw} / ${n} |
| Score table | \`data/scores.txt\` |

Checks not in the score table, rated with the generic default of their source (to be added to \`data/scores.txt\`): ${unscored[*]:-none}.
EOF
}
