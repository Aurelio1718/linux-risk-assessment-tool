#!/usr/bin/env bash
#
# ra-tool.sh - Risk assessment tool for Linux systems.
#
# Collects findings from Lynis, rkhunter and native checks, scores each
# one as impact x likelihood and prints them sorted by risk, together
# with a Markdown report.
#
# Usage: sudo bash ra-tool.sh [--skip-lynis] [--skip-rkhunter] [--skip-native] [-o DIR]

set -euo pipefail

VERSION="0.1.0"
# Absolute path of the directory containing this script, so that the
# library files are found regardless of the current working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/lynis.sh"
source "${SCRIPT_DIR}/lib/rkhunter.sh"
source "${SCRIPT_DIR}/lib/native.sh"

# Defaults, overridden by command-line options. Defined before parsing so
# they always exist under `set -u`.
SKIP_LYNIS=0
SKIP_RKHUNTER=0
SKIP_NATIVE=0
OUTPUT_DIR="${SCRIPT_DIR}/reports"

#######################################
# Print usage help.
# Outputs:
#   Help text to stdout.
#######################################
usage() {
  cat <<EOF
ra-tool ${VERSION} - risk assessment for Linux systems

Usage: sudo bash ra-tool.sh [options]

Options:
  --skip-lynis      do not run Lynis
  --skip-rkhunter   do not run rkhunter
  --skip-native     do not run the native checks
  -o DIR            directory for the Markdown report (default: reports/)
  -h, --help        show this help
EOF
}

#######################################
# Parse command-line options.
# Globals:
#   SKIP_LYNIS, SKIP_RKHUNTER, SKIP_NATIVE, OUTPUT_DIR (set)
# Arguments:
#   All script arguments ("$@").
#######################################
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --skip-lynis)    SKIP_LYNIS=1 ;;
      --skip-rkhunter) SKIP_RKHUNTER=1 ;;
      --skip-native)   SKIP_NATIVE=1 ;;
      -o)
        [[ $# -ge 2 ]] || die "Option -o requires a directory"
        OUTPUT_DIR="$2"
        shift   # extra shift: consume the option's value too
        ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; die "Unknown option: $1" ;;
    esac
    shift
  done
}

#######################################
# Entry point.
# Arguments:
#   All script arguments ("$@").
#######################################
main() {
  parse_args "$@"
  # Checked after parsing so that `-h` works without sudo.
  [[ $EUID -eq 0 ]] || die "Must be run as root: sudo bash ra-tool.sh"

  init_findings

  if [[ $SKIP_LYNIS -eq 0 ]]; then
    run_lynis
  fi
  if [[ $SKIP_RKHUNTER -eq 0 ]]; then
    run_rkhunter
  fi
  if [[ $SKIP_NATIVE -eq 0 ]]; then
    run_native
  fi
  print_table
}

main "$@"