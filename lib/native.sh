#!/usr/bin/env bash
#
# lib/native.sh - Native checks: what ra-tool verifies by itself.
#
# Only gaps that the other sources do not cover (checked against the
# Lynis 3.1.6 and rkhunter 1.4.6 tests):
#   NAT-SSH-PASSWD  SSH password authentication enabled  (sshd -T)
#   NAT-SSH-EMPTY   SSH accepts empty passwords          (sshd -T)
#   NAT-SUDO-NOPW   sudo rules that need no password     (/etc/sudoers*)
# Covered elsewhere, so not repeated here: extra UID 0 accounts (Lynis
# AUTH-9204), accounts without password (Lynis AUTH-9283), SSH root
# login (Lynis SSH-7408, rkhunter).
#
# All checks only read: nothing on the system is changed.
# A check that passes records nothing.
#
# Depends on lib/common.sh (info, warn, add_finding, WORK_DIR).

#######################################
# Run all native checks.
#######################################
run_native() {
  info "Running native checks..."
  native_ssh
  native_sudo_nopasswd
}

#######################################
# Check the effective SSH server configuration.
# `sshd -T` prints the configuration sshd would really use: compiled-in
# defaults plus sshd_config and its drop-in files, with keys in lower
# case. It is a test mode: it does not start or restart the service.
# Limitation: Match blocks are ignored (they would need `-C`).
# Globals:
#   WORK_DIR (read)
#######################################
native_ssh() {
  # No SSH server: nothing to assess, and not a problem in itself.
  if ! command -v sshd >/dev/null 2>&1; then
    info "sshd not installed: SSH checks skipped"
    return 0
  fi

  # SSH server present but its configuration cannot be read: the checks
  # did not run, so the user must know (a warning, not a silent skip).
  local cfg first_err
  if ! cfg="$(sshd -T 2>"${WORK_DIR}/sshd-T.err")"; then
    # First line of the error, e.g. a syntax error in sshd_config or
    # "Missing privilege separation directory: /run/sshd".
    read -r first_err < "${WORK_DIR}/sshd-T.err" || true
    warn "sshd -T failed, SSH checks skipped: ${first_err:-no error message}"
    return 0
  fi

  local password_auth empty_pw
  password_auth="$(sshd_option passwordauthentication "$cfg")"
  empty_pw="$(sshd_option permitemptypasswords "$cfg")"

  if [[ $password_auth == "yes" ]]; then
    add_finding native NAT-SSH-PASSWD \
      "SSH password authentication is enabled: brute force and reused passwords are possible; prefer keys only" \
      4 3
  fi

  if [[ $empty_pw == "yes" ]]; then
    add_finding native NAT-SSH-EMPTY \
      "SSH accepts empty passwords (PermitEmptyPasswords yes)" \
      5 4
  fi
}

#######################################
# Print the value of one option from `sshd -T` output.
# Arguments:
#   $1 - option name, lower case (e.g. passwordauthentication)
#   $2 - sshd -T output
# Outputs:
#   The value to stdout, or nothing if the option is missing.
#######################################
sshd_option() {
  # Lines look like "passwordauthentication yes".
  # Here-string (<<<) instead of `echo | awk`: no pipe needed.
  awk -v key="$1" '$1 == key { print $2; exit }' <<< "$2"
}

#######################################
# Check for sudo rules that do not ask for a password.
# With NOPASSWD, whoever takes over that user's session becomes root
# without knowing any password.
# Limitation: plain text search; aliases and files included from
# outside /etc/sudoers.d are not resolved.
#######################################
native_sudo_nopasswd() {
  local files
  # -r: recurse into /etc/sudoers.d; -l: print file names only;
  # the pattern skips commented lines ("# ... NOPASSWD").
  # grep exits 1 when nothing matches: that is the good case.
  files="$(grep -rlE '^[[:space:]]*[^#[:space:]].*NOPASSWD' \
    /etc/sudoers /etc/sudoers.d 2>/dev/null || true)"
  if [[ -n $files ]]; then
    add_finding native NAT-SUDO-NOPW \
      "sudo rules without password (NOPASSWD) in: ${files//$'\n'/ }" \
      4 2
  fi
}
