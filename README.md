# linux-risk-assessment-tool

A command-line tool that assesses the security risk of a Linux machine.
It integrates **three sources**: two established scanners, **Lynis** and
**rkhunter**, plus a few **native checks** for gaps they do not cover. All
findings are consolidated into a **risk register** where
**risk = impact × likelihood** (probability), each on a 1–5 scale.
The result is a table on the terminal, sorted by risk, and a technical
Markdown report with an action checklist.

It runs **on the machine being assessed**, as root, either directly or
launched from another machine over SSH (see
[Running from another machine](#running-from-another-machine)). It only
reads the system: it changes no configuration and installs nothing.

Excerpt of the terminal table (Ubuntu Server 26.04 test VM):

```
ID             Source   Risk                                                      L  I Risk  Level
-----------------------------------------------------------------------------------------------------
FIRE-4590      lynis    No host firewall filtering traffic (none active, or a...  3  4   12  Medium
NAT-SSH-PASSWD native   SSH accepts password logins: brute force and reused p...  3  4   12  Medium
...
[*] 34 risks from 47 raw findings: High 0, Medium 2, Moderate 7, Low 25
```

## Contents

- [Quick start](#quick-start)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Running from another machine](#running-from-another-machine)
- [Output](#output)
- [Risk method](#risk-method)
- [What is checked](#what-is-checked)
- [Try it: detect an insecure configuration](#try-it-detect-an-insecure-configuration)
- [Known false positives](#known-false-positives)
- [Limitations](#limitations)
- [Design decisions](#design-decisions)
- [Repository layout](#repository-layout)
- [Future work](#future-work)
- [References](#references)
- [License](#license)

## Quick start

On the machine to assess (tested on Ubuntu Server 26.04 LTS in a VM):

```bash
sudo apt update
sudo apt install --no-install-recommends lynis rkhunter unhide git
sudo rkhunter --propupd                 # rkhunter baseline, once
git clone https://github.com/Aurelio1718/linux-risk-assessment-tool.git
cd linux-risk-assessment-tool
sudo bash ra-tool.sh                    # about 6 minutes
sudo ls reports/                        # the Markdown report
```

Each step is explained below.

## Requirements

| Item | Version tested | Notes |
|---|---|---|
| Linux distribution | Ubuntu Server 26.04 LTS | other Debian-based systems should work; others are untested |
| Bash | 5.x | Bash 4.2 or later is required |
| Lynis | 3.1.6 (Ubuntu package) | `--skip-lynis` runs without it |
| rkhunter | 1.4.6 (Ubuntu package) | `--skip-rkhunter` runs without it |
| unhide | Ubuntu package | used by the rkhunter test for hidden processes |
| Privileges | root (`sudo`) | the scanners, `sshd -T` and sudoers need it |

Standard tools present on a default Ubuntu Server install are also used:
`awk`, `grep`, `sort`, `ss` (iproute2), `systemd-detect-virt`.

**Services.** No daemon of the tool or of the scanners has to be running
(the scheduled `lynis.timer` and rkhunter cron jobs are not needed). For
the SSH checks the **OpenSSH server** must be installed: they read
`sshd -T`, which needs the directory `/run/sshd`, created when sshd
starts. On systems where sshd is socket-activated it may not exist until
the first SSH connection; then the SSH checks are skipped with a message.
Connect once over SSH, or run `sudo systemctl start ssh`, before the
assessment.

**Network.** Internet access is needed only to install the packages; the
assessment itself runs offline.

**Data to enter.** None is required: the score table
[data/scores.txt](data/scores.txt) ships with the tool. The only
preparation is the rkhunter baseline (installation step 2). To see every
check fire, follow
[Try it](#try-it-detect-an-insecure-configuration).

## Installation

```bash
# 1. Install the scanners from the distribution repositories.
#    --no-install-recommends: rkhunter recommends a mail server, which the
#    tool does not need and which would change the attack surface being
#    measured.
sudo apt update
sudo apt install --no-install-recommends lynis rkhunter unhide

# 2. Create the rkhunter file-properties baseline, on a system you trust
#    (ideally right after installation): rkhunter compares system binaries
#    against it. See "Known false positives".
sudo rkhunter --propupd

# 3. Get the tool.
git clone https://github.com/Aurelio1718/linux-risk-assessment-tool.git
cd linux-risk-assessment-tool
```

The tool is run with `bash`, so no execute permission is needed. The
folders `lib/` and `data/` are both required.

## Usage

```bash
sudo bash ra-tool.sh [options]
```

| Option | Effect |
|---|---|
| `--skip-lynis` | do not run Lynis |
| `--skip-rkhunter` | do not run rkhunter (the slowest source) |
| `--skip-native` | do not run the native checks |
| `-o DIR` | write the report to `DIR` (default: `reports/` in the tool folder) |
| `-h`, `--help` | show help (works without sudo) |

A full run takes about **6 minutes** (rkhunter alone 3–5). Progress
messages go to stderr, the table to stdout.

The tool exits with status 0 when the assessment completes, whatever it
finds, and with 1 if it cannot run (not root, a scanner missing or
failing, an invalid score table).

## Running from another machine

The assessment always runs on the target, but it can be launched from an
admin machine over SSH. The target needs the packages of installation
steps 1–2 and a user with sudo rights.

```bash
# From the admin machine, inside the cloned repository.
# 1. Copy the tool (lib/ and data/ are required).
ssh target 'mkdir -p ~/linux-risk-assessment-tool'
scp -r ra-tool.sh lib data target:~/linux-risk-assessment-tool/

# 2. Run it. -t gives sudo a terminal for the password prompt.
ssh -t target 'sudo bash ~/linux-risk-assessment-tool/ra-tool.sh'
```

The report stays on the target, readable by root only. To read it on the
admin machine, copy it to your home on the target first (as your user,
mode 600), then download it:

```bash
ssh -t target 'sudo -v && d="$HOME/linux-risk-assessment-tool/reports" && f=$(sudo ls -t "$d" | head -1) && sudo install -m 600 -o "$USER" "$d/$f" "$HOME/ra-report-latest.md"'
scp target:ra-report-latest.md .
```

An automatic `--remote` option is planned (see [Future work](#future-work)).

## Output

1. **Table** on the terminal, highest risk first, followed by the count
   per level and by the list of checks not in the score table.
2. **Markdown report** `reports/ra-report-<host>-<YYYYMMDD-HHMMSS>.md`,
   written before the table:

   | Section | Content |
   |---|---|
   | 1–2 Introduction, Purpose | what was assessed and why |
   | 3 Context | host, OS, kernel, virtualisation, exposed services; network context, function, data and users are left to the analyst |
   | 4 Analysis | tools and versions, rating scales, levels, consolidation rules, activities run, results per tool |
   | 5 Risks | count per level, likelihood × impact matrix, risk register |
   | 6 Proposed actions | checklist (`- [ ]`) grouped by treatment: 6.1 Mitigations (High, Medium), 6.2 Improvements (Moderate, Low) |
   | 7 Conclusions | totals and highest risks |
   | 8 Annexes | A: full evidence and action for every risk; B: run details |

The report describes the weaknesses of the system, so it is readable by
root only (file 600, `reports/` 700 when created by the tool). Read it on
the machine with `sudo less reports/<file>`. The `reports/` folder is
excluded from Git.

Lynis and rkhunter write their report and log into a private temporary
directory, deleted when the tool ends, even on errors or Ctrl+C. Their
system-wide logs in `/var/log` are not touched.

## Risk method

Each risk is rated on two scales from 1 to 5; **Risk = Impact × Likelihood** (1–25). Tables show L before I.

| | Likelihood (L) | Impact (I) |
|---|---|---|
| 1 | Rare: needs physical access or unusual conditions | Negligible |
| 2 | Unlikely: needs local access with valid credentials | Minor: low-value information, local nuisance |
| 3 | Possible: reachable from the network, needs credentials or skill | Moderate: a service or an unprivileged account |
| 4 | Likely: exploitable from the network with known tools | Major: sensitive data or privileged functions |
| 5 | Almost certain: remote, no credentials needed | Critical: full control of the system (root) |

| Level | Risk | Treatment |
|---|---|---|
| High | 16–25 | Immediate action |
| Medium | 11–15 | Mitigate |
| Moderate | 6–10 | Monitor |
| Low | 1–5 | Acceptable |

### From raw findings to risks

The raw findings of all sources are consolidated in
[lib/reconcile.sh](lib/reconcile.sh):

- **R1** Findings with the same source and check ID form one risk (Lynis
  repeats some tests, e.g. `SSH-7408` once per SSH option).
- **R2** A Lynis warning describes the risk; the suggestions of the same
  test describe the action.
- **R3** The likelihood of a missing firewall (`FIRE-4590`) depends on the
  services exposed on the network (`ss`): 3 if any, 1 if none.
- **R4** The likelihood of SSH accepting empty passwords
  (`NAT-SSH-EMPTY`) depends on accounts without a password (Lynis
  `AUTH-9283`): 5 if any exist, 2 otherwise.
- **R6** Known false positives get a low score with a note (see
  [Known false positives](#known-false-positives)).

Scores, risk descriptions and actions come from
[data/scores.txt](data/scores.txt), one line per check:

```
source | id | impact | likelihood | risk | action
lynis  | AUTH-9204 | 5 | 4 | An account other than root has UID 0 ... | Remove the account ...
```

`-` keeps the score computed by the module (rkhunter and native checks
score themselves, e.g. to rate known false positives low). A check that
is not listed keeps a generic default (Lynis warning 3/3, suggestion 2/2)
and is listed at the end of the run and in the report: add it to the
table to rate it properly. Edit the table to tune scoring without
touching the code.

## What is checked

| Source | Coverage | IDs |
|---|---|---|
| Lynis | broad audit: packages, SSH, authentication, firewall, kernel, logging, file systems and more | Lynis test IDs, e.g. `SSH-7408` ([controls](https://cisofy.com/lynis/controls/)) |
| rkhunter | known rootkits, changed system binaries, hidden files | `RKH-PROPS`, `RKH-SSH-ROOT`, `RKH-HIDDEN`, `RKH-WARN` (derived from the warning text) |
| Native checks | effective SSH settings from `sshd -T`: password login, empty passwords; sudo rules without password | `NAT-SSH-PASSWD`, `NAT-SSH-EMPTY`, `NAT-SUDO-NOPW` |

Native checks exist only where no scanner covers the topic (verified on
the Lynis 3.1.6 source): extra UID 0 accounts are Lynis `AUTH-9204`,
accounts without password `AUTH-9283`, SSH root login `SSH-7408`.

## Try it: detect an insecure configuration

> **Only on a disposable test machine** (e.g. a VM with a snapshot to roll
> back to): these steps make the system deliberately insecure.

**1. Baseline run** on the clean system:

```bash
sudo bash ra-tool.sh --skip-rkhunter
```

**2. Introduce known weaknesses:**

```bash
# SSH: password login and empty passwords. sshd reads the drop-in files
# in alphabetical order and the first value wins, hence "00-".
# No restart needed: sshd -T reads the files directly.
printf 'PasswordAuthentication yes\nPermitEmptyPasswords yes\n' \
  | sudo tee /etc/ssh/sshd_config.d/00-ra-test.conf

# An extra account with UID 0 (-o allows a duplicate UID, -M: no home).
sudo useradd -o -u 0 -g 0 -M -s /usr/sbin/nologin ratest0

# An account with an empty password.
sudo useradd -M -s /usr/sbin/nologin ratest1
sudo passwd -d ratest1

# A sudo rule without password; visudo -c checks the syntax.
echo 'ratest1 ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/99-ra-test
sudo chmod 440 /etc/sudoers.d/99-ra-test
sudo visudo -c
```

**3. Run again** and compare with the baseline:

```bash
sudo bash ra-tool.sh --skip-rkhunter
```

Expected new or changed risks:

| ID | L × I | Level | Caused by |
|---|---|---|---|
| `NAT-SSH-EMPTY` | 5 × 5 = 25 | High | `PermitEmptyPasswords yes` and an account without password (R4) |
| `AUTH-9204` | 4 × 5 = 20 | High | `ratest0` |
| `AUTH-9283` | 3 × 4 = 12 | Medium | `ratest1` |
| `NAT-SSH-PASSWD` | 3 × 4 = 12 | Medium | `PasswordAuthentication yes` (already present if it is the system default) |
| `NAT-SUDO-NOPW` | 2 × 4 = 8 | Moderate | `/etc/sudoers.d/99-ra-test` |

**4. Undo:** roll back to the snapshot (safest), or:

```bash
sudo rm /etc/ssh/sshd_config.d/00-ra-test.conf /etc/sudoers.d/99-ra-test
sudo userdel ratest1
# userdel ratest0 may refuse because UID 0 belongs to root's processes:
# remove its line with `sudo vipw` and `sudo vipw -s` instead.
```

## Known false positives

| Finding | Why it appears | How the tool handles it |
|---|---|---|
| `RKH-PROPS` on system binaries | a package update changed the binary after the rkhunter baseline (Ubuntu installs security updates automatically) | rated 3 × 5; the action says to verify the file against its package (`dpkg --verify`) and, if legitimate, to run `sudo rkhunter --propupd` |
| `RKH-SSH-ROOT` "PermitRootLogin has not been set" | rkhunter reads `sshd_config` only; the OpenSSH default is `prohibit-password` | rated 1 × 4; the effective value is checked by Lynis `SSH-7408` (`sshd -T`) |
| `RKH-HIDDEN` on `/etc/.updated` and similar | files created by the system itself | rated 1 × 2 and marked as known false positive |
| `FIRE-4590` when a firewall has 3 rules or fewer | Lynis treats such a ruleset as empty | the risk is raised anyway: check the rules by hand |

Do not silence `RKH-PROPS` blindly: a changed `sshd` binary is also what a
trojaned SSH server looks like.

## Limitations

- **Ubuntu/Debian focus**: tested on Ubuntu Server 26.04; tool messages
  are parsed in English (the default of Lynis and rkhunter).
- **Local only**: the tool runs on the target; remote assessment is future
  work.
- **Generic ratings**: the tool does not know how exposed the machine is
  (Internet, LAN, isolated) or what data it holds; the analyst adjusts
  the ratings to the context.
- **One score per ID**: an entry in `scores.txt` applies to every finding
  with that ID.
- **SSH checks** ignore `Match` blocks in `sshd_config`.
- **Point in time**: results change with updates, the rkhunter baseline
  and the state of the kernel (see FIRE-4590 below).

## Design decisions

Short records of the main decisions (context → decision → consequence).

**Bash, no other runtime.** Lynis and rkhunter are shell tools and the
target is a server where extra runtimes are undesirable. Bash keeps the
tool auditable; the cost is careful error handling (`set -euo pipefail`,
explicit exit-status checks).

**Run on the target, as root.** The scanners and several checks need
root and local access. Remote assessment is future work.

**Minimal dependencies.** `apt install --no-install-recommends lynis
rkhunter unhide`: no mail server, so the tool does not change the attack
surface it measures; `unhide` is needed by the rkhunter hidden-processes
test.

**Established tools first, native checks only for gaps.** A native check
is written only when no scanner covers the topic, verified on the Lynis
source (UID 0 → `AUTH-9204`, empty passwords → `AUTH-9283`,
PermitRootLogin → `SSH-7408`).

**Read machine-oriented output.** Lynis is parsed from its report file
(`warning[]=`, `suggestion[]=`), rkhunter from its log, both written to a
private temporary directory.

**Stable IDs for rkhunter warnings.** rkhunter has no test IDs, so each
warning gets one derived from its text: the same problem always gets the
same ID and can be scored and tracked across runs.

**Accept rkhunter only if the scan completed.** rkhunter exits 1 both on
warnings and on errors, so a run is accepted only if its log ends with
`Info: End date is`.

**Risk = L × I on 1–5 scales, four levels with a treatment each.** The
treatment, not the number, tells what to do with each risk.

**Consolidation as explicit rules (R1–R6).** Grouping, scoring and
context adjustments are separate, documented steps, so every number in the
register has a stated basis (score table, module, generic default, rule).

**FIRE-4590 from the firewall state, not only from the Lynis suggestion.**
Lynis suggests FIRE-4590 only when no packet filter is "active", and it
counts as active a loaded `nf_tables` kernel module even with no rules.
The module loads on the first use of `nft`, `iptables` or `ufw`, so the
same unfiltered host got the finding or not depending on what had run
since boot. The Lynis module now raises FIRE-4590 also when the report
says `firewall_active=1` and `firewall_empty_ruleset=1`.

**Least privilege for results.** Reports are mode 600 (directory 700);
temporary files live in a `mktemp -d` directory removed on exit.

## Repository layout

| Path | Content |
|---|---|
| `ra-tool.sh` | entry point: options, root check, order of the steps |
| `lib/common.sh` | logging, temporary work area, findings store, terminal table |
| `lib/lynis.sh` | runs Lynis, parses its report, firewall state (FIRE-4590) |
| `lib/rkhunter.sh` | runs rkhunter, parses its log, known false positives |
| `lib/native.sh` | native checks (`sshd -T`, sudoers) |
| `lib/reconcile.sh` | consolidation rules R1–R6 into the risk register |
| `lib/report.sh` | Markdown report |
| `data/scores.txt` | likelihood, impact, risk text and action per check |
| `reports/` | generated reports (created at run time, not in Git) |

## Future work

- `--remote HOST`: copy the tool over SSH, run it on the target, fetch the
  report; network scan of the target from outside with `nmap`.
- Verify `RKH-PROPS` automatically with `dpkg --verify` and lower the
  likelihood for legitimate updates.
- R5: weigh SSH password login against brute-force protection (fail2ban).
- Default scores per category in `scores.txt`.
- More sources: `ssh-audit`, chkrootkit, OpenSCAP with Canonical's OVAL
  data.
- Hardware checks: disk space, CPU vulnerabilities, SMART on physical
  hosts.

## References

- [Lynis](https://cisofy.com/lynis/) and its [controls](https://cisofy.com/lynis/controls/) (test IDs); [source on GitHub](https://github.com/CISOfy/lynis)
- [rkhunter(8) manual page](https://manpages.ubuntu.com/manpages/en/man8/rkhunter.8.html)
- [sshd_config(5)](https://man.openbsd.org/sshd_config) and `sshd -T` in [sshd(8)](https://man.openbsd.org/sshd)
- [NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments](https://csrc.nist.gov/pubs/sp/800/30/r1/final)
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html) (code style)
- [Ubuntu Server: firewalls](https://documentation.ubuntu.com/server/how-to/security/firewalls/)

## License

[MIT](LICENSE)
