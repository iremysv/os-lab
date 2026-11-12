# OS-30 Ubuntu baseline checker and selected repairs

The roadmap's Python entry point is `linux-lab/scripts/harden_check.py`.
It uses only Python's standard library and delegates baseline collection to
`linux-lab/scripts/hardening.sh`. The Bash file is now audit-only: its old `apply`
spelling exits 2 without mutations and points to the single Python repair path.

Run inside the authorized Ubuntu guest, including Ubuntu 24.04 ARM64 on UTM.
The Python entry point refuses a missing/empty collector or a collector that
returns no findings, rather than reporting a clean audit.
The tool never connects to another machine, sources `.env`, or confuses host
forwarding port 2222 with guest port 22. It rejects non-Ubuntu platforms.

## Read-only audit

From the repository root, inside the guest:

```bash
python3 linux-lab/scripts/harden_check.py
python3 linux-lab/scripts/harden_check.py audit --format json
bash linux-lab/scripts/hardening.sh audit
```

An administrator can run audit in an existing privileged guest session for fuller
coverage. No automatic elevation or password prompt occurs. The audit never
refreshes package lists, installs updates, changes files, restarts services or
modifies UFW. Root-only `sudo -n -l -U USER` queries list policy for interactive
accounts without executing any permitted command. Names and firewall policy are
administrative evidence; review reports before sharing. Password hashes and
passwd GECOS/home fields are not printed.

Use an actual SSH connection context when investigating Match rules:

```bash
python3 linux-lab/scripts/harden_check.py audit --context 'user=student,host=client.example,addr=192.0.2.10,laddr=192.0.2.20,lport=22'
```

The example addresses are documentation-only; substitute actual client hostname,
client IP, server IP and server port. `sshd -T -C` resolves Include/Match itself.
Global settings do not establish per-connection policy. Context provenance and
other Match branches remain WARN; disk configuration may differ from a running
daemon with old settings or different arguments.

Checks include SSH service/socket state, effective root/password/empty-password/
key/keyboard-interactive settings and standard config ownership/modes; non-root
UID 0, interactive accounts, password state, sudoers syntax and effective sudo
command specifications; cached upgrades, security-labelled candidates, cache age,
unattended-upgrades/package/policy/timers and reboot marker; UFW status, defaults
and existing rules. Systemd-owned SSH endpoints must match ssh.socket's Listen
metadata; unrelated systemd listeners are not attributed to SSH. Socket matching
alone does not prove remote reachability.

Explicit parser errors are FAIL; permission or inconclusive errors remain WARN.
SSH permissions are checked independently of sshd syntax. Custom Include paths,
parent directories, external policy semantics and service-account sudo privileges
still need review. `/bin/sync` is a utility, not an interactive shell; UID 0
checks still apply. Unknown shell paths remain visible.

The chosen SSH baseline requires root/password/empty-password login disabled and
public-key login enabled; audit reports deviations, without silently fixing them.
The chosen UFW baseline is active with deny incoming / allow outgoing. Other
defaults, including deliberately stricter egress rules, are deviations requiring
explicit policy review, not authorization to replace them. Missing tools or
privileges remain WARN. Security-labelled cached APT counts are approximate;
no complete candidate-origin analysis or cache freshness is asserted.

PASS applies only to a named check; WARN means incomplete evidence or review,
FAIL means a baseline violation, SKIP explains unsupported/omitted work.
Audit exit codes: 0 no FAIL (WARN may remain), 1 baseline violations, 2
usage/platform/execution failure. JSON schema version 1 records UTC time,
exit code and status/check/detail findings. Redirect output only if you explicitly
want a report file; audit does not create one automatically.

## Plan before any repair

The Python entry point requires an explicit allowlist; plain `apply` cannot
choose changes. `plan` has no writes, no backups and no commands that modify state.
Root is required to read complete repair preconditions. In an administrator
session **inside the guest**, review one repair at a time:

```bash
python3 linux-lab/scripts/harden_check.py plan --fix ssh-permissions
python3 linux-lab/scripts/harden_check.py plan --fix user-key-permissions --user student
python3 linux-lab/scripts/harden_check.py plan --fix unattended-timer
python3 linux-lab/scripts/harden_check.py plan --fix ufw-ssh-rule --management-source 192.0.2.10 --ssh-port 22
```

Available repairs:

- `ssh-permissions`: set existing, root-owned standard sshd config files to 0600.
  Preserve contents and ownership. Validate `sshd -t` before and after. Require
  attributable actual SSH listeners. No reload, authentication or port change.
  A root-owned 0644 file can already pass the audit because it is not writable
  by others; selecting 0644 -> 0600 is an optional stricter profile, not proof
  that the existing mode is an audit FAIL.
- `user-key-permissions`: set the explicitly selected non-root user's existing,
  nonempty, user-owned authorized_keys file to 0600. Never recursively chmod a
  home or create accounts/keys. Refuse symlinks and unsafe directory ancestry;
  directory repairs and unexpected ownership require manual administrator review.
- `unattended-timer`: enable an installed apt-daily-upgrade.timer without --now,
  only if unattended-upgrades is already installed and enablement is unambiguous.
  Do not start services, change APT policy or install packages. Future schedules
  may install updates under the existing policy; consent covers that consequence.
- `ufw-ssh-rule`: add one TCP allow rule from one explicit client IP to an
  attributed actual SSH listener. No subnet, wildcard or command expression is
  accepted. Snapshot user.rules/user6.rules and standard UFW control/default/before/after
  configuration files, and verify UFW's generated rule, tagged with
  a unique `OS-30:<run-id>` comment. An equivalent pre-existing rule is left
  untouched rather than retagged.
  Do not activate UFW, change default policies, reset/delete existing rules or
  assert that an earlier deny was overridden. Duplicate rules may be a UFW no-op.

After reviewing the repair plan, replace `plan` with `apply`
and enter exactly `APPLY OS-30`. Both input and output must be TTYs. Piped answers,
--yes, different case and surrounding whitespace cannot authorize changes. There
is no automatic privilege escalation, command-string input or environment
variable root override.
Arguments and preconditions are checked before confirmation; state is rechecked
immediately after confirmation and before mutation. Already-satisfied permissions
or timer state are no-ops. Apply exits 0 for verified selected repairs/no-op,
2 for refusal/failure, 130 for interruption; this does not assert a clean audit.

Snapshots and manifest are retained in root-only `/var/backups/os-30/repair-*`.
Schema-2 manifests record the run ID, selected operations, original snapshots
and hashes/modes/ownership, verified post-apply file/timer/firewall state, and
completion status. Manifest updates are private, atomic and fsynced. A shared
nonblocking repair lock prevents simultaneous OS-30 application/rollback.
Single-link regular files and no-follow file descriptors prevent linked-path
permission operations. No automatic recursive ownership changes occur.

On failure, restore changed permission modes and the previous disabled timer
state when safe. Concurrent changes are not overwritten. If a UFW addition
cannot be verified, report possible partial application and the backup path;
**no automatic rule deletion/reset during apply failure** is attempted. An
administrator must review saved and current rules before manual recovery. Failed
or unfinished apply journals cannot be used by the new rollback command: they
lack a complete verified post-state. Backup failure stops before repairs.

These selected repairs do not make a server fully hardened. Disabling root or
password access, locking accounts and activating UFW remain outside automatic
application until an independent key/sudo connection and complete access path
can be verified. Docker-published ports require separate host review. The tool
never reports a repaired authentication/firewall baseline merely because an
additive rule or permission fix succeeded.

## Explicit rollback of a completed run

Use the suffix printed as `run-id` after a successful apply, not a path. For a
backup `/var/backups/os-30/repair-ab12cd34`, the command would be:

```bash
sudo python3 linux-lab/scripts/harden_check.py rollback ab12cd34
```

Review the plan in a recoverable, authorized lab before applying or rolling back.
Rollback verification uses fake commands and temporary fixtures; live UTM
rollback has not been verified.

The CLI accepts only a short lowercase alphanumeric/underscore/hyphen ID, never
a caller-supplied file path or alternative backup root. It reads only the matching
root-owned `repair-ID` directory under `/var/backups/os-30`. Backup root/run
folders must be real directories, root:root 0700; manifest and numbered snapshot
files must be single-link regular files, root:root 0600. Symlinks, traversal,
wrong ownership/modes, duplicate JSON keys, unknown operations, disallowed target
paths, altered snapshot hashes, legacy manifests and incomplete/failed apply
records are refused before system changes. Targets are limited to the recorded
standard SSH configs, selected user's authorized_keys and UFW snapshots.

A completed schema-2 manifest is required. Preview lists only the run's original
permission/timer changes and its own proven UFW rule. Root and input/output TTYs
are required, with the exact line `ROLLBACK OS-30 ab12cd34` for this example.
`APPLY OS-30`, piped input and surrounding whitespace do not authorize rollback.
Immediately before mutation, the shared lock is acquired and the manifest,
snapshots and current state are checked again.

File content hash, owner, group and mode must match the saved post-state.
Rollback only restores the previous mode through a no-follow file descriptor;
it never copies old content over a changed file, chowns an account, reloads SSH,
or restores a whole directory. Any permission-file or timer drift refuses the
entire rollback before target mutations. The timer's previous enablement is
restored only if this run changed it; no service is started or stopped.

For UFW, the saved before/after rule lists must prove exactly one addition with
the unique run marker. Current complete rule list, status and firewall file
fingerprints must match the recorded post-state. Only that validated rule may be
removed using fixed command arguments; no numbered-rule guessing, reset, enable,
default-policy change or removal of other rules is performed. An existing rule
that this run did not add is never removed. If identity/state cannot be proven,
UFW stays untouched, other proven repairs may be reverted, and the result is
**partial rollback, exit 2**, with a warning and backup location. A delete failure
or failed postcondition also stops with partial-state evidence; no second rule
is guessed/deleted. Inspect the retained manifest/snapshots before recovery.

Rollback progress is atomically journaled per operation. A partial run can be
retried only when the saved progress and current state agree; completed steps
are not repeated. An interruption after an intended step but before its progress
write is reconciled only against the exact saved previous state. A completed
rollback reports SKIP/no-op on repetition (exit 0), provided the restored state
still matches; later administrator changes are never overwritten. Old backups
without schema-2 post-state remain available for manual inspection but cannot be
automatically migrated into trusted rollback evidence. Do not hand-edit journals
to bypass refusal checks.

## Tests and evidence

The current focused integration run passed **97 tests** with fake OS commands
and temporary files. Actual commands and
results for the integration revision are recorded in `VERIFY.md`; they are
separate from historical local and operator-reported UTM checks.

```bash
python3 -m unittest discover -s linux-lab/tests -v
bash -n linux-lab/scripts/hardening.sh
./scripts/run-tests.sh
```

Bash audit tests use command mocks. Python repair tests use a fake OS boundary and
temporary files, including backup/postcondition/rollback/refusal scenarios. Real
PTY tests exercise consent against fake operations. None mutate actual SSH, apt,
accounts or UFW. Test dependencies may be provisioned before running offline tests;
tests themselves must not download dependencies or query external services.
The repository runner retains its existing dependency preparation; with network
access prohibited, use the focused unittest command unless dependencies are
already provisioned. No package installation is needed for the focused suite.

See `VERIFY.md` for executed checks and UTM evidence, and `REPORT.md` for
delivery scope. Historical audit runs do not verify later repair/rollback changes.

## Sharing evidence

Use synthetic fixtures or sanitized summaries in shared documents and videos.
Do not copy raw server audit output, account names, real addresses/hostnames,
local home paths, passwords or key material. Documentation examples use reserved
addresses and generic account names. JSON formatting tests with fakes are not
live JSON-audit evidence; live apply/rollback needs separate verification.
