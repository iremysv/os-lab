# OS-30 delivery report

## Scope

`linux-lab/scripts/harden_check.py` provides a local Ubuntu Server baseline audit,
read-only repair planning, approval-gated repairs and explicit rollback. It uses
Python's standard library and delegates audit collection to `hardening.sh`.
Missing/empty collector code and an execution producing no findings are refused.

Audit is the default. It does not modify configuration, refresh package lists,
install updates, restart services or change firewall rules. Commands use a fixed
system PATH; `.env` and host-forwarded SSH ports are not used. Output is available
as text or versioned JSON with PASS, FAIL, WARN and SKIP findings.

## Audit coverage

- SSH service/socket state, attributed TCP listeners, effective `sshd -T/-C`
  settings, syntax validation and standard config ownership/permissions.
- Non-root UID 0 accounts, interactive accounts, password state, sudoers syntax
  and privileged noninteractive sudo policy listings. `/bin/sync` is not a shell.
- Cached pending/security-labelled updates, cache age, unattended-upgrades
  package/policy/timer state and reboot marker.
- UFW status, rules and defaults against an active, deny-incoming/allow-outgoing
  baseline. Missing privileges or inconclusive evidence remain WARN.

## Repairs and rollback

`plan` previews explicitly selected repairs without writes. `apply` requires root,
input/output TTYs and the exact phrase `APPLY OS-30`. Supported repairs are:

- Optional stricter root-owned SSH configuration modes to 0600, with `sshd -t`
  before/after. An existing 0644 file can already pass the audit; 0644 -> 0600
  is not automatically remediation of an existing FAIL.
- An explicit non-root user's existing authorized_keys mode to 0600.
- Enablement of an installed unattended-upgrade timer without starting it.
- One management-IP allow rule to an attributed actual SSH port.

Apply retains private snapshots and schema-2 manifests under
`/var/backups/os-30/repair-<run-id>`, including verified post-state. Shared locking,
no-follow file access, target allowlists and drift checks protect repair/recovery.

```text
sudo python3 linux-lab/scripts/harden_check.py rollback <run-id>
```

Rollback previews changes and requires exact `ROLLBACK OS-30 <run-id>` consent.
It restores only recorded permission modes and timer enablement changed by that
run. Contents and ownership are not overwritten. Only a uniquely tagged UFW rule
proven to be that run's single addition may be removed. Ambiguous firewall state
produces a partial result and retained backup path, without guessed deletion or
reset. Progress is journaled for safe retries; a completed rollback is a no-op.
Legacy, incomplete, corrupt or unsafe backups and unexpected target drift are
refused.

No repair disables SSH root/password authentication, locks/deletes accounts,
installs packages, activates UFW or replaces its defaults. Future timer schedules
may install updates under existing policy. A successful selected repair does not
imply a clean baseline audit. Custom Include/parent permissions, service-account
and external sudo semantics, full package-origin classification and end-to-end
network reachability remain outside complete automated coverage.

## Files

- `linux-lab/scripts/harden_check.py`: CLI, reports, repair and rollback logic.
- `linux-lab/scripts/hardening.sh`: read-only Bash audit collectors.
- `linux-lab/tests/test_hardening.py`: mocked Bash collector tests.
- `linux-lab/tests/test_harden_check.py`: repair/CLI/guard/PTY tests.
- `linux-lab/tests/test_rollback.py`: rollback, drift, recovery and attack tests.
- `scripts/run-tests.sh`: integration with the repository test runner.
- `linux-lab/README.md`, `linux-lab/knowledge/hardening.md`: usage and recovery.
- `lat.md/linux-lab.md`: architecture and implementation links.
- `VERIFY.md`: executed checks and live evidence boundaries.

## Evidence boundary

The companion Bash collector is part of the deliverable and remains audit-only.
The repository runner preserves its existing stages with an added OS-30 unittest
stage; no unrelated runner implementation was replaced.

Operator-reported UTM text-audit and read-only-plan checks exist for an earlier
revision. They were not repeated during integration. Raw server findings and
identifying details are excluded from shared documentation. Live JSON audit,
apply and rollback are not verified; fake-command tests do not establish live
system behavior. Video evidence has not been supplied.

Current focused test commands/results are recorded in `VERIFY.md`. Historical
local runs are labeled separately and are not presented as new executions.

## Current focused verification

The latest pre-delivery run of
`python3 -m unittest discover -s linux-lab/tests -v` passed **97 tests in 52.513s**,
exit 0, after restoring the test-runner cd guard. Python/Bash syntax, existing ShellCheck and both
working-tree/index whitespace checks passed. The existing collector source was
completed and regressions now prevent missing, empty or non-reporting collectors
from being presented as a successful audit.

No package installation, full-runner execution or live host/VM security change
was performed. The graph checker was unavailable; the subsequent npx attempt
failed to retrieve lat.md with `ENOTFOUND` for `registry.npmjs.org`, so graph
validation could not run. No global installation or `lat init` was performed.
After the checks passed, the reviewed OS-30 files and README image
were staged; no commit or push was made. Subsequent documentation corrections
require their own staging review. No live audit was run during integration;
the earlier UTM audit and read-only plan were operator-reported on a previous
revision. `VERIFY.md` distinguishes those checks from local mock evidence.
