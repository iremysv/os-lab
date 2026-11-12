# OS-30 verification

## Historical local regression

Environment: macOS, branch `feat/os-30-hardening-checker`.
Recorded rollback regression command:

```bash
python3 -m unittest discover -s linux-lab/tests -v
```

Result: **94 tests passed in 19.494s**, exit 0:

- 24 Bash audit tests with PATH command mocks.
- 31 Python repair/CLI/guard tests, including real PTY confirmation tests.
- 39 rollback tests covering snapshots, allowed targets, invalid IDs, traversal,
  symlinks/hardlinks, ownership/modes, corrupt manifests, post-state drift,
  timer recovery, exact UFW rule identity, partial failure and safe repetition.

System commands are fake and file mutations are limited to temporary fixtures.
PTY tests invoke fake repair/rollback operations. No actual SSH, UFW, accounts,
packages or services are modified. Schema-2 rollback is not live-verified in UTM.

Additional recorded checks passed:

- Python AST parsing of `harden_check.py`, `test_harden_check.py` and `test_rollback.py`.
- `bash -n linux-lab/scripts/hardening.sh scripts/run-tests.sh`.
- `.venv-test/bin/shellcheck linux-lab/scripts/hardening.sh scripts/run-tests.sh`.
- `git diff --check`, plus whitespace/final-newline checks on untracked files.
- `npx --offline --yes --cache /tmp/os30-npm-cache --package lat.md lat check`.
  The existing no-init-version warning did not prevent success; no initialization
  or hooks were installed.

## Full repository runner: pre-rollback revision

```bash
PATH="$PWD/.venv-test/bin:$PATH" PIP_DISABLE_PIP_VERSION_CHECK=1 \
  npx --offline --yes --cache /tmp/os30-npm-cache --package lat.md \
  --call './scripts/run-tests.sh'
```

Recorded result: **exit 0; 5 stages passed, 0 failed, 1 skipped**.

- OS-30: 55 tests passed in 45.583s, before explicit rollback tests were added.
- Android: 51 passed, 1 skipped in 36.51s.
- Sample analysis/report smoke passed.
- All 54 Bash scripts parsed.
- `lat check` passed.
- Dashboard verification skipped: dependencies absent; dashboard unchanged.

Earlier attempts failed because test dependencies were unavailable and sandbox
permissions blocked localhost test sockets. These were resolved by provisioning
pytest/requests/cryptography in the ignored `.venv-test` and permitting local test
sockets. Dependency provisioning was separate from offline test execution.
ShellCheck was installed only in `.venv-test`; lat used a temporary npm cache.
No system or VM package installation was performed. The runner generates ignored
sample APK/report artifacts; those are not OS-30 live-audit evidence.

## Operator-reported UTM checks

Text audit and read-only permission planning were reported as completed on an
Ubuntu 24.04 ARM64 lab without applying changes. These checks belong to an earlier
revision and were not re-executed during integration. Raw audit findings, measured
server configuration, real account names, addresses/hostnames and local paths are
not retained in the shared verification record.

Live JSON audit, apply and rollback are unverified. Local fake-command and PTY
tests must not be presented as live Ubuntu verification.

## Rollback usage and evidence boundary

```text
sudo python3 linux-lab/scripts/harden_check.py rollback <run-id>
```

The command requires a valid private schema-2 backup, root, input/output TTYs and
exact `ROLLBACK OS-30 <run-id>` confirmation. Legacy or incomplete evidence and
file/timer drift refuse restoration. Unproven UFW state results in partial
rollback without deleting rules. See
[the recovery guide](linux-lab/knowledge/hardening.md#explicit-rollback-of-a-completed-run).

The command above is usage documentation, not a live execution result.
Live apply/rollback require separately reviewed changes and a recoverable lab.
Do not install pending upgrades or refresh APT metadata as part of audit.
Video evidence has not been supplied. Any recorded demonstration should clearly
use synthetic fixtures or sanitized summaries and distinguish reported lab
checks from mocked apply/rollback evidence. Do not copy raw server audit output
or identifying account, address, hostname, local-path or key material.

## Current integration checks

Scope: the canonical Python entry point, companion audit-only Bash collector,
selected repair/rollback operations and focused tests. The Python entry point
refuses missing/empty collectors and successful collector executions returning
no findings. Raw server audit output is excluded from this record.

The focused suite needs only Python's standard library; no package installation,
network access or live security operation is required. Results recorded below
are new executions and are separate from the historical runs above.

Latest pre-delivery checks (after the test-runner cd guard was restored):

- `python3 -m unittest discover -s linux-lab/tests -v`: **97 tests passed in
  52.513s**, exit 0 (24 Bash collector, 34 Python repair/CLI/guard/PTY,
  39 rollback/terminal). Three added regressions cover missing/empty collectors
  and a collector that returns no findings.
- Python AST parsing: passed for the entry point and all three OS-30 test files.
- `bash -n linux-lab/scripts/hardening.sh scripts/run-tests.sh`: passed, exit 0.
- `.venv-test/bin/shellcheck linux-lab/scripts/hardening.sh scripts/run-tests.sh`:
  passed, exit 0; the existing installed executable was used.
- `git diff --check` and `git diff --cached --check`: passed, exit 0.
- After all 97 tests and static checks passed, the reviewed OS-30 files and
  README image were staged. The staged documents were verified against the
  working files; no commit or push was made. Subsequent documentation corrections
  require their own staging review.
- `lat check`: could not run because no executable was installed. Attempted
  `npx --yes --cache /tmp/os30-lat-cache --package lat.md lat check` with bounded
  fetch time and no retries. Package retrieval failed with `ENOTFOUND` for
  `registry.npmjs.org`; the checker never started. Git status was unchanged
  before/after the attempt. No global installation or `lat init` was performed.
- The full repository runner was not rerun because its existing preparation can
  install dependencies. Historical results above are not new integration results.

No live audit was run during this integration or the local pre-delivery checks.
An operator reported UTM text audit and read-only plan execution on an earlier
revision, as described above; those are separate from local mock tests.
Live JSON audit, apply and rollback remain unverified. No package installation,
commit or push was performed. The npx package-access attempt above failed before
the graph checker could run; it is not a passing graph validation.
