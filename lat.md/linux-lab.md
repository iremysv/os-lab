# linux-lab

A disposable Linux VM on Ubuntu Server, built on `qemux/qemu`, for malware
detonation, ELF reverse engineering, exploit/kernel work and container-escape
practice behind KVM. It mirrors [[win-lab]] but boots any distro or ISO.

See [[linux-lab]], the service in [[linux-lab/docker-compose.yml]] and the
runbook [[linux-lab/README.md]].

## Service and endpoints

The `linux` service (container `linux-lab`) serves the noVNC web viewer on
`WEB_PORT` (8006) and SSH on `SSH_PORT` (2222 -> guest 22).

The guest is chosen with `BOOT` (a distro shortcut or an ISO URL) and
`BOOT_MODE` (UEFI by default), configured in [[linux-lab/.env.example]]. It
requires `/dev/kvm` and `/dev/net/tun` and `NET_ADMIN`; `storage/` and `shared/`
are bind-mounted.

## Lifecycle and readiness

`make boot` waits for the web viewer; `make wait-ready` also waits for SSH and
then writes the `storage/linux.ready` marker.

Probing logic is in [[linux-lab/scripts/wait-ready.sh]]; host checks (with a
lower 16 GB disk floor than the Windows lab) in [[linux-lab/scripts/preflight.sh]].
Readiness stages: container `Up`, web viewer HTTP 200, and SSH accepting.

## State, backup and containment

All guest state is in `storage/`; backup/restore reuse the shared pattern.

See [[linux-lab/scripts/backup.sh]] and [[linux-lab/scripts/restore.sh]];
`make reset CONFIRM=yes` re-provisions a clean guest. Because untrusted code is
expected, network containment is documented in
[[linux-lab/knowledge/networking.md]] and worked workflows in
[[linux-lab/knowledge/usecases.md]].

## Why qemux/qemu

The engine was chosen to match the Windows and macOS labs' compose+web-viewer UX.

Rationale and the alternatives considered (privileged containers, libvirt,
Firecracker, gVisor) are recorded in [[linux-lab/knowledge/draft.md]].

## OS-30 Ubuntu baseline checker and explicit repairs

[[linux-lab/scripts/harden_check.py]] is the standard-library Python entry point
requested by the roadmap. It provides a read-only audit and selected,
consent-gated repairs.

Its default audit delegates to [[linux-lab/scripts/hardening.sh]] for local SSH,
user/sudo, cached-update and UFW checks; text or versioned JSON reports preserve
WARN and FAIL evidence. A missing/empty collector or execution returning no
findings is refused rather than treated as a clean audit.
This runs inside an authorized Ubuntu guest (including ARM64 UTM), independently
of the Docker VM host and its SSH forwarding port.

Repair planning is read-only. Explicitly selected permission/timer/management-rule
repairs require root and exact interactive consent immediately before application.
Snapshots, metadata checks, no-follow file descriptors and a repair lock protect
against drift and overlapping application. SSH authentication and ports are not
changed; no package upgrades, UFW reset or automatic UFW activation occur. Failed
permission/timer changes are rolled back; an unverified UFW addition is reported
as partial state with saved rules, never hidden behind a claimed rollback.

The allowlist and limitations are explained in [[linux-lab/knowledge/hardening.md]].
[[linux-lab/tests/test_hardening.py]] and [[linux-lab/tests/test_harden_check.py]]
use command fakes and temporary files, not real host security changes. Actual
verification and sanitized operator-reported lab summaries are separated in [[VERIFY.md]];
[[REPORT.md]] records scope and remaining acceptance evidence.

Completed schema-2 repair manifests record verified post-state for explicit
`rollback ID`. The same lock and exact consent protect rollback; snapshot and
post-state drift refuse permission/timer restoration. Only a uniquely tagged,
proven run-owned UFW addition may be removed, with ambiguous firewall state
reported as partial recovery. Legacy/incomplete evidence is not trusted.
Rollback tests are in [[linux-lab/tests/test_rollback.py]] and use only temporary
files/fake commands; no live Ubuntu rollback is claimed.
