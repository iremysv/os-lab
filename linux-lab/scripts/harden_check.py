#!/usr/bin/env python3
"""OS-30 entry point: Bash baseline audit plus explicit, reversible repairs.

Only Python's standard library is required. No shell command strings, downloads,
password prompts, automatic elevation or host-forwarding .env values are used.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
from contextlib import contextmanager
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

SCRIPT_DIR = Path(__file__).resolve().parent
SSH_MAIN = Path('/etc/ssh/sshd_config')
SSH_SNIPPETS = Path('/etc/ssh/sshd_config.d')
UFW_FILES = tuple(Path(path) for path in (
    '/etc/ufw/user.rules', '/etc/ufw/user6.rules', '/etc/default/ufw',
    '/etc/ufw/ufw.conf', '/etc/ufw/before.rules', '/etc/ufw/after.rules',
    '/etc/ufw/before6.rules', '/etc/ufw/after6.rules', '/etc/ufw/sysctl.conf',
))
BACKUP_ROOT = Path('/var/backups/os-30')
BACKUP_UID = 0
BACKUP_GID = 0
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
FIXES = ("ssh-permissions", "user-key-permissions", "unattended-timer", "ufw-ssh-rule")


class Refused(RuntimeError):
    """A required safety condition was not established."""


class System:
    """Production boundary; tests inject a fake instead of executing OS tools."""

    def run(self, *args: str) -> subprocess.CompletedProcess:
        env = {"PATH": TRUSTED_PATH, "LC_ALL": "C", "LANG": "C"}
        try:
            return subprocess.run(args, env=env, text=True, capture_output=True,
                                  timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Refused(f"cannot complete {args[0]}; no result inferred") from exc

    def require(self, *args: str) -> str:
        result = self.run(*args)
        if result.returncode:
            # Do not leak arbitrary validator diagnostics or policy data.
            raise Refused(f"command failed: {' '.join(args[:2])}")
        return result.stdout

    def ubuntu(self) -> bool:
        if sys.platform != "linux":
            return False
        try:
            return any(line.strip() in ('ID=ubuntu', 'ID="ubuntu"')
                       for line in Path('/etc/os-release').read_text().splitlines())
        except OSError:
            return False

    def root(self) -> bool:
        return os.geteuid() == 0

    def interactive(self) -> bool:
        return sys.stdin.isatty() and sys.stdout.isatty()

    def account(self, name: str):
        try:
            return pwd.getpwnam(name)
        except KeyError as exc:
            raise Refused("selected local account does not exist") from exc


def trusted_parent(path: Path) -> None:
    """Refuse links or non-root/group-world-writable mutation ancestors."""
    for parent in path.parents:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise Refused(f"unsafe parent: {parent}")
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise Refused(f"untrusted parent permissions: {parent}")


def open_regular(path: Path) -> int:
    if not path.is_absolute() or '..' in path.parts:
        raise Refused('absolute, non-traversing file path required')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)


def private_path(path: Path, directory: bool = False) -> None:
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != BACKUP_UID or info.st_gid != BACKUP_GID
            or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or (not directory and info.st_nlink != 1)):
        raise Refused(f'untrusted backup ownership/type/permissions: {path}')


@contextmanager
def repair_lock(root: Path):
    trusted_parent(root)
    private_path(root, directory=True)
    fd = os.open(root / 'repair.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        private_path(root / 'repair.lock')
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused('another OS-30 repair/rollback is running; no changes') from exc
        yield


def save_manifest(backup: Path, manifest: dict) -> None:
    # Atomic private journal: a crash cannot expose a half-written JSON record.
    fd, temporary = tempfile.mkstemp(prefix='.manifest-', dir=backup)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(manifest, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, backup / 'manifest.json')
        directory = os.open(backup, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def ufw_rules(text: str) -> list[list[str]]:
    return [shlex.split(line) for line in text.splitlines() if line.startswith('ufw ')]


def read_file(path: Path) -> tuple[bytes, dict]:
    # Work through one no-follow descriptor, including the snapshot bytes, to
    # avoid following a link substituted between stat/read/backup/chmod.
    fd = open_regular(path)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Refused(f"single-link regular file required: {path}")
        data = stream.read()
    return data, {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
                  "gid": info.st_gid, "sha256": hashlib.sha256(data).hexdigest()}


def fingerprint(path: Path) -> dict:
    return read_file(path)[1]


def set_mode(path: Path, mode: int, expected: dict) -> None:
    fd = open_regular(path)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Refused(f"unsafe file type/link count: {path}")
        actual = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
                  "gid": info.st_gid, "sha256": hashlib.sha256(stream.read()).hexdigest()}
        if actual != expected:
            raise Refused(f"file changed before permission operation: {path}")
        os.fchmod(stream.fileno(), mode)


def listening_ports(system: System) -> set[int]:
    sockets = system.require("ss", "-H", "-ltnp")
    socket_result = system.run("systemctl", "show", "--property=Listen", "--value", "ssh.socket")
    socket_endpoints = set(re.findall(r"(?:^|\s)(\S+) \(Stream\)", socket_result.stdout))
    ports = set()
    for line in sockets.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        endpoint = fields[3]
        owned = '"sshd"' in line
        activated = '"systemd"' in line and endpoint in socket_endpoints
        if owned or activated:
            try:
                ports.add(int(endpoint.rsplit(':', 1)[1]))
            except (ValueError, IndexError):
                continue
    if not ports:
        raise Refused("cannot attribute actual SSH listening port; .env ports are never used")
    return ports


def audit(system: System, context: str | None, output_format: str) -> int:
    if not system.ubuntu():
        print('[SKIP] platform: Ubuntu required; no audit or application performed')
        return 2
    collector = SCRIPT_DIR / 'hardening.sh'
    if not collector.is_file() or collector.stat().st_size == 0:
        raise Refused('audit collector hardening.sh is missing or empty; audit not performed')
    args = ["bash", str(collector), "audit"]
    if context:
        args += ["--context", context]
    result = system.run(*args)
    if result.returncode in (0, 1) and not re.search(r'^\[(PASS|FAIL|WARN|SKIP)\] ', result.stdout, re.MULTILINE):
        raise Refused('audit collector returned no findings; audit incomplete')
    if output_format == "json":
        findings = []
        for line in result.stdout.splitlines():
            match = re.match(r"^\[(PASS|FAIL|WARN|SKIP)\] ([^:]+): (.*)$", line)
            if match:
                findings.append(dict(zip(("status", "check", "detail"), match.groups())))
            elif findings and not line.startswith("Summary:") and line.strip():
                findings[-1]["detail"] += "\n" + line
        print(json.dumps({"schema_version": 1, "task": "OS-30", "mode": "audit",
                          "recorded_at": datetime.now(timezone.utc).isoformat(),
                          "exit_code": result.returncode, "findings": findings}, indent=2))
    else:
        print(result.stdout, end="")
    if result.stderr:
        print('[WARN] audit.execution: diagnostic output omitted; inspect validator locally', file=sys.stderr)
    return result.returncode


class RepairPlan:
    """Small allowlist of repairs. Construction and preview are read-only."""

    def __init__(self, system: System, fixes: list[str], account: str | None = None,
                 source: str | None = None, port: int | None = None):
        self.system = system
        self.account_name = account
        self.fixes = list(dict.fromkeys(fixes))
        self.files: dict[Path, dict] = {}
        self.desired: dict[Path, int] = {}
        self.steps: list[str] = []
        self.port = port
        self.source = source
        self.timer_state = None
        self.ufw_state: dict[Path, dict] = {}
        self.ufw_before = None
        if not self.fixes:
            raise Refused("select at least one --fix; no default mutation")
        if any(fix not in FIXES for fix in self.fixes):
            raise Refused("unsupported repair")
        self.ports = listening_ports(system) if any(
            fix in self.fixes for fix in ("ssh-permissions", "user-key-permissions", "ufw-ssh-rule")) else set()
        if "ssh-permissions" in self.fixes:
            system.require("sshd", "-t")
            configs = [SSH_MAIN, *sorted(SSH_SNIPPETS.glob('*.conf'))]
            for path in configs:
                trusted_parent(path)
                self.add_mode(path, 0o600, root_owned=True)
        if "user-key-permissions" in self.fixes:
            if not account or not re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?", account):
                raise Refused("--user must name one explicit non-root local account")
            user = system.account(account)
            if user.pw_uid == 0:
                raise Refused("root key-permission repair is not supported")
            directory = Path(user.pw_dir) / '.ssh'
            # Owner-managed home/.ssh ancestors may be writable by their owner,
            # but never by another user or via a symlink.
            for parent in [directory, *directory.parents]:
                info = parent.lstat()
                if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or info.st_uid not in (0, user.pw_uid)
                        or stat.S_IMODE(info.st_mode) & 0o022):
                    raise Refused(f"unsafe account directory: {parent}; repair manually")
            # Only the key file is changed; no recursive chmod/chown of a home.
            key = directory / 'authorized_keys'
            key_data, key_state = read_file(key)
            if key_state['uid'] != user.pw_uid or not key_data:
                raise Refused("nonempty user-owned authorized_keys required")
            self.add_mode(key, 0o600)
        if "unattended-timer" in self.fixes:
            if system.require("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades").strip() != 'install ok installed':
                raise Refused("unattended-upgrades is not already installed")
            system.require("systemctl", "cat", "apt-daily-upgrade.timer")
            state = system.run("systemctl", "is-enabled", "apt-daily-upgrade.timer")
            self.timer_state = state.stdout.strip()
            if self.timer_state not in ('enabled', 'disabled'):
                raise Refused("timer must have an unambiguous enabled/disabled state")
            if self.timer_state == 'disabled':
                self.steps.append('Enable apt-daily-upgrade.timer without --now; future schedules may install updates under existing APT policy')
        if "ufw-ssh-rule" in self.fixes:
            try:
                address = ipaddress.ip_address(source or '')
            except ValueError as exc:
                raise Refused("--management-source must be one IP, not a subnet or shell expression") from exc
            if address.is_unspecified or address.is_multicast:
                raise Refused("invalid management client address")
            self.source = str(address)
            if port not in self.ports:
                raise Refused("--ssh-port must match an attributed real SSH listener")
            status = system.require("ufw", "status", "verbose")
            if 'Status: active' not in status and 'Status: inactive' not in status:
                raise Refused("UFW state unavailable")
            # Rule insertion only: never enable UFW, change defaults or delete
            # existing rules. Do not claim that an earlier deny is overridden.
            rules = ufw_rules(system.require("ufw", "show", "added"))
            self.ufw_before = {"rules": rules, "status": status}
            for path in UFW_FILES:
                trusted_parent(path)
                self.ufw_state[path] = fingerprint(path)
            self.steps.append(f'Add TCP allow rule from {self.source} to actual SSH port {port}; keep UFW activation/defaults and all existing rules unchanged')

    def add_mode(self, path: Path, mode: int, root_owned: bool = False) -> None:
        before = fingerprint(path)
        if root_owned and before['uid'] != 0:
            raise Refused(f"unexpected SSH config owner: {path}; no automatic chown")
        if before['mode'] != mode:
            self.files[path] = before
            self.desired[path] = mode
            self.steps.append(f'{path}: mode {before["mode"]:04o} -> {mode:04o}; contents/owner unchanged')

    def preview(self) -> None:
        print('[WARN] apply.scope: no root/password-login disabling, account deletion, package upgrades, UFW enabling or default-policy changes')
        for number, step in enumerate(self.steps, 1):
            print(f'  {number}. {step}')
        if not self.steps:
            print('[SKIP] apply: selected repairs already satisfied')

    def unchanged(self) -> None:
        for path, before in {**self.files, **self.ufw_state}.items():
            if fingerprint(path) != before:
                raise Refused(f"state changed since preview: {path}; rerun to review")
        if self.ports and listening_ports(self.system) != self.ports:
            raise Refused("SSH listeners changed since preview")
        if self.timer_state is not None:
            state = self.system.run("systemctl", "is-enabled", "apt-daily-upgrade.timer").stdout.strip()
            if state != self.timer_state:
                raise Refused("timer state changed since preview")

    def execute(self, backup_root: Path = Path('/var/backups/os-30')) -> Path | None:
        # Called only after CLI confirmation. No environment-variable root override.
        if not self.steps:
            return None
        self.unchanged()
        trusted_parent(backup_root)
        if backup_root.exists():
            info = backup_root.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise Refused("backup root must be a root-owned real directory with mode 0700")
        else:
            backup_root.mkdir(mode=0o700)
        with repair_lock(backup_root):
            return self._execute_locked(backup_root)

    def _execute_locked(self, backup_root: Path) -> Path:
        self.unchanged()
        backup = Path(tempfile.mkdtemp(prefix='repair-', dir=backup_root))
        states = {**self.files, **self.ufw_state}
        for number, path in enumerate(states):
            data, current = read_file(path)
            if current != states[path]:
                raise Refused('file changed during snapshot; no repairs applied')
            fd = os.open(backup / str(number), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        run_id = backup.name.removeprefix('repair-')
        manifest = {"schema_version": 2, "task": "OS-30", "run_id": run_id,
                    "status": "applying", "fixes": self.fixes, "user": self.account_name,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "files": [{"path": str(path), "backup": str(number), **state,
                               "operation": 'mode' if path in self.files else 'ufw-snapshot'}
                              for number, (path, state) in enumerate(states.items())],
                    "timer_before": self.timer_state, "timer_after": None,
                    "ufw": None, "steps": self.steps}
        save_manifest(backup, manifest)
        # Confirm snapshot consistency before making any system mutation.
        self.unchanged()
        for number, (path, state) in enumerate(states.items()):
            if hashlib.sha256((backup / str(number)).read_bytes()).hexdigest() != state['sha256']:
                raise Refused("backup integrity check failed")
        changed: list[Path] = []
        timer_attempted = False
        ufw_attempted = False
        try:
            for path, mode in self.desired.items():
                changed.append(path)
                set_mode(path, mode, self.files[path])
                if fingerprint(path) != {**self.files[path], 'mode': mode}:
                    raise Refused(f"permission postcondition failed: {path}")
            if 'ssh-permissions' in self.fixes:
                self.system.require('sshd', '-t')
            if self.timer_state == 'disabled':
                timer_attempted = True
                self.system.require('systemctl', 'enable', 'apt-daily-upgrade.timer')
                if self.system.require('systemctl', 'is-enabled', 'apt-daily-upgrade.timer').strip() != 'enabled':
                    raise Refused('timer postcondition failed')
            if 'ufw-ssh-rule' in self.fixes:
                if (ufw_rules(self.system.require('ufw', 'show', 'added')) != self.ufw_before['rules']
                        or self.system.require('ufw', 'status', 'verbose') != self.ufw_before['status']):
                    raise Refused('firewall changed since preview')
                # UFW may update an existing identical rule's comment. Avoid
                # touching such a rule: it could not be proven to belong to us.
                existing = any(self.rule_matches(shlex.join(rule)) for rule in self.ufw_before['rules'])
                ufw = {"before": self.ufw_before, "source": self.source, "port": self.port,
                       "marker": f'OS-30:{run_id}', "added_rule": None}
                if not existing:
                    ufw_attempted = True
                    self.system.require('ufw', 'allow', 'from', self.source, 'to', 'any',
                                        'port', str(self.port), 'proto', 'tcp', 'comment', ufw['marker'])
                rules = ufw_rules(self.system.require('ufw', 'show', 'added'))
                if not existing:
                    candidates = [rule for rule in rules if rule[-2:] == ['comment', ufw['marker']]
                                  and self.rule_matches(shlex.join(rule))]
                    if len(candidates) != 1:
                        raise Refused('added SSH allow rule could not be verified')
                    rule = candidates[0]
                    without = rules.copy()
                    without.remove(rule)
                    if without != self.ufw_before['rules']:
                        raise Refused('firewall change is not exactly one new rule')
                    ufw['added_rule'] = rule
                elif rules != self.ufw_before['rules']:
                    raise Refused('existing firewall rules changed')
                ufw['after'] = {"rules": rules, "status": self.system.require('ufw', 'status', 'verbose')}
                manifest['ufw'] = ufw
            for entry in manifest['files']:
                entry['post'] = fingerprint(Path(entry['path']))
            if self.timer_state is not None:
                manifest['timer_after'] = self.system.require('systemctl', 'is-enabled', 'apt-daily-upgrade.timer').strip()
            manifest['status'] = 'applied'
            save_manifest(backup, manifest)
            print(f'[PASS] apply: selected repairs verified; run-id: {run_id}; backup: {backup}')
            return backup
        except (Exception, KeyboardInterrupt) as exc:
            failures = []
            for path in reversed(changed):
                try:
                    current = fingerprint(path)
                    if current not in (self.files[path], {**self.files[path], 'mode': self.desired[path]}):
                        raise Refused('refusing rollback over concurrent file change')
                    set_mode(path, self.files[path]['mode'], current)
                except (OSError, Refused):
                    failures.append(str(path))
            if timer_attempted:
                try:
                    self.system.require('systemctl', 'disable', 'apt-daily-upgrade.timer')
                    if self.system.run('systemctl', 'is-enabled', 'apt-daily-upgrade.timer').stdout.strip() != 'disabled':
                        raise Refused('timer rollback postcondition failed')
                except Refused:
                    failures.append('timer enablement')
            # Never reset/delete UFW rules as rollback. On an unverified rule
            # addition, retain its snapshot and report partial state explicitly.
            if ufw_attempted:
                failures.append('UFW rule may have been added; inspect saved rules manually (no automatic delete/reset)')
            detail = '; '.join(failures) if failures else 'permission/timer changes rolled back'
            manifest['status'] = 'failed'
            try:
                save_manifest(backup, manifest)
            except OSError:
                detail += '; failed to persist failure journal'
            raise Refused(f'application failed; {detail}; backup: {backup}') from exc

    def rule_matches(self, line: str) -> bool:
        import shlex
        try:
            tokens = shlex.split(line)
        except ValueError:
            return False
        return (tokens[:2] == ['ufw', 'allow'] and
                all(any(tokens[i:i + 2] == pair for i in range(len(tokens) - 1))
                    for pair in (['from', self.source], ['to', 'any'], ['port', str(self.port)], ['proto', 'tcp'])))


def valid_run_id(value: str) -> bool:
    return bool(re.fullmatch(r'[a-z0-9_][a-z0-9_-]{5,63}', value))


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused('duplicate manifest key')
        result[key] = value
    return result


def checked_state(value) -> dict:
    if (not isinstance(value, dict) or set(value) != {'mode', 'uid', 'gid', 'sha256'}
            or any(type(value[k]) is not int or value[k] < 0 for k in ('mode', 'uid', 'gid'))
            or value['mode'] > 0o7777 or not isinstance(value['sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', value['sha256'])):
        raise Refused('invalid file-state metadata')
    return value


class RollbackPlan:
    """Validate all evidence first; restore metadata, never backup file contents."""

    def __init__(self, system: System, run_id: str):
        if not valid_run_id(run_id):
            raise Refused('invalid run-id; pass only the suffix printed after repair-')
        self.system, self.run_id = system, run_id
        self.root = BACKUP_ROOT
        self.backup = self.root / f'repair-{run_id}'
        trusted_parent(self.root)
        private_path(self.root, directory=True)
        private_path(self.backup, directory=True)
        self.manifest_path = self.backup / 'manifest.json'
        private_path(self.manifest_path)
        raw, self.manifest_state = read_file(self.manifest_path)
        if len(raw) > 1_000_000:
            raise Refused('manifest too large')
        self.data = json.loads(raw, object_pairs_hook=no_duplicate_keys)
        self.entries = []
        self.snapshots = {}
        self.validate()
        self.done = self.data['status'] == 'rolled_back'
        self.ufw_reason = None
        self.check_current()

    def validate(self):
        m = self.data
        if (not isinstance(m, dict) or type(m.get('schema_version')) is not int
                or m.get('schema_version') != 2 or m.get('task') != 'OS-30'
                or m.get('run_id') != self.run_id
                or m.get('status') not in ('applied', 'rollback_partial', 'rolled_back')):
            raise Refused('unsupported/unfinished manifest; verified schema-2 post-state required')
        fixes = m.get('fixes')
        if not isinstance(fixes, list) or not fixes or any(f not in FIXES for f in fixes):
            raise Refused('invalid recorded operations')
        files = m.get('files')
        if not isinstance(files, list) or len(files) > 256:
            raise Refused('invalid manifest file inventory')
        seen = set()
        for index, entry in enumerate(files):
            if not isinstance(entry, dict) or entry.get('backup') != str(index):
                raise Refused('backup names must be sequential OS-30 snapshot identifiers')
            path = Path(entry.get('path', ''))
            if not path.is_absolute() or '..' in path.parts or str(path) != entry.get('path') or path in seen:
                raise Refused('invalid/duplicate manifest target')
            seen.add(path)
            before = checked_state({k: entry.get(k) for k in ('mode', 'uid', 'gid', 'sha256')})
            post = checked_state(entry.get('post'))
            operation = entry.get('operation')
            if operation == 'mode':
                ssh = path == SSH_MAIN or (path.parent == SSH_SNIPPETS and path.suffix == '.conf')
                if ssh and 'ssh-permissions' in fixes:
                    if before['uid'] != 0:
                        raise Refused('non-root SSH config in manifest')
                    trusted_parent(path)
                elif 'user-key-permissions' in fixes and isinstance(m.get('user'), str):
                    user = self.system.account(m['user'])
                    if (user.pw_uid == 0 or path != Path(user.pw_dir) / '.ssh' / 'authorized_keys'
                            or before['uid'] != user.pw_uid):
                        raise Refused('invalid selected-account target')
                    for parent in path.parents:
                        info = parent.lstat()
                        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, user.pw_uid)
                                or stat.S_IMODE(info.st_mode) & 0o022):
                            raise Refused('unsafe account ancestry')
                else:
                    raise Refused('manifest target not allowed for recorded operation')
                if post != {**before, 'mode': 0o600} or before['mode'] == post['mode']:
                    raise Refused('post-state does not describe an OS-30 permission-only change')
            elif operation == 'ufw-snapshot' and 'ufw-ssh-rule' in fixes and path in UFW_FILES:
                trusted_parent(path)
                if any(post[k] != before[k] for k in ('uid', 'gid', 'mode')):
                    raise Refused('unexpected UFW ownership/mode change')
            else:
                raise Refused('invalid recorded file operation')
            snapshot = self.backup / str(index)
            private_path(snapshot)
            self.snapshots[snapshot] = fingerprint(snapshot)
            if self.snapshots[snapshot]['sha256'] != before['sha256']:
                raise Refused('backup checksum mismatch')
            if entry.get('rollback') not in (None, 'pending', 'done'):
                raise Refused('invalid rollback journal')
            self.entries.append((path, entry, before, post))
        before, after = m.get('timer_before'), m.get('timer_after')
        if 'unattended-timer' in fixes:
            if before not in ('disabled', 'enabled') or after != 'enabled':
                raise Refused('invalid timer transition')
        elif before is not None or after is not None:
            raise Refused('unselected timer operation')
        if m.get('timer_rollback') not in (None, 'pending', 'done'):
            raise Refused('invalid timer journal')
        self.validate_ufw()

    def validate_ufw(self):
        m, ufw = self.data, self.data.get('ufw')
        if 'ufw-ssh-rule' not in m['fixes']:
            if ufw is not None or any(e['operation'] == 'ufw-snapshot' for _, e, _, _ in self.entries):
                raise Refused('unselected firewall operation')
            return
        if not isinstance(ufw, dict):
            raise Refused('missing firewall post-state')
        paths = {p for p, e, _, _ in self.entries if e['operation'] == 'ufw-snapshot'}
        if paths != set(UFW_FILES):
            raise Refused('firewall snapshots incomplete')
        for state in (ufw.get('before'), ufw.get('after')):
            if (not isinstance(state, dict) or not isinstance(state.get('rules'), list)
                    or not isinstance(state.get('status'), str)
                    or any(not isinstance(rule, list) or any(not isinstance(t, str) for t in rule)
                           for rule in state['rules'])):
                raise Refused('invalid firewall state')
        rule = ufw.get('added_rule')
        if ufw.get('marker') != f'OS-30:{self.run_id}':
            raise Refused('firewall run marker mismatch')
        if rule is None:
            if ufw['before'] != ufw['after']:
                raise Refused('firewall no-op has mismatching state')
            return
        try:
            if not isinstance(ufw['source'], str):
                raise Refused('firewall source must be a canonical IP string')
            source = str(ipaddress.ip_address(ufw['source']))
            if source != ufw['source']:
                raise Refused('firewall source is not canonical')
        except (KeyError, ValueError, TypeError) as exc:
            raise Refused('invalid firewall source') from exc
        port = ufw.get('port')
        if type(port) is not int or not 1 <= port <= 65535:
            raise Refused('invalid firewall port')
        canonical = ['ufw', 'allow', 'from', source, 'to', 'any', 'port', str(port),
                     'proto', 'tcp', 'comment', ufw['marker']]
        # Accept semantic ordering from UFW only if it contains exactly these
        # tokens, with no extra options, and each key/value pair is intact.
        if (not isinstance(rule, list) or len(rule) != len(canonical) or rule[:2] != canonical[:2]
                or sorted(rule[2:]) != sorted(canonical[2:])
                or any(not any(rule[i:i+2] == pair for i in range(2, len(rule)-1))
                       for pair in (canonical[2:4], canonical[4:6], canonical[6:8], canonical[8:10], canonical[10:12]))):
            raise Refused('firewall rule identity not proven')
        before, after = ufw['before']['rules'], ufw['after']['rules']
        without = after.copy()
        if after.count(rule) != 1 or any(ufw['marker'] in token for r in before for token in r):
            raise Refused('firewall marker not unique to this run')
        without.remove(rule)
        if without != before:
            raise Refused('firewall delta is not exactly the recorded rule')
        if ufw.get('rollback') not in (None, 'pending', 'done'):
            raise Refused('invalid firewall rollback journal')

    def check_current(self):
        # Any file/timer drift refuses the entire operation before mutation.
        for path, entry, before, post in self.entries:
            if entry['operation'] == 'ufw-snapshot':
                continue
            actual = fingerprint(path)
            expected = before if entry.get('rollback') == 'done' or self.done else post
            if entry.get('rollback') == 'pending' and actual == before:
                continue  # crash after chmod, before progress journal
            if actual != expected:
                raise Refused(f'current state differs from recorded post-state: {path}; not overwritten')
        if self.data['timer_before'] is not None:
            state = self.system.run('systemctl', 'is-enabled', 'apt-daily-upgrade.timer').stdout.strip()
            expected = self.data['timer_before'] if self.done or self.data.get('timer_rollback') == 'done' else self.data['timer_after']
            if self.data.get('timer_rollback') == 'pending' and state == self.data['timer_before']:
                pass
            elif state != expected:
                raise Refused('timer differs from recorded post-state; not overwritten')
        self.ufw_reason = self.firewall_reason()

    def firewall_reason(self):
        ufw = self.data.get('ufw')
        if not ufw or ufw['added_rule'] is None:
            return None
        try:
            rules = ufw_rules(self.system.require('ufw', 'show', 'added'))
            status = self.system.require('ufw', 'status', 'verbose')
            restored = self.done or ufw.get('rollback') == 'done'
            if (restored or ufw.get('rollback') == 'pending') and rules == ufw['before']['rules'] and status == ufw['before']['status']:
                return None
            if restored or rules != ufw['after']['rules'] or status != ufw['after']['status']:
                return 'firewall policy/rule list differs from recorded post-state'
            for path, entry, _, post in self.entries:
                if entry['operation'] == 'ufw-snapshot' and fingerprint(path) != post:
                    return 'firewall file differs from recorded post-state'
        except (OSError, Refused, ValueError):
            return 'firewall state cannot be verified'
        return None

    def preview(self):
        if self.done:
            print(f'[SKIP] rollback: run {self.run_id} already rolled back; no changes')
            return
        for path, entry, before, post in self.entries:
            if entry['operation'] == 'mode' and entry.get('rollback') != 'done':
                print(f'  Restore only {path} mode {post["mode"]:04o} -> {before["mode"]:04o}; content/owner unchanged')
        if self.data['timer_before'] != self.data['timer_after'] and self.data.get('timer_rollback') != 'done':
            print(f'  Restore timer enablement to {self.data["timer_before"]}; no service start/stop')
        ufw = self.data.get('ufw')
        if ufw and ufw['added_rule'] and ufw.get('rollback') != 'done':
            print(f'  Remove only run-tagged UFW rule {ufw["marker"]}, if all firewall evidence still matches')
        if self.ufw_reason:
            print(f'[WARN] rollback.partial: UFW will not be changed: {self.ufw_reason}; backup: {self.backup}')

    def persist(self):
        save_manifest(self.backup, self.data)
        self.manifest_state = fingerprint(self.manifest_path)

    def execute(self) -> bool:
        with repair_lock(self.root):
            private_path(self.backup, directory=True)
            private_path(self.manifest_path)
            if fingerprint(self.manifest_path) != self.manifest_state:
                raise Refused('manifest changed since preview; no changes')
            for snapshot, expected in self.snapshots.items():
                private_path(snapshot)
                if fingerprint(snapshot) != expected:
                    raise Refused('backup changed since preview; no changes')
            self.check_current()
            if self.done:
                return True
            self.data['status'] = 'rollback_partial'
            self.persist()
            try:
                for path, entry, before, post in self.entries:
                    if entry['operation'] != 'mode' or entry.get('rollback') == 'done':
                        continue
                    actual = fingerprint(path)
                    resumed = entry.get('rollback') == 'pending' and actual == before
                    entry['rollback'] = 'pending'
                    self.persist()
                    if not resumed:
                        set_mode(path, before['mode'], post)
                    if fingerprint(path) != before:
                        raise Refused('permission rollback postcondition failed')
                    entry['rollback'] = 'done'
                    self.persist()
                if self.data['timer_before'] != self.data['timer_after'] and self.data.get('timer_rollback') != 'done':
                    self.data['timer_rollback'] = 'pending'
                    self.persist()
                    state = self.system.run('systemctl', 'is-enabled', 'apt-daily-upgrade.timer').stdout.strip()
                    if state == self.data['timer_after']:
                        self.system.require('systemctl', 'disable', 'apt-daily-upgrade.timer')
                    elif state != self.data['timer_before']:
                        raise Refused('timer drift during rollback')
                    if self.system.run('systemctl', 'is-enabled', 'apt-daily-upgrade.timer').stdout.strip() != self.data['timer_before']:
                        raise Refused('timer rollback postcondition failed')
                    self.data['timer_rollback'] = 'done'
                    self.persist()
                ufw = self.data.get('ufw')
                if ufw and ufw['added_rule'] and ufw.get('rollback') != 'done':
                    self.ufw_reason = self.firewall_reason()
                    if not self.ufw_reason:
                        ufw['rollback'] = 'pending'
                        self.persist()
                        rules = ufw_rules(self.system.require('ufw', 'show', 'added'))
                        if rules == ufw['after']['rules']:
                            reason = self.firewall_reason()
                            if reason:
                                raise Refused(f'firewall changed before deletion: {reason}')
                            # Fixed argv built from validated scalar fields, never
                            # execute arbitrary commands from the manifest.
                            self.system.require('ufw', '--force', 'delete', 'allow', 'from', ufw['source'],
                                                'to', 'any', 'port', str(ufw['port']), 'proto', 'tcp',
                                                'comment', ufw['marker'])
                        elif rules != ufw['before']['rules']:
                            raise Refused('firewall drift immediately before deletion')
                        if (ufw_rules(self.system.require('ufw', 'show', 'added')) != ufw['before']['rules']
                                or self.system.require('ufw', 'status', 'verbose') != ufw['before']['status']):
                            raise Refused('firewall rollback postcondition failed; no further deletion')
                        ufw['rollback'] = 'done'
                        self.persist()
                if self.ufw_reason:
                    print(f'[WARN] rollback.partial: {self.ufw_reason}; UFW untouched; backup: {self.backup}')
                    return False
                self.data['status'] = 'rolled_back'
                self.persist()
                print(f'[PASS] rollback: run {self.run_id} restored; backup retained: {self.backup}')
                return True
            except (Exception, KeyboardInterrupt) as exc:
                # Progress is journaled per operation. Never repeat unrelated
                # operations or roll forward over an administrator's changes.
                raise Refused(f'partial rollback; stopped safely; backup: {self.backup}') from exc


def main(argv: list[str] | None = None, system: System | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', choices=('audit', 'plan', 'apply', 'rollback'), default='audit')
    parser.add_argument('run_id', nargs='?', help='rollback run suffix (not a file path)')
    parser.add_argument('--context', help='sshd -C connection context; never inferred from .env')
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    parser.add_argument('--fix', action='append', choices=FIXES, default=[])
    parser.add_argument('--user', help='explicit account for user-key-permissions')
    parser.add_argument('--management-source', help='single management client IP for ufw-ssh-rule')
    parser.add_argument('--ssh-port', type=int, help='actual guest SSH listener, not the forwarded host port')
    args = parser.parse_args(argv)
    system = system or System()
    try:
        if args.mode == 'rollback':
            if not args.run_id or args.fix or args.user or args.management_source or args.ssh_port is not None or args.context or args.format != 'text':
                raise Refused('rollback requires only one run-id, no repair/audit options')
            if not system.ubuntu() or not system.root():
                raise Refused('rollback requires root inside Ubuntu; no automatic sudo')
            plan = RollbackPlan(system, args.run_id)
            plan.preview()
            if plan.done:
                return 0 if not plan.ufw_reason else 2
            if not system.interactive():
                raise Refused('input/output TTY required; no changes')
            if input(f'Type exactly ROLLBACK OS-30 {args.run_id}: ') != f'ROLLBACK OS-30 {args.run_id}':
                raise Refused('rollback confirmation mismatch; no changes')
            return 0 if plan.execute() else 2
        if args.run_id is not None:
            raise Refused('run-id is only valid with rollback')
        if args.mode == 'audit':
            if args.fix or args.user or args.management_source or args.ssh_port is not None:
                raise Refused('repair arguments are only valid with plan/apply')
            return audit(system, args.context, args.format)
        if args.context or args.format != 'text':
            raise Refused('--context/--format are audit options')
        if not system.ubuntu():
            raise Refused('Ubuntu required; no changes')
        if not system.root():
            raise Refused('root required to inspect the complete repair plan; no automatic sudo')
        plan = RepairPlan(system, args.fix, args.user, args.management_source, args.ssh_port)
        plan.preview()
        if args.mode == 'plan' or not plan.steps:
            return 0
        if not system.interactive():
            raise Refused('input/output TTY required; no changes')
        answer = input('Type exactly APPLY OS-30 to apply only the listed repairs: ')
        if answer != 'APPLY OS-30':
            raise Refused('confirmation mismatch; no changes')
        plan.execute()
        return 0
    except (Refused, OSError, EOFError, ValueError, TypeError) as exc:
        print(f'[FAIL] {args.mode}: {exc}', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('[WARN] operation interrupted; inspect any backup path printed above', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
