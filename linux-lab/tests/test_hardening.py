"""OS-30 subprocess tests: security commands are isolated PATH mocks."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'hardening.sh'
MOCK = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as f:
    f.write(json.dumps([name] + args) + '\n')
case = os.environ.get('CASE', '')
if name == 'uname': print('Darwin' if case == 'mac' else 'Linux'); sys.exit(0)
if name == 'grep' and args == ['-q', '^ID=ubuntu$', '/etc/os-release']: sys.exit(0)
if name == 'grep':
    s = sys.stdin.read()
    sys.exit(0 if s.strip() == 'install ok installed' else 1)
if name == 'systemctl':
    if args[0] == 'show':
        print('[::]:22 (Stream)' if case == 'socket' else '')
        sys.exit(0)
    if args[0] == 'is-enabled': sys.exit(0 if Path(os.environ['STATE']).exists() else 1)
    if args[0] in ('is-active', 'cat'): sys.exit(0)
    if args == ['enable', 'apt-daily-upgrade.timer']:
        Path(os.environ['STATE']).touch(); sys.exit(0)
    sys.exit(99)
if name == 'ss' and case in ('socket', 'unrelated_socket'):
    print('LISTEN 0 128 [::]:22 [::]:* users:(("systemd",pid=1,fd=3))\nLISTEN 0 128 127.0.0.1:9999 0.0.0.0:* users:(("systemd",pid=1,fd=4))'); sys.exit(0)
if name == 'ss': print('LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))'); sys.exit(0)
if name == 'sshd':
    if case == 'sshd_error': sys.exit(1)
    if case == 'sshd_denied': print('Permission denied', file=sys.stderr); sys.exit(1)
    if case == 'sshd_syntax': print('Bad configuration option: invalid', file=sys.stderr); sys.exit(1)
    if args == ['-t']: sys.exit(0)
    if args[0] == '-T':
        if case == 'match_password' and '-C' in args:
            print('permitrootlogin no\npasswordauthentication yes\npermitemptypasswords no\npubkeyauthentication yes\nkbdinteractiveauthentication no'); sys.exit(0)
        print('permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\npubkeyauthentication yes\nkbdinteractiveauthentication no')
        sys.exit(0)
    sys.exit(99)
if name == 'getent':
    if args == ['passwd']:
        print('root:x:0:0:PRIVATE:/root:/bin/bash')
        if case == 'uid0': print('extra:x:0:0:PRIVATE:/x:/bin/bash')
        if case == 'sync': print('sync:x:4:65534:PRIVATE:/bin:/bin/sync')
    else: print('sudo:x:27:admin')
    sys.exit(0)
if name == 'passwd':
    if case == 'empty_password': print(args[-1] + ' NP 2026-01-01 0 99999 7 -1')
    else: print(args[-1] + ' L 2026-01-01 0 99999 7 -1')
    sys.exit(0)
if name == 'visudo':
    if case == 'sudo_syntax': print('/etc/sudoers: syntax error', file=sys.stderr); sys.exit(1)
    if case == 'sudo_denied': print('Permission denied', file=sys.stderr); sys.exit(1)
    sys.exit(1 if case == 'sudo_error' else 0)
if name == 'sudo':
    if args != ['-n', '-l', '-U', 'root']: sys.exit(99)
    if case == 'policy_denied': sys.exit(1)
    print('User root may run the following commands on lab:\n    (ALL : ALL) NOPASSWD: /usr/bin/id'); sys.exit(0)
if name == 'apt':
    if args != ['list', '--upgradable']: sys.exit(99)
    print('Listing...\npkg/noble-security 2 arm64 [upgradable from: 1]'); sys.exit(0)
if name == 'apt-config': print('APT::Periodic::Unattended-Upgrade "1";'); sys.exit(0)
if name == 'dpkg-query': print('install ok installed'); sys.exit(0)
if name == 'ufw':
    if case == 'ufw_denied': sys.exit(1)
    if case == 'ufw_missing': sys.exit(127)
    if args == ['status', 'verbose'] and case == 'ufw_inactive': print('Status: inactive'); sys.exit(0)
    if args == ['status', 'verbose'] and case == 'ufw_unknown': print('Status: unknown'); sys.exit(0)
    if args == ['status', 'verbose'] and case == 'ufw_permissive': print('Status: active\nDefault: allow (incoming), allow (outgoing)'); sys.exit(0)
    if args == ['status', 'verbose'] and case == 'ufw_strict_outgoing': print('Status: active\nDefault: deny (incoming), deny (outgoing)'); sys.exit(0)
    if args == ['status', 'verbose']: print('Status: active\nDefault: deny (incoming), allow (outgoing)'); sys.exit(0)
    if args == ['show', 'added']: print('ufw allow 22/tcp'); sys.exit(0)
    sys.exit(99)
if name == 'stat': print('0 666' if case == 'unsafe_mode' else '0 644'); sys.exit(0)
if name == 'find': print('1700000000.0'); sys.exit(0)
if name == 'id': print('1000' if case == 'nonroot' else '0'); sys.exit(0)
sys.exit(99)
'''


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        mock = self.root / 'mock'
        mock.write_text(MOCK)
        mock.chmod(0o755)
        for cmd in ('uname', 'grep', 'systemctl', 'ss', 'sshd', 'getent', 'passwd',
                    'visudo', 'sudo', 'apt', 'apt-config', 'dpkg-query', 'ufw', 'stat', 'find', 'id',
                    'apt-get', 'chmod', 'chown', 'cp', 'usermod', 'userdel', 'reboot'):
            (self.root / cmd).symlink_to(mock)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'],
                        CALLS=str(self.root / 'calls'), STATE=str(self.root / 'state'))

    def run_script(self, *args, case=''):
        self.env['CASE'] = case
        return subprocess.run(['bash', str(SCRIPT), *args], env=self.env,
                              text=True, capture_output=True, timeout=10)

    def calls(self):
        return [json.loads(line) for line in (self.root / 'calls').read_text().splitlines()]

    def assert_read_only(self):
        for call in self.calls():
            self.assertNotIn(call[0], ('apt-get', 'chmod', 'chown', 'cp', 'usermod', 'userdel', 'reboot'))
            if call[0] == 'systemctl': self.assertIn(call[1], ('is-active', 'is-enabled', 'cat', 'show'))
            if call[0] == 'sudo': self.assertEqual(call[1:], ['-n', '-l', '-U', 'root'])
            if call[0] == 'ufw': self.assertIn(call[1:], (['status', 'verbose'], ['show', 'added']))
            if call[0] == 'apt': self.assertEqual(call[1:], ['list', '--upgradable'])

    def test_default_audit(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('[WARN] ssh.context', result.stdout)
        self.assertNotIn('PRIVATE', result.stdout)
        self.assert_read_only()

    def test_inactive_ufw_is_baseline_failure(self):
        result = self.run_script(case='ufw_inactive')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('[FAIL] ufw.status: Status: inactive', result.stdout)
        self.assert_read_only()

    def test_inaccessible_ufw_remains_warning(self):
        for case in ('ufw_denied', 'ufw_missing', 'ufw_unknown'):
            with self.subTest(case=case):
                result = self.run_script(case=case)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('[WARN] ufw.status:', result.stdout)
                self.assertNotIn('[FAIL] ufw.status:', result.stdout)
                self.assert_read_only()

    def test_sync_utility_is_not_an_interactive_shell(self):
        result = self.run_script(case='sync')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('review interactive account: sync', result.stdout)
        self.assertNotIn(['passwd', '-S', 'sync'], self.calls())
        self.assertIn('review interactive account: root', result.stdout)
        self.assert_read_only()

    def test_explicit_context_delegated_to_sshd(self):
        context = 'user=admin,host=client,addr=192.0.2.1,laddr=192.0.2.2,lport=22'
        result = self.run_script('audit', '--context', context)
        self.assertEqual(result.returncode, 0)
        self.assertIn(['sshd', '-T', '-C', context], self.calls())
        self.assert_read_only()

    def test_failed_sshd_is_warning(self):
        result = self.run_script(case='sshd_error')
        self.assertIn('[WARN] ssh.syntax', result.stdout)
        self.assertNotIn('[PASS] ssh.permitrootlogin', result.stdout)
        self.assert_read_only()

    def test_parser_errors_are_failures_and_permissions_still_checked(self):
        for case, check in (('sshd_syntax', 'ssh.syntax'), ('sudo_syntax', 'users.sudoers')):
            with self.subTest(case=case):
                result = self.run_script(case=case)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('[FAIL] ' + check, result.stdout)
                self.assertIn('[PASS] ssh.permissions', result.stdout)
                self.assert_read_only()

    def test_permission_denials_remain_warnings(self):
        for case, check in (('sshd_denied', 'ssh.syntax'), ('sudo_denied', 'users.sudoers')):
            with self.subTest(case=case):
                result = self.run_script(case=case)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('[WARN] ' + check, result.stdout)
                self.assertIn('[PASS] ssh.permissions', result.stdout)
                self.assert_read_only()

    def test_unsafe_ssh_config_permissions_fail(self):
        result = self.run_script(case='unsafe_mode')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('[FAIL] ssh.permissions', result.stdout)
        self.assert_read_only()

    def test_match_context_changes_effective_result(self):
        context = 'user=root,host=client,addr=192.0.2.1,laddr=192.0.2.2,lport=22'
        global_result = self.run_script(case='match_password')
        result = self.run_script('audit', '--context', context, case='match_password')
        self.assertEqual(global_result.returncode, 0)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('[FAIL] ssh.passwordauthentication: yes', result.stdout)
        self.assert_read_only()

    def test_ufw_defaults_are_evaluated(self):
        for case in ('ufw_permissive', 'ufw_strict_outgoing'):
            with self.subTest(case=case):
                result = self.run_script(case=case)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('[FAIL] ufw.policy', result.stdout)
                self.assert_read_only()

    def test_known_ufw_default_policy_passes(self):
        result = self.run_script()
        self.assertIn('[PASS] ufw.policy', result.stdout)
        self.assert_read_only()

    def test_direct_sshd_listener_is_attributed(self):
        result = self.run_script()
        self.assertIn('[PASS] ssh.listeners: sshd-owned TCP endpoints: 0.0.0.0:22', result.stdout)
        self.assert_read_only()

    def test_socket_endpoint_is_correlated_and_unrelated_port_excluded(self):
        result = self.run_script(case='socket')
        self.assertIn('[PASS] ssh.socket_listeners: ssh.socket/systemd endpoint match: [::]:22', result.stdout)
        self.assertNotIn('9999', result.stdout)
        self.assert_read_only()

    def test_unrelated_systemd_listener_not_claimed_as_ssh(self):
        result = self.run_script(case='unrelated_socket')
        self.assertIn('[WARN] ssh.listeners: no attributable', result.stdout)
        self.assertNotIn('[PASS] ssh.socket_listeners', result.stdout)
        self.assert_read_only()

    def test_effective_sudo_commands_reported(self):
        result = self.run_script()
        self.assertIn('root allowed command specifications:', result.stdout)
        self.assertIn('NOPASSWD: /usr/bin/id', result.stdout)
        self.assert_read_only()

    def test_failed_sudo_query_does_not_claim_no_privileges(self):
        result = self.run_script(case='policy_denied')
        self.assertIn('no absence of privilege inferred', result.stdout)
        self.assert_read_only()

    def test_unprivileged_audit_does_not_query_another_users_sudo_policy(self):
        result = self.run_script(case='nonroot')
        self.assertIn('root and sudo required', result.stdout)
        self.assertFalse(any(call[0] == 'sudo' for call in self.calls()))
        self.assert_read_only()

    def test_uid_zero_failure(self):
        result = self.run_script(case='uid0')
        self.assertEqual(result.returncode, 1)
        self.assertIn('[FAIL] users.uid0', result.stdout)

    def test_empty_password_failure(self):
        result = self.run_script(case='empty_password')
        self.assertEqual(result.returncode, 1)
        self.assertIn('[FAIL] users.password', result.stdout)

    def test_sudoers_validation_warning(self):
        result = self.run_script(case='sudo_error')
        self.assertIn('[WARN] users.sudoers', result.stdout)

    def test_legacy_bash_apply_has_no_mutation_path(self):
        result = self.run_script('apply')
        self.assertEqual(result.returncode, 2)
        self.assertIn('Bash audit performs no mutations', result.stdout)
        self.assert_read_only()

    def test_mac_platform_is_rejected(self):
        result = self.run_script(case='mac')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), [['uname', '-s']])

    def test_unknown_option(self):
        self.assertEqual(self.run_script('--yes').returncode, 2)


if __name__ == '__main__':
    unittest.main()
