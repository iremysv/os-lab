"""Rollback tests: temporary snapshots/files and FakeSystem only, never real OS tools."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_harden_check as fixtures

hc = fixtures.hc


class RollbackTests(unittest.TestCase):
    plan = fixtures.RepairTests.plan

    def setUp(self):
        fixtures.RepairTests.setUp(self)
        # Represent root-owned production target metadata on a non-root Mac.
        # Backup storage remains truly owned by the current test user, validated
        # through the explicit test-only BACKUP_UID/GID patches in the fixture.
        defaults = self.root / 'ufw-defaults'
        defaults.write_text('DEFAULT_INPUT_POLICY=DROP\n')
        self.rules = (*self.rules, defaults)
        p = patch.object(hc, 'UFW_FILES', self.rules)
        p.start(); self.addCleanup(p.stop)
        original_fstat = os.fstat
        inodes = {p.stat().st_ino for p in [self.config, *self.rules]}
        def fstat(fd):
            value = original_fstat(fd)
            if value.st_ino in inodes:
                fields = list(value)
                fields[4:6] = [0, 0]
                return os.stat_result(fields)
            return value
        p = patch.object(hc.os, 'fstat', side_effect=fstat)
        p.start(); self.addCleanup(p.stop)
        p = patch.object(hc, 'BACKUP_ROOT', self.backups)
        p.start(); self.addCleanup(p.stop)

    def applied(self, fixes=None):
        with contextlib.redirect_stdout(io.StringIO()):
            backup = self.plan(fixes).execute(self.backups)
        return backup, backup.name.removeprefix('repair-')

    def rollback(self, run_id):
        plan = hc.RollbackPlan(self.system, run_id)
        with contextlib.redirect_stdout(io.StringIO()):
            plan.preview()
            return plan.execute()

    def edit(self, backup, update):
        path = backup / 'manifest.json'
        value = json.loads(path.read_text())
        update(value)
        path.write_text(json.dumps(value))

    def test_apply_records_verified_post_state_and_successful_rollback(self):
        backup, run_id = self.applied()
        before_contents = self.config.read_bytes()
        data = json.loads((backup / 'manifest.json').read_text())
        self.assertEqual(data['schema_version'], 2)
        self.assertEqual(data['status'], 'applied')
        self.assertEqual(data['files'][0]['post']['mode'], 0o600)
        self.assertTrue(self.rollback(run_id))
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.config.read_bytes(), before_contents)
        self.assertEqual(json.loads((backup / 'manifest.json').read_text())['status'], 'rolled_back')

    def test_invalid_ids_and_traversal_are_rejected(self):
        for value in ('../repair-abcd12', '/tmp/abcd12', 'a/bcdef', 'repair-../../etc', '.', '', 'ABCDEF', 'ab\x00cdef'):
            with self.subTest(value=value), self.assertRaises(hc.Refused):
                hc.RollbackPlan(self.system, value)
        self.assertEqual(self.system.calls, [])

    def test_unknown_well_formed_id_is_refused(self):
        self.applied()
        with self.assertRaises(OSError): hc.RollbackPlan(self.system, 'unknown1')

    def test_broken_legacy_and_unfinished_manifests_refused(self):
        backup, run_id = self.applied()
        original = (backup / 'manifest.json').read_text()
        cases = ['{bad json', '{"task":"OS-30","task":"OTHER"}', json.dumps({'files': []})]
        for raw in cases:
            (backup / 'manifest.json').write_text(raw)
            with self.subTest(raw=raw), self.assertRaises((hc.Refused, ValueError)):
                hc.RollbackPlan(self.system, run_id)
        (backup / 'manifest.json').write_text(original)
        self.edit(backup, lambda m: m.update(status='failed'))
        with self.assertRaises(hc.Refused): hc.RollbackPlan(self.system, run_id)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_manifest_target_outside_allowlist_refused(self):
        backup, run_id = self.applied()
        self.edit(backup, lambda m: m['files'][0].update(path='/etc/passwd'))
        with self.assertRaises(hc.Refused): hc.RollbackPlan(self.system, run_id)

    def test_snapshot_path_traversal_refused(self):
        backup, run_id = self.applied()
        self.edit(backup, lambda m: m['files'][0].update(backup='../manifest.json'))
        with self.assertRaises(hc.Refused): hc.RollbackPlan(self.system, run_id)

    def test_snapshot_hash_tampering_refused(self):
        backup, run_id = self.applied()
        (backup / '0').write_bytes(b'tampered')
        with self.assertRaisesRegex(hc.Refused, 'checksum'): hc.RollbackPlan(self.system, run_id)

    def test_snapshot_and_manifest_symlinks_refused(self):
        backup, run_id = self.applied()
        snapshot = backup / '0'
        snapshot.unlink(); snapshot.symlink_to(self.config)
        with self.assertRaises(hc.Refused): hc.RollbackPlan(self.system, run_id)
        snapshot.unlink(); snapshot.write_bytes(self.config.read_bytes()); snapshot.chmod(0o600)
        manifest = backup / 'manifest.json'
        actual = backup / 'saved'
        manifest.rename(actual); manifest.symlink_to(actual)
        with self.assertRaises(hc.Refused): hc.RollbackPlan(self.system, run_id)

    def test_run_directory_symlink_refused(self):
        backup, _ = self.applied()
        (self.backups / 'repair-linked1').symlink_to(backup, target_is_directory=True)
        with self.assertRaises(hc.Refused): hc.RollbackPlan(self.system, 'linked1')

    def test_backup_hardlink_is_refused(self):
        backup, run_id = self.applied()
        os.link(backup / '0', backup / 'second-link')
        with self.assertRaises(hc.Refused): hc.RollbackPlan(self.system, run_id)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_lock_symlink_is_refused_without_target_changes(self):
        _, run_id = self.applied()
        plan = hc.RollbackPlan(self.system, run_id)
        lock = self.backups / 'repair.lock'
        lock.unlink(); lock.symlink_to(self.config)
        with self.assertRaises(OSError): plan.execute()
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_unexpected_backup_permissions_refused(self):
        backup, run_id = self.applied()
        for target, mode, restore in ((self.backups, 0o755, 0o700), (backup, 0o777, 0o700),
                                      (backup / 'manifest.json', 0o644, 0o600), (backup / '0', 0o666, 0o600)):
            target.chmod(mode)
            with self.subTest(target=target), self.assertRaises(hc.Refused): hc.RollbackPlan(self.system, run_id)
            target.chmod(restore)

    def test_unexpected_backup_owner_refused(self):
        _, run_id = self.applied()
        with patch.object(hc, 'BACKUP_UID', os.getuid() + 1), self.assertRaises(hc.Refused):
            hc.RollbackPlan(self.system, run_id)

    def test_modified_content_prevents_all_changes_including_timer(self):
        _, run_id = self.applied(['ssh-permissions', 'unattended-timer'])
        self.config.write_text('administrator changed this\n')
        calls = len(self.system.calls)
        with self.assertRaisesRegex(hc.Refused, 'post-state'): hc.RollbackPlan(self.system, run_id)
        self.assertTrue(self.system.enabled)
        self.assertFalse(any(call[:2] == ('systemctl', 'disable') for call in self.system.calls[calls:]))

    def test_mode_or_owner_drift_refused(self):
        _, run_id = self.applied()
        self.config.chmod(0o640)
        with self.assertRaises(hc.Refused): hc.RollbackPlan(self.system, run_id)
        self.config.chmod(0o600)
        original = hc.fingerprint
        def fingerprint(path):
            result = original(path)
            return {**result, 'uid': 1234} if path == self.config else result
        with patch.object(hc, 'fingerprint', side_effect=fingerprint), self.assertRaises(hc.Refused):
            hc.RollbackPlan(self.system, run_id)

    def test_drift_after_preview_refused(self):
        _, run_id = self.applied()
        plan = hc.RollbackPlan(self.system, run_id)
        self.config.write_text('late edit\n')
        with self.assertRaises(hc.Refused): plan.execute()
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_manifest_change_after_preview_refused(self):
        backup, run_id = self.applied()
        plan = hc.RollbackPlan(self.system, run_id)
        self.edit(backup, lambda m: m.update(steps=['modified']))
        with self.assertRaisesRegex(hc.Refused, 'manifest changed'): plan.execute()

    def test_snapshot_or_run_permissions_changed_after_preview_refused(self):
        backup, run_id = self.applied()
        plan = hc.RollbackPlan(self.system, run_id)
        (backup / '0').write_bytes(b'late backup edit')
        with self.assertRaisesRegex(hc.Refused, 'backup changed'): plan.execute()
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_run_directory_permissions_changed_after_preview_refused(self):
        backup, run_id = self.applied()
        plan = hc.RollbackPlan(self.system, run_id)
        backup.chmod(0o777)
        with self.assertRaises(hc.Refused): plan.execute()
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_timer_previous_disabled_state_restored_without_stopping_service(self):
        _, run_id = self.applied(['unattended-timer'])
        self.assertTrue(self.system.enabled)
        self.assertTrue(self.rollback(run_id))
        self.assertFalse(self.system.enabled)
        self.assertFalse(any('stop' in c or 'start' in c or '--now' in c for c in self.system.calls))

    def test_already_enabled_timer_never_disabled(self):
        self.system.enabled = True
        _, run_id = self.applied(['ssh-permissions', 'unattended-timer'])
        self.assertTrue(self.rollback(run_id))
        self.assertTrue(self.system.enabled)
        self.assertNotIn(('systemctl', 'disable', 'apt-daily-upgrade.timer'), self.system.calls)

    def test_timer_drift_refuses_permission_restore(self):
        _, run_id = self.applied(['ssh-permissions', 'unattended-timer'])
        self.system.enabled = False
        with self.assertRaisesRegex(hc.Refused, 'timer differs'): hc.RollbackPlan(self.system, run_id)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_ufw_removes_only_exact_run_tagged_rule(self):
        self.system.extra_rules = ['ufw allow 443/tcp']
        plan = self.plan(['ufw-ssh-rule'], source='192.0.2.10', port=22)
        with contextlib.redirect_stdout(io.StringIO()): backup = plan.execute(self.backups)
        run_id = backup.name.removeprefix('repair-')
        self.assertTrue(self.rollback(run_id))
        self.assertFalse(self.system.rule_added)
        self.assertTrue(self.rollback(run_id))  # never delete again on a completed run
        self.assertEqual(self.system.extra_rules, ['ufw allow 443/tcp'])
        deletes = [c for c in self.system.calls if c[:3] == ('ufw', '--force', 'delete')]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0][-2:], ('comment', f'OS-30:{run_id}'))
        self.assertFalse(any(c[:2] == ('ufw', 'reset') for c in self.system.calls))

    def ufw_applied(self, with_modes=False):
        fixes = ['ssh-permissions', 'ufw-ssh-rule'] if with_modes else ['ufw-ssh-rule']
        with contextlib.redirect_stdout(io.StringIO()):
            backup = self.plan(fixes, source='192.0.2.10', port=22).execute(self.backups)
        return backup, backup.name.removeprefix('repair-')

    def test_preexisting_equivalent_rule_is_not_retagged_or_removed(self):
        self.system.rule_added = True
        self.system.marker = 'ADMIN-EXISTING'
        _, run_id = self.ufw_applied()
        self.assertTrue(self.rollback(run_id))
        self.assertTrue(self.system.rule_added)
        self.assertEqual(self.system.marker, 'ADMIN-EXISTING')
        self.assertFalse(any(c[:2] == ('ufw', 'allow') or c[:3] == ('ufw', '--force', 'delete') for c in self.system.calls))

    def test_duplicate_run_marker_never_deleted(self):
        _, run_id = self.ufw_applied()
        self.system.extra_rules.append(f'ufw allow from 192.0.2.10 to any port 22 proto tcp comment OS-30:{run_id}')
        self.assertFalse(self.rollback(run_id))
        self.assertTrue(self.system.rule_added)
        self.assertFalse(any(c[:3] == ('ufw', '--force', 'delete') for c in self.system.calls))

    def test_status_change_prevents_rule_deletion(self):
        _, run_id = self.ufw_applied()
        original = self.system.run
        def run(*args):
            if args == ('ufw', 'status', 'verbose'):
                return subprocess.CompletedProcess(args, 0, stdout='Status: active', stderr='')
            return original(*args)
        with patch.object(self.system, 'run', side_effect=run):
            self.assertFalse(self.rollback(run_id))
        self.assertTrue(self.system.rule_added)

    def test_firewall_drift_skips_ufw_but_restores_proven_permissions(self):
        _, run_id = self.ufw_applied(with_modes=True)
        self.system.extra_rules.append('ufw deny 8080/tcp')
        self.assertFalse(self.rollback(run_id))
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.assertTrue(self.system.rule_added)
        self.assertFalse(any(c[:3] == ('ufw', '--force', 'delete') for c in self.system.calls))
        self.assertFalse(self.rollback(run_id))  # safe partial repeat, no other deletion

    def test_firewall_file_drift_prevents_rule_deletion(self):
        _, run_id = self.ufw_applied()
        self.rules[0].write_text('external firewall edit\n')
        self.assertFalse(self.rollback(run_id))
        self.assertTrue(self.system.rule_added)

    def test_firewall_default_config_drift_prevents_deletion(self):
        _, run_id = self.ufw_applied()
        self.rules[-1].write_text('DEFAULT_INPUT_POLICY=ACCEPT\n')
        self.assertFalse(self.rollback(run_id))
        self.assertTrue(self.system.rule_added)
        self.assertFalse(any(c[:3] == ('ufw', '--force', 'delete') for c in self.system.calls))

    def test_ambiguous_or_forged_rule_identity_refused(self):
        backup, run_id = self.ufw_applied()
        self.edit(backup, lambda m: m['ufw']['added_rule'].extend(['route', 'allow']))
        with self.assertRaises(hc.Refused): hc.RollbackPlan(self.system, run_id)
        self.assertTrue(self.system.rule_added)

    def test_partial_command_failure_can_resume_without_repeating_chmod(self):
        backup, run_id = self.applied(['ssh-permissions', 'unattended-timer'])
        self.system.fail_disable = True
        plan = hc.RollbackPlan(self.system, run_id)
        with self.assertRaisesRegex(hc.Refused, 'partial rollback'): plan.execute()
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.assertEqual(json.loads((backup / 'manifest.json').read_text())['status'], 'rollback_partial')
        self.system.fail_disable = False
        with patch.object(hc, 'set_mode', side_effect=AssertionError('must not chmod again')):
            self.assertTrue(self.rollback(run_id))

    def test_failed_ufw_delete_leaves_partial_journal(self):
        backup, run_id = self.ufw_applied()
        self.system.fail_delete = True
        with self.assertRaisesRegex(hc.Refused, 'partial rollback'):
            hc.RollbackPlan(self.system, run_id).execute()
        self.assertTrue(self.system.rule_added)
        self.assertEqual(json.loads((backup / 'manifest.json').read_text())['status'], 'rollback_partial')
        self.system.fail_delete = False
        self.assertTrue(self.rollback(run_id))

    def test_completed_run_repeat_is_noop(self):
        _, run_id = self.applied(['ssh-permissions', 'unattended-timer'])
        self.assertTrue(self.rollback(run_id))
        with patch.object(hc, 'set_mode', side_effect=AssertionError('no repeated chmod')):
            self.assertTrue(self.rollback(run_id))
        self.assertEqual(sum(c[:2] == ('systemctl', 'disable') for c in self.system.calls), 1)

    def test_lock_contention_is_refused(self):
        _, run_id = self.applied()
        plan = hc.RollbackPlan(self.system, run_id)
        with (self.backups / 'repair.lock').open('r+') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(hc.Refused, 'another OS-30'): plan.execute()

    def test_cli_confirmation_tty_and_root_guards(self):
        _, run_id = self.applied()
        for answer in ('yes', 'ROLLBACK OS-30', f'ROLLBACK OS-30 {run_id} '):
            with patch('builtins.input', return_value=answer), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(hc.main(['rollback', run_id], self.system), 2)
        self.system.tty = False
        with patch('builtins.input', side_effect=AssertionError('must not prompt')), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(hc.main(['rollback', run_id], self.system), 2)
        self.system.tty = True
        self.system.is_root = False
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(hc.main(['rollback', run_id], self.system), 2)
        self.system.is_root = True
        with patch('builtins.input', return_value=f'ROLLBACK OS-30 {run_id}'), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(hc.main(['rollback', run_id], self.system), 0)

    def test_cli_missing_id_and_extra_options_refused(self):
        for args in (['rollback'], ['rollback', 'abcdef', '--fix', 'unattended-timer'], ['plan', 'abcdef']):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(hc.main(args, self.system), 2)


class RollbackTerminalTests(unittest.TestCase):
    tty_run = fixtures.TerminalTests.tty_run

    def harness(self):
        return (
            "import sys; sys.path.insert(0, " + repr(str(Path(__file__).resolve().parent)) + "); "
            "import test_harden_check as t; s=t.FakeSystem(); "
            "s.interactive=lambda: sys.stdin.isatty() and sys.stdout.isatty(); "
            "P=type('P',(),{'__init__':lambda self,*a:None,'done':False,"
            "'preview':lambda self:None,'execute':lambda self: print('MOCK_ROLLBACK_EXECUTED') or True}); "
            "t.hc.RollbackPlan=P; sys.exit(t.hc.main(['rollback','abcdef'],s))"
        )

    def test_real_pty_exact_rollback_confirmation(self):
        code, output = self.tty_run('ROLLBACK OS-30 abcdef')
        self.assertEqual(code, 0, output)
        self.assertIn('MOCK_ROLLBACK_EXECUTED', output)

    def test_real_pty_apply_confirmation_cannot_authorize_rollback(self):
        code, output = self.tty_run('APPLY OS-30')
        self.assertEqual(code, 2, output)
        self.assertNotIn('MOCK_ROLLBACK_EXECUTED', output)

    def test_piped_exact_rollback_confirmation_refused(self):
        result = subprocess.run([sys.executable, '-c', self.harness()],
                                input='ROLLBACK OS-30 abcdef\n', capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('MOCK_ROLLBACK_EXECUTED', result.stdout)


if __name__ == '__main__':
    unittest.main()
