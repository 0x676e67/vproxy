#!/usr/bin/env python3
"""Harness ownership/receipt doubles, not evidence of a real management server."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import management_runtime as runtime
import management_runtime_windows as windows


class RuntimeTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(runtime.signal, 'pidfd_send_signal'), 'Linux pidfd cleanup')
    def test_failed_server_cleanup_signals_only_its_retained_pidfd(self):
        server = runtime.Server.__new__(runtime.Server)
        server.pidfd, server.process, server.log = 77, mock.Mock(returncode=-9), mock.Mock()
        server.process.poll.return_value = None
        server.record = {'forced': False}
        with mock.patch.object(runtime.signal, 'pidfd_send_signal') as send, mock.patch.object(runtime.os, 'close') as close:
            server.close()
        send.assert_called_once_with(77, runtime.signal.SIGKILL, None, 0)
        close.assert_called_once_with(77)
        server.process.kill.assert_not_called()
        server.process.wait.assert_called_once_with(timeout=3)
        self.assertIsNone(server.pidfd)
        self.assertEqual(server.record, {'forced': True, 'exit_code': -9})

    def test_readiness_never_follows_redirects(self):
        with self.assertRaisesRegex(runtime.Failure, '^readiness_redirect$'):
            runtime.NoRedirect().redirect_request(None, None, None, None, None, 'https://outside.invalid')

    def test_secret_scan_checks_all_output_blocks(self):
        runtime.no_secret_output([b'public metadata', b''], [b'private-token'])
        with self.assertRaisesRegex(runtime.Failure, '^secret_in_output$'):
            runtime.no_secret_output([b'public', b'unexpected private-token'], [b'private-token'])

    def test_private_output_never_overwrites_a_partial_or_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'private.json'
            runtime.private_json(file, {'original': True})
            with self.assertRaises(FileExistsError):
                runtime.private_json(file, {'replacement': True})
            self.assertEqual(json.loads(file.read_text()), {'original': True})
            if os.name == 'posix':
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                alias = Path(directory) / 'alias.json'
                alias.symlink_to(file)
                with self.assertRaises(FileExistsError):
                    runtime.private_json(alias, {})

    def test_saved_requires_original_node_id_action_cas_and_commit_result(self):
        reservation = {'id': 'original', 'action': 'create_user', 'expected_revision': '9', 'expected_epoch': '3'}
        record = dict(reservation, node_id='node', user_id='user', state='saved', saved_revision='10', rejection=None)
        runtime.saved(record, reservation, 'node')
        for field, value in (('id', 'replacement'), ('action', 'delete_user'), ('expected_revision', '8'),
                             ('expected_epoch', '4'), ('node_id', 'other'), ('state', 'reserved'),
                             ('saved_revision', '11'), ('user_id', None), ('rejection', 'policy_conflict')):
            with self.subTest(field=field), self.assertRaises(runtime.Failure):
                runtime.saved(dict(record, **{field: value}), reservation, 'node')

    def test_cli_timeout_reaps_original_child_without_replaying_command(self):
        process = mock.Mock(pid=123, returncode=-9)
        process.communicate.side_effect = subprocess.TimeoutExpired('private', 1)
        process.poll.return_value = None
        runner = runtime.Runner(Path('/fixture/vproxy'), Path('/fixture'))
        with mock.patch.object(runtime.subprocess, 'Popen', return_value=process) as start:
            with self.assertRaisesRegex(runtime.Failure, '^cli_deadline$'):
                runner.run('execute', 'operations', 'execute')
        self.assertEqual(start.call_count, 1)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=3)
        self.assertTrue(runner.children[0]['forced'])
        self.assertEqual(runner.children[0]['exit_code'], -9)

    def test_rejection_requires_nonzero_exit_empty_stdout_and_fixed_code(self):
        runner = runtime.Runner(Path('/fixture/vproxy'), Path('/fixture'))
        for code, stdout, stderr, accepted in (
            (1, b'', b'query rejected (403, insufficient_scope)', True),
            (0, b'', b'insufficient_scope', False),
            (1, b'private-response', b'insufficient_scope', False),
            (1, b'', b'network timeout', False),
        ):
            process = mock.Mock(pid=123, returncode=code)
            process.communicate.return_value = (stdout, stderr)
            process.poll.return_value = code
            with mock.patch.object(runtime.subprocess, 'Popen', return_value=process):
                if accepted:
                    self.assertEqual(runner.run('scope', 'query', rejection='insufficient_scope'), b'')
                else:
                    with self.assertRaises(runtime.Failure):
                        runner.run('scope', 'query', rejection='insufficient_scope')
            process.kill.assert_not_called()

    def test_timeout_and_child_diagnostics_do_not_enter_public_record(self):
        process = mock.Mock(pid=123, returncode=1)
        process.communicate.return_value = (b'password-secret', b'bearer-secret')
        process.poll.return_value = 1
        runner = runtime.Runner(Path('/fixture/vproxy'), Path('/fixture'))
        with mock.patch.object(runtime.subprocess, 'Popen', return_value=process):
            with self.assertRaisesRegex(runtime.Failure, '^cli_failed_prepare$'):
                runner.run('prepare', 'setup', 'prepare', password=b'password-secret\n')
        public = json.dumps(runner.children)
        self.assertNotIn('password-secret', public)
        self.assertNotIn('bearer-secret', public)


class WindowsTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows reparse attributes')
    def test_empty_bootstrap_resume_never_accepts_prior_fixture_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            windows.output_preflight(output, True)
            runtime.private_json(output / 'partial.json', {})
            with self.assertRaisesRegex(runtime.Failure, '^empty_bootstrap_required$'):
                windows.output_preflight(output, True)
            with self.assertRaisesRegex(runtime.Failure, '^new_fixture_required$'):
                windows.output_preflight(output, False)

    def test_tcp_startup_timeout_does_not_turn_tls_failures_into_retries(self):
        server = windows.Server.__new__(windows.Server)
        server.runner, server.process, server.port = mock.Mock(), mock.Mock(), 1234
        server.runner.left.return_value = 2
        server.process.poll.return_value = None
        with mock.patch.object(windows.socket, 'create_connection', side_effect=[TimeoutError(), mock.MagicMock()]) as connect, mock.patch.object(windows.time, 'sleep'), mock.patch.object(runtime.Server, 'ready', side_effect=runtime.Failure('tls_failed')) as tls:
            with self.assertRaisesRegex(runtime.Failure, '^tls_failed$'):
                server.ready('explicit-ca.pem')
        self.assertEqual(connect.call_count, 2)
        tls.assert_called_once_with('explicit-ca.pem')

    def test_console_interrupt_rejects_foreign_members_before_signal(self):
        console = windows.PrivateConsole.__new__(windows.PrivateConsole)
        console.api = mock.Mock()
        for actual, owned in (({os.getpid(), 123}, {os.getpid()}), ({123}, {123})):
            with mock.patch.object(console, 'console_members', return_value=actual), mock.patch.object(console, 'members', return_value=owned):
                with self.assertRaisesRegex(runtime.Failure, '^foreign_console_member$'):
                    console.interrupt()
        console.api.GenerateConsoleCtrlEvent.assert_not_called()

    def test_console_interrupt_is_bounded_by_current_job_membership(self):
        console = windows.PrivateConsole.__new__(windows.PrivateConsole)
        console.api = mock.Mock()
        with mock.patch.object(console, 'console_members', return_value={os.getpid(), 123}), mock.patch.object(console, 'members', return_value={os.getpid(), 123, 456}):
            console.interrupt()
        console.api.GenerateConsoleCtrlEvent.assert_called_once_with(0, 0)

    def test_cleanup_checks_for_orphans_not_only_shell_exit(self):
        console = windows.PrivateConsole.__new__(windows.PrivateConsole)
        with mock.patch.object(console, 'members', return_value={os.getpid(), 123}), mock.patch.object(windows.time, 'monotonic', side_effect=[0, 3]):
            with self.assertRaisesRegex(runtime.Failure, '^owned_descendants_remain$'):
                console.empty()

    def test_job_cleanup_observes_same_job_until_child_retires(self):
        console = windows.PrivateConsole.__new__(windows.PrivateConsole)
        with mock.patch.object(console, 'members', side_effect=[{os.getpid(), 123}, {os.getpid()}]) as members, mock.patch.object(windows.time, 'sleep') as sleep:
            console.empty()
        self.assertEqual(members.call_count, 2)
        sleep.assert_called_once_with(0.01)

    def test_windows_failed_shell_cleanup_uses_original_popen_handle(self):
        server = windows.Server.__new__(windows.Server)
        server.process, server.log = mock.Mock(returncode=1), mock.Mock()
        server.process.poll.return_value = None
        server.record = {'forced': False}
        server.close()
        server.process.kill.assert_called_once_with()
        server.process.wait.assert_called_once_with(timeout=3)
        self.assertEqual(server.record, {'forced': True, 'exit_code': 1})

    def test_stop_rejects_nonzero_shell_exit_as_not_graceful(self):
        server = windows.Server.__new__(windows.Server)
        server.process, server.runner = mock.Mock(returncode=130), mock.Mock()
        server.process.poll.return_value = None
        with self.assertRaisesRegex(runtime.Failure, '^server_shutdown_failed$'):
            server.stop()
        server.runner.console.interrupt.assert_called_once_with()
        server.runner.console.empty.assert_not_called()


if __name__ == '__main__':
    unittest.main()
