#!/usr/bin/env python3
"""Linux CLI journey against one new, private, numeric-loopback API node.

Uses the supplied native management binary, not mocks or an existing service.
Setup issues disposable file-only roots. Nothing is installed into system trust;
there is no proxy credential, remote node, OS service or schema migration. Failed
fixtures and one-time headers remain private for inspection; writes never retry.
"""

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request


class Failure(Exception):
    """Only fixed labels enter the public report, never arbitrary child output."""


def require(value, label):
    if not value:
        raise Failure(label)


def sha256(file):
    with Path(file).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def private_json(file, value):
    """Claim one new leaf; never replace a partial output or follow a symlink."""
    descriptor = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as output:
        json.dump(value, output, ensure_ascii=True, allow_nan=False)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def decode(raw):
    require(len(raw) <= 65536, 'cli_output_limit')
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        raise Failure('cli_json_invalid') from None


def metadata(raw, generation, *, revoked=False):
    match = re.fullmatch(rb'id=([A-Za-z0-9_-]{22}) name="[^"\r\n]*" generation=([0-9]+) scope=users:(read|write) created_at_unix_ms=[0-9]+ expires_at_unix_ms=[0-9]+ revoked=(true|false)\s*', raw)
    require(match and int(match[2]) == generation and (match[4] == b'true') == revoked, 'automation_metadata_invalid')
    return match[1].decode('ascii')


def header_secret(file):
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.geteuid() and info.st_mode & 0o777 == 0o600, 'header_not_private')
        raw = source.read(513)
    require(re.fullmatch(rb'Authorization: Bearer [A-Za-z0-9._~+/=-]{1,128}\n', raw) is not None, 'header_format')
    return raw.removeprefix(b'Authorization: Bearer ').rstrip(b'\n')


def no_secret_output(blocks, values):
    require(all(value not in block for block in blocks for value in values), 'secret_in_output')


def interrupted(*_):
    # Allow the existing finally blocks to reap only this run's children.
    raise Failure('journey_interrupted')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Failure('readiness_redirect')


def saved(record, reservation, node_id):
    """A successful process alone cannot certify the original operation's result."""
    require(record.get('state') == 'saved' and record.get('node_id') == node_id
            and record.get('id') == reservation.get('id')
            and record.get('action') == reservation.get('action')
            and record.get('expected_revision') == reservation.get('expected_revision')
            and record.get('expected_epoch') == reservation.get('expected_epoch')
            and record.get('saved_revision') == str(int(record['expected_revision']) + 1)
            and isinstance(record.get('user_id'), str) and record.get('rejection') is None,
            'operation_not_original_saved')


class Runner:
    """Run each explicit CLI once. A failed POST ends the journey, not a retry."""
    def __init__(self, binary, output):
        self.binary, self.output = binary, output
        self.until = time.monotonic() + 300
        self.children = []
        self.secrets, self.captured = [], []
        self.environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'RUST_LOG': 'info'}

    def left(self, maximum=20):
        remaining = min(maximum, self.until - time.monotonic())
        require(remaining > 0, 'journey_deadline')
        return remaining

    def run(self, label, *arguments, password=None, rejection=None):
        process = subprocess.Popen([str(self.binary), 'manage', *map(str, arguments)],
            stdin=subprocess.PIPE if password is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment, close_fds=True)
        record = {'label': label, 'pid': process.pid, 'forced': False}
        self.children.append(record)
        try:
            try:
                stdout, stderr = process.communicate(input=password, timeout=self.left())
            except subprocess.TimeoutExpired:
                raise Failure('cli_deadline') from None
            require(len(stdout) <= 65536 and len(stderr) <= 65536, 'cli_output_limit')
            self.captured.extend((stdout, stderr))
            if rejection is None:
                require(process.returncode == 0, 'cli_failed_' + label)
            else:
                require(process.returncode != 0 and not stdout
                        and rejection.encode('ascii') in stderr, 'cli_rejection_' + label)
            return stdout
        finally:
            if process.poll() is None:
                process.kill()
                record['forced'] = True
            process.wait(timeout=3)
            record['exit_code'] = process.returncode
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def json(self, label, *arguments, **options):
        return decode(self.run(label, *arguments, **options))

    def read_header(self, file):
        return header_secret(file)


class Server:
    """Keep the original pidfd through exec of the generated start.sh and reap."""
    def __init__(self, runner, launch, generation, port):
        self.runner, self.port = runner, port
        self.log_path = launch / ('runtime-%d.log' % generation)
        self.log = self.log_path.open('xb', buffering=0)
        self.process = self.pidfd = None
        self.record = {'generation': generation, 'forced': False}
        self.launch = launch

    def start(self):
        # The caller records ownership before spawn/pidfd acquisition can fail.
        self.process = subprocess.Popen(['/bin/sh', str(self.launch / 'start.sh')],
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log,
            env=self.runner.environment, close_fds=True, start_new_session=True)
        self.record['pid'] = self.process.pid
        self.pidfd = os.pidfd_open(self.process.pid, 0)
        os.set_inheritable(self.pidfd, False)

    def ready(self, ca):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=ca)
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
        until = time.monotonic() + self.runner.left()
        while True:
            require(self.process.poll() is None, 'server_exited_before_ready')
            try:
                with client.open('https://127.0.0.1:%d/api/v1/auth/session' % self.port, timeout=1):
                    pass
                raise Failure('anonymous_session_accepted')
            except urllib.error.HTTPError as error:
                with error:
                    require(error.code == 403 and decode(error.read(4097)).get('error', {}).get('code') == 'authentication_required', 'anonymous_session_response')
                return
            except urllib.error.URLError as error:
                # Only a not-yet-bound loopback port is a startup observation.
                # Certificate/time/hostname or other transport errors stop here.
                require(isinstance(error.reason, ConnectionRefusedError), 'server_tls_or_transport')
            require(time.monotonic() < until, 'server_readiness_deadline')
            time.sleep(0.03)

    def stop(self):
        require(self.process.poll() is None, 'server_exited_before_stop')
        # Ready is not proof of signal-handler registration. Inspect only this
        # still-owned process; pidfd is the authority used for the actual signal.
        until = time.monotonic() + self.runner.left(3)
        while True:
            status = Path('/proc/%d/status' % self.process.pid).read_text()
            caught = next(int(line.split()[1], 16) for line in status.splitlines() if line.startswith('SigCgt:'))
            if caught & (1 << (signal.SIGTERM - 1)):
                break
            require(time.monotonic() < until and self.process.poll() is None, 'sigterm_handler_unavailable')
            time.sleep(0.01)
        signal.pidfd_send_signal(self.pidfd, signal.SIGTERM, None, 0)
        self.process.wait(timeout=self.runner.left(10))
        require(self.process.returncode == 0, 'server_shutdown_failed')
        self.close()

    def close(self):
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    if self.pidfd is not None:
                        signal.pidfd_send_signal(self.pidfd, signal.SIGKILL, None, 0)
                    else:
                        self.process.kill()
                    self.record['forced'] = True
                self.process.wait(timeout=3)
                self.record['exit_code'] = self.process.returncode
        finally:
            if self.pidfd is not None:
                os.close(self.pidfd)
                self.pidfd = None
            self.log.close()


@dataclass(frozen=True)
class Fixture:
    """Non-secret references to the exact prepared identity and one-time headers."""
    prepared: Path
    launch: Path
    node_id: str
    port: int
    headers: dict
    principals: dict


def journey(runner, output, servers, server_type=Server):
    authority, prepared, signed, launch = (output / name for name in ('authority', 'node', 'signed', 'launch'))
    roots = runner.json('authority', 'setup', 'authority', '--output', authority)
    password = secrets.token_urlsafe(32)
    runner.secrets.append(password.encode('ascii'))
    private_json(authority / 'fixture-administrator.json', {'username': 'runtime-admin', 'password': password})
    # Reserve both numeric loopback ports together. A competing bind after
    # release is a failed fixture, never a reason to restart/replay setup.
    with socket.socket() as admin, socket.socket() as node:
        admin.bind(('127.0.0.1', 0))
        node.bind(('127.0.0.1', 0))
        admin_port, node_port = admin.getsockname()[1], node.getsockname()[1]
        admin_origin, node_origin = ('https://127.0.0.1:%d' % port for port in (admin_port, node_port))
        report = runner.json('prepare', 'setup', 'prepare', '--output', prepared,
            '--authority-public', authority / 'public.json', '--authority-sha256', roots['public_sha256'],
            '--name', 'CLI runtime fixture', '--administrator', 'runtime-admin', '--password-stdin',
            '--admin-origin', admin_origin, '--node-origin', node_origin,
            password=(password + '\n').encode('ascii'))
        runner.json('sign', 'setup', 'sign', '--authority', authority, '--request', prepared / 'public.json', '--output', signed)
        runner.json('plan', 'setup', 'plan', '--prepared', prepared, '--response', signed, '--output', launch,
            '--admin-bind', '127.0.0.1:%d' % admin_port, '--node-bind', '127.0.0.1:%d' % node_port)
    runner.json('check', 'setup', 'check', '--input', launch)
    state, node_id = prepared / 'state', report['node_id']
    headers, principals = {}, {}
    for name, scope in (('read', 'users:read'), ('write', 'users:write'), ('other', 'users:write')):
        headers[name] = prepared / (name + '.header')
        principals[name] = metadata(runner.run('issue_' + name, 'automation', 'create', '--data-dir', state,
            '--name', name, '--scope', scope, '--valid-for', '3600', '--output', headers[name]), 1)
        runner.secrets.append(runner.read_header(headers[name]))

    return exercise(runner, Fixture(prepared, launch, node_id, admin_port, headers, principals), servers, server_type)


def exercise(runner, fixture, servers, server_type=Server):
    """Use already-prepared resources; never perform setup or issue a new key."""
    prepared, launch, node_id, admin_port = fixture.prepared, fixture.launch, fixture.node_id, fixture.port
    state = prepared / 'state'
    headers, principals = dict(fixture.headers), fixture.principals
    connection = ['--origin', 'https://127.0.0.1:%d' % admin_port, '--ca', str(launch / 'admin-ca.pem')]

    def query(label, *args, caller='write'):
        return runner.json(label, 'query', *args, *connection, '--header-file', headers[caller])

    def deny(label, code, *args, caller='write'):
        runner.run(label, *args, *connection, '--header-file', headers[caller], rejection=code)

    server = server_type(runner, launch, 1, admin_port)
    servers.append(server)
    server.start()
    server.ready(str(launch / 'admin-ca.pem'))
    require(query('initial_users', 'users', caller='read')['items'] == [], 'initial_users_not_empty')
    deny('read_scope', 'insufficient_scope', 'query', 'operations', 'context', caller='read')
    receipts = []

    def mutate(change):
        context = query('context_' + change['action'], 'operations', 'context', '--node-id', node_id)
        require(context['node_id'] == node_id and context['local'] is True, 'context_binding')
        file = prepared / (change['action'] + '.json')
        private_json(file, change)
        args = ['--node-id', node_id, '--expected-revision', context['policy_revision'],
                '--expected-epoch', context['expected_epoch'], '--change-file', str(file)]
        if change['action'] == 'create_user':
            wrong = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode('ascii').rstrip('=')
            require(wrong != node_id, 'fixture_id_collision')
            deny('wrong_node', 'operation_conflict', 'operations', 'reserve', *args[2:], '--node-id', wrong)
            require(query('no_wrong_node_reservation', 'operations', 'list', '--node-id', node_id)['items'] == [], 'wrong_node_reserved')
        reservation = runner.json('reserve_' + change['action'], 'operations', 'reserve', *args, *connection, '--header-file', headers['write'])
        require(reservation.get('state') == 'reserved' and reservation.get('node_id') == node_id
                and reservation.get('action') == change['action']
                and reservation.get('expected_revision') == context['policy_revision']
                and reservation.get('expected_epoch') == context['expected_epoch'], 'reservation_binding')
        if change['action'] == 'create_user':
            require(query('reserved_no_user', 'users', caller='read')['items'] == [], 'reservation_mutated_user')
            deny('actor_isolation', 'operation_not_queryable', 'query', 'operations', 'get', '--node-id', node_id, '--id', reservation['id'], caller='other')
        record = runner.json('execute_' + change['action'], 'operations', 'execute', '--id', reservation['id'], *args, *connection, '--header-file', headers['write'])
        saved(record, reservation, node_id)
        exact = query('receipt_' + change['action'], 'operations', 'get', '--node-id', node_id, '--id', record['id'])
        require(exact == record, 'exact_receipt_changed')
        receipts.append(record)
        return record['user_id']

    user = mutate({'action': 'create_user', 'name': 'CLI runtime user', 'protocols': ['http', 'socks5'], 'concurrent_limit': 4})
    old_header = headers['write']
    headers['write'] = prepared / 'write-generation2.header'
    require(metadata(runner.run('rotate', 'automation', 'rotate', '--data-dir', state, '--id', principals['write'],
        '--expected-generation', '1', '--valid-for', '3600', '--output', headers['write']), 2) == principals['write'], 'rotation_identity')
    runner.secrets.append(runner.read_header(headers['write']))
    runner.run('old_key_rejected', 'query', 'users', *connection, '--header-file', old_header, rejection='invalid_token')
    require(query('rotated_history', 'operations', 'get', '--node-id', node_id, '--id', receipts[0]['id']) == receipts[0], 'rotation_lost_history')
    server.stop()
    server = server_type(runner, launch, 2, admin_port)
    servers.append(server)
    server.start()
    server.ready(str(launch / 'admin-ca.pem'))
    require(query('restart_history', 'operations', 'get', '--node-id', node_id, '--id', receipts[0]['id']) == receipts[0], 'restart_lost_history')
    require(query('restart_user', 'users', '--id', user, caller='read')['items'][0]['id'] == user, 'restart_lost_user')
    mutate({'action': 'update_user', 'id': user, 'name': 'CLI updated user', 'protocols': ['socks5'], 'concurrent_limit': 2})
    updated = query('updated_user', 'users', '--id', user, caller='read')['items']
    require(len(updated) == 1 and updated[0]['name'] == 'CLI updated user' and updated[0]['protocols'] == ['socks5']
            and updated[0]['concurrent_limit'] == 2, 'updated_user_mismatch')
    mutate({'action': 'set_user_active', 'id': user, 'active': False})
    require(query('disabled_user', 'users', '--id', user, caller='read')['items'][0]['active'] is False, 'user_not_disabled')
    mutate({'action': 'delete_user', 'id': user})
    require(query('deleted_user', 'users', '--id', user, '--include-deleted', caller='read')['items'][0]['deleted'] is True, 'user_not_deleted')
    history = query('final_history', 'operations', 'list', '--node-id', node_id)['items']
    require([item['id'] for item in history] == [item['id'] for item in reversed(receipts)], 'history_not_exact')
    require(query('other_history', 'operations', 'list', '--node-id', node_id, caller='other')['items'] == [], 'actor_history_leaked')
    metadata(runner.run('revoke_write', 'automation', 'revoke', '--data-dir', state, '--id', principals['write'], '--expected-generation', '2'), 2, revoked=True)
    deny('revoked_receipt', 'invalid_token', 'query', 'operations', 'get', '--node-id', node_id, '--id', receipts[0]['id'])
    server.stop()
    return {'node_id': node_id, 'user_id': user, 'operation_ids': [item['id'] for item in receipts],
            'actions': [item['action'] for item in receipts], 'last_saved_revision': receipts[-1]['saved_revision']}


def run_fixture(runner, output, server_type=Server, *, scope, final_check=lambda: None,
                action=journey, report_name='report.json'):
    """Publish only after owned-child cleanup and platform checks, including failure.

    The platform entry point must claim the private output directory first.
    Shared actions and receipt assertions stay identical on both platforms.
    """
    servers = []
    report = {'passed': False, 'binary_sha256': sha256(runner.binary), 'module_sha256': sha256(__file__),
              'runner_module_sha256': sha256(sys.modules[type(runner).__module__].__file__),
              'scope': scope, 'fixture': str(output)}
    try:
        report['result'] = action(runner, output, servers, server_type)
        report['passed'] = True
    except BaseException as error:
        report['failure'] = str(error) if isinstance(error, Failure) else 'journey_failed'
    finally:
        for server in servers:
            try:
                server.close()
                require(server.log_path.stat().st_size <= 1024 * 1024, 'server_log_limit')
                no_secret_output([server.log_path.read_bytes()], runner.secrets)
            except BaseException:
                report['passed'] = False
                report['cleanup_failure'] = 'owned_server_cleanup'
        report['children'] = runner.children
        report['servers'] = [server.record for server in servers]
        if any(item['forced'] for item in runner.children + report['servers']):
            report['passed'] = False
        try:
            final_check()
        except BaseException:
            report['passed'] = False
            report['cleanup_failure'] = 'platform_cleanup'
        try:
            no_secret_output(runner.captured + [json.dumps(report).encode('utf-8')], runner.secrets)
        except Failure:
            report['passed'] = False
            report['secret_scan_failed'] = True
        private_json(output / report_name, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New fixture directory under an operator-controlled parent; never reused')
    arguments = parser.parse_args()
    require(sys.platform == 'linux' and hasattr(os, 'pidfd_open'), 'linux_pidfd_required')
    binary = arguments.binary.resolve(strict=True)
    require(binary.is_file(), 'native_binary_required')
    output = arguments.output.absolute()
    output.mkdir(mode=0o700)
    previous_term = signal.signal(signal.SIGTERM, interrupted)
    try:
        report = run_fixture(Runner(binary, output), output,
            scope='fresh_linux_cli_setup_and_local_automation_only')
    finally:
        signal.signal(signal.SIGTERM, previous_term)
    print(json.dumps(report, ensure_ascii=True, allow_nan=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, Failure):
        print('{"passed":false,"failure":"fixture_preflight_failed"}')
        sys.exit(1)
