#!/usr/bin/env python3
"""Check fresh managed metering and normal restart using an existing test CA.

Linux only. Creates one private loopback fixture, never resets or resumes an
existing directory. Uses the supplied binary without rebuilding, and leaves
failed receipts and data intact. No system trust or OS service changes.
"""
import argparse
import base64
import contextlib
import json
import secrets
import signal
import socket
import socketserver
import sqlite3
import ssl
import sys
import threading
import time
from pathlib import Path

import management_first_connection as connection
import management_runtime as runtime

require = runtime.require
PREFIX = '/api/v1'
PAYLOAD = bytes(range(256)) * 16
RESPONSE = (b'HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n'
            b'Connection: close\r\n\r\n') + PAYLOAD


def exact(stream, size):
    result = bytearray()
    while len(result) < size:
        block = stream.recv(size - len(result))
        require(block, 'unexpected_proxy_eof')
        result.extend(block)
    return bytes(result)


def headers(stream):
    result = bytearray()
    while not result.endswith(b'\r\n\r\n'):
        require(len(result) < 8192, 'header_limit')
        result.extend(exact(stream, 1))
    return bytes(result)


class Target(socketserver.ThreadingTCPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = self.upload = self.download = self.errors = 0
        super().__init__(('127.0.0.1', 0), Handler)
        self.request_bytes = ('GET /meter HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n'
                              'Connection: close\r\n\r\n' % self.server_address[1]).encode('ascii')

    def handle_error(self, *_):
        # A traceback must never reproduce an untrusted header or a secret.
        with self.lock:
            self.errors += 1


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        raw = headers(self.request)
        require(raw == self.server.request_bytes, 'target_request_or_credential_leak')
        self.request.sendall(RESPONSE)
        with self.server.lock:
            self.server.requests += 1
            self.server.upload += len(raw)
            self.server.download += len(RESPONSE)


def proxy_request(port, target, login, secret, protocol, tls):
    with contextlib.ExitStack() as stack:
        stream = stack.enter_context(socket.create_connection(('127.0.0.1', port), timeout=5))
        if protocol == 'https':
            stream = stack.enter_context(tls.wrap_socket(stream, server_hostname='127.0.0.1'))
        if protocol == 'socks5':
            stream.sendall(b'\x05\x01\x02')
            require(exact(stream, 2) == b'\x05\x02', 'socks_auth_method')
            user, password = login.encode('ascii'), secret.encode('ascii')
            require(0 < len(user) < 256 and 0 < len(password) < 256, 'socks_auth_length')
            stream.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
            require(exact(stream, 2) == b'\x01\x00', 'socks_auth_status')
            stream.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'
                           + target.server_address[1].to_bytes(2, 'big'))
            require(exact(stream, 4) == b'\x05\x00\x00\x01', 'socks_connect_status')
            exact(stream, 6)
        else:
            token = base64.b64encode((login + ':' + secret).encode('ascii'))
            stream.sendall(('CONNECT 127.0.0.1:%d HTTP/1.1\r\n' % target.server_address[1]).encode('ascii')
                           + b'Proxy-Authorization: Basic ' + token + b'\r\n\r\n')
            require(headers(stream).split(b'\r\n', 1)[0].split(b' ', 2)[:2] == [b'HTTP/1.1', b'200'],
                    'http_connect_status')
        stream.sendall(target.request_bytes)
        require(exact(stream, len(RESPONSE)) == RESPONSE, 'target_response_bytes')
        require(stream.recv(1) == b'', 'target_response_trailing_bytes')


def offline(directory):
    database = directory / 'state/management.sqlite3'
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=2) as db:
        row = db.execute('SELECT meter_epoch,cursor,clean,loss_possible,history_gap,time_uncertain '
                         'FROM traffic_state WHERE singleton=1').fetchone()
        totals = db.execute('SELECT scope,subject_id,protocol,upload,download,saturated '
                            'FROM traffic_series ORDER BY scope,subject_id,protocol').fetchall()
        windows = db.execute('SELECT scope,subject_id,resolution,protocol,upload,download,saturated '
                             'FROM traffic_windows ORDER BY scope,subject_id,resolution,protocol').fetchall()
    return {'meter_epoch': row[0], 'cursor': row[1], 'clean': row[2], 'loss_possible': row[3],
            'history_gap': row[4], 'time_uncertain': row[5],
            'totals': [[*r[:3], int.from_bytes(r[3], 'big'), int.from_bytes(r[4], 'big'), r[5]] for r in totals],
            'windows': [[*r[:4], int.from_bytes(r[4], 'big'), int.from_bytes(r[5], 'big'), r[6]] for r in windows]}


def clean_state(state):
    require(state['clean'] == 1 and all(state[key] == 0 for key in
            ('loss_possible', 'history_gap', 'time_uncertain')), 'offline_continuity_flags')


def verify_totals(api, scopes, epoch, counts, request_size, journal):
    snapshots = []
    for scope, subject in scopes:
        query = '?scope=' + scope + ('&id=' + subject if subject else '')
        snapshot = api.request('GET', PREFIX + '/proxy/traffic' + query)
        journal.write(json.dumps({'kind': 'traffic', 'value': snapshot}) + '\n')
        journal.flush()
        require(snapshot['meter_epoch'] == epoch and not snapshot['checkpoint_error'], 'meter_epoch_or_checkpoint')
        require(not any(snapshot[key] for key in ('loss_possible', 'history_gap', 'time_uncertain')),
                'live_continuity_flags')
        for item in snapshot['items']:
            number = counts.get(item['protocol'], 0)
            for direction, size in [('upload', request_size), ('download', len(RESPONSE))]:
                live = item['live_' + direction + '_bytes']
                value = item['durable_' + direction + '_bytes'] if live is None else live
                require(int(value) == number * size, 'live_accepted_byte_count')
            require(not item['durable_saturated'] and not item['live_saturated'], 'meter_saturated')
        snapshots.append(snapshot)
    return snapshots


def verify_offline(state, epoch, scopes, counts, request_size):
    clean_state(state)
    require(state['meter_epoch'] == epoch, 'persisted_epoch_changed')
    expected = {}
    for scope, subject in scopes:
        for protocol, count in counts.items():
            if count:
                expected[(scope, subject, protocol)] = (count * request_size, count * len(RESPONSE))
    actual = {}
    for scope, subject, protocol, up, down, saturated in state['totals']:
        require(not saturated, 'durable_saturated')
        actual[(scope, subject, protocol)] = (up, down)
    require(actual == expected, 'durable_accepted_byte_count')
    history = {}
    for scope, subject, resolution, protocol, up, down, saturated in state['windows']:
        require(not saturated, 'history_saturated')
        key = (scope, subject, resolution, protocol)
        old = history.get(key, (0, 0))
        history[key] = (old[0] + up, old[1] + down)
    expected_history = {(s, who, resolution, p): value for (s, who, p), value in expected.items()
                        if s in (2, 3) for resolution in range(3)}
    require(history == expected_history, 'history_accepted_byte_count')


def journey(runner, output, servers, server_type, *, authority, seconds, interval):
    prepared, signed, launch = (output / name for name in ('node', 'signed', 'launch'))
    password = secrets.token_urlsafe(32)
    runner.secrets.append(password.encode('ascii'))
    runtime.private_json(output / 'fixture-administrator.json', {'username': 'runtime-admin', 'password': password})
    ports = []
    with contextlib.ExitStack() as stack:
        for _ in range(5):
            reserved = stack.enter_context(socket.socket())
            reserved.bind(('127.0.0.1', 0))
            ports.append(reserved.getsockname()[1])
        admin_port, node_port, *proxy_ports = ports
        metadata = runner.json('prepare', 'setup', 'prepare', '--output', prepared,
            '--authority-public', authority / 'public.json', '--authority-sha256', runtime.sha256(authority / 'public.json'),
            '--name', 'Clean metering fixture', '--administrator', 'runtime-admin', '--password-stdin',
            '--admin-origin', 'https://127.0.0.1:%d' % admin_port,
            '--node-origin', 'https://127.0.0.1:%d' % node_port, password=(password + '\n').encode('ascii'))
        runner.json('sign', 'setup', 'sign', '--authority', authority, '--request', prepared / 'public.json', '--output', signed)
        runner.json('plan', 'setup', 'plan', '--prepared', prepared, '--response', signed, '--output', launch,
                    '--admin-bind', '127.0.0.1:%d' % admin_port, '--node-bind', '127.0.0.1:%d' % node_port)
    runner.json('check', 'setup', 'check', '--input', launch)
    initial = offline(prepared)
    runtime.private_json(output / 'initial-meter.json', initial)
    clean_state(initial)
    require(not initial['totals'] and not initial['windows'] and initial['cursor'] == 0, 'fresh_meter_required')
    epoch = initial['meter_epoch']
    journal = (output / 'observations.jsonl').open('x', encoding='utf-8')
    (output / 'observations.jsonl').chmod(0o600)
    target = None
    thread = None
    current = None
    try:
        target = Target()
        thread = threading.Thread(target=target.serve_forever)
        thread.start()
        current = server_type(runner, launch, 1, admin_port)
        servers.append(current)
        current.start()
        current.ready(str(launch / 'admin-ca.pem'))
        api = connection.Api(runner, admin_port, launch / 'admin-ca.pem')
        api.login(password)
        policy = api.request('GET', PREFIX + '/proxy/policy')
        user = api.request('POST', PREFIX + '/proxy/users', {'expected_revision': policy['saved_revision'],
                           'name': 'Metered fixture', 'protocols': ['http', 'socks5'], 'concurrent_limit': 8}, expected=201)['user']
        policy = api.request('GET', PREFIX + '/proxy/policy')
        credential = api.request('POST', PREFIX + '/proxy/users/' + user['id'] + '/credentials',
                                 {'expected_revision': policy['saved_revision']}, expected=201)
        secret, login = credential['secret'], credential['credential']['login']
        runner.secrets.extend([secret.encode('ascii'), base64.b64encode((login + ':' + secret).encode('ascii'))])
        scopes = [('node', None), ('user', user['id']), ('credential', credential['credential']['id'])]
        sql_scopes = [(2, metadata['node_id']), (3, user['id']), (0, credential['credential']['id'])]
        owner = api.request('GET', PREFIX + '/proxy/owner')
        configuration = {'workers': 1, 'concurrent': 32, 'connect_timeout': 5,
            'listeners': [{'protocol': p, 'bind': '127.0.0.1:%d' % port, 'public_address': '127.0.0.1:%d' % port}
                          for p, port in zip(('http', 'https', 'socks5'), proxy_ports)]}

        def service(enabled):
            saved = api.request('GET', PREFIX + '/proxy/service')['saved']
            request_id = secrets.token_urlsafe(16)
            body = {'expected_node_id': metadata['node_id'], 'expected_revision': saved['revision'],
                    'controller_epoch': owner['epoch'], 'request_id': request_id,
                    'enabled': enabled, 'configuration': configuration}
            runtime.private_json(output / ('service-%s-intent.json' % enabled), body)
            operation = api.request('PUT', PREFIX + '/proxy/service', body, expected=202)['operation']
            expected = {'node_id': metadata['node_id'], 'revision': str(int(saved['revision']) + 1),
                        'controller_epoch': owner['epoch'], 'request_id': request_id, 'enabled': enabled}
            path = PREFIX + '/proxy/service/operations/' + expected['revision'] + '/' + request_id + '?controller_epoch=' + owner['epoch']
            until = time.monotonic() + 10
            while True:
                require(all(operation.get(k) == v for k, v in expected.items()), 'service_receipt_binding')
                if operation['state'] != 'pending':
                    break
                require(time.monotonic() < until, 'service_operation_deadline')
                time.sleep(.03)
                operation = api.request('GET', path)
            require(operation['state'] == 'applied', 'service_not_applied')
            runtime.private_json(output / ('service-%s-result.json' % enabled), operation)

        counts = {'http': 0, 'socks5': 0}
        service(True)
        verify_totals(api, scopes, epoch, counts, len(target.request_bytes), journal)
        tls = ssl.create_default_context(cafile=str(launch / 'admin-ca.pem'))
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.set_alpn_protocols(['http/1.1'])

        def cycle():
            for protocol, port in zip(('http', 'https', 'socks5'), proxy_ports):
                proxy_request(port, target, login, secret, protocol, tls)
                counts['socks5' if protocol == 'socks5' else 'http'] += 1

        started = time.monotonic()
        next_sample = started
        while time.monotonic() - started < seconds:
            cycle()
            if time.monotonic() >= next_sample:
                verify_totals(api, scopes, epoch, counts, len(target.request_bytes), journal)
                next_sample = time.monotonic() + 5
            time.sleep(interval)
        elapsed = time.monotonic() - started
        verify_totals(api, scopes, epoch, counts, len(target.request_bytes), journal)
        current.stop()
        persisted = offline(prepared)
        verify_offline(persisted, epoch, sql_scopes, {0: counts['http'], 1: counts['socks5']}, len(target.request_bytes))
        runtime.private_json(output / 'before-restart-meter.json', persisted)
        current = server_type(runner, launch, 2, admin_port)
        servers.append(current)
        current.start()
        current.ready(str(launch / 'admin-ca.pem'))
        old_api = api
        require(old_api.request('GET', PREFIX + '/auth/session', expected=403)['error']['code'] == 'authentication_required',
                'old_session_survived_restart')
        api = connection.Api(runner, admin_port, launch / 'admin-ca.pem')
        api.login(password)
        verify_totals(api, scopes, epoch, counts, len(target.request_bytes), journal)
        cycle()
        verify_totals(api, scopes, epoch, counts, len(target.request_bytes), journal)
        service(False)
        current.stop()
        final = offline(prepared)
        verify_offline(final, epoch, sql_scopes, {0: counts['http'], 1: counts['socks5']}, len(target.request_bytes))
        require(final['cursor'] > persisted['cursor'] > initial['cursor'], 'checkpoint_cursor_progress')
        runtime.private_json(output / 'final-meter.json', final)
        diagnosis = runner.json('offline_diagnose', 'diagnose', '--data-dir', prepared / 'state')
        require(diagnosis.get('checks_passed') is True, 'offline_diagnosis_failed')
        runtime.private_json(output / 'fixture.json', {'node_id': metadata['node_id'], 'ports': ports,
            'user_id': user['id'], 'credential_id': credential['credential']['id'], 'authority': str(authority)})
        require(target.errors == 0 and target.requests == sum(counts.values()), 'independent_target_count')
        require(target.upload == sum(counts.values()) * len(target.request_bytes)
                and target.download == sum(counts.values()) * len(RESPONSE), 'independent_target_bytes')
        return {'journey_sha256': runtime.sha256(__file__), 'authority_public_sha256': runtime.sha256(authority / 'public.json'),
                'node_id': metadata['node_id'], 'meter_epoch': epoch, 'counts': counts,
                'request_bytes': len(target.request_bytes), 'response_bytes': len(RESPONSE),
                'elapsed_seconds': elapsed, 'old_session_rejected': True, 'same_identity_restart': True,
                'three_scopes_and_history_exact': True, 'continuity_flags_clear': True, 'target_errors': target.errors}
    finally:
        # Cleanup has its own budget; failed assertions never bypass SIGTERM.
        runner.until = max(runner.until, time.monotonic() + 20)
        try:
            if current is not None and current.process is not None and current.process.poll() is None:
                current.stop()
        finally:
            if target is not None:
                if thread is not None and thread.ident is not None:
                    target.shutdown()
                target.server_close()
            if thread is not None and thread.ident is not None:
                thread.join(3)
            journal.close()
            require(thread is None or not thread.is_alive(), 'target_thread_not_reaped')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--authority', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=65)
    parser.add_argument('--interval', type=float, default=.25)
    args = parser.parse_args()
    require(sys.platform == 'linux' and hasattr(signal, 'pidfd_send_signal'), 'linux_pidfd_required')
    require(1 <= args.seconds <= 900 and .05 <= args.interval <= 5, 'bounded_duration_or_interval')
    binary, authority = args.binary.resolve(strict=True), args.authority.resolve(strict=True)
    require(binary.is_file() and runtime.sha256(binary) == args.binary_sha256, 'checked_binary_required')
    require((authority / 'public.json').is_file(), 'existing_test_authority_required')
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    runner = runtime.Runner(binary, output)
    runner.until = time.monotonic() + args.seconds + 180
    previous = {sig: signal.signal(sig, runtime.interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        action = lambda r, o, s, t: journey(r, o, s, t, authority=authority, seconds=args.seconds, interval=args.interval)
        report = runtime.run_fixture(runner, output, scope='fresh_metering_existing_test_ca', action=action)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, runtime.Failure):
        print('{"passed":false,"failure":"metering_preflight_failed"}')
        sys.exit(1)
