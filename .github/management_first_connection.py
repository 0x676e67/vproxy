#!/usr/bin/env python3
"""Linux first-connection journey against one new private loopback Web node.

Uses real HTTPS, Session/CSRF and authenticated proxy requests. No existing
state, remote service, system trust or OS service is used. Each mutation is
submitted once; failed fixtures remain private and are never replayed.
"""
import argparse
import base64
import http.client
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import management_runtime as runtime

require = runtime.require
PREFIX = '/api/v1'


class Api:
    def __init__(self, runner, port, ca):
        self.runner = runner
        self.origin = 'https://127.0.0.1:%d' % port
        self.context = ssl.create_default_context(cafile=str(ca))
        self.jar = http.cookiejar.CookieJar()
        self.client = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), runtime.NoRedirect(),
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=self.context))
        self.csrf = None
        self.requests = 0

    def request(self, method, path, body=None, expected=200):
        data = None if body is None else json.dumps(body).encode('utf-8')
        headers = {'Origin': self.origin}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        if self.csrf is not None and method != 'GET':
            headers['X-CSRF-Token'] = self.csrf
        request = urllib.request.Request(self.origin + path, data=data, headers=headers, method=method)
        self.requests += 1
        try:
            response = self.client.open(request, timeout=self.runner.left())
        except urllib.error.HTTPError as error:
            response = error
        with response:
            require(response.status == expected, 'https_status_%s_%s_%d' % (method, path, response.status))
            raw = response.read(65537)
            require(len(raw) <= 65536, 'https_response_limit')
            if path.startswith(PREFIX):
                require(response.headers.get('Cache-Control') == 'no-store', 'https_no_store')
                return runtime.decode(raw)
            return raw

    def login(self, password):
        result = self.request('POST', PREFIX + '/auth/login', {'username': 'runtime-admin', 'password': password})
        self.csrf = result['csrf_token']
        self.runner.secrets.append(self.csrf.encode('ascii'))
        self.runner.secrets.extend(cookie.value.encode('ascii') for cookie in self.jar)


class Echo(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    payload = b'vproxy-first-connection-ok\n'

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(self.payload)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(self.payload)

    def log_message(self, *_):
        pass


def proxy_request(runner, port, target_port, login, secret, *, rejected=False):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=runner.left(5))
    token = base64.b64encode((login + ':' + secret).encode('ascii')).decode('ascii')
    runner.secrets.append(token.encode('ascii'))
    try:
        connection.request('GET', 'http://127.0.0.1:%d/journey' % target_port,
                           headers={'Proxy-Authorization': 'Basic ' + token, 'Connection': 'close'})
        response = connection.getresponse()
        raw = response.read(4097)
        require(response.status == (407 if rejected else 200), 'proxy_authentication_or_target')
        if not rejected:
            require(raw == Echo.payload, 'proxy_target_payload')
    finally:
        connection.close()


def journey(runner, output, servers, server_type):
    authority, prepared, signed, launch = (output / name for name in ('authority', 'node', 'signed', 'launch'))
    roots = runner.json('authority', 'setup', 'authority', '--output', authority)
    password = secrets.token_urlsafe(32)
    runner.secrets.append(password.encode('ascii'))
    runtime.private_json(authority / 'fixture-administrator.json', {'username': 'runtime-admin', 'password': password})
    with socket.socket() as admin, socket.socket() as node, socket.socket() as occupied:
        for reserved in (admin, node, occupied):
            reserved.bind(('127.0.0.1', 0))
        admin_port, node_port, proxy_port = (reserved.getsockname()[1] for reserved in (admin, node, occupied))
        report = runner.json('prepare', 'setup', 'prepare', '--output', prepared,
            '--authority-public', authority / 'public.json', '--authority-sha256', roots['public_sha256'],
            '--name', 'First connection fixture', '--administrator', 'runtime-admin', '--password-stdin',
            '--admin-origin', 'https://127.0.0.1:%d' % admin_port,
            '--node-origin', 'https://127.0.0.1:%d' % node_port,
            password=(password + '\n').encode('ascii'))
        runner.json('sign', 'setup', 'sign', '--authority', authority,
                    '--request', prepared / 'public.json', '--output', signed)
        runner.json('plan', 'setup', 'plan', '--prepared', prepared, '--response', signed,
                    '--output', launch, '--admin-bind', '127.0.0.1:%d' % admin_port,
                    '--node-bind', '127.0.0.1:%d' % node_port)
    runner.json('check', 'setup', 'check', '--input', launch)
    node_id = report['node_id']
    ca = launch / 'admin-ca.pem'
    server = server_type(runner, launch, 1, admin_port)
    servers.append(server)
    server.start()
    server.ready(str(ca))
    api = Api(runner, admin_port, ca)
    api.login(password)
    require(b'<html' in api.request('GET', '/').lower(), 'embedded_web_html')
    before = api.request('GET', PREFIX + '/proxy/service')
    require(before['mode'] == 'web' and before['runtime']['state'] == 'stopped', 'initial_service_state')
    policy = api.request('GET', PREFIX + '/proxy/policy')
    require(not policy['proxy_running'], 'initial_policy_stopped')
    user = api.request('POST', PREFIX + '/proxy/users', {
        'expected_revision': policy['saved_revision'], 'name': 'First connection',
        'protocols': ['http'], 'concurrent_limit': 8}, expected=201)
    policy = api.request('GET', PREFIX + '/proxy/policy')
    credential = api.request('POST', PREFIX + '/proxy/users/' + user['user']['id'] + '/credentials',
                             {'expected_revision': policy['saved_revision']}, expected=201)
    secret = credential['secret']
    runner.secrets.append(secret.encode('ascii'))
    login = credential['credential']['login']
    credential_id = credential['credential']['id']
    revision = credential['credential']['verifier_revision']
    owner = api.request('GET', PREFIX + '/proxy/owner')
    epoch = owner['epoch']
    configuration = {'workers': 1, 'concurrent': 32, 'connect_timeout': 5,
        'listeners': [{'protocol': 'http', 'bind': '127.0.0.1:%d' % proxy_port,
                       'public_address': '127.0.0.1:%d' % proxy_port}]}

    def service(enabled, *, failed=False):
        current = api.request('GET', PREFIX + '/proxy/service')
        request_id = secrets.token_urlsafe(16)
        changed = api.request('PUT', PREFIX + '/proxy/service', {
            'expected_node_id': node_id, 'expected_revision': current['saved']['revision'],
            'controller_epoch': epoch, 'request_id': request_id,
            'enabled': enabled, 'configuration': configuration}, expected=202)
        operation = changed['operation']
        expected = {'node_id': node_id, 'revision': str(int(current['saved']['revision']) + 1),
                    'controller_epoch': epoch, 'request_id': request_id, 'enabled': enabled}
        require(all(operation.get(key) == value for key, value in expected.items()), 'service_receipt_binding')
        path = PREFIX + '/proxy/service/operations/' + operation['revision'] + '/' + request_id + '?controller_epoch=' + epoch
        operation = api.request('GET', path)
        until = time.monotonic() + runner.left(10)
        while operation['state'] == 'pending':
            require(time.monotonic() < until, 'service_operation_deadline')
            time.sleep(0.03)
            operation = api.request('GET', path)
        require(all(operation.get(key) == value for key, value in expected.items()), 'service_recovery_binding')
        require(operation['state'] == ('failed' if failed else 'applied'), 'service_operation_not_applied')
        current = api.request('GET', PREFIX + '/proxy/service')
        require(current['saved']['configuration'] == configuration and current['saved']['enabled'] == enabled,
                'saved_service_configuration')
        require(current['runtime']['state'] == ('failed' if failed else 'running' if enabled else 'stopped'), 'live_service_state')
        if failed:
            require(current['runtime']['error'] == 'address_in_use', 'occupied_port_not_reported')
        return current

    with socket.socket() as blocker:
        blocker.bind(('127.0.0.1', proxy_port))
        blocker.listen()
        service(True, failed=True)
    service(True)
    echo = ThreadingHTTPServer(('127.0.0.1', 0), Echo)
    worker = threading.Thread(target=echo.serve_forever, daemon=True)
    worker.start()
    try:
        proxy_request(runner, proxy_port, echo.server_port, login, secret)
        proxy_request(runner, proxy_port, echo.server_port, login, 'wrong-password', rejected=True)
        selected = {'expected_node_id': node_id, 'controller_epoch': epoch, 'verifier_revision': revision}
        revealed = api.request('POST', PREFIX + '/proxy/credentials/' + credential_id + '/secret', selected)
        require(revealed['secret'] == secret, 'saved_password_changed')
        policy = api.request('GET', PREFIX + '/proxy/policy')
        require(policy['proxy_running'] and policy['applied_revision'] == policy['saved_revision'], 'policy_not_live')
        server.stop()
        restarted = server_type(runner, launch, 2, admin_port)
        servers.append(restarted)
        restarted.start()
        restarted.ready(str(ca))
        api.request('GET', PREFIX + '/auth/session', expected=403)
        initial_requests = api.requests
        api = Api(runner, admin_port, ca)
        api.login(password)
        current = api.request('GET', PREFIX + '/proxy/service')
        require(current['saved']['configuration'] == configuration and current['runtime']['state'] == 'running',
                'restart_did_not_restore_listener')
        require(api.request('GET', PREFIX + '/node')['node_id'] == node_id, 'restart_identity_changed')
        require(api.request('POST', PREFIX + '/proxy/credentials/' + credential_id + '/secret', selected)['secret'] == secret,
                'restart_password_changed')
        proxy_request(runner, proxy_port, echo.server_port, login, secret)
        policy = api.request('GET', PREFIX + '/proxy/policy')
        rotated = api.request('POST', PREFIX + '/proxy/credentials/' + credential_id + '/rotate',
                              {'expected_revision': policy['saved_revision']})
        replacement = rotated['secret']
        runner.secrets.append(replacement.encode('ascii'))
        require(replacement != secret, 'rotation_secret_unchanged')
        selected['verifier_revision'] = rotated['credential']['verifier_revision']
        require(api.request('POST', PREFIX + '/proxy/credentials/' + credential_id + '/secret', selected)['secret'] == replacement,
                'rotated_password_not_recoverable')
        proxy_request(runner, proxy_port, echo.server_port, login, secret, rejected=True)
        proxy_request(runner, proxy_port, echo.server_port, login, replacement)
        service(False)
        with socket.socket() as probe:
            require(probe.connect_ex(('127.0.0.1', proxy_port)) != 0, 'stopped_listener_remains')
        restarted.stop()
    finally:
        echo.shutdown()
        echo.server_close()
        worker.join(timeout=3)
        require(not worker.is_alive(), 'target_thread_not_reaped')
    return {'journey_sha256': runtime.sha256(__file__),
            'node_id': node_id, 'https_requests': initial_requests + api.requests,
            'authenticated_requests': 3, 'rejected_requests': 2,
            'saved_password_recovered': True, 'same_identity_restart': True,
            'saved_listener_restored': True, 'occupied_port_recovered': True,
            'rotation_verified': True, 'normal_stop': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux' and hasattr(os, 'pidfd_open'), 'linux_pidfd_required')
    require(args.binary.resolve(strict=True).is_file(), 'native_binary_required')
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    runner = runtime.Runner(args.binary.resolve(strict=True), output)
    previous = signal.signal(signal.SIGTERM, runtime.interrupted)
    try:
        result = runtime.run_fixture(runner, output, scope='fresh_single_node_first_connection', action=journey)
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, runtime.Failure):
        print('{"passed":false,"failure":"fixture_preflight_failed"}')
        sys.exit(1)
