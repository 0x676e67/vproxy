#!/usr/bin/env python3
"""Bounded Linux soak of one stopped management_metering.py test fixture.

Reuses its identity, CA, account, credential, plan and binary. No initialize,
password rotation, trust installation, remote host or OS service operations.
The final report is successful only after the requested monotonic duration,
exact payload accounting, restoration and normal cleanup. heartbeat.json is
mutable progress, never a completion receipt; all other evidence is exclusive.
"""
import argparse
import base64
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request

import management_first_connection as connection
import management_metering as meter
import management_runtime as runtime

require = runtime.require
PREFIX = '/api/v1'
PROTOCOLS = ('http', 'https', 'socks5')
BUCKETS = (.001, .002, .005, .01, .02, .05, .1, .25, .5, 1, 2, 5)
BUSY_CODES = {'policy_busy', 'traffic_busy', 'service_busy'}
PUBLIC_GETS = {PREFIX + path for path in (
    '/proxy/policy', '/proxy/service', '/proxy/users', '/proxy/credentials', '/proxy/owner',
    '/proxy/traffic', '/proxy/traffic/buckets', '/proxy/health', '/alerts')}


class SoakApi(connection.Api):
    """Keep rejection evidence; only explicit public busy GETs may recover.

    TLS, cookies and redirects retain the existing client's configuration.
    Mutations, secret POSTs, expected denials and transport/format failures are
    one-shot, even when their error happens to contain a known busy code.
    """
    def __init__(self, runner, port, ca, events):
        super().__init__(runner, port, ca)
        self.init_observation(events)

    def init_observation(self, events):
        self.events = events
        self.observation_started = time.monotonic()
        self.http_stats = {'attempts': 0, 'successes': 0, 'failed_calls': 0,
                           'busy_get_responses': 0, 'recovered_gets': 0, 'exhausted_gets': 0}

    def event(self, value):
        value = {**value, 'observed_at_unix_ms': int(time.time() * 1000),
                 'elapsed_api_seconds': time.monotonic() - self.observation_started}
        encoded = json.dumps(value) + '\n'
        runtime.no_secret_output([encoded.encode('utf-8')], self.runner.secrets)
        self.events.write(encoded)
        self.events.flush()
        require(self.events.tell() <= 32 * 1024 * 1024, 'http_evidence_limit')

    def request(self, method, path, body=None, expected=200):
        try:
            return self._request(method, path, body, expected)
        except BaseException:
            self.http_stats['failed_calls'] += 1
            raise

    def _request(self, method, path, body, expected):
        require(path.startswith(PREFIX + '/'), 'local_api_path_required')
        resource = path.partition('?')[0]
        public = resource in PUBLIC_GETS or re.fullmatch(
            PREFIX + r'/proxy/service/operations/[0-9]+/[A-Za-z0-9_-]{22}', resource) is not None
        recoverable = method == 'GET' and body is None and expected == 200 and public
        attempts = 3 if recoverable else 1
        data = None if body is None else json.dumps(body).encode('utf-8')
        headers = {'Origin': self.origin}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        if self.csrf is not None and method != 'GET':
            headers['X-CSRF-Token'] = self.csrf
        for attempt in range(attempts):
            self.requests += 1
            self.http_stats['attempts'] += 1
            request = urllib.request.Request(self.origin + path, data=data, headers=headers, method=method)
            try:
                response = self.client.open(request, timeout=self.runner.left())
            except urllib.error.HTTPError as error:
                response = error
            except OSError as error:
                self.event({'method': method, 'path': path, 'status': None, 'attempt': attempt + 1,
                            'error_code': 'transport_error', 'kind': type(error).__name__, 'retry': False})
                raise runtime.Failure('https_transport_failed') from None
            with response:
                status = response.status
                no_store = response.headers.get('Cache-Control') == 'no-store'
                try:
                    raw = response.read(65537)
                except OSError:
                    self.event({'method': method, 'path': path, 'status': status, 'attempt': attempt + 1,
                                'error_code': 'body_read_failed', 'retry': False})
                    raise runtime.Failure('https_body_read_failed') from None
            value = None
            if len(raw) <= 65536:
                try:
                    value = json.loads(raw)
                except (ValueError, UnicodeError):
                    pass
            valid = isinstance(value, dict)
            error = value.get('error') if valid else None
            code = error.get('code') if isinstance(error, dict) else None
            code = code if isinstance(code, str) and re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code) else None
            valid = valid and no_store and not (status == expected == 200 and error is not None)
            if status == expected and valid:
                self.http_stats['successes'] += 1
                self.http_stats['recovered_gets'] += int(attempt > 0)
                return value
            busy = recoverable and valid and status == 503 and code in BUSY_CODES
            self.http_stats['busy_get_responses'] += int(busy)
            retry = busy and attempt + 1 < attempts
            self.event({'method': method, 'path': path, 'status': status, 'error_code': code,
                        'attempt': attempt + 1, 'no_store': no_store, 'valid_response': valid, 'retry': retry})
            if retry:
                delay = (.25, .5)[attempt]
                require(self.runner.left(delay) >= delay, 'busy_read_retry_deadline')
                time.sleep(delay)
                continue
            self.http_stats['exhausted_gets'] += int(busy)
            if not valid:
                raise runtime.Failure('https_response_invalid')
            raise runtime.Failure('https_status_%s_%s_%d_%s' % (method, path, status, code or 'unclassified'))


def private_stream(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, 'w', encoding='utf-8')


def heartbeat(output, value):
    temporary = output / '.heartbeat.tmp'
    with private_stream(temporary) as stream:
        json.dump(value, stream, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(output / 'heartbeat.json')


def resources(process):
    require(process.poll() is None, 'server_exited_during_soak')
    status = Path('/proc/%d/status' % process.pid).read_text()
    result = {}
    for line in status.splitlines():
        key, _, value = line.partition(':')
        if key in ('VmRSS', 'VmSize', 'Threads'):
            result[key] = int(value.split()[0])
    result['file_descriptors'] = len(list(Path('/proc/%d/fd' % process.pid).iterdir()))
    return result


def values(state):
    require(state['clean'] == 1 and not state['loss_possible'] and not state['time_uncertain'],
            'unclean_or_uncertain_fixture')
    result = {}
    for scope, subject, protocol, up, down, saturated in state['totals']:
        require(not saturated, 'durable_saturated')
        result[(scope, subject, protocol)] = (up, down)
    return result


def expected_values(baseline, scopes, counts, size):
    expected = baseline.copy()
    for scope, subject in scopes:
        for protocol, count in ((0, counts['http'] + counts['https']), (1, counts['socks5'])):
            key = (scope, subject, protocol)
            up, down = baseline.get(key, (0, 0))
            expected[key] = (up + count * size, down + count * len(meter.RESPONSE))
    return expected


def final_totals(api, scopes, expected, epoch, journal):
    for name, subject, code, actual_id in scopes:
        snapshot = api.request('GET', PREFIX + '/proxy/traffic?scope=' + name + ('&id=' + subject if subject else ''))
        journal.write(json.dumps({'kind': 'final_traffic', 'value': snapshot}) + '\n')
        require(snapshot['scope'] == {'kind': name, 'id': subject} and snapshot['meter_epoch'] == epoch,
                'scope_or_epoch_changed')
        require(not snapshot['loss_possible'] and not snapshot['time_uncertain'] and not snapshot['checkpoint_error'],
                'traffic_continuity_or_checkpoint')
        require({item['protocol'] for item in snapshot['items']} == {'http', 'socks5', 'masque'}, 'traffic_protocols')
        for item in snapshot['items']:
            protocol = {'http': 0, 'socks5': 1, 'masque': 2}[item['protocol']]
            pair = expected.get((code, actual_id, protocol), (0, 0))
            require(not item['durable_saturated'] and not item['live_saturated'], 'traffic_saturated')
            for direction, count in zip(('upload', 'download'), pair):
                live = item['live_' + direction + '_bytes']
                require(int(item['durable_' + direction + '_bytes'] if live is None else live) == count,
                        'final_exact_accepted_bytes')


def journey(runner, output, servers, server_type, *, fixture, generation, seconds, interval):
    metadata = json.loads((fixture / 'fixture.json').read_text())
    admin_port, node_port, *ports = metadata['ports']
    require(len(ports) == 3 and len(set(metadata['ports'])) == 5
            and all(type(port) is int and 0 < port < 65536 for port in metadata['ports']), 'fixture_ports')
    launch = fixture / 'launch'
    runner.json('retained_plan_check', 'setup', 'check', '--input', launch)
    initial = meter.offline(fixture / 'node')
    baseline = values(initial)
    epoch = initial['meter_epoch']
    runtime.private_json(output / 'initial-meter.json', initial)
    runtime.private_json(output / 'driver-inputs.json', {name: runtime.sha256(path) for name, path in (
        ('soak', __file__), ('metering', meter.__file__), ('runtime', runtime.__file__), ('connection', connection.__file__))})
    sources = output / 'driver-sources'
    sources.mkdir(mode=0o700)
    for path in (__file__, meter.__file__, runtime.__file__, connection.__file__):
        with (sources / Path(path).name).open('xb') as copy:
            copy.write(Path(path).read_bytes())
    target = worker = target_thread = current = api = None
    stopped = threading.Event()
    lock = threading.Lock()
    counts = {protocol: 0 for protocol in PROTOCOLS}
    latency = {protocol: {'count': 0, 'sum_seconds': 0., 'max_seconds': 0., 'buckets': [0] * (len(BUCKETS) + 1)}
               for protocol in PROTOCOLS}
    failures = []
    journal = private_stream(output / 'observations.jsonl')
    events = private_stream(output / 'http-events.jsonl')
    writes = 0
    try:
        with contextlib.ExitStack() as guards:
            for port in metadata['ports']:
                guard = guards.enter_context(socket.socket())
                guard.bind(('127.0.0.1', port))
        target = meter.Target()
        target_thread = threading.Thread(target=target.serve_forever)
        target_thread.start()
        current = server_type(runner, launch, generation, admin_port)
        servers.append(current)
        current.start()
        current.ready(str(launch / 'admin-ca.pem'))
        api = SoakApi(runner, admin_port, launch / 'admin-ca.pem', events)
        administrator = json.loads((fixture / 'fixture-administrator.json').read_text())
        runner.secrets.append(administrator['password'].encode('ascii'))
        api.login(administrator['password'])
        policy = api.request('GET', PREFIX + '/proxy/policy')
        original = api.request('GET', PREFIX + '/proxy/service')
        require(not policy['proxy_running'] and original['saved']['enabled'] is False, 'fixture_not_stopped')
        configuration = original['saved']['configuration']
        require(configuration['listeners'] == [{'protocol': p, 'bind': '127.0.0.1:%d' % port,
                'public_address': '127.0.0.1:%d' % port} for p, port in zip(PROTOCOLS, ports)], 'fixture_loopback_listeners')
        users = api.request('GET', PREFIX + '/proxy/users?limit=25')['items']
        credentials = api.request('GET', PREFIX + '/proxy/credentials?limit=25')['items']
        require(len(users) == len(credentials) == 1 and users[0]['id'] == metadata['user_id']
                and credentials[0]['id'] == metadata['credential_id'], 'fixture_identity_or_counts')
        user, credential = users[0], credentials[0]
        require(user['active'] and not user['deleted'] and credential['active'] and not credential['revoked']
                and len(user['name'].encode('utf-8')) <= 110, 'fixture_user_state')
        owner = api.request('GET', PREFIX + '/proxy/owner')
        secret = api.request('POST', PREFIX + '/proxy/credentials/' + credential['id'] + '/secret', {
            'expected_node_id': metadata['node_id'], 'controller_epoch': owner['epoch'],
            'verifier_revision': credential['verifier_revision']})['secret']
        runner.secrets.extend([secret.encode('ascii'), base64.b64encode((credential['login'] + ':' + secret).encode('ascii'))])
        runtime.private_json(output / 'original-public-state.json', {'service': original, 'user': user, 'credential': credential})
        scopes = [('node', None, 2, metadata['node_id']), ('user', user['id'], 3, user['id']),
                  ('credential', credential['id'], 0, credential['id'])]
        sql_scopes = [(code, actual_id) for _, _, code, actual_id in scopes]

        def service(enabled):
            saved = api.request('GET', PREFIX + '/proxy/service')['saved']
            request_id = secrets.token_urlsafe(16)
            body = {'expected_node_id': metadata['node_id'], 'expected_revision': saved['revision'],
                'controller_epoch': owner['epoch'], 'request_id': request_id, 'enabled': enabled, 'configuration': configuration}
            runtime.private_json(output / ('service-%s-intent.json' % enabled), body)
            operation = api.request('PUT', PREFIX + '/proxy/service', body, expected=202)['operation']
            expected = {'node_id': metadata['node_id'], 'revision': str(int(saved['revision']) + 1),
                        'controller_epoch': owner['epoch'], 'request_id': request_id, 'enabled': enabled}
            until = time.monotonic() + 10
            while True:
                require(all(operation.get(k) == v for k, v in expected.items()), 'service_receipt_binding')
                if operation['state'] != 'pending': break
                require(time.monotonic() < until, 'service_receipt_deadline')
                time.sleep(.03)
                operation = api.request('GET', PREFIX + '/proxy/service/operations/' + expected['revision'] + '/' + request_id
                                        + '?controller_epoch=' + owner['epoch'])
            require(operation['state'] == 'applied', 'service_not_applied')
            runtime.private_json(output / ('service-%s-result.json' % enabled), operation)

        def rename(name):
            nonlocal writes
            policy = api.request('GET', PREFIX + '/proxy/policy')
            body = {'expected_revision': policy['saved_revision'], 'name': name,
                    'protocols': user['protocols'], 'concurrent_limit': user['concurrent_limit']}
            runtime.private_json(output / ('user-%06d-intent.json' % writes), body)
            result = api.request('PUT', PREFIX + '/proxy/users/' + user['id'], body)
            require(result['revision'] == str(int(body['expected_revision']) + 1)
                    and result['user']['id'] == user['id'] and result['user']['name'] == name
                    and result['user']['protocols'] == user['protocols']
                    and result['user']['concurrent_limit'] == user['concurrent_limit'], 'user_write_receipt')
            runtime.private_json(output / ('user-%06d-result.json' % writes), result)
            writes += 1

        service(True)
        tls = ssl.create_default_context(cafile=str(launch / 'admin-ca.pem'))
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.set_alpn_protocols(['http/1.1'])

        def traffic():
            try:
                while not stopped.is_set():
                    for protocol, port in zip(PROTOCOLS, ports):
                        if stopped.is_set(): break
                        start = time.monotonic()
                        meter.proxy_request(port, target, credential['login'], secret, protocol, tls)
                        elapsed = time.monotonic() - start
                        with lock:
                            counts[protocol] += 1
                            item = latency[protocol]
                            item['count'] += 1
                            item['sum_seconds'] += elapsed
                            item['max_seconds'] = max(item['max_seconds'], elapsed)
                            item['buckets'][next((i for i, edge in enumerate(BUCKETS) if elapsed <= edge), len(BUCKETS))] += 1
                    stopped.wait(interval)
            except BaseException as error:
                with lock:
                    failures.append(str(error) if isinstance(error, runtime.Failure) else type(error).__name__)
                stopped.set()

        started = time.monotonic()
        worker = threading.Thread(target=traffic, daemon=True)
        worker.start()
        runtime.private_json(output / 'control.json', {'supervisor_pid': os.getpid(), 'server_pid': current.process.pid,
            'fixture': str(fixture), 'generation': generation, 'requested_seconds': seconds,
            'started_unix_ms': int(time.time() * 1000), 'node_id': metadata['node_id']})
        print('SOAK_RUNNING ' + str(output), flush=True)
        next_write = started
        next_snapshot = started
        next_login = started + 6 * 3600
        reads = 0
        last_cursor = initial['cursor']
        while time.monotonic() - started < seconds:
            require(not (output / 'stop.request').exists(), 'soak_stopped_before_duration')
            require(not stopped.is_set() and not failures, 'proxy_worker_failed')
            if time.monotonic() >= next_login:
                api.login(administrator['password'])
                next_login = time.monotonic() + 6 * 3600
            if time.monotonic() >= next_write:
                rename(user['name'] + (' soak A' if writes % 2 == 0 else ' soak B'))
                next_write = time.monotonic() + 60
            for path in ('/proxy/policy', '/proxy/service', '/proxy/traffic?scope=node', '/alerts', '/proxy/health'):
                response = api.request('GET', PREFIX + path)
                reads += 1
                if path.startswith('/proxy/traffic'):
                    require(response['meter_epoch'] == epoch and int(response['checkpoint_cursor']) >= last_cursor
                            and not response['loss_possible'] and not response['time_uncertain'] and not response['checkpoint_error'],
                            'soak_meter_continuity')
                    last_cursor = int(response['checkpoint_cursor'])
                    journal.write(json.dumps({'kind': 'meter_status', **{key: response[key] for key in (
                        'checkpoint_cursor', 'loss_possible', 'history_gap', 'time_uncertain', 'checkpoint_error',
                        'observed_at_unix_ms', 'last_completed_cycle_age_millis')}}) + '\n')
            if time.monotonic() >= next_snapshot:
                for name, subject, _, _ in scopes:
                    snapshot = api.request('GET', PREFIX + '/proxy/traffic?scope=' + name + ('&id=' + subject if subject else ''))
                    reads += 1
                    journal.write(json.dumps({'kind': 'traffic', 'value': snapshot}) + '\n')
                next_snapshot = time.monotonic() + 60
            with lock:
                progress = {'passed': False, 'state': 'running', 'elapsed_seconds': time.monotonic() - started,
                    'requested_seconds': seconds, 'counts': counts.copy(), 'user_writes': writes,
                    'management_reads': reads, 'failures': failures.copy(), 'server': resources(current.process)}
            journal.write(json.dumps({'kind': 'progress', **progress}) + '\n')
            heartbeat(output, progress)
            journal.flush()
            require(current.log_path.stat().st_size <= 1024 * 1024 and journal.tell() <= 128 * 1024 * 1024, 'soak_evidence_size_limit')
            time.sleep(min(5, max(0, seconds - (time.monotonic() - started))))
        stopped.set()
        worker.join(10)
        require(not worker.is_alive() and not failures, 'proxy_worker_not_reaped')
        elapsed = time.monotonic() - started
        require(elapsed >= seconds, 'requested_duration_incomplete')
        expected = expected_values(baseline, sql_scopes, counts, len(target.request_bytes))
        final_totals(api, scopes, expected, epoch, journal)
        require(target.errors == 0 and target.requests == sum(counts.values())
                and target.upload == sum(counts.values()) * len(target.request_bytes)
                and target.download == sum(counts.values()) * len(meter.RESPONSE), 'independent_target_bytes')
        rename(user['name'])
        service(False)
        final = api.request('GET', PREFIX + '/proxy/service')
        final_user = api.request('GET', PREFIX + '/proxy/users?limit=25')['items']
        final_credentials = api.request('GET', PREFIX + '/proxy/credentials?limit=25')['items']
        require(final['saved']['configuration'] == configuration and final['saved']['enabled'] is False
                and final['runtime']['state'] == 'stopped' and len(final_user) == len(final_credentials) == 1
                and final_user[0]['id'] == user['id'] and final_user[0]['name'] == user['name']
                and final_credentials[0] == credential, 'fixture_restoration')
        current.stop()
        persisted = meter.offline(fixture / 'node')
        require(persisted['meter_epoch'] == epoch and values(persisted) == expected, 'durable_exact_accepted_bytes')
        runtime.private_json(output / 'final-meter.json', persisted)
        return {'node_id': metadata['node_id'], 'meter_epoch': epoch, 'requested_seconds': seconds,
            'elapsed_seconds': elapsed, 'counts': counts, 'user_writes': writes, 'management_reads': reads,
            'http_stats': api.http_stats,
            'request_bytes': len(target.request_bytes), 'response_bytes': len(meter.RESPONSE), 'failures': failures,
            'latency_seconds_bucket_upper_bounds': [*BUCKETS, None], 'latency': latency,
            'history_gap': bool(persisted['history_gap']), 'continuity_loss_or_time_uncertain': False,
            'original_public_state_restored': True, 'target_errors': target.errors}
    finally:
        stopped.set()
        if worker is not None and worker.ident is not None: worker.join(10)
        runner.until = max(runner.until, time.monotonic() + 20)
        try:
            if current is not None and current.process is not None and current.process.poll() is None:
                current.stop()
        finally:
            if worker is not None and worker.ident is not None: worker.join(10)
            if target is not None:
                if target_thread is not None and target_thread.ident is not None: target.shutdown()
                target.server_close()
            if target_thread is not None and target_thread.ident is not None: target_thread.join(3)
            with lock:
                runtime.private_json(output / 'workload-stats.json', {'counts': counts, 'failures': failures,
                    'latency_seconds_bucket_upper_bounds': [*BUCKETS, None], 'latency': latency})
            if api is not None:
                runtime.private_json(output / 'http-stats.json', api.http_stats)
            events.close()
            journal.close()
            heartbeat(output, {'passed': False, 'state': 'finished_check_report', 'counts': counts,
                               'user_writes': writes, 'proxy_worker_reaped': worker is None or not worker.is_alive()})
            require(worker is None or not worker.is_alive(), 'proxy_worker_cleanup')
            require(target_thread is None or not target_thread.is_alive(), 'target_worker_cleanup')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--generation', type=int, required=True)
    parser.add_argument('--seconds', type=int, required=True)
    parser.add_argument('--interval', type=float, default=1.)
    args = parser.parse_args()
    require(sys.platform == 'linux' and hasattr(os, 'pidfd_open'), 'linux_pidfd_required')
    require(1 <= args.seconds <= 259200 and .25 <= args.interval <= 5 and 1 <= args.generation <= 1_000_000,
            'bounded_duration_interval_or_generation')
    binary, fixture = args.binary.resolve(strict=True), args.fixture.resolve(strict=True)
    require(runtime.sha256(binary) == args.binary_sha256, 'checked_binary_required')
    original = json.loads((fixture / 'report.json').read_text())
    require(original['passed'] and original['scope'] == 'fresh_metering_existing_test_ca'
            and original['binary_sha256'] == args.binary_sha256, 'checked_metering_fixture_required')
    require(not (fixture / 'launch' / ('runtime-%d.log' % args.generation)).exists(), 'unused_generation_required')
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    descriptor = os.open(fixture / 'soak.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'r+') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        runner = runtime.Runner(binary, output)
        runner.until = time.monotonic() + args.seconds + 180
        runner.environment['RUST_LOG'] = 'warn'
        previous = {sig: signal.signal(sig, runtime.interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            action = lambda r, o, s, t: journey(r, o, s, t, fixture=fixture, generation=args.generation,
                                              seconds=args.seconds, interval=args.interval)
            report = runtime.run_fixture(runner, output, scope='retained_single_node_managed_soak', action=action)
        finally:
            for sig, handler in previous.items(): signal.signal(sig, handler)
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, runtime.Failure):
        print('{"passed":false,"failure":"soak_preflight_failed"}')
        sys.exit(1)
