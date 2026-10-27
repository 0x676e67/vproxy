#!/usr/bin/env python3
"""No-node tests for typed busy recovery and one-shot mutation boundaries."""
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import urllib.response

import management_soak as soak


class Client:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def open(self, request, timeout):
        self.calls.append(request)
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        status, body, cache = response
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        headers = {'Cache-Control': cache}
        if status >= 400:
            raise urllib.error.HTTPError(request.full_url, status, 'fixed test rejection', headers, io.BytesIO(raw))
        return urllib.response.addinfourl(io.BytesIO(raw), headers, request.full_url, status)


def response(status=200, code=None, cache='no-store'):
    return status, {'ok': True} if code is None else {'error': {'code': code}}, cache


def api(responses):
    # The unchanged parent owns real TLS/cookies. These tests isolate request
    # decisions using the actual urllib response/HTTPError interfaces.
    value = soak.SoakApi.__new__(soak.SoakApi)
    value.runner = SimpleNamespace(left=lambda maximum=20: maximum, secrets=[])
    value.origin = 'https://127.0.0.1:12345'
    value.csrf = 'fixture-csrf'
    value.requests = 0
    value.client = Client(responses)
    value.init_observation(io.StringIO())
    return value


class ReadRecovery(unittest.TestCase):
    def test_typed_busy_gets_recover_with_two_bounded_delays(self):
        for code in sorted(soak.BUSY_CODES):
            with self.subTest(code=code), patch.object(soak.time, 'sleep') as sleep:
                client = api([response(503, code), response(503, code), response()])
                self.assertEqual(client.request('GET', '/api/v1/proxy/traffic?scope=node'), {'ok': True})
                self.assertEqual([call.args for call in sleep.call_args_list], [(.25,), (.5,)])
                self.assertEqual(client.requests, 3)
                self.assertEqual(client.http_stats['busy_get_responses'], 2)
                self.assertEqual(client.http_stats['recovered_gets'], 1)
                self.assertEqual(client.http_stats['failed_calls'], 0)
                events = [json.loads(line) for line in client.events.getvalue().splitlines()]
                self.assertEqual([(e['status'], e['error_code'], e['attempt']) for e in events],
                                 [(503, code, 1), (503, code, 2)])
                self.assertTrue(all(e['retry'] and e['observed_at_unix_ms'] > 0 for e in events))

    def test_sustained_busy_stops_at_three_attempts(self):
        client = api([response(503, 'traffic_busy')] * 4)
        with patch.object(soak.time, 'sleep') as sleep, self.assertRaises(soak.runtime.Failure):
            client.request('GET', '/api/v1/proxy/traffic?scope=node')
        self.assertEqual((client.requests, sleep.call_count), (3, 2))
        self.assertEqual(client.http_stats['exhausted_gets'], 1)
        self.assertEqual(client.http_stats['failed_calls'], 1)
        self.assertFalse(json.loads(client.events.getvalue().splitlines()[-1])['retry'])

    def test_unknown_errors_and_unavailable_are_not_busy(self):
        for status, code in [(503, 'traffic_unavailable'), (503, 'unknown_busy'),
                             (429, 'policy_busy'), (409, 'policy_revision_conflict')]:
            with self.subTest(status=status, code=code), patch.object(soak.time, 'sleep') as sleep:
                client = api([response(status, code), response()])
                with self.assertRaises(soak.runtime.Failure):
                    client.request('GET', '/api/v1/proxy/traffic?scope=node')
                self.assertEqual(client.requests, 1)
                sleep.assert_not_called()
                event = json.loads(client.events.getvalue())
                self.assertEqual((event['status'], event['error_code']), (status, code))
                self.assertFalse(event['retry'])

    def test_writes_and_secret_reads_never_retry(self):
        for method, path, body in [
            ('PUT', '/api/v1/proxy/users/fixture', {'name': 'fixture'}),
            ('PUT', '/api/v1/proxy/service', {'enabled': True}),
            ('POST', '/api/v1/proxy/credentials/fixture/secret', {'verifier_revision': '1'}),
            ('GET', '/api/v1/proxy/credentials/fixture/secret', None),
            ('POST', '/api/v1/auth/login', {'password': 'only-in-request'}),
            ('GET', '/api/v1/proxy/traffic', {'unexpected_body': True}),
        ]:
            with self.subTest(method=method, path=path), patch.object(soak.time, 'sleep') as sleep:
                client = api([response(503, 'policy_busy'), response()])
                with self.assertRaises(soak.runtime.Failure):
                    client.request(method, path, body)
                self.assertEqual(client.requests, 1)
                sleep.assert_not_called()
                request = client.client.calls[0]
                self.assertEqual(request.get_method(), method)
                if method != 'GET':
                    self.assertEqual(request.get_header('X-csrf-token'), 'fixture-csrf')
                self.assertNotIn('only-in-request', client.events.getvalue())

    def test_expected_denial_keeps_one_shot_semantics(self):
        client = api([response(403, 'authentication_required')])
        self.assertEqual(client.request('GET', '/api/v1/auth/session', expected=403)['error']['code'],
                         'authentication_required')
        self.assertEqual(client.requests, 1)
        self.assertEqual(client.events.getvalue(), '')

    def test_malformed_or_cacheable_responses_cannot_recover(self):
        for value in [(503, b'not JSON', 'no-store'), response(503, 'traffic_busy', 'public'),
                      (200, b'[]', 'no-store'), response(200, 'traffic_busy'),
                      (503, b'x' * 65537, 'no-store')]:
            with self.subTest(status=value[0]), patch.object(soak.time, 'sleep') as sleep:
                client = api([value, response()])
                with self.assertRaises(soak.runtime.Failure):
                    client.request('GET', '/api/v1/proxy/traffic')
                self.assertEqual(client.requests, 1)
                sleep.assert_not_called()
                self.assertEqual(json.loads(client.events.getvalue())['status'], value[0])

    def test_transport_and_retry_deadline_stop_without_extra_request(self):
        client = api([urllib.error.URLError('test transport'), response()])
        with patch.object(soak.time, 'sleep') as sleep, self.assertRaises(soak.runtime.Failure):
            client.request('GET', '/api/v1/proxy/traffic')
        self.assertEqual(client.requests, 1)
        sleep.assert_not_called()
        self.assertIsNone(json.loads(client.events.getvalue())['status'])
        client = api([response(503, 'traffic_busy'), response()])
        client.runner.left = lambda maximum=20: .1
        with patch.object(soak.time, 'sleep') as sleep, self.assertRaises(soak.runtime.Failure):
            client.request('GET', '/api/v1/proxy/traffic')
        self.assertEqual(client.requests, 1)
        self.assertEqual(client.http_stats['failed_calls'], 1)
        sleep.assert_not_called()

    def test_secret_error_code_is_not_written_to_evidence(self):
        client = api([response(503, 'private_fixture_secret')])
        client.runner.secrets = [b'private_fixture_secret']
        with self.assertRaises(soak.runtime.Failure):
            client.request('GET', '/api/v1/proxy/traffic')
        self.assertEqual(client.events.getvalue(), '')
        self.assertEqual(client.http_stats['failed_calls'], 1)

    def test_canceling_backoff_never_sends_the_next_attempt(self):
        client = api([response(503, 'traffic_busy'), response()])
        with patch.object(soak.time, 'sleep', side_effect=soak.runtime.Failure('interrupted')):
            with self.assertRaises(soak.runtime.Failure):
                client.request('GET', '/api/v1/proxy/traffic')
        self.assertEqual(client.requests, 1)
        self.assertEqual(client.http_stats['failed_calls'], 1)

    def test_only_known_public_reads_are_eligible(self):
        path = '/api/v1/proxy/service/operations/123/' + 'A' * 22 + '?controller_epoch=1'
        client = api([response(503, 'service_busy'), response()])
        with patch.object(soak.time, 'sleep'):
            self.assertEqual(client.request('GET', path), {'ok': True})
        self.assertEqual(client.requests, 2)
        for path, expected in [('/api/v1/proxy/unknown', 200), ('/api/v1/auth/session', 200),
                               ('/api/v1/proxy/traffic', 403)]:
            with self.subTest(path=path, expected=expected), patch.object(soak.time, 'sleep') as sleep:
                client = api([response(503, 'traffic_busy'), response()])
                with self.assertRaises(soak.runtime.Failure):
                    client.request('GET', path, expected=expected)
                self.assertEqual(client.requests, 1)
                sleep.assert_not_called()


if __name__ == '__main__':
    unittest.main()
