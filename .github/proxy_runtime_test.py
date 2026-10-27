#!/usr/bin/env python3
"""Isolated parser/ownership doubles, not evidence of running a release proxy."""

import io
import json
from pathlib import Path
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import proxy_runtime as runtime


class Stream:
    """Fragmented socket double; no bind, connect, subprocess or real signal."""
    def __init__(self, incoming, events=None, name="stream"):
        self.incoming = incoming
        self.sent = bytearray()
        self.events, self.name = events if events is not None else [], name

    def settimeout(self, value):
        self.timeout = value

    def recv(self, size):
        block, self.incoming = self.incoming[:min(size, 3)], self.incoming[min(size, 3):]
        self.events.append((self.name, "recv", block))
        return block

    def sendall(self, block):
        self.sent.extend(block)
        self.events.append((self.name, "send", block))

    def shutdown(self, how):
        self.events.append((self.name, "shutdown", how))


class RuntimeTests(unittest.TestCase):
    def test_shutdown_distinguishes_complete_drain_from_expected_deadline_error(self):
        self.assertEqual(runtime.shutdown_outcome(0, 0.1, False, b"normal log\n"), "complete")
        self.assertEqual(runtime.shutdown_outcome(1, 5.1, True, b"normal log\r\n" + runtime.DRAIN_TIMEOUT + b"\r\n"), "drain_timeout")
        for status, elapsed, stalled, output in (
            (0, 5.0, True, runtime.DRAIN_TIMEOUT),
            (0, 5.0, True, b""),
            (1, 5.0, True, b"Error: unrelated failure\n"),
            (1, 5.0, True, runtime.DRAIN_TIMEOUT + b"\nError: unrelated failure\n"),
            (1, 5.0, True, runtime.DRAIN_TIMEOUT + b"\nthread panicked after timeout\n"),
            (1, 5.0, True, runtime.DRAIN_TIMEOUT + b"\n" + runtime.DRAIN_TIMEOUT),
            (2, 5.0, True, runtime.DRAIN_TIMEOUT),
            (-15, 5.0, True, runtime.DRAIN_TIMEOUT),
            (1, 5.0, False, runtime.DRAIN_TIMEOUT),
            (0, 0.1, False, runtime.DRAIN_TIMEOUT),
            (0, 21.0, False, b""),
            (1, 21.0, True, runtime.DRAIN_TIMEOUT),
            (0, -0.1, False, b""),
            (0, float("nan"), False, b""),
        ):
            with self.subTest(status=status, elapsed=elapsed, stalled=stalled), self.assertRaisesRegex(runtime.RuntimeFailure, "proxy_shutdown_failed"):
                runtime.shutdown_outcome(status, elapsed, stalled, output)

    def test_shutdown_wait_requires_finished_bounded_log_before_accepting_exit(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(runtime, "Windows", return_value=None):
            proxy = runtime.Proxy(Path(temporary) / "unused", "http", 1, Path(temporary), runtime.Deadline(20), {})
            proxy.path.write_bytes(runtime.DRAIN_TIMEOUT + b"\n")
            proxy.process = mock.Mock(returncode=1)
            proxy.reader = mock.Mock()
            proxy.reader.is_alive.return_value = False
            with mock.patch.object(runtime.time, "monotonic", return_value=15.0):
                proxy.wait(10.0, True)
            self.assertEqual(proxy.record["shutdown_outcome"], "drain_timeout")
            proxy.reader.is_alive.return_value = True
            with mock.patch.object(runtime.time, "monotonic", return_value=15.0), self.assertRaisesRegex(runtime.RuntimeFailure, "proxy_log_failed"):
                proxy.wait(10.0, True)
            proxy.reader.is_alive.return_value = False
            proxy.path.write_bytes(b"x" * (runtime.LOG_LIMIT + 1))
            with mock.patch.object(runtime.time, "monotonic", return_value=15.0), self.assertRaisesRegex(runtime.RuntimeFailure, "proxy_log_limit"):
                proxy.wait(10.0, True)

    def test_http_connect_requires_success_and_no_tunnel_framing(self):
        stream = Stream(b"HTTP/1.1 200 Connection Established\r\nX-Test: yes\r\n\r\n")
        runtime.begin_request(stream, "http", 12345, runtime.Deadline(1))
        runtime.finish_request(stream, "http", 12345, runtime.Deadline(1))
        self.assertEqual(stream.sent, b"CONNECT 127.0.0.1:12345 HTTP/1.1\r\nHost: 127.0.0.1:12345\r\n\r\n")
        for wire, label in ((b"HTTP/1.1 407 Denied\r\n\r\n", "http_connect_status"),
                            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "http_connect_framing"),
                            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "http_connect_framing"),
                            (b"HTTP/1.1 200 OK\r\n bad\r\n\r\n", "http_header_syntax"),
                            (b"HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n", "http_header_name"),
                            (b"HTTP/1.1 200 OK\r\n", "unexpected_eof"), (b"x" * 4097, "http_header_limit")):
            with self.subTest(wire=wire[:35]), self.assertRaisesRegex(runtime.RuntimeFailure, label):
                runtime.finish_request(Stream(wire), "http", 1, runtime.Deadline(20))

    def test_socks_method_reply_address_lengths_and_status_are_exact(self):
        for address in (b"\x01" + b"\0" * 6, b"\x04" + b"\0" * 18, b"\x03\x03abc\0\1"):
            stream = Stream(b"\x05\x00\x05\x00\x00" + address)
            runtime.begin_request(stream, "socks5", 12345, runtime.Deadline(1))
            runtime.finish_request(stream, "socks5", 12345, runtime.Deadline(1))
            self.assertEqual(stream.sent, b"\x05\x01\x00\x05\x01\x00\x01\x7f\0\0\x01\x30\x39")
            self.assertEqual(stream.incoming, b"")
        for wire in (b"\x05\xff", b"\x05\x00\x05\x01\x00\x01" + b"\0" * 6,
                     b"\x05\x00\x05\x00\x01\x01", b"\x05\x00\x05\x00\x00\x03\0",
                     b"\x05\x00\x05\x00\x00\x09", b"\x05\x00\x05\x00\x00\x04\0"):
            with self.subTest(wire=wire), self.assertRaises(runtime.RuntimeFailure):
                runtime.finish_request(Stream(wire), "socks5", 1, runtime.Deadline(1))

    def test_reverse_fin_tail_follows_origin_observed_client_eof(self):
        events = []
        client, origin = Stream(runtime.DOWN, events, "client"), Stream(runtime.UP, events, "origin")
        runtime.fin_tail(client, origin, runtime.Deadline(2))
        self.assertEqual(client.sent, runtime.UP)
        self.assertEqual(origin.sent, runtime.DOWN)
        self.assertLess(events.index(("client", "shutdown", socket.SHUT_WR)), events.index(("origin", "recv", b"")))
        self.assertLess(events.index(("origin", "recv", b"")), events.index(("origin", "send", runtime.DOWN)))
        with self.assertRaises(runtime.RuntimeFailure):
            runtime.fin_tail(Stream(runtime.DOWN + b"extra"), Stream(runtime.UP), runtime.Deadline(2))

    def test_stall_window_double_rejects_early_exit_or_readability_and_keeps_one_second(self):
        client, origin = object(), object()
        deadline = SimpleNamespace(left=lambda maximum: maximum)
        proxy = SimpleNamespace(process=mock.Mock())
        proxy.process.poll.return_value = 0
        with mock.patch.object(runtime.select, "select") as waiting, self.assertRaisesRegex(runtime.RuntimeFailure, "stall_proxy_exited_early"):
            runtime.hold_stalled(proxy, client, origin, deadline)
        waiting.assert_not_called()
        proxy.process.poll.return_value = None
        for readable in ([client], [origin]):
            with mock.patch.object(runtime.time, "monotonic", side_effect=[10.0, 10.0]), mock.patch.object(runtime.select, "select", return_value=(readable, [], [])), self.assertRaisesRegex(runtime.RuntimeFailure, "stall_endpoint_readable"):
                runtime.hold_stalled(proxy, client, origin, deadline)
        proxy.process.poll.side_effect = [None, 0]
        with mock.patch.object(runtime.time, "monotonic", side_effect=[10.0, 10.0]), mock.patch.object(runtime.select, "select", return_value=([], [], [])), self.assertRaisesRegex(runtime.RuntimeFailure, "stall_proxy_exited_early"):
            runtime.hold_stalled(proxy, client, origin, deadline)
        proxy.process.poll.side_effect = None
        proxy.process.poll.return_value = None
        with mock.patch.object(runtime.time, "monotonic", side_effect=[10.0, 10.0, 11.0]), mock.patch.object(runtime.select, "select", return_value=([], [], [])) as waiting:
            runtime.hold_stalled(proxy, client, origin, deadline)
        waiting.assert_called_once_with([client, origin], [], [], 1.0)

    def test_deadline_interruption_and_log_short_writes_fail_closed(self):
        stopped = threading.Event()
        stopped.set()
        with self.assertRaisesRegex(runtime.RuntimeFailure, "runtime_interrupted"):
            runtime.Deadline(1, stopped).left()
        expired = runtime.Deadline(1)
        expired.until = 0
        with self.assertRaisesRegex(runtime.RuntimeFailure, "runtime_deadline"):
            expired.left()
        target = io.BytesIO()
        class Short:
            def write(self, data):
                return target.write(data[:2])
        runtime.write_all(Short(), b"abcdef")
        self.assertEqual(target.getvalue(), b"abcdef")
        with self.assertRaises(runtime.RuntimeFailure):
            runtime.write_all(SimpleNamespace(write=lambda _data: 0), b"x")

    def test_proxy_cleanup_continues_after_thread_join_error(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(runtime, "Windows", return_value=None):
            proxy = runtime.Proxy(Path(temporary) / "unused", "http", 1, Path(temporary), runtime.Deadline(1), {})
            process = mock.Mock()
            process.poll.return_value = None
            process.returncode = 1
            proxy.process = process
            proxy.reader = mock.Mock(ident=1)
            proxy.reader.join.side_effect = RuntimeError("synthetic")
            proxy.reader.is_alive.return_value = False
            proxy.output = io.BytesIO()
            errors = proxy.close()
            self.assertIn("proxy_log_join", errors)
            self.assertTrue(proxy.output.closed)
            process.kill.assert_called_once()
            process.wait.assert_called_once()
            process.stdout.close.assert_called_once()
            self.assertTrue(proxy.record["forced_cleanup"])

    def test_windows_sender_double_rejects_unrelated_console_members(self):
        api = mock.Mock()
        api.identity.return_value = [42, "created", runtime.normalized("C:/fixture/vproxy.exe")]
        api.alive.return_value = True
        api.kernel.GetConsoleProcessList.return_value = 3
        arguments = SimpleNamespace(handle=12, pid=42, created="created", binary=Path("C:/fixture/vproxy.exe"), binary_sha="pin", module_sha="pin")
        stdout = SimpleNamespace(buffer=io.BytesIO())
        with mock.patch.object(runtime, "Windows", return_value=api), mock.patch.object(runtime, "digest", return_value="pin"), mock.patch.object(runtime.sys, "stdout", stdout):
            self.assertEqual(runtime.sender(arguments), 1)
        self.assertFalse(json.loads(stdout.buffer.getvalue())["passed"])
        api.kernel.GenerateConsoleCtrlEvent.assert_not_called()
        api.kernel.FreeConsole.assert_called()
        api.close.assert_called_once_with(12)

    def test_failure_cleanup_still_closes_origin_socket_if_proxy_cleanup_raises(self):
        proxy = mock.Mock()
        proxy.record = {"forced_cleanup": False}
        proxy.start.side_effect = runtime.RuntimeFailure("synthetic_start")
        proxy.close.side_effect = RuntimeError("synthetic_cleanup")
        listener = mock.Mock()
        listener.getsockname.return_value = ("127.0.0.1", 12345)
        listener.fileno.return_value = -1
        with mock.patch.object(runtime, "Proxy", return_value=proxy), mock.patch.object(runtime.socket, "socket", return_value=listener):
            result = runtime.cell(Path("unused"), Path("unused"), "http", 1, True, {}, threading.Event())
        self.assertFalse(result["passed"])
        self.assertEqual(result["failure"], "synthetic_start")
        self.assertIn("proxy_cleanup_failed", result["cleanup_errors"])
        listener.close.assert_called_once()

    def test_run_detects_changed_input_even_with_passing_cell_doubles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            binary = root / "synthetic-binary"
            binary.write_bytes(b"before")
            def changed(*_args):
                binary.write_bytes(b"after")
                return {"passed": True}
            with mock.patch.object(runtime.platform, "system", return_value="Linux"), mock.patch.object(runtime.platform, "machine", return_value="x86_64"), mock.patch.object(runtime.signal, "signal"), mock.patch.object(runtime, "cell", side_effect=changed):
                result = runtime.run(binary, root / "changed", environment={})
            self.assertFalse(result["passed"])
            self.assertEqual(result["failure"], "runtime_binary_changed")

    def test_run_double_has_eight_cells_and_never_turns_failure_into_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            binary = root / "synthetic-binary"
            binary.write_bytes(b"not an executable; cell is mocked")
            with mock.patch.object(runtime.platform, "system", return_value="Linux"), mock.patch.object(runtime.platform, "machine", return_value="x86_64"), mock.patch.object(runtime.signal, "signal"), mock.patch.object(runtime, "cell", return_value={"passed": True}) as cells:
                result = runtime.run(binary, root / "eight", environment={"PATH": "/usr/bin:/bin"})
                self.assertTrue(result["passed"])
                self.assertEqual(cells.call_count, 8)
                self.assertEqual([(call.args[2], call.args[3], call.args[4]) for call in cells.call_args_list], [(protocol, workers, stalled) for stalled in (False, True) for protocol in ("http", "socks5") for workers in (1, 2)])
            with mock.patch.object(runtime.platform, "system", return_value="Linux"), mock.patch.object(runtime.platform, "machine", return_value="x86_64"), mock.patch.object(runtime.signal, "signal"), mock.patch.object(runtime, "cell", return_value={"passed": False}) as cells:
                result = runtime.run(binary, root / "failed", environment={})
                self.assertFalse(result["passed"])
                self.assertEqual(cells.call_count, 1)
                self.assertEqual(json.loads((root / "failed" / "report.json").read_text())["failure"], "proxy_runtime_case_failed")
            marker = root / "eight" / "marker"
            marker.write_bytes(b"retain")
            with self.assertRaises(FileExistsError):
                runtime.run(binary, root / "eight")
            self.assertEqual(marker.read_bytes(), b"retain")


if __name__ == "__main__":
    unittest.main()
