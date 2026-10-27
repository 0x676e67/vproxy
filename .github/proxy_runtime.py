#!/usr/bin/env python3
"""Native x64 release gate: anonymous numeric-loopback CONNECT and shutdown.

The caller checks/unpacks the archive first. No management identities,
credentials, TLS, system configuration or performance measurement are involved.
Unit doubles are not release-runtime evidence. Windows console delivery narrowly
follows the previously exercised G6 helper; only the disposable sender attaches.
Protocol references: https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6,
https://www.rfc-editor.org/rfc/rfc1928.html#section-3,
https://www.rfc-editor.org/rfc/rfc1928.html#section-6 and
https://www.rfc-editor.org/rfc/rfc9293.html#section-3.6.1.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time


LOG_LIMIT = 128 * 1024
SHUTDOWN_SECONDS = 20.0
PREFIX_UP, PREFIX_DOWN = b"client-ready", b"origin-ready"
UP = hashlib.shake_256(b"release-client-fin").digest(8192)
DOWN = hashlib.shake_256(b"release-origin-fin-tail").digest(8192)
BOUND = re.compile(rb"(?:Http\(s\)|Socks5) proxy server listening on 127\.0\.0\.1:([0-9]{1,5})(?:\s|$)")
DRAIN_TIMEOUT = b'Error: IO(Custom { kind: TimedOut, error: "proxy shutdown drain deadline elapsed" })'


class RuntimeFailure(Exception):
    """A fixed diagnostic label; never format arbitrary child output."""


def require(condition, label):
    if not condition:
        raise RuntimeFailure(label)


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_all(stream, data):
    remaining = memoryview(data)
    while remaining:
        count = stream.write(remaining)
        require(isinstance(count, int) and 0 < count <= len(remaining), "log_short_write")
        remaining = remaining[count:]


class Deadline:
    def __init__(self, seconds, interrupted=None):
        self.until = time.monotonic() + seconds
        self.interrupted = interrupted or threading.Event()

    def left(self, maximum=3.0):
        require(not self.interrupted.is_set(), "runtime_interrupted")
        value = min(maximum, self.until - time.monotonic())
        require(value > 0, "runtime_deadline")
        return value


def receive(stream, size, deadline):
    data = bytearray()
    while len(data) < size:
        stream.settimeout(deadline.left())
        block = stream.recv(size - len(data))
        require(bool(block), "unexpected_eof")
        data.extend(block)
    return bytes(data)


def send(stream, data, deadline):
    stream.settimeout(deadline.left())
    stream.sendall(data)


def eof(stream, deadline):
    stream.settimeout(deadline.left())
    require(stream.recv(1) == b"", "unexpected_trailing_payload")


def begin_request(stream, protocol, port, deadline):
    if protocol == "http":
        target = "127.0.0.1:%d" % port
        send(stream, ("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)).encode("ascii"), deadline)
    else:
        require(protocol == "socks5", "unsupported_protocol")
        send(stream, b"\x05\x01\x00", deadline)


def finish_request(stream, protocol, port, deadline):
    """Bound RFC 9110 CONNECT headers and RFC 1928 replies before tunnel data."""
    if protocol == "http":
        head = bytearray()
        while not head.endswith(b"\r\n\r\n"):
            require(len(head) < 4096, "http_header_limit")
            head.extend(receive(stream, 1, deadline))
        lines = bytes(head[:-4]).split(b"\r\n")
        status = lines[0].split()
        require(len(status) >= 2 and status[0] == b"HTTP/1.1" and len(status[1]) == 3
                and status[1].isdigit() and 200 <= int(status[1]) < 300, "http_connect_status")
        for line in lines[1:]:
            require(b":" in line and not line[:1].isspace(), "http_header_syntax")
            name = line.split(b":", 1)[0]
            require(re.fullmatch(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name) is not None, "http_header_name")
            require(name.lower() not in (b"content-length", b"transfer-encoding"), "http_connect_framing")
    else:
        require(protocol == "socks5", "unsupported_protocol")
        require(receive(stream, 2, deadline) == b"\x05\x00", "socks_method")
        send(stream, b"\x05\x01\x00\x01\x7f\x00\x00\x01" + port.to_bytes(2, "big"), deadline)
        reply = receive(stream, 4, deadline)
        require(reply[:3] == b"\x05\x00\x00", "socks_connect_status")
        if reply[3] in (1, 4):
            receive(stream, 6 if reply[3] == 1 else 18, deadline)
        elif reply[3] == 3:
            length = receive(stream, 1, deadline)[0]
            require(length > 0, "socks_reply_domain")
            receive(stream, length + 2, deadline)
        else:
            raise RuntimeFailure("socks_reply_address_type")


def prefixes(client, origin, deadline):
    send(client, PREFIX_UP, deadline)
    require(receive(origin, len(PREFIX_UP), deadline) == PREFIX_UP, "prefix_upload")
    send(origin, PREFIX_DOWN, deadline)
    require(receive(client, len(PREFIX_DOWN), deadline) == PREFIX_DOWN, "prefix_download")


def fin_tail(client, origin, deadline):
    send(client, UP, deadline)
    client.shutdown(socket.SHUT_WR)
    require(receive(origin, len(UP), deadline) == UP, "fin_upload")
    eof(origin, deadline)
    send(origin, DOWN, deadline)
    origin.shutdown(socket.SHUT_WR)
    require(receive(client, len(DOWN), deadline) == DOWN, "fin_reverse_tail")
    eof(client, deadline)


def hold_stalled(proxy, client, origin, deadline):
    """Observe one second without data/EOF or process exit after the marker.

    Local open descriptors alone do not establish that the proxy kept its
    stalled connections alive. This is a short lower-bound observation, not
    proof of the implementation's exact drain timeout; the same deadline wins.
    """
    until = time.monotonic() + 1.0
    while True:
        require(proxy.process.poll() is None, "stall_proxy_exited_early")
        remaining = until - time.monotonic()
        if remaining <= 0:
            break
        readable, _, _ = select.select([client, origin], [], [], deadline.left(remaining))
        require(not readable, "stall_endpoint_readable")
    require(proxy.process.poll() is None, "stall_proxy_exited_early")


def normalized(path):
    return os.path.normcase(os.path.abspath(str(path)))


def shutdown_outcome(status, elapsed, stalled, output):
    """Incomplete drain is an error, not a successful graceful shutdown.

    Accept only the current CLI's exact deadline diagnostic and exit code for
    the deliberately held-open fixture. An unrelated failure, or a zero exit
    that silently discards the stalled tunnel, must still fail the gate.
    """
    require(0 <= elapsed <= SHUTDOWN_SECONDS, "proxy_shutdown_failed")
    lines = output.splitlines()
    errors = [line for line in lines if line.startswith(b"Error:")]
    if stalled:
        require(status == 1 and errors == [DRAIN_TIMEOUT] and lines[-1] == DRAIN_TIMEOUT, "proxy_shutdown_failed")
        return "drain_timeout"
    require(status == 0 and not errors, "proxy_shutdown_failed")
    return "complete"


class Windows:
    """Held process identity/query in parent; console APIs only in sender()."""
    def __init__(self):
        require(os.name == "nt", "windows_required")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "GetCurrentProcess": ([], wintypes.HANDLE),
            "DuplicateHandle": ([wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.BOOL),
            "GetProcessId": ([wintypes.HANDLE], wintypes.DWORD),
            "GetProcessTimes": ([wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4, wintypes.BOOL),
            "QueryFullProcessImageNameW": ([wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            "FreeConsole": ([], wintypes.BOOL),
            "AttachConsole": ([wintypes.DWORD], wintypes.BOOL),
            "SetConsoleCtrlHandler": ([ctypes.c_void_p, wintypes.BOOL], wintypes.BOOL),
            "GetConsoleProcessList": ([ctypes.POINTER(wintypes.DWORD), wintypes.DWORD], wintypes.DWORD),
            "GenerateConsoleCtrlEvent": ([wintypes.DWORD, wintypes.DWORD], wintypes.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            method = getattr(self.kernel, name)
            method.argtypes, method.restype = arguments, result

    def identity(self, handle):
        times = [wintypes.FILETIME() for _ in range(4)]
        require(self.kernel.GetProcessTimes(handle, *(ctypes.byref(item) for item in times)), "process_times")
        path, length = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
        require(self.kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(length)), "process_image")
        pid = self.kernel.GetProcessId(handle)
        require(pid > 0 and 0 < length.value < 32768, "process_identity")
        return [int(pid), str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime), normalized(path.value)]

    def alive(self, handle):
        state = self.kernel.WaitForSingleObject(handle, 0)
        require(state in (0, 258), "process_wait")
        return state == 258

    def duplicate(self, handle):
        current, target = self.kernel.GetCurrentProcess(), wintypes.HANDLE()
        require(self.kernel.DuplicateHandle(current, handle, current, ctypes.byref(target),
                                           0x1000 | 0x00100000, True, 0) and target.value, "process_handle_duplicate")
        return target.value

    def close(self, handle):
        require(self.kernel.CloseHandle(handle), "process_handle_close")


def sender(arguments):
    """The sole role that detaches/attaches and broadcasts CTRL_C_EVENT(0,0)."""
    api, attached, handle = None, False, arguments.handle
    result = {"passed": False}
    try:
        api = Windows()
        require(digest(Path(__file__)) == arguments.module_sha and digest(arguments.binary) == arguments.binary_sha, "sender_input_changed")
        expected = [arguments.pid, arguments.created, normalized(arguments.binary)]
        require(api.identity(handle) == expected and api.alive(handle), "sender_identity")
        require(api.kernel.FreeConsole(), "sender_free_console")
        require(api.kernel.AttachConsole(arguments.pid), "sender_attach_console")
        attached = True
        require(api.kernel.SetConsoleCtrlHandler(None, True), "sender_ignore_after_attach")
        members = (wintypes.DWORD * 4)()
        count = api.kernel.GetConsoleProcessList(members, 4)
        require(count == 2 and set(members[:count]) == {arguments.pid, os.getpid()}, "sender_console_members")
        require(api.identity(handle) == expected and api.alive(handle), "sender_identity_before_signal")
        result["signal_monotonic"] = time.monotonic()
        require(api.kernel.GenerateConsoleCtrlEvent(0, 0), "sender_ctrl_c")
        result.update({"passed": True, "console_members": list(members[:count])})
    except BaseException as error:
        result["failure"] = str(error) if isinstance(error, RuntimeFailure) else "sender_failed"
    finally:
        if api is not None:
            try:
                if attached:
                    require(api.kernel.FreeConsole(), "sender_detach")
            except BaseException:
                result["passed"] = False
            try:
                api.close(handle)
                result["inherited_handle_closed"] = True
            except BaseException:
                result["passed"] = False
    raw = json.dumps(result, allow_nan=False).encode("ascii") + b"\n"
    write_all(sys.stdout.buffer, raw)
    sys.stdout.buffer.flush()
    return 0 if result["passed"] else 1


def default_environment():
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    if os.name == "nt":
        root = os.environ.get("SystemRoot")
        require(root and Path(root).is_absolute(), "windows_root_unavailable")
        environment.update({"SystemRoot": root, "WINDIR": root, "PATH": os.pathsep.join([str(Path(root) / "System32"), root])})
    return environment


class Proxy:
    def __init__(self, binary, protocol, workers, directory, deadline, environment):
        self.binary, self.deadline, self.environment = binary, deadline, environment
        self.path = directory / "proxy.log"
        self.argv = [str(binary), "run", "--bind", "127.0.0.1:0", "--workers", str(workers),
                     "--concurrent", "1", "--connect-timeout", "3", protocol]
        self.process = self.reader = self.output = self.pidfd = None
        self.ready, self.marker = threading.Event(), threading.Event()
        self.port, self.log_error = None, None
        self.record = {"argv": self.argv, "forced_cleanup": False}
        self.windows = Windows() if os.name == "nt" else None

    def start(self):
        self.output = self.path.open("xb", buffering=0)
        options = {"start_new_session": True} if os.name != "nt" else {}
        if self.windows:
            startup = subprocess.STARTUPINFO()
            startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = subprocess.SW_HIDE
            options = {"startupinfo": startup, "creationflags": subprocess.CREATE_NEW_CONSOLE}
        self.process = subprocess.Popen(self.argv, cwd=self.path.parent, env=self.environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            close_fds=True, bufsize=0, **options)
        self.record["pid"] = self.process.pid
        if self.windows:
            self.record["identity"] = self.windows.identity(int(self.process._handle))
            require(self.record["identity"][2] == normalized(self.binary), "proxy_image")
        else:
            self.pidfd = os.pidfd_open(self.process.pid, 0)
            os.set_inheritable(self.pidfd, False)
        self.reader = threading.Thread(target=self.read_log, name="release-proxy-log", daemon=True)
        self.reader.start()
        require(self.ready.wait(self.deadline.left(8.0)), "proxy_readiness_timeout")
        require(self.port is not None and self.process.poll() is None and self.log_error is None, "proxy_readiness_failed")

    def read_log(self):
        pending, total = b"", 0
        try:
            while block := os.read(self.process.stdout.fileno(), 4096):
                require(total + len(block) <= LOG_LIMIT, "proxy_log_limit")
                write_all(self.output, block)
                total += len(block)
                pending += block
                require(len(pending) <= 16384, "proxy_log_line_limit")
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    found = BOUND.search(line)
                    if found and self.port is None:
                        self.port = int(found[1])
                        require(0 < self.port < 65536, "proxy_port")
                        self.ready.set()
                    field = rb'\bsignal=(?:"Ctrl\+C"|Ctrl\+C)(?:\s|$)' if self.windows else rb'\bsignal=(?:"SIGTERM"|SIGTERM)(?:\s|$)'
                    if b"received graceful shutdown signal" in line and re.search(field, line):
                        self.marker.set()
        except BaseException as error:
            self.log_error = str(error) if isinstance(error, RuntimeFailure) else "proxy_log_failed"
        finally:
            try:
                self.output.flush()
                os.fsync(self.output.fileno())
            except (OSError, ValueError):
                self.log_error = self.log_error or "proxy_log_flush"
            finally:
                try:
                    self.output.close()
                except (OSError, ValueError):
                    self.log_error = self.log_error or "proxy_log_close"

    def signal(self):
        if not self.windows:
            # The listening log precedes handler registration. Verify the owned
            # Linux child has caught SIGTERM, rather than race default exit.
            until = time.monotonic() + self.deadline.left()
            while True:
                require(not select.select([self.pidfd], [], [], 0)[0], "proxy_exited_before_signal")
                status = Path("/proc/%d/status" % self.process.pid).read_text()
                caught = next(int(line.split()[1], 16) for line in status.splitlines() if line.startswith("SigCgt:"))
                if caught & (1 << (signal.SIGTERM - 1)):
                    break
                require(time.monotonic() < until, "sigterm_handler_unavailable")
                time.sleep(0.01)
        started = time.monotonic()
        self.deadline.until = min(self.deadline.until, started + SHUTDOWN_SECONDS)
        if self.windows:
            self.record["sender"] = self.send_windows()
        else:
            signal.pidfd_send_signal(self.pidfd, signal.SIGTERM, None, 0)
        require(self.marker.wait(self.deadline.left(2.0)), "shutdown_handler_log_missing")
        self.record["handler_marker_observed"] = True
        self.record["shutdown_started_monotonic"] = started
        return started

    def send_windows(self):
        duplicate, helper = None, None
        record = {"passed": False}
        self.record["sender"] = record
        try:
            duplicate = self.windows.duplicate(int(self.process._handle))
            startup = subprocess.STARTUPINFO()
            startup.lpAttributeList = {"handle_list": [duplicate]}
            identity = self.record["identity"]
            args = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--sender",
                    "--handle", str(duplicate), "--pid", str(identity[0]), "--created", identity[1],
                    "--binary", str(self.binary), "--binary-sha", digest(self.binary), "--module-sha", digest(Path(__file__))]
            before = time.monotonic()
            helper = subprocess.Popen(args, env=self.environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True,
                startupinfo=startup, creationflags=subprocess.CREATE_NO_WINDOW)
            record["pid"] = helper.pid
            raw, _ = helper.communicate(timeout=self.deadline.left(3.0))
            require(len(raw) <= 4096, "sender_output_limit")
            result = json.loads(raw)
            record["result"] = result
            require(helper.returncode == 0 and result.get("passed") is True
                    and result.get("inherited_handle_closed") is True, "sender_rejected")
            sent = result.get("signal_monotonic")
            require(type(sent) in (int, float) and math.isfinite(sent)
                    and before <= sent <= time.monotonic(), "sender_signal_time")
            record.update({"passed": True, "exit_code": helper.returncode, "result": result})
            return record
        finally:
            errors = []
            if helper is not None:
                try:
                    if helper.poll() is None:
                        helper.kill()
                        record["forced_cleanup"] = True
                    helper.wait(timeout=3)
                    record["exit_code"] = helper.returncode
                except BaseException:
                    errors.append("sender_reap")
                try:
                    if helper.stdout is not None:
                        helper.stdout.close()
                except (OSError, ValueError):
                    errors.append("sender_pipe")
                try:
                    helper._handle.Close()
                    record["process_handle_closed"] = True
                except (OSError, ValueError):
                    errors.append("sender_process_handle")
            if duplicate is not None:
                try:
                    self.windows.close(duplicate)
                    record["parent_duplicate_closed"] = True
                except BaseException:
                    errors.append("sender_duplicate")
            record["cleanup_errors"] = errors
            require(not errors, "sender_cleanup_failed")

    def wait(self, signal_started, stalled):
        self.process.wait(timeout=self.deadline.left(SHUTDOWN_SECONDS))
        elapsed = time.monotonic() - signal_started
        self.record.update({"exit_code": self.process.returncode, "signal_to_reap_seconds": elapsed})
        self.reader.join(self.deadline.left(3.0))
        require(not self.reader.is_alive() and self.log_error is None, "proxy_log_failed")
        with self.path.open("rb") as output:
            logged = output.read(LOG_LIMIT + 1)
        require(len(logged) <= LOG_LIMIT, "proxy_log_limit")
        self.record["shutdown_outcome"] = shutdown_outcome(self.process.returncode, elapsed, stalled, logged)

    def close(self):
        errors = []
        if self.process is not None:
            try:
                if self.process.poll() is None:
                    self.process.kill()
                    self.record["forced_cleanup"] = True
                self.process.wait(timeout=3)
                self.record["exit_code"] = self.process.returncode
            except BaseException:
                errors.append("proxy_reap")
        if self.reader is not None and self.reader.ident is not None:
            try:
                self.reader.join(3)
            except RuntimeError:
                errors.append("proxy_log_join")
            if self.reader.is_alive():
                errors.append("proxy_log_thread")
        for item, label in ((self.process.stdout if self.process else None, "proxy_pipe"), (self.output, "proxy_log")):
            if item is not None:
                try:
                    item.close()
                except (OSError, ValueError):
                    errors.append(label)
        if self.pidfd is not None:
            try:
                os.close(self.pidfd)
            except OSError:
                errors.append("proxy_pidfd")
        if self.windows and self.process is not None:
            try:
                self.process._handle.Close()
                self.record["process_handle_closed"] = True
            except (OSError, ValueError):
                errors.append("proxy_handle")
        if self.log_error:
            errors.append(self.log_error)
        if self.path.exists() and not (self.reader and self.reader.is_alive()):
            try:
                self.record["log"] = {"path": str(self.path), "bytes": self.path.stat().st_size, "sha256": digest(self.path)}
            except OSError:
                errors.append("proxy_log_digest")
        return errors


def cell(binary, directory, protocol, workers, stalled, environment, interrupted):
    deadline = Deadline(45, interrupted)
    proxy = Proxy(binary, protocol, workers, directory, deadline, environment)
    sockets = []
    result = {"protocol": protocol, "workers": workers, "stall": stalled, "passed": False, "process": proxy.record}
    cleanup = []
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sockets.append(listener)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        port = listener.getsockname()[1]
        proxy.start()

        def connect():
            stream = socket.create_connection(("127.0.0.1", proxy.port), timeout=deadline.left())
            sockets.append(stream)
            begin_request(stream, protocol, port, deadline)
            return stream

        def accept(client):
            finish_request(client, protocol, port, deadline)
            listener.settimeout(deadline.left())
            origin, peer = listener.accept()
            sockets.append(origin)
            require(peer[0] == "127.0.0.1", "origin_peer")
            prefixes(client, origin, deadline)
            return origin

        client = connect()
        origin = accept(client)
        if not stalled:
            waiting = connect()
            waiting.settimeout(0.15)
            try:
                waiting.recv(1)
            except socket.timeout:
                result["second_connection_no_reply_window_seconds"] = 0.15
            else:
                raise RuntimeFailure("second_connection_admitted_or_closed_while_full")
            fin_tail(client, origin, deadline)
            client.close()
            origin.close()
            client, origin = waiting, accept(waiting)
            result["cap_one_recovery"] = True
        started = proxy.signal()
        # The marker precedes request_graceful_shutdown: it proves handler
        # progress, not that every accept loop has already stopped.
        require(client.fileno() >= 0 and origin.fileno() >= 0, "endpoints_closed_before_handler")
        if stalled:
            hold_stalled(proxy, client, origin, deadline)
            result["stalled_no_early_exit_window_seconds"] = 1.0
        else:
            fin_tail(client, origin, deadline)
        proxy.wait(started, stalled)
        require(client.fileno() >= 0 and origin.fileno() >= 0, "fixture_released_endpoints_before_exit")
        try:
            probe = socket.create_connection(("127.0.0.1", proxy.port), timeout=3)
        except ConnectionRefusedError:
            result["port_refused_after_reap"] = True
        else:
            probe.close()
            raise RuntimeFailure("proxy_port_still_open")
        require(proxy.log_error is None, "proxy_log_failed")
        result.update({"passed": True, "duplex_prefixes_verified": True,
                       "fin_tail_verified": not stalled, "endpoints_held_until_exit": stalled})
    except BaseException as error:
        result["failure"] = str(error) if isinstance(error, RuntimeFailure) else type(error).__name__
    finally:
        # Reap the owned proxy before releasing a stalled connection on failure.
        try:
            cleanup.extend(proxy.close())
        except BaseException:
            cleanup.append("proxy_cleanup_failed")
        for stream in sockets:
            try:
                stream.close()
            except OSError:
                cleanup.append("owned_socket_close")
        result["owned_sockets_closed"] = all(stream.fileno() == -1 for stream in sockets)
        result["cleanup_errors"] = cleanup
        if cleanup or proxy.record["forced_cleanup"] or not result["owned_sockets_closed"]:
            result["passed"] = False
    return result


def run(binary, output_dir, *, environment=None):
    """Run eight serial cases on an already-checked extracted proxy executable.

    A new directory retains logs and report.json on either success or failure.
    The caller must propagate passed=false. No real network run occurs merely
    by importing this module or running its isolated parser/lifecycle unit tests.
    """
    binary, output_dir = Path(binary), Path(output_dir)
    require(platform.system() in ("Linux", "Windows") and platform.machine().lower() in ("x86_64", "amd64"), "native_x64_host_required")
    require(binary.is_absolute() and binary.resolve() == binary and stat.S_ISREG(binary.lstat().st_mode)
            and not binary.is_symlink() and binary.stat().st_size > 0, "checked_binary_required")
    require(output_dir.is_absolute() and output_dir.parent.resolve() == output_dir.parent
            and output_dir.parent.is_dir(), "real_output_parent_required")
    output_dir.mkdir(mode=0o700)
    report = {"passed": False, "scope": "anonymous numeric-loopback HTTP/SOCKS5 CONNECT; cap-one observation/recovery, FIN tails, normal/stalled shutdown; not performance, TLS or management E2E",
              "shutdown_budget_seconds": SHUTDOWN_SECONDS, "binary": str(binary), "binary_before_sha256": digest(binary), "cases": []}
    interrupted, previous = threading.Event(), {}
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, lambda _sig, _frame: interrupted.set())
        child_environment = dict(default_environment() if environment is None else environment)
        child_environment["RUST_LOG"] = "info"
        for stalled in (False, True):
            for protocol in ("http", "socks5"):
                for workers in (1, 2):
                    directory = output_dir / ("%s-w%d-%s" % (protocol, workers, "stall" if stalled else "normal"))
                    directory.mkdir(mode=0o700)
                    result = cell(binary, directory, protocol, workers, stalled, child_environment, interrupted)
                    report["cases"].append(result)
                    require(result["passed"], "proxy_runtime_case_failed")
        report["binary_after_sha256"] = digest(binary)
        require(report["binary_after_sha256"] == report["binary_before_sha256"], "runtime_binary_changed")
        report["passed"] = True
    except BaseException as error:
        report["failure"] = str(error) if isinstance(error, RuntimeFailure) else type(error).__name__
    finally:
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except (OSError, ValueError):
                report["passed"] = False
                report["failure"] = "signal_handler_restore"
    with (output_dir / "report.json").open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, allow_nan=False)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Internal private-console signal sender; runtime integration calls run().")
    parser.add_argument("--sender", action="store_true", required=True)
    parser.add_argument("--handle", type=int, required=True)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--created", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha", required=True)
    parser.add_argument("--module-sha", required=True)
    raise SystemExit(sender(parser.parse_args()))
