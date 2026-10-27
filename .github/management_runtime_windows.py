#!/usr/bin/env python3
"""Windows native CLI journey; disposable file CA, no service or system trust.

Run the shared journey inside one hidden, dedicated console and an unnamed job.
Ctrl+C is broadcast only after checking every console member belongs to that job.
The job handle is non-inherited and retained until worker exit, so parent failure
cannot orphan the generated PowerShell script or its native child. No process is
identified for termination by a saved PID, name or executable search.
"""

import argparse
import ctypes as c
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

import management_runtime as runtime


class BasicLimit(c.Structure):
    """Win32 JOBOBJECT_BASIC_LIMIT_INFORMATION; pointer-sized fields stay native."""
    _fields_ = [('process_time', c.c_int64), ('job_time', c.c_int64),
                ('flags', c.c_uint32), ('min_working_set', c.c_size_t),
                ('max_working_set', c.c_size_t), ('active_limit', c.c_uint32),
                ('affinity', c.c_size_t), ('priority', c.c_uint32), ('scheduling', c.c_uint32)]


class ExtendedLimit(c.Structure):
    """Only KILL_ON_JOB_CLOSE is enabled; no CPU, memory or breakaway policy."""
    _fields_ = [('basic', BasicLimit), ('io_counters', c.c_uint64 * 6),
                ('process_memory', c.c_size_t), ('job_memory', c.c_size_t),
                ('peak_process_memory', c.c_size_t), ('peak_job_memory', c.c_size_t)]


class ProcessList(c.Structure):
    """A bounded job membership query; truncation is rejected, never trusted."""
    _fields_ = [('assigned', c.c_uint32), ('count', c.c_uint32), ('ids', c.c_size_t * 128)]


class PrivateConsole:
    """Own one new console/job before any CLI or shell is spawned.

    https://learn.microsoft.com/en-us/windows/console/generateconsolectrlevent
    https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
    """
    def __init__(self):
        self.api = c.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'GetConsoleProcessList': ([c.POINTER(c.c_uint32), c.c_uint32], c.c_uint32),
            'CreateJobObjectW': ([c.c_void_p, c.c_wchar_p], c.c_void_p),
            'SetInformationJobObject': ([c.c_void_p, c.c_int, c.c_void_p, c.c_uint32], c.c_int),
            'AssignProcessToJobObject': ([c.c_void_p, c.c_void_p], c.c_int),
            'GetCurrentProcess': ([], c.c_void_p),
            'QueryInformationJobObject': ([c.c_void_p, c.c_int, c.c_void_p, c.c_uint32, c.c_void_p], c.c_int),
            'GenerateConsoleCtrlEvent': ([c.c_uint32, c.c_uint32], c.c_int),
            'CloseHandle': ([c.c_void_p], c.c_int),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result
        runtime.require(self.console_members() == {os.getpid()}, 'dedicated_console_required')
        self.handle = self.api.CreateJobObjectW(None, None)
        runtime.require(self.handle, 'job_create_failed')
        limit = ExtendedLimit()
        limit.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        try:
            runtime.require(self.api.SetInformationJobObject(self.handle, 9, c.byref(limit), c.sizeof(limit)), 'job_limit_failed')
            runtime.require(self.api.AssignProcessToJobObject(self.handle, self.api.GetCurrentProcess()), 'job_assign_failed')
        except BaseException:
            self.api.CloseHandle(self.handle)
            raise
        # Do not CloseHandle here: the worker belongs to this job. The OS closes
        # this sole non-inherited handle at exit and kills any failed descendants.

    def console_members(self):
        buffer = (c.c_uint32 * 128)()
        count = self.api.GetConsoleProcessList(buffer, len(buffer))
        runtime.require(0 < count <= len(buffer), 'console_members_unavailable')
        return set(buffer[:count])

    def members(self):
        info = ProcessList()
        runtime.require(self.api.QueryInformationJobObject(self.handle, 3, c.byref(info), c.sizeof(info), None), 'job_members_unavailable')
        runtime.require(info.assigned == info.count <= len(info.ids), 'job_members_truncated')
        return set(info.ids[:info.count])

    def interrupt(self):
        members = self.console_members()
        runtime.require(os.getpid() in members and members <= self.members(), 'foreign_console_member')
        # CTRL_C_EVENT cannot be restricted to a nonzero process group. This
        # worker's checked private console is the complete broadcast boundary.
        runtime.require(self.api.GenerateConsoleCtrlEvent(0, 0), 'console_interrupt_failed')

    def empty(self):
        # Job membership can lag a signaled child handle briefly. Observe this
        # same job, never restart children or infer completion from a shell PID.
        until = time.monotonic() + 2
        while self.members() != {os.getpid()}:
            runtime.require(time.monotonic() < until, 'owned_descendants_remain')
            time.sleep(0.01)


# The directory is still empty when its inherited ACL is removed. No secret is
# generated until an exact current-user/SYSTEM protected ACL has been read back.
PRIVATE_OUTPUT = r'''
$ErrorActionPreference='Stop'
$p=$env:VPROXY_CLI_FIXTURE
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$directory=[IO.DirectoryInfo]::new($p)
$before=[IO.FileSystemAclExtensions]::GetAccessControl($directory)
if($before.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){throw 'private output owner'}
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
foreach($id in @($sid,$system)) {
  $rule=[Security.AccessControl.FileSystemAccessRule]::new($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $acl.AddAccessRule($rule)
}
[IO.FileSystemAclExtensions]::SetAccessControl($directory,$acl)
$actual=[IO.FileSystemAclExtensions]::GetAccessControl($directory)
if(-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){throw 'private output owner'}
$rules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
if($rules.Count -ne 2){throw 'private output rules'}
foreach($rule in $rules){if($rule.IdentityReference.Value -notin @($sid.Value,$system.Value) -or $rule.AccessControlType -ne 'Allow' -or $rule.IsInherited){throw 'private output access'}}
'''


class Runner(runtime.Runner):
    def __init__(self, binary, output, powershell, console):
        super().__init__(binary, output)
        self.powershell, self.console = powershell, console
        system_root = os.environ['SystemRoot']
        self.environment = {'SystemRoot': system_root, 'WINDIR': system_root,
                            'SystemDrive': Path(system_root).drive,
                            'PATH': str(Path(system_root) / 'System32'),
                            'PATHEXT': '.COM;.EXE;.BAT;.CMD',
                            'ComSpec': str(Path(system_root) / 'System32/cmd.exe'),
                            'USERPROFILE': str(output), 'LOCALAPPDATA': str(output / 'local-cache'),
                            'APPDATA': str(output / 'roaming-cache'),
                            'ProgramData': str(output / 'program-cache'),
                            'ALLUSERSPROFILE': str(output / 'program-cache'),
                            'TEMP': str(output), 'TMP': str(output), 'RUST_LOG': 'info'}

    def read_header(self, file):
        # Every parent is created by this run: the private fixture ACL above and
        # native setup/create routines. The native query also checks its open
        # header handle's DACL. Do not apply POSIX mode/uid tests on Windows.
        before = file.lstat()
        runtime.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                        and not before.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT, 'header_not_private')
        with file.open('rb') as source:
            opened = os.fstat(source.fileno())
            runtime.require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'header_changed')
            raw = source.read(513)
        runtime.require(runtime.re.fullmatch(rb'Authorization: Bearer [A-Za-z0-9._~+/=-]{1,128}\n', raw) is not None, 'header_format')
        return raw.removeprefix(b'Authorization: Bearer ').rstrip(b'\n')


class Server(runtime.Server):
    """Execute the generated start.ps1, retaining its Popen handle until wait."""
    def start(self):
        self.process = subprocess.Popen([str(self.runner.powershell), '-NoProfile', '-NonInteractive',
            '-File', str(self.launch / 'start.ps1')], stdin=subprocess.DEVNULL,
            stdout=self.log, stderr=self.log, env=self.runner.environment, close_fds=True)
        self.record['pid'] = self.process.pid

    def ready(self, ca):
        # Windows can report a TCP connect timeout for an unbound loopback port.
        # Probe TCP separately: TLS/time/name failures are never startup retries.
        until = time.monotonic() + self.runner.left()
        while True:
            runtime.require(self.process.poll() is None, 'server_exited_before_ready')
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=0.3):
                    break
            except (ConnectionRefusedError, TimeoutError):
                runtime.require(time.monotonic() < until, 'server_tcp_readiness_deadline')
                time.sleep(0.03)
        super().ready(ca)

    def stop(self):
        runtime.require(self.process.poll() is None, 'server_exited_before_stop')
        self.runner.console.interrupt()
        self.process.wait(timeout=self.runner.left(10))
        runtime.require(self.process.returncode == 0, 'server_shutdown_failed')
        self.runner.console.empty()
        self.close()

    def close(self):
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    self.process.kill()
                    self.record['forced'] = True
                self.process.wait(timeout=3)
                self.record['exit_code'] = self.process.returncode
        finally:
            self.log.close()


def output_preflight(output, resume_empty):
    """An explicit bootstrap resume cannot touch any prior fixture contents."""
    if resume_empty:
        info = output.lstat()
        runtime.require(stat.S_ISDIR(info.st_mode)
                        and not info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
                        and not any(output.iterdir()), 'empty_bootstrap_required')
    else:
        runtime.require(not os.path.lexists(output), 'new_fixture_required')
    runtime.require(output.parent.is_dir(), 'fixture_parent_required')


def worker(arguments):
    console = PrivateConsole()
    # A Python handler, not SIG_IGN: Windows children must not inherit the
    # attribute that disables Ctrl+C. Only the worker consumes its own event.
    signal.signal(signal.SIGINT, lambda *_: None)
    output = arguments.output
    output_preflight(output, arguments.resume_empty_bootstrap)
    if not arguments.resume_empty_bootstrap:
        output.mkdir()  # Exclusive: existing outputs, including symlinks, fail.
    environment = dict(os.environ, VPROXY_CLI_FIXTURE=str(output))
    result = subprocess.run([str(arguments.powershell), '-NoProfile', '-NonInteractive', '-Command', PRIVATE_OUTPUT],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment, close_fds=True, timeout=10)
    runtime.require(result.returncode == 0 and not result.stdout, 'private_output_failed')
    runner = Runner(arguments.binary, output, arguments.powershell, console)
    report = runtime.run_fixture(runner, output, Server,
        scope='fresh_windows_cli_setup_and_local_automation_only', final_check=console.empty)
    print(json.dumps(report, ensure_ascii=True, allow_nan=False))
    return 0 if report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--powershell', type=Path, default=shutil.which('pwsh.exe'))
    parser.add_argument('--resume-empty-bootstrap', action='store_true', help='Resume only an empty directory after a failed preflight; no fixture contents may exist')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    runtime.require(sys.platform == 'win32' and arguments.powershell is not None, 'windows_pwsh_required')
    arguments.binary = arguments.binary.resolve(strict=True)
    arguments.powershell = Path(arguments.powershell).resolve(strict=True)
    arguments.output = arguments.output.absolute()
    runtime.require(arguments.binary.is_file() and arguments.powershell.is_file(), 'native_executables_required')
    output_preflight(arguments.output, arguments.resume_empty_bootstrap)
    if arguments.worker:
        return worker(arguments)
    startup = subprocess.STARTUPINFO()
    startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = subprocess.SW_HIDE
    command = [sys.executable, '-B', str(Path(__file__).resolve()), '--worker',
        '--binary', str(arguments.binary), '--output', str(arguments.output), '--powershell', str(arguments.powershell)]
    if arguments.resume_empty_bootstrap:
        command.append('--resume-empty-bootstrap')
    process = subprocess.Popen(command,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        close_fds=True, creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup)
    try:
        stdout, stderr = process.communicate(timeout=330)
        report = runtime.decode(stdout)
        runtime.require(process.returncode in (0, 1) and not stderr
                        and isinstance(report, dict) and report.get('passed') == (process.returncode == 0), 'worker_failed')
        print(json.dumps(report, ensure_ascii=True, allow_nan=False))
        return process.returncode
    finally:
        if process.poll() is None:
            process.kill()  # Retained worker handle; its job reaps descendants.
        process.wait(timeout=3)
        for stream in (process.stdout, process.stderr):
            stream.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except runtime.Failure as error:
        print(json.dumps({'passed': False, 'failure': str(error)}))
        sys.exit(1)
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError):
        print('{"passed":false,"failure":"windows_fixture_failed"}')
        sys.exit(1)
