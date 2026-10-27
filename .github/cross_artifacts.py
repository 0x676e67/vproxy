#!/usr/bin/env python3
"""Check trusted cross-build archives without compiling, repacking or publishing.

Runtime checks are opt-in and run only matching host binaries. File-header checks
do not prove ISA/ABI compatibility, static linking or complete format validity.
"""

import argparse
import gzip
import hashlib
from itertools import product
import json
import os
from pathlib import Path, PureWindowsPath
import platform
import re
import stat
import struct
import subprocess
import tarfile
import threading
import time


TARGETS = {
    "x86_64-pc-windows-gnu": ("pe", 64, 0x8664),
    "i686-pc-windows-gnu": ("pe", 32, 0x014C),
    "x86_64-apple-darwin": ("macho", 64, 0x01000007),
    "aarch64-apple-darwin": ("macho", 64, 0x0100000C),
    "x86_64-unknown-linux-musl": ("elf", 64, 62),
    "aarch64-unknown-linux-musl": ("elf", 64, 183),
    "armv7-unknown-linux-musleabihf": ("elf", 32, 40),
    "arm-unknown-linux-musleabihf": ("elf", 32, 40),
    "i686-unknown-linux-musl": ("elf", 32, 3),
}
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024
MAX_OUTPUT = 128 * 1024
COMMAND_TIMEOUT = 15
CLEANUP_TIMEOUT = 5
MAX_DOCUMENT = 256 * 1024
PROFILES = {"proxy": "", "api": "-api", "web": "-web"}


def selected_profiles(profiles):
    require(profiles in (*PROFILES, "all"), "invalid_profiles")
    return tuple(PROFILES) if profiles == "all" else (profiles,)


class CheckError(Exception):
    """A fixed diagnostic code; child output is retained only in bounded logs."""


def require(condition, code):
    if not condition:
        raise CheckError(code)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def regular(path, maximum):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
            and 0 < info.st_size <= maximum, "invalid_regular_file")
    return info


def runtime_targets(mode, system, machine):
    """Select only native hosts; do not infer cross-architecture emulation."""
    machine = machine.lower()
    if mode == "none":
        return []
    if mode == "linux" and system == "Linux" and machine in ("x86_64", "amd64"):
        return ["x86_64-unknown-linux-musl"]
    if mode == "windows" and system == "Windows" and machine in ("x86_64", "amd64"):
        return ["x86_64-pc-windows-gnu", "i686-pc-windows-gnu"]
    if mode == "macos" and system == "Darwin":
        if machine in ("x86_64", "amd64"):
            return ["x86_64-apple-darwin"]
        if machine in ("arm64", "aarch64"):
            return ["aarch64-apple-darwin"]
    raise CheckError("runtime_host_mismatch")


def binary_header(path, expected):
    """Inspect bounded basic headers, not the full loader or dependency graph."""
    kind, bits, machine = expected
    with path.open("rb") as source:
        header = source.read(1024 * 1024)
    require(len(header) >= 64, "short_binary_header")
    if kind == "pe":
        offset = struct.unpack_from("<I", header, 0x3C)[0]
        require(header[:2] == b"MZ" and 64 <= offset <= len(header) - 26,
                "invalid_dos_header")
        require(header[offset:offset + 4] == b"PE\x00\x00", "invalid_pe_signature")
        require(struct.unpack_from("<H", header, offset + 4)[0] == machine,
                "pe_machine_mismatch")
        require(struct.unpack_from("<H", header, offset + 24)[0]
                == (0x20B if bits == 64 else 0x10B), "pe_class_mismatch")
    elif kind == "macho":
        require(header[:4] == b"\xcf\xfa\xed\xfe", "macho_not_thin_little_endian_64")
        require(struct.unpack_from("<I", header, 4)[0] == machine, "macho_cpu_mismatch")
        require(struct.unpack_from("<I", header, 12)[0] == 2, "macho_not_executable")
    else:
        require(header[:4] == b"\x7fELF" and header[5] == 1, "elf_not_little_endian")
        require(header[4] == (2 if bits == 64 else 1), "elf_class_mismatch")
        require(struct.unpack_from("<H", header, 18)[0] == machine, "elf_machine_mismatch")
        require(struct.unpack_from("<H", header, 16)[0] in (2, 3), "elf_not_executable_or_shared")
    return {"format": kind, "bits": bits, "machine": machine}


def unpack(archive, directory, name, profile="proxy"):
    """Validate plain headers before decoding; copy only the executable.

    API/Web documents must match this checkout, allowing only CRLF/LF checkout
    differences. Original archive checksums still cover exact distributed bytes.
    No PAX/GNU extension or arbitrary member path is interpreted or extracted.
    """
    require(profile in PROFILES, "invalid_profile")
    documents = [] if profile == "proxy" else ["LICENSE", "README.md"]
    if profile == "web":
        documents.append("LICENSE.ant-design-pro")
    names = [name, *documents]
    directory.mkdir(mode=0o700)
    payload = directory / "payload.tar"
    size = 0
    try:
        with gzip.open(archive, "rb") as source, payload.open("xb") as output:
            while block := source.read(1024 * 1024):
                size += len(block)
                require(size <= MAX_EXPANDED, "expanded_tar_limit")
                output.write(block)
        require(size >= 1536 and size % 512 == 0, "invalid_tar_size")
        with payload.open("rb") as raw:
            offset, binary_size = 0, 0
            for index, expected in enumerate(names):
                raw.seek(offset)
                header = raw.read(512)
                require(len(header) == 512 and header[156:157] in (tarfile.REGTYPE, tarfile.AREGTYPE),
                        "tar_not_plain_regular_header")
                if profile != "proxy":
                    require(header[257:265] == b"ustar\x0000", "tar_profile_not_ustar")
                member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                # frombuf normalizes old-style regular names ending in '/' to
                # directories, so validating only the raw typeflag is not enough.
                require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                        and member.name == expected and not member.linkname and not member.sparse,
                        "tar_member_mismatch")
                mode = stat.S_IMODE(member.mode) if profile == "proxy" else member.mode
                require(mode == (0o755 if index == 0 else 0o644),
                        "tar_mode_mismatch")
                require(0 < member.size <= (MAX_BINARY if index == 0 else MAX_DOCUMENT),
                        "tar_member_size")
                data_offset = offset + 512
                offset = data_offset + ((member.size + 511) // 512) * 512
                require(size - offset >= 1024, "tar_end_blocks_missing")
                if index == 0:
                    binary_size = member.size
                else:
                    raw.seek(data_offset)
                    document = raw.read(member.size)
                    source_path = Path(__file__).resolve().parent.parent / (
                        "web/" + expected if expected == "LICENSE.ant-design-pro" else expected)
                    regular(source_path, MAX_DOCUMENT)
                    reference = source_path.read_bytes()
                    require(len(reference) <= MAX_DOCUMENT and document.decode("utf-8").strip()
                            and document.replace(b"\r\n", b"\n") == reference.replace(b"\r\n", b"\n"),
                            "tar_release_document_mismatch")
            raw.seek(offset)
            while block := raw.read(1024 * 1024):
                require(not any(block), "tar_appended_data")
            binary = directory / name
            raw.seek(512)
            remaining = binary_size
            with binary.open("xb") as output:
                while remaining:
                    block = raw.read(min(1024 * 1024, remaining))
                    require(bool(block), "tar_binary_truncated")
                    output.write(block)
                    remaining -= len(block)
    except (EOFError, UnicodeError, gzip.BadGzipFile, tarfile.TarError) as error:
        raise CheckError("invalid_archive") from error
    binary.chmod(0o755)
    regular(binary, MAX_BINARY)
    return binary


def runtime_environment(inherited, *, windows):
    """Keep command lookup local and fixed; never inherit the caller's PATH."""
    environment = {"LANG": "C", "LC_ALL": "C"}
    if windows:
        root = inherited.get("SystemRoot") or inherited.get("WINDIR")
        require(isinstance(root, str) and bool(root)
                and not any(ord(char) < 32 or ord(char) == 127 for char in root)
                and ";" not in root, "runtime_windows_root_missing_or_invalid")
        path = PureWindowsPath(root)
        require(path.is_absolute() and re.fullmatch(r"[A-Za-z]:", path.drive) is not None
                and ".." not in path.parts, "runtime_windows_root_missing_or_invalid")
        root = str(path)
        environment.update({"SystemRoot": root, "WINDIR": root,
                            "PATH": os.pathsep.join([str(path / "System32"), root])})
    else:
        environment["PATH"] = "/usr/bin:/bin"
    return environment


def bounded_command(arguments, directory, log, *, timeout=COMMAND_TIMEOUT, maximum=MAX_OUTPUT):
    """Bound merged stdout/stderr, then reap the direct child on every exit path.

    A reader thread works with Windows pipes as well as POSIX. Do not replace it
    with RLIMIT_FSIZE: that also limits UPX's internal unpacking files, not just
    captured output. The deadline covers execution/draining; cleanup has its own
    bounded wait and is not a general descendant-process supervisor.
    """
    require(timeout > 0 and maximum > 0, "invalid_runtime_limit")
    deadline = time.monotonic() + timeout
    process = None
    reader = None
    started = False
    done = threading.Event()
    state = {"size": 0, "error": None}
    with log.open("xb") as output:
        try:
            environment = runtime_environment(os.environ, windows=os.name == "nt")
            process = subprocess.Popen(list(map(str, arguments)), cwd=directory, env=environment,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, bufsize=0)
            require(process.stdout is not None, "runtime_stdout_missing")

            def drain():
                try:
                    while True:
                        block = process.stdout.read(min(8192, maximum - state["size"] + 1))
                        if not block:
                            return
                        if state["size"] + len(block) > maximum:
                            state["error"] = "runtime_output_limit"
                            return
                        output.write(block)
                        state["size"] += len(block)
                except Exception:
                    state["error"] = "runtime_capture_failed"
                finally:
                    done.set()

            reader = threading.Thread(target=drain, name="cross-artifact-output", daemon=True)
            reader.start()
            started = True
            while not done.wait(max(0, min(0.05, deadline - time.monotonic()))):
                require(time.monotonic() < deadline, "runtime_timeout")
            require(state["error"] is None, state["error"])
            remaining = deadline - time.monotonic()
            require(remaining > 0, "runtime_timeout")
            try:
                return process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as error:
                raise CheckError("runtime_timeout") from error
        finally:
            if process is not None:
                try:
                    try:
                        if process.poll() is None:
                            try:
                                process.kill()
                            except ProcessLookupError:
                                pass
                    finally:
                        try:
                            process.wait(timeout=CLEANUP_TIMEOUT)
                        finally:
                            if started:
                                reader.join(timeout=CLEANUP_TIMEOUT)
                                require(not reader.is_alive(), "runtime_reader_not_joined")
                finally:
                    if process.stdout is not None and (not started or not reader.is_alive()):
                        process.stdout.close()


def validate_output(option, text, version, profile="proxy"):
    if option == "--version":
        require(text.strip() == "vproxy " + version, "runtime_version_mismatch")
    elif option == "--help":
        require("Usage: vproxy" in text and "Commands:" in text, "runtime_help_missing")
        has_management = re.search(r"^\s+manage(?:\s|$)", text, re.MULTILINE) is not None
        require(has_management == (profile != "proxy"), "runtime_management_mismatch")
    elif option == "notices-help":
        require(re.search(r"(?m)^Usage: vproxy(?:\.exe)? self notices(?:[ \t].*)?\r?$", text)
                is not None, "runtime_notices_help_missing")
        require(("embedded Web template notice" in text) == (profile == "web"),
                "runtime_web_capability_mismatch")
    elif option == "serve-help":
        require(re.search(r"(?m)^Usage: vproxy(?:\.exe)? manage serve(?:[ \t].*)?\r?$", text)
                is not None, "runtime_management_help_missing")
    else:
        raise CheckError("invalid_smoke_option")


def smoke(binary, version, directory, profile="proxy"):
    result = []
    commands = [("--version", ["--version"]), ("--help", ["--help"]),
                ("notices-help", ["self", "notices", "--help"])]
    if profile != "proxy":
        commands.append(("serve-help", ["manage", "serve", "--help"]))
    for option, arguments in commands:
        log = directory / (option.removeprefix("--") + ".log")
        before = digest(binary)
        status = bounded_command([binary, *arguments], directory, log)
        require(status == 0, "runtime_exit_nonzero")
        try:
            text = log.read_text(encoding="utf-8", errors="strict")
        except UnicodeError as error:
            raise CheckError("runtime_output_encoding") from error
        validate_output(option, text, version, profile)
        require(digest(binary) == before, "runtime_binary_changed")
        result.append({"option": option, "exit": status, "output_bytes": log.stat().st_size,
                       "output_sha256": digest(log)})
    return result


def selected_targets(targets):
    """A local subset must be explicit; published consumers keep all nine."""
    if targets is None:
        return tuple(TARGETS)
    targets = tuple(targets)
    require(bool(targets) and len(set(targets)) == len(targets)
            and all(target in TARGETS for target in targets), "invalid_targets")
    return targets


def proxy_probe(binary, directory):
    """Load the optional network checker only after explicit native selection."""
    import proxy_runtime
    return proxy_runtime.run(binary, directory,
        environment=runtime_environment(os.environ, windows=os.name == "nt"))


def verify(artifacts, work, tag, version, runtime, profiles="proxy", *, targets=None, proxy_runtime=False):
    """Inspect the exact selected profile matrix; keep new work on any failure."""
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", tag) is not None, "invalid_tag")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", version) is not None, "invalid_version")
    artifacts, work = artifacts.absolute(), work.absolute()
    require(artifacts.is_dir() and artifacts.resolve() == artifacts and not artifacts.is_symlink(),
            "artifacts_not_real_directory")
    require(work.parent.is_dir() and work.parent.resolve() == work.parent, "work_parent_not_real")
    matrix = selected_targets(targets)
    selected = [target for target in runtime_targets(runtime, platform.system(), platform.machine())
                if target in matrix]
    capabilities = selected_profiles(profiles)
    require(runtime == "none" or bool(selected), "no_compatible_runtime_target")
    probe_target = {"linux": "x86_64-unknown-linux-musl", "windows": "x86_64-pc-windows-gnu"}.get(runtime)
    if proxy_runtime:
        require("proxy" in capabilities and probe_target in selected, "proxy_runtime_requires_native_x64_proxy")
    work.mkdir(mode=0o700)
    report = {"passed": False, "tag": tag, "version": version, "runtime_mode": runtime,
              "targets": [], "runtime": [], "upx_checked_here": False,
              "selected_targets": list(matrix), "complete_target_matrix": set(matrix) == set(TARGETS),
              "proxy_runtime_requested": proxy_runtime, "proxy_runtime": [],
              "profiles": list(capabilities),
              "scope": "Exact selected archives and matching-host CLI checks; explicit x64 proxy runtime checks use only numeric loopback. Checksums are integrity, not signatures.",
              "not_proven": ["full format, ISA/ABI or static dependency conformance",
                             "unselected platform execution",
                             "TLS/authentication, HTTP/2, UDP/MASQUE, load or long-running behavior"
                             if proxy_runtime else "proxy or network behavior",
                             "source-to-binary provenance or reproducible builds",
                             "API behavior or served Web assets"]}
    try:
        expected = {f"vproxy-{tag}{PROFILES[profile]}-{target}.tar.gz{suffix}"
                    for target in matrix for profile in capabilities for suffix in ("", ".sha256")}
        require({path.name for path in artifacts.iterdir()} == expected, "artifact_inventory_mismatch")
        binaries = {}
        for target, profile in product(matrix, capabilities):
            header = TARGETS[target]
            archive = artifacts / f"vproxy-{tag}{PROFILES[profile]}-{target}.tar.gz"
            checksum = archive.with_name(archive.name + ".sha256")
            info = regular(archive, MAX_ARCHIVE)
            regular(checksum, 512)
            archive_sha = digest(archive)
            require(checksum.read_bytes() == (archive_sha + "  " + archive.name + "\n").encode("ascii"),
                    "archive_checksum_mismatch")
            name = "vproxy.exe" if "windows" in target else "vproxy"
            binary = unpack(archive, work / (target + PROFILES[profile]), name, profile)
            binaries[(profile, target)] = binary
            report["targets"].append({"profile": profile, "target": target, "archive_sha256": archive_sha,
                "archive_bytes": info.st_size, "binary_sha256": digest(binary),
                "tar_mode": "0755", "header": binary_header(binary, header)})
        for target, profile in product(selected, capabilities):
            binary = binaries[(profile, target)]
            report["runtime"].append({"profile": profile, "target": target,
                "commands": smoke(binary, version, binary.parent, profile)})
        if proxy_runtime:
            binary = binaries[("proxy", probe_target)]
            before = digest(binary)
            result = proxy_probe(binary, binary.parent / "proxy-runtime")
            report["proxy_runtime"].append({"target": probe_target, "profile": "proxy",
                "binary_sha256": before, "checks": result})
            require(isinstance(result, dict) and result.get("passed") is True, "proxy_runtime_failed")
            require(digest(binary) == before, "proxy_runtime_binary_changed")
        report["passed"] = True
    except Exception as error:
        report["failure"] = {"kind": type(error).__name__,
                             "code": str(error) if isinstance(error, CheckError) else "check_failed"}
    with (work / "report.json").open("x", encoding="utf-8", newline="\n") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--runtime", choices=("none", "linux", "windows", "macos"), required=True)
    parser.add_argument("--profiles", choices=(*PROFILES, "all"), default="proxy")
    parser.add_argument("--targets", choices=tuple(TARGETS), nargs="+",
                        help="Explicit local subset; omitted means the complete nine-target inventory")
    parser.add_argument("--proxy-runtime", action="store_true",
                        help="Run anonymous loopback proxy/exit checks on the native Linux/Windows x64 payload")
    args = parser.parse_args()
    try:
        report = verify(args.artifacts, args.work_dir, args.tag, args.version, args.runtime, args.profiles,
                        targets=args.targets, proxy_runtime=args.proxy_runtime)
    except (CheckError, OSError) as error:
        print("Cross artifact check could not start: " + type(error).__name__)
        return 1
    print(json.dumps({"passed": report["passed"], "targets": len(report["targets"]),
                      "runtime_targets": len(report["runtime"]),
                      "report": str(args.work_dir / "report.json")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
