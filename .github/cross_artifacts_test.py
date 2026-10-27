"""Offline artifact checks: synthetic headers are never executed as binaries."""

import gzip
import hashlib
import importlib.util
import io
from itertools import product
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("cross_artifacts", Path(__file__).with_name("cross_artifacts.py"))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
TAG = "test-1.2.3"
VERSION = "2.5.5"


def header(target):
    kind, bits, machine = CHECK.TARGETS[target]
    result = bytearray(256)
    if kind == "pe":
        result[:2] = b"MZ"
        struct.pack_into("<I", result, 0x3C, 128)
        result[128:132] = b"PE\x00\x00"
        struct.pack_into("<H", result, 132, machine)
        struct.pack_into("<H", result, 152, 0x20B if bits == 64 else 0x10B)
    elif kind == "macho":
        result[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", result, 4, machine)
        struct.pack_into("<I", result, 12, 2)
    else:
        result[:4] = b"\x7fELF"
        result[4:6] = bytes((2 if bits == 64 else 1, 1))
        struct.pack_into("<H", result, 16, 2)
        struct.pack_into("<H", result, 18, machine)
    return bytes(result)


def archive(path, content=b"fixture", *, name="vproxy", mode=0o755, kind=tarfile.REGTYPE,
            extra=False, pax=None, documents=(), archive_format=tarfile.USTAR_FORMAT):
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT if pax else archive_format) as output:
        member = tarfile.TarInfo(name)
        member.mode = mode
        member.type = kind
        member.linkname = "outside" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
        member.pax_headers = pax or {}
        member.size = len(content) if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
        output.addfile(member, io.BytesIO(content) if member.size else None)
        for doc_name, doc_bytes, doc_mode, doc_kind in documents:
            member = tarfile.TarInfo(doc_name)
            member.mode, member.type = doc_mode, doc_kind
            member.linkname = "outside" if doc_kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
            member.size = len(doc_bytes) if doc_kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
            output.addfile(member, io.BytesIO(doc_bytes) if member.size else None)
        if extra:
            member = tarfile.TarInfo("second")
            output.addfile(member)


def documents(profile):
    names = [] if profile == "proxy" else ["LICENSE", "README.md"]
    if profile == "web":
        names.append("LICENSE.ant-design-pro")
    source = Path(__file__).resolve().parent.parent
    return [(name, (source / ("web/" + name if name == "LICENSE.ant-design-pro" else name)).read_bytes(),
             0o644, tarfile.REGTYPE) for name in names]


def packages(root, profiles="proxy", targets=None):
    result = root / "artifacts"
    result.mkdir()
    for target, profile in product(CHECK.selected_targets(targets), CHECK.selected_profiles(profiles)):
        path = result / f"vproxy-{TAG}{CHECK.PROFILES[profile]}-{target}.tar.gz"
        archive(path, header(target), name="vproxy.exe" if "windows" in target else "vproxy",
                documents=documents(profile))
        path.with_name(path.name + ".sha256").write_bytes(
            (hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n").encode("ascii"))
    return result


class CrossArtifactTests(unittest.TestCase):
    def test_target_subset_is_explicit_exact_and_does_not_weaken_default_inventory(self):
        selected = ("x86_64-pc-windows-gnu", "x86_64-unknown-linux-musl")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifacts = packages(root, "all", selected)
            with mock.patch.object(CHECK, "smoke", side_effect=AssertionError("static only")), \
                    mock.patch.object(CHECK, "proxy_probe", side_effect=AssertionError("static only")):
                report = CHECK.verify(artifacts, root / "partial", TAG, VERSION, "none", "all", targets=selected)
                self.assertTrue(report["passed"], report)
                self.assertEqual(report["selected_targets"], list(selected))
                self.assertFalse(report["complete_target_matrix"])
                self.assertEqual(len(report["targets"]), 6)
                self.assertEqual(len(list(artifacts.iterdir())), 12)
                full = CHECK.verify(artifacts, root / "full", TAG, VERSION, "none", "all")
                self.assertFalse(full["passed"])
            for invalid in ((), (selected[0], selected[0]), ("unknown",)):
                with self.subTest(invalid=invalid), self.assertRaises(CHECK.CheckError):
                    CHECK.selected_targets(invalid)

    def test_proxy_runtime_requires_explicit_compatible_proxy_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifacts = packages(root)
            with mock.patch.object(CHECK.platform, "system", return_value="Linux"), \
                    mock.patch.object(CHECK.platform, "machine", return_value="x86_64"), \
                    mock.patch.object(CHECK, "smoke", side_effect=AssertionError("must not run")), \
                    mock.patch.object(CHECK, "proxy_probe", side_effect=AssertionError("must not run")):
                for index, (runtime, profiles, targets) in enumerate([
                    ("none", "proxy", None), ("linux", "api", None), ("linux", "web", None),
                    ("linux", "proxy", ("x86_64-pc-windows-gnu",)),
                ]):
                    work = root / str(index)
                    with self.subTest(runtime=runtime, profiles=profiles), self.assertRaises(CHECK.CheckError):
                        CHECK.verify(artifacts, work, TAG, VERSION, runtime, profiles,
                                     targets=targets, proxy_runtime=True)
                    self.assertFalse(work.exists())
            with mock.patch.object(CHECK.platform, "system", return_value="Darwin"), \
                    mock.patch.object(CHECK.platform, "machine", return_value="arm64"), self.assertRaises(CHECK.CheckError):
                CHECK.verify(artifacts, root / "mac", TAG, VERSION, "macos", proxy_runtime=True)

    def test_proxy_runtime_uses_only_the_checked_x64_payload_and_propagates_failures(self):
        # All payloads here have synthetic headers; execution is explicitly mocked.
        for fault in (None, "false", "exception", "mutated"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                artifacts = packages(root, "all")
                def probe(binary, directory):
                    self.assertEqual(binary.name, "vproxy.exe")
                    self.assertEqual(binary.parent.name, "x86_64-pc-windows-gnu")
                    self.assertEqual(binary.read_bytes(), header("x86_64-pc-windows-gnu"))
                    self.assertEqual(directory, binary.parent / "proxy-runtime")
                    if fault == "exception":
                        raise OSError("synthetic fixture failure")
                    if fault == "mutated":
                        binary.write_bytes(b"changed fixture")
                    return {"passed": fault != "false"}
                with mock.patch.object(CHECK.platform, "system", return_value="Windows"), \
                        mock.patch.object(CHECK.platform, "machine", return_value="AMD64"), \
                        mock.patch.object(CHECK, "smoke", return_value=[]) as smoke, \
                        mock.patch.object(CHECK, "proxy_probe", side_effect=probe) as network:
                    report = CHECK.verify(artifacts, root / "work", TAG, VERSION, "windows", "all", proxy_runtime=True)
                    self.assertEqual(report["passed"], fault is None, report)
                    self.assertEqual(smoke.call_count, 6)  # Three profiles, x64 and retained i686 help.
                    network.assert_called_once()
                if fault is None:
                    self.assertEqual(len(report["proxy_runtime"]), 1)
                    self.assertTrue(report["complete_target_matrix"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            targets = ("x86_64-pc-windows-gnu",)
            with mock.patch.object(CHECK.platform, "system", return_value="Windows"), \
                    mock.patch.object(CHECK.platform, "machine", return_value="AMD64"), \
                    mock.patch.object(CHECK, "smoke", return_value=[]) as smoke, \
                    mock.patch.object(CHECK, "proxy_probe", return_value={"passed": True}) as network:
                report = CHECK.verify(packages(root, targets=targets), root / "work", TAG, VERSION,
                                      "windows", targets=targets, proxy_runtime=True)
                self.assertTrue(report["passed"], report)
                self.assertEqual(smoke.call_count, 1)
                network.assert_called_once()

    def test_explicit_profiles_require_the_complete_exact_matrix_and_matching_documents(self):
        for profiles, count in (("api", 9), ("web", 9), ("all", 27)):
            with self.subTest(profiles=profiles), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                artifacts = packages(root, profiles)
                with mock.patch.object(CHECK, "smoke", side_effect=AssertionError("No runtime selected")):
                    report = CHECK.verify(artifacts, root / "work", TAG, VERSION, "none", profiles)
                self.assertTrue(report["passed"], report)
                self.assertEqual(len(report["targets"]), count)
                self.assertEqual(len({(item["profile"], item["target"]) for item in report["targets"]}), count)
                self.assertEqual(len(list(artifacts.iterdir())), 2 * count)
                # A default invocation must not silently accept richer packages.
                mismatch = CHECK.verify(artifacts, root / "wrong", TAG, VERSION, "none")
                self.assertFalse(mismatch["passed"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            report = CHECK.verify(packages(root), root / "work", TAG, VERSION, "none", "all")
            self.assertFalse(report["passed"])
            with self.assertRaises(CHECK.CheckError):
                CHECK.selected_profiles("api,web")

    def test_management_documents_are_required_exact_safe_members_not_generic_extraction(self):
        for profile in ("api", "web"):
            for fault in ("missing", "extra", "wrong-content", "mode", "link", "extension", "slash", "order", "gnu"):
                with self.subTest(profile=profile, fault=fault), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    entries = documents(profile)
                    if fault == "missing":
                        entries.pop()
                    elif fault == "extra":
                        entries.append(("unexpected", b"extra", 0o644, tarfile.REGTYPE))
                    elif fault == "order":
                        entries.reverse()
                    else:
                        name, content, mode, kind = entries[-1]
                        if fault == "wrong-content":
                            content = b"Substituted document\n"
                        elif fault == "mode":
                            mode = 0o666
                        elif fault == "link":
                            kind = tarfile.SYMTYPE
                        elif fault == "slash":
                            name, kind = name + "/", tarfile.AREGTYPE
                        elif fault == "extension":
                            kind = tarfile.XHDTYPE
                        entries[-1] = (name, content, mode, kind)
                    path = root / "archive.tar.gz"
                    archive(path, documents=entries,
                            archive_format=tarfile.GNU_FORMAT if fault == "gnu" else tarfile.USTAR_FORMAT)
                    with self.assertRaises(CHECK.CheckError):
                        CHECK.unpack(path, root / "work", "vproxy", profile)
                    self.assertFalse((root / "work/vproxy").exists())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "archive.tar.gz"
            entries = [(name, content.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"), mode, kind)
                       for name, content, mode, kind in documents("web")]
            archive(path, documents=entries)
            self.assertEqual(CHECK.unpack(path, root / "work", "vproxy", "web").read_bytes(), b"fixture")

    def test_help_checks_reject_mislabeled_api_and_web_without_running_services(self):
        root_help = "Usage: vproxy\nCommands:\n  manage  Manage\n"
        for profile in ("api", "web"):
            CHECK.validate_output("--help", root_help, VERSION, profile)
            text = ("Print the project license and embedded Web template notice\n" if profile == "web"
                    else "Print the project license\n") + "Usage: vproxy self notices\n"
            CHECK.validate_output("notices-help", text, VERSION, profile)
            CHECK.validate_output("serve-help", "Usage: vproxy manage serve [OPTIONS]\n", VERSION, profile)
            other = "web" if profile == "api" else "api"
            with self.assertRaisesRegex(CHECK.CheckError, "runtime_web_capability_mismatch"):
                CHECK.validate_output("notices-help", text, VERSION, other)
        with self.assertRaises(CHECK.CheckError):
            CHECK.validate_output("--help", root_help, VERSION)
        for profile in ("proxy", "api", "web"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                binary = root / "vproxy"
                binary.write_bytes(header("x86_64-unknown-linux-musl"))
                calls = []

                def command(arguments, directory, log):
                    args = arguments[1:]
                    calls.append(args)
                    if args == ["--version"]:
                        text = "vproxy " + VERSION + "\n"
                    elif args == ["--help"]:
                        text = root_help if profile != "proxy" else "Usage: vproxy\nCommands:\n"
                    elif args == ["self", "notices", "--help"]:
                        text = ("embedded Web template notice\n" if profile == "web" else "") + "Usage: vproxy self notices\n"
                    else:
                        self.assertEqual(args, ["manage", "serve", "--help"])
                        text = "Usage: vproxy manage serve [OPTIONS]\n"
                    log.write_text(text, encoding="utf-8")
                    return 0

                with mock.patch.object(CHECK, "bounded_command", side_effect=command):
                    CHECK.smoke(binary, VERSION, root, profile)
                self.assertEqual(len(calls), 3 if profile == "proxy" else 4)
                self.assertTrue(all(args == ["--version"] or args[-1] == "--help" for args in calls))

    def test_nested_help_accepts_native_executable_suffix_only(self):
        for executable in ("vproxy", "vproxy.exe"):
            for profile in ("proxy", "api", "web"):
                notice = "embedded Web template notice\r\n" if profile == "web" else ""
                CHECK.validate_output("notices-help", notice + f"Usage: {executable} self notices\r\n",
                                      VERSION, profile)
                if profile != "proxy":
                    CHECK.validate_output("serve-help", f"Usage: {executable} manage serve [OPTIONS]\r\n",
                                          VERSION, profile)
        for executable in ("vproxy2", "vproxyXexe", "vproxy.exe.extra"):
            for option, command in (("notices-help", "self notices"), ("serve-help", "manage serve")):
                with self.subTest(executable=executable, option=option), self.assertRaises(CHECK.CheckError):
                    CHECK.validate_output(option, f"Usage: {executable} {command}\n", VERSION)
        for option, command in (("notices-help", "self notices-extra"),
                                ("serve-help", "manage serve-extra")):
            with self.subTest(option=option), self.assertRaises(CHECK.CheckError):
                CHECK.validate_output(option, f"Usage: vproxy.exe {command}\n", VERSION)

    def test_new_profiles_reject_high_mode_bits_in_original_tar_headers(self):
        for profile in ("api", "web"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                path = root / "archive.tar.gz"
                archive(path, documents=documents(profile))
                raw = bytearray(gzip.decompress(path.read_bytes()))
                # TarInfo.tobuf masks these bits, so construct the original
                # wire header and its checksum rather than a normalized fixture.
                raw[100:108] = b"0100755\0"
                raw[148:156] = b" " * 8
                raw[148:156] = (f"{sum(raw[:512]):06o}\0 ").encode("ascii")
                self.assertEqual(tarfile.TarInfo.frombuf(raw[:512], "utf-8", "strict").mode, 0o100755)
                path.write_bytes(gzip.compress(raw))
                with self.assertRaisesRegex(CHECK.CheckError, "tar_mode_mismatch"):
                    CHECK.unpack(path, root / "work", "vproxy", profile)

    def test_exact_nine_static_packages_succeed_without_execution_or_input_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifacts = packages(root)
            before = {path.name: path.read_bytes() for path in artifacts.iterdir()}
            with mock.patch.object(CHECK, "smoke", side_effect=AssertionError("No runtime selected")):
                report = CHECK.verify(artifacts, root / "work", TAG, VERSION, "none")
            self.assertTrue(report["passed"], report)
            self.assertEqual(len(report["targets"]), 9)
            self.assertEqual(report["runtime"], [])
            self.assertEqual(json.loads((root / "work/report.json").read_text()), report)
            self.assertEqual({path.name: path.read_bytes() for path in artifacts.iterdir()}, before)
            with self.assertRaises(FileExistsError):
                CHECK.verify(artifacts, root / "work", TAG, VERSION, "none")

    def test_inventory_checksums_and_nonregular_inputs_fail_closed(self):
        for fault in ("missing", "extra", "digest", "checksum-format", "directory"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                artifacts = packages(root)
                path = next(artifacts.glob("*.sha256"))
                if fault == "missing":
                    path.unlink()
                elif fault == "extra":
                    (artifacts / "extra").write_bytes(b"unexpected")
                elif fault == "directory":
                    path.unlink()
                    path.mkdir()
                else:
                    text = path.read_bytes()
                    path.write_bytes(b"0" * 64 + text[64:] if fault == "digest" else text.replace(b"  ", b" "))
                report = CHECK.verify(artifacts, root / "work", TAG, VERSION, "none")
                self.assertFalse(report["passed"])
                self.assertIn("failure", report)

    def test_tar_rejects_wrong_members_types_and_original_permissions(self):
        faults = ({"name": "../vproxy"}, {"name": "/vproxy"}, {"name": "nested/vproxy"},
                  {"name": "vproxy/", "kind": tarfile.AREGTYPE},
                  {"extra": True}, {"kind": tarfile.DIRTYPE}, {"kind": tarfile.SYMTYPE},
                  {"kind": tarfile.LNKTYPE}, {"kind": tarfile.GNUTYPE_SPARSE},
                  {"pax": {"comment": "not part of the release format"}},
                  {"mode": 0o600}, {"mode": 0o777}, {"mode": 0o4755})
        for fault in faults:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                path = root / "archive.tar.gz"
                archive(path, **fault)
                with self.assertRaises(CHECK.CheckError):
                    CHECK.unpack(path, root / "unpacked", "vproxy")
                self.assertFalse((root / "vproxy").exists())

    def test_tar_rejects_truncation_appended_data_and_size_limits(self):
        for fault in ("truncated-gzip", "missing-end", "appended", "expanded", "binary"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                path = root / "archive.tar.gz"
                archive(path)
                if fault == "truncated-gzip":
                    path.write_bytes(path.read_bytes()[:-8])
                elif fault in ("missing-end", "appended"):
                    raw = gzip.decompress(path.read_bytes())
                    raw = raw[:1024] if fault == "missing-end" else raw + b"x" * 512
                    path.write_bytes(gzip.compress(raw))
                setting = "MAX_EXPANDED" if fault == "expanded" else "MAX_BINARY"
                limit = 512 if fault == "expanded" else (1 if fault == "binary" else CHECK.MAX_BINARY)
                with mock.patch.object(CHECK, setting, limit), self.assertRaises(CHECK.CheckError):
                    CHECK.unpack(path, root / "unpacked", "vproxy")

    def test_basic_binary_headers_reject_wrong_machine_class_endianness_and_offsets(self):
        cases = [("x86_64-pc-windows-gnu", 0, b"NO"),
                 ("x86_64-pc-windows-gnu", 0x3C, struct.pack("<I", 0xFFFFFFFF)),
                 ("i686-pc-windows-gnu", 132, struct.pack("<H", 0x8664)),
                 ("i686-pc-windows-gnu", 152, struct.pack("<H", 0x20B)),
                 ("x86_64-apple-darwin", 0, b"\xca\xfe\xba\xbe"),
                 ("aarch64-apple-darwin", 4, struct.pack("<I", 0x01000007)),
                 ("x86_64-unknown-linux-musl", 4, b"\x01"),
                 ("armv7-unknown-linux-musleabihf", 5, b"\x02"),
                 ("i686-unknown-linux-musl", 18, struct.pack("<H", 62)),
                 ("arm-unknown-linux-musleabihf", 16, struct.pack("<H", 1))]
        for target, offset, replacement in cases:
            with self.subTest(target=target, offset=offset), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "binary"
                data = bytearray(header(target))
                data[offset:offset + len(replacement)] = replacement
                path.write_bytes(data)
                with self.assertRaises(CHECK.CheckError):
                    CHECK.binary_header(path, CHECK.TARGETS[target])

    def test_host_selection_is_explicit_and_never_selects_foreign_execution(self):
        self.assertEqual(CHECK.runtime_targets("none", "Other", "other"), [])
        self.assertEqual(CHECK.runtime_targets("linux", "Linux", "x86_64"), ["x86_64-unknown-linux-musl"])
        self.assertEqual(CHECK.runtime_targets("windows", "Windows", "AMD64"),
                         ["x86_64-pc-windows-gnu", "i686-pc-windows-gnu"])
        self.assertEqual(CHECK.runtime_targets("macos", "Darwin", "arm64"), ["aarch64-apple-darwin"])
        self.assertEqual(CHECK.runtime_targets("macos", "Darwin", "x86_64"), ["x86_64-apple-darwin"])
        for mode, system, machine in (("linux", "Linux", "aarch64"), ("windows", "Windows", "ARM64"),
                                     ("windows", "Windows", "x86"), ("macos", "Linux", "x86_64"),
                                     ("linux", "Windows", "AMD64"), ("other", "Linux", "x86_64")):
            with self.subTest(mode=mode, system=system, machine=machine), self.assertRaises(CHECK.CheckError):
                CHECK.runtime_targets(mode, system, machine)

    def test_verification_calls_only_selected_host_smoke(self):
        for mode, system, machine, expected in (
                ("linux", "Linux", "x86_64", ["x86_64-unknown-linux-musl"]),
                ("windows", "Windows", "AMD64", ["x86_64-pc-windows-gnu", "i686-pc-windows-gnu"]),
                ("macos", "Darwin", "arm64", ["aarch64-apple-darwin"])):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                artifacts = packages(root)
                with mock.patch.object(CHECK.platform, "system", return_value=system), \
                        mock.patch.object(CHECK.platform, "machine", return_value=machine), \
                        mock.patch.object(CHECK, "smoke", return_value=[{"synthetic": True}]) as smoke:
                    report = CHECK.verify(artifacts, root / "work", TAG, VERSION, mode)
                self.assertTrue(report["passed"], report)
                self.assertEqual([call.args[0].parent.name for call in smoke.call_args_list], expected)
                self.assertEqual([item["target"] for item in report["runtime"]], expected)

    def test_proxy_smoke_output_requires_exact_version_and_no_manage_command(self):
        CHECK.validate_output("--version", "vproxy 2.5.5\n", VERSION)
        CHECK.validate_output("--help", "Usage: vproxy [OPTIONS]\nCommands:\n  update  Update\n", VERSION)
        for option, text in (("--version", "vproxy 0.0.0\n"), ("--version", ""),
                             ("--help", "Usage: another\nCommands:\n"),
                             ("--help", "Usage: vproxy\nCommands:\n  manage  Manage\n")):
            with self.subTest(option=option, text=text), self.assertRaises(CHECK.CheckError):
                CHECK.validate_output(option, text, VERSION)

    def test_bounded_runner_preserves_small_output_and_does_not_limit_internal_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            log = root / "output.log"
            code = "import os,tempfile; f=tempfile.TemporaryFile(); os.ftruncate(f.fileno(),262144); print('small output')"
            status = CHECK.bounded_command([sys.executable, "-c", code], root, log)
            self.assertEqual(status, 0)
            self.assertEqual(log.read_bytes().splitlines(), [b"small output"])

    def test_runtime_environment_uses_only_fixed_system_search_directories(self):
        inherited = {"PATH": ".;C:\\bin;untrusted", "HTTP_PROXY": "not inherited",
                     "SystemRoot": "C:\\Windows", "WINDIR": "D:\\Other"}
        with mock.patch.object(CHECK.os, "pathsep", ";"):
            environment = CHECK.runtime_environment(inherited, windows=True)
            self.assertEqual(environment, {"LANG": "C", "LC_ALL": "C",
                "SystemRoot": "C:\\Windows", "WINDIR": "C:\\Windows",
                "PATH": "C:\\Windows\\System32;C:\\Windows"})
            self.assertEqual(CHECK.runtime_environment({"WINDIR": "D:\\Windows"}, windows=True)["PATH"],
                             "D:\\Windows\\System32;D:\\Windows")
            for root in (None, "", ".", "Windows", "C:Windows", "\\Windows",
                         "C:\\Windows;C:\\bin", "C:\\Windows\n", "C:\\Windows\\..\\Other"):
                with self.subTest(root=root), self.assertRaises(CHECK.CheckError):
                    CHECK.runtime_environment({} if root is None else {"SystemRoot": root}, windows=True)
        self.assertEqual(CHECK.runtime_environment(inherited, windows=False),
                         {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})

    def test_smoke_rejects_nonzero_exit_and_invalid_output_without_executing_fixture_headers(self):
        for fault, expected in (("nonzero", "runtime_exit_nonzero"),
                                ("encoding", "runtime_output_encoding")):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                binary = root / "vproxy"
                binary.write_bytes(header("x86_64-unknown-linux-musl"))

                def command(arguments, directory, log):
                    log.write_bytes(b"\xff" if fault == "encoding" else b"vproxy 2.5.5\n")
                    return 1 if fault == "nonzero" else 0

                with mock.patch.object(CHECK, "bounded_command", side_effect=command), \
                        self.assertRaisesRegex(CHECK.CheckError, expected):
                    CHECK.smoke(binary, VERSION, root)

    def test_bounded_runner_kills_and_reaps_overflow_and_closed_output_hang(self):
        cases = [("import sys; sys.stdout.buffer.write(b'x'*1048576); sys.stdout.flush()", "runtime_output_limit", 64, 5),
                 ("import os,time; os.close(1); os.close(2); time.sleep(10)", "runtime_timeout", 1024, 0.2)]
        original_popen = subprocess.Popen
        for code, expected, maximum, timeout in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                children = []

                def launch(*arguments, **keywords):
                    child = original_popen(*arguments, **keywords)
                    children.append(child)
                    return child

                log = root / "output.log"
                with mock.patch.object(CHECK.subprocess, "Popen", side_effect=launch), \
                        self.assertRaisesRegex(CHECK.CheckError, expected):
                    CHECK.bounded_command([sys.executable, "-c", code], root, log,
                                          maximum=maximum, timeout=timeout)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].returncode)
                self.assertTrue(children[0].stdout.closed)
                self.assertLessEqual(log.stat().st_size, maximum)


if __name__ == "__main__":
    unittest.main()
