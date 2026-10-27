"""Execute the cross-release Bash script with local, non-compiling tool doubles.

Run with POSIX Python 3.12+ (including WSL Ubuntu). Bash, cp, chmod,
mktemp and the filesystem are real. No Rust target is installed, no Rust output
is compiled or run, and no UPX binary is invoked. The ARM compiler is a recording
double. These are fault/packaging checks, not evidence of a successful build.
"""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("build.sh").resolve()
ADAPTER = SCRIPT.with_name("zig-cc.sh")
TARGETS = {
    "windows": ["x86_64-pc-windows-gnu", "i686-pc-windows-gnu"],
    "macos": ["x86_64-apple-darwin", "aarch64-apple-darwin"],
    "linux": [
        "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
        "armv7-unknown-linux-musleabihf", "arm-unknown-linux-musleabihf",
        "i686-unknown-linux-musl",
    ],
}
ALL_TARGETS = sum(TARGETS.values(), [])
ARM_TARGETS = ("armv7-unknown-linux-musleabihf", "arm-unknown-linux-musleabihf")
PROFILES = ("proxy", "api", "web")
DOCUMENTS = {
    "LICENSE": b"Synthetic vproxy release license\n",
    "README.md": b"Synthetic vproxy release usage\n",
    "LICENSE.ant-design-pro": b"Synthetic Ant Design Pro license\n",
}

# Each tool is a separate process. Only this driver writes its command ledger;
# Bash stays responsible for control flow, exit handling and final handoff.
DRIVER = r'''
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile

root = Path(os.environ["FAKE_ROOT"]).resolve()
tool, args = sys.argv[1], sys.argv[2:]
ledger = root / "tool-ledger.jsonl"
records = [json.loads(line) for line in ledger.read_text().splitlines()] if ledger.exists() else []
ordinal = 1 + sum(record["tool"] == tool for record in records)
with ledger.open("a", encoding="utf8") as output:
    output.write(json.dumps({"tool": tool, "args": args, "ordinal": ordinal,
                             "strip": os.environ.get("CARGO_PROFILE_RELEASE_STRIP"),
                             "cc": {key: value for key, value in os.environ.items() if key.startswith("CC_")},
                             "aws_policy": {key: value for key, value in os.environ.items() if key.startswith("AWS_LC_SYS_USE_SYSTEM")}}) + "\n")
fault_at = os.environ.get("FAKE_FAULT_AT", "1")
fault = tool == os.environ.get("FAKE_FAULT_TOOL") and (fault_at == "all" or ordinal == int(fault_at))
mode = os.environ.get("FAKE_FAULT_MODE", "exit")

def owned(value):
    path = Path(value).resolve()
    if not path.is_relative_to(root):
        raise RuntimeError("Tool double refused a path outside its fixture")
    return path

def fail():
    print("Injected fixture tool failure: " + tool, file=sys.stderr)
    sys.exit(23)

if tool == "nasm":
    if fault:
        fail()
    if args != ["-v"]:
        raise RuntimeError("Unexpected NASM double arguments")
    print("NASM version 2.16.01")
elif tool == "compiler":
    sys.exit(int(os.environ.get("FAKE_COMPILER_EXIT", "0")))
elif tool == "stat":
    if fault:
        fail()
    if args[:3] != ["-c", "%d", "--"] or len(args) != 4:
        raise RuntimeError("Unexpected stat double arguments")
    print(owned(args[-1]).stat().st_dev)
elif tool == "rustup":
    if fault:
        fail()
    if args == ["target", "list", "--installed"]:
        for target in json.loads(os.environ["FAKE_TARGETS"]):
            if target != os.environ.get("FAKE_MISSING_TARGET"):
                print(target)
    elif len(args) != 3 or args[:2] != ["target", "add"]:
        raise RuntimeError("Unexpected rustup double arguments")
elif tool == "cargo":
    target = args[args.index("--target") + 1]
    features = args[args.index("--features") + 1].split(",")
    profile = "web" if "web-ui" in features else "api" if "management" in features else "proxy"
    build = owned(args[args.index("--target-dir") + 1])
    binary = build / target / "release" / ("vproxy.exe" if "windows" in target else "vproxy")
    if fault and mode == "exit":
        fail()
    if fault and mode == "missing":
        sys.exit(0)
    binary.parent.mkdir(parents=True, exist_ok=True)
    if fault and mode == "symlink":
        old = owned(os.environ["FAKE_OLD_BINARY"])
        binary.symlink_to(old)
    else:
        identity = "Synthetic binary for " + target + ("" if profile == "proxy" else " profile " + profile) + "\n"
        binary.write_bytes(b"" if fault and mode == "empty" else identity.encode())
elif tool == "upx":
    if fault:
        fail()
    binary = owned(args[-1])
    if args[0] != "-t":
        with binary.open("ab") as output:
            output.write(b"Synthetic UPX packing marker\n")
    elif not binary.read_bytes().endswith(b"Synthetic UPX packing marker\n"):
        raise RuntimeError("UPX test double received an unpacked file")
elif tool == "tar":
    if args[:1] == ["--format=ustar"]:
        args = args[1:]
    archive = owned(args[1])
    if args[0] == "-czf":
        if fault:
            archive.write_bytes(b"partial archive left for inspection\n")
            fail()
        directory_index = args.index("-C")
        directory = owned(args[directory_index + 1])
        members = args[directory_index + 2:]
        if not members:
            raise RuntimeError("Archive double requires explicit members")
        with tarfile.open(archive, "x:gz", format=tarfile.USTAR_FORMAT) as output:
            for member in members:
                source = owned(directory / member)
                output.add(source, arcname=source.name, recursive=False)
    elif args[0] == "-tzf":
        if fault:
            fail()
        with tarfile.open(archive, "r:gz") as source:
            for member in source:
                print(member.name)
    else:
        raise RuntimeError("Unexpected tar double arguments")
elif tool == "shasum":
    if fault:
        if "-c" not in args:
            print("partial checksum left for inspection")
        fail()
    if args[:2] != ["-a", "256"]:
        raise RuntimeError("Unexpected checksum double arguments")
    if "-c" in args:
        manifest = owned(args[-1])
        digest, name = manifest.read_text(encoding="ascii").strip().split("  ", 1)
        if hashlib.sha256(owned(name).read_bytes()).hexdigest() != digest:
            fail()
        if os.environ.get("FAKE_LATE_BIN") == str(ordinal):
            destination = root / "bin"
            destination.mkdir()
            (destination / "operator-material").write_bytes(b"Late operator material; preserve exactly\n")
    else:
        archive = owned(args[-1])
        print(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name)
elif tool == "mv":
    if fault and mode == "exit":
        fail()
    if fault and mode == "no-handoff":
        sys.exit(0)
    source, destination = owned(args[-2]), owned(args[-1])
    if destination.exists() or destination.is_symlink():
        sys.exit(0)
    source.rename(destination)
    if fault and mode == "after-rename":
        fail()
else:
    raise RuntimeError("Unexpected fixture tool")
'''


def snapshot(path):
    """Inspect fixture leaves without following any pre-existing symlink."""
    if path.is_symlink():
        return ("symlink", os.readlink(path))
    if path.is_file():
        return ("file", path.read_bytes())
    if path.is_dir():
        return ("directory", {child.name: snapshot(child) for child in sorted(path.iterdir())})
    return None


class CrossReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Do not silently skip every test or mistake Windows' WSL launcher for
        # a native POSIX shell. CI/WSL must provide the real execution boundary.
        if os.name != "posix" or shutil.which("bash") is None:
            raise RuntimeError("Run these Bash fault checks with POSIX Python, for example WSL Ubuntu")

    def fixture(self, temporary):
        root = Path(temporary) / "source with spaces"
        root.mkdir()
        (root / "Cargo.toml").write_text('[package]\nname="vproxy"\nversion="0.0.1"\n')
        (root / "Cargo.lock").write_text("version = 4\n")
        for document in ("LICENSE", "README.md"):
            (root / document).write_bytes(DOCUMENTS[document])
        (root / "web/dist").mkdir(parents=True)
        (root / "web/LICENSE.ant-design-pro").write_bytes(DOCUMENTS["LICENSE.ant-design-pro"])
        (root / "web/dist/vproxy-web.json").write_bytes(b'{"fixture_only":true}\n')
        (root / "web/dist/index.html").write_bytes(b"<!doctype html><title>Fixture only</title>\n")
        copied = root / ".github/build.sh"
        copied.parent.mkdir()
        shutil.copyfile(SCRIPT, copied)
        shutil.copyfile(ADAPTER, copied.with_name(ADAPTER.name))
        # Never normalize line endings: the exact checkout bytes must execute.
        self.assertEqual(copied.read_bytes(), SCRIPT.read_bytes())
        self.assertEqual(copied.with_name(ADAPTER.name).read_bytes(), ADAPTER.read_bytes())
        tools = root / "tool doubles"
        tools.mkdir()
        driver = tools / "driver.py"
        driver.write_text(DRIVER, encoding="utf8")
        for tool in ("rustup", "cargo", "upx", "tar", "shasum", "mv", "stat", "nasm"):
            launcher = tools / tool
            launcher.write_text("#!/usr/bin/env bash\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(driver)) + " " + shlex.quote(tool) + ' "$@"\n')
            launcher.chmod(0o700)
        compiler = tools / "compiler with spaces"
        compiler.write_text("#!/usr/bin/env bash\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(driver)) + ' compiler "$@"\n')
        compiler.chmod(0o700)
        return root

    def invoke(self, root, mode="all", **changes):
        environment = {
            "PATH": str(root / "tool doubles") + os.pathsep + os.defpath,
            "LC_ALL": "C.UTF-8", "root": str(root), "os": mode,
            "tag": "v1.2.3-test", "name": "vproxy", "FAKE_ROOT": str(root),
            "FAKE_TARGETS": json.dumps(ALL_TARGETS),
        }
        environment.update(changes)
        result = subprocess.run([shutil.which("bash"), str(root / ".github/build.sh")], cwd=root, env=environment,
                                text=True, encoding="utf8", errors="strict", capture_output=True, timeout=30)
        self.assertLess(len(result.stdout) + len(result.stderr), 64 * 1024)
        ledger = root / "tool-ledger.jsonl"
        records = [json.loads(line) for line in ledger.read_text().splitlines()] if ledger.exists() else []
        return result, records

    def assert_failed_private(self, root, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((root / "bin").exists())
        self.assertFalse((root / "bin").is_symlink())
        stages = list((root / "target").glob("cross-release.*"))
        self.assertEqual(len(stages), 1, "Failed private work must remain available")
        self.assertTrue((stages[0] / "artifacts").is_dir())

    def assert_complete(self, root, targets, tag="v1.2.3-test", profiles=("proxy",)):
        expected = {f"vproxy-{tag}{'' if profile == 'proxy' else '-' + profile}-{target}.tar.gz{suffix}"
                    for target in targets for profile in profiles for suffix in ("", ".sha256")}
        self.assertEqual({path.name for path in (root / "bin").iterdir()}, expected)
        for target in targets:
            for profile in profiles:
                binary = "vproxy.exe" if "windows" in target else "vproxy"
                suffix = "" if profile == "proxy" else "-" + profile
                archive = root / "bin" / f"vproxy-{tag}{suffix}-{target}.tar.gz"
                expected_members = [binary]
                if profile != "proxy":
                    expected_members += ["LICENSE", "README.md"]
                if profile == "web":
                    expected_members += ["LICENSE.ant-design-pro"]
                with tarfile.open(archive, "r:gz") as payload:
                    members = payload.getmembers()
                    self.assertEqual([member.name for member in members], expected_members)
                    self.assertTrue(all(member.isfile() for member in members))
                    self.assertEqual(members[0].mode & 0o777, 0o755)
                    actual = payload.extractfile(members[0]).read()
                    expected_binary = ("Synthetic binary for " + target + ("" if profile == "proxy" else " profile " + profile) + "\n").encode()
                    self.assertEqual(actual, expected_binary, "A profile must never package another profile's build output")
                    for member in members[1:]:
                        self.assertEqual(member.mode & 0o777, 0o644)
                        self.assertEqual(payload.extractfile(member).read(), DOCUMENTS[member.name])
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                self.assertEqual(archive.with_name(archive.name + ".sha256").read_text(), digest + "  " + archive.name + "\n")

    def test_success_parameters_artifact_names_and_all_nine_target_handoff(self):
        for mode, targets in {**TARGETS, "all": ALL_TARGETS}.items():
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="vproxy-cross-check-") as temporary:
                root = self.fixture(temporary)
                result, records = self.invoke(root, mode, FAKE_MISSING_TARGET=targets[-1])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_complete(root, targets)
                builds = [record for record in records if record["tool"] == "cargo"]
                self.assertEqual(len(builds), len(targets))
                directories = set()
                for record, target in zip(builds, targets, strict=True):
                    self.assertEqual(record["aws_policy"]["AWS_LC_SYS_USE_SYSTEM"], "0")
                    self.assertEqual(record["aws_policy"]["AWS_LC_SYS_USE_SYSTEM_" + target.replace("-", "_")], "0")
                    arguments = record["args"]
                    self.assertEqual(arguments[0], "build" if "windows" in target else "zigbuild")
                    for flag in ("--release", "--locked", "--no-default-features"):
                        self.assertIn(flag, arguments)
                    self.assertEqual(arguments[arguments.index("--bin") + 1], "vproxy")
                    self.assertEqual(arguments[arguments.index("--target") + 1], target)
                    self.assertEqual(arguments[arguments.index("--manifest-path") + 1], str(root / "Cargo.toml"))
                    features = arguments[arguments.index("--features") + 1]
                    expected_features = "userspace"
                    if "linux" in target:
                        expected_features += ",mimalloc" if target.startswith(("x86_64-", "aarch64-")) else ",jemalloc"
                    self.assertEqual(features, expected_features)
                    directory = Path(arguments[arguments.index("--target-dir") + 1])
                    self.assertEqual(directory.parent.parent, root / "target")
                    self.assertTrue(directory.parent.name.startswith("cross-release."))
                    directories.add(directory)
                    self.assertEqual(record["strip"], "none" if "apple-darwin" in target else None)
                    if target in ARM_TARGETS:
                        adapter = Path(record["cc"]["CC_" + target.replace("-", "_")])
                        self.assertEqual(adapter.parent, directory.parent)
                        self.assertEqual(adapter.read_bytes(), ADAPTER.read_bytes())
                        self.assertEqual(adapter.stat().st_mode & 0o777, 0o755)
                        self.assertEqual(record["cc"], {"CC_" + target.replace("-", "_"): str(adapter)})
                    else:
                        self.assertEqual(record["cc"], {}, "The ARM adapter must not leak into other targets")
                self.assertEqual(len(directories), 1)
                upx = [record["args"] for record in records if record["tool"] == "upx"]
                self.assertEqual(upx, [], "Linked executable bytes must not be packed")
                moves = [record["args"] for record in records if record["tool"] == "mv"]
                self.assertEqual(len(moves), 1)
                self.assertEqual(moves[0][:3], ["-T", "--no-clobber", "--"])
                self.assertEqual(moves[0][-1], str(root / "bin"))
                self.assertEqual(records[-1]["tool"], "mv")
                self.assertIn(["target", "add", targets[-1]], [record["args"] for record in records if record["tool"] == "rustup"])

    def test_explicit_x64_subset_keeps_profile_matrix_and_build_order(self):
        selected = ["x86_64-pc-windows-gnu", "x86_64-unknown-linux-musl"]
        with tempfile.TemporaryDirectory(prefix="vproxy-cross-x64-") as temporary:
            root = self.fixture(temporary)
            result, records = self.invoke(root, targets=",".join(selected), profiles="all")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            builds = [record["args"] for record in records if record["tool"] == "cargo"]
            self.assertEqual([args[args.index("--target") + 1] for args in builds],
                             [target for target in selected for _profile in PROFILES])
            self.assert_complete(root, selected, profiles=PROFILES)

    def test_subset_uses_only_selected_tool_requirements_and_native_payload_bytes(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-cross-native-") as temporary:
            root = self.fixture(temporary)
            (root / "tool doubles/upx").unlink()
            result, records = self.invoke(root, targets="x86_64-unknown-linux-musl",
                                          profiles="all", FAKE_FAULT_TOOL="nasm")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_complete(root, ["x86_64-unknown-linux-musl"], profiles=PROFILES)
            self.assertFalse(any(record["tool"] in ("upx", "nasm") for record in records))

    def test_invalid_target_subsets_fail_before_tools_and_cannot_expand_the_matrix(self):
        known = "x86_64-unknown-linux-musl"
        for value in ("", known + "," + known, "," + known, known + ",", known + ",," + known,
                      known + "\nx86_64-pc-windows-gnu", known + "\r", "unknown-target",
                      "$(touch not-created)", "x86_64-pc-windows-gnu"):
            with self.subTest(targets=value), tempfile.TemporaryDirectory(prefix="vproxy-cross-subset-reject-") as temporary:
                root = self.fixture(temporary)
                result, records = self.invoke(root, "linux", targets=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(records, [])
                self.assertFalse((root / "target").exists())
                self.assertFalse((root / "bin").exists())
                self.assertFalse((root / "not-created").exists())

    def test_unusable_nasm_fails_before_private_stage_or_cargo(self):
        for mode in ("windows", "all"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="vproxy-cross-check-") as temporary:
                root = self.fixture(temporary)
                result, records = self.invoke(root, mode, FAKE_FAULT_TOOL="nasm")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((root / "target").exists())
                self.assertFalse((root / "bin").exists())
                self.assertEqual([record["tool"] for record in records], ["nasm"])

    def test_bundled_aws_policy_overrides_global_and_target_system_discovery(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-cross-check-") as temporary:
            root = self.fixture(temporary)
            key = "AWS_LC_SYS_USE_SYSTEM_x86_64_pc_windows_gnu"
            result, records = self.invoke(root, "windows", AWS_LC_SYS_USE_SYSTEM="1", **{key: "1"})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            builds = [record for record in records if record["tool"] == "cargo"]
            self.assertTrue(builds)
            for record in builds:
                self.assertEqual(record["aws_policy"]["AWS_LC_SYS_USE_SYSTEM"], "0")
                self.assertEqual(record["aws_policy"][key], "0")

    def test_api_web_and_all_profiles_keep_target_allocators_and_exact_package_members(self):
        for selection in ("api", "web", "all"):
            profiles = PROFILES if selection == "all" else (selection,)
            with self.subTest(profiles=selection), tempfile.TemporaryDirectory(prefix="vproxy-cross-profiles-") as temporary:
                root = self.fixture(temporary)
                result, records = self.invoke(root, profiles=selection)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_complete(root, ALL_TARGETS, profiles=profiles)
                builds = [record for record in records if record["tool"] == "cargo"]
                expected_builds = [(target, profile) for target in ALL_TARGETS for profile in profiles]
                self.assertEqual(len(builds), len(expected_builds))
                directories = set()
                for record, (target, profile) in zip(builds, expected_builds, strict=True):
                    arguments = record["args"]
                    self.assertEqual(arguments[arguments.index("--target") + 1], target)
                    expected_features = "userspace"
                    if "linux" in target:
                        expected_features += ",mimalloc" if target.startswith(("x86_64-", "aarch64-")) else ",jemalloc"
                    expected_features += ",management" if profile == "api" else ",web-ui" if profile == "web" else ""
                    self.assertEqual(arguments[arguments.index("--features") + 1], expected_features)
                    for flag in ("--release", "--locked", "--no-default-features"):
                        self.assertIn(flag, arguments)
                    directories.add(Path(arguments[arguments.index("--target-dir") + 1]))
                    self.assertEqual(record["strip"], "none" if "apple-darwin" in target else None)
                self.assertEqual(len(directories), 1, "All profiles must share the private dependency cache")
                moves = [record["args"] for record in records if record["tool"] == "mv"]
                handoffs = [arguments for arguments in moves if arguments[-1] == str(root / "bin")]
                self.assertEqual(len(handoffs), 1)
                self.assertEqual(handoffs[0][:3], ["-T", "--no-clobber", "--"])
                self.assertEqual(records[-1]["tool"], "mv")
                self.assertEqual(records[-1]["args"], handoffs[0])
                self.assertEqual(len(moves), 19 if selection == "all" else 1)
                upx = [record for record in records if record["tool"] == "upx"]
                self.assertEqual(upx, [], "All profiles must retain their native executable")
                if selection == "all":
                    self.assertEqual(len(list((root / "bin").iterdir())), 54)
                    stage = next((root / "target").glob("cross-release.*"))
                    for target in ALL_TARGETS:
                        for previous, current in (("proxy", "api"), ("api", "web")):
                            retained = stage / "previous" / f"{target}-before-{current}"
                            expected = ("Synthetic binary for " + target + ("" if previous == "proxy" else " profile " + previous) + "\n").encode()
                            self.assertEqual(retained.read_bytes(), expected, "Retained raw outputs must not be UPX-mutated")

    def test_later_profile_failures_cannot_handoff_or_reuse_previous_capability_binary(self):
        cases = [("cargo", 2, "exit"), ("cargo", 3, "missing"), ("cargo", 14, "empty"),
                 ("cargo", 27, "symlink"),
                 ("tar", 54, "exit"), ("shasum", 54, "exit")]
        for tool, ordinal, failure in cases:
            with self.subTest(tool=tool, ordinal=ordinal, failure=failure), tempfile.TemporaryDirectory(prefix="vproxy-cross-profile-fault-") as temporary:
                root = self.fixture(temporary)
                old = root / "operator-binary"
                old.write_bytes(b"Operator binary outside the current build stage\n")
                before = old.read_bytes()
                result, records = self.invoke(root, profiles="all", FAKE_FAULT_TOOL=tool,
                                              FAKE_FAULT_AT=str(ordinal), FAKE_FAULT_MODE=failure,
                                              FAKE_OLD_BINARY=str(old))
                self.assert_failed_private(root, result)
                self.assertEqual(old.read_bytes(), before)
                self.assertEqual(sum(record["tool"] == tool for record in records), ordinal)
                self.assertFalse(any(record["tool"] == "mv" and record["args"][-1] == str(root / "bin")
                                     for record in records), "Private history moves are not a completed release handoff")

    def test_profile_documents_and_web_inputs_fail_before_tools_without_breaking_proxy_only(self):
        cases = [("api", "LICENSE"), ("api", "README.md"), ("web", "web/LICENSE.ant-design-pro"),
                 ("web", "web/dist/vproxy-web.json"), ("all", "web/dist/index.html")]
        for profile, missing in cases:
            with self.subTest(profile=profile, missing=missing), tempfile.TemporaryDirectory(prefix="vproxy-cross-profile-input-") as temporary:
                root = self.fixture(temporary)
                (root / missing).unlink()
                result, records = self.invoke(root, profiles=profile)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(records, [], "Missing release inputs must fail before any recorded tool")
                self.assertFalse((root / "target").exists())
                self.assertFalse((root / "bin").exists())
        with tempfile.TemporaryDirectory(prefix="vproxy-cross-proxy-no-docs-") as temporary:
            root = self.fixture(temporary)
            for missing in ("LICENSE", "README.md", "web/LICENSE.ant-design-pro",
                            "web/dist/vproxy-web.json", "web/dist/index.html"):
                (root / missing).unlink()
            result, _records = self.invoke(root, "macos")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_complete(root, TARGETS["macos"])

    def test_real_arm_adapter_preserves_arguments_and_only_preprocesses_dependency_only_requests(self):
        cases = [(["-MM", "unit with spaces.c"], True), (["-M", "unit.c"], True),
                 (["-MM", "-M", "-MF", "deps with spaces.d", "unit.c"], True),
                 (["-E", "-MM", "unit.c"], False), (["-MM", "-E", "unit.c"], False),
                 (["-c", "unit.c", "-o", "object with spaces.o"], False),
                 (["-MD", "-c", "unit.c"], False), (["-MMD", "-c", "unit.c"], False),
                 (["-Wp,-MM", "$(touch not-created)", "-MMsuffix"], False)]
        for target in ARM_TARGETS:
            for arguments, prepend in cases:
                with self.subTest(target=target, arguments=arguments), tempfile.TemporaryDirectory(prefix="vproxy-arm-cc-") as temporary:
                    root = self.fixture(temporary)
                    adapter = root / ".github" / ADAPTER.name
                    adapter.chmod(0o700)
                    environment = {"PATH": os.defpath, "FAKE_ROOT": str(root), "TARGET": target,
                                   "CARGO_TARGET_" + target.upper().replace("-", "_") + "_LINKER": str(root / "tool doubles/compiler with spaces")}
                    result = subprocess.run([str(adapter), *arguments], cwd=root, env=environment, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    records = [json.loads(line) for line in (root / "tool-ledger.jsonl").read_text().splitlines()]
                    self.assertEqual(len(records), 1, "The adapter must not retry a compiler invocation")
                    self.assertEqual(records[0]["tool"], "compiler")
                    self.assertEqual(records[0]["args"], (["-E"] if prepend else []) + arguments)
                    self.assertFalse((root / "not-created").exists())
        with tempfile.TemporaryDirectory(prefix="vproxy-arm-cc-exit-") as temporary:
            root = self.fixture(temporary)
            adapter = root / ".github" / ADAPTER.name
            adapter.chmod(0o700)
            result = subprocess.run([str(adapter), "-MM", "unit.c"], cwd=root,
                                    env={"PATH": os.defpath, "FAKE_ROOT": str(root), "TARGET": ARM_TARGETS[0],
                                         "CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER": str(root / "tool doubles/compiler with spaces"),
                                         "FAKE_COMPILER_EXIT": "23"}, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 23)
            self.assertEqual(len((root / "tool-ledger.jsonl").read_text().splitlines()), 1)

    def test_real_arm_adapter_rejects_invalid_target_or_compiler_before_invocation(self):
        for kind in ("no-target", "bad-target", "missing-linker", "relative", "absent", "non-executable", "self", "self-alias"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="vproxy-arm-cc-reject-") as temporary:
                root = self.fixture(temporary)
                adapter = root / ".github" / ADAPTER.name
                adapter.chmod(0o700)
                linker = root / "tool doubles/compiler with spaces"
                if kind == "relative":
                    linker = linker.relative_to(root)
                elif kind == "absent":
                    linker = root / "not-a-compiler"
                elif kind == "non-executable":
                    linker.chmod(0o600)
                elif kind == "self":
                    linker = adapter
                elif kind == "self-alias":
                    linker = root / "adapter alias"
                    linker.symlink_to(adapter)
                environment = {"PATH": os.defpath, "FAKE_ROOT": str(root), "TARGET": ARM_TARGETS[0],
                               "CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER": str(linker)}
                if kind == "no-target":
                    environment.pop("TARGET")
                elif kind == "bad-target":
                    environment["TARGET"] = "x86_64-unknown-linux-musl"
                elif kind == "missing-linker":
                    environment.pop("CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER")
                result = subprocess.run([str(adapter), "-MM", "unit.c"], cwd=root, env=environment, capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "tool-ledger.jsonl").exists(), "Rejected input must not reach the compiler")

    def test_custom_arm_cc_is_preserved_and_unpaired_rust_linker_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-arm-cc-custom-") as temporary:
            root = self.fixture(temporary)
            custom = {"CC_" + (target.replace("-", "_") if index == 0 else target): str(root / ("custom compiler " + str(index)))
                      for index, target in enumerate(ARM_TARGETS)}
            changes = {**custom, **{"CARGO_TARGET_" + target.upper().replace("-", "_") + "_LINKER": str(root / "custom Rust linker")
                                    for target in ARM_TARGETS}}
            result, records = self.invoke(root, "linux", **changes)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_complete(root, TARGETS["linux"])
            self.assertTrue(all(record["cc"] == custom for record in records if record["tool"] == "cargo"))
        for target in ARM_TARGETS:
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix="vproxy-arm-linker-conflict-") as temporary:
                root = self.fixture(temporary)
                result, records = self.invoke(root, "linux", **{
                    "CARGO_TARGET_" + target.upper().replace("-", "_") + "_LINKER": str(root / "tool doubles/compiler with spaces")})
                self.assert_failed_private(root, result)
                built = [record["args"][record["args"].index("--target") + 1] for record in records if record["tool"] == "cargo"]
                self.assertEqual(built, TARGETS["linux"][:TARGETS["linux"].index(target)])
                self.assertFalse(any(record["tool"] in ("compiler", "mv") for record in records))

    def test_cargo_failure_or_absent_invalid_fresh_binary_cannot_reuse_old_target(self):
        for ordinal, failure in ((1, "exit"), (9, "exit"), (1, "missing"), (9, "missing"), (1, "empty"), (1, "symlink")):
            with self.subTest(ordinal=ordinal, failure=failure), tempfile.TemporaryDirectory(prefix="vproxy-cross-cargo-") as temporary:
                root = self.fixture(temporary)
                old = root / "target" / ALL_TARGETS[ordinal - 1] / "release" / ("vproxy.exe" if "windows" in ALL_TARGETS[ordinal - 1] else "vproxy")
                old.parent.mkdir(parents=True)
                old.write_bytes(b"Old binary must never be packaged or modified\n")
                before = old.read_bytes()
                result, records = self.invoke(root, FAKE_FAULT_TOOL="cargo", FAKE_FAULT_AT=str(ordinal),
                                              FAKE_FAULT_MODE=failure, FAKE_OLD_BINARY=str(old))
                self.assert_failed_private(root, result)
                self.assertEqual(old.read_bytes(), before)
                self.assertEqual(sum(record["tool"] == "cargo" for record in records), ordinal)
                self.assertFalse(any(record["tool"] == "mv" for record in records))

    def test_real_archive_checksum_stat_and_directory_handoff_for_all_targets_and_profiles(self):
        # The fault matrix controls these tools, but this independent success
        # case also exercises their installed CLI syntax and archive semantics.
        for tool in ("tar", "shasum", "mv", "stat"):
            self.assertIsNotNone(shutil.which(tool, path=os.defpath), "Required real tool is missing: " + tool)
        with tempfile.TemporaryDirectory(prefix="vproxy-cross-real-packaging-") as temporary:
            root = self.fixture(temporary)
            for tool in ("tar", "shasum", "mv", "stat"):
                (root / "tool doubles" / tool).unlink()
            result, records = self.invoke(root, profiles="all")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_complete(root, ALL_TARGETS, profiles=PROFILES)
            self.assertEqual({record["tool"] for record in records}, {"rustup", "cargo", "nasm"})
            self.assertEqual(sum(record["tool"] == "nasm" for record in records), 1)
            self.assertEqual(sum(record["tool"] == "cargo" for record in records), 27)
            self.assertFalse(any(record["tool"] == "upx" for record in records))
            stages = list((root / "target").glob("cross-release.*"))
            self.assertEqual(len(stages), 1)
            self.assertFalse((stages[0] / "artifacts").exists())
            for target in ALL_TARGETS:
                binary = "vproxy.exe" if "windows" in target else "vproxy"
                original = stages[0] / "build" / target / "release" / binary
                self.assertEqual(original.read_bytes(), ("Synthetic binary for " + target + " profile web\n").encode(),
                                 "Packaging must preserve the linked executable bytes")

    def test_tool_faults_and_success_without_handoff_never_publish_partial_sets(self):
        cases = [(tool, ordinal, "exit") for tool, ordinals in (
            ("tar", (1, 2, 18)), ("shasum", (1, 2, 18)), ("mv", (1,)),
        ) for ordinal in ordinals] + [("mv", 1, "no-handoff")]
        for tool, ordinal, failure in cases:
            with self.subTest(tool=tool, ordinal=ordinal, failure=failure), tempfile.TemporaryDirectory(prefix="vproxy-cross-fault-") as temporary:
                root = self.fixture(temporary)
                result, records = self.invoke(root, FAKE_FAULT_TOOL=tool, FAKE_FAULT_AT=str(ordinal), FAKE_FAULT_MODE=failure)
                self.assert_failed_private(root, result)
                self.assertEqual(sum(record["tool"] == tool for record in records), ordinal)
                # No retry of the failed command, and no handoff after a known
                # earlier failure, even after other targets were staged.
                self.assertEqual(records[-1]["tool"], tool)
                if tool != "mv":
                    self.assertFalse(any(record["tool"] == "mv" for record in records))
        for ordinal in ("1", "2", "all"):
            with self.subTest(stat_failure=ordinal), tempfile.TemporaryDirectory(prefix="vproxy-cross-stat-") as temporary:
                root = self.fixture(temporary)
                result, records = self.invoke(root, FAKE_FAULT_TOOL="stat", FAKE_FAULT_AT=ordinal)
                self.assert_failed_private(root, result)
                self.assertFalse(any(record["tool"] == "cargo" for record in records))
                self.assertEqual(sum(record["tool"] == "stat" for record in records), 2 if ordinal == "2" else 1)
                self.assertEqual(records[-1]["tool"], "stat")

    def test_existing_or_late_output_is_not_replaced_and_rename_unknown_is_not_rolled_back(self):
        for kind in ("file", "empty-directory", "directory", "dangling-symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="vproxy-cross-existing-") as temporary:
                root = self.fixture(temporary)
                output = root / "bin"
                if kind == "file":
                    output.write_bytes(b"Existing file, never overwrite\n")
                elif kind == "dangling-symlink":
                    output.symlink_to(root / "not-created")
                else:
                    output.mkdir()
                    if kind == "directory":
                        (output / "vproxy-v1.2.3-test-x86_64-pc-windows-gnu.tar.gz").write_bytes(b"Existing release, never overwrite\n")
                before = snapshot(output)
                result, records = self.invoke(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(snapshot(output), before)
                self.assertEqual(records, [])
                self.assertFalse((root / "target").exists())
        with tempfile.TemporaryDirectory(prefix="vproxy-cross-late-output-") as temporary:
            root = self.fixture(temporary)
            result, records = self.invoke(root, FAKE_LATE_BIN="18")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(snapshot(root / "bin"), ("directory", {"operator-material": ("file", b"Late operator material; preserve exactly\n")}))
            self.assertFalse(any(record["tool"] == "mv" for record in records))
            self.assertEqual(len(list((root / "target").glob("cross-release.*/artifacts"))), 1)
        with tempfile.TemporaryDirectory(prefix="vproxy-cross-rename-unknown-") as temporary:
            root = self.fixture(temporary)
            result, records = self.invoke(root, FAKE_FAULT_TOOL="mv", FAKE_FAULT_MODE="after-rename")
            self.assertNotEqual(result.returncode, 0)
            # Once rename happened, an unknown/error result must not trigger
            # destructive rollback of a complete output or be reported success.
            self.assert_complete(root, ALL_TARGETS)
            self.assertEqual(sum(record["tool"] == "mv" for record in records), 1)
            self.assertEqual(len(list((root / "target").glob("cross-release.*"))), 1)

    def test_default_tag_and_invalid_inputs_preserve_compatibility_without_shell_expansion(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-cross-default-tag-") as temporary:
            root = self.fixture(temporary)
            result, _records = self.invoke(root, "macos", tag="")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_complete(root, TARGETS["macos"], tag="latest")
        for change in ({"tag": "../escape"}, {"tag": "bad tag"}, {"tag": "$(touch not-created)"},
                       {"name": "another-binary"}, {"os": "unsupported"}, {"profiles": "api,web"},
                       {"profiles": "../api"}, {"profiles": "$(touch not-created)"}, {"profiles": "web api"}):
            with self.subTest(change=change), tempfile.TemporaryDirectory(prefix="vproxy-cross-input-") as temporary:
                root = self.fixture(temporary)
                result, records = self.invoke(root, **change)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "bin").exists())
                self.assertFalse((root / "not-created").exists())
                self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
