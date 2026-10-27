"""Standard-library checks for the release gate, never a Cargo build or server.

Archive parsing/extraction and artifact files are real in new TemporaryDirectory
leaves. Cargo/compiler/executable calls are stubbed only to test gate ordering;
these tests do not certify a native executable, dependency resolver or CLI parser.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("release_profiles.py")
SPEC = importlib.util.spec_from_file_location("release_profiles_under_test", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("release checker import unavailable")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

PREFIX = "vproxy-0.0.1"
PUBLIC_ANCHOR = "src/manage/acme/staging-roots.pem"
PUBLIC_ANCHOR_BYTES = (SCRIPT.parent.parent / PUBLIC_ANCHOR).read_bytes()
INPUTS = {
    "Cargo.toml": b'[package]\nname = "vproxy"\nversion = "0.0.1"\n',
    "Cargo.toml.orig": b'[package]\nname = "vproxy"\nversion = "0.0.1"\n',
    "Cargo.lock": b'version = 4\n\n[[package]]\nname = "vproxy"\nversion = "0.0.1"\n',
    "build.rs": b"fn main() {}\n",
    "src/main.rs": b"fn main() {}\n",
    "README.md": b"Non-secret release checker fixture.\n",
    "LICENSE": b"Fixture license text.\n",
    PUBLIC_ANCHOR: PUBLIC_ANCHOR_BYTES,
}
WEB_INPUTS = {
    "web/dist/index.html": b"fixture",
    "web/dist/vproxy-web.json": b"{}",
    "web/LICENSE.ant-design-pro": b"Public frontend template license notice.\n",
}


def member(name, size=1, kind=tarfile.REGTYPE):
    result = tarfile.TarInfo(name)
    result.size, result.type = size, kind
    if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
        result.linkname = "../../not-owned"
    return result


def crate_file(path, files):
    with tarfile.open(path, "x:gz") as archive:
        for relative, contents in files.items():
            archive.addfile(member(PREFIX + "/" + relative, len(contents)), io.BytesIO(contents))


def dependency_tree(mode):
    names = {"vproxy", "base64"} | gate.AWS_LC_PACKAGES
    if mode != "proxy":
        names |= gate.MANAGEMENT_PACKAGES
    if mode == "web":
        names |= gate.WEB_PACKAGES
    return "\n".join(f"{name} v0.0.1" for name in sorted(names)) + "\n"


class ReleaseGateTests(unittest.TestCase):
    def test_only_the_exact_pinned_public_anchor_is_allowed_before_extraction(self):
        expected_size, expected_sha256 = gate.PUBLIC_TRUST_ANCHORS[PUBLIC_ANCHOR]
        self.assertEqual(len(PUBLIC_ANCHOR_BYTES), expected_size)
        self.assertEqual(hashlib.sha256(PUBLIC_ANCHOR_BYTES).hexdigest(), expected_sha256)
        self.assertEqual(set(gate.PUBLIC_TRUST_ANCHORS), {PUBLIC_ANCHOR})
        for relative in (
            PUBLIC_ANCHOR.upper(), PUBLIC_ANCHOR.replace(".pem", ".PeM"),
            "staging-roots.pem", "src/other/staging-roots.pem",
            "src/manage/acme/extra.pem", "src/manage/acme/staging-roots.key",
        ):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                gate.package_members([member(PREFIX + "/" + relative, expected_size)], PREFIX)
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                gate.package_members([member(PREFIX + "/" + PUBLIC_ANCHOR, expected_size, kind)], PREFIX)
        for size in (-1, expected_size - 1, expected_size + 1, gate.MAX_FILE_BYTES + 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                gate.package_members([member(PREFIX + "/" + PUBLIC_ANCHOR, size)], PREFIX)
        with self.assertRaises(ValueError):
            gate.package_members([member(PREFIX + "/" + PUBLIC_ANCHOR, expected_size)] * 2, PREFIX)
        with tempfile.TemporaryDirectory(prefix="vproxy-release-public-anchor-test-") as temporary:
            root = Path(temporary)
            for label, data in (
                ("changed", bytes([PUBLIC_ANCHOR_BYTES[0] ^ 1]) + PUBLIC_ANCHOR_BYTES[1:]),
                ("crlf", PUBLIC_ANCHOR_BYTES.replace(b"\n", b"\r\n")),
                ("short", PUBLIC_ANCHOR_BYTES[:-1]),
                ("extra", PUBLIC_ANCHOR_BYTES + b"\n"),
            ):
                with self.subTest(label=label):
                    crate, destination = root / (label + ".crate"), root / (label + "-output")
                    crate_file(crate, {**INPUTS, PUBLIC_ANCHOR: data})
                    with self.assertRaisesRegex(ValueError, "pinned public trust anchor"):
                        gate.unpack(crate, destination, PREFIX, "proxy")
                    self.assertFalse(destination.exists())

    def test_package_member_names_types_and_private_material_are_rejected(self):
        for name in (
            "/" + PREFIX + "/src/main.rs", "other-0.0.1/src/main.rs",
            PREFIX + "/../outside", PREFIX + "/src/./main.rs",
            PREFIX + "/src//main.rs", PREFIX + "/src\\main.rs",
            PREFIX + "/C:/outside", PREFIX + "/src/new\nline.rs",
            PREFIX + "/src/tab\t.rs", PREFIX + "/src/delete\x7f.rs",
            PREFIX + "/src/name./main.rs", PREFIX + "/src/name /main.rs",
            PREFIX + "/src/main.rs.", PREFIX + "/src/main.rs ",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                gate.package_members([member(name)], PREFIX)
        for kind in (tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                gate.package_members([member(PREFIX + "/src/main.rs", kind=kind)], PREFIX)
        for relative in (
            ".agents/private.md", ".git/config", "web/node_modules/a/index.js",
            "target/release/vproxy", "web/src/.umi/routes.ts", "web/src/.umi-production/routes.ts",
            "fixture.KEY", "fixture.PeM", "fixture.p12", "fixture.pfx", "management.sqlite3",
        ):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                gate.package_members([member(PREFIX + "/" + relative)], PREFIX)
        for component in (
            "CON", "prn.txt", "Aux", "nul.rs", "COM1", "COM9.txt", "LPT1", "lpt9.txt",
            "COM¹.rs", "LPT²", "com³.txt", "name<.rs", "name>.rs", 'name".rs',
            "name|.rs", "name?.rs", "name*.rs",
        ):
            for relative in ("src/" + component, component + "/main.rs"):
                with self.subTest(relative=relative), self.assertRaises(ValueError):
                    gate.package_members([member(PREFIX + "/" + relative)], PREFIX)
        for component in ("COM0.rs", "LPT10.txt", "console.rs", "name..rs"):
            accepted = [member(PREFIX + "/src/" + component)]
            with self.subTest(allowed_component=component):
                self.assertEqual(gate.package_members(accepted, PREFIX), accepted)

    def test_inventory_bounds_and_case_insensitive_duplicates_are_not_extracted(self):
        for entries in (
            [member(PREFIX + "/src/main.rs"), member(PREFIX + "/src/main.rs")],
            [member(PREFIX + "/src/Main.rs"), member(PREFIX + "/src/main.rs")],
            [member(PREFIX + "/src/main.rs", -1)],
            [member(PREFIX + "/src/main.rs", gate.MAX_FILE_BYTES + 1)],
        ):
            with self.subTest(entries=[item.name for item in entries]), self.assertRaises(ValueError):
                gate.package_members(entries, PREFIX)
        accepted = [member(PREFIX + "/src/main.rs", 0), member(PREFIX + "/LICENSE", 2)]
        self.assertEqual(gate.package_members(accepted, PREFIX), accepted)
        with patch.object(gate, "MAX_FILES", 1), self.assertRaises(ValueError):
            gate.package_members(accepted, PREFIX)
        with patch.object(gate, "MAX_TOTAL_BYTES", 1), self.assertRaises(ValueError):
            gate.package_members(accepted, PREFIX)

    def test_unpack_validates_complete_package_before_any_extraction(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-release-check-test-") as temporary:
            root = Path(temporary)
            cases = [
                ("missing-license", {k: v for k, v in INPUTS.items() if k != "LICENSE"}, "proxy"),
                ("no-manifest", {**INPUTS, **{k: v for k, v in WEB_INPUTS.items() if k != "web/dist/vproxy-web.json"}}, "web"),
                ("no-index", {**INPUTS, **{k: v for k, v in WEB_INPUTS.items() if k != "web/dist/index.html"}}, "web"),
                ("no-web-notice", {**INPUTS, **{k: v for k, v in WEB_INPUTS.items() if k != "web/LICENSE.ant-design-pro"}}, "web"),
                ("unexpected-api-dist", {**INPUTS, "web/dist/asset.js": b"fixture"}, "api"),
                ("unexpected-proxy-dist", {**INPUTS, "web/dist/asset.js": b"fixture"}, "proxy"),
                ("private-member", {**INPUTS, ".agents/notes.md": b"not extracted"}, "proxy"),
            ]
            for label, files, mode in cases:
                with self.subTest(label=label):
                    crate = root / (label + ".crate")
                    destination = root / (label + "-output")
                    crate_file(crate, files)
                    with self.assertRaises(ValueError):
                        gate.unpack(crate, destination, PREFIX, mode)
                    self.assertFalse(destination.exists())
            for mode in gate.FEATURES:
                files = dict(INPUTS)
                if mode == "web":
                    files.update(WEB_INPUTS)
                crate = root / (mode + ".crate")
                destination = root / (mode + "-output")
                crate_file(crate, files)
                packaged, count = gate.unpack(crate, destination, PREFIX, mode)
                self.assertEqual(packaged, destination / PREFIX)
                self.assertEqual(count, len(files))
                self.assertEqual(
                    {str(path.relative_to(packaged)).replace(os.sep, "/"): path.read_bytes()
                     for path in packaged.rglob("*") if path.is_file()}, files,
                )
            self.assertFalse((root / "not-owned").exists())

    def test_normal_build_dependency_closure_separates_all_three_modes(self):
        for mode in gate.FEATURES:
            with self.subTest(mode=mode):
                tree = dependency_tree(mode)
                expected = sorted({line.split()[0] for line in tree.splitlines()})
                self.assertEqual(gate.check_dependencies(tree + tree, mode), expected)
                for kernel in ("aya", "aya-ebpf"):
                    with self.assertRaises(ValueError):
                        gate.check_dependencies(tree + f"{kernel} v0.0.1\n", mode)
                for allocator in gate.ALLOCATOR_PACKAGES:
                    with self.subTest(mode=mode, allocator=allocator), self.assertRaises(ValueError):
                        gate.check_dependencies(tree + f"{allocator} v0.0.1\n", mode)
                with self.assertRaisesRegex(ValueError, "AWS-LC without ring"):
                    gate.check_dependencies(tree + "ring v0.0.1\n", mode)
                for package in gate.AWS_LC_PACKAGES:
                    with self.subTest(mode=mode, missing=package), self.assertRaisesRegex(ValueError, "AWS-LC without ring"):
                        gate.check_dependencies(tree.replace(f"{package} v0.0.1\n", ""), mode)
                with self.assertRaises(ValueError):
                    gate.check_dependencies(tree.replace("vproxy v0.0.1\n", ""), mode)
        for package in gate.MANAGEMENT_PACKAGES | gate.WEB_PACKAGES:
            with self.subTest(leak=package), self.assertRaises(ValueError):
                gate.check_dependencies(dependency_tree("proxy") + f"{package} v0.0.1\n", "proxy")
        for package in gate.MANAGEMENT_PACKAGES:
            for mode in ("api", "web"):
                with self.subTest(missing=package, mode=mode), self.assertRaises(ValueError):
                    gate.check_dependencies(dependency_tree(mode).replace(f"{package} v0.0.1\n", ""), mode)
        for package in gate.WEB_PACKAGES:
            with self.subTest(leak=package), self.assertRaises(ValueError):
                gate.check_dependencies(dependency_tree("api") + f"{package} v0.0.1\n", "api")
            with self.subTest(missing=package), self.assertRaises(ValueError):
                gate.check_dependencies(dependency_tree("web").replace(f"{package} v0.0.1\n", ""), "web")

    def test_smoke_checks_actual_artifact_variant_and_never_starts_a_service(self):
        binary, directory = Path("vproxy-tested"), Path("package-fixture")
        for mode in gate.FEATURES:
            outputs = ["vproxy 0.0.1\n", "Commands:\n  run  Run server\n"]
            if mode != "proxy":
                outputs[1] += "  manage  Manage persistent node state\n"
                outputs.append("Run the HTTPS management API\n")
            with self.subTest(mode=mode), patch.object(gate, "run", side_effect=outputs) as command:
                self.assertEqual(gate.smoke(binary, mode, directory), "vproxy 0.0.1")
                expected = [[binary, "--version"], [binary, "--help"]]
                if mode != "proxy":
                    expected.append([binary, "manage", "serve", "--help"])
                self.assertEqual([call.args[0] for call in command.call_args_list], expected)
                self.assertTrue(all(call.args[1] == directory and call.kwargs == {"capture": True, "timeout": 30}
                                    for call in command.call_args_list))
        for mode, help_text in (("proxy", "  manage  must not appear\n"), ("api", "  run  only\n"), ("web", "  run  only\n")):
            with self.subTest(mode=mode), patch.object(gate, "run", side_effect=["vproxy 0.0.1", help_text]) as command:
                with self.assertRaises(ValueError):
                    gate.smoke(binary, mode, directory)
                self.assertEqual(command.call_count, 2)

    def test_finished_archive_is_validated_before_smoking_its_extracted_binary(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-release-archive-test-") as temporary:
            root = Path(temporary)
            binary = root / "vproxy"
            binary.write_bytes(b"fixture executable bytes\n")
            valid = {"vproxy": binary.read_bytes(), "LICENSE": b"license", "README.md": b"readme"}

            def write_archive(label, entries):
                archive_path = root / (label + ".tar.gz")
                with tarfile.open(archive_path, "x:gz") as archive:
                    for info, data in entries:
                        archive.addfile(info, io.BytesIO(data) if info.isfile() else None)
                return archive_path

            entries = [(member(name, len(data)), data) for name, data in valid.items()]
            archive = write_archive("valid", entries)
            extracted = gate.check_archive(archive, root / "valid-output", binary)
            self.assertEqual(extracted, root / "valid-output/vproxy")
            self.assertEqual(extracted.read_bytes(), binary.read_bytes())
            notice = root / "LICENSE.ant-design-pro"
            notice.write_bytes(WEB_INPUTS["web/LICENSE.ant-design-pro"])
            notice_entry = (member(notice.name, notice.stat().st_size), notice.read_bytes())
            web_archive = write_archive("valid-web", entries + [notice_entry])
            web_extracted = gate.check_archive(web_archive, root / "valid-web-output", binary, notice)
            self.assertEqual(web_extracted.read_bytes(), binary.read_bytes())
            self.assertEqual((web_extracted.parent / notice.name).read_bytes(), notice.read_bytes())
            with self.assertRaises(ValueError):
                gate.check_archive(archive, root / "missing-web-notice-output", binary, notice)
            self.assertEqual(list((root / "missing-web-notice-output").iterdir()), [])
            changed_notice = write_archive("changed-web-notice", entries + [(member(notice.name, 7), b"changed")])
            with self.assertRaisesRegex(ValueError, "frontend license notice"):
                gate.check_archive(changed_notice, root / "changed-web-notice-output", binary, notice)
            with self.assertRaises(ValueError):
                gate.check_archive(web_archive, root / "unexpected-web-notice-output", binary)
            self.assertEqual(list((root / "unexpected-web-notice-output").iterdir()), [])
            for label, invalid in (
                ("extra", entries + [(member("extra", 1), b"x")]),
                ("missing", entries[:-1]),
                ("traversal", [entries[0], entries[1], (member("../README.md", 1), b"x")]),
                ("duplicate", [entries[0], entries[1], entries[1]]),
                ("symlink", [(member("vproxy", 0, tarfile.SYMTYPE), b"")] + entries[1:]),
                ("directory", [(member("vproxy", 0, tarfile.DIRTYPE), b"")] + entries[1:]),
                ("changed-binary", [(member("vproxy", 7), b"changed")] + entries[1:]),
            ):
                with self.subTest(label=label):
                    archive = write_archive(label, invalid)
                    destination = root / (label + "-output")
                    with self.assertRaises(ValueError):
                        gate.check_archive(archive, destination, binary)
                    # Content mismatches can leave inspected files, but never
                    # reach smoke; invalid member sets are rejected before read.
                    if label != "changed-binary":
                        self.assertEqual(list(destination.iterdir()), [])
            self.assertFalse((root / "README.md").exists())

    def build_fixture(self, root, mode, failure=None):
        source, work = root / "source", root / "work"
        source.mkdir()
        files = dict(INPUTS)
        if mode == "web":
            files.update(WEB_INPUTS)
        for relative, data in files.items():
            output = source / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)

        def command(arguments, directory, **_options):
            values = list(map(str, arguments))
            if values[:4] == ["cargo", "--color", "never", "package"]:
                if failure == "package":
                    raise subprocess.CalledProcessError(7, values)
                packaged = dict(files)
                if failure == "unpack":
                    packaged.pop("LICENSE")
                if failure == "web-notice":
                    packaged.pop("web/LICENSE.ant-design-pro")
                if failure == "lock":
                    packaged["Cargo.lock"] = INPUTS["Cargo.lock"].replace(b'"0.0.1"', b'"0.0.2"')
                if failure == "public-anchor":
                    packaged[PUBLIC_ANCHOR] = b"x" * len(PUBLIC_ANCHOR_BYTES)
                destination = Path(values[values.index("--target-dir") + 1]) / "package"
                destination.mkdir(parents=True)
                crate_file(destination / (PREFIX + ".crate"), packaged)
                return None
            if values[:4] == ["cargo", "--color", "never", "tree"]:
                tree = "vproxy v0.0.1\n" if failure == "closure" else dependency_tree(mode)
                return tree + "ring v0.0.1\n" if failure == "ring" else tree
            if values[:4] == ["cargo", "--color", "never", "build"]:
                if failure == "build":
                    raise subprocess.CalledProcessError(9, values)
                target = Path(values[values.index("--target-dir") + 1]) / values[values.index("--target") + 1] / "release"
                target.mkdir(parents=True)
                (target / ("vproxy.exe" if os.name == "nt" else "vproxy")).write_bytes(b"not an executable; run is stubbed\n")
                return None
            if values[-1] == "--version":
                return "vproxy 0.0.2\n" if failure == "version" else "vproxy 0.0.1\n"
            if values[-1] == "--help":
                return "Commands:\n  run  Run server\n" + ("  manage  Manage node\n" if mode != "proxy" else "")
            if values == ["rustc", "-vV"]:
                return "rustc fixture\nhost: fixture-host\n"
            raise AssertionError("Unexpected external command in test fixture")

        return source, work, command

    def test_build_creates_checksums_only_after_all_package_and_binary_gates(self):
        for mode in gate.FEATURES:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="vproxy-release-build-test-") as temporary:
                source, work, command = self.build_fixture(Path(temporary), mode)
                before = (source / "Cargo.lock").read_bytes()
                with patch.object(gate, "run", side_effect=command) as calls, contextlib.redirect_stdout(io.StringIO()):
                    gate.build(source, work, mode)
                artifacts = work / "artifacts"
                report = json.loads((artifacts / "build.json").read_text(encoding="utf8"))
                self.assertEqual(report["mode"], mode)
                self.assertEqual(report["features"], [gate.FEATURES[mode]])
                self.assertTrue(report["no_default_features"])
                self.assertEqual(report["allocator"], "system")
                self.assertIs(report["publishing"], False)
                self.assertEqual(report["checkout_lock_sha256"], hashlib.sha256(before).hexdigest())
                self.assertEqual(report["packaged_lock_sha256"], hashlib.sha256(INPUTS["Cargo.lock"]).hexdigest())
                self.assertEqual((source / "Cargo.lock").read_bytes(), before)
                checksum_lines = (artifacts / "SHA256SUMS").read_text(encoding="ascii").splitlines()
                self.assertEqual(len(checksum_lines), 3)
                for line in checksum_lines:
                    sha256, name = line.split("  ", 1)
                    self.assertEqual(hashlib.sha256((artifacts / name).read_bytes()).hexdigest(), sha256)
                archive = artifacts / f"{PREFIX}-{mode}-fixture-host.tar.gz"
                with tarfile.open(archive, "r:gz") as payload:
                    expected = {"vproxy.exe" if os.name == "nt" else "vproxy", "README.md", "LICENSE"}
                    if mode == "web":
                        expected.add("LICENSE.ant-design-pro")
                        self.assertEqual(payload.extractfile("LICENSE.ant-design-pro").read(), WEB_INPUTS["web/LICENSE.ant-design-pro"])
                    self.assertEqual(set(payload.getnames()), expected)
                cargo_calls = [list(map(str, call.args[0])) for call in calls.call_args_list if call.args[0][0] == "cargo"]
                self.assertEqual(len(cargo_calls), 3)
                for arguments in cargo_calls:
                    self.assertIn("--locked", arguments)
                    self.assertIn("--no-default-features", arguments)
                    self.assertEqual(arguments[arguments.index("--features") + 1], gate.FEATURES[mode])
                self.assertIn("--release", cargo_calls[-1])
                self.assertEqual(cargo_calls[-1][cargo_calls[-1].index("--bin") + 1], "vproxy")
                for arguments in cargo_calls[1:]:
                    self.assertEqual(arguments[arguments.index("--target") + 1], "fixture-host")
                smoke_calls = [call for call in calls.call_args_list if str(call.args[0][0]).startswith(str(work / "archive-check"))]
                self.assertEqual(len(smoke_calls), 2 if mode == "proxy" else 3)
                self.assertTrue(all(call.args[1] == work / "archive-check" for call in smoke_calls))

    def test_packaging_can_normalize_only_lockfile_line_endings_without_changing_graph(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-release-lock-normalize-test-") as temporary:
            source, work, command = self.build_fixture(Path(temporary), "proxy")
            original = INPUTS["Cargo.lock"].replace(b"\n", b"\r\n")
            (source / "Cargo.lock").write_bytes(original)
            with patch.object(gate, "run", side_effect=command), contextlib.redirect_stdout(io.StringIO()):
                gate.build(source, work, "proxy")
            report = json.loads((work / "artifacts/build.json").read_text(encoding="utf8"))
            self.assertNotEqual(report["checkout_lock_sha256"], report["packaged_lock_sha256"])
            self.assertEqual(report["checkout_lock_sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(report["packaged_lock_sha256"], hashlib.sha256(INPUTS["Cargo.lock"]).hexdigest())
            self.assertEqual((source / "Cargo.lock").read_bytes(), original)

    def test_gate_failure_never_emits_a_success_manifest_or_checksum_and_is_not_retried(self):
        for mode, failure in [("api", case) for case in ("package", "unpack", "public-anchor", "lock", "closure", "ring", "build", "version")] + [("web", "web-notice")]:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix="vproxy-release-fail-test-") as temporary:
                source, work, command = self.build_fixture(Path(temporary), mode, failure)
                with patch.object(gate, "run", side_effect=command) as calls, contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        gate.build(source, work, mode)
                self.assertFalse((work / "artifacts/build.json").exists())
                self.assertFalse((work / "artifacts/SHA256SUMS").exists())
                if failure != "version":
                    self.assertFalse((work / "artifacts").exists())
                commands = [tuple(map(str, call.args[0])) for call in calls.call_args_list]
                self.assertEqual(len(commands), len(set(commands)))
                self.assertEqual((source / "Cargo.lock").read_bytes(), INPUTS["Cargo.lock"])
        with tempfile.TemporaryDirectory(prefix="vproxy-release-copy-fail-test-") as temporary:
            source, work, command = self.build_fixture(Path(temporary), "proxy")
            with patch.object(gate, "run", side_effect=command), patch.object(gate.shutil, "copyfile", side_effect=OSError("fixture write failure")), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(OSError):
                    gate.build(source, work, "proxy")
            # A late I/O failure retains diagnostic work, but cannot certify its
            # partial artifact set with a successful build report/checksum list.
            self.assertTrue(work.is_dir())
            self.assertFalse((work / "artifacts/build.json").exists())
            self.assertFalse((work / "artifacts/SHA256SUMS").exists())

    def test_existing_work_directory_is_not_reused_or_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-release-existing-test-") as temporary:
            source, work, command = self.build_fixture(Path(temporary), "proxy")
            work.mkdir()
            sentinel = work / "operator-material"
            sentinel.write_bytes(b"keep this exact fixture")
            with patch.object(gate, "run", side_effect=command) as calls:
                with self.assertRaises(FileExistsError):
                    gate.build(source, work, "proxy")
            calls.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b"keep this exact fixture")


if __name__ == "__main__":
    unittest.main()
