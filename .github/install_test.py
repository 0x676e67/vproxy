"""Offline checks of the Python embedded in the real, single-file installer.

No fixture executable is run and no system installation path is used. Archive,
checksum and no-overwrite filesystem operations are real in owned temporary
directories; network and release metadata are explicit test doubles.
"""

import contextlib
import gzip
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request


SCRIPT = Path(__file__).with_name("install.sh")
TARGET = "x86_64-unknown-linux-musl"
TAG = "v2.5.5"
ARCHIVE = "vproxy-2.5.5-" + TARGET + ".tar.gz"
BINARY = b"Synthetic fixture; never execute.\n"
NOTICE = b"Synthetic license notice, not an executable.\n"


def load_installer():
    lines = SCRIPT.read_bytes().splitlines(keepends=True)
    marker = b"<<'VPROXY_INSTALL_PY'"
    starts = [index for index, line in enumerate(lines) if marker in line]
    if len(starts) != 1:
        raise RuntimeError("Expected exactly one embedded installer entry point")
    start = starts[0] + 1
    ends = [index for index in range(start, len(lines)) if lines[index].rstrip(b"\r\n") == b"VPROXY_INSTALL_PY"]
    if len(ends) != 1:
        raise RuntimeError("Expected one independent embedded installer terminator")
    source = b"".join(lines[start:ends[0]])
    module = types.ModuleType("vproxy_installer_under_test")
    module.__file__ = str(SCRIPT)
    sys.modules[module.__name__] = module
    with patch.object(socket.socket, "connect", side_effect=AssertionError("Network is forbidden in installer tests")), patch("urllib.request.build_opener", side_effect=AssertionError("Network is forbidden in installer tests")):
        exec(compile(source, str(SCRIPT), "exec"), module.__dict__)
    return module


installer = load_installer()


def metadata():
    return {"tag_name": TAG, "draft": False, "prerelease": False, "assets": []}


def tar_bytes(entries, archive_format=tarfile.USTAR_FORMAT, global_pax=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=archive_format, pax_headers=global_pax) as output:
        for entry in entries:
            name, contents, kind, pax = entry[:4]
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(contents)
            member.mode = entry[4] if len(entry) == 5 else (0o755 if name == "vproxy" else 0o644)
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = "../../not-owned"
                member.size = 0
            if kind == tarfile.DIRTYPE:
                member.size = 0
            member.pax_headers = pax
            output.addfile(member, io.BytesIO(contents) if member.size else None)
    return stream.getvalue()


def regular(contents=BINARY):
    return ("vproxy", contents, tarfile.REGTYPE, {})


def profile_entries(profile, contents=BINARY):
    entries = [regular(contents)]
    if profile != "proxy":
        entries.extend((name, NOTICE, tarfile.REGTYPE, {}) for name in ("LICENSE", "README.md"))
    if profile == "web":
        entries.append(("LICENSE.ant-design-pro", NOTICE, tarfile.REGTYPE, {}))
    return entries


def archive_bytes(contents=BINARY, profile="proxy"):
    return gzip.compress(tar_bytes(profile_entries(profile, contents)), mtime=0)


def unpack_destination(root, label):
    stage = root / label
    stage.mkdir()
    return stage / "candidate"


class Response:
    def __init__(self, body=b"fixture payload", status=200, url="https://fixture.invalid/asset", headers=None,
                 chunk_size=3, failure=None, after_read=None):
        self.body, self.status, self.url = body, status, url
        self.headers = {} if headers is None else headers
        self.chunk_size, self.failure, self.after_read = chunk_size, failure, after_read
        self.offset, self.calls, self.requests, self.closed = 0, 0, [], False

    def __enter__(self):
        return self

    def __exit__(self, *_exception):
        self.closed = True

    def geturl(self):
        return self.url

    def read1(self, size):
        self.requests.append(size)
        self.calls += 1
        if self.failure is not None and self.calls > 1:
            raise self.failure
        chunk = self.body[self.offset:self.offset + min(size, self.chunk_size)]
        self.offset += len(chunk)
        if self.after_read is not None:
            self.after_read()
        return chunk


class InstallerTests(unittest.TestCase):
    def setUp(self):
        # A missed mock must fail, not contact GitHub or another host.
        self.network = patch.object(socket.socket, "connect", side_effect=AssertionError("Network is forbidden in installer tests"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.opener = patch.object(installer.urllib.request, "build_opener", side_effect=AssertionError("A download mock is required"))
        self.opener.start()
        self.addCleanup(self.opener.stop)

    def test_platform_mapping_and_stable_legacy_release_names(self):
        targets = {
            ("Linux", "x86_64"): "x86_64-unknown-linux-musl",
            ("Linux", "amd64"): "x86_64-unknown-linux-musl",
            ("Linux", "aarch64"): "aarch64-unknown-linux-musl",
            ("Linux", "arm64"): "aarch64-unknown-linux-musl",
            ("Linux", "arm"): "arm-unknown-linux-musleabihf",
            ("Linux", "armv7l"): "armv7-unknown-linux-musleabihf",
            ("Linux", "i686"): "i686-unknown-linux-musl",
            ("Darwin", "x86_64"): "x86_64-apple-darwin",
            ("Darwin", "arm64"): "aarch64-apple-darwin",
            ("Darwin", "aarch64"): "aarch64-apple-darwin",
        }
        for (system, machine), target in targets.items():
            with self.subTest(system=system, machine=machine):
                self.assertEqual(installer.target_for(system, machine), target)
                self.assertEqual(installer.release_names(metadata(), target),
                                 (TAG, "vproxy-2.5.5-" + target + ".tar.gz", "vproxy-2.5.5-" + target + ".tar.gz.sha256"))
                for profile, suffix in (("proxy", ""), ("api", "-api"), ("web", "-web")):
                    archive = "vproxy-2.5.5" + suffix + "-" + target + ".tar.gz"
                    self.assertEqual(installer.release_names(metadata(), target, profile),
                                     (TAG, archive, archive + ".sha256"))
        for system, machine in (("Windows", "x86_64"), ("FreeBSD", "x86_64"), ("Linux", "riscv64"), ("Darwin", "armv7l")):
            with self.subTest(system=system, machine=machine), self.assertRaises(installer.InstallError):
                installer.target_for(system, machine)
        without_prefix = metadata()
        without_prefix["tag_name"] = "2.5.5"
        self.assertEqual(installer.release_names(without_prefix, TARGET), ("2.5.5", ARCHIVE, ARCHIVE + ".sha256"))
        repeated = metadata()
        repeated["tag_name"] = "vv2.5.5"
        self.assertEqual(installer.release_names(repeated, TARGET),
                         ("vv2.5.5", "vproxy-v2.5.5-" + TARGET + ".tar.gz", "vproxy-v2.5.5-" + TARGET + ".tar.gz.sha256"))

    def test_release_metadata_does_not_turn_untrusted_values_into_paths(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-install-profile-") as temporary:
            destination = Path(temporary) / "must-not-be-created"
            for profile in ("", "API", "other", "../web", None, []):
                with self.subTest(profile=profile), patch.object(installer, "fetch_latest") as fetch, patch.object(installer, "download") as retrieve:
                    with self.assertRaises(installer.InstallError):
                        installer.release_names(metadata(), TARGET, profile)
                    with self.assertRaises(installer.InstallError):
                        installer.install(destination, profile)
                    fetch.assert_not_called()
                    retrieve.assert_not_called()
                    self.assertFalse(destination.exists())
        for value in (None, [], "not an object"):
            with self.subTest(value=value), self.assertRaises(installer.InstallError):
                installer.release_names(value, TARGET)
        for tag in (None, 123, "", "v", "../escape", "v2/5/5", "v2\\5", "v2.5.5\n", "v2.5.5\x00", "v2 5.5", "-2.5.5", "é", "v2.5.5+build", "x" * 129):
            data = metadata()
            data["tag_name"] = tag
            with self.subTest(tag=tag), self.assertRaises(installer.InstallError):
                installer.release_names(data, TARGET)
        for flag in ("draft", "prerelease"):
            for value in (True, 0, "false", None):
                data = metadata()
                data[flag] = value
                with self.subTest(flag=flag, value=value), self.assertRaises(installer.InstallError):
                    installer.release_names(data, TARGET)
            data = metadata()
            del data[flag]
            with self.subTest(missing=flag), self.assertRaises(installer.InstallError):
                installer.release_names(data, TARGET)
        with tempfile.TemporaryDirectory(prefix="vproxy-install-json-") as temporary:
            for index, payload in enumerate((json.dumps(metadata()).encode(), b"not JSON", b"\xff")):
                path = Path(temporary) / (str(index) + ".json")
                with patch.object(installer, "download", side_effect=lambda _url, output, _limit: output.write_bytes(payload)) as download:
                    if index == 0:
                        self.assertEqual(installer.fetch_latest(path), metadata())
                    else:
                        with self.assertRaises(installer.InstallError):
                            installer.fetch_latest(path)
                    download.assert_called_once_with(installer.LATEST, path, 1024 * 1024)

    def test_checksum_is_one_exact_lowercase_digest_and_basename(self):
        digest = hashlib.sha256(b"fixture archive").hexdigest()
        with tempfile.TemporaryDirectory(prefix="vproxy-install-checksum-") as temporary:
            path = Path(temporary) / "checksum"
            for ending in ("", "\n"):
                path.write_bytes((digest + "  " + ARCHIVE + ending).encode("ascii"))
                self.assertEqual(installer.expected_digest(path, ARCHIVE), digest)
            for contents in (
                digest[:-1] + "  " + ARCHIVE + "\n",
                digest.upper() + "  " + ARCHIVE + "\n",
                digest + " " + ARCHIVE + "\n",
                digest + " *" + ARCHIVE + "\n",
                digest + "  ./" + ARCHIVE + "\n",
                digest + "  " + ARCHIVE + ".other\n",
                digest + "  " + ARCHIVE + "\r\n",
                digest + "  " + ARCHIVE + "\n\n",
                (digest + "  " + ARCHIVE + "\n") * 2,
                digest + "  " + ARCHIVE + "\x00",
            ):
                path.write_bytes(contents.encode("ascii"))
                with self.subTest(contents=repr(contents)), self.assertRaises(installer.InstallError):
                    installer.expected_digest(path, ARCHIVE)

    def test_https_download_status_limits_partial_streams_deadline_and_no_retry(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-install-https-") as temporary:
            root = Path(temporary)
            for scheme in ("http", "file", "ftp"):
                with self.subTest(scheme=scheme), patch.object(installer.urllib.request, "build_opener") as build:
                    with self.assertRaises(installer.InstallError):
                        installer.download(scheme + "://fixture.invalid/asset", root / scheme, 32)
                    build.assert_not_called()
            for label, response, limit, succeeds in (
                ("bounded-chunks", Response(), 32, True),
                ("exact-limit", Response(b"12345", headers={"Content-Length": "5"}), 5, True),
                ("bad-status", Response(status=404), 32, False),
                ("plaintext-final-url", Response(url="http://fixture.invalid/asset"), 32, False),
                ("oversized-length", Response(headers={"Content-Length": "33"}), 32, False),
                ("invalid-length", Response(headers={"Content-Length": "-1"}), 32, False),
                ("oversized-body", Response(b"123456"), 5, False),
                ("incomplete-body", Response(b"123", headers={"Content-Length": "4"}), 32, False),
                ("empty-body", Response(b""), 32, False),
                ("broken-read", Response(failure=OSError("private redirect metadata")), 32, False),
                ("http-incomplete-read", Response(failure=http.client.IncompleteRead(b"private partial body")), 32, False),
            ):
                with self.subTest(label=label), patch.object(installer.urllib.request, "build_opener") as build:
                    opener = build.return_value
                    opener.open.return_value = response
                    destination = root / label
                    if succeeds:
                        installer.download("https://fixture.invalid/asset", destination, limit)
                        self.assertEqual(destination.read_bytes(), response.body)
                    else:
                        with self.assertRaises(installer.InstallError) as caught:
                            installer.download("https://fixture.invalid/asset", destination, limit)
                        self.assertNotIn("private", str(caught.exception))
                    opener.open.assert_called_once()
                    self.assertEqual(opener.open.call_args.kwargs, {"timeout": 30})
                    self.assertEqual(opener.open.call_args.args[0].full_url, "https://fixture.invalid/asset")
                    self.assertIsInstance(build.call_args.args[0], installer.HttpsOnlyRedirect)
                    self.assertTrue(response.closed)
                    self.assertTrue(all(0 < size <= min(installer.CHUNK_BYTES, limit + 1) for size in response.requests))
            for phase in ("before-read", "after-read"):
                clock = [0.0]
                response = Response(after_read=lambda: clock.__setitem__(0, 91.0))
                with self.subTest(deadline=phase), patch.object(installer.urllib.request, "build_opener") as build, patch.object(installer.time, "monotonic", side_effect=lambda: clock[0]):
                    if phase == "before-read":
                        def delayed_open(*_arguments, **_options):
                            clock[0] = 91.0
                            return response
                        build.return_value.open.side_effect = delayed_open
                    else:
                        build.return_value.open.return_value = response
                    with self.assertRaises(installer.InstallError):
                        installer.download("https://fixture.invalid/asset", root / phase, 32)
                    self.assertEqual(response.calls, 0 if phase == "before-read" else 1)
                    build.return_value.open.assert_called_once()
            request = urllib.request.Request("https://fixture.invalid/asset")
            with self.assertRaises(installer.InstallError):
                installer.HttpsOnlyRedirect().redirect_request(request, None, 302, "Found", {}, "http://fixture.invalid/next")
            redirected = installer.HttpsOnlyRedirect().redirect_request(request, None, 302, "Found", {}, "https://other.invalid/next")
            self.assertEqual(redirected.full_url, "https://other.invalid/next")
            with patch.object(installer.urllib.request, "build_opener") as build:
                build.return_value.open.side_effect = urllib.error.URLError("private query token")
                with self.assertRaises(installer.InstallError) as caught:
                    installer.download("https://fixture.invalid/asset", root / "connection-failure", 32)
                self.assertNotIn("private", str(caught.exception))
                build.return_value.open.assert_called_once()

    def test_unpack_copies_only_one_root_regular_binary_and_enforces_both_limits(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-install-unpack-") as temporary:
            root = Path(temporary)
            archive = root / "good.tar.gz"
            archive.write_bytes(archive_bytes())
            destination = unpack_destination(root, "valid")
            installer.unpack(archive, destination)
            self.assertEqual(destination.read_bytes(), BINARY)
            self.assertFalse((root / "not-owned").exists())
            for label, constant, limit in (("binary", "MAX_BINARY_BYTES", len(BINARY) - 1),
                                           ("tar", "MAX_TAR_BYTES", len(tar_bytes([regular()])) - 1)):
                with self.subTest(limit=label), patch.object(installer, constant, limit), self.assertRaises(installer.InstallError):
                    installer.unpack(archive, unpack_destination(root, label))
            with patch.object(installer, "MAX_BINARY_BYTES", len(BINARY)):
                exact = unpack_destination(root, "exact-bound")
                installer.unpack(archive, exact)
                self.assertEqual(exact.read_bytes(), BINARY)
            existing = unpack_destination(root, "existing")
            existing.write_bytes(b"Keep operator material\n")
            with self.assertRaises((installer.InstallError, FileExistsError)):
                installer.unpack(archive, existing)
            self.assertEqual(existing.read_bytes(), b"Keep operator material\n")

    def test_profile_inventory_notices_and_permissions_are_checked_before_copy(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-install-profiles-") as temporary:
            root = Path(temporary)
            count = 0

            def check(entries, profile, *, succeeds=False, archive_format=tarfile.USTAR_FORMAT):
                nonlocal count
                count += 1
                archive = root / ("archive-" + str(count) + ".tar.gz")
                archive.write_bytes(gzip.compress(tar_bytes(entries, archive_format), mtime=0))
                destination = unpack_destination(root, "stage-" + str(count))
                if succeeds:
                    installer.unpack(archive, destination, profile)
                    self.assertEqual(destination.read_bytes(), BINARY)
                    self.assertEqual({path.name for path in destination.parent.iterdir()}, {"candidate", "payload.tar"})
                else:
                    with self.assertRaises(installer.InstallError):
                        installer.unpack(archive, destination, profile)
                    self.assertFalse(destination.exists())

            # Existing proxy archives keep their normal GNU header and mode
            # compatibility; the installed executable still receives 0755.
            check([("vproxy", BINARY, tarfile.REGTYPE, {}, 0o640)], "proxy",
                  succeeds=True, archive_format=tarfile.GNU_FORMAT)
            for profile in ("api", "web"):
                entries = profile_entries(profile)
                with self.subTest(profile=profile, valid=True):
                    check(entries, profile, succeeds=True)
                    check(list(reversed(entries)), profile, succeeds=True)
                for index, entry in enumerate(entries):
                    with self.subTest(profile=profile, missing=entry[0]):
                        check(entries[:index] + entries[index + 1:], profile)
                    with self.subTest(profile=profile, duplicate=entry[0]):
                        check(entries + [entry], profile)
                    wrong_mode = (*entry, 0o644 if entry[0] == "vproxy" else 0o755)
                    with self.subTest(profile=profile, wrong_mode=entry[0]):
                        check(entries[:index] + [wrong_mode] + entries[index + 1:], profile)
                with self.subTest(profile=profile, extra=True):
                    check(entries + [("extra", NOTICE, tarfile.REGTYPE, {})], profile)
                    check(entries, profile, archive_format=tarfile.GNU_FORMAT)
                for contents in (b"", b" \t\r\n", b"\xff"):
                    modified = [entries[0], ("LICENSE", contents, tarfile.REGTYPE, {}), *entries[2:]]
                    with self.subTest(profile=profile, invalid_notice=contents):
                        check(modified, profile)
                for name in ("../LICENSE", "./LICENSE", "sub/LICENSE", "/LICENSE"):
                    modified = [entries[0], (name, NOTICE, tarfile.REGTYPE, {}), *entries[2:]]
                    with self.subTest(profile=profile, unsafe_name=name):
                        check(modified, profile)
                for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE,
                             tarfile.FIFOTYPE, tarfile.GNUTYPE_SPARSE):
                    modified = [entries[0], ("LICENSE", NOTICE, kind, {}), *entries[2:]]
                    with self.subTest(profile=profile, unsafe_type=kind):
                        check(modified, profile)
                # These extensions occur after an acceptable first header, not
                # only at archive offset zero. No parser may consume them first.
                modified = [entries[0], ("LICENSE", NOTICE, tarfile.REGTYPE, {"comment": "hidden extension"}), *entries[2:]]
                with self.subTest(profile=profile, pax_after_binary=True):
                    check(modified, profile, archive_format=tarfile.PAX_FORMAT)
                for kind in (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                    modified = [entries[0], ("././@LongLink", b"LICENSE\0", kind, {}), *entries[1:]]
                    with self.subTest(profile=profile, gnu_extension_after_binary=kind):
                        check(modified, profile)
                with patch.object(installer, "MAX_TEXT_BYTES", len(NOTICE)):
                    check(entries, profile, succeeds=True)
                with patch.object(installer, "MAX_TEXT_BYTES", len(NOTICE) - 1):
                    check(entries, profile)
            check(profile_entries("web"), "api")
            check(profile_entries("api"), "web")

    def test_tar_metadata_links_paths_and_trailing_members_are_rejected(self):
        cases = []
        for name in ("/vproxy", "../vproxy", "sub/vproxy", "./vproxy", "vproxy.exe", "Vproxy"):
            cases.append((name, tar_bytes([(name, BINARY, tarfile.REGTYPE, {})])))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.GNUTYPE_SPARSE):
            cases.append((repr(kind), tar_bytes([("vproxy", BINARY, kind, {})])))
        cases.extend([
            ("empty", tar_bytes([])),
            ("empty-binary", tar_bytes([regular(b"")])),
            ("duplicate", tar_bytes([regular(), regular()])),
            ("extra-member", tar_bytes([regular(), ("README.md", b"extra", tarfile.REGTYPE, {})])),
            ("pax", tar_bytes([("vproxy", BINARY, tarfile.REGTYPE, {"comment": "untrusted metadata"})], tarfile.PAX_FORMAT)),
            ("global-pax", tar_bytes([regular()], tarfile.PAX_FORMAT, {"comment": "global metadata"})),
            ("gnu-longname-hidden-header", tar_bytes([
                ("././@LongLink", b"vproxy\0", tarfile.GNUTYPE_LONGNAME, {}),
                ("ignored-header-name", BINARY, tarfile.REGTYPE, {}),
            ], tarfile.GNU_FORMAT)),
            ("gnu-longlink-hidden-header", tar_bytes([
                ("././@LongLink", b"../../not-owned\0", tarfile.GNUTYPE_LONGLINK, {}), regular(),
            ], tarfile.GNU_FORMAT)),
            ("truncated-tar-payload", tar_bytes([regular()])[:512 + len(BINARY)]),
            ("concatenated-tar", tar_bytes([regular()]) + tar_bytes([regular()])),
        ])
        with tempfile.TemporaryDirectory(prefix="vproxy-install-bad-tar-") as temporary:
            root = Path(temporary)
            for index, (label, raw) in enumerate(cases):
                archive = root / (str(index) + ".tar.gz")
                archive.write_bytes(gzip.compress(raw, mtime=0))
                with self.subTest(label=label), self.assertRaises(installer.InstallError):
                    installer.unpack(archive, unpack_destination(root, "bad-tar-" + str(index)))
            for index, contents in enumerate((b"not gzip", archive_bytes()[:-1], archive_bytes() + archive_bytes())):
                archive = root / ("gzip-" + str(index) + ".tar.gz")
                archive.write_bytes(contents)
                with self.subTest(gzip=index), self.assertRaises(installer.InstallError):
                    installer.unpack(archive, unpack_destination(root, "gzip-" + str(index)))

    @unittest.skipUnless(os.name == "posix", "Real tar/shasum compatibility runs under POSIX Python")
    def test_real_tar_and_shasum_are_accepted_without_running_binary(self):
        for tool in ("tar", "shasum"):
            self.assertIsNotNone(shutil.which(tool), "Required real packaging tool is missing: " + tool)
        with tempfile.TemporaryDirectory(prefix="vproxy-install-real-tar-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "vproxy").write_bytes(BINARY)
            (source / "vproxy").chmod(0o755)
            archive = root / ARCHIVE
            arguments = [shutil.which("tar"), "-czf", str(archive), "-C", str(source), "vproxy"]
            if sys.platform == "darwin":
                # G2 builds on Linux with GNU tar's default format. BSD tar can
                # emit PAX metadata; exercise a compatible ustar fixture on macOS.
                arguments.insert(1, "--format=ustar")
            subprocess.run(arguments, check=True,
                           capture_output=True, text=True, encoding="utf8", timeout=10)
            checksum = subprocess.run([shutil.which("shasum"), "-a", "256", archive.name], cwd=root, check=True,
                                      capture_output=True, text=True, encoding="ascii", timeout=10)
            sidecar = root / (archive.name + ".sha256")
            sidecar.write_bytes(checksum.stdout.encode("ascii"))
            self.assertEqual(installer.expected_digest(sidecar, archive.name), hashlib.sha256(archive.read_bytes()).hexdigest())
            destination = unpack_destination(root, "verified")
            installer.unpack(archive, destination)
            self.assertEqual(destination.read_bytes(), BINARY)

    @unittest.skipUnless(os.name == "posix", "Real Linux/macOS install filesystem checks run under POSIX Python")
    def test_install_uses_real_checksum_archive_and_no_overwrite_delivery(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-install-success-") as temporary:
            root = Path(temporary)
            for profile in ("proxy", "api", "web"):
                output = root / ("private destination with spaces " + profile)
                output.mkdir(mode=0o700)
                payload = archive_bytes(profile=profile)
                _, name, sidecar = installer.release_names(metadata(), TARGET, profile)
                checksum = (hashlib.sha256(payload).hexdigest() + "  " + name + "\n").encode()
                downloads = []

                def download(url, path, limit):
                    self.assertFalse(Path(path).exists())
                    contents = checksum if url.endswith(".sha256") else payload
                    self.assertLessEqual(len(contents), limit)
                    Path(path).write_bytes(contents)
                    downloads.append((url, limit))

                release = metadata()
                release["assets"] = [{"name": name, "browser_download_url": "https://private:secret@ignored.invalid/token"}]
                with self.subTest(profile=profile), patch.object(installer, "fetch_latest", return_value=release), patch.object(installer, "download", side_effect=download), patch.object(installer.platform, "system", return_value="Linux"), patch.object(installer.platform, "machine", return_value="x86_64"):
                    installed = installer.install(output) if profile == "proxy" else installer.install(output, profile)
                self.assertEqual(installed, output / "vproxy")
                self.assertEqual(installed.read_bytes(), BINARY)
                self.assertEqual(installed.stat().st_mode & 0o777, 0o755)
                base = installer.REPOSITORY + "/releases/download/" + TAG + "/"
                self.assertEqual(downloads, [(base + sidecar, 1024), (base + name, installer.MAX_DOWNLOAD_BYTES)])
                self.assertEqual({path.name for path in output.iterdir()}, {"vproxy"})
            for directory in ("", "   ", "\t\n"):
                with self.subTest(empty_directory=repr(directory)), contextlib.chdir(root), patch.object(installer, "fetch_latest") as fetch, patch.object(installer, "download") as retrieve:
                    with self.assertRaises(installer.InstallError):
                        installer.install(directory)
                    fetch.assert_not_called()
                    retrieve.assert_not_called()
            for kind in ("file", "directory", "dangling-symlink"):
                with self.subTest(existing=kind):
                    destination = root / kind
                    destination.mkdir(mode=0o700)
                    existing = destination / "vproxy"
                    if kind == "file":
                        existing.write_bytes(b"Existing executable, do not change\n")
                    elif kind == "directory":
                        existing.mkdir()
                        (existing / "operator-material").write_bytes(b"keep")
                    else:
                        existing.symlink_to(destination / "absent")
                    for profile in ("proxy", "api", "web"):
                        with patch.object(installer, "fetch_latest") as fetch, patch.object(installer, "download") as retrieve:
                            with self.assertRaises((installer.InstallError, FileExistsError)):
                                installer.install(destination, profile)
                        fetch.assert_not_called()
                        retrieve.assert_not_called()
                    if kind == "file":
                        self.assertEqual(existing.read_bytes(), b"Existing executable, do not change\n")
                    elif kind == "directory":
                        self.assertEqual((existing / "operator-material").read_bytes(), b"keep")
                    else:
                        self.assertTrue(existing.is_symlink())
                        self.assertFalse(existing.exists())

    @unittest.skipUnless(os.name == "posix", "Real Linux/macOS install filesystem checks run under POSIX Python")
    def test_explicit_profiles_never_fall_back_when_assets_or_checksums_fail(self):
        for profile in ("api", "web"):
            for fault in ("missing-checksum", "missing-archive", "wrong-checksum-name", "wrong-profile-archive"):
                with self.subTest(profile=profile, fault=fault), tempfile.TemporaryDirectory(prefix="vproxy-install-no-fallback-") as temporary:
                    output = Path(temporary) / "private destination"
                    _, name, sidecar = installer.release_names(metadata(), TARGET, profile)
                    payload = archive_bytes() if fault == "wrong-profile-archive" else archive_bytes(profile=profile)
                    checksum_name = ARCHIVE if fault == "wrong-checksum-name" else name
                    checksum = (hashlib.sha256(payload).hexdigest() + "  " + checksum_name + "\n").encode()
                    downloads = []

                    def download(url, path, limit):
                        downloads.append(url)
                        if ((fault == "missing-checksum" and url.endswith(".sha256"))
                                or (fault == "missing-archive" and not url.endswith(".sha256"))):
                            raise installer.InstallError("Fixture asset is missing")
                        Path(path).write_bytes(checksum if url.endswith(".sha256") else payload)

                    with patch.object(installer, "fetch_latest", return_value=metadata()), patch.object(installer, "download", side_effect=download), patch.object(installer.platform, "system", return_value="Linux"), patch.object(installer.platform, "machine", return_value="x86_64"):
                        with self.assertRaises(installer.InstallError):
                            installer.install(output, profile)
                    base = installer.REPOSITORY + "/releases/download/" + TAG + "/"
                    expected = [base + sidecar]
                    if fault not in ("missing-checksum", "wrong-checksum-name"):
                        expected.append(base + name)
                    self.assertEqual(downloads, expected)
                    self.assertEqual(list(output.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "Real Linux/macOS install filesystem checks run under POSIX Python")
    def test_partial_and_failed_install_cannot_publish_or_replace_late_operator_file(self):
        for fault in ("download-checksum", "download-archive", "checksum", "archive", "chmod", "link", "race", "after-link"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="vproxy-install-failure-") as temporary:
                output = Path(temporary) / "private output"
                output.mkdir(mode=0o700)
                payload = b"invalid gzip" if fault == "archive" else archive_bytes()
                digest = "0" * 64 if fault == "checksum" else hashlib.sha256(payload).hexdigest()
                checksum = (digest + "  " + ARCHIVE + "\n").encode()
                downloaded = []
                original_link = installer.os.link

                def download(url, path, limit):
                    contents = checksum if url.endswith(".sha256") else payload
                    Path(path).write_bytes(contents)
                    downloaded.append(url)
                    if (fault == "download-checksum" and url.endswith(".sha256")) or (fault == "download-archive" and not url.endswith(".sha256")):
                        raise installer.InstallError("Injected partial download")

                def late_link(source, destination, **kwargs):
                    Path(destination).write_bytes(b"Late operator file; never replace\n")
                    # Let the real filesystem enforce no-clobber after the
                    # operator file appeared, rather than mocking the result.
                    return original_link(source, destination, **kwargs)

                def unknown_link(source, destination, **kwargs):
                    original_link(source, destination, **kwargs)
                    raise OSError("Injected error after completed publication")

                with contextlib.ExitStack() as stack:
                    stack.enter_context(patch.object(installer, "fetch_latest", return_value=metadata()))
                    stack.enter_context(patch.object(installer, "download", side_effect=download))
                    stack.enter_context(patch.object(installer.platform, "system", return_value="Linux"))
                    stack.enter_context(patch.object(installer.platform, "machine", return_value="x86_64"))
                    if fault == "chmod":
                        stack.enter_context(patch.object(installer.os, "chmod", side_effect=PermissionError("Injected permission failure")))
                    if fault in ("link", "race", "after-link"):
                        effect = late_link if fault == "race" else unknown_link if fault == "after-link" else PermissionError("Injected handoff failure")
                        stack.enter_context(patch.object(installer.os, "link", side_effect=effect))
                    with self.assertRaises((installer.InstallError, OSError)):
                        installer.install(output)
                self.assertTrue(downloaded)
                target = output / "vproxy"
                if fault == "race":
                    self.assertEqual(target.read_bytes(), b"Late operator file; never replace\n")
                elif fault == "after-link":
                    # An error after the atomic publication cannot prove that
                    # nothing happened; do not delete or replay a complete file.
                    self.assertEqual(target.read_bytes(), BINARY)
                else:
                    self.assertFalse(target.exists())
                    self.assertFalse(target.is_symlink())
                self.assertEqual({path.name for path in output.iterdir()}, {"vproxy"} if fault in ("race", "after-link") else set())

    def test_main_exit_and_output_do_not_report_a_failed_install_as_success(self):
        with tempfile.TemporaryDirectory(prefix="vproxy-install-main-") as temporary:
            directory = Path(temporary) / "explicit private bin"
            destination = directory / "vproxy"
            for failure in (None, installer.InstallError("Injected validation failure"), PermissionError("Injected filesystem failure")):
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(installer, "install", return_value=destination, side_effect=failure) as install, contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = installer.main(["--bin-dir", str(directory)])
                install.assert_called_once_with(str(directory), "proxy")
                if failure is None:
                    self.assertEqual(result, 0)
                    self.assertIn("Installed:", stdout.getvalue())
                    self.assertEqual(stderr.getvalue(), "")
                else:
                    self.assertEqual(result, 1)
                    self.assertNotIn("Installed:", stdout.getvalue())
                    self.assertIn("Installation failed:", stderr.getvalue())
            for profile in ("proxy", "api", "web"):
                with patch.object(installer, "install", return_value=destination) as install, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(installer.main(["--bin-dir", str(directory), "--profile", profile]), 0)
                install.assert_called_once_with(str(directory), profile)


if __name__ == "__main__":
    unittest.main()
