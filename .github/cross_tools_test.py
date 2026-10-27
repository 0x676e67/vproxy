"""Offline boundary checks; no network request or downloaded tool is executed."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import urllib.request


SPEC = importlib.util.spec_from_file_location('cross_tools_under_test', Path(__file__).with_name('cross_tools.py'))
if SPEC is None or SPEC.loader is None:
    raise RuntimeError('Cannot load the adjacent tool helper')
tools = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tools)


def regular(name, data=b'fixture executable, never executed\n'):
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mode = 0o644
    return member, data


def write_archive(path, members):
    with tarfile.open(path, 'x:xz') as archive:
        for member, data in members:
            archive.addfile(member, io.BytesIO(data) if data is not None else None)


class CrossToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.version_info < (3, 12):
            raise RuntimeError('Run with patched Python 3.12 or newer')

    def cached_tools(self, root):
        cache = root / 'archive cache'
        cache.mkdir()
        fixtures = []
        for name, version, filename, url, _expected, arguments in tools.TOOLS:
            packed = cache / filename
            write_archive(packed, [regular(name + '-bundle/' + name)])
            fixtures.append((name, version, filename, url,
                             hashlib.sha256(packed.read_bytes()).hexdigest(), arguments))
        return cache, tuple(fixtures)

    def test_sha_and_download_size_failure_stop_before_unpack_or_probe(self):
        for failure in ('sha', 'cache-size', 'https-size'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix='vproxy-tool-download-') as temporary:
                root = Path(temporary)
                cache = root / 'cache'
                cache.mkdir()
                payload = b'fixture compressed bytes'
                (cache / 'zig.tar.xz').write_bytes(payload)
                tool = ('zig', '0.16.0', 'zig.tar.xz', 'https://download.invalid/zig.tar.xz',
                        '0' * 64 if failure == 'sha' else hashlib.sha256(payload).hexdigest(), ('version',))
                work = root / 'fresh work'
                response = io.BytesIO(payload)
                opener = mock.Mock()
                opener.open.return_value = response
                with mock.patch.object(tools, 'TOOLS', (tool,)), \
                        mock.patch.object(tools, 'MAX_DOWNLOAD', len(payload) - 1 if failure != 'sha' else len(payload)), \
                        mock.patch.object(tools.platform, 'system', return_value='Linux'), \
                        mock.patch.object(tools.platform, 'machine', return_value='x86_64'), \
                        mock.patch.object(tools.urllib.request, 'build_opener', return_value=opener) as network, \
                        mock.patch.object(tools, 'unpack') as unpack, \
                        mock.patch.object(tools.subprocess, 'run') as probe:
                    with self.assertRaisesRegex(ValueError, 'SHA256 mismatch|size exceeded'):
                        tools.prepare(work, None if failure == 'https-size' else cache)
                    unpack.assert_not_called()
                    probe.assert_not_called()
                    if failure == 'https-size':
                        self.assertEqual(network.call_count, 1)
                        self.assertEqual(opener.open.call_count, 1)
                        self.assertTrue(response.closed)
                    else:
                        network.assert_not_called()
                self.assertTrue((work / 'downloads/zig.tar.xz').is_file(), 'Failed private download is retained')
                self.assertFalse((work / 'environment.sh').exists())
                self.assertFalse((work / 'tools.json').exists())

    def test_redirect_refuses_http_and_credentials_without_opening_a_destination(self):
        handler = tools.HttpsRedirect()
        request = urllib.request.Request('https://download.invalid/tool.tar.xz')
        for target in ('http://other.invalid/tool', 'https://user:password@other.invalid/tool'):
            with self.subTest(target=target):
                with mock.patch.object(urllib.request.HTTPRedirectHandler, 'redirect_request') as parent:
                    with self.assertRaisesRegex(ValueError, 'HTTPS without credentials'):
                        handler.redirect_request(request, None, 302, 'Found', {}, target)
                    parent.assert_not_called()
        redirected = handler.redirect_request(request, None, 302, 'Found', {}, 'https://other.invalid/tool')
        self.assertEqual(redirected.full_url, 'https://other.invalid/tool')

    def test_unpack_rejects_traversal_before_extracting(self):
        for name in ('../escaped', '/escaped', 'bundle/../../escaped', 'bundle\\escaped', 'drive:escaped'):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='vproxy-tool-path-') as temporary:
                root = Path(temporary)
                packed = root / 'tool.tar.xz'
                write_archive(packed, [regular(name)])
                with mock.patch.object(tarfile.TarFile, 'extractall') as extract:
                    with self.assertRaises(ValueError):
                        tools.unpack(packed, root / 'unpacked', 'zig')
                    extract.assert_not_called()
                self.assertFalse((root / 'escaped').exists())

    @unittest.skipUnless(os.name == 'posix', 'Real POSIX link/data-filter boundary')
    def test_data_filter_rejects_symlink_and_hardlink_escape(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='vproxy-tool-link-') as temporary:
                root = Path(temporary)
                outside = root / 'outside'
                outside.mkdir()
                marker = outside / 'operator-material'
                marker.write_bytes(b'preserve exactly\n')
                member = tarfile.TarInfo('jump')
                member.type = kind
                member.linkname = '../outside' if kind == tarfile.SYMTYPE else '../outside/operator-material'
                packed = root / 'tool.tar.xz'
                write_archive(packed, [(member, None), regular('jump/escaped')])
                with self.assertRaises((ValueError, tarfile.FilterError)):
                    tools.unpack(packed, root / 'unpacked', 'zig')
                self.assertEqual(marker.read_bytes(), b'preserve exactly\n')
                self.assertEqual({path.name for path in outside.iterdir()}, {'operator-material'})

    def test_total_expansion_limit_includes_extended_headers_before_tar_parsing(self):
        with tempfile.TemporaryDirectory(prefix='vproxy-tool-expand-') as temporary:
            root = Path(temporary)
            packed = root / 'tool.tar.xz'
            member, data = regular('zig', b'x')
            member.pax_headers = {'comment': 'x' * 12000}
            write_archive(packed, [(member, data)])
            # One payload byte fits, but its PAX metadata exceeds this total cap.
            with mock.patch.object(tools, 'MAX_EXPANDED', 10000), mock.patch.object(tools.tarfile, 'open') as parse:
                with self.assertRaisesRegex(ValueError, 'expansion exceeded'):
                    tools.unpack(packed, root / 'unpacked', 'zig')
                parse.assert_not_called()

    def test_missing_or_multiple_tool_binaries_are_rejected(self):
        for members in ([regular('bundle/readme')], [regular('one/zig'), regular('two/zig')]):
            with self.subTest(members=len(members)), tempfile.TemporaryDirectory(prefix='vproxy-tool-cardinality-') as temporary:
                root = Path(temporary)
                packed = root / 'tool.tar.xz'
                write_archive(packed, members)
                with self.assertRaisesRegex(ValueError, 'Expected one tool executable'):
                    tools.unpack(packed, root / 'unpacked', 'zig')

    def test_existing_work_is_not_reused_or_modified(self):
        with tempfile.TemporaryDirectory(prefix='vproxy-tool-existing-') as temporary:
            work = Path(temporary) / 'existing work'
            work.mkdir()
            marker = work / 'operator-material'
            marker.write_bytes(b'preserve exactly\n')
            with mock.patch.object(tools.platform, 'system', return_value='Linux'), \
                    mock.patch.object(tools.platform, 'machine', return_value='x86_64'), \
                    mock.patch.object(tools, 'archive') as archive, \
                    mock.patch.object(tools, 'unpack') as unpack, \
                    mock.patch.object(tools.subprocess, 'run') as probe:
                with self.assertRaises(FileExistsError):
                    tools.prepare(work)
                archive.assert_not_called()
                unpack.assert_not_called()
                probe.assert_not_called()
            self.assertEqual(marker.read_bytes(), b'preserve exactly\n')
            self.assertEqual({path.name for path in work.iterdir()}, {'operator-material'})

    def test_complete_mock_setup_publishes_environment_only_after_all_versions_pass(self):
        for outcome in ('success', 'wrong-version', 'failed-probe'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory(prefix='vproxy-tool-setup-') as temporary:
                root = Path(temporary)
                cache, fixtures = self.cached_tools(root)
                work = root / 'fresh work with spaces'
                results = [subprocess.CompletedProcess([], 0, (version if name == 'zig' else name + ' ' + version).encode() + b'\n', b'')
                           for name, version, _filename, _url, _expected, _arguments in fixtures]
                if outcome == 'wrong-version':
                    results[-1] = subprocess.CompletedProcess([], 0, b'upx unexpected-version\n', b'')
                elif outcome == 'failed-probe':
                    results[-1] = subprocess.CalledProcessError(23, ['fixture-version-probe'])
                with mock.patch.object(tools, 'TOOLS', fixtures), \
                        mock.patch.object(tools.platform, 'system', return_value='Linux'), \
                        mock.patch.object(tools.platform, 'machine', return_value='x86_64'), \
                        mock.patch.object(tools.urllib.request, 'build_opener') as network, \
                        mock.patch.object(tools.subprocess, 'run', side_effect=results) as probe:
                    if outcome == 'success':
                        report = tools.prepare(work, cache)
                        self.assertEqual(len(report['tools']), 3)
                        self.assertEqual(json.loads((work / 'tools.json').read_text())['tools'], report['tools'])
                        environment = (work / 'environment.sh').read_text()
                        self.assertIn('export RUSTUP_TOOLCHAIN=1.97.0\n', environment)
                        self.assertIn('export RUSTUP_AUTO_INSTALL=0\n', environment)
                        self.assertIn('CARGO_ZIGBUILD_ZIG_PATH=', environment)
                        self.assertIn(':"$PATH"\n', environment)
                    else:
                        failure = (self.assertRaisesRegex(ValueError, 'Tool version mismatch') if outcome == 'wrong-version'
                                   else self.assertRaises(subprocess.CalledProcessError))
                        with failure:
                            tools.prepare(work, cache)
                        self.assertFalse((work / 'environment.sh').exists())
                        self.assertFalse((work / 'tools.json').exists())
                    self.assertEqual(probe.call_count, 3)
                    network.assert_not_called()
                    for call, tool in zip(probe.call_args_list, fixtures, strict=True):
                        name, _version, _filename, _url, _expected, arguments = tool
                        binary = Path(call.args[0][0])
                        self.assertTrue(binary.is_relative_to(work / name))
                        self.assertEqual(call.args[0][1:], list(arguments))
                        self.assertEqual(call.kwargs['timeout'], 15)
                        self.assertTrue(call.kwargs['check'])
                self.assertEqual(len(list((work / 'downloads').iterdir())), 3, 'Private failed setup remains inspectable')


if __name__ == '__main__':
    unittest.main()
