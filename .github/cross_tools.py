#!/usr/bin/env python3
"""Prepare pinned Linux x64 cross tools in a new job-owned directory.

Python 3.12+ is required. Rust/targets and MinGW belong to the workflow, not this
installer. --archives uses a local cache but still checks every archive SHA.
Failures retain their directory; no shell profile or system path is modified.
"""
import argparse
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import platform
import shlex
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request


TOOLS = (
    ('zig', '0.16.0', 'zig-x86_64-linux-0.16.0.tar.xz',
     'https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz',
     '70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00', ('version',)),
    ('cargo-zigbuild', '0.23.4', 'cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz',
     'https://github.com/rust-cross/cargo-zigbuild/releases/download/v0.23.4/cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz',
     '9e3cf73485edbd45905c8aadbc0fdf869c7ddc3848f0c898229f2680db52e44b', ('--version',)),
    ('upx', '5.2.1', 'upx-5.2.1-amd64_linux.tar.xz',
     'https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-amd64_linux.tar.xz',
     '402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657', ('--version',)),
)
MAX_DOWNLOAD = 128 * 1024 * 1024
MAX_EXPANDED = 1024 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class HttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        target = urllib.parse.urlsplit(url)
        require(target.scheme == 'https' and not target.username and not target.password,
                'Tool download redirect must use HTTPS without credentials')
        return super().redirect_request(request, response, code, message, headers, url)


def archive(tool, destination, cache=None):
    """Copy or download once, bounded, then authenticate against the pinned SHA."""
    _, _, name, url, expected, _ = tool
    deadline = time.monotonic() + 600
    if cache is not None:
        source = cache / name
        require(source.is_file() and not source.is_symlink() and source.resolve() == source,
                'Cached tool must be a real regular file')
        incoming = source.open('rb')
    else:
        opener = urllib.request.build_opener(HttpsRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        incoming = opener.open(urllib.request.Request(url,
            headers={'User-Agent': 'vproxy-cross-tools'}), timeout=30)
    size = 0
    value = hashlib.sha256()
    with incoming, destination.open('xb') as output:
        while True:
            require(time.monotonic() < deadline, 'Tool download deadline exceeded')
            block = incoming.read1(1024 * 1024)
            require(time.monotonic() < deadline, 'Tool download deadline exceeded')
            if not block:
                break
            size += len(block)
            require(size <= MAX_DOWNLOAD, 'Tool download size exceeded')
            value.update(block)
            output.write(block)
    require(size > 0 and value.hexdigest() == expected, 'Tool archive SHA256 mismatch')


def unpack(path, destination, executable):
    """Validate the bounded, SHA-checked archive before Python's data-filter extraction."""
    destination.mkdir(mode=0o700)
    # Bound all decompressed bytes, including extended headers, before tarfile
    # allocates member metadata. The anonymous scratch file is job-local.
    with tempfile.TemporaryFile(dir=destination.parent) as payload:
        size = 0
        with lzma.open(path, 'rb') as compressed:
            while block := compressed.read(1024 * 1024):
                size += len(block)
                require(size <= MAX_EXPANDED, 'Tool archive expansion exceeded')
                payload.write(block)
        payload.seek(0)
        with tarfile.open(fileobj=payload, mode='r:') as source:
            members = []
            total = 0
            for member in source:
                members.append(member)
                require(len(members) <= 100_000, 'Tool archive member count exceeded')
                name = PurePosixPath(member.name)
                require(not name.is_absolute() and '..' not in name.parts
                        and '\\' not in member.name and ':' not in member.name
                        and not any(ord(char) < 32 for char in member.name)
                        and (member.isfile() or member.isdir() or member.issym() or member.islnk()),
                        'Unsafe tool archive member')
                total += member.size
                require(0 <= member.size <= MAX_EXPANDED and total <= MAX_EXPANDED,
                        'Tool archive expansion exceeded')
            require(members, 'Tool archive is empty')
            source.extractall(destination, members=members, filter='data')
    binaries = [item for item in destination.rglob(executable)
                if item.is_file() and not item.is_symlink()]
    require(len(binaries) == 1, 'Expected one tool executable')
    binary = binaries[0]
    require(binary.resolve().is_relative_to(destination.resolve())
            and binary.stat().st_size > 0, 'Unsafe tool executable')
    binary.chmod(0o755)
    return binary


def prepare(work, cache=None):
    require(sys.version_info >= (3, 12), 'Python 3.12 or newer required')
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64',
            'Tool preparation requires Linux x86_64')
    work = work.absolute()
    require(work.parent.is_dir() and work.parent.resolve() == work.parent,
            'Expected a real existing parent directory')
    # mkdir is exclusive; a failed/old invocation cannot be silently reused.
    work.mkdir(mode=0o700)
    downloads = work / 'downloads'
    downloads.mkdir(mode=0o700)
    report = {'tools': [], 'scope': 'Pinned tools only; not a reproducible host environment'}
    paths = []
    zig = None
    for tool in TOOLS:
        name, version, filename, url, expected, arguments = tool
        print('Preparing ' + name + ' ' + version, flush=True)
        packed = downloads / filename
        archive(tool, packed, cache)
        binary = unpack(packed, work / name, name)
        result = subprocess.run([str(binary), *arguments], check=True, capture_output=True,
                                stdin=subprocess.DEVNULL, timeout=15)
        expected_version = version if name == 'zig' else name + ' ' + version
        require(result.stdout.decode('utf-8').splitlines()[0].strip() == expected_version,
                'Tool version mismatch')
        paths.append(str(binary.parent))
        if name == 'zig':
            zig = binary
        report['tools'].append({'name': name, 'version': version, 'url': url,
            'archive_sha256': expected, 'binary': str(binary), 'binary_sha256': digest(binary)})
    environment = {
        'RUSTUP_TOOLCHAIN': '1.97.0', 'RUSTUP_AUTO_INSTALL': '0',
        'CARGO_ZIGBUILD_ZIG_PATH': str(zig),
        'CARGO_ZIGBUILD_CACHE_DIR': str(work / 'zig-cache'),
        'ZIG_GLOBAL_CACHE_DIR': str(work / 'zig-global-cache'),
    }
    with (work / 'environment.sh').open('x', encoding='utf-8', newline='\n') as output:
        for key, value in environment.items():
            output.write('export ' + key + '=' + shlex.quote(value) + '\n')
        output.write('export PATH=' + shlex.quote(':'.join(paths)) + ':"$PATH"\n')
    with (work / 'tools.json').open('x', encoding='utf-8') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--archives', type=Path)
    arguments = parser.parse_args()
    prepare(arguments.directory, arguments.archives.absolute() if arguments.archives else None)


if __name__ == '__main__':
    main()
