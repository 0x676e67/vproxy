#!/usr/bin/env bash
# Bash 3 is enough; Python's standard library handles JSON and archive types.
# No sudo, dependency installation, service changes or executable launch.
set -eu
command -v python3 >/dev/null 2>&1 || {
  printf 'Installation requires Python 3.12+; install it or use a manual release archive.\n' >&2
  exit 1
}
exec python3 - "$@" <<'VPROXY_INSTALL_PY'
import argparse
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
MAX_TAR_BYTES = 256 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_TEXT_BYTES = 1024 * 1024
CHUNK_BYTES = 64 * 1024
TRANSFER_SECONDS = 90
REPOSITORY = "https://github.com/0x676e67/vproxy"
LATEST = "https://api.github.com/repos/0x676e67/vproxy/releases/latest"
PROFILES = {"proxy": "", "api": "-api", "web": "-web"}


class InstallError(Exception):
    """A failed precondition or transfer; never retry by skipping verification."""


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        # GitHub assets redirect to a different host, but never to plaintext.
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise InstallError("Refusing a non-HTTPS redirect")
        return super().redirect_request(request, response, code, message, headers, newurl)


def target_for(system, machine):
    """Resolve only supported Linux/macOS userspace release targets."""
    linux = {
        "x86_64": "x86_64-unknown-linux-musl",
        "amd64": "x86_64-unknown-linux-musl",
        "aarch64": "aarch64-unknown-linux-musl",
        "arm64": "aarch64-unknown-linux-musl",
        "armv7l": "armv7-unknown-linux-musleabihf",
        "arm": "arm-unknown-linux-musleabihf",
        "i686": "i686-unknown-linux-musl",
    }
    darwin = {"x86_64": "x86_64-apple-darwin", "arm64": "aarch64-apple-darwin",
              "aarch64": "aarch64-apple-darwin"}
    target = {"Linux": linux, "Darwin": darwin}.get(system, {}).get(machine)
    if target is None:
        raise InstallError("Unsupported system or architecture; use a manual release archive")
    return target


def profile_suffix(profile):
    if not isinstance(profile, str) or profile not in PROFILES:
        raise InstallError("Unknown release profile")
    return PROFILES[profile]


def release_names(release, target, profile="proxy"):
    """Select one exact profile name; missing assets must never select another."""
    suffix = profile_suffix(profile)
    if not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False:
        raise InstallError("Expected a published stable release")
    tag = release.get("tag_name")
    if not isinstance(tag, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag) is None:
        raise InstallError("Invalid release tag")
    version = tag[1:] if tag.startswith("v") else tag
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", version) is None:
        raise InstallError("Invalid archive version")
    archive = "vproxy-{}{}-{}.tar.gz".format(version, suffix, target)
    return tag, archive, archive + ".sha256"


def copy_bounded(source, destination, limit, deadline):
    """Bound actual bytes, not Content-Length; read1 avoids waiting to fill a chunk."""
    count = 0
    while True:
        if time.monotonic() >= deadline:
            raise InstallError("Transfer or decompression time budget expired")
        chunk = source.read1(min(CHUNK_BYTES, limit - count + 1))
        if time.monotonic() >= deadline:
            raise InstallError("Transfer or decompression time budget expired")
        if not chunk:
            return count
        count += len(chunk)
        if count > limit:
            raise InstallError("Download or expanded archive exceeds its size limit")
        destination.write(chunk)


def download(url, path, limit):
    """Use normal TLS verification and fail closed on HTTP, redirect or size errors.

    The 90s budget is checked between read1 calls; a blocked call can additionally
    take the 30s socket timeout. This is not a hard whole-process deadline.
    """
    if urllib.parse.urlsplit(url).scheme != "https":
        raise InstallError("Only HTTPS downloads are supported")
    request = urllib.request.Request(url, headers={"User-Agent": "vproxy-installer", "Accept": "application/vnd.github+json"})
    opener = urllib.request.build_opener(HttpsOnlyRedirect())
    deadline = time.monotonic() + TRANSFER_SECONDS
    try:
        with opener.open(request, timeout=30) as response:
            if response.status != 200 or urllib.parse.urlsplit(response.geturl()).scheme != "https":
                raise InstallError("Download did not return HTTPS status 200")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > limit):
                raise InstallError("Invalid or oversized download length")
            with path.open("xb") as output:
                count = copy_bounded(response, output, limit, deadline)
            if count == 0 or (length is not None and count != int(length)):
                raise InstallError("Download is empty or incomplete")
    except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException) as error:
        # Do not expose signed redirect query strings or proxy credentials.
        raise InstallError("HTTPS download failed; no executable was installed") from error


def expected_digest(path, archive):
    """Accept only G2's one-line shasum sidecar; never evaluate manifest paths."""
    payload = path.read_bytes()
    match = re.fullmatch(rb"([0-9a-f]{64})  " + re.escape(archive.encode("ascii")) + rb"\n?", payload)
    if match is None:
        raise InstallError("Invalid or mismatched SHA-256 sidecar")
    return match.group(1).decode("ascii")


def unpack(archive, destination, profile="proxy"):
    """Validate the exact profile inventory, then copy only its regular binary.

    Bound gzip output before tarfile parses extended headers. Reject PAX, GNU
    longname/sparse metadata, duplicates, links and nonzero trailing archives.
    Proxy mode retains legacy header/mode compatibility; API/Web require USTAR
    and release permissions. Their bounded UTF-8 notices are checked but not
    installed: the binary embeds its notices. No downloaded code is run.
    """
    profile_suffix(profile)
    expected = {"vproxy"}
    if profile != "proxy":
        expected.update({"LICENSE", "README.md"})
    if profile == "web":
        expected.add("LICENSE.ant-design-pro")
    raw = destination.with_name("payload.tar")
    try:
        with gzip.open(archive, "rb") as compressed, raw.open("xb") as output:
            tar_size = copy_bounded(compressed, output, MAX_TAR_BYTES, time.monotonic() + TRANSFER_SECONDS)
        if tar_size < 1536 or tar_size % 512:
            raise InstallError("Truncated or misaligned tar archive")
        with raw.open("rb") as source:
            seen, offset, binary = set(), 0, None
            while True:
                header = source.read(512)
                if len(header) != 512:
                    raise InstallError("Truncated tar header")
                if header == b"\0" * 512:
                    if tar_size - offset < 1024:
                        raise InstallError("Tar end blocks are missing")
                    # Do not parse anything after the first end block, including
                    # an appended archive hidden behind otherwise valid padding.
                    while tail := source.read(CHUNK_BYTES):
                        if tail.strip(b"\0"):
                            raise InstallError("Archive contains nonzero trailing data")
                    break
                # Inspect EVERY raw typeflag before decoding; TarFile.next()
                # would consume PAX/GNU metadata automatically between members.
                if header[156:157] not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                    raise InstallError("Expected only regular tar members")
                if profile != "proxy" and header[257:265] != b"ustar\x0000":
                    raise InstallError("Profile archive must use USTAR headers")
                member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                if (member.name not in expected or member.name in seen or member.linkname
                        or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.issparse()):
                    raise InstallError("Unexpected or duplicate profile archive member")
                limit = MAX_BINARY_BYTES if member.name == "vproxy" else MAX_TEXT_BYTES
                if not 0 < member.size <= limit:
                    raise InstallError("Archive member is empty or oversized")
                if profile != "proxy" and member.mode != (0o755 if member.name == "vproxy" else 0o644):
                    raise InstallError("Profile archive member has invalid permissions")
                payload_start = offset + 512
                payload_end = payload_start + ((member.size + 511) // 512) * 512
                if payload_end + 1024 > tar_size:
                    raise InstallError("Truncated or misaligned tar archive")
                if member.name == "vproxy":
                    binary = (payload_start, member.size)
                else:
                    text = source.read(member.size)
                    if len(text) != member.size or not text.decode("utf-8").strip():
                        raise InstallError("Archive notice is incomplete or empty UTF-8 text")
                seen.add(member.name)
                source.seek(payload_end)
                offset = payload_end
            if seen != expected or binary is None:
                raise InstallError("Archive is missing required profile members")
            source.seek(binary[0])
            remaining = binary[1]
            deadline = time.monotonic() + TRANSFER_SECONDS
            with destination.open("xb") as output:
                while remaining:
                    if time.monotonic() >= deadline:
                        raise InstallError("Binary copy time budget expired")
                    block = source.read(min(CHUNK_BYTES, remaining))
                    if time.monotonic() >= deadline:
                        raise InstallError("Binary copy time budget expired")
                    if not block:
                        raise InstallError("Archive binary is incomplete")
                    output.write(block)
                    remaining -= len(block)
                output.flush()
                os.fsync(output.fileno())
        destination.chmod(0o755)
    except (OSError, EOFError, ValueError, tarfile.TarError) as error:
        raise InstallError("Archive validation failed; no executable was installed") from error


def fetch_latest(path):
    download(LATEST, path, 1024 * 1024)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as error:
        raise InstallError("Invalid release metadata") from error


def install(bin_dir, profile="proxy"):
    """Install into a new file on the same filesystem, never replace an old one.

    Refuse existing regular files, directories and even dangling symlinks before
    network I/O. link() repeats the no-clobber condition atomically at publication.
    A failure reported after successful publication has an unknown outcome: inspect
    the exact destination rather than replaying an installation automatically.
    """
    profile_suffix(profile)
    target = target_for(platform.system(), platform.machine())
    if not str(bin_dir).strip():
        raise InstallError("--bin-dir must not be empty")
    try:
        directory = Path(bin_dir).expanduser().resolve()
    except (RuntimeError, ValueError) as error:
        raise InstallError("Invalid installation directory") from error
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "vproxy"
    if os.path.lexists(destination):
        raise InstallError("Destination already exists; keep it or choose another --bin-dir")
    with tempfile.TemporaryDirectory(prefix=".vproxy-install-", dir=directory) as temporary:
        stage = Path(temporary)
        tag, archive_name, checksum_name = release_names(fetch_latest(stage / "release.json"), target, profile)
        base = REPOSITORY + "/releases/download/" + tag + "/"
        archive, checksum = stage / archive_name, stage / checksum_name
        download(base + checksum_name, checksum, 1024)
        expected = expected_digest(checksum, archive_name)
        download(base + archive_name, archive, MAX_DOWNLOAD_BYTES)
        digest = hashlib.sha256()
        with archive.open("rb") as source:
            for chunk in iter(lambda: source.read(CHUNK_BYTES), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise InstallError("SHA-256 mismatch; no executable was installed")
        binary = stage / "vproxy"
        unpack(archive, binary, profile)
        # Same-filesystem hard links are atomic and no-clobber on Linux/macOS.
        # This does not provide directory fsync/power-loss durability guarantees.
        os.link(binary, destination)
    return destination


def main(argv=None):
    parser = argparse.ArgumentParser(description="Install a latest stable vproxy release profile without replacing existing files (Python 3.12+).")
    parser.add_argument("--bin-dir", default=str(Path.home() / ".local" / "bin"), help="installation directory (default: ~/.local/bin)")
    parser.add_argument("--profile", choices=PROFILES, default="proxy", help="release profile (default: proxy; api or web must be selected explicitly)")
    args = parser.parse_args(argv)
    try:
        if sys.version_info < (3, 12):
            raise InstallError("Python 3.12+ is required")
        destination = install(args.bin_dir, args.profile)
    except (InstallError, OSError) as error:
        print("Installation failed: {}".format(error), file=sys.stderr)
        print("If the destination exists, inspect it before retrying; it was not replaced.", file=sys.stderr)
        return 1
    print("Installed: {}".format(destination))
    print("Add its directory to PATH if needed. No service was started.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
VPROXY_INSTALL_PY
