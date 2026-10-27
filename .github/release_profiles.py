#!/usr/bin/env python3
"""Build non-publishing native artifacts from the actual Cargo source package.

Requires Python 3.12+, Cargo and rustc on PATH. Only the web mode requires an
already-built API bundle. Each run owns a new work directory; failed work is
retained for inspection, and no existing artifacts are overwritten or removed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib


FEATURES = {"proxy": "userspace", "api": "management", "web": "web-ui"}
MANAGEMENT_PACKAGES = {"argon2", "axum", "rusqlite"}
WEB_PACKAGES = {"rust-embed", "rust-embed-impl", "rust-embed-utils"}
ALLOCATOR_PACKAGES = {"mimalloc", "tikv-jemallocator", "tcmalloc", "snmalloc-rs", "rpmalloc"}
AWS_LC_PACKAGES = {"aws-lc-rs", "aws-lc-sys"}
# This public-only bundle is compiled into management builds. Keep its exact
# source-package path and LF bytes pinned; no other PEM or key material is allowed.
PUBLIC_TRUST_ANCHORS = {
    "src/manage/acme/staging-roots.pem": (
        5535, "0b549d3d047d7ab477a78f4c27bb1b2a15f5766619898ee8f21b7939566339a4",
    ),
}
MAX_FILES = 20_000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024


def run(arguments, directory, *, capture=False, timeout=1800):
    """Run once, without a shell or retries; preserve build diagnostics on failure."""
    print("+ " + " ".join(map(str, arguments)), flush=True)
    result = subprocess.run(
        list(map(str, arguments)), cwd=directory, check=True, timeout=timeout,
        text=True, encoding="utf-8", errors="strict",
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout if capture else None


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def package_members(archive, prefix):
    """Reject non-portable/private members before extracting a bounded local crate."""
    members = []
    names = set()
    total = 0
    for member in archive:
        path = PurePosixPath(member.name)
        if (
            not member.isfile() or len(path.parts) < 2 or path.parts[0] != prefix
            or path.is_absolute() or "\\" in member.name or ":" in member.name
            or any(ord(char) < 32 or ord(char) == 127 for char in member.name)
            or any(part in {"", ".", ".."} for part in member.name.split("/"))
            or any(
                part.endswith((".", " ")) or any(char in '<>"|?*' for char in part)
                or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?", part)
                for part in path.parts
            )
        ):
            raise ValueError("Source package contains an unsafe member")
        relative = PurePosixPath(*path.parts[1:])
        public_anchor = PUBLIC_TRUST_ANCHORS.get(relative.as_posix())
        if any(
            part in {".agents", ".git", "node_modules", "target"}
            or part.startswith(".umi") for part in relative.parts
        ) or (
            relative.suffix.lower() in {".key", ".pem", ".p12", ".pfx", ".sqlite3"}
            and public_anchor is None
        ):
            raise ValueError("Private or generated development files entered the package")
        if public_anchor is not None and member.size != public_anchor[0]:
            raise ValueError("Source package changed a pinned public trust anchor")
        folded = member.name.casefold()
        if folded in names or member.size < 0 or member.size > MAX_FILE_BYTES:
            raise ValueError("Source package contains a duplicate or oversized member")
        names.add(folded)
        total += member.size
        members.append(member)
        if len(members) > MAX_FILES or total > MAX_TOTAL_BYTES:
            raise ValueError("Source package exceeds its inventory limit")
    return members


def unpack(crate, destination, prefix, mode):
    """Extract only the validated source package, never the checkout or its target/."""
    with tarfile.open(crate, "r:gz") as archive:
        members = package_members(archive, prefix)
        names = {member.name.removeprefix(prefix + "/") for member in members}
        required = {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", "build.rs", "src/main.rs", "README.md", "LICENSE"}
        if not required <= names:
            raise ValueError("Source package is missing required build inputs")
        has_dist = any(name.startswith("web/dist/") for name in names)
        if mode == "web":
            if not {"web/dist/vproxy-web.json", "web/dist/index.html", "web/LICENSE.ant-design-pro"} <= names:
                raise ValueError("Web package is missing its built API bundle")
        elif has_dist:
            raise ValueError("Proxy/API checks require a checkout without web/dist")
        # A path-only exception could publish private material renamed as this
        # public bundle. Inspect the bounded member before extracting any file.
        for member in members:
            anchor = PUBLIC_TRUST_ANCHORS.get(member.name.removeprefix(prefix + "/"))
            if anchor is not None:
                contents = archive.extractfile(member)
                if contents is None:
                    raise ValueError("Source package is missing a pinned public trust anchor")
                with contents:
                    data = contents.read(anchor[0] + 1)
                if len(data) != anchor[0] or hashlib.sha256(data).hexdigest() != anchor[1]:
                    raise ValueError("Source package changed a pinned public trust anchor")
        archive.extractall(destination, members=members, filter="data")
    return destination / prefix, len(members)


def check_dependencies(tree, mode):
    """Check normal/build dependency closure, excluding test-only dependencies."""
    packages = {line.split()[0] for line in tree.splitlines() if line.strip()}
    if "vproxy" not in packages or packages & ({"aya-ebpf", "aya"} | ALLOCATOR_PACKAGES):
        raise ValueError("Unexpected native release dependency closure")
    if "ring" in packages or not AWS_LC_PACKAGES <= packages:
        raise ValueError("Native release requires AWS-LC without ring")
    if mode == "proxy":
        if packages & (MANAGEMENT_PACKAGES | WEB_PACKAGES):
            raise ValueError("Proxy build enabled management or embedded Web dependencies")
    elif not MANAGEMENT_PACKAGES <= packages:
        raise ValueError("Management dependencies are missing")
    if mode == "web":
        if not WEB_PACKAGES <= packages:
            raise ValueError("Embedded Web dependencies are missing")
    elif packages & WEB_PACKAGES:
        raise ValueError("Non-Web build enabled embedded Web dependencies")
    return sorted(packages)


def smoke(binary, mode, directory):
    """Check the packaged executable exists and exposes the intended build variant."""
    version = run([binary, "--version"], directory, capture=True, timeout=30).strip()
    help_text = run([binary, "--help"], directory, capture=True, timeout=30)
    has_manage = re.search(r"^\s+manage\s", help_text, re.MULTILINE) is not None
    if has_manage != (mode != "proxy"):
        raise ValueError("Executable does not match the selected management variant")
    if mode != "proxy":
        run([binary, "manage", "serve", "--help"], directory, capture=True, timeout=30)
    return version


def check_archive(path, destination, binary, notice=None):
    """Read the finished archive back and run only its extracted executable."""
    destination.mkdir()
    expected = {binary.name, "LICENSE", "README.md"}
    if notice is not None:
        expected.add(notice.name)
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) != len(expected) or {member.name for member in members} != expected:
            raise ValueError("Binary archive has unexpected contents")
        if any(not member.isfile() or member.size < 0 or member.size > MAX_FILE_BYTES for member in members):
            raise ValueError("Binary archive contains an invalid member")
        archive.extractall(destination, members=members, filter="data")
    extracted = destination / binary.name
    if digest(extracted) != digest(binary):
        raise ValueError("Binary archive changed the executable")
    if notice is not None and digest(destination / notice.name) != digest(notice):
        raise ValueError("Binary archive changed the frontend license notice")
    return extracted


def build(source, work, mode, cache=None):
    """Package, build and archive a native system-allocator variant without publishing."""
    manifest = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf-8"))
    version = manifest["package"]["version"]
    if manifest["package"]["name"] != "vproxy" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", version):
        raise ValueError("Unexpected source package identity")
    # CI owns an empty checkout per matrix cell. Fail rather than silently reuse
    # a Web bundle in API/proxy cells, or install Node as part of an API build.
    if mode != "web" and (source / "web/dist").exists():
        raise ValueError("Use a checkout without web/dist for proxy/API checks")
    work.mkdir()
    rustc = run(["rustc", "-vV"], source, capture=True, timeout=30).strip()
    host = next(line.removeprefix("host: ") for line in rustc.splitlines() if line.startswith("host: "))
    if not re.fullmatch(r"[A-Za-z0-9_-]+", host):
        raise ValueError("Unexpected Rust host target")
    package_target = work / "package-target"
    cargo = ["cargo", "--color", "never"]
    selection = ["--locked", "--no-default-features", "--features", FEATURES[mode]]
    run(cargo + ["package", "--allow-dirty", "--no-verify", "--target-dir", package_target] + selection, source)
    prefix = "vproxy-" + version
    crate = package_target / "package" / (prefix + ".crate")
    packaged, count = unpack(crate, work / "unpacked", prefix, mode)
    # Cargo emits a normalized lockfile when packaging (for example LF instead
    # of a Windows checkout's CRLF). Compare all parsed fields, not line endings.
    packaged_lock = tomllib.loads((packaged / "Cargo.lock").read_text(encoding="utf-8"))
    source_lock = tomllib.loads((source / "Cargo.lock").read_text(encoding="utf-8"))
    if packaged_lock != source_lock:
        raise ValueError("Packaging changed the locked dependency graph")
    tree = run(cargo + ["tree", "--target", host, "--edges", "normal,build", "--prefix", "none", "--format", "{p}"] + selection, packaged, capture=True)
    dependencies = check_dependencies(tree, mode)
    target = cache if cache is not None else work / "build-target"
    run(cargo + ["build", "--release", "--target", host, "--bin", "vproxy", "--target-dir", target] + selection, packaged)
    binary = target / host / "release" / ("vproxy.exe" if os.name == "nt" else "vproxy")
    artifacts = work / "artifacts"
    artifacts.mkdir()
    archive_path = artifacts / f"{prefix}-{mode}-{host}.tar.gz"
    notice = packaged / "web/LICENSE.ant-design-pro" if mode == "web" else None
    with tarfile.open(archive_path, "x:gz") as archive:
        archive.add(binary, arcname=binary.name, recursive=False)
        archive.add(packaged / "LICENSE", arcname="LICENSE", recursive=False)
        archive.add(packaged / "README.md", arcname="README.md", recursive=False)
        if notice is not None:
            archive.add(notice, arcname=notice.name, recursive=False)
    extracted = check_archive(archive_path, work / "archive-check", binary, notice)
    actual_version = smoke(extracted, mode, extracted.parent)
    if actual_version != "vproxy " + version:
        raise ValueError("Executable version does not match the source package")
    source_crate = artifacts / crate.name
    shutil.copyfile(crate, source_crate)
    report = {
        "schema": 1, "mode": mode, "version": version, "host": host,
        "features": [FEATURES[mode]], "no_default_features": True,
        "allocator": "system", "rustc": rustc,
        "python": sys.version,
        "package_members": count, "normal_build_packages": dependencies,
        "binary_sha256": digest(binary), "archive_sha256": digest(archive_path),
        "source_crate_sha256": digest(source_crate),
        "checkout_lock_sha256": digest(source / "Cargo.lock"),
        "packaged_lock_sha256": digest(packaged / "Cargo.lock"),
        "web_manifest_sha256": digest(packaged / "web/dist/vproxy-web.json") if mode == "web" else None,
        "publishing": False,
        "runtime_check": "archive-extracted version/help only; no service or database",
    }
    with (artifacts / "build.json").open("x", encoding="utf-8", newline="\n") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    with (artifacts / "SHA256SUMS").open("x", encoding="ascii", newline="\n") as output:
        for path in [archive_path, source_crate, artifacts / "build.json"]:
            output.write(f"{digest(path)}  {path.name}\n")
    print(json.dumps({"artifacts": str(artifacts), "mode": mode, "host": host}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=FEATURES, required=True)
    parser.add_argument("--work-dir", type=Path, required=True, help="new directory under an existing parent")
    parser.add_argument("--cache-dir", type=Path, help="optional Cargo build cache; do not share between concurrent runs")
    args = parser.parse_args()
    build(Path(__file__).resolve().parent.parent, args.work_dir.resolve(), args.mode,
          args.cache_dir.resolve() if args.cache_dir else None)


if __name__ == "__main__":
    main()
