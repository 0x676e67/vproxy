# Installation

## Choose a build

| Build | What it provides |
| --- | --- |
| Proxy | HTTP, HTTPS, SOCKS5 and MASQUE; the default Cargo build |
| API | Proxy support, persistent users, node control and an HTTPS management API |
| Web | Everything in API, plus an embedded browser interface |

API and Web builds use the `management` and `web-ui` features respectively.
A release must contain the requested variant; the installer will not substitute
another variant when an archive is missing. Build from a checkout when the variant
you need has not been released.

## Install with Cargo

The project currently requires Rust 1.97 or newer.

```sh
cargo install vproxy
```

This installs the proxy build. For management builds, use the source-build steps below.

## Download a release

Use the archive for your operating system, architecture and chosen build from
[GitHub releases](https://github.com/0x676e67/vproxy/releases).
Check its matching `.sha256` file before extracting it. A checksum detects a
changed download; it is not a separate publisher signature.

Linux and macOS users can use the shell installer with Bash and a patched Python
3.12 or newer. Download the script before running it:

```sh
install_script=$(mktemp) &&
  curl --disable --fail --show-error --silent --location \
    --proto '=https' --proto-redir '=https' \
    --output "$install_script" \
    https://raw.githubusercontent.com/0x676e67/vproxy/main/.github/install.sh &&
  bash "$install_script"
```

The default destination is `~/.local/bin`. Add it to `PATH` if needed. The installer
keeps existing files and does not start a service. Use `--bin-dir PATH` for another
directory, or `--profile api` / `--profile web` for a management build. Inspect or
remove the temporary script afterwards. Windows users should use an archive or Cargo;
WSL uses the Linux installer.

## Build from a checkout

For a proxy:

```sh
cargo build --release
```

For the management API without frontend assets:

```sh
cargo build --release --no-default-features --features management
```

For the Web interface, first build the frontend with Node.js 22.12 or newer:

```sh
cd web
npm ci
npm run build
cd ..
cargo build --release --no-default-features --features web-ui
```

The binary is in `target/release/`. Install it on your `PATH` before following the
management guides. The Web bundle is embedded; the running server needs neither
Node.js nor a separate frontend directory. Cargo checks that the bundle matches
its sources and rejects demo output.

## Docker

The repository image contains the proxy build:

```sh
docker run --rm -it -p 127.0.0.1:8100:8100   ghcr.io/0x676e67/vproxy:latest run http
```

Use the source builds above when you need management. Keep private state and keys
outside the source tree and container build context.

Next: [run a proxy](proxy.md) or [set up Web management](getting-started.md).
