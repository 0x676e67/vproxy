# vproxy

[![CI](https://github.com/0x676e67/vproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/vproxy/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/vproxy.svg)](https://crates.io/crates/vproxy)
[![License](https://img.shields.io/crates/l/vproxy)](LICENSE)

vproxy is a proxy server for HTTP, HTTPS, SOCKS5 and HTTP/3 CONNECT-UDP (MASQUE).
Run a standalone proxy, or add persistent users and a Web management interface.

It supports IPv4 and IPv6, authentication, connection limits, CIDR-based address
selection and device presets. SOCKS5 includes CONNECT, BIND and UDP ASSOCIATE.

## Start a local proxy

Install the default proxy build with Rust 1.97 or newer:

```sh
cargo install vproxy
vproxy run --bind 127.0.0.1:8100 http -u demo -p change-me
```

In another terminal, test it. Curl asks for the proxy password:

```sh
curl --proxy http://127.0.0.1:8100 --proxy-user demo https://example.com
```

This example listens on loopback. See [Proxy usage](docs/proxy.md) for HTTPS,
SOCKS5, MASQUE, listener limits and IPv6 routing. Other installation methods are
in [Installation](docs/installation.md).

## Use the Web interface

Choose a Web build and follow [Getting started](docs/getting-started.md) to prepare
a node, configure HTTPS and sign in. Then [start a listener, create a user and
export a working connection](docs/managed-proxy.md).

| Build | Choose it for |
| --- | --- |
| Proxy (default) | A standalone proxy configured from the command line |
| API (`management`) | A managed child node or an HTTPS API without frontend files |
| Web (`web-ui`) | Browser administration with an embedded frontend |

Management features are under active development. A Web build needs frontend
assets at build time; it needs no Node.js installation at runtime.

## Documentation

The [user guide](docs/README.md) has separate pages for installation, node setup,
connections, certificates, backups, operations, monitoring and automation.
The guides are also available in the [online source repository](https://github.com/0x676e67/vproxy/tree/main/docs).

For source changes, see [Development](docs/development.md).
[Historical benchmarks](docs/benchmarks.md) describe an older local comparison.
Use `vproxy --help` or a subcommand's `--help` for the options in your installed build.

## Help and contributing

Report bugs and discuss changes through [GitHub issues](https://github.com/0x676e67/vproxy/issues).
You can support development through [GitHub Sponsors](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md).

## License

GPL-3.0. See [LICENSE](LICENSE). The Web template's MIT notice is retained in
[web/LICENSE.ant-design-pro](web/LICENSE.ant-design-pro).
