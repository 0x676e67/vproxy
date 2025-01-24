[![Release](https://github.com/0x676e67/vproxy/actions/workflows/release.yml/badge.svg)](https://github.com/0x676e67/vproxy/actions/workflows/release.yml)
[![Crates.io License](https://img.shields.io/crates/l/vproxy)](./LICENSE)
![Crates.io MSRV](https://img.shields.io/crates/msrv/vproxy)
[![crates.io](https://img.shields.io/crates/v/vproxy.svg)](https://crates.io/crates/vproxy)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/vproxy)](https://crates.io/crates/vproxy)

# vproxy

> 🚀 Help me work seamlessly with open source sharing by [sponsoring me on GitHub](https://github.com/0x676e67/0x676e67/blob/main/SPONSOR.md)

A high-performance `HTTP`/`HTTPS`/`SOCKS5` proxy server

## Features

- IPv4/IPv6 priority
- Configurable concurrency limits
- Service binding `CIDR` address
- Specify a `CIDR` subnet range
- Basic authentication
- Proxy extensions

## Manual

```shell
$ vproxy -h
A high-performance HTTP/HTTPS/SOCKS5 proxy server

Usage: vproxy
       vproxy <COMMAND>

Commands:
  run      Run server
  start    Start server daemon
  restart  Restart server daemon
  stop     Stop server daemon
  ps       Show server daemon process
  log      Show server daemon log
  self     Modify server installation
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

$ vproxy run -h
Run server

Usage: vproxy run [OPTIONS] <COMMAND>

Commands:
  http    Http server
  https   Https server
  socks5  Socks5 server
  help    Print this message or the help of the given subcommand(s)

Options:
      --log <LOG>
          Log level e.g. trace, debug, info, warn, error [env: VPROXY_LOG=] [default: info]
  -b, --bind <BIND>
          Bind address [default: 0.0.0.0:1080]
  -T, --connect-timeout <CONNECT_TIMEOUT>
          Connection timeout in seconds [default: 10]
  -c, --concurrent <CONCURRENT>
          Concurrent connections [default: 1024]
  -i, --cidr <CIDR>
          IP-CIDR, e.g. 2001:db8::/32
  -r, --cidr-range <CIDR_RANGE>
          IP-CIDR-Range, e.g. 64
  -f, --fallback <FALLBACK>
          Fallback address
  -h, --help
          Print help
```

## Installation

<details>

<summary>If you need more detailed installation and usage information, please check here</summary>

### Install

- curl

```bash
curl https://raw.githubusercontent.com/0x676e67/vproxy/main/.github/install.sh | bash
```

- wget

```bash
wget -qO- https://raw.githubusercontent.com/0x676e67/vproxy/main/.github/install.sh | bash
```

- cargo

```bash
cargo install vproxy
```

- Dokcer

```bash
docker run --rm -it ghcr.io/0x676e67/vproxy:latest run http
```

### Note

If you run the program as root, it will automatically configure the sysctl `net.ipv6.ip_nonlocal_bind=1`, `net.ipv6.conf.all.disable_ipv6`, and `ip route add local 2001:470:e953::/48 dev lo` for you. Otherwise you will need to configure these settings manually.

If no subnet is configured, the local default network proxy request will be used. When the local machine sets the priority `Ipv4`/`Ipv6` and the priority is `Ipv4`, it will always use `Ipv4` to make requests (if any).

```shell
# Enable binding to non-local IPv6 addresses
sudo sysctl net.ipv6.ip_nonlocal_bind=1

# Enable IPv6
sudo sysctl net.ipv6.conf.all.disable_ipv6=0

# Replace with your IPv6 subnet
sudo ip route add local 2001:470:e953::/48 dev lo

# Run the server http/socks5
vproxy run -i 2001:470:e953::/48 http

# Start the daemon (runs in the background), requires sudo
sudo vproxy start -i 2001:470:e953::/48 http

# Restart the daemon, requires sudo
sudo vproxy restart

# Stop the daemon, requires sudo
sudo vproxy stop

# Show daemon log
vproxy log

# Show daemon status
vproxy status

# Download and install updates to vproxy
vproxy self update

# Uninstall vproxy
vproxy self uninstall

# Test loop request
while true; do curl -x http://127.0.0.1:8100 -s https://api.ip.sb/ip -A Mozilla; done
...
2001:470:e953:5b75:c862:3328:3e8f:f4d1
2001:470:e953:b84d:ad7d:7399:ade5:4c1c
2001:470:e953:4f88:d5ca:84:83fd:6faa
2001:470:e953:29f3:41e2:d3f2:4a49:1f22
2001:470:e953:98f6:cb40:9dfd:c7ab:18c4
2001:470:e953:f1d7:eb68:cc59:b2d0:2c6f

```

- TTL Extension

Append `-ttl-` to the username, where TTL is a fixed value (e.g., `username-ttl-2`). The TTL value is the number of requests that can be made with the same IP. When the TTL value is reached, the IP will be changed.

- Session Extension

Append `-session-id` to the username, where session is a fixed value and ID is an arbitrary random value (e.g., `username-session-123456`). Keep the Session ID unchanged to use a fixed IP.

- Range Extension

Append `-range-id` to the username, where range is a fixed value and ID is any random value (e.g. `username-range-123456`). By keeping the Range ID unchanged, you can use a fixed CIDR range in a fixed range. in addition, you must set the startup parameter `--cidr-range`, and the length is within a valid range.

### Examples

- Http proxy session with username and password:

```shell
vproxy run --bind 127.0.0.1:8101 -i 2001:470:70c6::/48 http -u test -p test

$ for i in `seq 1 10`; do curl -x "http://test-session-123456789:test@127.0.0.1:8101" https://api6.ipify.org; done
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5

$ for i in `seq 1 10`; do curl -x "http://test-session-987654321:test@127.0.0.1:8101" https://api6.ipify.org; done
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
```

- Socks5 proxy session with username and password

```shell
vproxy run --bind 127.0.0.1:8101 -i 2001:470:70c6::/48 socks5 -u test -p test

$ for i in `seq 1 3`; do curl -x "socks5h://test-session-123456789:test@127.0.0.1:8101" https://api6.ipify.org; done
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5

$ for i in `seq 1 3`; do curl -x "socks5h://test-session-987654321:test@127.0.0.1:8101" https://api6.ipify.org; done
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102

```

- TTL proxy session with username and password

```shell
vproxy run --bind 127.0.0.1:8101 -i 2001:470:70c6::/48 socks5 -u test -p test

$ for i in `seq 1 3`; do curl -x "socks5h://test-ttl-2:test@127.0.0.1:8101" https://api6.ipify.org; done
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f6

$ for i in `seq 1 3`; do curl -x "socks5h://test-ttl-2:test@127.0.0.1:8101" https://api6.ipify.org; done
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d105
```

</details>

## Contributing

If you would like to submit your contribution, please open a [Pull Request](https://github.com/0x676e67/vproxy/pulls).

## Getting help

Your question might already be answered on the [issues](https://github.com/0x676e67/vproxy/issues)

## License

**vproxy** © [0x676e67](https://github.com/0x676e67), Released under the [GPL-3.0](./LICENSE) License.
