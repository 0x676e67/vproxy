[![CI](https://github.com/gngpp/vproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/gngpp/vproxy/actions/workflows/ci.yml)
[![CI](https://github.com/gngpp/vproxy/actions/workflows/release.yml/badge.svg)](https://github.com/gngpp/vproxy/actions/workflows/release.yml)
<a target="_blank" href="https://github.com/gngpp/vproxy/blob/main/LICENSE">
<img src="https://img.shields.io/badge/GPL-3.0-blue.svg"/>
</a>
<a href="https://github.com/gngpp/vproxy/releases">
<img src="https://img.shields.io/github/release/gngpp/vproxy.svg?style=flat">
</a>
</a><a href="https://github.com/gngpp/vproxy/releases">
<img src="https://img.shields.io/github/downloads/gngpp/vproxy/total?style=flat">
</a>

# vproxy

An easy and powerful Rust HTTP/Socks5 proxy that allows initiating network requests using IP binding calculated from CIDR addresses.

### Features

- IPv4/IPv6 priority
- Service binding `IP-CIDR` address
- Fallback address when `IP-CIDR` address is unreachable
- Basic authentication
- IP whitelist
- Proxy support (HTTP, SOCKS5)

### Install

- Curl

```shell
curl -s -o /tmp/install.sh https://raw.githubusercontent.com/0x676e67/vproxy/main/install.sh && bash /tmp/install.sh
```

- Cargo

```shell
cargo install vproxy
```

### Usage

If you run the program with sudo, it will automatically configure sysctl net.ipv6.ip_nonlocal_bind=1 and ip route add local 2001:470:e953::/48 dev lo for you. If you do not run it with sudo, you will need to configure these manually.

```shell
# Enable binding to non-local IPv6 addresses
sudo sysctl net.ipv6.ip_nonlocal_bind=1

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

# Online update
vproxy update

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

### Manual

If no subnet is configured, the local default network proxy request will be used. When the local machine sets the priority `Ipv4`/`Ipv6` and the priority is `Ipv4`, it will always use `Ipv4` to make requests (if any).

- When using passwordless authorization, if an IP whitelist exists, only authorized IPs can pass the request.
- Append `-session-id` to the username, where session is a fixed value and ID is an arbitrary random value (e.g., `username-session-123456`). Keep the Session ID unchanged to use a fixed IP.
- For HTTP users who are using password-less authorization and need a fixed IP address, you can add the `session-id` header to the request (e.g., `session-id: 123456`). By keeping the Session ID unchanged, you can use a fixed IP. Keep in mind Chrome and Firefox can't set `--proxy-header` like curl.
### Examples
#### Http proxy session with username and password:
```shell
./vproxy run --bind 127.0.0.1:8101 -i 2001:470:70c6::/48 http -u test -p test

$ for i in `seq 1 10`; do curl -x "http://test-session-123456789:test@127.0.0.1:8101" https://api6.ipify.org; done
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
$ for i in `seq 1 10`; do curl -x "http://test-session-987654321:test@127.0.0.1:8101" https://api6.ipify.org; done
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
```
#### Http proxy session with passwordless authorization:
```shell
./vproxy run --bind 127.0.0.1:8101 -w 127.0.0.1 -i 2001:470:70c6::/48 http

$ for i in `seq 1 3`; do curl --proxy-header "session-id: 123456789" -x "http://159.223.22.161:8101" https://api6.ipify.org; done
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
for i in `seq 1 3`; do curl --proxy-header "session-id: 987654321" -x "http://159.223.22.161:8101" https://api6.ipify.org; done
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
```
#### Socks5 proxy session with username and password
```shell
./vproxy run --bind 127.0.0.1:8101 -i 2001:470:70c6::/48 socks5 -u test -p test

$ for i in `seq 1 3`; do curl -x "socks5h://test-session-123456789:test@127.0.0.1:8101" https://api6.ipify.org; done
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
$ for i in `seq 1 3`; do curl -x "socks5h://test-session-987654321:test@127.0.0.1:8101" https://api6.ipify.org; done
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102

```

```shell
$ vproxy -h
An easy and powerful Rust HTTP/Socks5 Proxy

Usage: vproxy
       vproxy <COMMAND>

Commands:
  run      Run server
  start    Start server daemon
  restart  Restart server daemon
  stop     Stop server daemon
  ps       Show the server daemon process
  log      Show the server daemon log
  update   Update the application
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

$ vproxy run -h
Run server

Usage: vproxy run [OPTIONS] <COMMAND>

Commands:
  http    Http server
  socks5  Socks5 server
  help    Print this message or the help of the given subcommand(s)

Options:
      --debug                              Debug mode [env: VPROXY_DEBUG=]
  -b, --bind <BIND>                        Bind address [default: 0.0.0.0:8100]
  -c, --concurrent <CONCURRENT>            Concurrent connections [default: 1024]
  -T, --connect-timeout <CONNECT_TIMEOUT>  Connection timeout [default: 10]
  -w, --whitelist <WHITELIST>              IP addresses whitelist, e.g. 47.253.53.46,47.253.81.245
  -i, --cidr <CIDR>                        Ip-CIDR, e.g. 2001:db8::/32
  -f, --fallback <FALLBACK>                Fallback address
  -h, --help                               Print help
```

### Compile

- To compile on a Linux machine (e.g., Ubuntu):

```shell
git clone https://github.com/gngpp/vproxy.git && cd vproxy
cargo build --release
```

### Contributing

If you would like to submit your contribution, please open a [Pull Request](https://github.com/gngpp/vproxy/pulls).

### Getting help

Your question might already be answered on the [issues](https://github.com/gngpp/vproxy/issues)

### License

**vproxy** © [gngpp](https://github.com/gngpp), Released under the [GPL-30](./LICENSE) License.

Your question might already be answered on the [issues](https://github.com/gngpp/vproxy/issues)

### License

**vproxy** © [gngpp](https://github.com/gngpp), Released under the [GPL-30](./LICENSE) License.
