# Run a proxy

These commands use the proxy CLI. For saved users and browser-managed listeners,
follow [Users and proxy connections](managed-proxy.md).

## HTTP and SOCKS5

Start a local HTTP proxy with example credentials:

```sh
vproxy run --bind 127.0.0.1:8100 http -u demo -p change-me
```

In another terminal, make a request. Curl prompts for the proxy password:

```sh
curl --proxy http://127.0.0.1:8100 --proxy-user demo https://example.com
```

For SOCKS5, choose the protocol and port:

```sh
vproxy run --bind 127.0.0.1:1080 socks5 -u demo -p change-me
curl --proxy socks5h://127.0.0.1:1080 --proxy-user demo https://example.com
```

`socks5h` asks the proxy to resolve the destination hostname. SOCKS5 also supports
BIND and UDP ASSOCIATE for clients that implement them. The username and password
options on these CLI examples are visible to local process inspection. Use the
managed workflow when you need stored credentials and controlled password delivery.

## HTTPS

Provide the proxy's certificate and matching private key:

```sh
vproxy run --bind 127.0.0.1:8100 https   --tls-cert cert.pem --tls-key key.pem -u demo -p change-me
curl --proxy https://localhost:8100 --proxy-cacert proxy-ca.pem   --proxy-user demo https://example.com
```

The proxy certificate must match the hostname in the proxy URL. `--proxy-cacert`
trusts the proxy; normal destination-certificate verification remains enabled.
When no certificate is supplied, HTTPS creates a self-signed certificate in the
platform cache directory. A client must explicitly trust the appropriate CA or
certificate before using it.

## MASQUE

HTTP/3 CONNECT-UDP uses the `quic` subcommand:

```sh
vproxy run --bind 127.0.0.1:4433 quic   --tls-cert cert.pem --tls-key key.pem -u demo -p change-me
```

Use a client that implements RFC 9298 and trusts the proxy certificate. If your
client replaces its root bundle, retain the normal roots needed for HTTPS targets.

## Share a TCP listener

Auto mode detects HTTP, HTTPS and SOCKS5 on one TCP port:

```sh
vproxy run --bind 127.0.0.1:8100 auto -u demo -p change-me   --tls-cert cert.pem --tls-key key.pem
```

MASQUE uses a separate QUIC listener.

## Connection limits

`run --concurrent N` sets a positive per-listener limit, defaulting to 1024.
TCP sessions retain a slot through authentication and their remaining work.
SOCKS5 BIND and UDP ASSOCIATE retain it while their control connection remains open.
Auto mode shares one limit across its TCP protocols; MASQUE counts active tunnels.

At capacity, a listener waits before accepting more sockets. A client's TCP
connection can reach the operating-system backlog while its handshake waits, so
set a client timeout. Managed-user quotas are separate from listener limits.

## IPv6 and routing extensions

Use `run -i YOUR_CIDR` to select an address from a subnet you control. The host
needs the corresponding local routing and non-local-bind configuration. On Linux,
running with elevated privileges can change the network settings used by this
mode; review your host configuration before using it.

Username extensions choose a routing key:

| Suffix | Effect |
| --- | --- |
| `-session-ID` | Stable selection for the same session value and configuration |
| `-ttl-N` | Time-derived selection in N-second buckets |
| `-range-ID` | Stable range selection with the configured `--cidr-range` |

TTL is a duration, not a request count. Stable selection also depends on the
available addresses and routing policy. For managed users, device presets and
routing permissions can further limit which choices are available.

Use `vproxy run --help` and the chosen protocol's `--help` for the complete options.
