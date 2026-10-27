# Historical local benchmarks

These results came from the older README's vproxy 2.5.1 comparison. They describe
a local virtual-machine setup, not the current version's production capacity.

- Host CPU: Apple M3 Max, 16 cores, 4.06 GHz.
- Guest: Ubuntu 25.04 aarch64, kernel 6.15.11-orbstack-00542-g4f455d264886.
- Tools: iperf3 3.18 and proxychains-ng 4.17.
- Path: iperf3 client → local SOCKS5 proxy → iperf3 server.

Receiver throughput reported by the original ten-second runs:

| Proxy | Forward, 10 streams | Reverse, 1 stream | Reverse, 10 streams |
| --- | --- | --- | --- |
| vproxy 2.5.1 | 359 Gbit/s | 99.5 Gbit/s | 367 Gbit/s |
| hev-socks5-server 2.7.0 | 401 Gbit/s | 99.3 Gbit/s | 387 Gbit/s |
| fast-socks5 1.0.0-rc.0 | 211 Gbit/s | 37.4 Gbit/s | 178 Gbit/s |

The comparison used [hev-socks5-server](https://github.com/heiher/hev-socks5-server)
and [fast-socks5](https://github.com/dizda/fast-socks5).

The client commands were `proxychains iperf3 -c 127.0.0.1 -P 10`, the same command
with `-R` for reverse traffic, and `-R` without `-P 10` for a single reverse stream.
Virtualization, loopback and shared host resources affect these measurements.
Repeat a comparison under your own workload before using it to size a deployment.
The original terminal output remains in the repository history.
