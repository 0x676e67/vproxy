# vproxy documentation

Start with the guide for the way you want to use vproxy.

| Task | Guide |
| --- | --- |
| Install a binary or build from source | [Installation](installation.md) |
| Run an HTTP, HTTPS, SOCKS5 or MASQUE proxy | [Proxy usage](proxy.md) |
| Set up the Web interface and your first node | [Getting started with Web management](getting-started.md) |
| Start managed listeners and connect a client | [Users and proxy connections](managed-proxy.md) |
| Connect nodes and delegate control | [Node management](nodes.md) |
| Renew certificates or enable automatic browser HTTPS | [Certificates](certificates.md) |
| Back up state, restore a node or recover an administrator | [Backup and recovery](backup-recovery.md) |
| Install a service, pause admission or drain connections | [Operating a node](operations.md) |
| Check health, traffic, alerts and notifications | [Monitoring](observability.md) |
| Query the API or automate user changes | [Automation and API](automation.md) |
| Build, test or change the project | [Development](development.md) |

[Experimental recovery](experimental-recovery.md) covers identity snapshots and
witness records for operators evaluating those features. [Historical benchmarks](benchmarks.md)
describe an older local test setup.

The proxy-only build is the default. Management commands require the `management`
feature; the browser interface also requires `web-ui`. Management features are
under active development. Use `vproxy --version` and `vproxy manage --help` to
check the binary you have installed.

[Back to the project overview](../README.md).
