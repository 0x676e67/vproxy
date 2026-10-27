# Users and proxy connections

Start with a running management node. Use a [Web build](getting-started.md) for
browser administration; an API-only node can be managed by a Web controller.

## Start a listener

Open the local node card and its proxy-service controls. Configure the protocols,
listener addresses and limits you need, then start the service. Wait for a
successful applied result and a ready listener before testing a connection.

A listener address says where the server accepts connections. When exporting a
connection for another machine, use a reachable hostname or address instead of
`127.0.0.1`, `::1` or a wildcard bind address.

An installation started with a fixed `--proxy-config` uses that file as its startup
configuration. Its service settings are read-only in the Web interface. Prepare
a new configuration and launch plan to change that kind of installation.

## Create a user and credential

1. Select the node that should own the user. Check the local/remote scope shown
   by the interface before making a change.
2. Create the user and enable the required protocols. Set a connection limit
   appropriate for that user.
3. Open **Connections** and create a proxy credential for the user.
4. Select **Open connection**. The panel reads its saved password and previews
   the default endpoint. Choose another endpoint if needed, then generate the
   updated preview.
5. Copy the username, password, proxy URL or a curl/Python example. These examples
   include the password; no separate password entry is needed.

Creating a user alone does not create a usable password. A credential must be
active, its user must allow the chosen protocol, and the selected listener must
be running.

## Test the connection

The connection preview includes ready-to-run HTTP/HTTPS CONNECT and SOCKS5
CONNECT examples. They verify TLS normally and use a fixed example destination.
Generating or copying code does not test the connection. Password-bearing code
and files must stay private; a curl command can expose the password in shell
history and to local processes.

If you prefer not to put the password in a command, curl can prompt for it:

```sh
curl --proxy http://127.0.0.1:8080 --proxy-user EXPORTED_USERNAME https://example.com
```

For an HTTPS proxy, add the proxy CA when it uses a private certificate:

```sh
curl --proxy https://proxy.example.com:8443 --proxy-cacert proxy-ca.pem   --proxy-user EXPORTED_USERNAME https://example.com
```

For SOCKS5, use `socks5h://HOST:PORT` with a compatible client. MASQUE requires an
HTTP/3 CONNECT-UDP client. Exporting a format does not establish that a client
implements every protocol feature.

Management builds also provide `vproxy manage test-connection --help` for testing
one exported connection locally. This command sends real traffic and affects
metering.

## Find the connection again

After refresh, reopening the browser or a normal node restart, sign in and open
the same user's connection panel. It displays the current password while the
credential remains active and its encrypted secret is available. The browser
remembers addresses and protocols, not passwords or client code. Retain the
node's private state files so it can decrypt saved secrets.

An older credential may have no saved password copy. The panel reports that
condition without rotating it automatically. Rotate it explicitly if a new
password is needed.

Rotation changes the password and invalidates the previous generation. Revocation
permanently disables a credential. Retrieve the current generation instead of
creating another user merely to recover a connection description.

## Understand change results

- **Saved**: the node stored the policy.
- **Applied**: the live proxy engine accepted that policy.
- **Result unknown**: the response was lost or the original operation cannot yet
  be confirmed. Read the original result before submitting another change.

Keep the original node, operation or request ID when navigating away from a
pending change. A later status read describes the current node; it may not prove
what an earlier request did.

## Routing and device presets

Address pools and permissions restrict a user's available egress choices. Built-in
TCP presets choose an allowed device profile; they do not grant an address or
turn an unavailable endpoint into a working connection. The server's registered
IP is display metadata, separate from the address used for proxy egress.

See [Node management](nodes.md) for remote scope and [Monitoring](observability.md)
for health and traffic observations.
