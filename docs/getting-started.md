# Set up Web management locally

This walkthrough creates one local node, opens its Web interface, and leads into
creating a working proxy connection. Install a [Web build](installation.md) first.
The shell examples below use a new private directory under your home directory.

## 1. Create a local signing authority

```sh
vproxy_lab="$HOME/vproxy-demo"
mkdir -m 700 "$vproxy_lab"
vproxy manage setup authority --output "$vproxy_lab/authority"
```

Keep the reported `public_sha256` for the next step. The authority output contains
public certificates and private signing keys. For this local walkthrough it stays
on the same computer, separate from the node. In a remote deployment, keep the
signing authority on its signing machine and transfer only public requests and
responses.

## 2. Prepare the node

```sh
vproxy manage setup prepare --output "$vproxy_lab/node" \
  --authority-public "$vproxy_lab/authority/public.json" \
  --authority-sha256 REPLACE_WITH_REPORTED_SHA256 \
  --admin-origin https://localhost:8443 \
  --node-origin https://localhost:8444
```

Enter a display name, administrator name and password when prompted. The command
creates the node's database, private keys and public certificate request. Each
output must be a new directory; existing output is kept rather than overwritten.

## 3. Sign the request

Review the node ID and HTTPS names, then run:

```sh
vproxy manage setup sign --authority "$vproxy_lab/authority" \
  --request "$vproxy_lab/node/public.json" --output "$vproxy_lab/signed"
```

For a separate signing machine, copy only the node's `public.json` request there,
and return only the signed response. The node's `admin.key`, `node.key` and `state/`
stay on the node. Signing does not register or authorize another node.

## 4. Create and run a launch plan

```sh
vproxy manage setup plan --prepared "$vproxy_lab/node" \
  --response "$vproxy_lab/signed" --output "$vproxy_lab/launch"
vproxy manage setup check --input "$vproxy_lab/launch"
sh "$vproxy_lab/launch/start.sh"
```

On Windows, use `pwsh -File PATH_TO_LAUNCH/start.ps1` instead. The launch plan
references this executable and these local files. Regenerate it if their paths or
checked configuration change. Its default listener addresses are loopback.
Check the server's readiness output before opening the browser.

## 5. Open the browser

Trust the public management CA in `authority/admin-ca.pem` through your browser's
normal certificate-trust process. Do not import either `.key` file or substitute
the separate node-to-node CA. Then open `https://localhost:8443` and sign in with
the administrator created in step 2.

Management is now running. Continue with [Users and proxy connections](managed-proxy.md)
to start a proxy listener, create a user and credential, and test the connection.

For remote access, prepare the installation with the real HTTPS names clients
will use and choose explicit listener addresses. See [Certificates](certificates.md)
for public browser HTTPS and [Operating a node](operations.md) for service startup.
