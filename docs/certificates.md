# Certificates

vproxy uses certificates for three separate connections:

| Connection | What needs to trust it |
| --- | --- |
| Browser management HTTPS | The administrator's browser or API client |
| Node-to-node mutual TLS | Both nodes, plus each node's peer registry |
| HTTPS or MASQUE proxy | The proxy client |

Keep the corresponding keys and trust decisions separate. A certificate's valid
dates do not establish name coverage, peer authorization or network reachability.

## Manual certificate setup

[The setup guide](getting-started.md) creates private keys on each node and sends
only public requests to a signing machine. The offline signer issues fixed 90-day
leaf profiles. Keep the signing authority private and plan renewal before expiry.

A browser using a private management certificate needs the public management CA
installed through your normal trust process. Proxy clients use their own proxy-CA
settings. Node mTLS additionally requires the exact peer certificate to be registered.

## Renew a manually managed node

1. Sign the original node request into a new response directory.
2. On its original node, create a new launch plan referencing that response.
3. Register the replacement public node certificate on each peer that must accept
   it, using the current authorization revision.
4. Switch the process or service to the new plan and check both directions of mTLS.
5. Revoke the old public leaf only after the replacement has been verified.

```sh
vproxy manage setup sign --authority /secure/vproxy-authority   --request /secure/edge-01-request.json --output /secure/edge-01-signed-renewed
vproxy manage setup plan --prepared /secure/edge-01   --response /secure/edge-01-signed-renewed --output /secure/edge-01-launch-renewed
vproxy manage setup check --input /secure/edge-01-launch-renewed
```

Retain the original node keys and identity. A new key or node ID is a different
recovery operation. New files, successful signing and a passing offline check
still need a running-process handover and peer probes. Generate a new service
plan when switching an installed management service.

## Automatic browser HTTPS

ACME manages the browser listener's certificate. It does not issue node mTLS or
proxy-listener certificates. Use a public DNS name and make the selected challenge
reachable from the CA. An explicit production selection is required for a trusted
public certificate; staging certificates are for testing.

For an existing management installation:

```sh
vproxy manage serve --data-dir /var/lib/vproxy/management   --bind 0.0.0.0:443 --public-origin https://admin.example.com   --acme --acme-accept-terms --acme-production   --acme-contact operator@example.com
```

For a prepared installation, pass the ACME options to `manage setup plan` instead.
Use `manage serve --help` to choose the challenge method and its bind address.
DNS must already point to the correct host. vproxy does not create DNS records or
open firewall ports.

Inspect an interrupted order before taking another action:

```sh
vproxy manage acme inspect --data-dir /var/lib/vproxy/management   --public-origin https://admin.example.com --environment production
```

If inspection offers recovery, follow the exact saved order's recovery procedure
and expected hash. Do not delete its cache or place another order just because
the previous response was lost.
