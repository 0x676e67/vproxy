# Manage multiple nodes

Each node has its own database, users, proxy credentials and identity. A Web
controller can show other nodes and manage the policy they explicitly delegate.
An API build is sufficient on a child node.

## Register a peer

Node-to-node traffic uses mutual TLS, separate from browser HTTPS and proxy
passwords. Obtain the peer's node ID, node certificate, CA and expected TLS name
through a trusted process.

On the node accepting that peer:

```sh
vproxy manage peers register --data-dir /var/lib/vproxy/management   --node-id PEER_NODE_ID --name edge-02   --ca /secure/node-ca.pem --certificate /secure/edge-02-chain.pem   --server-name edge-02.example.com
vproxy manage peers list --data-dir /var/lib/vproxy/management
```

Register the required identities on both sides for a two-way relationship.
A valid CA chain alone does not authorize a peer: vproxy also checks the exact
registered certificate and its current authorization state.

You can test the relationship without editing proxy policy:

```sh
vproxy manage peers probe --data-dir /var/lib/vproxy/management   --endpoint https://edge-02.example.com:9443 --peer-id PEER_NODE_ID   --ca /secure/node-ca.pem   --cert /secure/edge-01-chain.pem --key /secure/edge-01-key.pem
```

## Add a target to the controller

Use the node setup guide in the Web interface to inspect the local node, add the
peer identity and register the target's node-control origin. Use the HTTPS name
from the node certificate. The optional server IP is a display label; it does not
replace the control origin, update DNS or verify public reachability.

Keep the target inactive until its identity and connection have been checked.
Selecting a remote scope changes where user searches and changes are performed.
The interface should continue to show that scope while an operation is pending.

## Delegate proxy-policy control

A registered peer does not automatically own another node's policy. Inspect the
child node's current owner and explicitly grant the chosen controller:

```sh
vproxy manage owner status --data-dir /var/lib/vproxy/management
vproxy manage owner grant --data-dir /var/lib/vproxy/management   --controller-node-id CONTROLLER_NODE_ID --expected-epoch CURRENT_EPOCH
```

Use the epoch reported by `status`. Keep the local identity and remote target
visible when confirming a write. To recover local ownership, consult
`vproxy manage owner --help` and inspect the current state before changing it.

## Follow a remote change

Remote changes can be saved before the live proxy applies them. Keep the original
ticket, read its result, and use the target's history to find earlier commands.
A replaced current ticket does not erase the history of the original command.

If a write times out or the browser is closed, read that exact original ticket.
Do not create another command to find out whether the first one ran. Revoked
peers, a changed owner or a replacement runtime can leave an old outcome unknown.

See [Certificates](certificates.md) when replacing a node certificate, and
[Operating a node](operations.md) before stopping listeners.
