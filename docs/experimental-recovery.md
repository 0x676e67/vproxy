# Experimental identity recovery

The usual recovery path is a [backup imported as a new node](backup-recovery.md).
Identity snapshots and witness records serve a different purpose and require an
explicit recovery design. They are not an automatic failover switch.

## Identity and configuration snapshots

An ordinary database backup omits identity keys and startup configuration.
A snapshot can capture selected identity and checked configuration files into a
private, quarantined package. Treat it as sensitive as the running node itself.

```sh
vproxy manage snapshot configure   --plan /secure/edge-01-launch --surface api-only   --output /secure/edge-01-snapshot-config
vproxy manage snapshot create --data-dir /var/lib/vproxy/edge-01   --config /secure/edge-01-snapshot-config/configuration.json   --output /secure/backups/edge-01-identity
vproxy manage snapshot verify --input /secure/backups/edge-01-identity
```

Choose the surface that matches the plan; consult `snapshot configure --help`
for Web or other supported surfaces. Configuration capture checks selected inputs;
it does not make a live old node safe to run beside an identity copy.

## Witness records

`manage witness` maintains external records used by the recovery foundation.
The experimental source transaction runtime has been retired. Existing source
markers and database bindings still block ordinary startup and writes; removing
the runtime does not release a protected identity. Ordinary backups, quarantined
identity snapshots, and external witness records remain available.

Before evaluating witnessed recovery, decide who owns the independent witness,
how the old node is fenced, which snapshot/configuration is authoritative, and
what data-loss and recovery-time bounds your deployment requires. Preserve unknown
outcomes and reconcile the original operation rather than advancing a replacement.

Use `vproxy manage witness --help` and `vproxy manage snapshot --help` for the
available offline inspection and record operations. Keep witness and recovery
material separate from ordinary proxy credentials and browser trust.

A passing package verification proves the checks it reports. This build cannot
start a protected source or complete a same-identity recovery.
