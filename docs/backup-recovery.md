# Backup and recovery

## Back up management state

Stop the management instances using the directory, then create a new backup:

```sh
vproxy manage backup --data-dir /var/lib/vproxy/management   --output /secure/backups/edge-01-backup
vproxy manage verify-backup --input /secure/backups/edge-01-backup
```

The backup contains sensitive user and authorization data. Store it privately.
Verification checks the package; it does not install it or change live state.
Ordinary database backups do not preserve all node identity keys and startup
configuration. Use an [identity snapshot](experimental-recovery.md) only when you
also need that broader, explicitly reviewed package.

## Restore as a new node

A normal restore imports drafts under a new identity. Choose a destination that
does not exist, even as an empty directory. Keep it separate from the backup.

```sh
vproxy manage restore --as-new-node   --input /secure/backups/edge-01-backup   --data-dir /var/lib/vproxy/edge-01-recovered   --node-name edge-01-new.example.com
vproxy manage recovery status --data-dir /var/lib/vproxy/edge-01-recovered
```

The terminal asks for the new display name, administrator and password. The TLS
name is a single DNS hostname or IP address, without a URL scheme or port.
Automation can use `--name`, `--administrator` and `--password-stdin`; keep the
password in a protected file rather than a command argument.

The import creates a new node ID, key and certificate request. Restored users and
routing data need review; old proxy credentials, automation grants and peer trust
do not become active credentials for this new identity.

Review the recovery status, then finalize the exact recovery ID it reports:

```sh
vproxy manage recovery finalize --data-dir /var/lib/vproxy/edge-01-recovered   --expected-id RECOVERY_ID
```

Use `manage setup recover --help` to prepare the recovered node's browser and
node identities, have its public request signed, and create a new launch plan.
Re-register it with controllers as a new node. Finalizing review does not itself
start listeners or make the recovered node reachable.

## Recover an administrator password

If the current password is known, change it from the signed-in browser account
settings. The change invalidates existing administrator sessions; sign in again.

If it is lost, stop management, prepare a private password file and run:

```sh
vproxy manage reset-password --data-dir /var/lib/vproxy/management   --administrator admin --password-stdin   --backup /secure/backups/before-password-recovery.sqlite3   < /secure/new-admin-password
```

Retain the backup and restart through the installation's normal launch plan. The
command recovers an existing administrator; it does not change proxy passwords.
A lost command response may require inspecting the existing result before retrying.

## Upgrade an older database

Stop the processes using it and supply a new backup path:

```sh
vproxy manage migrate --data-dir /var/lib/vproxy/management   --backup /secure/backups/before-migration.sqlite3
```

Inspect the result before starting the new binary. Reading a status page is not
permission to migrate, and a backup is not a shortcut for rolling an active node
back to an earlier identity.

HTTP/HTTPS accounting separation requires schema 29. The migration keeps old
combined counters and starts separate counters for new traffic; user permissions
do not change. To roll back this upgrade, restore the stopped node's consistent
pre-upgrade database together with its matching program. Replacing only the
binary is not a database rollback.
