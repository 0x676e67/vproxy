# Operate a node

## Run management as a Linux user service

Start with a checked [launch plan](getting-started.md). Generate a unit without
installing or starting it:

```sh
vproxy manage setup service --plan /secure/edge-01-launch   --output /secure/edge-01-service
vproxy manage setup check --input /secure/edge-01-service
```

The output reports `unit_file`, named `vproxy-management-NODE_ID.service`.
Install it through the user service manager under the same account that owns the
state and keys. Keep the executable and checked plan files at their original paths.
Use the reported unit name for `systemctl --user status`, `stop` or `restart`.

The separate `vproxy systemd` CLI manages a standalone proxy service. It is not a
replacement for the generated management unit.

## Pause new proxy operations

Use the node card's maintenance controls to pause admission. Check that the saved
policy has also been applied. Existing authorized work continues. Pausing does
not close every TCP connection or stop the management API.

Resuming admission is a separate confirmed action. A new owner or policy revision
can invalidate the original maintenance decision, so read the latest state first.

## Drain listeners

After pausing, request a listener drain in the node card. It stops new proxy work
and waits for existing operations to finish. Long-lived CONNECT, SOCKS5 BIND/UDP,
keepalive or QUIC sessions may keep it waiting.

A successful `drained` result means the local protocol drivers finished. An
interrupted or failed result is not success, even with zero remaining operations.
Management stays available while draining. Starting listeners again requires a
process restart and readiness check, followed by a separate admission-resume action.

If the browser closes or the response is lost, retain the original runtime and
request IDs and read that request's result. Do not send a new drain to query the
first one. A replacement process cannot prove the old process's outcome.

## Update or uninstall a binary

```sh
vproxy self update
vproxy self notices
```

The updater keeps the current build mode and requires the archive and matching
checksum for the compiled target. It will not silently switch an API/Web installation
to a proxy build. A binary replacement does not migrate a database or restart a
service; plan those steps separately.

Stop services before `vproxy self uninstall`. Keep private state and backups until
you have decided how to retain or remove them. If an update reports an uncertain
replacement, inspect the executable and saved result before repeating it.

See [Monitoring](observability.md) for alerts and a redacted diagnostic command.
