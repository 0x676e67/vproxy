# Automation and API

Use an API or Web build. Browser administration uses a session cookie and CSRF
protection; scripts use a separate scoped automation identity. Node mTLS and
proxy authentication are different interfaces.

## Create a read identity

Use an existing private output parent on the node:

```sh
vproxy manage automation create --data-dir /var/lib/vproxy/management   --name monitoring --valid-for 86400 --output /secure/edge-01.header
vproxy manage automation list --data-dir /var/lib/vproxy/management
```

The default scope is `users:read`. Validity must be between 60 seconds and 90 days.
The private output contains a complete Authorization header; list commands cannot
recover it. Keep its contents out of command arguments, URLs, traces and logs.

Read a page with the CLI:

```sh
vproxy manage query users --origin https://admin.example.com:8443   --ca /secure/admin-ca.pem --header-file /secure/edge-01.header --limit 25
```

Or use a client that reads the header from its protected file:

```sh
curl --disable --noproxy '*' --proto '=https' --connect-timeout 10 --max-time 10   --cacert /secure/admin-ca.pem --header @/secure/edge-01.header   'https://admin.example.com:8443/api/v1/proxy/users?limit=25'
```

The CLI validates the HTTPS origin, CA and response. Search continuations bind
the query and policy revision; restart a search when that context changes.
Ordinary paginated listing is not a single database snapshot.

## Rotate or revoke

Use the ID and current generation from `list`, and a new output file for rotation:

```sh
vproxy manage automation rotate --data-dir /var/lib/vproxy/management   --id PRINCIPAL_ID --expected-generation 1 --valid-for 86400   --output /secure/edge-01-next.header
vproxy manage automation revoke --data-dir /var/lib/vproxy/management   --id PRINCIPAL_ID --expected-generation 2
```

Rotation invalidates the old token and preserves its scope. Revocation is permanent.
After a lost issuance or rotation response, retain the output and inspect the
identity before retrying; the file or database change may already exist.

## Automate user changes

Create a separate identity with `--scope users:write`. It includes user reads and
allows the supported non-secret local user-operation workflow. It does not grant
credential access, proxy-password export, routing changes or remote control.

1. Read `manage query operations context` for the current node, owner and revision.
2. Save the intended non-secret change in a private JSON file.
3. Use `manage operations reserve` and retain the returned operation ID.
4. Execute that exact operation with the same change and assertions.
5. Query its result before attempting any replacement operation.

Use each command's `--help` and the exported automation contract for its required
fields. Do not combine a Bearer identity with browser cookies or proxy credentials.
An older database must be explicitly migrated before using write identities.

## Export the API reference

```sh
vproxy manage api-spec > management.openapi.json
vproxy manage api-spec --automation > automation.openapi.json
```

Exporting these OpenAPI 3.1 documents needs no database, credential or running
service. The first describes browser administration; the second covers scoped
local user reads and operations. It is the reference for request fields and routes.
Keep revision and counter values as decimal strings. An OpenAPI `operationId`
names a method; it is not the ID of a saved user operation or node command.

The HTTP response to a mutation can be lost after it commits. Retain and query
the exact original operation or ticket; a fresh status read or another POST is
not a substitute for that result.
