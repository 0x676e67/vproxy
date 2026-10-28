# Monitor and troubleshoot

## Read the node card

Check the node identity and selected local/remote scope first. Then distinguish:

- Listener readiness: whether the expected proxy or HTTPS listener is running.
- Address health: whether an observed bind or TCP check succeeded recently.
- Egress: an actual observation of the address used to reach a destination.

A registered server IP is a label, not an egress measurement. Missing or expired
observations should remain unknown; zero traffic and unavailable traffic are
different states.

## Traffic

Traffic views separate node, user, credential, protocol and pool scopes. Retain
meter epochs and history-gap or loss indicators when comparing samples. Restarts,
retention and unavailable observations can make an interval incomplete.

Managed traffic counts accepted proxy payload. It is not a billable wire-byte
measurement, and a successful local write does not prove every byte reached the
remote application. A normal shutdown and an interrupted accounting history have
different evidence.

## Alerts and history

The header bell opens the unread list on this management node. Each entry shows
its source, resource and latest change, with a link to the matching history event.
Use **Mark all as read** to acknowledge the changes in the displayed inbox, or
mark an individual entry. Changes arriving afterward remain unread. These review
acknowledgements are shared on this node, rather than private per-browser flags.

If a request loses its response, review its result in event history before trying
again. The interface does not silently repeat an uncertain acknowledgement.

Open an alert to inspect its origin, resource, timestamps and evidence. Current
alerts describe current observations; persistent history retains earlier episodes
and acknowledgements across normal restarts. An acknowledgement records review;
it does not fix the resource or restart a service.

Remote collection can fail independently of the remote service. Keep collection
errors visible instead of treating an unreachable target as healthy or inventing
a successful observation.

## Webhook notifications

Notifications are disabled until a local browser administrator configures a
receiver. Use an HTTPS endpoint you control. The receiver must be publicly
addressable under the delivery policy; loopback and private-address destinations
are rejected. Automation tokens and remote node ownership do not grant permission
to change this local outbound authority.

Check the saved configuration and delivery result. Explicit retry is a separate
action, and a lost configuration response should be reconciled using its original
operation ID. Finishing a browser review does not send another notification.

## Collect a diagnostic report

```sh
vproxy manage diagnose --data-dir /var/lib/vproxy/management
```

This inspects the selected existing state offline and prints a redacted report.
It does not start listeners, probe an address or scan arbitrary logs. Read its
coverage and error fields before interpreting a missing observation. Review the
report before sharing it; keep databases, keys and raw credential files private.

For command options, use `vproxy manage diagnose --help`. For a failed connection,
check [Users and proxy connections](managed-proxy.md) before rotating credentials
or recreating users.
