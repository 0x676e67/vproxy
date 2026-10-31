export default {
  "menu.resources": "IP resources",
  "resources.title": "IP resources",
  "resources.description":
    "Manage the selected node’s finite egress inventory and shared pools.",
  "resources.localOnly": "Local node only",
  "resources.remoteScope": "Selected target’s resources",
  "resources.remoteScopeHint":
    "Enrollment is not control authorization. The child must explicitly grant this controller ownership. Unsupported or failed reads never fall back to this machine.",
  "resources.remoteWriteHint":
    "Writes require IPAM v2, the child’s current owner grant, an active target and no unresolved command. Refresh the policy after reviewing its receipt.",
  "resources.remoteIntentHint":
    "A saved intent may still execute. Do not repeat a creation with a new command. Inspect the durable ticket and refresh current policy; resource IDs can be recovered from the ticket, but historical entities are not reconstructed.",
  "resources.upgradeTarget":
    "This target does not support IPAM v2. Upgrade it before using these controls; the page stays read-only and never falls back to local resources.",
  "resources.inventoryHint":
    "Registration does not configure interfaces or routes, prove address ownership, or assert health. The concrete source address must already be usable on this node.",
  "resources.prefixes": "Prefixes",
  "resources.addresses": "Addresses",
  "resources.lookupTitle": "Find an address by ID",
  "resources.lookupId": "Address resource ID",
  "resources.lookupSubmit": "Find address",
  "resources.lookupOpen": "View this address",
  "resources.lookupBrowse": "View address list",
  "resources.lookupReading": "Reading this address's directory record…",
  "resources.lookupCancelled":
    "Address read cancelled. No current record is shown.",
  "resources.lookupTargetFailed":
    "The selected node could not be verified. No address was read.",
  "resources.lookupUnsupported":
    "This node does not support address lookup by ID.",
  "resources.lookupNotFound":
    "No address record was returned for this ID on the selected node.",
  "resources.lookupFailed":
    "The address could not be read. Read again to confirm its current record.",
  "resources.lookupReadOnly":
    "Address directory record, read only. To make changes, open the address list and read it again.",
  "resources.pools": "Shared pools",
  "resources.name": "Name",
  "resources.id": "Resource ID",
  "resources.cidr": "Canonical CIDR",
  "resources.ip": "Source IP",
  "resources.prefixId": "Prefix ID (optional)",
  "resources.family": "Address family",
  "resources.members": "Members",
  "resources.memberCount": "Registered members",
  "resources.revision": "Resource revision",
  "resources.globalRevision": "Global policy revision",
  "resources.health": "Health",
  "resources.healthHint":
    "This inventory is not a health snapshot. Open Health observations for scoped evidence. Active is a selection policy state, not a reachability result.",
  "resources.register": "Register",
  "resources.details": "Details",
  "resources.retire": "Permanently retire",
  "resources.drain": "Drain",
  "resources.resume": "Resume selection",
  "resources.active": "Active",
  "resources.draining": "Draining",
  "resources.retired": "Retired",
  "resources.registered": "Registered",
  "resources.retireHint":
    "Retirement is permanent and preserves the resource identity. It stops new finite exit/pool selections, not existing flows or host routes. Legacy CIDR routing can still derive the same IP. A prefix requires all contained addresses to be retired first.",
  "resources.drainHint":
    "Draining reversibly stops new finite exit/pool selections. It does not change host IPs/routes or exclude the same IP from legacy CIDR routing. Existing flows retain their source; resuming does not verify health.",
  "resources.prefixHint":
    "Use a canonical network such as 192.0.2.0/24 or 2001:db8::/64. A prefix is inventory metadata; it is never expanded into all possible addresses.",
  "resources.addressHint":
    "Register one concrete IP. If a prefix is supplied, the server verifies that the address belongs to it. Copy the prefix’s ID from its details.",
  "resources.poolHint":
    "A pool is finite, shared and single-family. Only explicitly registered members are considered; there is no exclusive allocation or global health guarantee.",
  "resources.cidrRule":
    "Enter an IP network with its prefix length; the server checks canonical form.",
  "resources.ipRule":
    "Enter one IPv4 or IPv6 address, without a port or scope identifier.",
  "resources.idRule":
    "Use a canonical 22-character resource ID, not an IP address.",
  "resources.addMember": "Add address",
  "resources.removeMember": "Remove member",
  "resources.memberHint":
    "Membership accepts an address ID of the same family. This page is cursor-paged; it does not load the complete pool.",
  "resources.removeHint":
    "Remove this address from the shared pool for new flows. Existing flows are not disconnected.",
  "resources.selector": "Username selector suffix",
  "resources.selectorHint":
    "Append exactly one -exit-<token> or -pool-<token> suffix to the machine login. The token is the stable ID’s 16 bytes as 32 lowercase hex digits, not a raw IP. Do not combine it with a session selector.",
  "resources.saved":
    "Saved global revision {revision}. Changes affect new flows only; saving is not a health result or a guarantee that a proxy is running.",
  "resources.permissionTitle": "Routing permissions — {name}",
  "resources.permission": "Routing permissions",
  "resources.permissionHint":
    "Grant only the selected node’s explicit addresses and pools. Unknown or failed reads do not enable a route. Changes apply to new flows, not existing connections.",
  "resources.legacyAllowed": "Allow legacy/default routing",
  "resources.legacyHint":
    "Allows this node’s existing CIDR/session/range routing, which may derive an IP even when that finite resource is draining or retired. Disable this permission to restrict a user strictly to explicit grants. This does not grant another user’s explicit resources.",
  "resources.exitsGrant": "Allowed address IDs",
  "resources.poolsGrant": "Allowed pool IDs",
  "resources.grantsHint":
    "Enter up to 32 distinct canonical IDs per field. Copy IDs from IP resources; do not enter selector tokens or raw IPs.",
  "resources.grantRule":
    "Use at most 32 distinct canonical resource IDs in each field.",
  "resources.denyAllHint":
    "Legacy/default routing is disabled and no address or pool is granted. This denies all new routing for this user. Existing flows continue with their original source.",
  "resources.permissionUnknown":
    "Routing permission is unknown. Refresh successfully before editing; no compatibility grant is assumed.",
  "resources.remoteUnsupported":
    "IP resource permissions are local-only in C3 v1. Manage them on the target node itself.",
  "resources.observations": "Health observations",
  "resources.observationHint":
    "Success belongs only to the listed bind or numeric TCP target. Bind-only checks do not establish public Internet, UDP, QUIC or prefix health. Missing and expired observations remain unknown; these checks do not change routing policy.",
  "resources.snapshotHint":
    "This is a manual snapshot, not live health. Reading it does not trigger probes. Age is reported by the node at retrieval; read again to check expiry. A new node process has a new boot ID and starts without observations.",
  "resources.readLatestSnapshot": "Read latest snapshot",
  "resources.guidanceTitle": "View guidance",
  "resources.guidance.bindSuccess":
    "This source IP bound locally for this check. Public Internet, UDP and QUIC connectivity remain untested.",
  "resources.guidance.tcpSuccess":
    "This source connected to the listed TCP target for this check. Other destinations, UDP and QUIC remain untested.",
  "resources.guidance.unknown":
    "No valid result is available. Read the latest snapshot and check the observer and inventory notices; do not treat this as an address failure.",
  "resources.guidance.address_unavailable":
    "On the selected node, check the source IP configuration and binding prerequisites.",
  "resources.guidance.connection_refused":
    "Check the source IP's network conditions. For TCP checks, also check the listed target's port, service and access rules. This result does not identify where the refusal occurred.",
  "resources.guidance.timed_out":
    "Check the source IP's network path and access rules. For TCP checks, also check the listed target. A timeout alone does not identify the cause.",
  "resources.guidance.permission_denied":
    "Check the selected node's service account and network permissions. Do not bypass security checks.",
  "resources.guidance.network_unreachable":
    "Check the selected node's source IP and routes. For TCP checks, also check the path to the listed target; other destinations may still be reachable.",
  "resources.guidance.failed":
    "Read the latest snapshot. If this keeps failing, inspect the selected node's service logs; no specific cause is confirmed.",
  "resources.guidance.family_mismatch":
    "Check the source IP's address family. For TCP checks, the configured target must use the same family: IPv4 or IPv6.",
  "resources.guidance.cancelled":
    "A cancelled check does not show that the address failed. Read the latest snapshot.",
  "resources.healthUnavailable":
    "The local health observer is unavailable. No reachability conclusion can be drawn.",
  "resources.catalogError":
    "The latest inventory read failed; new probes are paused. The catalog time and age still describe the last successful read, not the failed attempt.",
  "resources.catalogNotLoaded":
    "Inventory has not been loaded by the health observer; missing observations are unknown.",
  "resources.restartHint":
    "The node’s health process restarted. This snapshot belongs to a new boot ID; old observations are not carried across.",
  "resources.bootId": "Observer boot ID",
  "resources.sequence": "Observation sequence",
  "resources.catalogLoaded": "Inventory loaded",
  "resources.catalogObserved": "Last successful inventory read",
  "resources.catalogAge": "Inventory age at retrieval (ms)",
  "resources.inFlight": "Checks in progress",
  "resources.retrieved": "Snapshot retrieved",
  "resources.snapshotTitle": "Snapshot — retrieved {time} (not live)",
  "resources.pageSize": "Addresses per page",
  "resources.check": "Check",
  "resources.bind": "Local bind",
  "resources.tcp": "TCP connection",
  "resources.target": "Numeric target",
  "resources.observed": "Observed at",
  "resources.age": "Age at retrieval (ms)",
  "resources.latency": "Latency (ms)",
  "resources.unknown": "Unknown",
  "resources.success": "This check succeeded",
  "resources.address_unavailable": "Source address unavailable",
  "resources.connection_refused": "Target connection refused",
  "resources.timed_out": "Check timed out",
  "resources.permission_denied": "Local permission denied",
  "resources.network_unreachable": "Network unreachable",
  "resources.failed": "Check failed",
  "resources.family_mismatch": "Address family mismatch",
  "resources.cancelled": "Check cancelled",
  "resources.changePending": "Submitting resource change",
  "resources.changePendingHint":
    "Waiting for a reply. Leaving the page or checking the session cannot undo a saved change.",
  "resources.changeWaitingHint":
    "The task was accepted. Review the original task and current resources before starting another change.",
  "resources.changeRejectedHint":
    "The request was rejected before the write. Read the current state before starting a new change.",
  "resources.changeObservationHint":
    "This is the current state, not automatic confirmation or a replay of the old request. A matching name does not identify the result of a creation.",
  "resources.changeNotReady":
    "The current state does not yet allow a new change.",
  "resources.changeTicketChanged":
    "The current task differs from the retained task. It cannot confirm the earlier result.",
  "resources.readChangeState": "Read current resource state",
  "resources.changeNewResource": "New resource; ID not confirmed",
  "resources.changeMemberId": "Member address ID",
  "resources.changeMemoryHint":
    "This browser keeps a non-secret review note. It cannot restore a lost reply, password or permission to replay the request.",
  "resources.changeRestored": "Resource change needs review",
  "resources.changeRestoredHint":
    "A browser note was restored. Read the current state before starting a new change. Its task ID is only a hint and cannot enable retry or cancellation.",
  "resources.changeCapacity":
    "Too many nodes have changes awaiting review. Review the existing changes before starting another.",
};
