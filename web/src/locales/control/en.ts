export default {
  "acme.title": "Management HTTPS",
  "acme.refresh": "Refresh status",
  "acme.scope":
    "Local process snapshot. Refreshing reads status only. Certificate availability does not confirm browser trust or public reachability.",
  "acme.manual":
    "This process uses a manually configured certificate. Automatic issuance and renewal are off.",
  "acme.stagingWarning": "Staging certificates are not trusted by browsers.",
  "acme.environment.staging": "Staging",
  "acme.environment.production": "Production",
  "acme.activity.waiting": "Waiting for the next attempt",
  "acme.activity.working": "Issuing or recovering an identity",
  "acme.activity.stopped": "Automatic certificate worker stopped",
  "acme.lastFailure": "Previous attempt",
  "acme.failure.attempt_unavailable":
    "The previous attempt did not complete normally. A usable certificate may still be active.",
  "acme.failure.review_required":
    "The previous certificate operation needs review. Check the local logs.",
  "acme.certificate": "Current certificate",
  "acme.available": "Available at the server's observation time",
  "acme.unavailable": "No usable certificate at the server's observation time",
  "acme.notActivated": "No identity activated in this process",
  "acme.validFrom": "Valid from",
  "acme.validUntil": "Valid until",
  "acme.challenge": "Challenge",
  "acme.nextAttempt": "Next attempt",
  "acme.noSchedule": "No waiting attempt scheduled",
  "acme.due": "Due; waiting for the worker",
  "acme.observed": "Read at server time",
  "acme.dateRange": "Outside the date display range",
  "acme.unsupported": "This server does not provide certificate status.",
  "control.scope": "Management scope",
  "control.invalidScope": "Invalid management scope",
  "control.invalidScopeHint":
    "This link contains an invalid or ambiguous node or filter. No node data was requested. Return to Nodes and select the intended node explicitly.",
  "control.localScope": "This node · local policy",
  "control.remoteScope": "Remote node policy",
  "control.nodesDescription":
    "Manage this node and explicitly registered destinations. Each node keeps its own proxy policy and runtime.",
  "control.changePending": "Saving node configuration",
  "control.changePendingHint":
    "Do not submit again. Leaving this page does not undo a request already sent.",
  "control.changeRejectedHint":
    "The request was rejected before the change was admitted. Read the current configuration before starting a new operation.",
  "control.changeNode": "Managing node",
  "control.changeAction": "Submitted operation",
  "control.changeExpectedRevision": "Destination revision before submission",
  "control.changeExpectedEpoch": "Control epoch before submission",
  "control.changeNewTarget": "New destination",
  "control.changeObservationHint":
    "Current local configuration, read separately. It does not confirm whether the earlier request succeeded or whether the remote node is reachable.",
  "control.changeMissing":
    "This destination is not queryable now. That does not prove the earlier request never executed.",
  "control.changeReviewHint":
    "Check the exact destination and owner. Continuing closes the old forms and permits a new operation; it does not resend the earlier request or confirm its outcome.",
  "control.readChangeState": "Read current node configuration",
  "control.continueChange": "I've checked; start a new operation",
  "control.changeMemoryHint":
    "Non-secret review notes stay in this browser across reloads and sign-ins to the same account. They are not server receipts or replay keys. Clearing browser data can remove them; always check current configuration before a new change.",
  "control.changeCapacity":
    "Retained node-change notes have reached the limit. Existing notes are kept; review them on their original account and node before starting another change.",
  "control.changeStorageBlocked":
    "Changes paused · check browser review storage",
  "control.changeStorage.unsupported":
    "This browser cannot coordinate saved review notes across tabs. Reading remains available, but changes are disabled. Use a browser with Web Locks and local storage.",
  "control.changeStorage.unavailable":
    "The browser could not save or remove a review note. No new change is sent without a saved note; a request already sent may still execute. Reads remain available. Keep existing browser data and check its storage settings.",
  "control.changeStorage.invalid":
    "Stored review metadata is invalid or was replaced. Changes are disabled; no stored note is replayed or treated as a receipt. Read the current state and retain the browser data for inspection.",
  "control.changeStorage.capacity":
    "Browser review storage has reached its note limit. Unresolved notes are not removed automatically. Read and explicitly acknowledge existing notes on their original account and node before a new change.",
  "control.changeIdentityPending":
    "Unconfirmed node-change notes are retained, but the current node identity is not confirmed. Refresh before making another change.",
  "control.registryNotice":
    "Registration, control permission and proxy operation are separate facts.",
  "control.grantRequired":
    "Enroll both nodes' certificates offline first. On the child, explicitly grant policy control to this controller's node ID. Adding a destination here does not grant that permission.",
  "control.enrollmentRequired":
    "The node ID and certificate must already be enrolled locally. This form saves a destination; it does not trust a new certificate.",
  "control.addTarget": "Add destination",
  "control.editTarget": "Configure destination",
  "control.nodeId": "Enrolled node ID",
  "control.idRule": "Use the canonical 22-character node ID from enrollment",
  "control.origin": "Node mTLS origin",
  "control.originHint":
    "Use the node listener, not the browser or proxy port. HTTPS origin only, without path, credentials, query or trailing slash.",
  "control.originRule":
    "Use a canonical HTTPS origin, such as https://node.example:9443",
  "control.serverIp": "Server IP (registered)",
  "control.serverIpHint":
    "Optional numeric IPv4/IPv6, recorded on this manager for display. Leave blank to clear. This value does not change connection addresses, certificate checks or proxy routing, and does not verify public reachability or identify proxy egress.",
  "control.serverIpRule":
    "Enter a numeric IPv4/IPv6 address without a port, brackets or subnet prefix. Unspecified, broadcast and multicast addresses are not allowed.",
  "control.serverIpUnregistered": "Not registered",
  "control.egressIp": "Proxy egress IP",
  "control.egressUnknown": "Dynamically selected · not observed",
  "control.egressHint":
    "Proxy policy, IP pools and sessions select egress. This card does not probe public egress; server registration and local bind health are not public egress observations.",
  "control.manageIps": "Manage IP resources",
  "control.deliveryEnabled": "Enable delivery configuration",
  "control.localOwner": "This node's policy owner",
  "control.nodeDetails": "Details and configuration",
  "control.controller": "Authorized controller",
  "control.epoch": "Control epoch",
  "control.ownerHint":
    "A remote owner blocks local policy edits. Ownership changes advance the epoch and invalidate the previous command namespace; users and credentials stay unchanged.",
  "control.grant": "Grant control",
  "control.grantHint":
    "Grant policy management to an active enrolled peer. Even granting the same peer advances the epoch. Verify its stable node ID before confirming.",
  "control.takeover": "Take back local control",
  "control.takeoverHint":
    "Revoke the current control assignment and advance the epoch. Old remote commands can no longer apply. This does not remove users or terminate existing proxy operations.",
  "control.locallyManaged":
    "A remote controller owns this local policy; local editing is disabled.",
  "control.includeRetired": "Include retired destinations",
  "control.searchNodes": "Search registered nodes",
  "control.searchInvalid":
    "Search text is too long or contains control characters.",
  "control.searchEmpty": "No registered nodes match",
  "control.configured": "Delivery configured on",
  "control.paused": "Delivery paused",
  "control.retired": "Retired",
  "control.rollback": "Rollback detected · delivery blocked",
  "control.pause": "Pause delivery",
  "control.resume": "Resume delivery",
  "control.reactivate": "Reactivate delivery",
  "control.reactivateHint":
    "Reactivate this destination while retaining its unresolved command and all observation floors. Any pending intent may resume delivery. This does not restore a permanently revoked certificate or bypass epoch/rollback checks.",
  "control.retire": "Retire destination",
  "control.pauseHint":
    "Change future delivery admission. An already in-flight command may still execute; pausing is not cancellation or rollback. Pending intent is retained.",
  "control.retireHint":
    "Retire this local destination and pause future delivery, retaining unresolved intent and all observation floors. This does not cancel an operation the target already accepted or stop its independent proxy.",
  "control.tlsUnavailable":
    "Outbound node TLS is not configured. Local destination management is available, but remote reads and commands are unavailable.",
  "control.configRevision": "Destination revision",
  "control.observedEpoch": "Last observed control epoch",
  "control.observedPolicy": "Last observed saved policy",
  "control.healthUnknown":
    "Load IP health and traffic on demand from the Resources and Traffic pages; this card does not fetch those metrics.",
  "control.targetUnknown":
    "Registry configuration is not a reachability or health check. Open policy management for a verified remote read.",
  "control.manageUsers": "Manage proxy users",
  "control.command": "Latest durable command",
  "control.readTicket": "Read local ticket",
  "control.readCreatedUser": "Find created user",
  "control.readCreatedUserHint":
    "Checks this job's retained receipt and reads its exact user ID. No command is resent and no password is recovered. An expired receipt does not mean the command failed.",
  "control.receiptExpired":
    "The receipt is no longer retained. The command may have executed; do not create it again automatically.",
  "control.jobUnread": "Command ticket not loaded.",
  "control.noJob": "No command ticket is recorded for this destination.",
  "control.jobId": "Stable job ID",
  "control.sequence": "Command number",
  "control.attempts": "Recorded retry attempts",
  "control.ticketHint":
    "A ticket is historical metadata, not a health observation. Saved does not mean applied. Refresh reads the target's receipt without executing the mutation.",
  "control.refresh": "Refresh target receipt",
  "control.retry": "Retry the same command",
  "control.supersede": "Supersede spent command",
  "control.retryHint":
    "Resume this exact command ID and payload after reviewing the target. This does not allocate another operation or return its password again.",
  "control.supersedeHint":
    "Retire uncertainty only when a verified observation proves this command slot was spent or its epoch changed. This is not evidence that it applied; the server rejects an unproven supersession.",
  "control.intentSaved": "Intent saved · execution may still occur",
  "control.reviewBeforeEdit":
    "Check the ticket and refresh the verified remote policy before another change.",
  "control.secretUnavailable":
    "The saved intent may still execute. No password was delivered here; receipts do not contain it. Confirm the receipt, then read the selected current credential's saved password in Connection configuration. If no copy is available, rotate explicitly. Do not automatically submit a replacement mutation.",
  "control.receiptReceived": "Target receipt received",
  "control.receiptHint":
    "Check the receipt state: saved, applied and rejected are different outcomes. Retries and receipt reads do not return passwords.",
  "control.rejected": "The target recorded a terminal rejection",
  "control.denied":
    "Node ownership, enrollment or destination configuration no longer permits this operation. Review the latest state.",
  "control.unavailable":
    "Node control is unavailable. Check the destination, node TLS and the durable ticket before any explicit retry.",
  "control.timeout":
    "The node response timed out. The command may still have committed; check its durable ticket.",
  "control.job.pending": "Pending · outcome unconfirmed",
  "control.job.blocked": "Blocked · operator review required",
  "control.job.saved": "Saved on target · not confirmed applied",
  "control.job.applied": "Applied receipt · historical",
  "control.job.rejected": "Terminal rejection",
  "control.job.superseded": "Superseded · old slot retired",
};
