export default {
  "alerts.back": "Back to alerts",
  "menu.alerts": "Alerts",
  "alerts.title": "Alerts",
  "alerts.active": "Active problems",
  "alerts.recent": "Recent records",
  "alerts.activeCount": "Total active problems",
  "alerts.recentCount": "Total recent records",
  "alerts.coverage": "Observation coverage",
  "alerts.localEgress": "Local egress checks",
  "alerts.localTraffic": "Local traffic records",
  "alerts.localManagementHttps": "Local management HTTPS certificates",
  "alerts.localNodeTls": "Local node mTLS certificates",
  "alerts.localProxyTls": "Local proxy TLS certificates",
  "alerts.localProxyExpected": "Local proxy expected to run",
  "alerts.remoteCached": "Locally stored remote records",
  "alerts.remoteObservation": "Background target observations",
  "alerts.backgroundEnabled": "Background target collection enabled",
  "alerts.backgroundDisabled": "Background target collection not enabled",
  "alerts.backgroundHint":
    "The node collects registered targets' own alerts without a browser. Unread, stale or failed sources remain unknown; zero recorded problems does not prove health. This does not send email, webhooks or other external notifications.",
  "alerts.backgroundDisabledHint":
    "Background target collection is off. An administrator can enable --observe-target-alerts on a schema22 controller. Starting Node overview reads affects only this browser and does not enable background collection.",
  "alerts.sourceNode": "Source node",
  "alerts.foreignObservation": "Observed from a registered target",
  "alerts.enabled": "Included",
  "alerts.disabled": "Not included",
  "alerts.expected": "Yes",
  "alerts.notExpected": "No",
  "alerts.remoteHint":
    "Records here can include cached remote traffic/jobs and opt-in background observations. Source IDs are preserved. Reading this page starts no remote probe or external notification.",
  "alerts.managementHttpsHint":
    "Certificate observations describe the source node's loaded management HTTPS, node mTLS and proxy TLS identities. Dates do not prove trust, name coverage, revocation status or connectivity. Not included does not mean healthy. These reads do not load certificate files, issue certificates or expose private keys.",
  "alerts.lifecycleHint":
    "These live records reset when management restarts. Durable records and acknowledgements are in Event history.",
  "alerts.observationHint":
    "Unknown or stale observations do not prove recovery. Monitoring stops when the resource or observation scope changes.",
  "alerts.refresh": "Read again",
  "alerts.polling": "Reads every 10 seconds while this page is visible",
  "alerts.paused": "Page hidden; reads paused",
  "alerts.received": "Last read: {time}",
  "alerts.collectionObserved": "Last collection",
  "alerts.collectionAge": "Collection age (ms)",
  "alerts.waiting": "Alerts have not been read",
  "alerts.remoteManual": "Read the selected node when requested",
  "alerts.remoteSnapshot":
    "Snapshot from this node; it does not update automatically",
  "alerts.remoteUnread": "Read this node's own alerts to view its records",
  "alerts.remoteReading": "Reading this node's own alerts",
  "alerts.remoteLifecycle":
    "Recent records belong to this node's current management process and reset when it restarts. Reading does not run an egress check.",
  "alerts.remoteUnsupported": "This node does not support egress alert reads.",
  "alerts.remoteFailed": "The node could not be read or is unreachable.",
  "alerts.remoteUnmonitored":
    "This node has no included observation sources. Its health is unknown.",
  "alerts.remoteUnknown":
    "Current state is unconfirmed. These records do not prove recovery.",
  "fleet.title": "Node overview",
  "fleet.hint": "Read each node's own observations",
  "fleet.ownHint":
    "Only this node's own sources are included. Its cached remote traffic, jobs and downstream node directory are not exported. Coverage does not prove health.",
  "fleet.scope":
    "Start explicitly to read this node and up to 128 registered targets, two remote reads at a time. Each card uses one first page for complete counts, not a complete incident list. No downstream nodes or remote history are read.",
  "fleet.start": "Start overview reads",
  "fleet.stop": "Stop overview reads",
  "fleet.running": "Reads repeat 30 seconds after a round finishes",
  "fleet.stopped":
    "Stopped. Start again to read; stored cards are not current.",
  "fleet.known": "Current snapshots: {known} of {total} nodes",
  "fleet.reading":
    "Reading the registered node set and confirming it has not changed…",
  "fleet.unread": "The node set has not been read",
  "fleet.local": "This management node",
  "fleet.open": "Open this node's alerts",
  "fleet.unknown": "Unknown",
  "fleet.registryChanged":
    "The registered node set changed or exceeded its bounds. This round is unconfirmed. Start again after reviewing node settings.",
  "fleet.unsupported":
    "This node does not support all local alert reads. No egress-only fallback was used.",
  "fleet.nodeLocationHint":
    "Find this ID on Nodes; the link does not select its card.",
  "fleet.state.read": "Current snapshot",
  "fleet.state.waiting": "Not confirmed in this round",
  "fleet.state.stopped": "Reads stopped",
  "fleet.state.stale": "Observation stale or incomplete",
  "fleet.state.paused": "Target delivery paused; not read",
  "fleet.state.retired": "Target retired; not read",
  "fleet.state.unavailable": "Controller unavailable; not read",
  "fleet.state.rollback": "Target rollback warning; not read",
  "fleet.state.failed": "Read failed; state unknown",
  "fleet.state.unsupported": "Node alert reads unsupported",
  "alerts.previousRecord": "Previous record",
  "alerts.remoteRecovered": "Recovery recorded on this node",
  "alerts.changed": "Records changed or management restarted. Read again.",
  "alerts.invalidQuery": "Invalid alert query. Read again.",
  "alerts.unavailable": "Alerts are temporarily unavailable.",
  "alerts.retained":
    "Showing the last successful read. The current problem count is unconfirmed.",
  "alerts.collectionError":
    "Some observations could not be collected. These records may be incomplete.",
  "alerts.dropped": "{count} alert records exceeded the retention limit.",
  "alerts.restarted": "Management restarted and recent records were reset.",
  "alerts.kind": "Problem",
  "alerts.subject": "Node and resource",
  "alerts.status": "Status",
  "alerts.reason": "Observation",
  "alerts.previousObservation": "Previously observed: {reason}",
  "alerts.observed": "Last observed",
  "alerts.firstObserved": "First observed",
  "alerts.ended": "Ended",
  "alerts.age": "Since update/end (ms)",
  "alerts.stale": "Observation not fresh",
  "alerts.action": "View",
  "alerts.openResources": "IP resources",
  "alerts.openNodeResources": "Open this node's resources",
  "alerts.openTraffic": "Traffic",
  "alerts.openPolicy": "Proxy configuration",
  "alerts.openJob": "Node job",
  "alerts.openNode": "View node",
  "alerts.bind": "Bind",
  "alerts.tcp": "TCP connection",
  "alerts.pageSize": "Rows per page",
  "alerts.emptyActive": "No active problems in the current records",
  "alerts.emptyRecent": "No recent records",
  "alerts.noData": "No records available yet",
  "alerts.status.active": "Active",
  "alerts.status.recovered": "Recovered",
  "alerts.status.unmonitored": "Monitoring stopped",
  "alerts.kind.egress_check": "Egress check",
  "alerts.kind.health_catalog": "Egress catalog",
  "alerts.kind.policy": "Proxy configuration",
  "alerts.kind.traffic_checkpoint": "Traffic checkpoint",
  "alerts.kind.traffic_continuity": "Traffic continuity",
  "alerts.kind.remote_traffic": "Remote traffic records",
  "alerts.kind.remote_job": "Remote job",
  "alerts.kind.remote_observation": "Remote observation collection",
  "alerts.kind.management_https": "Management HTTPS",
  "alerts.kind.node_tls": "Node mTLS",
  "alerts.kind.proxy_tls": "Proxy TLS",
  "alerts.code.unknown": "A problem was observed. View the related records.",
  "alerts.code.egress_address_unavailable": "Egress address cannot be bound",
  "alerts.code.egress_connection_refused": "Target refused the connection",
  "alerts.code.egress_timed_out": "Connection timed out",
  "alerts.code.egress_permission_denied": "Host denied the network operation",
  "alerts.code.egress_network_unreachable": "Network unreachable",
  "alerts.code.egress_failed": "Egress check failed",
  "alerts.code.egress_family_mismatch": "Address family mismatch",
  "alerts.code.health_catalog_unavailable":
    "Egress catalog temporarily unavailable",
  "alerts.code.health_catalog_stale": "Egress catalog observation is stale",
  "alerts.code.proxy_not_running": "Expected proxy is not running",
  "alerts.code.proxy_drain_failed": "Local proxy drain failed",
  "alerts.code.proxy_drain_interrupted": "Local proxy drain was interrupted",
  "alerts.code.policy_publication_unavailable":
    "Applied configuration cannot be read",
  "alerts.code.policy_not_applied": "Saved configuration has not been applied",
  "alerts.code.traffic_checkpoint_failed": "Traffic checkpoint failed",
  "alerts.code.traffic_checkpoint_stale": "Traffic checkpoint is stale",
  "alerts.code.traffic_loss_possible": "Traffic records may have been lost",
  "alerts.code.traffic_history_gap": "Traffic history has a gap",
  "alerts.code.traffic_time_uncertain": "Traffic time range is uncertain",
  "alerts.code.remote_traffic_continuity_error":
    "Remote traffic continuity error",
  "alerts.code.remote_traffic_not_authorized":
    "Remote traffic read is not authorized",
  "alerts.code.remote_collector_unavailable":
    "Remote traffic collection is not enabled",
  "alerts.code.remote_traffic_unsupported":
    "Remote traffic reads are unsupported",
  "alerts.code.remote_traffic_unavailable":
    "Remote traffic records temporarily unavailable",
  "alerts.code.remote_traffic_stale": "Remote traffic records are stale",
  "alerts.code.remote_job_blocked": "Remote job is blocked",
  "alerts.code.remote_job_rejected": "Remote job was rejected",
  "alerts.code.remote_observation_pending":
    "Target observations have not been read yet",
  "alerts.code.remote_observation_unavailable":
    "Target observations could not be read",
  "alerts.code.remote_observation_unsupported":
    "Target observation reads are unsupported",
  "alerts.code.remote_observation_not_authorized":
    "Target observation reads are not authorized",
  "alerts.code.remote_observation_stale": "Target observations are stale",
  "alerts.code.remote_observation_changed":
    "Target observations changed during collection",
  "alerts.code.remote_observation_capacity":
    "Target observations exceeded the collection limit",
  "alerts.code.remote_observation_incomplete":
    "Target observations are incomplete",
  "alerts.code.https_identity_unavailable":
    "Management HTTPS certificate unavailable",
  "alerts.code.https_identity_expiring":
    "Management HTTPS certificate expires within 7 days",
  "alerts.code.https_identity_expired":
    "Management HTTPS certificate has expired",
  "alerts.code.https_identity_not_yet_valid":
    "Management HTTPS certificate is not yet valid",
  "alerts.code.https_identity_metadata_unavailable":
    "Management HTTPS certificate metadata could not be read",
  "alerts.code.node_tls_identity_unavailable":
    "Node mTLS certificate is unavailable",
  "alerts.code.node_tls_identity_expiring":
    "Node mTLS certificate expires within 7 days",
  "alerts.code.node_tls_identity_expired": "Node mTLS certificate has expired",
  "alerts.code.node_tls_identity_not_yet_valid":
    "Node mTLS certificate is not yet valid",
  "alerts.code.node_tls_identity_metadata_unavailable":
    "Node mTLS certificate metadata could not be read",
  "alerts.code.proxy_tls_identity_unavailable":
    "Proxy TLS certificate is unavailable",
  "alerts.code.proxy_tls_identity_expiring":
    "Proxy TLS certificate expires within 7 days",
  "alerts.code.proxy_tls_identity_expired": "Proxy TLS certificate has expired",
  "alerts.code.proxy_tls_identity_not_yet_valid":
    "Proxy TLS certificate is not yet valid",
  "alerts.code.proxy_tls_identity_metadata_unavailable":
    "Proxy TLS certificate metadata could not be read",
  "alerts.code.acme_attempt_unavailable":
    "Previous certificate attempt did not complete normally",
  "alerts.code.acme_review_required": "Certificate handling needs review",
  "alerts.code.acme_worker_stopped": "Issuance worker exited",
} as const;
