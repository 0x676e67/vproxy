export default {
  "menu.service": "Proxy service",
  "service.title": "Proxy service",
  "service.refresh": "Refresh status",
  "service.changed":
    "Configuration changed. Load and review the saved configuration; it will not be overwritten automatically.",
  "service.busy":
    "Service control is busy. Look up the original operation before deciding whether to submit a new one.",
  "service.unavailable":
    "Service control is unavailable. Refresh status and check service logs.",
  "service.state.stopped": "Stopped",
  "service.state.unknown": "State unconfirmed",
  "service.state.starting": "Starting",
  "service.state.running": "Listening",
  "service.state.stopping": "Stopping",
  "service.state.failed": "Start or stop failed",
  "service.liveRevision": "Running configuration {revision}",
  "service.notTested":
    "A listening socket does not prove target connectivity. Test a real request with proxy credentials after enabling.",
  "service.users": "Create a user or get a connection",
  "service.startup":
    "A startup configuration file manages this node's listeners. This page is read only.",
  "service.upgrade":
    "Upgrade and migrate the management database before controlling listeners here.",
  "service.delegated":
    "Another node controls this node. Local listener changes are unavailable.",
  "service.otherChange":
    "Review the unresolved operation on the nodes page first.",
  "service.unconfirmed": "The previous service operation is unconfirmed",
  "service.following": "Applying configuration",
  "service.followingHint":
    "Checking this operation automatically. Leaving this page does not cancel it.",
  "service.noReplay":
    "Look up the original operation first. Refreshing or cancelling does not undo accepted work or retry it. If its receipt is unavailable, review current state before deciding what to do next.",
  "service.inspect": "Look up original operation",
  "service.acknowledge": "Reviewed; allow a new operation",
  "service.receipt.pending": "The operation is still pending",
  "service.receipt.applied":
    "This operation completed. Check the current listener state.",
  "service.receipt.failed":
    "This operation failed; configuration was saved. Check ports or certificates before applying again.",
  "service.receipt.interrupted":
    "A service restart interrupted the original operation. Its result cannot be treated as successful.",
  "service.configuration": "Listener configuration",
  "service.reload": "Load saved configuration",
  "service.listener": "Listener {number}",
  "service.remove": "Remove",
  "service.protocol": "Protocol",
  "service.port": "Listen port",
  "service.host": "Client host",
  "service.publicPort": "Client port",
  "service.advanced": "Advanced address settings",
  "service.bind": "Listen IP",
  "service.add": "Add listener",
  "service.defaultEgress":
    "Uses the node's default egress without requiring IP resources. Existing user routing restrictions still apply.",
  "service.limits": "Performance and timeout",
  "service.workers": "Worker threads",
  "service.concurrent": "Concurrent limit per listener",
  "service.timeout": "Connect timeout (s)",
  "service.invalid":
    "Check listen IPs, ports, and client hosts. Each TCP or UDP bind must be unique.",
  "service.apply": "Apply configuration",
  "service.start": "Enable proxy",
  "service.stop": "Stop proxy",
  "service.confirmStart": "Apply proxy listeners?",
  "service.confirmStop": "Stop the proxy?",
  "service.startWarning":
    "Listeners accept network connections; proxy user credentials remain required. HTTPS uses this node's certificate, so the client host must match it. Applying changes first drains existing connections, then rebinds. Client addresses only generate connections; they do not change DNS or firewall settings.",
  "service.stopWarning":
    "Stop these listeners and drain existing connections within a deadline. Users, credentials, and traffic history remain; the management UI stays available.",
  "service.error.address_in_use":
    "The listen address is in use. Choose another port.",
  "service.error.address_unavailable":
    "The listen IP is not available on this host. Check the bind address.",
  "service.error.permission_denied":
    "Cannot bind this port. Check port conflicts and system permissions.",
  "service.error.timed_out":
    "The service operation timed out. Refresh status and look up the original operation.",
  "service.error.not_ready":
    "The proxy is not ready. Check certificates and service logs.",
  "service.error.service_failed":
    "The service operation failed. Check service logs.",
};
