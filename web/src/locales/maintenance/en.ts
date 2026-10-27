export default {
  "maintenance.title": "Proxy maintenance",
  "maintenance.read": "Read current maintenance state",
  "maintenance.pause": "Pause new proxy operations",
  "maintenance.resume": "Resume new proxy operations",
  "maintenance.confirm": "Confirm this change",
  "maintenance.cancel": "Cancel",
  "maintenance.accepting": "Accepting new operations",
  "maintenance.paused": "New operations paused",
  "maintenance.saved": "Saved admission setting",
  "maintenance.runtime": "Observed runtime setting",
  "maintenance.active": "Active operations observed",
  "maintenance.zero": "No active operations observed",
  "maintenance.savedRevision": "Saved policy revision",
  "maintenance.runtimeRevision": "Observed runtime revision",
  "maintenance.durableRevision": "Last durable application checkpoint",
  "maintenance.unknown": "Unknown",
  "maintenance.scope":
    "Pause affects new authenticated proxy operations, not existing operations or delivery of management commands. It does not stop the node.",
  "maintenance.shutdown":
    "After pausing, use Online connection drain to stop listeners and wait for local connection owners. The lease counter cannot prove empty HTTP, HTTP/2, TLS or QUIC queues, even at zero. Do not force-stop from this count.",
  "maintenance.queue":
    "A remote change uses one durable command. The controller may retry delivery of that same command identity. This page does not resubmit or poll automatically.",
  "maintenance.confirmHint":
    "Submit once using the displayed node, policy revision and ownership epoch. The saved setting and runtime application are separate facts. Read current state explicitly after the reply.",
  "maintenance.confirmRemote":
    "The current target revision and next command number are also bound to this submission. Pausing target delivery is a different setting.",
  "maintenance.unsupported": "This node does not support maintenance state.",
  "maintenance.interrupted":
    "The read was interrupted. Read again for a current observation.",
  "maintenance.historical":
    "This is an earlier observation, not current state. Read again before making another decision.",
  "maintenance.localControlled":
    "Another controller owns this node. Local maintenance changes are blocked.",
  "maintenance.remoteUnavailable":
    "This target is paused, retired, rolled back or not owned by this controller. Maintenance changes are blocked.",
  "maintenance.otherChange":
    "Review the unresolved node change before starting another change.",
  "maintenance.sequenceExhausted":
    "The policy or command sequence has reached its limit. New changes are blocked; ask the operator to review the node without resetting or replaying the sequence.",
  "maintenance.pending": "Submitting this maintenance change…",
  "maintenance.uncertain":
    "This change has no confirmed final result. Do not repeat it. Read the current state and, when available, the original command receipt; a later setting does not prove this write succeeded.",
  "maintenance.retained":
    "An unresolved maintenance change is retained. Open the matching node card to review it; a refreshed list does not resolve it.",
  "maintenance.intent": "Requested admission setting",
  "maintenance.expectedRevision": "Original policy revision",
  "maintenance.expectedEpoch": "Original ownership epoch",
  "maintenance.job": "Original command ID",
  "maintenance.readReceipt": "Refresh original command receipt",
  "maintenance.receiptMismatch":
    "The current command is not the original maintenance command. Its result is not attributed to this change.",
  "maintenance.receiptPending":
    "A command is still pending or blocked. Finish reviewing it before acknowledging this change.",
  "maintenance.acknowledge": "I reviewed current state; allow a new decision",
  "maintenance.acknowledgeHint":
    "This only clears the browser reminder. It neither declares the original change successful nor repeats it. A new change needs a fresh read and confirmation.",
  "maintenance.savedReply":
    "The change was saved. Runtime application and active operations still need a separate read.",
  "maintenance.appliedReply":
    "The command reported application. Active operations still need a separate read.",
  "maintenance.rejectedReply":
    "The command was rejected. Read current state before deciding what to do next.",
  "maintenance.jobState": "Observed command state",
} as const;
