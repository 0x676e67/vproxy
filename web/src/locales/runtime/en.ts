export default {
  "runtime.title": "Online connection drain",
  "runtime.read": "Read current forwarding state",
  "runtime.lookup": "Read original drain result",
  "runtime.start": "Stop listeners and drain connections",
  "runtime.confirm": "Confirm irreversible drain",
  "runtime.cancel": "Cancel",
  "runtime.scope":
    "Stop proxy listeners and wait for existing connections to finish naturally. Management stays online. This runtime cannot resume listening; an explicit restart is required.",
  "runtime.wait":
    "Long-lived UDP associations, tunnels or keepalive connections can keep draining indefinitely. This page never force-stops them or retries the POST.",
  "runtime.boundary":
    "Drained means the local forwarding drivers and their owners finished. It does not confirm peer receipt, empty remote buffers or settled traffic accounting. A zero lease count is not completion proof.",
  "runtime.pausedRequired":
    "Save a pause for new proxy operations before draining.",
  "runtime.restart":
    "This runtime has left serving state. Restart forwarding explicitly to listen again; changing the saved admission setting cannot restore these listeners.",
  "runtime.resumeBlocked":
    "Resume is blocked: a serving runtime has not been confirmed. Check forwarding state; a drained instance needs an explicit restart.",
  "runtime.unavailable": "No forwarding runtime is available on this node.",
  "runtime.unsupported": "This node does not support runtime observations.",
  "runtime.originalUnknown":
    "The original runtime/request could not be found. Its outcome remains unknown. A new runtime or current-state read cannot claim that result. Do not submit it again.",
  "runtime.retained":
    "An original drain request is retained. Open its node card to review it.",
  "runtime.pending": "Submitting this drain request…",
  "runtime.unknown":
    "Keep the original request for review. A 202 means accepted, not drained. Read its exact result; refreshing current state does not establish the original outcome.",
  "runtime.accepted":
    "The original request was accepted. Read its result to check progress.",
  "runtime.original": "Observation of the original runtime/request",
  "runtime.current": "Current observation only",
  "runtime.runtimeId": "Runtime ID",
  "runtime.requestId": "Original request ID",
  "runtime.phase": "Forwarding phase",
  "runtime.active": "Observed admission leases",
  "runtime.serving": "Serving",
  "runtime.draining": "Draining",
  "runtime.drained": "Local drain finished",
  "runtime.interrupted": "Drain interrupted",
  "runtime.failed": "Drain failed",
  "runtime.ownerBlocked":
    "This target is not currently writable by this controller. Read fresh target and ownership state before deciding.",
} as const;
