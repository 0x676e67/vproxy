export default {
  "notifications.title": "Webhook notifications",
  "notifications.confirm": "Confirm",
  "notifications.cancel": "Cancel",
  "notifications.description":
    "Send newly recorded alerts from this management node. Child-node events require background alert collection. Receiver acceptance does not mean a person has read the notification.",
  "notifications.refresh": "Refresh status",
  "notifications.savedState": "Saved configuration",
  "notifications.enabled": "Enabled",
  "notifications.disabled": "Disabled",
  "notifications.destination": "Receiver",
  "notifications.configured": "Configured; secrets hidden",
  "notifications.notConfigured": "Not configured",
  "notifications.token": "Bearer token (optional)",
  "notifications.cursor": "Processed through event",
  "notifications.skipped": "Skipped through at reconfiguration",
  "notifications.lastAccepted": "Last receiver-accepted delivery",
  "notifications.discarded": "Last discarded delivery",
  "notifications.none": "None",
  "notifications.enable": "Enable notifications",
  "notifications.url": "HTTPS receiver URL",
  "notifications.urlHint":
    "Public HTTPS addresses only. The URL may contain secrets and is never returned by reads. Private/loopback addresses, redirects and environment proxies are not used.",
  "notifications.keep": "Leave blank to keep the saved value",
  "notifications.tokenHint":
    "Enter only to replace it. Browser review notes never store the token. Private database backups include it.",
  "notifications.clearToken": "Delete the current token",
  "notifications.auto":
    "Receiver deduplicates deliveries; enable automatic retries",
  "notifications.autoHint":
    "The receiver must deduplicate by observer_node_id and delivery_id. Six automatic attempts maximum, with minimum delays of 30, 60, 120, 240 and 480 seconds. Otherwise leave this off and review manually.",
  "notifications.autoEligible":
    "This failure is eligible for automatic retry, up to six attempts in total.",
  "notifications.discardHint":
    "Allow discarding this delivery, including a request the receiver may already have received",
  "notifications.save": "Save configuration",
  "notifications.saveWarning":
    "Start at the current event sequence without backfilling history. Discarding the pending delivery retains its ID for review. A submitted request cannot be recalled.",
  "notifications.forget": "Delete receiver configuration",
  "notifications.forgetWarning":
    "Disable notifications and delete the current URL/token. Existing backups are unchanged and submitted requests cannot be recalled.",
  "notifications.retry": "Retry once with the original ID",
  "notifications.retryWarning":
    "The receiver may already have received the request. Confirm deduplication and follow its waiting policy first. This attempt reuses the original delivery ID and body; it does not create another delivery.",
  "notifications.attempts": "{count} attempts started",
  "notifications.refreshDelivery": "Refresh status to read subsequent results.",
  "notifications.outcome.ready": "One attempt permitted; waiting to run",
  "notifications.outcome.sending": "Attempt started; result not yet recorded",
  "notifications.outcome.rejected": "Receiver returned a non-success status",
  "notifications.outcome.deferred":
    "Receiver requested a delay; automatic retries paused",
  "notifications.outcome.unknown": "Delivery outcome unknown",
  "notifications.outcome.destination_blocked":
    "Receiver connection preflight failed",
  "notifications.reviewRequired":
    "Review the last operation before submitting another",
  "notifications.result.saved":
    "The current receipt proves the original configuration was saved.",
  "notifications.result.admitted":
    "The current record proves the original retry was admitted, not that the receiver processed it.",
  "notifications.result.unknown":
    "The current record cannot confirm the original outcome. No request will be replayed automatically.",
  "notifications.finishReview": "Finish review and continue",
  "notifications.reviewWarning":
    "Clear only this browser review note. Do not resend, undo a server operation or mark an unknown result successful.",
  "notifications.notesUnavailable":
    "Browser review notes are unavailable. Use a browser with Web Locks and local storage. Writes are blocked to preserve unknown-operation assertions.",
  "notifications.invalid":
    "Invalid notification settings. Check the URL, token and pending delivery.",
  "notifications.changed":
    "Configuration or delivery changed. Refresh and review it.",
};
