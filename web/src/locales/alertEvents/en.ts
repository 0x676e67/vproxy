export default {
  "alertEvents.title": "Event history",
  "alertEvents.conflict":
    "The episode state changed. Read it again before another acknowledgement.",
  "alertEvents.storeCapacity":
    "History storage has reached its limit. Check the original acknowledgement result before another action.",
  "alertEvents.scope":
    "Reads durable records on this management node, including retained background observations when enabled. Source IDs identify the observed node. Selecting an origin filters local records without contacting it or reading its history.",
  "alertEvents.warning":
    "History does not prove current health. Acknowledging only marks a state as reviewed; it does not repair a problem.",
  "alertEvents.refresh": "Read latest events",
  "alertEvents.eventId": "Original event ID",
  "alertEvents.exactHint":
    "Exact IDs are looked up across all origins on this management node.",
  "alertEvents.observer": "Observing management node",
  "alertEvents.lookup": "Find event",
  "alertEvents.invalidId":
    "Enter a positive decimal event ID without leading zeros.",
  "alertEvents.missing":
    "This record is not retained. Missing or trimmed records do not prove that an event never occurred.",
  "alertEvents.trimmed":
    "Older events have been removed by the retention limit. Their episodes may still be retained.",
  "alertEvents.empty": "No retained events on this page",
  "alertEvents.sequence": "Event sequence",
  "alertEvents.episode": "Episode",
  "alertEvents.transition": "Recorded change",
  "alertEvents.transition.opened": "Problem observed",
  "alertEvents.transition.reason_changed": "Reason changed",
  "alertEvents.transition.recovered": "Recovery observed",
  "alertEvents.transition.unmonitored": "Monitoring ended",
  "alertEvents.transition.acknowledged": "State acknowledged",
  "alertEvents.recorded": "Recorded at",
  "alertEvents.boot": "Observation process ID",
  "alertEvents.incident": "Original incident ID",
  "alertEvents.endReason": "Monitoring end reason",
  "alertEvents.end.source_unmonitored": "Observation source stopped",
  "alertEvents.end.monitor_restarted": "Management process restarted",
  "alertEvents.unknownTime": "Unknown",
  "alertEvents.outsideDate":
    "Unix milliseconds: {value} (outside the displayable date range)",
  "alertEvents.openEpisode": "View and review",
  "alertEvents.episodeTitle": "Retained episode",
  "alertEvents.episodeHint":
    "This is the latest retained projection for the original episode. It is not a fresh health check.",
  "alertEvents.latest": "Latest state sequence",
  "alertEvents.acknowledged": "Latest state acknowledged",
  "alertEvents.unacknowledged": "Latest state not acknowledged",
  "alertEvents.previousAck": "A previous state was acknowledged",
  "alertEvents.ackSequence": "Last acknowledged state",
  "alertEvents.ackBy": "Recorded acknowledgement by",
  "alertEvents.ackAt": "Recorded acknowledgement time",
  "alertEvents.ack": "Mark as read",
  "alertEvents.confirm": "Mark this state as read?",
  "alertEvents.confirmHint":
    "This does not end the alert, restore monitoring or retry a task.",
  "alertEvents.unknown":
    "The acknowledgement result is unknown. Read the original episode; do not send the request again.",
  "alertEvents.confirming": "Submitting the acknowledgement",
  "alertEvents.readOriginal": "Read original episode",
  "alertEvents.covered":
    "The original state has been acknowledged. This does not identify which request performed the acknowledgement.",
  "alertEvents.advanced":
    "The episode has a later state. Finishing this review does not acknowledge that new state.",
  "alertEvents.finish": "Finish this review",
  "alertEvents.finishHint":
    "Remove only this browser reminder. The original request's outcome may remain unknown; nothing will be resent.",
  "alertEvents.missingReview":
    "The original request's outcome is still unknown, and its history is no longer queryable. Finishing removes only this browser reminder; it does not undo or resend the acknowledgement.",
  "alertEvents.storage":
    "Acknowledgements are paused because browser review storage is unavailable. History reads remain available.",
  "alertEvents.capacity":
    "Review storage is full. Review existing acknowledgement results before starting another.",
  "alertEvents.badge": "Unread notifications: {count}",
  "alertEvents.badgeUnknown": "Unacknowledged episode count is unknown",
  "alertEvents.badgeHint":
    "Mark states as read in event history to clear notifications; this does not resolve alerts",
};
