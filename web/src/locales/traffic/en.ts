import type zh from "./zh";

export default {
  "menu.traffic": "Traffic",
  "traffic.title": "Traffic accounting",
  "traffic.description":
    "Accepted proxy payload by node, user, credential or actually selected pool. Read-only manual snapshots, not live bandwidth or a billing ledger.",
  "traffic.open": "Traffic",
  "traffic.source": "Source node",
  "traffic.dimension": "Accounting entity",
  "traffic.node": "Node",
  "traffic.user": "User",
  "traffic.credential": "Credential",
  "traffic.pool": "Actually selected pool",
  "traffic.id": "Entity ID",
  "traffic.idHint":
    "Paste the complete ID, or open traffic from a user, credential or pool",
  "traffic.apply": "View",
  "traffic.invalidId":
    "Enter a canonical entity ID; a display name is not an ID.",
  "traffic.protocol": "Protocol",
  "traffic.allProtocols": "All protocols",
  "traffic.resolution": "History window",
  "traffic.minute": "Minute",
  "traffic.hour": "Hour",
  "traffic.day": "Day",
  "traffic.refresh": "Read a new snapshot",
  "traffic.snapshot":
    "Manual snapshot · retrieved {time} · does not update automatically",
  "traffic.waiting": "No snapshot retrieved yet",
  "traffic.definition":
    "Upload is client → egress; download is the reverse. Only payload accepted by the transport API is counted, excluding proxy negotiation, HTTP framing and the proxy's outer TLS/QUIC. This is not peer delivery. End-to-end TLS/SSH inside CONNECT still belongs to the opaque payload.",
  "traffic.local":
    "Reading this node only. Nodes account independently; parent and child totals are not added together.",
  "traffic.remoteUnavailable": "Remote traffic is unavailable",
  "traffic.remoteHint":
    "Remote statistics are durable-only: node reads use a persistent cache; user/credential/pool reads are on demand. Local data never replaces remote data. An old cache proves neither current reachability nor authorization.",
  "traffic.remoteDurableOnly":
    "The node protocol supplies durable totals only, not current memory counts. This does not establish whether the target proxy is running.",
  "traffic.remoteOpenRun":
    "The source's latest run has not been confirmed to have ended cleanly. Its running state is unknown, and an uncheckpointed tail may exist; this is not evidence that the process stopped or bytes were lost.",
  "traffic.noData":
    "No verified durable data yet; no zeroes or samples replace it.",
  "traffic.cacheHint":
    "Persistent-cache source mode (not proof that data exists). Use last-success time and source state to assess freshness.",
  "traffic.onDemandHint":
    "Read on demand for this request. Durable totals exclude the uncheckpointed memory tail.",
  "traffic.collectorUnavailable":
    "The background collector is unavailable; this does not prove the target proxy stopped.",
  "traffic.sourceSuccess": "Last successful source read",
  "traffic.sourceAge": "Source age when retrieved",
  "traffic.targetRevision": "Current target registration revision",
  "traffic.source.pending":
    "Awaiting remote traffic collection; missing samples remain unknown",
  "traffic.source.ready":
    "Last remote traffic read succeeded (manual snapshot)",
  "traffic.source.stale":
    "Remote statistics are stale; any data below is a historical durable snapshot",
  "traffic.source.unsupported":
    "The target does not support traffic accounting; any historical data is old cache only",
  "traffic.source.unavailable":
    "The target cannot currently be read; any data is old cache, not zero current traffic",
  "traffic.source.not_authorized":
    "This node identity is not currently authorized by the target; any data is previously imported historical cache",
  "traffic.source.continuity_error":
    "Remote meter continuity validation failed; retained history does not mean the new epoch was accepted",
  "traffic.source.paused":
    "Target collection is paused; no automatic target reads occur, while retained cache remains viewable",
  "traffic.totals": "Cumulative payload",
  "traffic.cumulativeHint":
    "The current cumulative snapshot already includes durable totals; never add them together. Saturated values are lower bounds. Missing memory observations remain unknown.",
  "traffic.durableUpload": "Durable upload",
  "traffic.durableDownload": "Durable download",
  "traffic.liveUpload": "Current cumulative upload snapshot",
  "traffic.liveDownload": "Current cumulative download snapshot",
  "traffic.apiOnly":
    "This management process has no active proxy run marker. Durable totals remain available; current memory counts are unknown. This does not prove that another independent process stopped.",
  "traffic.warning": "Data completeness",
  "traffic.loss":
    "An uncheckpointed tail may have been lost. Totals are known lower bounds, not a lossless billing ledger.",
  "traffic.gap":
    "Some historical windows are missing. Missing samples are not zero traffic.",
  "traffic.clock":
    "The clock was unavailable or discontinuous; UTC window attribution may be incomplete.",
  "traffic.checkpointError":
    "The last checkpoint failed. Accepted bytes remain in memory; persistence may be delayed.",
  "traffic.checkpointStage.sample": "Failed while sampling counters.",
  "traffic.checkpointStage.write_admission": "Could not acquire a writer slot.",
  "traffic.checkpointStage.update_gate":
    "Could not acquire the policy update lock.",
  "traffic.checkpointStage.store": "Failed during storage or run validation.",
  "traffic.checkpointStage.worker":
    "The storage worker did not complete normally.",
  "traffic.checkpointStage.observation":
    "Could not confirm local checkpoint state.",
  "traffic.saturated": "Saturated · lower bound",
  "traffic.normal": "Not saturated",
  "traffic.state": "Counter state",
  "traffic.metadata": "Meter provenance and completeness",
  "traffic.origin": "Origin node ID",
  "traffic.epoch": "Independent meter epoch",
  "traffic.started": "Meter start",
  "traffic.checkpoint": "Durable checkpoint sequence",
  "traffic.checkpointAt": "Last durable checkpoint",
  "traffic.observedAt": "API snapshot time",
  "traffic.run": "This process's active run ID",
  "traffic.clean": "Latest durable run marker",
  "traffic.cleanYes": "Clean finish confirmed",
  "traffic.cleanNo": "Open / clean finish unconfirmed",
  "traffic.completedAt": "Last complete checkpoint cycle",
  "traffic.cycleAge": "Cycle age when retrieved",
  "traffic.history": "Durable history windows",
  "traffic.historyHint":
    "Approximate UTC-aligned checkpoint windows, not packet timestamps. Missing windows/protocols remain unknown, not zero. This table and cumulative totals may come from different checkpoints.",
  "traffic.noCredentialHistory":
    "Credentials retain cumulative totals only. Use node, owning-user or actually selected-pool history.",
  "traffic.window": "Window start (UTC-aligned)",
  "traffic.upload": "Upload payload",
  "traffic.download": "Download payload",
  "traffic.unknown": "Unknown / no sample",
  "traffic.noHistory":
    "No durable windows for this filter; this does not mean zero traffic.",
  "traffic.retentionFloor": "Current retention floor: {time}",
  "traffic.retentionGap":
    "The requested cursor precedes the retention floor. Earlier coverage is unknown.",
  "traffic.pageSize": "Windows per page",
  "traffic.invalidQuery":
    "Invalid traffic filter. Check the entity ID, window and cursor.",
  "traffic.busy": "Traffic reads are temporarily busy. Retry manually shortly.",
  "traffic.unavailable":
    "Traffic is unavailable; no zeroes or samples replace it. Check node version and durable storage.",
  "traffic.changed":
    "The meter epoch changed during this read. Retrieve a consistent snapshot again.",
} satisfies Record<keyof typeof zh, string>;
