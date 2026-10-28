export default {
  "users.readPassword": "Reload password",
  "users.passwordNotSaved":
    "No recoverable password was saved for this credential. Use your original password, or close this window and explicitly rotate it once.",
  "users.passwordChanged":
    "The credential was rotated. Reopen the current credential.",
  "users.passwordKeyUnavailable":
    "The password encryption key is unavailable. Proxy authentication is unchanged. Check this node's key file or backup.",
  "users.passwordInvalid":
    "The saved password failed its integrity check. The credential was not changed or rotated. Check the node's storage.",
  "users.proxyNotStarted": "Proxy service is not running",
  "users.proxyNotStartedHint":
    "This node is running the management interface only. Creating a user or generating a URL does not start a proxy listener.",
  "users.crossNodeSearch": "Find users across nodes",
  "users.crossOpen": "Find across nodes",
  "users.crossLocating": "Locating user",
  "users.crossLocateCancel": "Cancel locating",
  "users.crossLocated": "User located",
  "users.crossMissing": "User not found on this node",
  "users.crossLocationHint":
    "Re-read by user ID. Continue on the current node.",
  "users.crossLocationCancelled":
    "Locating cancelled. Refresh explicitly to read again.",
  "users.crossHint":
    "Select nodes, then search. Each result is a separate observation, not a shared snapshot. Locate a user to switch nodes and read their current state before acting.",
  "users.crossDirectory": "Choose nodes",
  "users.crossSelected": "{count} selected · {loaded} remote nodes loaded",
  "users.crossSelectLoaded": "Select all loaded nodes and this node",
  "users.crossClearSelection": "Clear selection",
  "users.crossDirectoryPrevious": "Previous node page",
  "users.crossDirectoryNext": "Next node page",
  "users.crossDirectoryRefresh": "Read this node page again",
  "users.crossDirectoryEmpty": "No remote nodes on this page",
  "users.crossControllerUnavailable":
    "Remote control is unavailable. Remote searches may fail; this node can still be searched.",
  "users.crossSearchForm": "Cross-node user search",
  "users.crossCancel": "Stop searching",
  "users.crossClose": "Close",
  "users.crossProgress": "Checked {completed} of {total} nodes",
  "users.crossUnread": "Not checked",
  "users.crossReading": "Reading",
  "users.crossReady": "Read complete",
  "users.crossCancelled": "Cancelled",
  "users.crossFailed": "Read failed",
  "users.crossEmpty": "No matching users on this node",
  "users.crossRevision": "Observed revision {revision}",
  "users.crossMore": "More results are available on this node.",
  "users.crossReadAgain": "Search this node again",
  "users.crossPrevious": "Previous result page",
  "users.crossNext": "Next result page",
  "users.crossLocate": "Locate this user",
  "users.localOperations": "My local operations",
  "users.checkOperation": "Check this operation",
  "users.operationId": "Operation ID",
  "users.operationSaved": "Saved",
  "users.readSavedUser": "Read the saved user",
  "users.operationPreparationFailed": "Preparation incomplete",
  "users.operationPreparationHint":
    "No execution request was sent. Check the current state before explicitly starting a new operation.",
  "users.operationUnavailable":
    "No queryable record was found. This does not prove failure. Check the current state before submitting again.",
  "users.operationCapacity":
    "Operation history is at capacity. Check again later; do not submit repeatedly.",
  "users.historyRefresh": "Read latest records",
  "users.historyInspect": "View details",
  "users.historyDetail": "Operation details",
  "users.historyNext": "Older records",
  "users.historyPrevious": "Newer records",
  "users.historyReserved": "Reserved",
  "users.historySaved": "Saved",
  "users.historyRejected": "Rejected",
  "users.historySetActive": "Change active state",
  "users.historyNode": "Node ID",
  "users.historyUser": "User ID",
  "users.historyExpected": "Version before submission",
  "users.historyEmpty": "No queryable records",
  "users.historyUnread": "Records have not been read",
  "users.historyHint":
    "Only your user operations on this node are listed, without original forms or secrets. Up to 256 records per account and 4,096 per node are retained; older records may be pruned. Reads never execute or resend an operation.",
  "users.historySavedHint":
    "The operation was durably saved. This receipt does not prove the current policy is unchanged, applied, or that the proxy is reachable.",
  "users.historyReservedHint":
    "An ID was reserved, but no execution result is available. Reading it will not execute the operation. Check the current state first.",
  "menu.users": "Proxy users",
  "users.title": "Proxy users",
  "users.description":
    "Manage the selected node's proxy users and machine credentials. Administrator accounts and node mTLS identities are separate.",
  "users.policy": "Policy details",
  "users.savedRevision": "Saved revision",
  "users.appliedRevision": "Current runtime revision",
  "users.durableRevision": "Historical durable receipt",
  "users.proxyState": "Proxy status",
  "users.running": "Running",
  "users.degraded": "Listener running · admission unavailable",
  "users.pending": "Running · saved policy not yet applied",
  "users.apiOnly": "Not started",
  "users.userCount": "Users, including deleted history",
  "users.credentialCount": "Credentials, including revoked history",
  "users.revisionHint":
    "Saved does not mean running. The durable receipt records past activation; only the current runtime revision describes this managed instance.",
  "users.admissionHint":
    "Disabling, deleting or revoking prevents new authentication. Existing tunnels finish normally; these actions do not forcibly disconnect them.",
  "users.list": "Users",
  "users.searchTitle": "Find users",
  "users.searchMode": "Find by",
  "users.searchName": "By name",
  "users.searchId": "By ID",
  "users.searchQuery": "Name or full user ID",
  "users.searchSubmit": "Search",
  "users.searchClear": "Clear",
  "users.searchResults": "Search results",
  "users.searchEmpty": "No matching users",
  "users.searchInvalid":
    "Enter a name (up to 128 UTF-8 bytes) or a full user ID.",
  "users.searchChanged": "User data changed. Search again.",
  "users.searchChangedHint":
    "Search again to read from the first page. Earlier results cannot be combined with the new version.",
  "users.searchUnsupported": "This node does not support user search.",
  "users.searchUnsupportedHint":
    "Clear the search to browse this node's user pages.",
  "users.name": "Display name",
  "users.nameRule":
    "Use 1–128 UTF-8 bytes without control characters or surrounding whitespace",
  "users.protocols": "Allowed protocols",
  "users.noProtocols": "No protocols allowed",
  "users.limit": "Concurrent operations per user",
  "users.limitRule": "Use an integer from 1 to 1,000,000",
  "users.state": "State",
  "users.enabled": "Enabled",
  "users.disabled": "Disabled",
  "users.deleted": "Deleted",
  "users.revoked": "Permanently revoked",
  "users.userRevision": "User revision",
  "users.verifierRevision": "Secret generation",
  "users.actions": "Actions",
  "users.create": "Create user",
  "users.edit": "Edit user",
  "users.save": "Save",
  "users.cancel": "Cancel",
  "users.confirm": "Confirm operation",
  "users.enable": "Enable",
  "users.disable": "Disable",
  "users.disableHint":
    "Change whether this identity may start new operations. Existing operations are not disconnected.",
  "users.delete": "Permanently delete user",
  "users.deleteHint":
    "Permanently retire this user and revoke all their credentials. This cannot be undone. History is kept; existing operations are not disconnected.",
  "users.reviewNode": "Node",
  "users.reviewLocalNode": "This management node",
  "users.reviewOrigin": "Management address",
  "users.reviewUser": "User",
  "users.reviewCredential": "Credential",
  "users.reviewRevision": "Policy revision",
  "users.reviewChanged": "Review this operation again",
  "users.reviewChangedHint":
    "Close this window, read the latest status, then select the operation again.",
  "users.refresh": "Refresh",
  "users.readAgain": "Read again",
  "users.readLatest": "Read latest status",
  "users.readRecentTask": "View latest task",
  "users.viewExactTask": "View task",
  "users.reviewNewOperation": "Start a new operation",
  "users.checkSession": "Check sign-in",
  "users.operationUnknown": "Result unknown",
  "users.operationRejected": "Request not accepted",
  "users.operationDetails": "Operation details",
  "users.operationPending": "Task accepted",
  "users.operationFinished": "Task finished",
  "users.operationOnLocal": "This node · submitted against revision {revision}",
  "users.operationOnNode": "Node {id} · submitted against revision {revision}",
  "users.operationUser": "User {id}",
  "users.operationCredential": "Credential {id}",
  "users.operationUnknownHint":
    "User and credential changes are locked. Check the status without repeating the operation. Reading, leaving or signing in again does not undo a submitted change.",
  "users.operationPendingHint":
    "Check the task below. Do not submit this operation again.",
  "users.operationReadHint":
    "Read the latest status before starting a new operation.",
  "users.operationReviewedHint":
    "Latest status read. Review it, then start a new operation if needed.",
  "users.recentTaskNotProof":
    "No task ID was received for this operation. The latest task may belong to someone else and cannot confirm this result.",
  "users.operationTaskChanged":
    "The latest task is different. It cannot confirm this operation. Keep the recorded task ID for manual review.",
  "users.supersededNotRollback":
    "The command slot was superseded. This does not prove the original change was rolled back.",
  "users.operationScopeChanged":
    "The node registration or controller changed. Review node control settings; this view cannot confirm the operation in the new scope.",
  "users.operationSecretMissing":
    "The password was not received. Check the original operation and current credential first. On this node, you can try reading a saved password. Status reads do not resend or rotate anything.",
  "users.readFailedHint":
    "This read failed. Read again to inspect the status; it will not resend a change or resolve an unknown result.",
  "users.includeDeleted": "Include deleted users",
  "users.empty": "No users on this page",
  "users.previous": "Previous page",
  "users.next": "Next page",
  "users.page": "Page {page}",
  "users.credentials": "Connections",
  "users.credentialsFor": "Connections · {name}",
  "users.credentialsHint":
    "The user's protocol permissions and concurrency budget apply. Saved passwords can be read in the connection form.",
  "users.createCredential": "Create credential",
  "users.deliveryCreated": "User created · {name}",
  "users.deliveryNext":
    "Create a proxy credential, then copy a connection URL.",
  "users.createCredentialAndConnect": "Create proxy credential",
  "users.createCredentialHint":
    "Generate a separate proxy login and password. These cannot sign in to the administrator interface.",
  "users.noCredentials": "No credentials on this page",
  "users.login": "Machine login",
  "users.rotate": "Rotate password",
  "users.rotateHint":
    "The old password will stop working for new authentication. The login stays the same. Existing operations continue, and disabled credentials stay disabled.",
  "users.revoke": "Permanently revoke",
  "users.revokeHint":
    "This credential can never be enabled or rotated again. History is retained; existing operations are not forcibly disconnected.",
  "users.secretTitle": "Proxy connection credential",
  "users.secret": "Proxy password",
  "users.secretWarning":
    "The password and password-bearing links grant proxy access. View them only on a trusted device and do not share them with unauthorized people.",
  "users.secretClose": "Close",
  "users.conflict": "The policy revision changed. Read the latest status.",
  "users.denied": "Policy access was denied. Read the latest status.",
  "users.notFound": "The resource was not found. Read the latest list.",
  "users.invalid": "The policy input was rejected. Check its values.",
  "users.busy":
    "Policy storage or coordination is busy. Read the status later.",
  "users.unavailable":
    "Policy availability could not be confirmed. Check the management service before making another change.",
  "users.upgradeRequired":
    "Explicit offline database migration is required for proxy management.",
  "users.mutationUncertain":
    "A failed or lost response does not prove rollback. Mutations are never retried automatically; refresh and check the latest state first.",
  "users.demoTitle": "User management is disabled in demo mode",
  "users.demoDescription":
    "Demo mode does not call management APIs or issue credentials. Open the production build on the management HTTPS origin to manage users.",
};
