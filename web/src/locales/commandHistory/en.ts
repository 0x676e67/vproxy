export default {
  "commandHistory.open": "Command history",
  "commandHistory.title": "Remote command history",
  "commandHistory.scope":
    "Reads records saved on this controller for this node. It does not contact the destination, refresh its receipt or authorize another action.",
  "commandHistory.limit":
    "Up to 128 records are retained per node. Earlier records and commands predating this history may be unavailable. A missing record does not mean the command never executed.",
  "commandHistory.secret":
    "Passwords and original mutation payloads cannot be recovered here. Pending, blocked or superseded commands may still have changed the target. Do not resubmit them based on this history.",
  "commandHistory.historical":
    "Saved and applied are historical receipt states, not proof of the current policy, runtime or client connectivity.",
  "commandHistory.refresh": "Read latest records",
  "commandHistory.previous": "Previous page",
  "commandHistory.next": "Older records",
  "commandHistory.close": "Close history",
  "commandHistory.lookup": "Find exact job",
  "commandHistory.lookupLabel": "Original job ID",
  "commandHistory.lookupHint":
    "Enter the original 22-character job ID. This reads only that record, without retrying a command.",
  "commandHistory.invalidJob": "Enter a canonical 22-character job ID.",
  "commandHistory.missing":
    "This job is not retained for this node on this controller. Its execution remains unknown; no command was resent.",
  "commandHistory.unavailable":
    "History is unavailable. No empty or successful result has been inferred.",
  "commandHistory.empty":
    "No records are retained on this page. This does not prove that no commands executed.",
  "commandHistory.trimmed":
    "Older records have been removed by the retention limit.",
  "commandHistory.oldest": "Oldest retained history sequence",
  "commandHistory.sequence": "History sequence",
  "commandHistory.controller": "Controller node",
  "commandHistory.target": "Destination node",
  "commandHistory.administrator": "Submitting administrator ID",
  "commandHistory.version": "Command protocol",
  "commandHistory.action": "Action",
  "commandHistory.recorded": "First recorded",
  "commandHistory.updated": "Last recorded update",
  "commandHistory.unknownTime": "Unknown",
  "commandHistory.rawTime":
    "Unix seconds: {seconds} (outside the displayable date range)",
  "commandHistory.imported":
    "Imported from the previous command slot; older history is incomplete.",
  "commandHistory.userId": "Receipt user ID",
  "commandHistory.credentialId": "Receipt credential ID",
  "commandHistory.resultUnknown": "Not retained or not received",
  "commandHistory.outcome": "Recorded outcome code",
  "commandHistory.action.create_user": "Create user",
  "commandHistory.action.update_user": "Update user",
  "commandHistory.action.set_user_active": "Change user admission",
  "commandHistory.action.delete_user": "Retire user",
  "commandHistory.action.create_credential": "Create proxy credential",
  "commandHistory.action.set_credential_active": "Change credential admission",
  "commandHistory.action.rotate_credential": "Rotate proxy credential",
  "commandHistory.action.revoke_credential": "Revoke proxy credential",
  "commandHistory.action.create_prefix": "Create IP prefix",
  "commandHistory.action.retire_prefix": "Retire IP prefix",
  "commandHistory.action.create_address": "Create IP address",
  "commandHistory.action.set_address_state": "Change IP address state",
  "commandHistory.action.create_pool": "Create IP pool",
  "commandHistory.action.set_pool_state": "Change IP pool state",
  "commandHistory.action.add_pool_member": "Add pool member",
  "commandHistory.action.remove_pool_member": "Remove pool member",
  "commandHistory.action.set_route_permission": "Change route permission",
  "commandHistory.action.set_user_presets": "Change user TCP presets",
  "commandHistory.action.set_pool_preset": "Change pool TCP preset",
  "commandHistory.action.set_public_address": "Change public proxy address",
  "commandHistory.action.set_admission": "Change proxy admission",
};
