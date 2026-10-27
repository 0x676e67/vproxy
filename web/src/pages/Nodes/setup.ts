import { ApiError, type ManagementClient } from "../../api/client";
import { canonicalId } from "../../api/proxy";
import type { RemotePolicy, Target } from "../../api/targets";

/** A fixed local admission reason, not a manufactured remote status/code.
 * ApiError inheritance preserves it across the session's safe error boundary. */
export class SetupIssue extends ApiError {
  constructor(
    readonly messageKey:
      "setup.changed" | "setup.inactive" | "setup.ownerMismatch",
  ) {
    super("format");
  }
}

/** Only a canonical public ID is interpolated; all file/origin/epoch inputs
 * remain visibly quoted placeholders, not executable discovered settings. */
export function setupCommands(controllerId: string, childId?: string) {
  if (
    !canonicalId(controllerId) ||
    (childId !== undefined && !canonicalId(childId))
  )
    throw new ApiError("format");
  const controller = `'${controllerId}'`;
  const child = childId
    ? `'${childId}'`
    : "'<CHILD_NODE_ID_FROM_TRUSTED_CHANNEL>'";
  // A child joining this manager must use an already accepted node authority.
  // Making a fresh authority here would not change the manager's TLS roots.
  const plan =
    "--prepared '<CHILD_PREPARED_DIR>' --response '<CHILD_SIGNED_RESPONSE_DIR>' ";
  const binds =
    "--admin-bind '<CHILD_ADMIN_BIND>' --node-bind '<CHILD_NODE_BIND>'";
  return {
    prepare:
      "vproxy manage status --data-dir '<CHILD_PRIVATE_DATA_DIR>'\n" +
      "vproxy manage serve --help",
    prepareChild:
      "vproxy manage setup prepare --output '<CHILD_PREPARED_DIR>' " +
      "--authority-public '<VERIFIED_AUTHORITY_PUBLIC_JSON>' " +
      "--authority-sha256 '<VERIFIED_AUTHORITY_SHA256>' " +
      "--admin-origin '<CHILD_ADMIN_HTTPS_ORIGIN>' --node-origin '<CHILD_NODE_MTLS_ORIGIN>'",
    signChild:
      "vproxy manage setup sign --authority '<EXISTING_AUTHORITY_DIR_ON_SIGNER>' " +
      "--request '<CHILD_REQUEST_PUBLIC_JSON_ON_SIGNER>' --output '<NEW_SIGNED_RESPONSE_DIR>'",
    planChild:
      "vproxy manage setup plan " +
      plan +
      "--output '<CHILD_LAUNCH_DIR>' " +
      binds +
      "\n" +
      "vproxy manage setup check --input '<CHILD_LAUNCH_DIR>'",
    startChild: "sh '<CHILD_LAUNCH_DIR>/start.sh'",
    startChildWindows: "pwsh -File '<CHILD_LAUNCH_DIR>/start.ps1'",
    proxyChild:
      "vproxy manage setup proxy --output '<NEW_PROXY_CONFIG_DIR>'\n" +
      "vproxy manage setup plan " +
      plan +
      "--output '<NEW_PROXY_LAUNCH_DIR>' " +
      binds +
      " --proxy-config '<NEW_PROXY_CONFIG_DIR>/proxy.json'\n" +
      "vproxy manage setup check --input '<NEW_PROXY_LAUNCH_DIR>'",
    serviceChild:
      "vproxy manage setup service --plan '<CHILD_LAUNCH_DIR>' --output '<NEW_SERVICE_PLAN_DIR>'\n" +
      "vproxy manage setup check --input '<NEW_SERVICE_PLAN_DIR>'",
    registerMain:
      "vproxy manage peers register --data-dir '<MAIN_PRIVATE_DATA_DIR>' " +
      `--node-id ${child} --name child ` +
      "--ca '<NODE_CA_PUBLIC_PEM>' --certificate '<CHILD_PUBLIC_NODE_CHAIN_PEM>' " +
      "--server-name '<CHILD_CERTIFICATE_SAN>'",
    registerChild:
      "vproxy manage peers register --data-dir '<CHILD_PRIVATE_DATA_DIR>' " +
      `--node-id ${controller} --name manager ` +
      "--ca '<NODE_CA_PUBLIC_PEM>' --certificate '<MAIN_PUBLIC_NODE_CHAIN_PEM>' " +
      "--server-name '<MAIN_CERTIFICATE_SAN>'",
    probeMain:
      "vproxy manage peers probe --data-dir '<MAIN_PRIVATE_DATA_DIR>' " +
      `--peer-id ${child} --endpoint '<CHILD_NODE_MTLS_ORIGIN>' ` +
      "--ca '<NODE_CA_PUBLIC_PEM>' --cert '<MAIN_NODE_CHAIN_PEM>' --key '<MAIN_NODE_KEY_FILE>'",
    probeChild:
      "vproxy manage peers probe --data-dir '<CHILD_PRIVATE_DATA_DIR>' " +
      `--peer-id ${controller} --endpoint '<MAIN_NODE_MTLS_ORIGIN>' ` +
      "--ca '<NODE_CA_PUBLIC_PEM>' --cert '<CHILD_NODE_CHAIN_PEM>' --key '<CHILD_NODE_KEY_FILE>'",
    grant:
      "vproxy manage owner status --data-dir '<CHILD_PRIVATE_DATA_DIR>'\n" +
      "vproxy manage owner grant --data-dir '<CHILD_PRIVATE_DATA_DIR>' " +
      `--controller-node-id ${controller} --expected-epoch '<CURRENT_EPOCH_FROM_STATUS>'\n` +
      "vproxy manage owner status --data-dir '<CHILD_PRIVATE_DATA_DIR>'",
  };
}

function sameDestination(current: Target, expected: Target): void {
  if (
    current.node_id !== expected.node_id ||
    current.origin !== expected.origin ||
    current.revision !== expected.revision
  )
    throw new SetupIssue("setup.changed");
  if (!current.active || current.retired || current.rollback_detected)
    throw new SetupIssue("setup.inactive");
}

/** One explicit policy read, bracketed by local registry reads. The existing
 * backend checks the selected node's exact DER and wire-envelope node_id before
 * returning RemotePolicy; that DTO intentionally has no caller-trusted ID. */
export async function verifySetup(
  client: Pick<ManagementClient, "target" | "targetPolicy">,
  expected: Target,
  controllerId: string,
  signal: AbortSignal,
): Promise<RemotePolicy> {
  if (!canonicalId(controllerId) || expected.node_id === controllerId)
    throw new ApiError("format");
  const active = () => {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
  };
  active();
  const before = await client.target(expected.node_id, signal);
  active();
  sameDestination(before, expected);
  const policy = await client.targetPolicy(expected.node_id, signal);
  active();
  if (policy.controller_node_id !== controllerId)
    throw new SetupIssue("setup.ownerMismatch");
  const after = await client.target(expected.node_id, signal);
  active();
  sameDestination(after, expected);
  return policy;
}
