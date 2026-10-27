import type { ManagementClient } from "./client";
import { ApiError } from "./error";
import { userInput, type ChangeResult } from "./proxy";
import {
  nextCommand,
  type Mutation,
  type RemotePolicy,
  type Owner,
  type Submission,
  type Target,
} from "./targets";

export type ProxyScope =
  { kind: "local" } | { kind: "target"; target: Target; policy: RemotePolicy };
/** Remote ownership restricts local writes, not non-secret local inspection. */
export function scopeAccess(
  scope: ProxyScope | null,
  owner: Owner | null,
  blocked: boolean,
) {
  const readDisabled = blocked || !scope;
  return {
    readDisabled,
    writeDisabled:
      readDisabled ||
      (scope?.kind === "local" && owner?.controller_node_id !== null),
  };
}
export interface ScopeChange extends Omit<ChangeResult, "revision"> {
  revision: string | null;
  submission: Submission | null;
}
type Operation =
  | "createUser"
  | "updateUser"
  | "userState"
  | "deleteUser"
  | "createCredential"
  | "credentialState"
  | "rotateCredential"
  | "revokeCredential";
/** A small fixed protocol adapter, not an arbitrary request/CRUD framework. */
export type ProxyOperations = {
  [K in Operation]: (
    ...args: Parameters<ManagementClient[K]>
  ) => Promise<ScopeChange>;
};

export function proxyOperations(
  client: ManagementClient,
  scope: ProxyScope,
): ProxyOperations {
  const local = async (
    result: Promise<ChangeResult>,
  ): Promise<ScopeChange> => ({ ...(await result), submission: null });
  const remote = async (
    mutation: Mutation,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ScopeChange> => {
    if (scope.kind !== "target") throw new ApiError("format");
    // A credential page can have moved ahead of the last verified policy read.
    // Do not invent a new command sequence from stale browser state.
    if (scope.policy.saved_revision !== revision)
      throw new ApiError("server", "policy_conflict", 409);
    const submitted = await client.targetCommand(
      scope.target.node_id,
      {
        expected_target_revision: scope.target.revision,
        controller_epoch: scope.policy.controller_epoch,
        command_id: nextCommand(scope.policy.last_terminal_command),
        expected_policy_revision: revision,
        mutation,
      },
      csrf,
      signal,
    );
    const response = submitted.response;
    const result: ScopeChange = {
      revision: response?.receipt.policy_revision ?? null,
      user: response?.user ?? null,
      credential: response?.credential ?? null,
      secret: response?.secret ?? null,
      submission: submitted,
    };
    // Secret UI owns the sole retained reference; metadata/ticket views do not.
    if (response) {
      response.secret = null;
      response.secret_available = false;
    }
    return result;
  };
  return {
    createUser: (input, revision, csrf, signal) =>
      scope.kind === "local"
        ? local(client.createUser(input, revision, csrf, signal))
        : remote(
            { ...userInput(input), action: "create_user" },
            revision,
            csrf,
            signal,
          ),
    updateUser: (id, input, revision, csrf, signal) =>
      scope.kind === "local"
        ? local(client.updateUser(id, input, revision, csrf, signal))
        : remote(
            { ...userInput(input), action: "update_user", id },
            revision,
            csrf,
            signal,
          ),
    userState: (id, active, revision, csrf, signal) =>
      scope.kind === "local"
        ? local(client.userState(id, active, revision, csrf, signal))
        : remote(
            { action: "set_user_active", id, active },
            revision,
            csrf,
            signal,
          ),
    deleteUser: (id, revision, csrf, signal) =>
      scope.kind === "local"
        ? local(client.deleteUser(id, revision, csrf, signal))
        : remote({ action: "delete_user", id }, revision, csrf, signal),
    createCredential: (user_id, revision, csrf, signal) =>
      scope.kind === "local"
        ? local(client.createCredential(user_id, revision, csrf, signal))
        : remote(
            { action: "create_credential", user_id },
            revision,
            csrf,
            signal,
          ),
    credentialState: (id, active, revision, csrf, signal) =>
      scope.kind === "local"
        ? local(client.credentialState(id, active, revision, csrf, signal))
        : remote(
            { action: "set_credential_active", id, active },
            revision,
            csrf,
            signal,
          ),
    rotateCredential: (id, revision, csrf, signal) =>
      scope.kind === "local"
        ? local(client.rotateCredential(id, revision, csrf, signal))
        : remote({ action: "rotate_credential", id }, revision, csrf, signal),
    revokeCredential: (id, revision, csrf, signal) =>
      scope.kind === "local"
        ? local(client.revokeCredential(id, revision, csrf, signal))
        : remote({ action: "revoke_credential", id }, revision, csrf, signal),
  };
}
