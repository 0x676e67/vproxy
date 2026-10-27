import { ApiError } from "./error";
import {
  canonicalId,
  canonicalRevision,
  shape,
  type ProxyCredential,
} from "./proxy";

export interface CredentialSecretInput {
  expected_node_id: string;
  controller_epoch: string;
  verifier_revision: string;
}
export interface TargetCredentialSecretInput extends CredentialSecretInput {
  expected_target_revision: string;
  user_id: string;
}
/** Ephemeral response only. Never retain this in preferences, task history or logs. */
export interface CredentialSecret {
  credential_id: string;
  user_id: string;
  verifier_revision: string;
  secret: string;
}
export function credentialSecretInput(
  value: CredentialSecretInput,
): CredentialSecretInput {
  shape(value, ["expected_node_id", "controller_epoch", "verifier_revision"]);
  if (
    !canonicalId(value.expected_node_id) ||
    !canonicalRevision(value.controller_epoch) ||
    !canonicalRevision(value.verifier_revision)
  )
    throw new ApiError("format");
  return { ...value };
}
export function credentialSecret(
  value: unknown,
  credential: Pick<ProxyCredential, "id" | "user_id" | "verifier_revision">,
): CredentialSecret {
  shape(value, ["credential_id", "user_id", "verifier_revision", "secret"]);
  if (
    !canonicalId(credential.id) ||
    !canonicalId(credential.user_id) ||
    !canonicalRevision(credential.verifier_revision) ||
    value.credential_id !== credential.id ||
    value.user_id !== credential.user_id ||
    value.verifier_revision !== credential.verifier_revision ||
    typeof value.secret !== "string" ||
    !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value.secret)
  ) {
    throw new ApiError("format");
  }
  return value as unknown as CredentialSecret;
}

/** The source checks its inspected registration; the target checks owner and
 * exact user/credential generation. No password belongs in this selection. */
export function targetCredentialSecretInput(
  value: TargetCredentialSecretInput,
): TargetCredentialSecretInput {
  shape(value, [
    "expected_node_id",
    "expected_target_revision",
    "user_id",
    "controller_epoch",
    "verifier_revision",
  ]);
  const checked = credentialSecretInput({
    expected_node_id: value.expected_node_id,
    controller_epoch: value.controller_epoch,
    verifier_revision: value.verifier_revision,
  });
  if (
    !canonicalRevision(value.expected_target_revision) ||
    !canonicalId(value.user_id)
  )
    throw new ApiError("format");
  return {
    ...checked,
    expected_target_revision: value.expected_target_revision,
    user_id: value.user_id,
  };
}
