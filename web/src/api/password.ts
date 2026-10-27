import { ApiError } from "./error";

/** These messages contain no credentials and survive only until the next login. */
export type PasswordChangeNotice =
  "changed" | "unconfirmed" | "blocked" | "failed";

function boundedPassword(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    new TextEncoder().encode(value).length <= 1024 &&
    !/[\u0000-\u001f\u007f-\u009f]/.test(value) &&
    ![...value].some((character) => {
      const point = character.codePointAt(0)!;
      return point >= 0xd800 && point <= 0xdfff;
    })
  );
}

export const validCurrentPassword = (value: unknown): value is string =>
  boundedPassword(value);
export const validNewPassword = (value: unknown): value is string =>
  boundedPassword(value) && [...value].length >= 12;

const preFenceFailures = new Map([
  ["invalid_password_input", 400],
  ["invalid_json", 400],
  ["invalid_body", 400],
  ["invalid_headers", 400],
  ["invalid_credentials", 403],
  ["invalid_csrf", 403],
  ["invalid_origin", 403],
  ["invalid_host", 403],
  ["json_required", 415],
  ["body_too_large", 413],
  ["body_timeout", 408],
  ["login_rate_limited", 429],
  ["authentication_busy", 503],
  ["password_change_busy", 503],
  ["management_upgrade_required", 503],
]);

/** Only explicit pre-fence refusals keep the current view. A lost/malformed
 * response cannot prove rollback; never infer success or retry the mutation. */
export function passwordChangeDisposition(
  error: ApiError,
): "retain" | PasswordChangeNotice {
  if (error.kind === "https") return "retain";
  if (error.kind !== "server") return "unconfirmed";
  const expectedStatus = preFenceFailures.get(error.code ?? "");
  if (expectedStatus !== undefined && expectedStatus === error.status)
    return "retain";
  if (error.code === "password_change_outcome_unknown" && error.status === 503)
    return "blocked";
  if (
    (error.code === "password_change_failed" && error.status === 500) ||
    (error.code === "password_change_conflict" && error.status === 409) ||
    (error.code === "authentication_required" && error.status === 403)
  )
    return "failed";
  return "unconfirmed";
}
