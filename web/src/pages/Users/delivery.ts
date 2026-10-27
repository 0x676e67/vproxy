import type { ProxyUser } from "../../api/proxy";
import type { ScopeChange } from "../../api/scope";

/** A completed create response, retained independently of the current page.
 * It authorizes no follow-up write: credential creation still needs a click,
 * a fresh policy observation and the existing explicit confirmation. */
export interface CreatedUserDelivery {
  user: ProxyUser;
  revision: string;
}

export function createdUserDelivery(
  result: ScopeChange,
): CreatedUserDelivery | null {
  const response = result.submission?.response;
  if (
    !result.user ||
    !result.revision ||
    (result.submission &&
      (!response ||
        response.replayed ||
        response.receipt.status === "rejected"))
  )
    return null;
  return { user: result.user, revision: result.revision };
}
