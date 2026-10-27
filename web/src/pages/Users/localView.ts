import { ApiError, apiError, type ManagementClient } from "../../api/client";
import type { Pagination, UserSearchInput } from "../../api/proxy";

function pause(signal: AbortSignal, milliseconds: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      reject(new DOMException("Aborted", "AbortError"));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, milliseconds);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
}

/** Only these local, public-metadata GETs tolerate transient admission busy.
 * Sample the entire view again; a retry must not mix revisions or keep a
 * failed sample's sibling alive. Writes and secret reads never enter here. */
export async function readLocalUserView(
  client: Pick<ManagementClient, "policy" | "users" | "userSearch" | "owner">,
  options: Pagination & { include_deleted: boolean },
  search: UserSearchInput | null,
  signal: AbortSignal,
) {
  for (let attempt = 0; ; attempt += 1) {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const sample = new AbortController();
    const abort = () => sample.abort();
    signal.addEventListener("abort", abort, { once: true });
    try {
      const [policy, page] = await Promise.all([
        client.policy(sample.signal),
        search
          ? client.userSearch({ ...options, ...search }, sample.signal)
          : client.users(options, sample.signal),
      ]);
      if (sample.signal.aborted)
        throw new DOMException("Aborted", "AbortError");
      // Separate responses still need the existing CAS consistency check.
      if (policy.saved_revision !== page.revision)
        throw new ApiError(
          "server",
          search ? "user_search_changed" : "policy_conflict",
          409,
        );
      const owner = await client.owner(sample.signal);
      if (sample.signal.aborted)
        throw new DOMException("Aborted", "AbortError");
      return { policy, page, owner };
    } catch (cause) {
      const error = apiError(cause);
      if (
        signal.aborted ||
        attempt >= 2 ||
        error.kind !== "server" ||
        error.status !== 503 ||
        error.code !== "policy_busy"
      )
        throw cause;
    } finally {
      sample.abort();
      signal.removeEventListener("abort", abort);
    }
    await pause(signal, 250 * (attempt + 1));
  }
}
