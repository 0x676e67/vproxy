import { ApiError } from "../api/error";
import { canonicalId, canonicalRevision } from "../api/proxy";
import { trafficLocation } from "../api/traffic";

export type ScopedPath = "/users" | "/resources" | "/traffic" | "/alerts";
export interface ScopeLocation {
  pathname: string;
  search: string;
}

export function isScopedPath(path: string): path is ScopedPath {
  return ["/users", "/resources", "/traffic", "/alerts"].includes(path);
}

/** An absent target explicitly selects this node, never a remembered remote.
 * Invalid locations must not fall back to local reads or mutation authority.
 */
export function scopeLocation({
  pathname,
  search,
}: ScopeLocation): string | null {
  if (!isScopedPath(pathname) || search.length > 1024)
    throw new ApiError("format");
  if (pathname === "/traffic") return trafficLocation(search).peer;
  if (pathname === "/resources") return resourceLocation(search).peer;
  if (pathname === "/alerts") return alertLocation(search).peer;
  const query = new URLSearchParams(search);
  const keys = [...query.keys()];
  if (keys.some((key) => key !== "target") || keys.length > 1)
    throw new ApiError("format");
  const target = query.get("target");
  if (target !== null && !canonicalId(target)) throw new ApiError("format");
  return target;
}

/** History reads the local durable journal. A target here filters origin only;
 * it never selects a remote API, and an event ID cannot select a mutation. */
export function alertLocation(search: string): {
  peer: string | null;
  history: boolean;
  eventId: string | null;
} {
  if (search.length > 1024) throw new ApiError("format");
  const query = new URLSearchParams(search),
    keys = [...query.keys()];
  const peer = query.get("target"),
    view = query.get("view"),
    eventId = query.get("event");
  if (
    new Set(keys).size !== keys.length ||
    keys.some((key) => !["target", "view", "event"].includes(key)) ||
    (peer !== null && !canonicalId(peer)) ||
    (view !== null && view !== "history") ||
    (eventId !== null && (view !== "history" || !canonicalRevision(eventId)))
  )
    throw new ApiError("format");
  return { peer, history: view === "history", eventId };
}

export function alertHistoryHref(
  peer: string | null = null,
  eventId: string | null = null,
): string {
  const query = new URLSearchParams({ view: "history" });
  if (peer !== null) query.set("target", peer);
  if (eventId !== null) query.set("event", eventId);
  const search = `?${query}`;
  alertLocation(search);
  return `/alerts${search}`;
}

/** Address selection exists only on Resources; switching workspaces drops it. */
export function resourceLocation(search: string): {
  peer: string | null;
  address: string | null;
} {
  if (search.length > 1024) throw new ApiError("format");
  const query = new URLSearchParams(search);
  const keys = [...query.keys()];
  if (
    keys.some((key) => key !== "target" && key !== "address") ||
    new Set(keys).size !== keys.length
  )
    throw new ApiError("format");
  const peer = query.get("target");
  const address = query.get("address");
  if (
    (peer !== null && !canonicalId(peer)) ||
    (address !== null && !canonicalId(address))
  )
    throw new ApiError("format");
  return { peer, address };
}

/** Fixed page and canonical node ID only; no entity/filter state crosses pages. */
export function scopeHref(path: ScopedPath, target: string | null): string {
  if (!isScopedPath(path) || (target !== null && !canonicalId(target)))
    throw new ApiError("format");
  return target === null ? path : `${path}?${new URLSearchParams({ target })}`;
}

/** Service is local-only, so its menu link never carries a remote target.
 * Invalid scoped URLs offer only the global Nodes recovery link. */
export function menuScopeHref(
  path: string | undefined,
  current: ScopeLocation,
): string | null {
  if (path === "/nodes") return "/nodes";
  if (path === "/service") {
    try {
      if (isScopedPath(current.pathname)) scopeLocation(current);
      return "/service";
    } catch {
      return null;
    }
  }
  if (!path || !isScopedPath(path)) return null;
  if (!isScopedPath(current.pathname)) return scopeHref(path, null);
  try {
    return scopeHref(path, scopeLocation(current));
  } catch {
    return null;
  }
}

/** Validate before entering Router, even when called outside a page picker. */
export function checkedScopeHref(href: string): string {
  const match = /^(\/users|\/resources|\/traffic|\/alerts)(\?[^#]*)?$/.exec(
    href,
  );
  if (!match || match[0] !== href) throw new ApiError("format");
  scopeLocation({ pathname: match[1], search: match[2] ?? "" });
  return href;
}
