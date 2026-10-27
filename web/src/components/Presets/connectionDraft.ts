import { shape, canonicalId } from "../../api/proxy";
import {
  publicEndpointInput,
  type EndpointProtocol,
} from "../../api/endpoints";

export interface ConnectionDraft {
  endpoint: string;
  host: string;
  port: string;
  protocol: EndpointProtocol;
}

export interface ConnectionDraftScope {
  administrator: string;
  node: string;
  user: string;
  credential: string;
}

const protocols = ["http", "https", "socks5", "masque"] as const;
const prefix = "vproxy.connection.v1.";
type DraftStorage = Pick<Storage, "getItem" | "setItem">;

function key(scope: ConnectionDraftScope): string {
  const ids = [scope.administrator, scope.node, scope.user, scope.credential];
  if (!ids.every((value) => canonicalId(value) && value.length === 22))
    throw new Error("Invalid connection draft scope");
  return prefix + ids.join(".");
}

/** Only an endpoint tuple is retained. Never accept a whole form, login,
 * password, routing extension, authorization snapshot or generated URL. */
function draft(value: unknown): ConnectionDraft {
  shape(value, ["endpoint", "host", "port", "protocol"]);
  if (
    typeof value.endpoint !== "string" ||
    !/^(?:manual|(?:[0-9]|1[0-5]):(?:http|https|socks5|masque))$/.test(
      value.endpoint,
    ) ||
    !protocols.includes(value.protocol as EndpointProtocol)
  )
    throw new Error("Invalid connection draft");
  publicEndpointInput(value.host, value.port);
  return {
    endpoint: value.endpoint,
    host: value.host as string,
    port: value.port as string,
    protocol: value.protocol as EndpointProtocol,
  };
}

/** Read one bounded, non-secret preference. It is not authority or evidence
 * that the endpoint still exists: callers must reconcile a fresh node catalog. */
export function readConnectionDraft(
  scope: ConnectionDraftScope,
  storage?: DraftStorage,
): { value: ConnectionDraft | null; unavailable: boolean } {
  let raw: string | null;
  try {
    raw = (storage ?? window.localStorage).getItem(key(scope));
  } catch {
    return { value: null, unavailable: true };
  }
  try {
    return {
      value: raw === null || raw.length > 1024 ? null : draft(JSON.parse(raw)),
      unavailable: false,
    };
  } catch {
    // Corrupt or older browser data cannot become an endpoint or authorization.
    return { value: null, unavailable: false };
  }
}

/** Project the four named fields explicitly, so even a full form containing a
 * password cannot serialize extra data. Incomplete edits retain the last valid
 * tuple; blocked/quota-limited browser storage must remain visible to the UI. */
export function writeConnectionDraft(
  scope: ConnectionDraftScope,
  fields: Partial<ConnectionDraft>,
  storage?: DraftStorage,
): "saved" | "incomplete" | "unavailable" {
  let value: ConnectionDraft;
  try {
    value = draft({
      endpoint: fields.endpoint,
      host: fields.host,
      port: fields.port,
      protocol: fields.protocol,
    });
  } catch {
    return "incomplete";
  }
  try {
    (storage ?? window.localStorage).setItem(key(scope), JSON.stringify(value));
    return "saved";
  } catch {
    return "unavailable";
  }
}
