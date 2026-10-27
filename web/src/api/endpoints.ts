import { connectionHost } from "./connection";
import { ApiError } from "./error";
import { canonicalId, count, shape } from "./proxy";
import { validIp } from "./routing";
import { validServerIp } from "./targets";

export type EndpointProtocol = "http" | "https" | "socks5" | "masque";
export type ListenerProtocol = EndpointProtocol | "auto";
export interface EndpointListener {
  protocol: ListenerProtocol;
  bind: string;
  public_address: string | null;
}
export interface EndpointCatalog {
  node_id: string;
  proxy_running: boolean;
  listeners: EndpointListener[];
}
export interface EndpointChoice {
  key: string;
  protocol: EndpointProtocol;
  host: string;
  port: number;
}

const endpointProtocols = ["http", "https", "socks5", "masque"] as const;
const listenerProtocols = [...endpointProtocols, "auto"] as const;
const invalid = (): never => {
  throw new ApiError("format");
};

/** Keep public destinations aligned with server admission, including mapped
 * IPv4 ranges. DNS-looking legacy IPv4 spellings must not change meaning when
 * a client applies WHATWG host parsing. Private and loopback hosts remain valid. */
function publicHost(value: string): string {
  const host = connectionHost(value);
  if (/[\[\]]/.test(value) && !host.includes(":")) return invalid();
  if (validIp(host)) {
    if (!validServerIp(host)) return invalid();
  } else {
    try {
      if (new URL(`http://${host}/`).hostname !== host) return invalid();
    } catch {
      return invalid();
    }
  }
  return host;
}

/** Parse explicit authorities without accepting URLs, userinfo, or implicit ports.
 * Bind addresses may be unspecified; client-facing addresses must be usable
 * host syntax accepted by the existing connection builder. Neither is probed. */
function address(
  value: unknown,
  bind: boolean,
): { host: string; port: number } {
  if (
    typeof value !== "string" ||
    value.length > 259 ||
    /[^\x21-\x7e]/.test(value)
  )
    return invalid();
  const match = /^(?:\[([^\[\]]+)\]|([^:]+)):([1-9][0-9]{0,4})$/.exec(value);
  if (!match || Number(match[3]) > 65535) return invalid();
  const host = match[1] ?? match[2];
  // Brackets are only valid for IPv6; unbracketed IPv6 cannot match above.
  if (match[1] !== undefined ? !host.includes(":") : /[\[\]]/.test(host))
    return invalid();
  if (bind) {
    // SocketAddrV6 may report a numeric interface scope. It is bind metadata,
    // never a client-facing host or an input to connectionUrl.
    const scoped = /^([0-9a-fA-F:.]+)%([0-9]{1,10})$/.exec(host);
    if (
      scoped
        ? !scoped[1].includes(":") ||
          !validIp(scoped[1]) ||
          Number(scoped[2]) > 4294967295
        : !validIp(host)
    )
      return invalid();
  }
  return { host: bind ? host : publicHost(host), port: Number(match[3]) };
}

/** Decode a declared client authority for editing, never infer it from a bind
 * address. The same admission rules protect the existing URL-only catalog. */
export function publicEndpointAddress(value: unknown): {
  host: string;
  port: number;
} {
  return address(value, false);
}

/** Build only non-secret host:port metadata. A protocol/scheme, credentials,
 * path, wildcard bind, implicit port or IPv6 zone is not a public authority. */
export function publicEndpointInput(host: unknown, port: unknown): string {
  if (
    typeof host !== "string" ||
    typeof port !== "string" ||
    !/^[1-9][0-9]{0,4}$/.test(port)
  )
    return invalid();
  let checked = publicHost(host);
  if (checked.includes(":")) {
    checked = new URL(`http://[${checked}]/`).hostname.slice(1, -1);
    // Rust uses dotted decimal for IPv4-mapped IPv6; WHATWG emits two hex
    // groups. Match the settings server without changing the v1 read parser.
    const mapped = /^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(checked);
    if (mapped) {
      const high = parseInt(mapped[1], 16),
        low = parseInt(mapped[2], 16);
      checked = `::ffff:${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
    }
  }
  const authority = `${checked.includes(":") ? `[${checked}]` : checked}:${port}`;
  publicEndpointAddress(authority);
  return authority;
}

/** Validate one bounded node response without inferring public access from bind.
 * An expected identity binds remote responses to their selected node. */
export function endpointCatalog(
  value: unknown,
  expectedNodeId?: string,
): EndpointCatalog {
  shape(value, ["node_id", "proxy_running", "listeners"]);
  if (
    !canonicalId(value.node_id) ||
    value.node_id.length !== 22 ||
    (expectedNodeId !== undefined &&
      (!canonicalId(expectedNodeId) ||
        expectedNodeId.length !== 22 ||
        value.node_id !== expectedNodeId)) ||
    typeof value.proxy_running !== "boolean" ||
    !Array.isArray(value.listeners) ||
    value.listeners.length > 16 ||
    (value.proxy_running && value.listeners.length === 0)
  )
    return invalid();
  const listeners = value.listeners.map((item) => {
    shape(item, ["protocol", "bind", "public_address"]);
    if (!listenerProtocols.includes(item.protocol as ListenerProtocol))
      return invalid();
    address(item.bind, true);
    if (item.public_address !== null) address(item.public_address, false);
    return {
      protocol: item.protocol as ListenerProtocol,
      bind: item.bind as string,
      public_address: item.public_address as string | null,
    };
  });
  return {
    node_id: value.node_id,
    proxy_running: value.proxy_running,
    listeners,
  };
}

/** Offer only explicitly advertised addresses. Choices describe configuration,
 * not reachability; callers must present the catalog's runtime state separately. */
export function endpointChoices(catalog: EndpointCatalog): EndpointChoice[] {
  const checked = endpointCatalog(catalog);
  return checked.listeners.flatMap((listener, index) => {
    if (listener.public_address === null) return [];
    const parsed = address(listener.public_address, false);
    const protocols: EndpointProtocol[] =
      listener.protocol === "auto"
        ? ["http", "https", "socks5"]
        : [listener.protocol];
    return protocols.map((protocol) => ({
      key: `${index}:${protocol}`,
      protocol,
      ...parsed,
    }));
  });
}

/** Match the finite syntax emitted by connectionUsername, including its u64 TTL
 * bound. Arbitrary logins or extension fragments cannot enter a credential URI. */
export function validConnectionUsername(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length > 255 ||
    /[^A-Za-z0-9_-]/.test(value) ||
    !/^vp2_[0-9a-f]{32}(?:-device-(?:windows|linux|android|macos|ios))?(?:-(?:(?:exit|pool)-[0-9a-f]{32}|(?:session|range)-[A-Za-z0-9_]{1,128}|ttl-[1-9][0-9]{0,19}))?$/.test(
      value,
    )
  )
    return false;
  const ttl = /-ttl-([0-9]+)$/.exec(value);
  return ttl === null || BigInt(ttl[1]) <= 18446744073709551615n;
}

/** Return copyable text, never a navigation target. Secrets are optional and
 * must be supplied together; this pure helper does not retain or recover them.
 * MASQUE returns the RFC 9298 section 2 default URI template, not a general
 * HTTP proxy URL. Its client must configure Basic authentication separately:
 * https://www.rfc-editor.org/rfc/rfc9298.html#section-2 */
export function connectionUrl(
  endpoint: Pick<EndpointChoice, "protocol" | "host" | "port">,
  username?: string,
  password?: string,
): string {
  if (
    !endpoint ||
    !endpointProtocols.includes(endpoint.protocol) ||
    typeof endpoint.host !== "string" ||
    /[^\x21-\x7e]/.test(endpoint.host) ||
    !count(endpoint.port, 65535, 1)
  )
    return invalid();
  const host = publicHost(endpoint.host);
  const authority = `${host.includes(":") ? `[${host}]` : host}:${endpoint.port}`;
  const supplied = username !== undefined || password !== undefined;
  if (endpoint.protocol === "masque") {
    if (supplied) return invalid();
    return `https://${authority}/.well-known/masque/udp/{target_host}/{target_port}/`;
  }
  let userinfo = "";
  if (supplied) {
    if (
      !validConnectionUsername(username) ||
      typeof password !== "string" ||
      password.length !== 43 ||
      !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(password)
    )
      return invalid();
    userinfo = `${encodeURIComponent(username)}:${encodeURIComponent(password)}@`;
  }
  return `${endpoint.protocol}://${userinfo}${authority}`;
}
