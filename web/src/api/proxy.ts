import { ApiError } from "./error";

export type ProxyProtocol = "http" | "socks5" | "masque";
export interface ProxyUser {
  id: string;
  name: string;
  active: boolean;
  deleted: boolean;
  protocols: ProxyProtocol[];
  concurrent_limit: number;
  revision: string;
}
export interface ProxyCredential {
  id: string;
  user_id: string;
  login: string;
  syntax_version: 2;
  active: boolean;
  revoked: boolean;
  verifier_revision: string;
}
export interface PolicyStatus {
  saved_revision: string;
  applied_revision: string | null;
  durable_applied_revision: string | null;
  proxy_running: boolean;
  user_count: number;
  credential_count: number;
}
export interface Page<T> {
  revision: string;
  items: T[];
  next_cursor: string | null;
}
export interface UserInput {
  name: string;
  protocols: ProxyProtocol[];
  concurrent_limit: number;
}
export interface ChangeResult {
  revision: string;
  user: ProxyUser | null;
  credential: ProxyCredential | null;
  secret: string | null;
}
export interface Pagination {
  after?: string;
  limit?: number;
}
export interface UserSearchInput {
  mode: "name" | "id";
  q: string;
}
export interface UserSearchOptions extends UserSearchInput, Pagination {
  include_deleted?: boolean;
}
export type ChangeKind = "user" | "credential" | "secret";
export type ApiMethod = "GET" | "POST" | "PUT";

export const canonicalId = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9_-]{21}[AQgw]$/.test(value);
export const canonicalRevision = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[1-9][0-9]{0,18}$/.test(value) &&
  (value.length < 19 || value <= "9223372036854775807");
/** Local registry search only; no wildcard or authority is encoded here. */
export function targetFilter(value: string): string {
  if (
    typeof value !== "string" ||
    new TextEncoder().encode(value).length > 256 ||
    /\p{Cc}/u.test(value)
  )
    throw new ApiError("format");
  return value.trim();
}
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
export function shape(
  value: unknown,
  keys: string[],
): asserts value is Record<string, unknown> {
  if (
    !object(value) ||
    Object.keys(value).length !== keys.length ||
    !keys.every((key) => Object.hasOwn(value, key))
  )
    throw new ApiError("format");
}
export const count = (
  value: unknown,
  maximum: number,
  minimum = 0,
): value is number =>
  typeof value === "number" &&
  Number.isSafeInteger(value) &&
  value >= minimum &&
  value <= maximum;
export const validUserName = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  new TextEncoder().encode(value).length <= 128 &&
  value.trim() === value &&
  !/[\u0000-\u001f\u007f-\u009f]/.test(value);
const protocols = (value: unknown): value is ProxyProtocol[] =>
  Array.isArray(value) &&
  value.length <= 3 &&
  new Set(value).size === value.length &&
  value.every((item) => ["http", "socks5", "masque"].includes(item));

export function proxyUser(value: unknown): ProxyUser {
  shape(value, [
    "id",
    "name",
    "active",
    "deleted",
    "protocols",
    "concurrent_limit",
    "revision",
  ]);
  if (
    !canonicalId(value.id) ||
    typeof value.name !== "string" ||
    !validUserName(value.name) ||
    typeof value.active !== "boolean" ||
    typeof value.deleted !== "boolean" ||
    !protocols(value.protocols) ||
    !count(value.concurrent_limit, 1_000_000, 1) ||
    !canonicalRevision(value.revision)
  )
    throw new ApiError("format");
  return {
    id: value.id,
    name: value.name,
    active: value.active,
    deleted: value.deleted,
    protocols: [...value.protocols],
    concurrent_limit: value.concurrent_limit,
    revision: value.revision,
  };
}
export function proxyCredential(value: unknown): ProxyCredential {
  shape(value, [
    "id",
    "user_id",
    "login",
    "syntax_version",
    "active",
    "revoked",
    "verifier_revision",
  ]);
  if (
    !canonicalId(value.id) ||
    !canonicalId(value.user_id) ||
    typeof value.login !== "string" ||
    !/^vp2_[0-9a-f]{32}$/.test(value.login) ||
    value.syntax_version !== 2 ||
    typeof value.active !== "boolean" ||
    typeof value.revoked !== "boolean" ||
    !canonicalRevision(value.verifier_revision)
  )
    throw new ApiError("format");
  return {
    id: value.id,
    user_id: value.user_id,
    login: value.login,
    syntax_version: 2,
    active: value.active,
    revoked: value.revoked,
    verifier_revision: value.verifier_revision,
  };
}
export function policyStatus(value: unknown): PolicyStatus {
  shape(value, [
    "saved_revision",
    "applied_revision",
    "durable_applied_revision",
    "proxy_running",
    "user_count",
    "credential_count",
  ]);
  if (
    !canonicalRevision(value.saved_revision) ||
    !(
      value.applied_revision === null ||
      canonicalRevision(value.applied_revision)
    ) ||
    !(
      value.durable_applied_revision === null ||
      canonicalRevision(value.durable_applied_revision)
    ) ||
    typeof value.proxy_running !== "boolean" ||
    !count(value.user_count, 1024) ||
    !count(value.credential_count, 8192) ||
    (!value.proxy_running && value.applied_revision !== null)
  )
    throw new ApiError("format");
  const saved = value.saved_revision;
  const notNewer = (revision: string | null) =>
    revision === null ||
    revision.length < saved.length ||
    (revision.length === saved.length && revision <= saved);
  if (
    !notNewer(value.applied_revision as string | null) ||
    !notNewer(value.durable_applied_revision as string | null)
  )
    throw new ApiError("format");
  return value as unknown as PolicyStatus;
}
export function page<T extends { id: string }>(
  value: unknown,
  parse: (item: unknown) => T,
): Page<T> {
  shape(value, ["revision", "items", "next_cursor"]);
  if (
    !canonicalRevision(value.revision) ||
    !Array.isArray(value.items) ||
    value.items.length > 50 ||
    !(value.next_cursor === null || canonicalId(value.next_cursor))
  )
    throw new ApiError("format");
  const items = value.items.map(parse);
  if (
    items.some((item, index) => index > 0 && items[index - 1].id >= item.id) ||
    (value.next_cursor !== null && items.at(-1)?.id !== value.next_cursor)
  )
    throw new ApiError("format");
  return { revision: value.revision, items, next_cursor: value.next_cursor };
}
export function changeResult(value: unknown, kind: ChangeKind): ChangeResult {
  shape(value, ["revision", "user", "credential", "secret"]);
  if (!canonicalRevision(value.revision)) throw new ApiError("format");
  const user = value.user === null ? null : proxyUser(value.user);
  const credential =
    value.credential === null ? null : proxyCredential(value.credential);
  if (
    kind === "user"
      ? !user || credential !== null || value.secret !== null
      : !user || !credential || credential.user_id !== user.id
  )
    throw new ApiError("format");
  if (
    kind === "secret"
      ? typeof value.secret !== "string" ||
        !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value.secret)
      : value.secret !== null
  )
    throw new ApiError("format");
  return {
    revision: value.revision,
    user,
    credential,
    secret: value.secret as string | null,
  };
}
export function idPath(value: string): string {
  if (!canonicalId(value)) throw new ApiError("format");
  return encodeURIComponent(value);
}
export function revisionInput(value: string): string {
  if (!canonicalRevision(value)) throw new ApiError("format");
  return value;
}
export function userInput(value: UserInput): UserInput {
  if (
    !validUserName(value.name) ||
    !protocols(value.protocols) ||
    !count(value.concurrent_limit, 1_000_000, 1)
  )
    throw new ApiError("format");
  return {
    name: value.name,
    protocols: [...value.protocols],
    concurrent_limit: value.concurrent_limit,
  };
}
export function listQuery(
  options: Pagination & { include_deleted?: boolean; user_id?: string },
  credentials: boolean,
): string {
  const allowed = credentials
    ? ["after", "limit", "user_id"]
    : ["after", "limit", "include_deleted"];
  if (Object.keys(options).some((key) => !allowed.includes(key)))
    throw new ApiError("format");
  const query = new URLSearchParams();
  if (options.after !== undefined) {
    idPath(options.after);
    query.set("after", options.after);
  }
  if (options.limit !== undefined) {
    if (!count(options.limit, 50, 1)) throw new ApiError("format");
    query.set("limit", String(options.limit));
  }
  if (options.include_deleted !== undefined) {
    if (typeof options.include_deleted !== "boolean")
      throw new ApiError("format");
    query.set("include_deleted", String(options.include_deleted));
  }
  if (options.user_id !== undefined) {
    idPath(options.user_id);
    query.set("user_id", options.user_id);
  }
  return query.size ? `?${query}` : "";
}

export const userSearchCursor = (value: unknown): value is string =>
  typeof value === "string" && /^us1_[A-Za-z0-9_-]{97}[AQgw]$/.test(value);

export function userSearchQuery(options: UserSearchOptions): string {
  if (
    Object.keys(options).some(
      (key) =>
        !["mode", "q", "after", "limit", "include_deleted"].includes(key),
    ) ||
    !["name", "id"].includes(options.mode) ||
    !validUserName(options.q) ||
    /\p{Surrogate}/u.test(options.q) ||
    (options.mode === "id" && !canonicalId(options.q)) ||
    (options.mode === "id" && options.after !== undefined) ||
    (options.after !== undefined && !userSearchCursor(options.after)) ||
    (options.limit !== undefined && !count(options.limit, 50, 1)) ||
    (options.include_deleted !== undefined &&
      typeof options.include_deleted !== "boolean")
  )
    throw new ApiError("format");
  const query = new URLSearchParams({ mode: options.mode, q: options.q });
  if (options.after !== undefined) query.set("after", options.after);
  if (options.limit !== undefined) query.set("limit", String(options.limit));
  if (options.include_deleted !== undefined)
    query.set("include_deleted", String(options.include_deleted));
  return `?${query}`;
}

/** Search cursors are opaque snapshot tokens, not the old list's last user ID. */
export function userSearchPage(
  value: unknown,
  options: UserSearchOptions,
): Page<ProxyUser> {
  userSearchQuery(options);
  shape(value, ["revision", "items", "next_cursor"]);
  const limit = options.limit ?? 25;
  if (
    !canonicalRevision(value.revision) ||
    !Array.isArray(value.items) ||
    value.items.length > limit ||
    !(value.next_cursor === null || userSearchCursor(value.next_cursor)) ||
    (value.next_cursor !== null && value.next_cursor === options.after)
  )
    throw new ApiError("format");
  const revision = value.revision;
  const items = value.items.map(proxyUser);
  if (
    items.some(
      (item, index) =>
        (index > 0 && items[index - 1].id >= item.id) ||
        BigInt(item.revision) > BigInt(revision) ||
        (!options.include_deleted && item.deleted),
    ) ||
    (value.next_cursor !== null && items.length !== limit) ||
    (options.mode === "id" &&
      (items.length > 1 ||
        items.some((item) => item.id !== options.q) ||
        value.next_cursor !== null))
  )
    throw new ApiError("format");
  return { revision, items, next_cursor: value.next_cursor };
}

/** Defense in depth: methods and statuses are fixed even at the transport layer. */
export function endpointStatus(
  endpoint: string,
  method: ApiMethod,
): 200 | 201 | 202 | 204 | readonly [200, 202] {
  const [path, query, extra] = endpoint.split("?");
  if (extra !== undefined) throw new ApiError("format");
  const serviceResult =
    /^\/proxy\/service\/operations\/([1-9][0-9]{0,18})\/([A-Za-z0-9_-]{21}[AQgw])$/.exec(
      path,
    );
  if (serviceResult) {
    if (
      method !== "GET" ||
      !canonicalRevision(serviceResult[1]) ||
      !query?.match(/^controller_epoch=[1-9][0-9]{0,18}$/) ||
      !canonicalRevision(query.slice("controller_epoch=".length))
    )
      throw new ApiError("format");
    return 200;
  }
  const alertExact =
    /^\/(alert-events|alert-episodes)\/([1-9][0-9]{0,18})(?:\/(acknowledge))?$/.exec(
      path,
    );
  if (alertExact) {
    if (
      !canonicalRevision(alertExact[2]) ||
      query !== undefined ||
      (alertExact[3]
        ? alertExact[1] !== "alert-episodes" || method !== "POST"
        : method !== "GET")
    )
      throw new ApiError("format");
    return 200;
  }
  if (path === "/alert-summary") {
    if (query !== undefined || method !== "GET") throw new ApiError("format");
    return 200;
  }
  if (path === "/alert-episodes/acknowledge") {
    if (query !== undefined || method !== "POST") throw new ApiError("format");
    return 200;
  }
  if (path === "/alert-episodes") {
    if (
      method !== "GET" ||
      (query !== undefined && (!query.length || query.length > 256))
    )
      throw new ApiError("format");
    const seen = new Set<string>();
    for (const [key, value] of new URLSearchParams(query)) {
      if (
        seen.has(key) ||
        (key === "before"
          ? !canonicalRevision(value)
          : key !== "through" || (value !== "0" && !canonicalRevision(value)))
      )
        throw new ApiError("format");
      seen.add(key);
    }
    return 200;
  }
  if (path === "/alert-events") {
    if (
      method !== "GET" ||
      (query !== undefined && (!query.length || query.length > 256))
    )
      throw new ApiError("format");
    const seen = new Set<string>();
    for (const [key, value] of new URLSearchParams(query)) {
      if (seen.has(key)) throw new ApiError("format");
      seen.add(key);
      if (
        ["before", "episode_id"].includes(key)
          ? !canonicalRevision(value)
          : key === "origin_node_id"
            ? !canonicalId(value)
            : key !== "limit" ||
              !/^[1-9][0-9]?$/.test(value) ||
              !count(Number(value), 50, 1)
      )
        throw new ApiError("format");
    }
    return 200;
  }
  const commandHistory =
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/commands\/history(?:\/([A-Za-z0-9_-]{21}[AQgw]))?$/.exec(
      path,
    );
  if (commandHistory) {
    if (
      method !== "GET" ||
      (commandHistory[1] && query !== undefined) ||
      (query !== undefined && (query.length === 0 || query.length > 128))
    )
      throw new ApiError("format");
    const seen = new Set<string>();
    for (const [key, value] of new URLSearchParams(query)) {
      if (seen.has(key)) throw new ApiError("format");
      seen.add(key);
      if (
        key === "before"
          ? !canonicalRevision(value)
          : key !== "limit" ||
            !/^[1-9][0-9]?$/.test(value) ||
            !count(Number(value), 50, 1)
      )
        throw new ApiError("format");
    }
    return 200;
  }
  const runtime =
    /^\/(?:proxy|targets\/[A-Za-z0-9_-]{21}[AQgw]\/proxy)\/runtime(?:\/(drain|drains\/[A-Za-z0-9_-]{21}[AQgw]\/[A-Za-z0-9_-]{21}[AQgw]))?$/.exec(
      path,
    );
  if (runtime) {
    if (
      query !== undefined ||
      (runtime[1] === "drain" ? method !== "POST" : method !== "GET")
    )
      throw new ApiError("format");
    return runtime[1] === "drain" ? 202 : 200;
  }
  if (
    /^\/(?:proxy|targets\/[A-Za-z0-9_-]{21}[AQgw]\/proxy)\/addresses\/[A-Za-z0-9_-]{21}[AQgw]$/.test(
      path,
    )
  ) {
    if (method !== "GET" || query !== undefined) throw new ApiError("format");
    return 200;
  }
  if (
    path === "/alerts" ||
    path === "/operations-alerts" ||
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/(?:egress-alerts|operations-alerts)$/.test(
      path,
    )
  ) {
    if (method !== "GET" || (query !== undefined && query.length > 600))
      throw new ApiError("format");
    const values = new URLSearchParams(query);
    const seen = new Set<string>();
    for (const [key, value] of values) {
      if (seen.has(key)) throw new ApiError("format");
      seen.add(key);
      if (
        key === "state"
          ? !["active", "recent"].includes(value)
          : key === "after"
            ? !/^[\x21-\x7e]{1,160}$/.test(value)
            : key !== "limit" ||
              !/^[1-9][0-9]?$/.test(value) ||
              !count(Number(value), 16, 1)
      )
        throw new ApiError("format");
    }
    return 200;
  }
  if (path === "/proxy/user-operations") {
    if (method === "POST" && query === undefined) return 201;
    if (method !== "GET" || (query !== undefined && query.length > 128))
      throw new ApiError("format");
    const values = new URLSearchParams(query);
    const seen = new Set<string>();
    for (const [key, value] of values) {
      if (seen.has(key)) throw new ApiError("format");
      seen.add(key);
      if (
        key === "before"
          ? !canonicalRevision(value)
          : key !== "limit" ||
            !/^[1-9][0-9]?$/.test(value) ||
            !count(Number(value), 50, 1)
      )
        throw new ApiError("format");
    }
    return 200;
  }
  const userOperation =
    /^\/proxy\/user-operations\/([A-Za-z0-9_-]{21}[AQgw])(?:\/(execute))?$/.exec(
      path,
    );
  if (userOperation) {
    if (
      query !== undefined ||
      (userOperation[2] ? method !== "POST" : method !== "GET")
    )
      throw new ApiError("format");
    return 200;
  }
  if (
    path === "/proxy/users/search" ||
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/users\/search$/.test(path)
  ) {
    if (method !== "GET" || query === undefined || query.length > 1024)
      throw new ApiError("format");
    // Unlike URLSearchParams, decodeURIComponent rejects malformed UTF-8 and
    // percent escapes instead of silently searching for a replacement glyph.
    const values = new Map<string, string>();
    for (const pair of query.split("&")) {
      const separator = pair.indexOf("=");
      if (separator < 0) throw new ApiError("format");
      let key: string;
      let value: string;
      try {
        key = decodeURIComponent(pair.slice(0, separator).replace(/\+/g, " "));
        value = decodeURIComponent(
          pair.slice(separator + 1).replace(/\+/g, " "),
        );
      } catch {
        throw new ApiError("format");
      }
      if (values.has(key)) throw new ApiError("format");
      values.set(key, value);
    }
    const options: Record<string, unknown> = Object.fromEntries(values);
    if (values.has("limit")) {
      if (!/^[1-9][0-9]?$/.test(values.get("limit")!))
        throw new ApiError("format");
      options.limit = Number(values.get("limit"));
    }
    if (values.has("include_deleted")) {
      if (!["true", "false"].includes(values.get("include_deleted")!))
        throw new ApiError("format");
      options.include_deleted = values.get("include_deleted") === "true";
    }
    userSearchQuery(options as unknown as UserSearchOptions);
    return 200;
  }
  if (
    ["/proxy/traffic", "/proxy/traffic/buckets"].includes(path) ||
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/traffic(?:\/buckets)?$/.test(path)
  ) {
    if (method !== "GET") throw new ApiError("format");
    const history = path.endsWith("/buckets");
    const values = new URLSearchParams(query);
    const seen = new Set<string>();
    for (const [key] of values) {
      if (
        !(
          history
            ? ["scope", "id", "protocol", "resolution", "after", "limit"]
            : ["scope", "id", "protocol"]
        ).includes(key) ||
        seen.has(key)
      )
        throw new ApiError("format");
      seen.add(key);
    }
    const scope = values.get("scope") ?? "node";
    const id = values.get("id");
    if (
      !(scope === "node"
        ? id === null
        : ["user", "pool", ...(history ? [] : ["credential"])].includes(
            scope,
          ) && canonicalId(id))
    )
      throw new ApiError("format");
    if (
      values.has("protocol") &&
      !["http", "socks5", "masque"].includes(values.get("protocol")!)
    )
      throw new ApiError("format");
    if (
      values.has("resolution") &&
      !["minute", "hour", "day"].includes(values.get("resolution")!)
    )
      throw new ApiError("format");
    const after = values.get("after");
    if (
      after !== null &&
      (!/^(0|[1-9][0-9]{0,15})$/.test(after) ||
        BigInt(after) > BigInt(Number.MAX_SAFE_INTEGER))
    )
      throw new ApiError("format");
    const limit = values.get("limit");
    if (
      limit !== null &&
      (!/^[1-9][0-9]?$/.test(limit) || !count(Number(limit), 50, 1))
    )
      throw new ApiError("format");
    return 200;
  }
  const routingList =
    [
      "/proxy/prefixes",
      "/proxy/addresses",
      "/proxy/pools",
      "/proxy/health",
    ].includes(path) ||
    /^\/proxy\/pools\/[A-Za-z0-9_-]{21}[AQgw]\/members$/.test(path) ||
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/proxy\/(prefixes|addresses|pools|health|pools\/[A-Za-z0-9_-]{21}[AQgw]\/members)$/.test(
      path,
    );
  if (query !== undefined) {
    if (
      method !== "GET" ||
      (!routingList &&
        !["/proxy/users", "/proxy/credentials", "/targets"].includes(path) &&
        !/^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/(users|credentials)$/.test(path))
    )
      throw new ApiError("format");
    const values = new URLSearchParams(query);
    const seen = new Set<string>();
    const options: Record<string, unknown> = {};
    for (const [key, value] of values) {
      const allowed = routingList
        ? ["after", "limit"]
        : path.endsWith("/credentials")
          ? ["after", "limit", "user_id"]
          : path === "/targets"
            ? ["after", "limit", "include_retired", "q"]
            : ["after", "limit", "include_deleted"];
      if (!allowed.includes(key)) throw new ApiError("format");
      if (seen.has(key)) throw new ApiError("format");
      seen.add(key);
      if (key === "limit") {
        if (!/^[1-9][0-9]?$/.test(value)) throw new ApiError("format");
        options.limit = Number(value);
      } else if (key === "include_deleted" || key === "include_retired") {
        if (!["true", "false"].includes(value)) throw new ApiError("format");
        options[key] = value === "true";
      } else options[key] = value;
    }
    if (path === "/targets") {
      if (query.length > 1024) throw new ApiError("format");
      try {
        for (const part of query.split(/[&=]/))
          decodeURIComponent(part.replace(/\+/g, " "));
      } catch {
        throw new ApiError("format");
      }
      if (options.after !== undefined) idPath(options.after as string);
      if (options.limit !== undefined && !count(options.limit, 25, 1))
        throw new ApiError("format");
      if (options.q !== undefined) targetFilter(options.q as string);
    } else {
      listQuery(options, path.endsWith("/credentials"));
      if (
        path.endsWith("/proxy/health") &&
        options.limit !== undefined &&
        !count(options.limit, 16, 1)
      )
        throw new ApiError("format");
    }
  }
  const fixed = new Map([
    ["GET /auth/session", 200],
    ["POST /auth/login", 200],
    ["POST /auth/logout", 204],
    ["POST /auth/password", 204],
    ["GET /node", 200],
    ["GET /notifications/webhook", 200],
    ["POST /notifications/webhook", 200],
    ["POST /notifications/webhook/retry", 200],
    ["GET /tls/acme", 200],
    ["GET /tls/status", 200],
    ["GET /proxy/policy", 200],
    ["GET /proxy/service", 200],
    ["PUT /proxy/service", 202],
    ["GET /proxy/maintenance", 200],
    ["POST /proxy/maintenance", 200],
    ["GET /proxy/endpoints", 200],
    ["GET /proxy/endpoint-settings", 200],
    ["GET /proxy/owner", 200],
    ["PUT /proxy/owner", 200],
    ["GET /targets", 200],
    ["POST /targets", 201],
    ["GET /proxy/users", 200],
    ["POST /proxy/users", 201],
    ["GET /proxy/credentials", 200],
    ["GET /proxy/prefixes", 200],
    ["POST /proxy/prefixes", 201],
    ["GET /proxy/addresses", 200],
    ["POST /proxy/addresses", 201],
    ["GET /proxy/pools", 200],
    ["POST /proxy/pools", 201],
    ["GET /proxy/health", 200],
    ["GET /proxy/presets", 200],
  ]);
  const status = fixed.get(`${method} ${path}`);
  if (status !== undefined) return status as 200 | 201 | 204;
  if (
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/proxy\/maintenance$/.test(path) &&
    method === "GET"
  )
    return 200;
  if (
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/maintenance\/commands\/refresh$/.test(
      path,
    ) &&
    method === "POST"
  )
    return 200;
  if (
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/maintenance\/commands$/.test(path) &&
    method === "POST"
  )
    return [200, 202];
  if (
    /^\/proxy\/endpoint-settings\/[A-Za-z0-9_-]{21}[AQgw]$/.test(path) &&
    method === "PUT"
  )
    return 200;
  if (
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/proxy\/endpoint-settings$/.test(
      path,
    ) &&
    method === "GET"
  )
    return 200;
  if (
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/proxy\/endpoint-commands$/.test(
      path,
    ) &&
    method === "POST"
  )
    return [200, 202];
  if (
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/proxy\/endpoint-command\/refresh$/.test(
      path,
    ) &&
    method === "POST"
  )
    return 200;
  if (
    /^\/proxy\/(users|pools)\/[A-Za-z0-9_-]{21}[AQgw]\/presets$/.test(path) &&
    (method === "GET" || method === "PUT")
  )
    return 200;
  if (
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/proxy\/(endpoints|presets|(users|pools)\/[A-Za-z0-9_-]{21}[AQgw]\/presets)$/.test(
      path,
    ) &&
    method === "GET"
  )
    return 200;
  if (
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/preset\/commands$/.test(path) &&
    method === "POST"
  )
    return [200, 202];
  if (
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/routing\/commands$/.test(path) &&
    method === "POST"
  )
    return [200, 202];
  if (
    /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/proxy\/(prefixes|addresses|pools|health|pools\/[A-Za-z0-9_-]{21}[AQgw]\/members|users\/[A-Za-z0-9_-]{21}[AQgw]\/routing)$/.test(
      path,
    ) &&
    method === "GET"
  )
    return 200;
  const routing =
    /^\/proxy\/(prefixes|addresses|pools|users)\/([^/]+)\/(retire|state|members(?:\/remove)?|routing)$/.exec(
      path,
    );
  // User state belongs to the policy endpoints below; this classifier owns
  // only user routing, so it must not reject a valid user-state mutation.
  if (routing && (routing[1] !== "users" || routing[3] === "routing")) {
    if (!canonicalId(routing[2])) throw new ApiError("format");
    const [, resource, , action] = routing;
    if (
      resource === "users" &&
      action === "routing" &&
      (method === "GET" || method === "PUT")
    )
      return 200;
    if (resource === "pools" && action === "members" && method === "GET")
      return 200;
    if (
      method === "POST" &&
      ((resource === "prefixes" && action === "retire") ||
        (resource === "addresses" && action === "state") ||
        (resource === "pools" &&
          ["state", "members", "members/remove"].includes(action)))
    )
      return 200;
    throw new ApiError("format");
  }
  const targetSecret =
    /^\/targets\/([^/]+)\/proxy\/credentials\/([^/]+)\/secret$/.exec(path);
  if (targetSecret) {
    if (
      method !== "POST" ||
      query !== undefined ||
      !canonicalId(targetSecret[1]) ||
      !canonicalId(targetSecret[2])
    )
      throw new ApiError("format");
    return 200;
  }
  const target =
    /^\/targets\/([^/]+)(?:\/(policy|users|credentials|state|retire|commands|command)(?:\/(retry|supersede|refresh|user-result))?)?$/.exec(
      path,
    );
  if (target) {
    if (!canonicalId(target[1])) throw new ApiError("format");
    const [, , action, operation] = target;
    if (
      method === "GET" &&
      !operation &&
      (!action ||
        ["policy", "users", "credentials", "command"].includes(action))
    )
      return 200;
    if (method === "PUT" && !action) return 200;
    if (method === "POST" && !operation && action === "commands")
      return [200, 202];
    if (
      method === "POST" &&
      ((!operation && ["state", "retire"].includes(action)) ||
        (action === "command" &&
          ["retry", "supersede", "refresh", "user-result"].includes(operation)))
    )
      return 200;
    throw new ApiError("format");
  }
  const match =
    /^\/proxy\/(users|credentials)\/([^/]+)(?:\/(state|delete|credentials|rotate|revoke|secret))?$/.exec(
      path,
    );
  if (!match || !canonicalId(match[2])) throw new ApiError("format");
  const [, resource, , action] = match;
  if (resource === "users" && !action && method === "PUT") return 200;
  if (
    method === "POST" &&
    (resource === "users"
      ? ["state", "delete", "credentials"]
      : ["state", "rotate", "revoke", "secret"]
    ).includes(action)
  )
    return action === "credentials" ? 201 : 200;
  throw new ApiError("format");
}
