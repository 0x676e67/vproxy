import { ApiError } from "./error";
import { canonicalId, canonicalRevision, count, shape } from "./proxy";
import { decimalZero, job, type Job } from "./targets";

const versionActions = [
  [
    "create_user",
    "update_user",
    "set_user_active",
    "delete_user",
    "create_credential",
    "set_credential_active",
    "rotate_credential",
    "revoke_credential",
  ],
  [
    "create_prefix",
    "retire_prefix",
    "create_address",
    "set_address_state",
    "create_pool",
    "set_pool_state",
    "add_pool_member",
    "remove_pool_member",
    "set_route_permission",
  ],
  ["set_user_presets", "set_pool_preset"],
  ["set_public_address"],
  ["set_admission"],
] as const;
export type CommandHistoryAction = (typeof versionActions)[number][number];
export interface CommandHistoryEntry {
  sequence: string;
  controller_node_id: string;
  administrator_id: string;
  protocol_version: number;
  action: CommandHistoryAction;
  job: Job;
  user_id: string | null;
  credential_id: string | null;
  imported: boolean;
  recorded_at_unix_s: string | null;
  updated_at_unix_s: string | null;
}
export interface CommandHistoryOptions {
  before?: string;
  limit?: number;
}
export interface CommandHistoryPage {
  items: CommandHistoryEntry[];
  next_cursor: string | null;
  oldest_sequence: string | null;
  trimmed: boolean;
}
const invalid = (): never => {
  throw new ApiError("format");
};

/** A local history row is a historical fact, not authority to retry or recover a secret. */
export function commandHistoryEntry(
  value: unknown,
  peer: string,
  controller: string,
  expectedJob?: string,
): CommandHistoryEntry {
  shape(value, [
    "sequence",
    "controller_node_id",
    "administrator_id",
    "protocol_version",
    "action",
    "job",
    "user_id",
    "credential_id",
    "imported",
    "recorded_at_unix_s",
    "updated_at_unix_s",
  ]);
  if (
    !canonicalId(peer) ||
    !canonicalId(controller) ||
    (expectedJob !== undefined && !canonicalId(expectedJob)) ||
    !canonicalRevision(value.sequence) ||
    value.controller_node_id !== controller ||
    !canonicalId(value.administrator_id) ||
    !count(value.protocol_version, 5, 1) ||
    !versionActions[value.protocol_version - 1].some(
      (action) => action === value.action,
    ) ||
    !(value.user_id === null || canonicalId(value.user_id)) ||
    !(value.credential_id === null || canonicalId(value.credential_id)) ||
    typeof value.imported !== "boolean" ||
    !(
      value.recorded_at_unix_s === null || decimalZero(value.recorded_at_unix_s)
    ) ||
    !(
      value.updated_at_unix_s === null || decimalZero(value.updated_at_unix_s)
    ) ||
    (value.imported && value.recorded_at_unix_s !== null)
  )
    return invalid();
  const ticket = job(value.job, peer);
  if (!ticket || (expectedJob !== undefined && ticket.job_id !== expectedJob))
    return invalid();
  const complete = ticket.state === "saved" || ticket.state === "applied";
  if (
    (!complete && (value.user_id !== null || value.credential_id !== null)) ||
    (value.protocol_version !== 1 &&
      (value.user_id !== null || value.credential_id !== null))
  )
    return invalid();
  switch (value.protocol_version) {
    case 1:
      if (
        ticket.resource !== undefined ||
        ticket.routing ||
        ticket.preset ||
        ticket.maintenance ||
        ticket.user_creation !== (value.action === "create_user") ||
        (complete && !value.imported && !canonicalId(value.user_id)) ||
        (String(value.action).endsWith("_user") ||
        value.action === "set_user_active"
          ? value.credential_id !== null
          : complete && !value.imported && !canonicalId(value.credential_id))
      )
        return invalid();
      break;
    case 2: {
      const kind =
        value.action === "set_route_permission"
          ? "permission"
          : ["create_prefix", "retire_prefix"].includes(String(value.action))
            ? "prefix"
            : ["create_address", "set_address_state"].includes(
                  String(value.action),
                )
              ? "address"
              : "pool";
      if (
        ticket.resource !== undefined ||
        ticket.user_creation ||
        ticket.preset ||
        ticket.maintenance ||
        (complete
          ? ticket.routing?.kind !== kind
          : ticket.routing !== undefined)
      )
        return invalid();
      break;
    }
    case 3:
      if (
        ticket.resource !== undefined ||
        ticket.user_creation ||
        ticket.routing ||
        ticket.maintenance ||
        (complete
          ? ticket.preset?.kind !==
            (value.action === "set_user_presets" ? "user" : "pool")
          : ticket.preset !== undefined)
      )
        return invalid();
      break;
    case 4:
      if (ticket.resource !== "proxy_endpoints") return invalid();
      break;
    case 5:
      if (ticket.resource !== undefined || !ticket.maintenance)
        return invalid();
      break;
  }
  return { ...value, job: ticket } as unknown as CommandHistoryEntry;
}

export function commandHistoryQuery(options: CommandHistoryOptions): string {
  if (
    typeof options !== "object" ||
    options === null ||
    Array.isArray(options) ||
    Object.keys(options).some((key) => !["before", "limit"].includes(key)) ||
    (options.before !== undefined && !canonicalRevision(options.before)) ||
    (options.limit !== undefined && !count(options.limit, 50, 1))
  )
    return invalid();
  const query = new URLSearchParams();
  if (options.before !== undefined) query.set("before", options.before);
  if (options.limit !== undefined) query.set("limit", String(options.limit));
  return query.size ? `?${query}` : "";
}

/** One descending snapshot. The retained floor is not proof that older work never ran. */
export function commandHistoryPage(
  value: unknown,
  peer: string,
  controller: string,
  options: CommandHistoryOptions,
): CommandHistoryPage {
  commandHistoryQuery(options);
  shape(value, ["items", "next_cursor", "oldest_sequence", "trimmed"]);
  if (
    !Array.isArray(value.items) ||
    value.items.length > (options.limit ?? 25) ||
    !(value.next_cursor === null || canonicalRevision(value.next_cursor)) ||
    !(
      value.oldest_sequence === null || canonicalRevision(value.oldest_sequence)
    ) ||
    typeof value.trimmed !== "boolean"
  )
    return invalid();
  const items = value.items.map((item) =>
    commandHistoryEntry(item, peer, controller),
  );
  const last = items.at(-1);
  if (
    new Set(items.map((item) => item.job.job_id)).size !== items.length ||
    items.some(
      (item, index) =>
        (index > 0 &&
          BigInt(item.sequence) >= BigInt(items[index - 1].sequence)) ||
        (options.before !== undefined &&
          BigInt(item.sequence) >= BigInt(options.before)),
    ) ||
    (last &&
      (value.oldest_sequence === null ||
        BigInt(last.sequence) < BigInt(value.oldest_sequence))) ||
    (value.next_cursor !== null
      ? items.length !== (options.limit ?? 25) ||
        last?.sequence !== value.next_cursor ||
        value.oldest_sequence === null ||
        BigInt(value.next_cursor) <= BigInt(value.oldest_sequence)
      : !!last && last.sequence !== value.oldest_sequence) ||
    (!last && value.oldest_sequence !== null && options.before === undefined)
  )
    return invalid();
  return {
    items,
    next_cursor: value.next_cursor,
    oldest_sequence: value.oldest_sequence,
    trimmed: value.trimmed,
  };
}

/** Date display is optional; lossless seconds remain available outside JS's date range. */
export function commandHistoryDate(seconds: string): Date | null {
  if (!decimalZero(seconds)) return null;
  const milliseconds = BigInt(seconds) * 1000n;
  return milliseconds <= 8_640_000_000_000_000n
    ? new Date(Number(milliseconds))
    : null;
}
