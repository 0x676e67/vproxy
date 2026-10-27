/** Stable region identifiers; translated display labels belong to the locale catalogs. */
export type RegionKey =
  "hongKong" | "tokyo" | "singapore" | "losAngeles" | "frankfurt" | "osaka";

/**
 * Presentation model: absent observations remain unknown, never synthetic zeroes.
 *
 * A management link, proxy service, and outbound-IP health are separate signals.
 * Losing the link cannot prove that the proxy stopped or that its IPs are unhealthy.
 * `null` means no current observation; a measured zero remains a real zero.
 */
export interface ManagedNode {
  /** Stable opaque identity, independent of a mutable display name. */
  id: string;
  name: string;
  /** The identity endpoint does not yet describe parent/child relationships. */
  relationshipsKnown: boolean;
  version?: string;
  os?: string;
  arch?: string;
  /** A built-in region can be translated; a user-provided region is not translated. */
  region: RegionKey | null;
  customRegion?: string;
  /** Deployment zone is a machine identifier, not a localized region name. */
  zone: string | null;
  /** This relationship describes management, never the route taken by proxy traffic. */
  parentId: string | null;
  childCount: number | null;
  local: boolean;
  /** Pending enrollment is not a failed connection to an already enrolled node. */
  control: "connected" | "disconnected" | "pending";
  /** No disconnected sample claims that its independently running proxy has stopped. */
  proxy: "running" | "unknown";
  /** Age of the latest management observation, or null before any observation. */
  observationAgeSeconds: number | null;
  /** Health observations have their own timestamp and may outlive a management link. */
  healthAgeSeconds: number | null;
  /** Sample rates are Mbps; missing observations must not become zero traffic or load. */
  metrics: {
    connections: number;
    uploadMbps: number;
    downloadMbps: number;
    cpuPercent: number;
    memoryPercent: number;
  } | null;
  /** Unknown addresses are neither healthy nor unhealthy; the three counts sum to total. */
  ipv4: {
    healthy: number;
    unhealthy: number;
    unknown: number;
    total: number;
  } | null;
  /** Finite prefix/active-address observations, not an enumeration of every IPv6 address. */
  ipv6: {
    prefixCount: number;
    activeAddresses: number;
    status: "healthy" | "stale";
  } | null;
  /** Desired configuration is not treated as applied until the node acknowledges it. */
  appliedRevision: number | null;
  desiredRevision: number | null;
  /** Documentation-range sample addresses only; this module never contacts them. */
  ipv4Address: string | null;
  ipv6Prefix: string | null;
}

/** Both languages are searchable regardless of the currently selected UI locale. */
export const regionSearchTerms: Readonly<Record<RegionKey, readonly string[]>> =
  {
    hongKong: ["中国香港", "香港", "Hong Kong", "HongKong"],
    tokyo: ["日本", "东京", "東京", "Japan", "Tokyo"],
    singapore: ["新加坡", "Singapore"],
    losAngeles: ["美国", "洛杉矶", "United States", "USA", "Los Angeles"],
    frankfurt: ["德国", "法兰克福", "Germany", "Frankfurt"],
    osaka: ["日本", "大阪", "Japan", "Osaka"],
  };

/** UI attention combines independent signals; it is not a global IP-health verdict. */
export function needsAttention(node: ManagedNode): boolean {
  return (
    node.control !== "connected" ||
    node.proxy !== "running" ||
    node.metrics === null ||
    node.ipv4 === null ||
    node.ipv4.unhealthy > 0 ||
    node.ipv4.unknown > 0 ||
    node.ipv6 === null ||
    node.ipv6.status === "stale" ||
    node.appliedRevision !== node.desiredRevision
  );
}

/** Filter nodes without changing their order or depending on the active locale. */
export function filterNodes(
  nodes: readonly ManagedNode[],
  query: string,
  filter: "all" | "attention" | "disconnected",
): ManagedNode[] {
  const normalizedQuery = query.trim().normalize("NFKC").toLocaleLowerCase();

  const namesById = new Map(nodes.map((node) => [node.id, node.name]));
  return nodes.filter((node) => {
    if (filter === "attention" && !needsAttention(node)) return false;
    if (filter === "disconnected" && node.control !== "disconnected")
      return false;

    const terms = [
      node.id,
      node.name,
      (node.parentId && namesById.get(node.parentId)) || "",
      node.parentId ?? "",
      node.zone ?? "",
      node.customRegion ?? "",
      ...(node.region === null ? [] : regionSearchTerms[node.region]),
    ];
    return terms.some((term) =>
      term.normalize("NFKC").toLocaleLowerCase().includes(normalizedQuery),
    );
  });
}

/** No measured nodes means no total; measured zero is deliberately preserved. */
export function observedConnections(
  nodes: readonly ManagedNode[],
): number | null {
  let total: number | null = null;
  for (const node of nodes) {
    if (node.metrics) total = (total ?? 0) + node.metrics.connections;
  }
  return total;
}
