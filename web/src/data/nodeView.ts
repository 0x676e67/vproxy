import type { NodeView } from "../api/client";
import type { ManagedNode } from "./nodes";

/** The identity endpoint proves identity, not proxy state, health or enrollment. */
export function managedNode(fact: NodeView): ManagedNode {
  return {
    id: fact.node_id,
    name: fact.name,
    version: fact.version,
    os: fact.os,
    arch: fact.arch,
    relationshipsKnown: false,
    region: null,
    zone: null,
    parentId: null,
    childCount: null,
    local: true,
    control: "connected",
    proxy: "unknown",
    observationAgeSeconds: null,
    healthAgeSeconds: null,
    metrics: null,
    ipv4: null,
    ipv6: null,
    appliedRevision: null,
    desiredRevision: null,
    ipv4Address: null,
    ipv6Prefix: null,
  };
}
