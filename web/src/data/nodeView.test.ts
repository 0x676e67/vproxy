import { describe, expect, it } from "vitest";
import { managedNode } from "./nodeView";
import { filterNodes, observedConnections } from "./nodes";
import { createSampleNodes } from "./samples";

describe("real node facts", () => {
  const fact = {
    node_id: "A".repeat(22),
    name: "Renamable identity",
    version: "2.5.5",
    os: "linux",
    arch: "aarch64",
    capabilities: ["local_administration"],
  };
  it("keeps unsupported proxy, health, metrics, config and relationships unknown", () => {
    const node = managedNode(fact);
    expect(node).toMatchObject({
      id: fact.node_id,
      name: fact.name,
      proxy: "unknown",
      metrics: null,
      ipv4: null,
      ipv6: null,
      appliedRevision: null,
      desiredRevision: null,
      relationshipsKnown: false,
      childCount: null,
    });
    expect(observedConnections([node])).toBeNull();
    expect(observedConnections([])).toBeNull();
    const sample = createSampleNodes()[0]!;
    expect(
      observedConnections([
        { ...sample, metrics: { ...sample.metrics!, connections: 0 } },
        node,
      ]),
    ).toBe(0);
  });

  it("keeps identity stable across a rename and searches parent names without replacing IDs", () => {
    const parent = managedNode(fact);
    const renamed = managedNode({ ...fact, name: "New display name" });
    const child = {
      ...parent,
      id: "B".repeat(22),
      name: "Child",
      parentId: parent.id,
    };
    expect(renamed.id).toBe(parent.id);
    expect(filterNodes([renamed, child], "new display", "all")).toEqual([
      renamed,
      child,
    ]);
    expect(child.parentId).toBe(parent.id);
  });
});
