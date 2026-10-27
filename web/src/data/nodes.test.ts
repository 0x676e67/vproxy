import { describe, expect, it } from "vitest";
import { filterNodes, needsAttention } from "./nodes";
import { createPendingNode, createSampleNodes } from "./samples";

describe("local node presentation model", () => {
  it("matches both region languages independently of the active UI locale", () => {
    const nodes = createSampleNodes();
    const idsFor = (query: string) =>
      filterNodes(nodes, query, "all").map((node) => node.id);

    expect(idsFor("Tokyo")).toEqual(["jp-edge-01"]);
    expect(idsFor("东京")).toEqual(idsFor("Tokyo"));
    expect(idsFor("  ＴＯＫＹＯ  ")).toEqual(idsFor("Tokyo"));
    expect(idsFor("Japan")).toEqual(["jp-edge-01", "jp-edge-02"]);
    expect(idsFor("日本")).toEqual(idsFor("Japan"));
    expect(idsFor("洛杉矶")).toEqual(idsFor("Los Angeles"));
  });

  it("searches node identity, parent identity, and custom region labels", () => {
    const pending = createPendingNode({
      name: "test-edge",
      region: "Test Region",
      parentId: "hk-control-01",
    });
    const nodes = [...createSampleNodes(), pending];

    expect(filterNodes(nodes, "TEST-EDGE", "all")).toEqual([pending]);
    expect(filterNodes(nodes, "test region", "all")).toEqual([pending]);
    expect(
      filterNodes(nodes, "hk-control-01", "all").map((node) => node.id),
    ).toEqual([
      "hk-control-01",
      "jp-edge-01",
      "sg-edge-01",
      "us-edge-01",
      "de-edge-01",
      "test-edge",
    ]);
  });

  it("keeps pending enrollment distinct from a disconnected management link", () => {
    const pending = createPendingNode({
      name: "new-edge",
      region: "",
      parentId: null,
    });
    const nodes = [...createSampleNodes(), pending];

    expect(
      filterNodes(nodes, "", "disconnected").map((node) => node.id),
    ).toEqual(["us-edge-01"]);
    expect(filterNodes(nodes, "", "attention")).toContain(pending);
  });

  it("reports health uncertainty and unapplied configuration without blaming healthy nodes", () => {
    const nodes = createSampleNodes();

    expect(nodes.filter(needsAttention).map((node) => node.id)).toEqual([
      "sg-edge-01",
      "us-edge-01",
      "jp-edge-02",
    ]);
    const singapore = nodes.find((node) => node.id === "sg-edge-01");
    const osaka = nodes.find((node) => node.id === "jp-edge-02");
    expect(singapore?.ipv4).toEqual({
      healthy: 26,
      unhealthy: 6,
      unknown: 0,
      total: 32,
    });
    expect(singapore?.appliedRevision).toBe(47);
    expect(singapore?.desiredRevision).toBe(48);
    expect(osaka?.ipv4).toEqual({
      healthy: 6,
      unhealthy: 0,
      unknown: 2,
      total: 8,
    });
  });

  it("does not turn a lost management link into measured zeroes or a stopped proxy", () => {
    const disconnected = createSampleNodes().find(
      (node) => node.control === "disconnected",
    );

    expect(disconnected).toMatchObject({
      proxy: "unknown",
      metrics: null,
      ipv4: null,
      ipv6: null,
      observationAgeSeconds: 720,
      healthAgeSeconds: 720,
      appliedRevision: 46,
      desiredRevision: 48,
    });
  });

  it("creates pending samples without fabricated health, rates, revisions, or addresses", () => {
    expect(
      createPendingNode({
        name: "  new-edge  ",
        region: "  Custom Region  ",
        parentId: null,
      }),
    ).toEqual({
      id: "new-edge",
      name: "new-edge",
      relationshipsKnown: true,
      region: null,
      customRegion: "Custom Region",
      zone: null,
      parentId: null,
      childCount: 0,
      local: false,
      control: "pending",
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
    });
  });
});
