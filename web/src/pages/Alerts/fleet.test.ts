import { describe, expect, it, vi } from "vitest";
import type { ManagementClient } from "../../api/client";
import {
  ALERT_PEER,
  ALERT_NODE,
  nodeAlertPageFixture,
} from "../../api/alerts.fixtures";
import type { Target } from "../../api/targets";
import { freshRow, readRegistry, waitingRows } from "./fleet";
const target: Target = {
  node_id: ALERT_PEER,
  name: "Child",
  origin: "https://child.example",
  server_ip: null,
  active: true,
  retired: false,
  revision: "1",
  observed_epoch: null,
  observed_command: null,
  observed_policy_revision: null,
  rollback_detected: false,
};
describe("fleet registry bounds and observation age", () => {
  it("refuses duplicate or non-progressing registry pages without continuing", async () => {
    const targets = vi.fn<ManagementClient["targets"]>(async () => ({
      items: [target],
      next_cursor: target.node_id,
      controller_available: true,
    }));
    await expect(
      readRegistry(
        { targets } as unknown as ManagementClient,
        new AbortController().signal,
        () => true,
      ),
    ).rejects.toMatchObject({ code: "fleet_registry_changed" });
    expect(targets).toHaveBeenCalledTimes(1);
    targets.mockResolvedValue({
      items: [],
      next_cursor: null,
      controller_available: true,
    });
    expect(
      (
        await readRegistry(
          { targets } as unknown as ManagementClient,
          new AbortController().signal,
          () => true,
        )
      ).targets,
    ).toEqual([]);
  });
  it("stops at 128 registered targets within six pages and refuses a larger inventory", async () => {
    const inventory = Array.from({ length: 129 }, (_, index) => ({
      ...target,
      node_id: Buffer.from(
        Uint8Array.from({ length: 16 }, (_, slot) => (slot === 15 ? index : 0)),
      ).toString("base64url"),
    })).sort((left, right) => (left.node_id < right.node_id ? -1 : 1));
    const targets = vi.fn<ManagementClient["targets"]>(async (options) => {
      const start =
        options.after === undefined
          ? 0
          : inventory.findIndex((row) => row.node_id === options.after) + 1;
      const items = inventory.slice(start, start + 25);
      return {
        items,
        next_cursor:
          start + items.length < inventory.length
            ? items.at(-1)!.node_id
            : null,
        controller_available: true,
      };
    });
    await expect(
      readRegistry(
        { targets } as unknown as ManagementClient,
        new AbortController().signal,
        () => true,
      ),
    ).rejects.toMatchObject({ code: "fleet_registry_changed" });
    expect(targets).toHaveBeenCalledTimes(6);
  });
  it("does not treat paused, retired, rollback or unavailable targets as zero incident snapshots", () => {
    const rows = waitingRows(
      {
        targets: [
          { ...target, active: false },
          { ...target, retired: true, active: false },
          { ...target, rollback_detected: true },
          target,
        ],
        available: false,
        fingerprint: "fixed",
      },
      ALERT_NODE,
    );
    expect(rows.map((row) => row.outcome)).toEqual([
      "waiting",
      "paused",
      "retired",
      "rollback",
      "unavailable",
    ]);
    expect(rows.every((row) => row.page === null && !freshRow(row))).toBe(true);
  });
  it("adds elapsed monotonic age and preserves incomplete or missing observations as unknown", () => {
    const row = {
      target,
      nodeId: ALERT_PEER,
      page: nodeAlertPageFixture({ age_millis: "1000" }),
      received: 100,
      outcome: "read" as const,
      error: null,
    };
    expect(freshRow(row, 100)).toBe(true);
    expect(freshRow(row, 30_100)).toBe(false);
    for (const page of [
      { ...row.page, age_millis: null },
      { ...row.page, collection_error: true },
    ])
      expect(freshRow({ ...row, page }, 100)).toBe(false);
  });
});
