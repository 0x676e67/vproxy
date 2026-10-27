import { describe, expect, it, vi } from "vitest";
import { nodeAlertPage, nodeAlertQuery } from "./nodeAlerts";
import {
  ALERT_BOOT,
  ALERT_PEER,
  ALERT_NODE,
  alertFixture,
  nodeAlertPageFixture,
} from "./alerts.fixtures";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import { endpointStatus } from "./proxy";

describe("exact node-only operations alert reads", () => {
  it("requires all six local coverage flags and binds every local kind and fixed code to the exact origin", () => {
    const page = nodeAlertPageFixture();
    expect(nodeAlertPage(page, ALERT_PEER)).toEqual(page);
    const values = [
      [
        "egress_check",
        "egress_connection_refused",
        page.items[0].resource_id,
        "tcp",
        page.items[0].target,
      ],
      ["health_catalog", "health_catalog_stale", null, null, null],
      ["policy", "proxy_drain_failed", null, null, null],
      ["traffic_checkpoint", "traffic_checkpoint_failed", null, null, null],
      ["traffic_continuity", "traffic_time_uncertain", null, null, null],
      ["management_https", "acme_review_required", null, null, null],
      ["node_tls", "node_tls_identity_expired", null, null, null],
      [
        "proxy_tls",
        "proxy_tls_identity_unavailable",
        page.items[0].resource_id,
        null,
        null,
      ],
    ] as const;
    for (const [kind, code, resource_id, check, target] of values) {
      const item = { ...page.items[0], kind, code, resource_id, check, target };
      expect(
        nodeAlertPage({ ...page, items: [item] }, ALERT_PEER).items[0],
      ).toEqual(item);
      if (!["egress_check", "proxy_tls"].includes(kind))
        expect(() =>
          nodeAlertPage(
            {
              ...page,
              items: [{ ...item, resource_id: page.items[0].resource_id }],
            },
            ALERT_PEER,
          ),
        ).toThrow(ApiError);
      for (const patch of [
        { code: "unknown_new_code" },
        { origin_node_id: ALERT_NODE },
      ])
        expect(() =>
          nodeAlertPage(
            { ...page, items: [{ ...item, ...patch }] },
            ALERT_PEER,
          ),
        ).toThrow(ApiError);
    }
    for (const patch of [
      { node_id: ALERT_NODE },
      { monitored: true },
      {
        items: [
          {
            ...page.items[0],
            kind: "remote_job",
            code: "remote_job_blocked",
            check: null,
            target: null,
          },
        ],
      },
      { coverage: { ...page.coverage, remote_cached: false } },
      { coverage: { ...page.coverage, remote_observation: false } },
      {
        items: [
          {
            ...page.items[0],
            kind: "remote_observation",
            code: "remote_observation_unavailable",
            resource_id: null,
            check: null,
            target: null,
          },
        ],
      },
      { coverage: { ...page.coverage, local_node_tls: null } },
    ])
      expect(() => nodeAlertPage({ ...page, ...patch }, ALERT_PEER)).toThrow(
        ApiError,
      );
    const coverage = { ...page.coverage } as Record<string, unknown>;
    delete coverage.local_node_tls;
    expect(() => nodeAlertPage({ ...page, coverage }, ALERT_PEER)).toThrow(
      ApiError,
    );
  });
  it("keeps node cursors distinct from local and egress and validates complete filtered counts", () => {
    const cursor = `${ALERT_BOOT}:1:node-active:1`;
    const page = nodeAlertPageFixture({ active_count: 2, next_cursor: cursor });
    expect(nodeAlertPage(page, ALERT_PEER, { limit: 1 }).next_cursor).toBe(
      cursor,
    );
    expect(nodeAlertQuery({ after: cursor, limit: 1 })).toBe(
      `?after=${encodeURIComponent(cursor)}&limit=1`,
    );
    expect(
      nodeAlertPage(
        {
          ...page,
          items: [alertFixture({ id: "2", origin_node_id: ALERT_PEER })],
          next_cursor: null,
        },
        ALERT_PEER,
        { after: cursor, limit: 1 },
      ).items[0].id,
    ).toBe("2");
    for (const after of [
      cursor.replace("node-active", "active"),
      cursor.replace("node-active", "egress-active"),
      cursor.replace("node-active", "node-recent"),
      cursor.replace(":1:node", ":0:node"),
    ])
      expect(() => nodeAlertQuery({ after })).toThrow(ApiError);
    for (const patch of [
      { next_cursor: cursor.replace("node-active", "egress-active") },
      { active_count: 0 },
      { active_count: 6145 },
      { items: [] },
    ])
      expect(() =>
        nodeAlertPage({ ...page, ...patch }, ALERT_PEER, { limit: 1 }),
      ).toThrow(ApiError);
  });
  it("uses only the fixed local or registered-target endpoint and never falls back when unsupported", async () => {
    const fetcher = vi.fn(async () => jsonResponse(nodeAlertPageFixture()));
    const client = new ManagementClient(fetcher, () => true),
      signal = new AbortController().signal;
    await client.targetOperationsAlerts(ALERT_PEER, { limit: 1 }, signal);
    expect(fetcher).toHaveBeenLastCalledWith(
      `/api/v1/targets/${ALERT_PEER}/operations-alerts?limit=1`,
      expect.objectContaining({ method: "GET" }),
    );
    await client.operationsAlerts({ limit: 1 }, signal);
    expect(fetcher).toHaveBeenLastCalledWith(
      "/api/v1/operations-alerts?limit=1",
      expect.objectContaining({ method: "GET" }),
    );
    const unsupported = vi.fn(async () =>
      jsonResponse({ error: { code: "operations_alerts_unsupported" } }, 502),
    );
    await expect(
      new ManagementClient(unsupported, () => true).targetOperationsAlerts(
        ALERT_PEER,
        {},
        signal,
      ),
    ).rejects.toMatchObject({ code: "operations_alerts_unsupported" });
    expect(unsupported).toHaveBeenCalledTimes(1);
    expect(() =>
      endpointStatus(
        `/targets/${ALERT_PEER}/operations-alerts?state=active`,
        "POST",
      ),
    ).toThrow(ApiError);
  });
});
