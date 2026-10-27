import { describe, expect, it, vi } from "vitest";
import {
  alertPage,
  alertCodes,
  alertQuery,
  egressAlertPage,
  egressAlertQuery,
} from "./alerts";
import {
  ALERT_BOOT,
  ALERT_PEER,
  alertFixture,
  alertPageFixture,
  egressAlertPageFixture,
} from "./alerts.fixtures";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import { endpointStatus } from "./proxy";

describe("bounded process-local alert reads", () => {
  it("reads local management HTTPS incidents without resource or target selectors", () => {
    const incident = alertFixture({
      kind: "management_https",
      resource_id: null,
      check: null,
      target: null,
      code: "https_identity_unavailable",
    });
    for (const code of [
      "https_identity_unavailable",
      "https_identity_expiring",
      "https_identity_expired",
      "https_identity_not_yet_valid",
      "https_identity_metadata_unavailable",
      "acme_attempt_unavailable",
      "acme_review_required",
      "acme_worker_stopped",
    ]) {
      const page = alertPageFixture({ items: [{ ...incident, code }] });
      expect(alertPage(page).items).toEqual(page.items);
    }
    for (const invalid of [
      { resource_id: alertFixture().resource_id },
      { check: "bind" },
      { target: "127.0.0.1:443" },
    ])
      expect(() =>
        alertPage({
          ...alertPageFixture(),
          items: [{ ...incident, ...invalid }],
        }),
      ).toThrow(ApiError);
  });

  it("defaults only omitted optional legacy coverage and rejects supplied invalid flags", () => {
    const page = alertPageFixture();
    const legacyCoverage: Record<string, unknown> = { ...page.coverage };
    const sources = [
      "local_management_https",
      "local_node_tls",
      "local_proxy_tls",
      "remote_observation",
    ] as const;
    for (const source of sources) delete legacyCoverage[source];
    expect(alertPage({ ...page, coverage: legacyCoverage }).coverage).toEqual(
      page.coverage,
    );
    for (const source of sources) {
      expect(legacyCoverage).not.toHaveProperty(source);
      for (const included of [false, true])
        expect(
          alertPage({
            ...page,
            coverage: { ...page.coverage, [source]: included },
          }).coverage[source],
        ).toBe(included);
      for (const invalid of [null, undefined, 0, "true", {}, []])
        expect(() =>
          alertPage({
            ...page,
            coverage: { ...page.coverage, [source]: invalid },
          }),
        ).toThrow(ApiError);
    }
    const missing = { ...legacyCoverage };
    delete missing.local_traffic;
    for (const coverage of [
      missing,
      { ...page.coverage, unreviewed_source: false },
      null,
      [],
    ])
      expect(() => alertPage({ ...page, coverage })).toThrow(ApiError);
  });

  it("retains background collection failures as source-node observations without resource or probe selectors", () => {
    const codes = alertCodes.filter((code) =>
      code.startsWith("remote_observation_"),
    );
    expect(codes).toHaveLength(8);
    for (const code of codes) {
      const item = alertFixture({
        kind: "remote_observation",
        origin_node_id: ALERT_PEER,
        resource_id: null,
        check: null,
        target: null,
        code,
        evidence_fresh: false,
      });
      const page = alertPageFixture({
        active_count: 12288,
        coverage: { ...alertPageFixture().coverage, remote_observation: true },
        items: [item],
      });
      expect(alertPage(page)).toEqual(page);
      for (const invalid of [
        { resource_id: ALERT_PEER },
        { check: "bind" },
        { target: "127.0.0.1:443" },
      ])
        expect(() =>
          alertPage({ ...page, items: [{ ...item, ...invalid }] }),
        ).toThrow(ApiError);
    }
  });

  it("binds local node and proxy TLS incidents to their distinct resource identities", () => {
    for (const kind of ["node_tls", "proxy_tls"] as const) {
      const resource_id =
        kind === "node_tls" ? null : alertFixture().resource_id;
      const incident = alertFixture({
        kind,
        resource_id,
        check: null,
        target: null,
      });
      for (const suffix of [
        "unavailable",
        "expiring",
        "expired",
        "not_yet_valid",
        "metadata_unavailable",
      ]) {
        const item = { ...incident, code: `${kind}_identity_${suffix}` };
        expect(alertPage(alertPageFixture({ items: [item] })).items).toEqual([
          item,
        ]);
        expect(() =>
          egressAlertPage(
            egressAlertPageFixture({
              items: [{ ...item, origin_node_id: ALERT_PEER }],
            }),
            ALERT_PEER,
          ),
        ).toThrow(ApiError);
      }
      const invalidResources =
        kind === "node_tls"
          ? [alertFixture().resource_id]
          : [null, "not-an-endpoint", "AAAAAAAAAAAAAAAAAAAAAB"];
      for (const resource_id of invalidResources)
        expect(() =>
          alertPage(
            alertPageFixture({ items: [{ ...incident, resource_id }] }),
          ),
        ).toThrow(ApiError);
      for (const invalid of [
        { check: "tcp" },
        { target: "127.0.0.1:443" },
      ] as const)
        expect(() =>
          alertPage(alertPageFixture({ items: [{ ...incident, ...invalid }] })),
        ).toThrow(ApiError);
    }
  });

  it("preserves u64 evidence and distinguishes recovery from stopped monitoring", () => {
    const maximum = "18446744073709551615";
    const page = alertPageFixture({
      active_count: 0,
      recent_count: 2,
      dropped: maximum,
      items: [
        alertFixture({
          id: maximum,
          status: "recovered",
          ended_at_unix_ms: maximum,
          age_millis: maximum,
        }),
        alertFixture({
          id: "2",
          status: "unmonitored",
          ended_at_unix_ms: null,
          evidence_fresh: false,
        }),
      ],
    });
    expect(alertPage(page, { state: "recent" })).toEqual(page);
    expect(
      alertPage(
        alertPageFixture({ observed_at_unix_ms: null, age_millis: "0" }),
      ),
    ).toMatchObject({ age_millis: "0" });
    const unknown = alertPageFixture({
      items: [
        alertFixture({ code: "future_fixed_code", evidence_fresh: false }),
      ],
    });
    expect(alertPage(unknown).items[0].code).toBe("future_fixed_code");
    expect(
      alertPage(
        alertPageFixture({
          active_count: 6144,
          recent_count: 256,
          items: [alertFixture({ check: "bind", target: null })],
        }),
      ),
    ).toMatchObject({ active_count: 6144, recent_count: 256 });
  });

  it("rejects impossible shapes, unsafe counts, duplicate episodes and mismatched lists", () => {
    const invalid = [
      { revision: "0" },
      { revision: "18446744073709551616" },
      { active_count: -1 },
      { recent_count: 4294967296 },
      { active_count: 12289 },
      { recent_count: 257 },
      { age_millis: null },
      { observed_at_unix_ms: 1780000001000 },
      { coverage: { ...alertPageFixture().coverage, remote_cached: "true" } },
      { coverage: { ...alertPageFixture().coverage, remote_egress: true } },
      { items: [alertFixture({ id: "01" })] },
      { items: [alertFixture({ evidence_fresh: undefined } as never)] },
      { items: [alertFixture({ age_millis: "-1" })] },
      {
        items: [alertFixture({ status: "recovered", ended_at_unix_ms: "10" })],
      },
      { items: [alertFixture({ target: "https://outside.invalid" })] },
      { items: [alertFixture({ resource_id: null })] },
      { items: [alertFixture({ check: null })] },
      { items: [alertFixture({ check: "bind" })] },
      { items: [alertFixture({ target: null })] },
      { items: [alertFixture({ target: "127.0.0.1:0" })] },
      {
        items: [alertFixture({ kind: "policy", check: "bind", target: null })],
      },
      { items: [alertFixture({ kind: "policy", check: null })] },
      { items: [alertFixture({ code: "unsafe\nmessage" })] },
      { items: [alertFixture(), alertFixture()], active_count: 2 },
      { next_cursor: "opaque" },
      { extra: true },
    ];
    for (const change of invalid)
      expect(() => alertPage({ ...alertPageFixture(), ...change })).toThrow(
        ApiError,
      );
    expect(() => alertPage(alertPageFixture(), { state: "recent" })).toThrow(
      ApiError,
    );
    expect(() =>
      alertPage(
        alertPageFixture({
          active_count: 0,
          recent_count: 1,
          items: [
            alertFixture({
              status: "unmonitored",
              ended_at_unix_ms: "10",
              evidence_fresh: true,
            }),
          ],
        }),
        { state: "recent" },
      ),
    ).toThrow(ApiError);
  });

  it("accepts only fixed GET queries with bounded opaque cursors", () => {
    expect(alertQuery({})).toBe("");
    expect(
      alertQuery({
        state: "recent",
        after: "boot.revision.recent.16",
        limit: 16,
      }),
    ).toBe("?state=recent&after=boot.revision.recent.16&limit=16");
    for (const path of [
      "/alerts",
      "/alerts?state=active&limit=1",
      "/alerts?state=recent&after=opaque&limit=16",
    ])
      expect(endpointStatus(path, "GET")).toBe(200);
    for (const query of [
      "state=history",
      "state=",
      "state=active&state=recent",
      "limit=0",
      "limit=17",
      "limit=01",
      "after=",
      "after=%0a",
      `after=${"x".repeat(161)}`,
      "target=remote",
      "limit=1?state=active",
    ])
      expect(() => endpointStatus(`/alerts?${query}`, "GET")).toThrow(ApiError);
    expect(() => endpointStatus("/alerts", "POST")).toThrow(ApiError);
    expect(() => alertQuery({ state: "recent", after: "\n" })).toThrow(
      ApiError,
    );
    expect(() => alertQuery({ limit: 17 })).toThrow(ApiError);
    expect(() => alertQuery({ target: "remote" } as never)).toThrow(ApiError);
  });

  it("keeps reads local, bounded and cancellable without a mutation or CSRF secret", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(alertPageFixture()));
    const client = new ManagementClient(fetcher, () => true);
    const pending = new AbortController();
    expect(
      await client.alerts({ state: "active", limit: 10 }, pending.signal),
    ).toEqual(alertPageFixture());
    expect(fetcher).toHaveBeenCalledWith(
      "/api/v1/alerts?state=active&limit=10",
      expect.objectContaining({
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
      }),
    );
    const init = fetcher.mock.calls[0][1];
    expect(init?.body).toBeUndefined();
    expect(init?.headers).not.toHaveProperty("X-CSRF-Token");
    fetcher.mockImplementation(() => new Promise(() => {}));
    const read = client.alerts({}, pending.signal);
    pending.abort();
    await expect(read).rejects.toMatchObject({ name: "AbortError" });
    expect(fetcher.mock.calls[1][1]?.signal?.aborted).toBe(true);
  });
});

describe("selected node egress alert reads", () => {
  it("binds counts, exact page lengths and egress cursors to one snapshot", () => {
    const cursor = `${ALERT_BOOT}:1:egress-active:1`;
    const first = egressAlertPageFixture({
      active_count: 2,
      next_cursor: cursor,
    });
    expect(egressAlertPage(first, ALERT_PEER, { limit: 1 })).toEqual(first);
    const next = egressAlertPageFixture({
      active_count: 2,
      items: [alertFixture({ id: "2", origin_node_id: ALERT_PEER })],
    });
    expect(
      egressAlertPage(next, ALERT_PEER, { after: cursor, limit: 1 }),
    ).toEqual(next);
    const recent = egressAlertPageFixture({
      active_count: 0,
      recent_count: 1,
      items: [
        alertFixture({
          origin_node_id: ALERT_PEER,
          kind: "health_catalog",
          resource_id: null,
          check: null,
          target: null,
          status: "unmonitored",
          code: "health_catalog_stale",
          ended_at_unix_ms: null,
          evidence_fresh: false,
        }),
      ],
    });
    expect(egressAlertPage(recent, ALERT_PEER, { state: "recent" })).toEqual(
      recent,
    );
    const unmonitored = egressAlertPageFixture({
      monitored: false,
      observed_at_unix_ms: null,
      age_millis: null,
      active_count: 0,
      items: [],
    });
    expect(egressAlertPage(unmonitored, ALERT_PEER)).toEqual(unmonitored);
    for (const change of [
      { active_count: 1 },
      { recent_count: 1 },
      { age_millis: "0" },
      { dropped: "1" },
    ])
      expect(() =>
        egressAlertPage({ ...unmonitored, ...change }, ALERT_PEER),
      ).toThrow(ApiError);
  });

  it("rejects another origin, unrelated kinds or reasons, invalid evidence and cross-source cursors", () => {
    const page = egressAlertPageFixture();
    const incident = page.items[0];
    for (const change of [
      { node_id: ALERT_BOOT },
      { boot_id: "not-a-boot" },
      { revision: "01" },
      { observed_at_unix_ms: 1 },
      { age_millis: null },
      { collection_error: undefined },
      { monitored: null },
      { active_count: 6145 },
      { recent_count: 257 },
      { active_count: 2 },
      { dropped: "18446744073709551616" },
      { items: [{ ...incident, origin_node_id: ALERT_BOOT }] },
      { items: [{ ...incident, kind: "policy", check: null, target: null }] },
      { items: [{ ...incident, code: "future_egress_reason" }] },
      { items: [{ ...incident, check: "bind" }] },
      { items: [{ ...incident, target: "https://outside.invalid" }] },
      {
        items: [
          {
            ...incident,
            kind: "health_catalog",
            check: null,
            target: null,
            code: "health_catalog_stale",
          },
        ],
      },
      { items: [incident, incident], active_count: 2 },
      { next_cursor: `${ALERT_BOOT}:1:active:1` },
      { next_cursor: `${ALERT_BOOT}:2:egress-active:1` },
      { extra: false },
    ])
      expect(() => egressAlertPage({ ...page, ...change }, ALERT_PEER)).toThrow(
        ApiError,
      );
    for (const after of [
      "opaque",
      `${ALERT_BOOT}:1:active:1`,
      `${ALERT_BOOT}:1:egress-recent:1`,
      `${ALERT_BOOT}:01:egress-active:1`,
      `${ALERT_BOOT}:1:egress-active:01`,
      `${ALERT_BOOT}:1:egress-active:6145`,
    ])
      expect(() => egressAlertQuery({ after })).toThrow(ApiError);
    expect(() =>
      egressAlertPage(page, ALERT_PEER, {
        after: `${ALERT_BOOT}:2:egress-active:0`,
      }),
    ).toThrow(ApiError);
    expect(() =>
      egressAlertPage(
        egressAlertPageFixture({
          active_count: 0,
          recent_count: 1,
          items: [{ ...incident, status: "recovered", evidence_fresh: false }],
        }),
        ALERT_PEER,
        { state: "recent" },
      ),
    ).toThrow(ApiError);
  });

  it("uses one fixed cancellable GET without a mutation secret or local fallback", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(egressAlertPageFixture()));
    const client = new ManagementClient(fetcher, () => true);
    const pending = new AbortController();
    expect(
      await client.targetEgressAlerts(
        ALERT_PEER,
        { state: "active", limit: 16 },
        pending.signal,
      ),
    ).toEqual(egressAlertPageFixture());
    expect(fetcher).toHaveBeenCalledWith(
      `/api/v1/targets/${ALERT_PEER}/egress-alerts?state=active&limit=16`,
      expect.objectContaining({
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
      }),
    );
    expect(fetcher.mock.calls[0][1]?.body).toBeUndefined();
    expect(fetcher.mock.calls[0][1]?.headers).not.toHaveProperty(
      "X-CSRF-Token",
    );
    for (const query of ["state=all", "limit=17", "target=other", "limit=01"])
      expect(() =>
        endpointStatus(`/targets/${ALERT_PEER}/egress-alerts?${query}`, "GET"),
      ).toThrow(ApiError);
    expect(() =>
      endpointStatus(`/targets/${ALERT_PEER}/egress-alerts`, "POST"),
    ).toThrow(ApiError);
    await expect(
      client.targetEgressAlerts("invalid", {}, pending.signal),
    ).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).toHaveBeenCalledTimes(1);
    fetcher.mockImplementation(() => new Promise(() => {}));
    const late = client.targetEgressAlerts(ALERT_PEER, {}, pending.signal);
    pending.abort();
    await expect(late).rejects.toMatchObject({ name: "AbortError" });
    expect(fetcher.mock.calls[1][1]?.signal?.aborted).toBe(true);
  });
});
