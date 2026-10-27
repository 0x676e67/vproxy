import { afterEach, describe, expect, it, vi } from "vitest";
import { ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import { endpointStatus } from "./proxy";
import { webhookChange, webhookRetry, webhookView } from "./notifications";
import {
  WEBHOOK_NODE,
  WEBHOOK_OPERATION,
  deliveryFixture,
  webhookChangeFixture,
  webhookFixture,
} from "./notifications.fixtures";

afterEach(() => vi.unstubAllGlobals());
describe("node-local webhook contract", () => {
  it("admits only the three explicit local bindings", () => {
    expect(endpointStatus("/notifications/webhook", "GET")).toBe(200);
    expect(endpointStatus("/notifications/webhook", "POST")).toBe(200);
    expect(endpointStatus("/notifications/webhook/retry", "POST")).toBe(200);
    for (const [path, method] of [
      ["/notifications/webhook", "PUT"],
      ["/notifications/webhook/retry", "GET"],
      [`/targets/${WEBHOOK_NODE}/notifications/webhook`, "GET"],
      ["/notifications/webhook?", "GET"],
    ] as const)
      expect(() => endpointStatus(path, method)).toThrow();
  });
  it("accepts only the exact non-secret projection and the requested node", () => {
    const value = webhookFixture();
    expect(webhookView(value, WEBHOOK_NODE)).toEqual(value);
    for (const extra of [
      { url: "secret" },
      { bearer: "secret" },
      { digest: "secret" },
    ])
      expect(() => webhookView({ ...value, ...extra }, WEBHOOK_NODE)).toThrow();
    expect(() => webhookView(value, "A".repeat(22))).toThrow();
    expect(() => webhookView({ ...value, cursor: 1 }, WEBHOOK_NODE)).toThrow();
    expect(() =>
      webhookView({ ...value, revision: "00" }, WEBHOOK_NODE),
    ).toThrow();
  });
  it("rejects contradictory delivery facts, unsafe counters and invalid retry eligibility", () => {
    const value = {
      ...webhookFixture(),
      enabled: true,
      configured: true,
      revision: "1",
      operation_id: WEBHOOK_OPERATION,
      pending: deliveryFixture(),
    };
    expect(webhookView(value, WEBHOOK_NODE)).toEqual(value);
    for (const patch of [
      { after_sequence: "1" },
      { through_sequence: "0" },
      { http_status: 204 },
      { outcome: "accepted" },
      { attempts: 2 ** 32 },
      { event_count: 17 },
      { automatic_retry_eligible: true },
    ])
      expect(() =>
        webhookView(
          { ...value, pending: { ...value.pending, ...patch } },
          WEBHOOK_NODE,
        ),
      ).toThrow();
    expect(
      webhookView(
        {
          ...value,
          automatic_retry: true,
          pending: {
            ...value.pending,
            outcome: "rejected",
            http_status: 503,
            automatic_retry_eligible: true,
          },
        },
        WEBHOOK_NODE,
      ).pending?.automatic_retry_eligible,
    ).toBe(true);
  });
  it("bounds secret input without persisting it and requires an explicit clear", () => {
    expect(webhookChange(webhookChangeFixture())).toEqual(
      webhookChangeFixture(),
    );
    for (const url of [
      "http://hooks.example",
      "https://user:secret@hooks.example",
      "https://@hooks.example",
      "https://hooks.example/#",
      "https://hooks.example:0",
      "https://hooks.example/" + "x".repeat(2048),
    ])
      expect(() => webhookChange({ ...webhookChangeFixture(), url })).toThrow();
    for (const bearer of [
      "bad\r\nheader",
      "=broken",
      "mid=dle",
      "",
      "x".repeat(1025),
    ])
      expect(() =>
        webhookChange({ ...webhookChangeFixture(), bearer }),
      ).toThrow();
    expect(() =>
      webhookChange({ ...webhookChangeFixture(), clear_bearer: true }),
    ).toThrow();
    expect(() =>
      webhookChange({ ...webhookChangeFixture(), clear_destination: true }),
    ).toThrow();
    expect(
      webhookChange({
        ...webhookChangeFixture(),
        enabled: false,
        url: null,
        bearer: null,
        clear_destination: true,
      }).clear_destination,
    ).toBe(true);
    expect(() =>
      webhookRetry({
        expected_node_id: WEBHOOK_NODE,
        expected_revision: "1",
        delivery_id: deliveryFixture().id,
        expected_attempts: 2 ** 32 - 1,
      }),
    ).toThrow();
  });
  it("uses one Session/CSRF POST, exact receipt assertions and never a target route", async () => {
    const input = webhookChangeFixture();
    const fetch = vi.fn(async () =>
      jsonResponse({
        ...webhookFixture(),
        revision: "1",
        operation_id: input.operation_id,
        enabled: true,
        configured: true,
        has_bearer: true,
      }),
    );
    vi.stubGlobal("fetch", fetch);
    const client = new ManagementClient(fetch, () => true);
    await client.configureWebhook(
      input,
      "csrf-test",
      new AbortController().signal,
    );
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, options] = fetch.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe("/api/v1/notifications/webhook");
    expect(options.credentials).toBe("same-origin");
    expect(options.headers).toMatchObject({ "X-CSRF-Token": "csrf-test" });
    expect(JSON.parse(String(options.body))).toEqual(input);
    fetch.mockResolvedValueOnce(
      jsonResponse({
        ...webhookFixture(),
        revision: "2",
        operation_id: input.operation_id,
        enabled: true,
        configured: true,
      }),
    );
    await expect(
      client.configureWebhook(input, "csrf-test", new AbortController().signal),
    ).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
