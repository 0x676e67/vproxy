import { describe, expect, it } from "vitest";
import {
  webhookCodec,
  webhookResult,
  type WebhookNote,
} from "./webhook-review";
import {
  WEBHOOK_NODE,
  WEBHOOK_OPERATION,
  deliveryFixture,
  webhookFixture,
} from "../api/notifications.fixtures";
const note = (): WebhookNote => ({
  administratorId: "A".repeat(22),
  nodeId: WEBHOOK_NODE,
  operationId: WEBHOOK_OPERATION,
  revision: "0",
  action: "configure",
  deliveryId: null,
  attempts: null,
});
describe("non-secret webhook review assertions", () => {
  it("rejects secrets, malformed IDs and foreign retry assertions", () => {
    expect(webhookCodec.decode(note())).toEqual(note());
    expect(webhookCodec.decode({ ...note(), url: "secret" })).toBeNull();
    expect(webhookCodec.decode({ ...note(), bearer: "secret" })).toBeNull();
    expect(webhookCodec.decode({ ...note(), operationId: "bad" })).toBeNull();
    expect(webhookCodec.decode({ ...note(), action: "retry" })).toBeNull();
  });
  it("distinguishes exact configuration receipt, retry admission and unknown replacement", () => {
    const value = {
      ...webhookFixture(),
      revision: "1",
      operation_id: WEBHOOK_OPERATION,
    };
    expect(webhookResult(note(), value)).toBe("saved");
    expect(webhookResult(note(), { ...value, revision: "2" })).toBe("unknown");
    expect(webhookResult(note(), { ...value, node_id: "A".repeat(22) })).toBe(
      "unknown",
    );
    const retry = {
      ...note(),
      revision: "1",
      action: "retry" as const,
      deliveryId: deliveryFixture().id,
      attempts: 1,
    };
    expect(webhookResult(retry, { ...value, pending: deliveryFixture() })).toBe(
      "unknown",
    );
    expect(
      webhookResult(retry, {
        ...value,
        pending: { ...deliveryFixture(), outcome: "ready" },
      }),
    ).toBe("admitted");
    expect(
      webhookResult(retry, {
        ...value,
        pending: { ...deliveryFixture(), attempts: 2 },
      }),
    ).toBe("admitted");
    expect(
      webhookResult(retry, {
        ...value,
        last_accepted_delivery_id: retry.deliveryId,
      }),
    ).toBe("admitted");
    expect(
      webhookResult(retry, {
        ...value,
        discarded_delivery_id: retry.deliveryId,
      }),
    ).toBe("unknown");
  });
});
