import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import {
  alertEvent,
  alertEpisode,
  alertEventPage,
  alertEventQuery,
  alertSummary,
  unreadAlertPage,
  alertAcknowledgementBatch,
  alertAcknowledgementResult,
} from "./alertEvents";
import {
  eventFixture,
  episodeFixture,
  eventPageFixture,
  summaryFixture,
  EVENT_NODE,
  EVENT_OTHER,
  EVENT_ACTOR,
} from "./alertEvents.fixtures";
import { endpointStatus } from "./proxy";
describe("durable local events and acknowledgement assertions", () => {
  it("validates inbox watermarks, unread projections and exact batch identities without numeric rounding", () => {
    const value = {
      node_id: EVENT_NODE,
      items: [episodeFixture()],
      next_cursor: null,
      through_sequence: "1",
    };
    expect(unreadAlertPage(value, EVENT_NODE, {}).items).toHaveLength(1);
    expect(endpointStatus("/alert-episodes", "GET")).toBe(200);
    expect(endpointStatus("/alert-episodes?before=2&through=3", "GET")).toBe(
      200,
    );
    expect(endpointStatus("/alert-episodes/acknowledge", "POST")).toBe(200);
    for (const path of [
      "/alert-episodes?through=01",
      "/alert-episodes?through=1&through=2",
      "/alert-episodes?limit=50",
      "/alert-episodes?before=0",
    ]) {
      expect(() => endpointStatus(path, "GET")).toThrow(ApiError);
    }
    expect(() => endpointStatus("/alert-episodes/acknowledge", "GET")).toThrow(
      ApiError,
    );
    for (const patch of [
      { through_sequence: "0" },
      { items: [episodeFixture(true)] },
      { node_id: EVENT_OTHER },
      { next_cursor: "1" },
      { through_sequence: "9223372036854775808" },
    ]) {
      expect(() =>
        unreadAlertPage({ ...value, ...patch }, EVENT_NODE, {}),
      ).toThrow(ApiError);
    }
    expect(() => unreadAlertPage(value, EVENT_NODE, { through: "2" })).toThrow(
      ApiError,
    );
    const input = {
      expected_node_id: EVENT_NODE,
      items: [{ episode_id: "1", expected_transition_sequence: "1" }],
    };
    expect(alertAcknowledgementBatch(input)).toEqual(input);
    expect(() =>
      alertAcknowledgementBatch({
        ...input,
        items: [...input.items, ...input.items],
      }),
    ).toThrow(ApiError);
    expect(() => alertAcknowledgementBatch({ ...input, items: [] })).toThrow(
      ApiError,
    );
    expect(
      alertAcknowledgementResult(
        { node_id: EVENT_NODE, items: [episodeFixture(true)] },
        input,
      ),
    ).toHaveLength(1);
    expect(() =>
      alertAcknowledgementResult(
        { node_id: EVENT_NODE, items: [episodeFixture()] },
        input,
      ),
    ).toThrow(ApiError);
    expect(() =>
      alertAcknowledgementResult(
        { node_id: EVENT_OTHER, items: [episodeFixture(true)] },
        input,
      ),
    ).toThrow(ApiError);
  });
  it("requires exact immutable event fields and distinguishes u64 incident/evidence/time from i64 identities", () => {
    const value = eventFixture();
    expect(
      alertEvent(
        {
          ...value,
          incident_id: "18446744073709551615",
          evidence_sequence: "18446744073709551615",
          recorded_at_unix_ms: null,
        },
        EVENT_NODE,
        "1",
      ).incident_id,
    ).toBe("18446744073709551615");
    for (const patch of [
      { node_id: EVENT_OTHER },
      { sequence: "0" },
      { sequence: "9223372036854775808" },
      { episode_id: "01" },
      { episode_id: "2" },
      { sequence: "2" },
      { origin_node_id: "not-a-node" },
      { transition: "unmonitored" },
      { end_reason: "source_unmonitored" },
      { incident_id: "0" },
      { incident_id: "18446744073709551616" },
      { transition: "failed" },
      { status: "active" },
      { evidence_fresh: true },
      { ended_at_unix_ms: null },
      { recorded_at_unix_ms: "-1" },
      { administrator_id: EVENT_ACTOR },
      { acknowledged_transition_sequence: "1" },
      { password: "not-retained" },
    ])
      expect(() => alertEvent({ ...value, ...patch }, EVENT_NODE)).toThrow(
        ApiError,
      );
    expect(
      alertEvent(
        {
          ...value,
          sequence: "2",
          transition: "acknowledged",
          administrator_id: EVENT_ACTOR,
          acknowledged_transition_sequence: "1",
        },
        EVENT_NODE,
      ).transition,
    ).toBe("acknowledged");
    expect(() => alertEvent(value, EVENT_NODE, "2")).toThrow(ApiError);
    expect(() =>
      alertEvent(
        {
          ...value,
          sequence: "3",
          episode_id: "2",
          transition: "acknowledged",
          administrator_id: EVENT_ACTOR,
          acknowledged_transition_sequence: "1",
        },
        EVENT_NODE,
      ),
    ).toThrow(ApiError);
  });
  it("preserves foreign own-node observations and separates a collection failure from its local observer", () => {
    for (const kind of [
      "policy",
      "traffic_checkpoint",
      "traffic_continuity",
      "health_catalog",
      "management_https",
      "node_tls",
      "proxy_tls",
      "egress_check",
    ] as const) {
      const observation = {
        ...eventFixture(),
        kind,
        origin_node_id: EVENT_OTHER,
        resource_id:
          kind === "proxy_tls" || kind === "egress_check" ? EVENT_ACTOR : null,
        check: kind === "egress_check" ? ("bind" as const) : null,
      };
      expect(alertEvent(observation, EVENT_NODE).origin_node_id).toBe(
        EVENT_OTHER,
      );
      expect(
        alertEpisode(
          {
            ...episodeFixture(),
            kind,
            origin_node_id: EVENT_OTHER,
            resource_id: observation.resource_id,
            check: observation.check,
          },
          EVENT_NODE,
          "1",
        ).origin_node_id,
      ).toBe(EVENT_OTHER);
    }
    const failure = {
      ...eventFixture(),
      kind: "remote_observation",
      origin_node_id: EVENT_OTHER,
      code: "remote_observation_stale",
    };
    expect(alertEvent(failure, EVENT_NODE).kind).toBe("remote_observation");
    for (const patch of [
      { origin_node_id: EVENT_NODE },
      { resource_id: EVENT_ACTOR },
      { check: "bind" },
      { target: "127.0.0.1:443" },
    ])
      expect(() => alertEvent({ ...failure, ...patch }, EVENT_NODE)).toThrow(
        ApiError,
      );
  });
  it("keeps old acknowledgement history without falsely marking a later state acknowledged", () => {
    const value = episodeFixture(true);
    expect(
      alertEpisode({ ...value, acknowledged_at_unix_ms: null }, EVENT_NODE, "1")
        .is_acknowledged,
    ).toBe(true);
    expect(
      alertEpisode(
        {
          ...value,
          latest_transition_sequence: "3",
          is_acknowledged: false,
          status: "unmonitored",
          end_reason: "monitor_restarted",
        },
        EVENT_NODE,
        "1",
      ).acknowledged_transition_sequence,
    ).toBe("1");
    for (const patch of [
      { acknowledged_by: null },
      { acknowledgement_event_sequence: null },
      { acknowledgement_event_sequence: "1" },
      { latest_transition_sequence: "3" },
      { is_acknowledged: false },
      { id: "2" },
      { status: "unmonitored" },
      { status: "recovered", end_reason: "source_unmonitored" },
      { age_millis: "0" },
    ])
      expect(() =>
        alertEpisode({ ...value, ...patch }, EVENT_NODE, "1"),
      ).toThrow(ApiError);
    expect(() =>
      alertEpisode(
        { ...value, id: "2", latest_transition_sequence: "1" },
        EVENT_NODE,
        "2",
      ),
    ).toThrow(ApiError);
    expect(() =>
      alertEpisode(
        {
          ...value,
          id: "2",
          latest_transition_sequence: "3",
          is_acknowledged: false,
        },
        EVENT_NODE,
        "2",
      ),
    ).toThrow(ApiError);
    expect(
      alertSummary(
        {
          ...summaryFixture(),
          retained_episode_count: 16_384,
          retained_event_count: 0,
          oldest_sequence: null,
        },
        EVENT_NODE,
      ).retained_episode_count,
    ).toBe(16_384);
    expect(() =>
      alertSummary(
        { ...summaryFixture(), retained_episode_count: 16_385 },
        EVENT_NODE,
      ),
    ).toThrow(ApiError);
    expect(() =>
      alertSummary(
        { ...summaryFixture(), unacknowledged_count: 2 },
        EVENT_NODE,
      ),
    ).toThrow(ApiError);
  });
  it("uses local fixed paths, exclusive origin/episode filters and one exact POST without retry", async () => {
    expect(
      alertEventQuery({
        before: "3",
        limit: 10,
        origin_node_id: EVENT_OTHER,
        episode_id: "1",
      }),
    ).toBe(`?before=3&limit=10&origin_node_id=${EVENT_OTHER}&episode_id=1`);
    const signal = new AbortController().signal,
      response = episodeFixture(true);
    const fetcher = vi.fn(async () => jsonResponse(response)),
      client = new ManagementClient(fetcher, () => true);
    await client.acknowledgeAlertEpisode(
      "1",
      { expected_node_id: EVENT_NODE, expected_transition_sequence: "1" },
      "csrf",
      signal,
    );
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenLastCalledWith(
      "/api/v1/alert-episodes/1/acknowledge",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          expected_node_id: EVENT_NODE,
          expected_transition_sequence: "1",
        }),
        headers: expect.objectContaining({ "X-CSRF-Token": "csrf" }),
      }),
    );
    await client.alertEpisode(EVENT_NODE, "1", signal);
    expect(fetcher).toHaveBeenLastCalledWith(
      "/api/v1/alert-episodes/1",
      expect.objectContaining({ method: "GET" }),
    );
    for (const suffix of [
      "?before=0",
      "?limit=51",
      "?limit=1&%6cimit=2",
      "?episode_id=0",
      "?origin_node_id=bad",
      "?latest=true",
    ])
      expect(() => endpointStatus(`/alert-events${suffix}`, "GET")).toThrow(
        ApiError,
      );
    expect(() => endpointStatus("/alert-events/1/acknowledge", "POST")).toThrow(
      ApiError,
    );
    expect(() =>
      endpointStatus("/alert-episodes/1/acknowledge", "GET"),
    ).toThrow(ApiError);
    expect(() => endpointStatus("/alert-events/1?before=2", "GET")).toThrow(
      ApiError,
    );
    const failed = vi.fn(async () => {
      throw new TypeError("synthetic lost response");
    });
    await expect(
      new ManagementClient(failed, () => true).acknowledgeAlertEpisode(
        "1",
        { expected_node_id: EVENT_NODE, expected_transition_sequence: "1" },
        "csrf",
        signal,
      ),
    ).rejects.toMatchObject({ kind: "network" });
    expect(failed).toHaveBeenCalledTimes(1);
    const later = new ManagementClient(
      async () =>
        jsonResponse({
          ...episodeFixture(true),
          latest_transition_sequence: "3",
          acknowledged_transition_sequence: "3",
          acknowledgement_event_sequence: "4",
        }),
      () => true,
    );
    await expect(
      later.acknowledgeAlertEpisode(
        "1",
        { expected_node_id: EVENT_NODE, expected_transition_sequence: "1" },
        "csrf",
        signal,
      ),
    ).rejects.toMatchObject({ kind: "format" });
  });
  it("validates descending pages and gives only the bounded event list a larger byte budget", async () => {
    const value = eventPageFixture();
    expect(alertEventPage(value, EVENT_NODE, {}).items).toHaveLength(1);
    expect(() => alertEventPage(value, EVENT_NODE, { before: "1" })).toThrow(
      ApiError,
    );
    expect(() =>
      alertEventPage(value, EVENT_NODE, { origin_node_id: EVENT_OTHER }),
    ).toThrow(ApiError);
    expect(() =>
      alertEventPage({ ...value, trimmed: false }, EVENT_NODE, {}),
    ).toThrow(ApiError);
    const items = Array.from({ length: 50 }, (_, index) => ({
      ...eventFixture(),
      sequence: String(100 - index),
      episode_id: String(100 - index),
      incident_id: String(18_446_744_073_709_551_615n - BigInt(index)),
      kind: "egress_check",
      resource_id: EVENT_OTHER,
      check: "tcp",
      target: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
      code: "a".repeat(64),
      first_observed_at_unix_ms: "18446744073709551615",
      last_observed_at_unix_ms: "18446744073709551615",
      evidence_sequence: "18446744073709551615",
      observed_at_unix_ms: "18446744073709551615",
      recorded_at_unix_ms: "18446744073709551615",
    }));
    const large = { ...value, items, oldest_sequence: "51" };
    expect(
      new TextEncoder().encode(JSON.stringify(large)).length,
    ).toBeGreaterThan(32_768);
    const client = new ManagementClient(
        async () => jsonResponse(large),
        () => true,
      ),
      signal = new AbortController().signal;
    expect(
      (await client.alertEvents(EVENT_NODE, { limit: 50 }, signal)).items,
    ).toHaveLength(50);
    const detail = new ManagementClient(
      async () =>
        new Response(" ".repeat(32_768) + JSON.stringify(eventFixture()), {
          headers: { "Content-Type": "application/json" },
        }),
      () => true,
    );
    await expect(
      detail.alertEvent(EVENT_NODE, "1", signal),
    ).rejects.toMatchObject({ kind: "format" });
  });
});
