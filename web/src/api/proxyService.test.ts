import { describe, expect, it, vi } from "vitest";
import { ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import { PEER } from "./maintenance.fixtures";
import {
  serviceConfiguration,
  serviceStatus,
  serviceReceipt,
  serviceChange,
  type ServiceOperation,
} from "./proxyService";
import {
  serviceConfig,
  serviceFixture,
  serviceInput,
} from "./proxyService.fixtures";
import { endpointStatus } from "./proxy";

describe("Web listener control contract", () => {
  it("separates saved enabled from actual failed, stopped and old running observations", () => {
    for (const state of ["failed", "stopped", "running"] as const) {
      const status = serviceFixture();
      status.saved = {
        revision: "5",
        enabled: true,
        configuration: serviceConfig(),
      };
      status.runtime = {
        generation: "2",
        configuration_revision: "3",
        state,
        error: state === "failed" ? "address_in_use" : null,
        listeners: state === "running" ? serviceConfig().listeners : [],
      };
      expect(serviceStatus(status, status.node_id)).toEqual(status);
    }
    expect(() => serviceStatus(serviceFixture(), PEER)).toThrow();
    expect(() =>
      serviceStatus(
        { ...serviceFixture(), password: "forbidden" },
        serviceFixture().node_id,
      ),
    ).toThrow();
    expect(() =>
      serviceStatus(
        {
          ...serviceFixture(),
          runtime: { ...serviceFixture().runtime, state: "running" },
        },
        serviceFixture().node_id,
      ),
    ).toThrow();
  });
  it("bounds resources and transport duplicates without conflating TCP with MASQUE UDP", () => {
    const node = serviceFixture().node_id,
      config = serviceConfig();
    expect(() =>
      serviceConfiguration({ ...config, workers: 0 }, node),
    ).toThrow();
    expect(() =>
      serviceConfiguration({ ...config, connect_timeout: 301 }, node),
    ).toThrow();
    expect(() =>
      serviceConfiguration({ ...config, concurrent: 2147483648 }, node),
    ).toThrow();
    expect(() =>
      serviceConfiguration(
        {
          ...config,
          listeners: [
            ...config.listeners,
            { ...config.listeners[0], protocol: "http" },
          ],
        },
        node,
      ),
    ).toThrow();
    expect(
      serviceConfiguration(
        {
          ...config,
          listeners: [
            ...config.listeners,
            { ...config.listeners[0], protocol: "masque" },
          ],
        },
        node,
      ).listeners,
    ).toHaveLength(2);
    expect(() =>
      serviceChange({
        ...serviceInput(),
        configuration: {
          ...config,
          listeners: [
            {
              ...config.listeners[0],
              public_address: "https://user:pass@host:443",
            },
          ],
        },
      }),
    ).toThrow();
  });
  it("accepts only the exact original receipt, never a newer successful task", () => {
    const { configuration: _, ...original } = serviceInput();
    const receipt = {
      node_id: original.expected_node_id,
      revision: "2",
      controller_epoch: original.controller_epoch,
      request_id: original.request_id,
      enabled: true,
      state: "failed",
    };
    expect(serviceReceipt(receipt, original).state).toBe("failed");
    for (const patch of [
      { node_id: PEER },
      { revision: "3" },
      { controller_epoch: "3" },
      { request_id: PEER },
      { enabled: false },
      { state: "success" },
    ])
      expect(() =>
        serviceReceipt({ ...receipt, ...patch }, original),
      ).toThrow();
    expect(() =>
      serviceReceipt(receipt, {
        ...original,
        configuration: serviceConfig(),
      } as ServiceOperation),
    ).toThrow();
  });
  it("uses a Session/CSRF PUT and a strictly addressed GET without payload replay", async () => {
    const input = serviceInput(),
      { configuration: _, ...original } = input;
    const operation = {
      node_id: input.expected_node_id,
      revision: "2",
      controller_epoch: input.controller_epoch,
      request_id: input.request_id,
      enabled: true,
      state: "pending",
    };
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({ operation, runtime: serviceFixture().runtime }, 202),
      )
      .mockResolvedValueOnce(jsonResponse(operation));
    const client = new ManagementClient(fetcher, () => true),
      signal = new AbortController().signal;
    await client.setProxyService(input, "csrf", signal);
    await client.proxyServiceOperation(original, signal);
    expect(fetcher.mock.calls[0]).toMatchObject([
      "/api/v1/proxy/service",
      {
        method: "PUT",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "X-CSRF-Token": "csrf" },
        body: JSON.stringify(input),
      },
    ]);
    expect(fetcher.mock.calls[1]).toMatchObject([
      `/api/v1/proxy/service/operations/2/${input.request_id}?controller_epoch=2`,
      { method: "GET" },
    ]);
    expect(fetcher.mock.calls[1][1]?.body).toBeUndefined();
    for (const path of [
      `/proxy/service/operations/2/${input.request_id}?controller_epoch=2&controller_epoch=3`,
      `/proxy/service/operations/2/${input.request_id}?controller_epoch=02`,
      "/proxy/service?target=other",
    ])
      expect(() => endpointStatus(path, "GET")).toThrow();
  });
});
