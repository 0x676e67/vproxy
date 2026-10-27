import { describe, expect, it, vi } from "vitest";
import { ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import { ApiError } from "./error";
import { publicEndpointAddress, publicEndpointInput } from "./endpoints";
import {
  endpointSelection,
  endpointSettings,
  endpointSubmission,
  selectedPublicAddress,
} from "./endpointSettings";
import {
  endpointCommandFixture,
  metadataJobFixture,
  settingsFixture,
  LOCAL,
  PEER,
  LISTENER,
  GENERATION,
} from "./endpointSettings.fixtures";
import { job, submission } from "./targets";
import { endpointStatus } from "./proxy";

describe("endpoint settings wire boundaries", () => {
  it("reads finite unique listener identities and exact effective projection", () => {
    const value = settingsFixture();
    expect(endpointSettings(value, LOCAL).listeners[0].id).toBe(LISTENER);
    for (const corrupt of [
      { ...value, node_id: PEER },
      { ...value, generation: GENERATION.toUpperCase() },
      { ...value, listeners: [...value.listeners, value.listeners[0]] },
      { ...value, listeners: Array(17).fill(value.listeners[0]) },
      { ...value, detached: Array(257).fill({}) },
      {
        ...value,
        detached: [
          {
            id: LISTENER,
            protocol: "http",
            bind: "0.0.0.0:8080",
            selection: { mode: "hidden" },
          },
        ],
      },
      {
        ...value,
        listeners: [{ ...value.listeners[0], selection: { mode: "hidden" } }],
      },
      {
        ...value,
        detached: [{ ...value.listeners[0], selection: { mode: "inherit" } }],
      },
      { ...value, credentials: [] },
    ])
      expect(() => endpointSettings(corrupt, LOCAL)).toThrow(ApiError);
    expect(
      endpointSelection({
        mode: "custom",
        public_address: "[::ffff:192.0.2.1]:1080",
      }),
    ).toEqual({ mode: "custom", public_address: "[::ffff:192.0.2.1]:1080" });
    expect(publicEndpointInput("2001:0DB8:0:0::1", "443")).toBe(
      "[2001:db8::1]:443",
    );
  });

  it("recognizes metadata tickets without treating them as policy or secret responses", () => {
    const input = endpointCommandFixture();
    for (const state of [
      "pending",
      "blocked",
      "saved",
      "rejected",
      "superseded",
    ]) {
      const ticket = {
        ...metadataJobFixture(),
        state,
        metadata_revision: state === "saved" ? "5" : null,
      };
      expect(
        endpointSubmission({ job: ticket, response: null }, PEER, input, 202)
          .job.state,
      ).toBe(state);
      expect(job(ticket, PEER)?.resource).toBe("proxy_endpoints");
    }
    const ticket = {
      ...metadataJobFixture(),
      state: "saved",
      metadata_revision: "5",
    };
    const response = {
      receipt: {
        controller_epoch: "2",
        command_id: "8",
        status: "saved",
        metadata_revision: "5",
        rejection: null,
        listener_id: LISTENER,
        generation: GENERATION,
      },
      replayed: false,
    };
    expect(
      endpointSubmission({ job: ticket, response }, PEER, input, 200).response
        ?.receipt.status,
    ).toBe("saved");
    for (const bad of [
      { job: { ...ticket, state: "applied" }, response },
      { job: { ...ticket, metadata_revision: "6" }, response },
      { job: ticket, response: { ...response, secret: "untrusted" } },
      {
        job: ticket,
        response: {
          ...response,
          receipt: { ...response.receipt, listener_id: LOCAL },
        },
      },
    ])
      expect(() => endpointSubmission(bad, PEER, input, 200)).toThrow(ApiError);
    expect(() =>
      submission(
        { job: ticket, response: null },
        PEER,
        {
          expected_target_revision: "3",
          controller_epoch: "2",
          command_id: "8",
          expected_policy_revision: "9",
          mutation: { action: "create_credential", user_id: LOCAL },
        },
        202,
      ),
    ).toThrow(ApiError);
  });

  it("uses fixed routes and only enlarges settings response bounds", async () => {
    expect(endpointStatus("/proxy/endpoint-settings", "GET")).toBe(200);
    expect(endpointStatus("/proxy/endpoint-settings/" + LISTENER, "PUT")).toBe(
      200,
    );
    expect(() =>
      endpointStatus("/proxy/endpoint-settings/" + LISTENER, "POST"),
    ).toThrow(ApiError);
    const client = new ManagementClient(undefined, () => true);
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse(settingsFixture()),
    );
    vi.stubGlobal("fetch", fetcher);
    try {
      await client.endpointSettings(new AbortController().signal);
      expect(fetcher.mock.calls[0][0]).toBe("/api/v1/proxy/endpoint-settings");
      // Valid data padded with harmless JSON whitespace still exercises the cap.
      vi.stubGlobal(
        "fetch",
        vi.fn(
          async () =>
            new Response(
              JSON.stringify(settingsFixture()) + " ".repeat(40_000),
              { headers: { "Content-Type": "application/json" } },
            ),
        ),
      );
      expect(
        (await client.endpointSettings(new AbortController().signal)).node_id,
      ).toBe(LOCAL);
      await expect(
        client.proxyEndpoints(new AbortController().signal),
      ).rejects.toMatchObject({ kind: "format" });
      vi.stubGlobal(
        "fetch",
        vi.fn(
          async () =>
            new Response(
              JSON.stringify(settingsFixture()) + " ".repeat(262_144),
              { headers: { "Content-Type": "application/json" } },
            ),
        ),
      );
      await expect(
        client.endpointSettings(new AbortController().signal),
      ).rejects.toMatchObject({ kind: "format" });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("persistent endpoint selection", () => {
  it("keeps following startup, custom metadata and explicit hidden distinct", () => {
    expect(
      selectedPublicAddress({ mode: "inherit" }, "proxy.example:1080"),
    ).toBe("proxy.example:1080");
    expect(selectedPublicAddress({ mode: "inherit" }, null)).toBeNull();
    expect(
      selectedPublicAddress({ mode: "hidden" }, "proxy.example:1080"),
    ).toBeNull();
    expect(
      selectedPublicAddress(
        { mode: "custom", public_address: "new.example:443" },
        "proxy.example:1080",
      ),
    ).toBe("new.example:443");
    for (const input of [
      { mode: "inherit", public_address: null },
      { mode: "hidden", public_address: "proxy.example:1080" },
      { mode: "custom" },
      { mode: "custom", public_address: null },
      { mode: "custom", public_address: "PROXY.example:1080" },
      { mode: "custom", public_address: "https://proxy.example:1080" },
      { mode: "unknown" },
    ])
      expect(() => endpointSelection(input)).toThrow(ApiError);
  });
});

describe("client address metadata input", () => {
  it("uses explicit host and canonical port without inventing a client protocol", () => {
    expect(publicEndpointInput("PROXY.example", "1080")).toBe(
      "proxy.example:1080",
    );
    expect(publicEndpointInput("[2001:db8::1]", "443")).toBe(
      "[2001:db8::1]:443",
    );
    expect(publicEndpointAddress("[2001:db8::1]:443")).toEqual({
      host: "2001:db8::1",
      port: 443,
    });
    expect(publicEndpointInput("127.0.0.1", "1")).toBe("127.0.0.1:1");
  });

  it("rejects URLs, secret-like authorities and unusable or ambiguous addresses", () => {
    for (const host of [
      "",
      "https://proxy.example",
      "user:password@proxy.example",
      "proxy.example/path",
      "proxy.example?token=value",
      "proxy.example#fragment",
      "proxy.example\n",
      "0.0.0.0",
      "::",
      "224.0.0.1",
      "ff02::1",
      "127.1",
      "[127.0.0.1]",
      "[proxy.example]",
      "fe80::1%eth0",
    ])
      expect(() => publicEndpointInput(host, "443"), host).toThrow(ApiError);
    for (const port of ["", "0", "00080", "-1", "1.5", "1e2", "65536"])
      expect(() => publicEndpointInput("proxy.example", port), port).toThrow(
        ApiError,
      );
  });
});
