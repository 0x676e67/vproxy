// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://manager.example/"}
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { ConfigProvider } from "antd";
import { StrictMode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import { LOCAL, PEER } from "../../api/maintenance.fixtures";
import { serviceConfig, serviceFixture } from "../../api/proxyService.fixtures";
import type {
  ServiceChange,
  ServiceReceipt,
  ServiceStatus,
} from "../../api/proxyService";
import { ManagementProvider, useManagement } from "../../auth/context";
import type { SessionController } from "../../auth/session";
import ServicePage from "./index";

vi.mock("@umijs/max", async () => ({
  Link: (await import("react-router-dom")).Link,
}));
vi.mock("../../hooks/useMessages", () => ({
  useMessages: () => ({ t: (key: string) => key, intl: { locale: "en-US" } }),
}));
let snapshot: ServiceStatus, delegated: boolean, controller: SessionController;
let requests: { path: string; method: string; body: unknown }[];
let mutate: (input: ServiceChange) => Promise<Response>;
let readStatus: () => Promise<Response>;
let readOriginal: () => Promise<Response>;
let original: ServiceReceipt | null;
beforeEach(() => {
  snapshot = serviceFixture();
  delegated = false;
  requests = [];
  original = null;
  readStatus = async () => jsonResponse(snapshot);
  readOriginal = async () => jsonResponse(original);
  mutate = async (input) => {
    const revision = (BigInt(input.expected_revision) + 1n).toString();
    snapshot.saved = {
      revision,
      enabled: input.enabled,
      configuration: input.configuration,
    };
    snapshot.runtime = {
      generation: "1",
      configuration_revision: revision,
      state: input.enabled ? "running" : "stopped",
      error: null,
      listeners: input.enabled ? input.configuration.listeners : [],
    };
    original = {
      node_id: LOCAL,
      controller_epoch: input.controller_epoch,
      request_id: input.request_id,
      revision,
      enabled: input.enabled,
      state: "applied",
    };
    return jsonResponse(
      { operation: original, runtime: snapshot.runtime },
      202,
    );
  };
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  vi.stubGlobal("matchMedia", (media: string) => ({
    matches: false,
    media,
    onchange: null,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent: () => false,
  }));
  const computed = window.getComputedStyle.bind(window);
  vi.spyOn(window, "getComputedStyle").mockImplementation((element) =>
    computed(element),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input),
        method = init?.method ?? "GET",
        body = init?.body ? JSON.parse(String(init.body)) : null;
      requests.push({ path, method, body });
      if (path === "/api/v1/auth/session")
        return jsonResponse({
          ...sessionFixture(),
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        });
      if (path === "/api/v1/node")
        return jsonResponse({
          node_id: LOCAL,
          name: "Test node",
          version: "test",
          os: "linux",
          arch: "x86_64",
          capabilities: [],
        });
      if (path === "/api/v1/proxy/owner")
        return jsonResponse({
          controller_node_id: delegated ? PEER : null,
          epoch: "2",
          last_terminal_command: "0",
        });
      if (path === "/api/v1/proxy/service")
        return method === "PUT" ? mutate(body) : readStatus();
      if (path.startsWith("/api/v1/proxy/service/operations/"))
        return readOriginal();
      throw new Error("Unexpected service fixture endpoint");
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function Host() {
  controller = useManagement().controller;
  return <ServicePage />;
}
async function mount(initial: "stopped" | "running" = "stopped") {
  render(
    <StrictMode>
      <ConfigProvider theme={{ token: { motion: false } }}>
        <MemoryRouter>
          <ManagementProvider>
            <Host />
          </ManagementProvider>
        </MemoryRouter>
      </ConfigProvider>
    </StrictMode>,
  );
  await screen.findByText(`service.state.${initial}`);
  await waitFor(() =>
    expect(
      screen
        .getByRole("button", {
          name: initial === "running" ? "service.apply" : "service.start",
        })
        .hasAttribute("disabled"),
    ).toBe(false),
  );
}
const puts = () => requests.filter((item) => item.method === "PUT");
async function start() {
  fireEvent.click(screen.getByRole("button", { name: "service.start" }));
  const dialog = await screen.findByRole("dialog");
  fireEvent.click(
    within(dialog).getByRole("button", { name: "service.apply" }),
  );
}

/** Deliver the accepted response after switching clocks, keeping form
 * validation and the confirmation dialog on real browser timers. */
async function pendingStart() {
  await mount();
  let accept!: (value: Response) => void;
  mutate = (input) => {
    snapshot.saved = {
      revision: "2",
      enabled: true,
      configuration: input.configuration,
    };
    snapshot.runtime = {
      generation: "1",
      configuration_revision: null,
      state: "starting",
      error: null,
      listeners: [],
    };
    original = {
      node_id: LOCAL,
      controller_epoch: input.controller_epoch,
      request_id: input.request_id,
      revision: "2",
      enabled: true,
      state: "pending",
    };
    return new Promise((resolve) => {
      accept = resolve;
    });
  };
  await start();
  await waitFor(() => expect(puts()).toHaveLength(1));
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  await act(async () => {
    accept(
      jsonResponse({ operation: original, runtime: snapshot.runtime }, 202),
    );
  });
  expect(screen.getByText("service.following")).toBeTruthy();
}
const lookups = () =>
  requests.filter((item) =>
    item.path.startsWith("/api/v1/proxy/service/operations/"),
  );

async function tick(milliseconds = 1000) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(milliseconds);
  });
}

describe("local service setup", () => {
  it("follows only the accepted request through pending to a terminal receipt without another write or resetting the form", async () => {
    await pendingStart();
    await tick();
    expect(lookups()).toHaveLength(1);
    expect(controller.nodeChanges.snapshot()[0]?.phase).toBe("pending");
    snapshot.runtime = {
      generation: "1",
      configuration_revision: "2",
      state: "running",
      error: null,
      listeners: serviceConfig().listeners,
    };
    original = { ...original!, state: "applied" };
    await tick();
    expect(screen.getByText("service.state.running")).toBeTruthy();
    expect(screen.getByText("service.receipt.applied")).toBeTruthy();
    expect(screen.queryByText("service.following")).toBeNull();
    expect(controller.nodeChanges.snapshot()).toHaveLength(0);
    expect(puts()).toHaveLength(1);
    const sent = puts()[0].body as ServiceChange;
    expect(lookups().map((item) => item.path)).toEqual([
      `/api/v1/proxy/service/operations/2/${sent.request_id}?controller_epoch=2`,
      `/api/v1/proxy/service/operations/2/${sent.request_id}?controller_epoch=2`,
    ]);
    expect(
      (screen.getByLabelText("service.host") as HTMLInputElement).value,
    ).toBe("manager.example");
    await tick(60_000);
    expect(lookups()).toHaveLength(2);
    expect(puts()).toHaveLength(1);
  });

  it("shows an exact failure even when a later configuration is listening", async () => {
    await pendingStart();
    original = { ...original!, state: "failed" };
    snapshot.runtime = {
      generation: "2",
      configuration_revision: "3",
      state: "running",
      error: null,
      listeners: serviceConfig().listeners,
    };
    await tick();
    expect(screen.getByText("service.receipt.failed")).toBeTruthy();
    expect(screen.getByText("service.state.running")).toBeTruthy();
    expect(controller.nodeChanges.snapshot()).toHaveLength(0);
    await tick(60_000);
    expect(lookups()).toHaveLength(1);
    expect(puts()).toHaveLength(1);
  });

  it("limits pending queries and keeps the original reminder for manual lookup", async () => {
    await pendingStart();
    await tick(60_000);
    expect(lookups()).toHaveLength(15);
    expect(puts()).toHaveLength(1);
    expect(controller.nodeChanges.snapshot()[0]?.phase).toBe("unknown");
    expect(screen.getByText("service.unconfirmed")).toBeTruthy();
    expect(screen.queryByText("service.following")).toBeNull();
    expect(
      (
        screen.getByRole("button", {
          name: "service.acknowledge",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    original = { ...original!, state: "interrupted" };
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "service.inspect" }));
    });
    expect(screen.getByText("service.receipt.interrupted")).toBeTruthy();
    expect(lookups()).toHaveLength(16);
    expect(controller.nodeChanges.snapshot()).toHaveLength(1);
  });

  it("also stops at the overall deadline when individual reads are slow", async () => {
    await pendingStart();
    readOriginal = () =>
      new Promise((resolve) => {
        setTimeout(() => resolve(jsonResponse(original)), 14_000);
      });
    await tick(30_000);
    expect(lookups()).toHaveLength(2);
    expect(screen.getByText("service.unconfirmed")).toBeTruthy();
    expect(controller.nodeChanges.snapshot()[0]?.phase).toBe("unknown");
    await tick(60_000);
    expect(lookups()).toHaveLength(2);
    expect(puts()).toHaveLength(1);
  });

  it("does not overlap queries or accept an old query after session replacement", async () => {
    await pendingStart();
    let deliver!: (value: Response) => void;
    readOriginal = () =>
      new Promise((resolve) => {
        deliver = resolve;
      });
    await tick(1000);
    await tick(2000);
    expect(lookups()).toHaveLength(1);
    await act(async () => {
      await controller.check();
    });
    expect(controller.nodeChanges.snapshot()[0]?.phase).toBe("unknown");
    await act(async () => {
      deliver(jsonResponse({ ...original!, state: "applied" }));
    });
    await tick(60_000);
    expect(screen.queryByText("service.receipt.applied")).toBeNull();
    expect(screen.getByText("service.unconfirmed")).toBeTruthy();
    expect(lookups()).toHaveLength(1);
    expect(puts()).toHaveLength(1);
  });

  it("cancels the waiting timer on unmount without cancelling or resubmitting the admitted operation", async () => {
    await pendingStart();
    cleanup();
    await tick(60_000);
    expect(lookups()).toHaveLength(0);
    expect(puts()).toHaveLength(1);
    expect(controller.nodeChanges.snapshot()[0]?.phase).toBe("unknown");
  });

  it("retains the reminder on a mismatched receipt instead of adopting current listening state", async () => {
    await pendingStart();
    original = { ...original!, request_id: PEER, state: "applied" };
    snapshot.runtime = {
      generation: "1",
      configuration_revision: "2",
      state: "running",
      error: null,
      listeners: serviceConfig().listeners,
    };
    await tick(60_000);
    expect(lookups()).toHaveLength(1);
    expect(screen.queryByText("service.receipt.applied")).toBeNull();
    expect(screen.getByText("service.state.running")).toBeTruthy();
    expect(screen.getByText("service.unconfirmed")).toBeTruthy();
    expect(controller.nodeChanges.snapshot()[0]?.phase).toBe("unknown");
    expect(puts()).toHaveLength(1);
  });

  it("mounts under StrictMode, preserves unsaved inputs on refresh, and starts actual listeners only after confirmation", async () => {
    await mount();
    expect(
      (screen.getByLabelText("service.host") as HTMLInputElement).value,
    ).toBe("manager.example");
    fireEvent.change(screen.getByLabelText("service.host"), {
      target: { value: "proxy.example" },
    });
    fireEvent.click(screen.getByRole("button", { name: "service.refresh" }));
    await waitFor(() =>
      expect(
        requests.filter((item) => item.path === "/api/v1/proxy/service"),
      ).toHaveLength(2),
    );
    expect(
      (screen.getByLabelText("service.host") as HTMLInputElement).value,
    ).toBe("proxy.example");
    expect(puts()).toHaveLength(0);
    fireEvent.change(screen.getByLabelText("service.port"), {
      target: { value: "18555" },
    });
    await start();
    await screen.findByText("service.state.running");
    expect(puts()).toHaveLength(1);
    expect(puts()[0].body).toMatchObject({
      enabled: true,
      expected_node_id: LOCAL,
      expected_revision: "1",
      configuration: {
        listeners: [
          {
            protocol: "https",
            bind: "0.0.0.0:18555",
            public_address: "proxy.example:18555",
          },
        ],
      },
    });
    expect(
      screen.getByRole("link", { name: "service.users" }).getAttribute("href"),
    ).toBe("/users");
    fireEvent.click(screen.getByRole("button", { name: "service.stop" }));
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "service.stop",
      }),
    );
    await screen.findByText("service.state.stopped");
    expect(puts()[1].body).toMatchObject({
      enabled: false,
      expected_revision: "2",
    });
  });
  it("does not equate saved enabled with running or automatically retry a failed operation", async () => {
    await mount();
    mutate = async (input) => {
      snapshot.saved = {
        revision: "2",
        enabled: true,
        configuration: input.configuration,
      };
      snapshot.runtime = {
        generation: "1",
        configuration_revision: null,
        state: "failed",
        error: "address_in_use",
        listeners: [],
      };
      return jsonResponse(
        {
          operation: {
            node_id: LOCAL,
            controller_epoch: input.controller_epoch,
            request_id: input.request_id,
            revision: "2",
            enabled: true,
            state: "failed",
          },
          runtime: snapshot.runtime,
        },
        202,
      );
    };
    await start();
    await screen.findByText("service.error.address_in_use");
    expect(screen.queryByText("service.state.running")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "service.refresh" }));
    expect(puts()).toHaveLength(1);
  });
  it("retains a lost response for exact-ID lookup instead of retrying or adopting current success", async () => {
    await mount();
    mutate = async (input) => {
      original = {
        node_id: LOCAL,
        controller_epoch: input.controller_epoch,
        request_id: input.request_id,
        revision: "2",
        enabled: true,
        state: "failed",
      };
      throw new TypeError("Synthetic lost response");
    };
    await start();
    await screen.findByText("service.unconfirmed");
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    await tick(60_000);
    expect(lookups()).toHaveLength(0);
    vi.useRealTimers();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "service.inspect" }));
    });
    expect(screen.getByText("service.receipt.failed")).toBeTruthy();
    const sent = puts()[0].body as ServiceChange;
    expect(
      requests.some(
        (item) =>
          item.path ===
          `/api/v1/proxy/service/operations/2/${sent.request_id}?controller_epoch=2`,
      ),
    ).toBe(true);
    expect(puts()).toHaveLength(1);
    fireEvent.click(
      screen.getByRole("button", { name: "service.acknowledge" }),
    );
    await waitFor(() =>
      expect(controller.nodeChanges.snapshot()).toHaveLength(0),
    );
  });
  it("revokes editing when delegated, without applying a local fallback", async () => {
    await mount();
    delegated = true;
    fireEvent.click(screen.getByRole("button", { name: "service.refresh" }));
    await screen.findByText("service.delegated");
    expect(
      (
        screen.getByRole("button", {
          name: "service.start",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(puts()).toHaveLength(0);
  });
  it("can disable a saved enabled configuration even when its listeners are already stopped", async () => {
    snapshot.saved = {
      revision: "2",
      enabled: true,
      configuration: serviceConfig(),
    };
    await mount();
    fireEvent.click(screen.getByRole("button", { name: "service.stop" }));
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "service.stop",
      }),
    );
    await waitFor(() => expect(puts()).toHaveLength(1));
    expect(puts()[0].body).toMatchObject({
      enabled: false,
      expected_revision: "2",
    });
  });
  it("does not publish an abort-ignoring old response into a replacement session", async () => {
    await mount();
    let deliver!: (value: Response) => void;
    mutate = () =>
      new Promise<Response>((resolve) => {
        deliver = resolve;
      });
    await start();
    await waitFor(() => expect(puts()).toHaveLength(1));
    const input = puts()[0].body as ServiceChange;
    await act(async () => {
      await controller.check();
    });
    await screen.findByText("service.unconfirmed");
    await act(async () => {
      deliver(
        jsonResponse(
          {
            operation: {
              node_id: LOCAL,
              revision: "2",
              controller_epoch: input.controller_epoch,
              request_id: input.request_id,
              enabled: true,
              state: "applied",
            },
            runtime: {
              generation: "1",
              configuration_revision: "2",
              state: "running",
              error: null,
              listeners: input.configuration.listeners,
            },
          },
          202,
        ),
      );
    });
    expect(screen.queryByText("service.state.running")).toBeNull();
    expect(screen.getByText("service.state.stopped")).toBeTruthy();
    expect(puts()).toHaveLength(1);
    expect(controller.nodeChanges.snapshot()[0]?.phase).toBe("unknown");
  });
  it("withdraws stale listening evidence and disables edits after a failed refresh", async () => {
    snapshot.saved = {
      revision: "2",
      enabled: true,
      configuration: serviceConfig(),
    };
    snapshot.runtime = {
      generation: "1",
      configuration_revision: "2",
      state: "running",
      error: null,
      listeners: serviceConfig().listeners,
    };
    await mount("running");
    readStatus = async () => {
      throw new TypeError("Synthetic unavailable read");
    };
    fireEvent.click(screen.getByRole("button", { name: "service.refresh" }));
    await screen.findByText("api.network");
    expect(screen.getByText("service.state.unknown")).toBeTruthy();
    expect(screen.queryByText("service.state.running")).toBeNull();
    expect(
      (
        screen.getByRole("button", {
          name: "service.start",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(puts()).toHaveLength(0);
    readStatus = async () => jsonResponse(snapshot);
    fireEvent.click(screen.getByRole("button", { name: "service.refresh" }));
    await screen.findByText("service.state.running");
    expect(
      (
        screen.getByRole("button", {
          name: "service.apply",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(false);
  });
});
