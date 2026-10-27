// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://manager.example/"}
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { ConfigProvider } from "antd";
import { StrictMode, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ManagementClient } from "../../api/client";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import {
  LOCAL,
  PEER,
  JOB,
  targetFixture,
} from "../../api/maintenance.fixtures";
import { runtimeFixture, RUNTIME } from "../../api/runtime.fixtures";
import type { DrainRequest, RuntimeStatus as Status } from "../../api/runtime";
import { ManagementProvider, useManagement } from "../../auth/context";
import type { SessionController } from "../../auth/session";
import ManagementGate from "../../components/ManagementGate";
import en from "../../locales/en-US";
import zh from "../../locales/zh-CN";
import RuntimeStatus from "./RuntimeStatus";

vi.mock("../../hooks/useMessages", async () => {
  const en = (await import("../../locales/en-US")).default;
  const zh = (await import("../../locales/zh-CN")).default;
  return {
    useMessages: () => ({
      intl: { locale },
      t: (id: keyof typeof en) => (locale === "zh-CN" ? zh : en)[id],
    }),
  };
});
let locale: "en-US" | "zh-CN";
let controller: SessionController, remote: boolean, snapshot: Status;
let readStatus: () => Promise<Response>, exactStatus: () => Promise<Response>;
let mutate: (body: unknown) => Promise<Response>;
let requests: {
  path: string;
  method: string;
  body: unknown;
  signal: AbortSignal | null;
}[];
const path = () => `/api/v1${remote ? `/targets/${PEER}` : ""}/proxy/runtime`;
const writes = () => requests.filter((request) => request.method === "POST");
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
beforeEach(() => {
  locale = "en-US";
  remote = false;
  snapshot = runtimeFixture();
  requests = [];
  readStatus = async () => jsonResponse(snapshot);
  exactStatus = async () => jsonResponse(snapshot);
  mutate = async (body) => {
    const request = (
      remote ? (body as { request: DrainRequest }).request : body
    ) as DrainRequest;
    snapshot = {
      ...runtimeFixture(remote, "draining"),
      runtime: { ...runtimeFixture(remote, "draining").runtime!, request },
    };
    return jsonResponse(snapshot, 202);
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
      const endpoint = String(input),
        method = init?.method ?? "GET",
        body = init?.body ? JSON.parse(init.body as string) : null;
      requests.push({
        path: endpoint,
        method,
        body,
        signal: init?.signal ?? null,
      });
      if (endpoint === "/api/v1/auth/session")
        return jsonResponse({
          ...sessionFixture(),
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        });
      if (endpoint === `/api/v1/targets/${PEER}`)
        return jsonResponse(targetFixture());
      if (endpoint === path() && method === "GET") return readStatus();
      if (endpoint === `${path()}/drain` && method === "POST")
        return mutate(body);
      if (endpoint.startsWith(`${path()}/drains/`) && method === "GET")
        return exactStatus();
      throw new Error("Unexpected runtime fixture endpoint");
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function Host() {
  controller = useManagement().controller;
  const [shown, setShown] = useState(true),
    [node, setNode] = useState(LOCAL);
  return (
    <>
      <button onClick={() => setShown((value) => !value)}>test.toggle</button>
      <button onClick={() => setNode(PEER)}>test.node</button>
      <ManagementGate>
        {shown && (
          <RuntimeStatus
            localNodeId={node}
            target={remote ? targetFixture() : null}
            unavailable={false}
          />
        )}
      </ManagementGate>
    </>
  );
}
const messages = () => (locale === "zh-CN" ? zh : en);
async function mount() {
  render(
    <StrictMode>
      <ConfigProvider theme={{ token: { motion: false } }}>
        <ManagementProvider>
          <Host />
        </ManagementProvider>
      </ConfigProvider>
    </StrictMode>,
  );
  await screen.findByRole("button", { name: messages()["runtime.title"] });
}
const click = (key: keyof typeof en) =>
  fireEvent.click(screen.getByRole("button", { name: messages()[key] }));
async function open() {
  click("runtime.title");
  await screen.findByText(messages()["runtime.serving"]);
}
async function submit() {
  click("runtime.start");
  await screen.findByRole("button", { name: messages()["runtime.confirm"] });
  click("runtime.confirm");
}

describe("explicit runtime drain workflow", () => {
  it.each(["en-US", "zh-CN"] as const)(
    "keeps the read button name stable while loading and after completion in %s",
    async (language) => {
      locale = language;
      await mount();
      await open();
      const pending = deferred<Response>();
      readStatus = () => pending.promise;
      click("runtime.read");
      const button = screen.getByRole("button", {
        name: messages()["runtime.read"],
      }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      await act(async () => pending.resolve(jsonResponse(snapshot)));
      await waitFor(() =>
        expect(
          (
            screen.getByRole("button", {
              name: messages()["runtime.read"],
            }) as HTMLButtonElement
          ).disabled,
        ).toBe(false),
      );
      expect(writes()).toHaveLength(0);
    },
  );

  it("distinguishes planned drain progress from driver failure without resolving an unknown original request", async () => {
    await mount();
    await open();
    await submit();
    await screen.findByText(en["runtime.unknown"]);
    for (const [phase, severity] of [
      ["draining", "info"],
      ["drained", "success"],
      ["interrupted", "error"],
      ["failed", "error"],
    ] as const) {
      snapshot = {
        ...snapshot,
        runtime: {
          ...snapshot.runtime!,
          phase,
          active_operations: "0",
        },
      };
      click("runtime.read");
      const status = await screen.findByText(en[`runtime.${phase}`]);
      await waitFor(() =>
        expect(
          (
            screen.getByRole("button", {
              name: en["runtime.read"],
            }) as HTMLButtonElement
          ).disabled,
        ).toBe(false),
      );
      expect(status.closest(".ant-alert")?.classList).toContain(
        `ant-alert-${severity}`,
      );
      expect(screen.getByText(en["runtime.current"])).toBeTruthy();
      expect(screen.getByText(en["runtime.unknown"])).toBeTruthy();
      expect(screen.getByText(en["runtime.restart"])).toBeTruthy();
      expect(screen.getByText(en["runtime.boundary"])).toBeTruthy();
    }
    expect(writes()).toHaveLength(1);
    expect(
      requests.filter((request) => request.path.includes("/drains/")),
    ).toHaveLength(0);
  });
  it("reads on expansion, confirms once, retains 202 and obtains progress by the exact original pair", async () => {
    await mount();
    expect(requests.filter((request) => request.path === path())).toHaveLength(
      0,
    );
    await open();
    await submit();
    await screen.findByText(en["runtime.unknown"]);
    expect(writes()).toHaveLength(1);
    const request = writes()[0].body as DrainRequest;
    expect(request).toMatchObject({
      expected_node_id: LOCAL,
      expected_epoch: "2",
      expected_revision: "9",
      runtime_id: RUNTIME,
    });
    expect(request.request_id).toMatch(/^[A-Za-z0-9_-]{21}[AQgw]$/);
    expect(screen.queryByText(en["runtime.drained"])).toBeNull();
    snapshot = {
      ...snapshot,
      runtime: {
        ...snapshot.runtime!,
        phase: "drained",
        active_operations: "8",
      },
    };
    click("runtime.lookup");
    await screen.findByText(en["runtime.drained"]);
    expect(requests.at(-1)?.path).toBe(
      `${path()}/drains/${RUNTIME}/${request.request_id}`,
    );
    expect(screen.getByText(en["runtime.original"])).toBeTruthy();
    expect(screen.getByText("8")).toBeTruthy();
    expect(writes()).toHaveLength(1);
  });
  it("binds remote target CAS and fresh controller ownership without allocating a durable command", async () => {
    remote = true;
    snapshot = runtimeFixture(true);
    await mount();
    await open();
    await submit();
    await screen.findByText(en["runtime.unknown"]);
    expect(writes()).toHaveLength(1);
    expect(writes()[0]).toMatchObject({
      path: `${path()}/drain`,
      body: {
        expected_target_revision: "4",
        request: {
          expected_node_id: PEER,
          expected_epoch: "2",
          expected_revision: "9",
          runtime_id: RUNTIME,
        },
      },
    });
    expect(requests.some((request) => request.path.includes("commands"))).toBe(
      false,
    );
  });
  it("requires saved pause and serving state even when the lease count is zero", async () => {
    snapshot = {
      ...runtimeFixture(),
      saved_accepting: true,
      runtime: { ...runtimeFixture().runtime!, active_operations: "0" },
    };
    await mount();
    await open();
    await screen.findByText(en["runtime.pausedRequired"]);
    expect(
      (
        screen.getByRole("button", {
          name: en["runtime.start"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    snapshot = runtimeFixture(false, "drained");
    click("runtime.read");
    await screen.findByText(en["runtime.restart"]);
    expect(
      (
        screen.getByRole("button", {
          name: en["runtime.start"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(writes()).toHaveLength(0);
  });
  it("restores the original non-secret request after remount and never binds an unknown result to a replacement runtime", async () => {
    await mount();
    await open();
    await submit();
    await screen.findByText(en["runtime.unknown"]);
    const original = writes()[0].body as DrainRequest;
    cleanup();
    await mount();
    await screen.findByText(en["runtime.unknown"]);
    exactStatus = async () =>
      jsonResponse({ error: { code: "resource_not_found" } }, 404);
    click("runtime.lookup");
    await screen.findByText(en["runtime.originalUnknown"]);
    expect(requests.at(-1)?.path).toBe(
      `${path()}/drains/${RUNTIME}/${original.request_id}`,
    );
    snapshot = {
      ...runtimeFixture(),
      runtime: { ...runtimeFixture().runtime!, runtime_id: JOB },
    };
    click("runtime.read");
    await screen.findByText(en["runtime.serving"]);
    expect(screen.getByText(en["runtime.current"])).toBeTruthy();
    expect(screen.getByText(en["runtime.unknown"])).toBeTruthy();
    click("runtime.lookup");
    await screen.findByText(en["runtime.originalUnknown"]);
    expect(requests.at(-1)?.path).toBe(
      `${path()}/drains/${RUNTIME}/${original.request_id}`,
    );
    expect(writes()).toHaveLength(1);
  });
  it("keeps an aborted POST unknown, holds its lease until the callback settles and discards a late success", async () => {
    const late = deferred<Status>();
    const operation = vi
      .spyOn(ManagementClient.prototype, "drainRuntime")
      .mockImplementation(() => late.promise);
    await mount();
    await open();
    await submit();
    await waitFor(() => expect(operation).toHaveBeenCalledTimes(1));
    const original = operation.mock.calls[0][1];
    const response: Status = {
      ...runtimeFixture(false, "drained"),
      runtime: {
        ...runtimeFixture(false, "drained").runtime!,
        request: original,
      },
    };
    try {
      // Ant Design ignores Modal cancel while confirmLoading. Unmount is the
      // actual cancellation boundary, as it is for navigation away from Nodes.
      fireEvent.click(screen.getByRole("button", { name: "test.toggle" }));
      expect(operation.mock.calls[0][4].aborted).toBe(true);
      fireEvent.click(screen.getByRole("button", { name: "test.toggle" }));
      await screen.findByText(en["runtime.unknown"]);
      click("runtime.read");
      await screen.findByText(en["runtime.serving"]);
      click("maintenance.acknowledge");
      await act(async () => {});
      expect(screen.getByText(en["runtime.unknown"])).toBeTruthy();
      await act(async () => {
        late.resolve(response);
      });
      expect(screen.queryByText(en["runtime.drained"])).toBeNull();
      expect(screen.getByText(en["runtime.unknown"])).toBeTruthy();
      expect(operation).toHaveBeenCalledTimes(1);
    } finally {
      // Even a failing assertion must release the real browser scope lease.
      await act(async () => {
        late.resolve(response);
      });
    }
  });
  it("aborts session/identity reads and ignores a late result, while older-node 404 stays local", async () => {
    const late = deferred<Response>();
    readStatus = () => late.promise;
    await mount();
    click("runtime.title");
    await waitFor(() =>
      expect(
        requests.filter((request) => request.path === path()),
      ).toHaveLength(1),
    );
    const request = requests.find((request) => request.path === path())!;
    await act(async () => {
      await controller.check();
    });
    expect(request.signal?.aborted).toBe(true);
    await act(async () => {
      late.resolve(jsonResponse(runtimeFixture(false, "drained")));
    });
    expect(screen.queryByText(en["runtime.drained"])).toBeNull();
    readStatus = async () =>
      jsonResponse({ error: { code: "resource_not_found" } }, 404);
    click("runtime.title");
    await screen.findByText(en["runtime.unsupported"]);
    expect(writes()).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "test.node" }));
    await act(async () => {});
    expect(screen.queryByText(en["runtime.unsupported"])).toBeNull();
  });
  it("keeps the irreversible action and unknown-result warnings in Chinese", async () => {
    locale = "zh-CN";
    await mount();
    await open();
    click("runtime.start");
    await screen.findByRole("button", { name: zh["runtime.confirm"] });
    expect(screen.getAllByText(zh["runtime.scope"]).length).toBeGreaterThan(0);
    expect(screen.getAllByText(zh["runtime.wait"]).length).toBeGreaterThan(0);
    click("runtime.confirm");
    await screen.findByText(zh["runtime.unknown"]);
    expect(writes()).toHaveLength(1);
  });
});
