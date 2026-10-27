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
import type {
  MaintenanceChange,
  MaintenanceStatus as Status,
} from "../../api/maintenance";
import {
  LOCAL,
  PEER,
  JOB,
  maintenanceFixture,
  maintenanceJobFixture,
  targetFixture,
} from "../../api/maintenance.fixtures";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import type { Job } from "../../api/targets";
import { ManagementProvider, useManagement } from "../../auth/context";
import type { SessionController } from "../../auth/session";
import ManagementGate from "../../components/ManagementGate";
import messages from "../../locales/en-US";
import MaintenanceStatus from "./MaintenanceStatus";
import { runtimeFixture } from "../../api/runtime.fixtures";

vi.mock("../../hooks/useMessages", async () => {
  const captions = (await import("../../locales/en-US")).default;
  return {
    useMessages: () => ({
      intl: { locale: "en-US" },
      t: (id: keyof typeof captions) => captions[id],
    }),
  };
});
let controller: SessionController;
let remote: boolean;
let drained: boolean;
let runtimeError: string | null;
let snapshot: Status;
let currentJob: Job | null;
let readStatus: () => Promise<Response>;
let mutate: () => Promise<Response>;
let requests: {
  path: string;
  method: string;
  body: unknown;
  signal: AbortSignal | null;
}[];
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
const maintenancePath = () =>
  remote
    ? `/api/v1/targets/${PEER}/proxy/maintenance`
    : "/api/v1/proxy/maintenance";
const reads = () =>
  requests.filter(
    (request) => request.path === maintenancePath() && request.method === "GET",
  );
const writes = () => requests.filter((request) => request.method === "POST");
beforeEach(() => {
  remote = false;
  drained = false;
  runtimeError = null;
  snapshot = maintenanceFixture();
  currentJob = null;
  requests = [];
  readStatus = async () => jsonResponse(snapshot);
  mutate = async () =>
    jsonResponse({
      saved_revision: "10",
      applied_revision: "10",
      running: true,
    });
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
        method = init?.method ?? "GET";
      requests.push({
        path,
        method,
        body: init?.body ? JSON.parse(init.body as string) : null,
        signal: init?.signal ?? null,
      });
      if (path === "/api/v1/auth/session")
        return jsonResponse({
          ...sessionFixture(),
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        });
      if (path === maintenancePath() && method === "GET") return readStatus();
      if (
        path ===
        (remote
          ? `/api/v1/targets/${PEER}/proxy/runtime`
          : "/api/v1/proxy/runtime")
      )
        return runtimeError
          ? jsonResponse({ error: { code: runtimeError } }, 502)
          : jsonResponse({
              ...runtimeFixture(remote, drained ? "drained" : "serving"),
              saved_accepting: drained ? false : snapshot.saved_accepting,
            });
      if (path === `/api/v1/targets/${PEER}`)
        return jsonResponse(targetFixture());
      if (path === `/api/v1/targets/${PEER}/command`)
        return jsonResponse(currentJob);
      if (
        path === `/api/v1/targets/${PEER}/maintenance/commands/refresh` &&
        method === "POST"
      )
        return jsonResponse(currentJob);
      if (
        (path === "/api/v1/proxy/maintenance" ||
          path === `/api/v1/targets/${PEER}/maintenance/commands`) &&
        method === "POST"
      )
        return mutate();
      throw new Error("Unexpected fixture API request");
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function Host() {
  const management = useManagement();
  controller = management.controller;
  const [shown, setShown] = useState(true);
  const [local, setLocal] = useState(LOCAL);
  return (
    <>
      <button onClick={() => setShown((value) => !value)}>test.toggle</button>
      <button onClick={() => setLocal(PEER)}>test.node</button>
      <ManagementGate>
        {shown && (
          <MaintenanceStatus
            localNodeId={local}
            target={remote ? targetFixture() : null}
            unavailable={false}
          />
        )}
      </ManagementGate>
    </>
  );
}
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
  await screen.findByRole("button", { name: messages["maintenance.title"] });
}
const open = () =>
  fireEvent.click(
    screen.getByRole("button", { name: messages["maintenance.title"] }),
  );
const refresh = () =>
  fireEvent.click(
    screen.getByRole("button", { name: messages["maintenance.read"] }),
  );
async function confirmPause() {
  fireEvent.click(
    screen.getByRole("button", { name: messages["maintenance.pause"] }),
  );
  const confirm = await screen.findByRole("button", {
    name: messages["maintenance.confirm"],
  });
  fireEvent.click(confirm);
}

describe("explicit node maintenance workflow", () => {
  it("keeps the read button name stable while loading and after completion", async () => {
    const pending = deferred<Response>();
    readStatus = () => pending.promise;
    await mount();
    open();
    await waitFor(() => expect(reads()).toHaveLength(1));
    const button = screen.getByRole("button", {
      name: messages["maintenance.read"],
    }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    await act(async () => pending.resolve(jsonResponse(snapshot)));
    await waitFor(() =>
      expect(
        (
          screen.getByRole("button", {
            name: messages["maintenance.read"],
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(false),
    );
    expect(writes()).toHaveLength(0);
  });

  it("keeps legacy remote admission pause readable without trusting unsupported runtime state", async () => {
    remote = true;
    snapshot = maintenanceFixture(true);
    runtimeError = "node_protocol_unsupported";
    await mount();
    open();
    await screen.findByText("3");
    await waitFor(() =>
      expect(
        (
          screen.getByRole("button", {
            name: messages["maintenance.pause"],
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(false),
    );
    snapshot = {
      ...snapshot,
      saved_accepting: false,
      runtime_accepting: false,
    };
    refresh();
    await screen.findByText(messages["runtime.resumeBlocked"]);
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.resume"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    snapshot = maintenanceFixture(true);
    runtimeError = "node_unavailable";
    refresh();
    await screen.findByText(messages["control.unavailable"]);
    // A failed refresh cannot replace the earlier paused observation with
    // this fixture's newer accepting=true value. Retain it as historical and
    // keep its resume action disabled rather than inventing current facts.
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.resume"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(
      screen.queryByRole("button", { name: messages["maintenance.pause"] }),
    ).toBeNull();
    expect(writes()).toHaveLength(0);
  });
  it("does not offer saved admission resume after the runtime has drained", async () => {
    snapshot = {
      ...maintenanceFixture(),
      saved_accepting: false,
      runtime_accepting: false,
    };
    drained = true;
    await mount();
    open();
    await screen.findByText(messages["runtime.resumeBlocked"]);
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.resume"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(writes()).toHaveLength(0);
  });
  it("blocks a new write at the signed policy or command sequence limit without throwing or resetting it", async () => {
    snapshot = {
      ...snapshot,
      saved_revision: "9223372036854775807",
      applied_revision: "9223372036854775807",
      durable_applied_revision: null,
    };
    await mount();
    open();
    await screen.findByText(messages["maintenance.sequenceExhausted"]);
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.pause"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    cleanup();
    remote = true;
    snapshot = maintenanceFixture(true);
    snapshot.ownership.last_terminal_command = "9223372036854775807";
    await mount();
    open();
    await screen.findByText(messages["maintenance.sequenceExhausted"]);
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.pause"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(writes()).toHaveLength(0);
  });
  it("submits local pause once and keeps saved acknowledgements separate from fresh runtime observations", async () => {
    await mount();
    expect(reads()).toHaveLength(0);
    open();
    await screen.findByText("3");
    expect(screen.getByText(messages["maintenance.shutdown"])).toBeTruthy();
    await confirmPause();
    await screen.findByText(messages["maintenance.savedReply"]);
    expect(writes()).toHaveLength(1);
    expect(writes()[0].body).toEqual({
      expected_node_id: LOCAL,
      expected_revision: "9",
      expected_epoch: "2",
      accepting: false,
    });
    expect(reads()).toHaveLength(1);
    expect(screen.queryByText(messages["maintenance.zero"])).toBeNull();
    expect(screen.getByText(messages["maintenance.historical"])).toBeTruthy();
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.pause"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    snapshot = {
      ...snapshot,
      saved_revision: "10",
      applied_revision: "10",
      saved_accepting: false,
      runtime_accepting: false,
      active_operations: "0",
    };
    refresh();
    await screen.findByText(messages["maintenance.zero"]);
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.resume"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(false);
    expect(reads()).toHaveLength(2);
    expect(writes()).toHaveLength(1);
  });
  it("keeps one remote command fenced until an explicit exact-ticket review, without automatic retry or polling", async () => {
    remote = true;
    snapshot = maintenanceFixture(true);
    currentJob = maintenanceJobFixture();
    mutate = async () => jsonResponse({ job: currentJob, response: null }, 202);
    await mount();
    open();
    await screen.findByText("3");
    await confirmPause();
    await screen.findByText(messages["maintenance.uncertain"]);
    expect(writes()).toHaveLength(1);
    expect(writes()[0]).toMatchObject({
      path: `/api/v1/targets/${PEER}/maintenance/commands`,
      body: {
        expected_target_revision: "4",
        controller_epoch: "2",
        command_id: "8",
        expected_policy_revision: "9",
        mutation: { action: "set_admission", accepting: false },
      },
    });
    expect(reads()).toHaveLength(1);
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.acknowledge"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    refresh();
    await screen.findByText(messages["maintenance.receiptPending"]);
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.acknowledge"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    const receipt = screen.getByRole("button", {
      name: messages["maintenance.readReceipt"],
    });
    expect((receipt as HTMLButtonElement).disabled).toBe(false);
    currentJob = {
      ...maintenanceJobFixture(),
      state: "applied",
      policy_revision: "10",
    };
    snapshot = {
      ...snapshot,
      saved_revision: "10",
      applied_revision: "10",
      saved_accepting: false,
      runtime_accepting: false,
      active_operations: "0",
    };
    fireEvent.click(receipt);
    await screen.findByText(messages["maintenance.zero"]);
    await waitFor(() =>
      expect(
        (
          screen.getByRole("button", {
            name: messages["maintenance.acknowledge"],
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(false),
    );
    fireEvent.click(
      screen.getByRole("button", { name: messages["maintenance.acknowledge"] }),
    );
    await waitFor(() =>
      expect(screen.queryByText(messages["maintenance.uncertain"])).toBeNull(),
    );
    expect(screen.getByText(messages["maintenance.historical"])).toBeTruthy();
    expect(writes()).toHaveLength(2);
    expect(writes()[1]).toMatchObject({
      path: `/api/v1/targets/${PEER}/maintenance/commands/refresh`,
      body: { job_id: JOB },
    });
    expect(
      requests.some((request) => /\/retry|\/supersede/.test(request.path)),
    ).toBe(false);
    expect(reads()).toHaveLength(3);
  });
  it("restores an unknown write without fetching, replaying or inventing a result", async () => {
    mutate = async () => {
      throw new TypeError("private-response-marker");
    };
    await mount();
    open();
    await screen.findByText("3");
    await confirmPause();
    await screen.findByText(messages["maintenance.uncertain"]);
    expect(writes()).toHaveLength(1);
    const before = localStorage.length;
    expect(before).toBe(1);
    expect(localStorage.getItem(localStorage.key(0)!)).not.toMatch(
      /private-response-marker|csrf|password|payload/,
    );
    cleanup();
    await mount();
    await screen.findByText(messages["maintenance.uncertain"]);
    expect(reads()).toHaveLength(1);
    expect(writes()).toHaveLength(1);
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.acknowledge"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    refresh();
    await screen.findByText("3");
    await waitFor(() =>
      expect(
        (
          screen.getByRole("button", {
            name: messages["maintenance.acknowledge"],
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(false),
    );
    fireEvent.click(
      screen.getByRole("button", { name: messages["maintenance.acknowledge"] }),
    );
    await waitFor(() => expect(localStorage.length).toBe(0));
    expect(writes()).toHaveLength(1);
    expect(screen.queryByText("private-response-marker")).toBeNull();
  });
  it("does not attribute another latest job to an unknown maintenance command or clear pending work", async () => {
    remote = true;
    snapshot = maintenanceFixture(true);
    currentJob = maintenanceJobFixture();
    mutate = async () => jsonResponse({ job: currentJob, response: null }, 202);
    await mount();
    open();
    await screen.findByText("3");
    await confirmPause();
    await screen.findByText(messages["maintenance.uncertain"]);
    currentJob = { ...maintenanceJobFixture(), job_id: LOCAL };
    refresh();
    await screen.findByText(messages["maintenance.receiptMismatch"]);
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.readReceipt"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.acknowledge"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(screen.getByText(JOB)).toBeTruthy();
    expect(writes()).toHaveLength(1);
  });
  it("keeps the original job in a receipt refresh body and refuses a slot replacement between review and refresh", async () => {
    remote = true;
    snapshot = maintenanceFixture(true);
    currentJob = maintenanceJobFixture();
    mutate = async () => jsonResponse({ job: currentJob, response: null }, 202);
    await mount();
    open();
    await screen.findByText("3");
    await confirmPause();
    await screen.findByText(messages["maintenance.uncertain"]);
    refresh();
    await screen.findByText(messages["maintenance.receiptPending"]);
    currentJob = { ...maintenanceJobFixture(), job_id: LOCAL };
    fireEvent.click(
      screen.getByRole("button", { name: messages["maintenance.readReceipt"] }),
    );
    await screen.findByText(messages["api.format"]);
    expect(writes()).toHaveLength(2);
    expect(writes()[1]).toMatchObject({
      path: `/api/v1/targets/${PEER}/maintenance/commands/refresh`,
      body: { job_id: JOB },
    });
    expect(reads()).toHaveLength(2);
    expect(screen.getByText(JOB)).toBeTruthy();
    expect(screen.getByText(messages["maintenance.uncertain"])).toBeTruthy();
    expect(
      (
        screen.getByRole("button", {
          name: messages["maintenance.acknowledge"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });
  it("refuses a write when the non-secret journal cannot be saved", async () => {
    await mount();
    open();
    await screen.findByText("3");
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("Synthetic storage failure");
    });
    await confirmPause();
    await waitFor(() =>
      expect(
        (
          screen.getByRole("button", {
            name: messages["maintenance.pause"],
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(true),
    );
    expect(writes()).toHaveLength(0);
  });
  it("keeps cancelled writes unknown until their actual callback settles and discards a late success", async () => {
    const late = deferred<MaintenanceChange>();
    const operation = vi
      .spyOn(ManagementClient.prototype, "setMaintenance")
      .mockImplementation(() => late.promise);
    await mount();
    open();
    await screen.findByText("3");
    await confirmPause();
    await waitFor(() => expect(operation).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "test.toggle" }));
    expect(operation.mock.calls[0][2].aborted).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "test.toggle" }));
    await screen.findByText(messages["maintenance.uncertain"]);
    refresh();
    await screen.findByText("3");
    fireEvent.click(
      screen.getByRole("button", { name: messages["maintenance.acknowledge"] }),
    );
    await act(async () => {});
    expect(screen.getByText(messages["maintenance.uncertain"])).toBeTruthy();
    await act(async () => {
      late.resolve({
        saved_revision: "10",
        applied_revision: "10",
        running: true,
      });
    });
    expect(screen.queryByText(messages["maintenance.savedReply"])).toBeNull();
    expect(screen.getByText(messages["maintenance.uncertain"])).toBeTruthy();
    expect(operation).toHaveBeenCalledTimes(1);
  });
  it("aborts an old identity/session read, keeps unknown counts unknown, and does not let older nodes affect the page", async () => {
    const late = deferred<Response>();
    readStatus = () => late.promise;
    await mount();
    open();
    await waitFor(() => expect(reads()).toHaveLength(1));
    const signal = reads()[0].signal;
    await act(async () => {
      await controller.check();
    });
    expect(signal?.aborted).toBe(true);
    expect(
      screen
        .getByRole("button", { name: messages["maintenance.title"] })
        .getAttribute("aria-expanded"),
    ).toBe("false");
    readStatus = async () =>
      jsonResponse({
        ...snapshot,
        applied_revision: null,
        runtime_accepting: null,
        active_operations: null,
      });
    open();
    await screen.findByText(messages["maintenance.active"]);
    await act(async () => {
      late.resolve(jsonResponse({ ...snapshot, active_operations: "0" }));
    });
    expect(screen.queryByText(messages["maintenance.zero"])).toBeNull();
    readStatus = async () =>
      jsonResponse(
        {
          error: {
            code: "resource_not_found",
            message: "private-server-marker",
          },
        },
        404,
      );
    refresh();
    await screen.findByText(messages["maintenance.unsupported"]);
    expect(screen.queryByText("private-server-marker")).toBeNull();
    expect(writes()).toHaveLength(0);
  });
});
