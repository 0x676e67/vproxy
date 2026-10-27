// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://localhost/"}
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
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import {
  settingsFixture,
  metadataJobFixture,
  endpointPolicyFixture,
  endpointRemotePolicyFixture,
  targetFixture,
  LOCAL,
  PEER,
  LISTENER,
  JOB,
  GENERATION,
} from "../../api/endpointSettings.fixtures";
import { ManagementProvider } from "../../auth/context";
import { job } from "../../api/targets";
import CommandPanel from "../../pages/Users/CommandPanel";
import EndpointButton from "./Endpoints";

vi.mock("../../hooks/useMessages", () => ({
  useMessages: () => ({ t: (key: string) => key }),
}));
let settings: ReturnType<typeof settingsFixture>;
let writes: { path: string; init: RequestInit }[];
let paths: string[];
let remoteJob: ReturnType<typeof metadataJobFixture> | null;
let writeResponse: (() => Promise<Response>) | null;
let settingsDelay: Promise<Response> | null;
let settingsSignal: AbortSignal | null;
let unsupported: boolean;
let upgradeRequired: boolean;
let settingsDenied: boolean;
beforeEach(() => {
  settings = settingsFixture();
  writes = [];
  paths = [];
  remoteJob = null;
  writeResponse = null;
  settingsDelay = null;
  settingsSignal = null;
  unsupported = false;
  upgradeRequired = false;
  settingsDenied = false;
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent: () => false,
  }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input).replace(/^\/api\/v1/, "");
      paths.push(path);
      if (path === "/auth/session") return jsonResponse(sessionFixture());
      if (init?.method !== "GET") {
        writes.push({ path, init: init! });
        if (writeResponse) return writeResponse();
        if (path === "/targets/" + PEER + "/proxy/endpoint-commands") {
          remoteJob = metadataJobFixture();
          return jsonResponse({ job: remoteJob, response: null }, 202);
        }
        if (path === "/targets/" + PEER + "/proxy/endpoint-command/refresh") {
          remoteJob = {
            ...metadataJobFixture(),
            state: "saved",
            metadata_revision: "5",
          };
          settings = {
            ...settings,
            revision: "5",
            listeners: [
              {
                ...settings.listeners[0],
                selection: { mode: "hidden" },
                public_address: null!,
              },
            ],
          };
          return jsonResponse(remoteJob);
        }
        if (path.startsWith("/proxy/endpoint-settings/")) {
          const body = JSON.parse(String(init?.body));
          const selected = body.selection;
          settings = {
            ...settings,
            revision: String(BigInt(settings.revision) + 1n),
            listeners: [
              {
                ...settings.listeners[0],
                selection: selected,
                public_address:
                  selected.mode === "hidden"
                    ? null!
                    : selected.mode === "custom"
                      ? selected.public_address
                      : "startup.example:1080",
              },
            ],
            detached: selected.mode === "inherit" ? [] : settings.detached,
          };
          return jsonResponse(settings);
        }
        throw new Error("unexpected test mutation");
      }
      if (path === "/proxy/policy")
        return jsonResponse(endpointPolicyFixture());
      if (path === "/proxy/owner")
        return jsonResponse({
          controller_node_id: null,
          epoch: "1",
          last_terminal_command: "0",
        });
      if (path === "/node")
        return jsonResponse({
          node_id: LOCAL,
          name: "Local fixture",
          version: "test",
          os: "windows",
          arch: "x86_64",
          capabilities: [],
        });
      if (path === "/targets/" + PEER) return jsonResponse(targetFixture());
      if (path === "/targets/" + PEER + "/command")
        return jsonResponse(remoteJob);
      if (path === "/targets/" + PEER + "/policy")
        return jsonResponse(endpointRemotePolicyFixture());
      if (path.endsWith("/proxy/endpoint-settings")) {
        settingsSignal = init?.signal ?? null;
        if (settingsDenied)
          return jsonResponse({ error: { code: "node_control_denied" } }, 403);
        if (upgradeRequired)
          return jsonResponse(
            { error: { code: "management_upgrade_required" } },
            path.startsWith("/targets/") ? 502 : 503,
          );
        if (unsupported)
          return jsonResponse(
            { error: { code: "remote_endpoint_management_unsupported" } },
            502,
          );
        return settingsDelay ?? jsonResponse(settings);
      }
      if (
        path === "/targets/" + PEER + "/proxy/endpoints" ||
        path === "/proxy/endpoints"
      )
        return jsonResponse({
          node_id: settings.node_id,
          proxy_running: false,
          listeners: settings.listeners.map(
            ({ protocol, bind, public_address }) => ({
              protocol,
              bind,
              public_address,
            }),
          ),
        });
      throw new Error("unexpected test read");
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
function mount(peer: string | null = null) {
  const tree = (selected: string | null) => (
    <ConfigProvider theme={{ token: { motion: false } }}>
      <MemoryRouter>
        <ManagementProvider>
          <EndpointButton peer={selected} nodeId={selected ?? LOCAL} />
        </ManagementProvider>
      </MemoryRouter>
    </ConfigProvider>
  );
  const mounted = render(tree(peer));
  return {
    ...mounted,
    changeTarget: (selected: string | null) => mounted.rerender(tree(selected)),
  };
}
// Match each real button by its rendered caption without repeatedly computing
// the accessibility tree of the whole AntD modal in every lifecycle step.
function button(caption: string): HTMLButtonElement {
  const element = screen.getByText(caption).closest("button");
  if (!element) throw new Error("Expected the caption on a real button");
  return element;
}
function addressCopyButtons(): HTMLButtonElement[] {
  // These are AntD's real accessible copy controls, not a clipboard mock.
  return within(screen.getByRole("dialog")).queryAllByRole("button", {
    name: "Copy",
  }) as HTMLButtonElement[];
}
function expectAddressesNotCopyable() {
  expect(addressCopyButtons().every((copy) => copy.disabled)).toBe(true);
}
async function openEndpoints() {
  await waitFor(() => expect(button("connections.open").disabled).toBe(false));
  fireEvent.click(button("connections.open"));
}
async function edit() {
  await screen.findByText("connections.editAddress");
  fireEvent.click(button("connections.editAddress"));
  await screen.findByLabelText("connections.mode.hidden");
}
async function hide() {
  await edit();
  fireEvent.click(screen.getByLabelText("connections.mode.hidden"));
  fireEvent.click(button("connections.saveDeclaration"));
}
describe("persistent selected-node endpoint modal", () => {
  it("submits an explicit local declaration once and updates only effective links", async () => {
    mount();
    await openEndpoints();
    await hide();
    await screen.findByText("connections.declarationSaved");
    expect(writes).toHaveLength(1);
    expect(writes[0].path).toBe("/proxy/endpoint-settings/" + LISTENER);
    expect(JSON.parse(String(writes[0].init.body))).toEqual({
      expected_revision: "4",
      generation: GENERATION,
      selection: { mode: "hidden" },
    });
    expect(new Headers(writes[0].init.headers).get("X-CSRF-Token")).toBe(
      sessionFixture().csrf_token,
    );
    expect(screen.queryByText("http://startup.example:1080")).toBeNull();
    const dialog = screen.getByRole("dialog");
    expect((dialog as HTMLElement).style.top).toBe("16px");
    expect((dialog as HTMLElement).style.margin).toBe("0px auto");
    expect(dialog.querySelectorAll('input[type="password"]')).toHaveLength(0);
    expect(
      screen
        .getByText("connections.connectivityNotTested")
        .closest(".ant-collapse"),
    ).toBeNull();
    expect(screen.queryByText("connections.metadataOnlyHint")).toBeNull();
    fireEvent.click(screen.getByText("connections.endpointDetails"));
    await screen.findByText("connections.metadataOnlyHint");
    expect(writes).toHaveLength(1);
  });

  it("requires explicit refresh after CAS conflict without rebasing a dirty form", async () => {
    mount();
    await openEndpoints();
    await edit();
    settings = { ...settings, revision: "5" };
    fireEvent.click(screen.getByLabelText("connections.mode.hidden"));
    fireEvent.click(button("connections.saveDeclaration"));
    await screen.findByText("users.conflict");
    expect(writes).toHaveLength(0);
    expect(button("connections.saveDeclaration").disabled).toBe(true);
    fireEvent.click(button("connections.readLatest"));
    await screen.findByText("connections.editAddress");
    // Refresh discards the old draft; a second mutation requires a new edit.
    expect(screen.queryByRole("radio")).toBeNull();
    expect(within(screen.getByRole("dialog")).getByText("5")).toBeTruthy();
    expect(button("connections.editAddress").disabled).toBe(false);
    expect(writes).toHaveLength(0);
  });

  it("keeps a lost save observation-only after a fresh read and same-scope reopen", async () => {
    writeResponse = async () => {
      throw new Error("transport lost");
    };
    mount();
    await openEndpoints();
    await hide();
    await screen.findByText("connections.writeUnknown");
    expect(
      screen.getByText("connections.writeUnknown").closest(".ant-collapse"),
    ).toBeNull();
    fireEvent.click(button("connections.saveDeclaration"));
    fireEvent.click(button("connections.readLatest"));
    await screen.findByText("connections.editAddress");
    expect(button("connections.editAddress").disabled).toBe(true);
    fireEvent.click(button("connections.close"));
    await openEndpoints();
    await screen.findByText("connections.writeUnknown");
    await screen.findByText("connections.editAddress");
    expect(button("connections.editAddress").disabled).toBe(true);
    expectAddressesNotCopyable();
    expect(button("connections.beginNewDeclaration").disabled).toBe(true);
    fireEvent.click(button("connections.readLatest"));
    await waitFor(() => {
      expect(button("connections.beginNewDeclaration").disabled).toBe(false);
      const readLatest = button("connections.readLatest");
      expect(readLatest.disabled).toBe(false);
      expect(readLatest.classList.contains("ant-btn-loading")).toBe(false);
    });
    expect(button("connections.editAddress").disabled).toBe(true);
    let finish!: (response: Response) => void;
    settingsSignal = null;
    settingsDelay = new Promise((resolve) => {
      finish = resolve;
    });
    const readLatest = button("connections.readLatest");
    const beginNew = button("connections.beginNewDeclaration");
    const readStart = paths.length;
    try {
      // Prove the read claimed its slot before this old button can start intent.
      act(() => {
        fireEvent.click(readLatest);
        expect(paths.slice(readStart)).toEqual(["/proxy/policy"]);
        expect(beginNew.disabled).toBe(false);
        fireEvent.click(beginNew);
      });
      await waitFor(() => expect(settingsSignal).not.toBeNull());
      expect(settingsSignal!.aborted).toBe(false);
      expect(screen.getByText("connections.writeUnknown")).toBeTruthy();
      expect(button("connections.beginNewDeclaration").disabled).toBe(true);
      expect(button("connections.editAddress").disabled).toBe(true);
      expectAddressesNotCopyable();
      expect(writes).toHaveLength(1);
    } finally {
      settingsDelay = null;
      await act(async () => {
        finish(jsonResponse(settings));
      });
    }
    await waitFor(() =>
      expect(button("connections.beginNewDeclaration").disabled).toBe(false),
    );
    fireEvent.click(button("connections.beginNewDeclaration"));
    expect(button("connections.editAddress").disabled).toBe(false);
    expect(screen.queryByText("connections.writeUnknown")).toBeNull();
    expect(screen.getByText("connections.newDeclarationNotice")).toBeTruthy();
    expect(addressCopyButtons()).toHaveLength(3);
    expect(writes).toHaveLength(1);
  });

  it("does not invent an unknown write when a pre-dispatch read is closed", async () => {
    let finish!: (response: Response) => void;
    mount();
    await openEndpoints();
    await edit();
    settingsSignal = null;
    settingsDelay = new Promise((resolve) => {
      finish = resolve;
    });
    fireEvent.click(screen.getByLabelText("connections.mode.hidden"));
    fireEvent.click(button("connections.saveDeclaration"));
    await waitFor(() => expect(settingsSignal).not.toBeNull());
    const oldSignal = settingsSignal!;
    expect(writes).toHaveLength(0);
    fireEvent.click(button("connections.close"));
    expect(oldSignal.aborted).toBe(true);
    settingsDelay = null;
    await openEndpoints();
    await screen.findByText("connections.editAddress");
    expect(button("connections.editAddress").disabled).toBe(false);
    expect(screen.queryByText("connections.writeUnknown")).toBeNull();
    expect(addressCopyButtons()).toHaveLength(3);
    await act(async () => {
      finish(jsonResponse(settingsFixture()));
    });
    expect(button("connections.editAddress").disabled).toBe(false);
    expect(screen.queryByText("connections.writeUnknown")).toBeNull();
    expect(writes).toHaveLength(0);
  });

  it("uses one remote ticket, then only the exact metadata receipt refresh", async () => {
    settings = settingsFixture(PEER);
    mount(PEER);
    await openEndpoints();
    await hide();
    await screen.findByText("connections.declarationQueued");
    expect(writes).toHaveLength(1);
    expect(JSON.parse(String(writes[0].init.body))).toEqual({
      expected_target_revision: "3",
      controller_epoch: "2",
      command_id: "8",
      expected_metadata_revision: "4",
      mutation: {
        listener_id: LISTENER,
        generation: GENERATION,
        selection: { mode: "hidden" },
      },
    });
    expect(
      screen
        .getByRole("button", { name: "connections.editAddress" })
        .hasAttribute("disabled"),
    ).toBe(true);
    fireEvent.click(
      screen.getByRole("button", { name: "connections.checkDeclaration" }),
    );
    await screen.findByText("connections.metadataSaved");
    expect(writes.map((item) => item.path)).toEqual([
      "/targets/" + PEER + "/proxy/endpoint-commands",
      "/targets/" + PEER + "/proxy/endpoint-command/refresh",
    ]);
    expect(JSON.parse(String(writes[1].init.body))).toEqual({ job_id: JOB });
    expect(paths).not.toContain("/proxy/endpoint-settings");
  });

  it("blocks old remote URL copies until a fresh confirmed declaration is read", async () => {
    const selection = {
      mode: "custom",
      public_address: "updated.example:1081",
    } as const;
    const readLatest = async () => {
      const commandPath = "/targets/" + PEER + "/command";
      const settingsPath = "/targets/" + PEER + "/proxy/endpoint-settings";
      const beforeCommand = paths.filter((path) => path === commandPath).length;
      const beforeSettings = paths.filter(
        (path) => path === settingsPath,
      ).length;
      let finish!: (response: Response) => void;
      settingsSignal = null;
      settingsDelay = new Promise((resolve) => {
        finish = resolve;
      });
      try {
        await waitFor(() =>
          expect(button("connections.readLatest").disabled).toBe(false),
        );
        fireEvent.click(button("connections.readLatest"));
        // An already-idle button alone does not prove this click started a read.
        // Hold the final response until this observation has its own request slot.
        await waitFor(() => {
          expect(paths.filter((path) => path === commandPath)).toHaveLength(
            beforeCommand + 1,
          );
          expect(paths.filter((path) => path === settingsPath)).toHaveLength(
            beforeSettings + 1,
          );
          expect(settingsSignal).not.toBeNull();
          expect(button("connections.readLatest").disabled).toBe(true);
        });
      } finally {
        settingsDelay = null;
        await act(async () => {
          finish(jsonResponse(settings));
        });
      }
      await waitFor(() =>
        expect(button("connections.readLatest").disabled).toBe(false),
      );
    };
    settings = settingsFixture(PEER);
    mount(PEER);
    await openEndpoints();
    await screen.findByText("http://startup.example:1080");
    expect(addressCopyButtons()).toHaveLength(3);
    await edit();
    fireEvent.click(screen.getByLabelText("connections.mode.custom"));
    const host = await screen.findByRole("textbox", {
      name: "connections.clientHost",
    });
    fireEvent.change(host, {
      target: { value: "updated.example" },
    });
    fireEvent.change(screen.getByLabelText("connections.clientPort"), {
      target: { value: "1081" },
    });
    await screen.findByText(selection.public_address);
    await waitFor(() =>
      expect(button("connections.saveDeclaration").disabled).toBe(false),
    );
    fireEvent.click(button("connections.saveDeclaration"));
    await screen.findByText("connections.declarationQueued");
    expect(writes).toHaveLength(1);
    expect(JSON.parse(String(writes[0].init.body)).mutation.selection).toEqual(
      selection,
    );
    expectAddressesNotCopyable();
    await readLatest();
    expect(button("connections.editAddress").disabled).toBe(true);
    expectAddressesNotCopyable();
    remoteJob = {
      ...metadataJobFixture(),
      state: "saved",
      metadata_revision: "5",
    };
    await readLatest();
    await screen.findByText("connections.metadataSaved");
    expect(screen.getByText("http://startup.example:1080")).toBeTruthy();
    expect(button("connections.editAddress").disabled).toBe(true);
    expectAddressesNotCopyable();
    writeResponse = async () => {
      remoteJob = {
        ...metadataJobFixture(),
        state: "saved",
        metadata_revision: "5",
      };
      settings = {
        ...settings,
        revision: "5",
        listeners: [
          {
            ...settings.listeners[0],
            selection,
            public_address: selection.public_address,
          },
        ],
      };
      return jsonResponse(remoteJob);
    };
    fireEvent.click(button("connections.checkDeclaration"));
    await screen.findByText("http://updated.example:1081");
    expect(screen.queryByText("http://startup.example:1080")).toBeNull();
    expect(addressCopyButtons()).toHaveLength(3);
    expect(writes.map((item) => item.path)).toEqual([
      "/targets/" + PEER + "/proxy/endpoint-commands",
      "/targets/" + PEER + "/proxy/endpoint-command/refresh",
    ]);
    expect(JSON.parse(String(writes[1].init.body))).toEqual({ job_id: JOB });
  });

  it("uses only the same old node's catalog when endpoint management is unsupported", async () => {
    settings = settingsFixture(PEER);
    unsupported = true;
    mount(PEER);
    await openEndpoints();
    await screen.findByText("connections.managementUnsupported");
    expect(
      screen.queryByRole("button", { name: "connections.editAddress" }),
    ).toBeNull();
    expect(paths).toContain("/targets/" + PEER + "/proxy/endpoints");
    expect(paths).not.toContain("/proxy/endpoints");
    fireEvent.click(screen.getByText("connections.endpointDetails"));
    await screen.findByText("connections.endpointHint");
    expect(screen.queryByText("connections.metadataOnlyHint")).toBeNull();
    expect(writes).toHaveLength(0);
  });

  it.each([null, PEER])(
    "keeps the same node's links read-only when its database needs migration (%s)",
    async (peer) => {
      upgradeRequired = true;
      settings = settingsFixture(peer ?? LOCAL);
      mount(peer);
      await openEndpoints();
      await screen.findByText("connections.managementUnsupported");
      expect(
        screen.queryByRole("button", { name: "connections.editAddress" }),
      ).toBeNull();
      expect(paths).toContain(
        peer === null
          ? "/proxy/endpoints"
          : "/targets/" + PEER + "/proxy/endpoints",
      );
      expect(writes).toHaveLength(0);
    },
  );

  it("keeps blocked metadata jobs visible and does not turn denial into a fallback", async () => {
    settings = settingsFixture(PEER);
    remoteJob = { ...metadataJobFixture(), state: "blocked" };
    mount(PEER);
    await openEndpoints();
    await screen.findByText("connections.blockedTicket");
    expect(
      screen.getByText("connections.blockedTicket").closest(".ant-collapse"),
    ).toBeNull();
    expect(screen.getByText(JOB)).toBeTruthy();
    expect(
      screen
        .getByRole("button", { name: "connections.editAddress" })
        .hasAttribute("disabled"),
    ).toBe(true);
    expect(writes).toHaveLength(0);
    settingsDenied = true;
    fireEvent.click(
      screen.getByRole("button", { name: "connections.readLatest" }),
    );
    await screen.findByText("control.denied");
    expect(paths).not.toContain("/targets/" + PEER + "/proxy/endpoints");
    expect(paths).not.toContain("/proxy/endpoints");
  });

  it("labels saved metadata without policy application wording and keeps its real check handler", async () => {
    remoteJob = {
      ...metadataJobFixture(),
      state: "saved",
      metadata_revision: "5",
    };
    render(
      <ConfigProvider theme={{ token: { motion: false } }}>
        <MemoryRouter>
          <ManagementProvider>
            <CommandPanel
              targetId={PEER}
              job={job(remoteJob, PEER)}
              busy={false}
              onChange={vi.fn()}
              onBusy={vi.fn()}
              onRefresh={vi.fn()}
            />
          </ManagementProvider>
        </MemoryRouter>
      </ConfigProvider>,
    );
    expect(screen.getByText("connections.metadataSaved")).toBeTruthy();
    expect(screen.queryByText("control.job.saved")).toBeNull();
    expect(screen.queryByRole("button", { name: "control.retry" })).toBeNull();
    await waitFor(() =>
      expect(
        screen
          .getByRole("button", { name: "connections.checkDeclaration" })
          .hasAttribute("disabled"),
      ).toBe(false),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "connections.checkDeclaration" }),
    );
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0].path).toBe(
      "/targets/" + PEER + "/proxy/endpoint-command/refresh",
    );
    expect(JSON.parse(String(writes[0].init.body))).toEqual({ job_id: JOB });
  });

  it("cancels a read on close and ignores an abort-insensitive late response", async () => {
    let finish!: (response: Response) => void;
    settingsDelay = new Promise((resolve) => {
      finish = resolve;
    });
    mount();
    await openEndpoints();
    await waitFor(() => expect(settingsSignal).not.toBeNull());
    fireEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "connections.close",
      }),
    );
    expect(settingsSignal!.aborted).toBe(true);
    await act(async () => {
      finish(jsonResponse(settingsFixture()));
    });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(writes).toHaveLength(0);
  });

  it("discards an old node's late read when the target changes without remounting auth", async () => {
    let finish!: (response: Response) => void;
    settingsDelay = new Promise((resolve) => {
      finish = resolve;
    });
    const mounted = mount();
    await openEndpoints();
    await waitFor(() => expect(settingsSignal).not.toBeNull());
    const oldSignal = settingsSignal!;
    settingsDelay = null;
    settings = settingsFixture(PEER);
    mounted.changeTarget(PEER);
    await screen.findByRole("button", { name: "connections.editAddress" });
    expect(oldSignal.aborted).toBe(true);
    await act(async () => {
      finish(jsonResponse(settingsFixture()));
    });
    expect(within(screen.getByRole("dialog")).queryByText(LOCAL)).toBeNull();
    expect(within(screen.getByRole("dialog")).getByText(PEER)).toBeTruthy();
    expect(writes).toHaveLength(0);
  });

  it("keeps a closed dispatched write unknown despite a late reply without polluting another node", async () => {
    let finish!: (response: Response) => void;
    writeResponse = () =>
      new Promise((resolve) => {
        finish = resolve;
      });
    const mounted = mount();
    await openEndpoints();
    await hide();
    await waitFor(() => expect(writes).toHaveLength(1));
    fireEvent.click(
      screen.getByRole("button", { name: /connections\.saveDeclaration$/ }),
    );
    const oldSignal = writes[0].init.signal!;
    fireEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "connections.close",
      }),
    );
    expect(oldSignal.aborted).toBe(true);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByText("connections.declarationSaved")).toBeNull();
    expect(writes).toHaveLength(1);
    await openEndpoints();
    await screen.findByText("connections.writeUnknown");
    await screen.findByText("connections.editAddress");
    expect(button("connections.editAddress").disabled).toBe(true);
    expectAddressesNotCopyable();
    expect(button("connections.beginNewDeclaration").disabled).toBe(true);
    // The real client races cancellation, so its caller settles even though
    // this fake fetch deliberately ignores abort and returns much later.
    await act(async () => {
      finish(jsonResponse({ ...settingsFixture(), revision: "5" }));
    });
    expect(screen.queryByText("connections.declarationSaved")).toBeNull();
    expect(button("connections.beginNewDeclaration").disabled).toBe(true);
    expect(button("connections.editAddress").disabled).toBe(true);
    fireEvent.click(button("connections.readLatest"));
    await waitFor(() =>
      expect(button("connections.beginNewDeclaration").disabled).toBe(false),
    );
    expect(button("connections.editAddress").disabled).toBe(true);
    expectAddressesNotCopyable();
    settings = settingsFixture(PEER);
    mounted.changeTarget(PEER);
    await screen.findByText("connections.editAddress");
    await waitFor(() =>
      expect(button("connections.editAddress").disabled).toBe(false),
    );
    expect(screen.queryByText("connections.writeUnknown")).toBeNull();
    expect(addressCopyButtons()).toHaveLength(3);
    expect(writes).toHaveLength(1);
  });

  it("clears a detached override only after a separate confirmation and only with inherit", async () => {
    settings.detached = [
      {
        id: PEER,
        protocol: "http",
        bind: "127.0.0.1:9090",
        selection: { mode: "hidden" },
      },
    ];
    mount();
    await openEndpoints();
    fireEvent.click(await screen.findByText("connections.detached (1)"));
    fireEvent.click(
      await screen.findByRole("button", { name: "connections.clearDetached" }),
    );
    await screen.findByText("connections.clearDetachedHint");
    expect(writes).toHaveLength(0);
    expect(screen.queryByRole("radio")).toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: "connections.clearDetached" }),
    );
    await screen.findByText("connections.declarationSaved");
    expect(writes).toHaveLength(1);
    expect(writes[0].path).toBe("/proxy/endpoint-settings/" + PEER);
    expect(JSON.parse(String(writes[0].init.body))).toEqual({
      expected_revision: "4",
      generation: GENERATION,
      selection: { mode: "inherit" },
    });
  });
});
