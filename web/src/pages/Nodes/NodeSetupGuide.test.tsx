// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://manager.example"}
import { StrictMode, useState } from "react";
import { MemoryRouter } from "react-router-dom";
import { ConfigProvider } from "antd";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import type { NodeView } from "../../api/client";
import type { RemotePolicy, Target } from "../../api/targets";
import { ManagementProvider, useManagement } from "../../auth/context";
import NodeSetupGuide from "./NodeSetupGuide";

// Keep the installed Router and all Guide, Ant Design, form, session and client
// code real. Only translation and Umi's Router re-export are fixture boundaries.
vi.mock("../../hooks/useMessages", () => ({
  useMessages: () => ({
    t: (id: string, values?: Record<string, unknown>) =>
      id === "setup.stepLabel"
        ? `${values?.current}/${values?.total} · ${values?.title}`
        : id,
  }),
}));
vi.mock("@umijs/max", async () => ({
  Link: (await import("react-router-dom")).Link,
}));

const controllerId = "A".repeat(22);
const childId = "Q".repeat(22);
const localNode: NodeView = {
  node_id: controllerId,
  name: "manager",
  version: "fixture",
  os: "linux",
  arch: "x86_64",
  capabilities: ["local_administration"],
};
const target = (): Target => ({
  node_id: childId,
  name: "child",
  origin: "https://child.example:9443",
  server_ip: null,
  active: true,
  retired: false,
  revision: "1",
  observed_epoch: null,
  observed_command: null,
  observed_policy_revision: null,
  rollback_detected: false,
});
const policy = (): RemotePolicy => ({
  controller_node_id: controllerId,
  controller_epoch: "27",
  last_terminal_command: "0",
  saved_revision: "9",
  applied_revision: null,
  durable_applied_revision: null,
  proxy_running: false,
  user_count: 0,
  credential_count: 0,
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

let viewportWidth = 1280;
beforeEach(() => {
  // jsdom does not perform layout or implement matchMedia. These platform-only
  // shims select a component branch, not prove its rendered dimensions. Keep
  // the real Grid, Modal, Steps, Select, Form and their event lifecycles.
  viewportWidth = 1280;
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  vi.stubGlobal("matchMedia", (query: string) => {
    const width = /^\((min|max)-width:\s*(\d+)px\)$/.exec(query);
    return {
      matches: width
        ? width[1] === "min"
          ? viewportWidth >= Number(width[2])
          : viewportWidth <= Number(width[2])
        : false,
      media: query,
      onchange: null,
      addListener() {},
      removeListener() {},
      addEventListener() {},
      removeEventListener() {},
      dispatchEvent() {
        return false;
      },
    };
  });
  const computed = window.getComputedStyle.bind(window);
  vi.spyOn(window, "getComputedStyle").mockImplementation((element) =>
    computed(element),
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function mount(destination: Target | null = target(), available = true) {
  const closed = vi.fn();
  const registered = vi.fn();
  function Host() {
    const { controller, state } = useManagement();
    const [opened, setOpened] = useState<number | null>(null);
    return (
      <>
        <output data-testid="session-phase">{state.phase}</output>
        <button
          disabled={state.phase !== "authenticated" || state.busy}
          onClick={() => setOpened(controller.generation())}
        >
          open-setup
        </button>
        <button onClick={() => void controller.check()}>recheck-session</button>
        {opened !== null &&
          opened === controller.generation() &&
          state.phase === "authenticated" && (
            <NodeSetupGuide
              key={opened}
              node={localNode}
              target={destination}
              controllerAvailable={available}
              register={(value, signal) =>
                state.session
                  ? controller.resource(
                      state.session,
                      (client, csrf, request) =>
                        client.configureTarget(
                          value.node_id,
                          value.origin,
                          value.active,
                          null,
                          csrf,
                          request,
                          value.server_ip,
                        ),
                      signal,
                    )
                  : Promise.resolve(undefined)
              }
              registered={registered}
              close={() => {
                closed();
                setOpened(null);
              }}
            />
          )}
      </>
    );
  }
  const view = render(
    <StrictMode>
      <MemoryRouter>
        <ConfigProvider theme={{ token: { motion: false } }}>
          <ManagementProvider>
            <Host />
          </ManagementProvider>
        </ConfigProvider>
      </MemoryRouter>
    </StrictMode>,
  );
  const open = async () => {
    await waitFor(() =>
      expect(
        (
          screen.getByRole("button", {
            name: "open-setup",
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(false),
    );
    fireEvent.click(screen.getByRole("button", { name: "open-setup" }));
    await screen.findByRole("dialog");
  };
  return { ...view, closed, registered, open };
}

function transport(
  handler?: (path: string, init?: RequestInit) => Promise<Response>,
) {
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    const path = String(input);
    if (path === "/api/v1/auth/session")
      return jsonResponse({
        ...sessionFixture(),
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      });
    if (handler) return handler(path, init);
    if (path === `/api/v1/targets/${childId}`) return jsonResponse(target());
    if (path === `/api/v1/targets/${childId}/policy`)
      return jsonResponse(policy());
    throw new Error("unexpected fixture API route");
  });
  vi.stubGlobal("fetch", fetcher);
  return fetcher;
}

const callsFor = (fetcher: ReturnType<typeof transport>, path: string) =>
  fetcher.mock.calls.filter(([input]) => input === path);

async function openStepOptions() {
  const input = screen.getByRole("combobox", {
    name: "setup.stepNavigation",
  });
  fireEvent.mouseDown(input);
  const dropdown = await waitFor(() => {
    expect(input.getAttribute("aria-expanded")).toBe("true");
    const list = document.getElementById(
      input.getAttribute("aria-controls") ?? "",
    );
    const container = list?.closest<HTMLElement>(".ant-select-dropdown");
    expect(container).not.toBeNull();
    return container!;
  });
  return { input, dropdown };
}

function stepOption(dropdown: HTMLElement, label: string) {
  return within(dropdown).getByText(label, {
    selector: ".ant-select-item-option-content",
  });
}

describe("real node setup component lifecycle", () => {
  it("uses compact instruction navigation without requests and keeps address explanations collapsed by default", async () => {
    viewportWidth = 390;
    const fetcher = transport();
    const view = mount(null);
    await view.open();
    const dialog = screen.getByRole("dialog");
    const controls = within(dialog);
    const initialCalls = fetcher.mock.calls.length;
    const address = controls.getByRole("button", {
      name: "setup.addressDetails",
    });
    expect(address.getAttribute("aria-expanded")).toBe("false");
    expect(controls.queryByText("setup.adminOriginHint")).toBeNull();
    expect(
      controls.getByRole("radio", { name: "setup.newChild" }),
    ).toBeTruthy();
    expect(controls.getByText("setup.progressHint")).toBeTruthy();
    expect(controls.getByText("setup.pkiRequired")).toBeTruthy();
    expect(controls.getByText("setup.offlineAuthority")).toBeTruthy();
    expect(controls.getByText("setup.newOutputs")).toBeTruthy();
    fireEvent.click(address);
    expect(address.getAttribute("aria-expanded")).toBe("true");
    expect(controls.getByText("setup.adminOriginHint")).toBeTruthy();
    expect(controls.getByText(controllerId)).toBeTruthy();
    fireEvent.click(address);
    expect(address.getAttribute("aria-expanded")).toBe("false");

    const { input, dropdown } = await openStepOptions();
    const blocked = stepOption(dropdown, "5/5 · setup.verify");
    expect(
      blocked.closest(".ant-select-item-option")?.getAttribute("aria-disabled"),
    ).toBe("true");
    fireEvent.click(blocked);
    expect(
      controls.getByRole("heading", { name: "setup.prepare" }),
    ).toBeTruthy();
    fireEvent.click(stepOption(dropdown, "2/5 · setup.enroll"));
    await waitFor(() =>
      expect(input.getAttribute("aria-expanded")).toBe("false"),
    );
    const heading = controls.getByRole("heading", { name: "setup.enroll" });
    expect(document.activeElement).toBe(heading);
    expect(controls.queryByText("setup.verified")).toBeNull();
    expect(fetcher.mock.calls.slice(initialCalls)).toEqual([]);
    expect(view.registered).not.toHaveBeenCalled();
  });

  it("disables compact navigation during a save and preserves the saved identity when returning to preparation", async () => {
    viewportWidth = 390;
    const saved = deferred<Response>();
    const fetcher = transport(async (path, init) => {
      if (path === "/api/v1/targets" && init?.method === "POST")
        return saved.promise;
      throw new Error("unexpected fixture API route");
    });
    const view = mount(null);
    await view.open();
    const { dropdown } = await openStepOptions();
    fireEvent.click(stepOption(dropdown, "4/5 · setup.save"));
    fireEvent.change(screen.getByLabelText("control.nodeId"), {
      target: { value: childId },
    });
    fireEvent.change(screen.getByLabelText("control.origin"), {
      target: { value: target().origin },
    });
    fireEvent.click(screen.getByRole("button", { name: "setup.saveAction" }));
    await waitFor(() =>
      expect(callsFor(fetcher, "/api/v1/targets")).toHaveLength(1),
    );
    const navigation = screen.getByRole("combobox", {
      name: "setup.stepNavigation",
    }) as HTMLInputElement;
    expect(navigation.disabled).toBe(true);
    fireEvent.mouseDown(navigation);
    expect(navigation.getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByRole("heading", { name: "setup.save" })).toBeTruthy();
    await act(async () => saved.resolve(jsonResponse(target(), 201)));
    expect(navigation.disabled).toBe(false);
    expect(document.activeElement).toBe(
      screen.getByRole("heading", { name: "setup.verify" }),
    );
    const options = await openStepOptions();
    expect(
      stepOption(options.dropdown, "5/5 · setup.verify")
        .closest(".ant-select-item-option")
        ?.getAttribute("aria-disabled"),
    ).toBe("false");
    fireEvent.click(stepOption(options.dropdown, "1/5 · setup.prepare"));
    const controls = within(screen.getByRole("dialog"));
    expect(
      controls.queryByRole("radio", { name: "setup.newChild" }),
    ).toBeNull();
    expect(controls.getByText("setup.existingLocked")).toBeTruthy();
    expect(controls.queryByText("setup.offlinePrepare")).toBeNull();
    expect(callsFor(fetcher, "/api/v1/targets")).toHaveLength(1);
    expect(callsFor(fetcher, `/api/v1/targets/${childId}/policy`)).toHaveLength(
      0,
    );
    expect(view.registered).toHaveBeenCalledTimes(1);
  });

  it("switches new and existing child instructions without sending requests or manufacturing control proof", async () => {
    const fetcher = transport();
    const view = mount(null);
    await view.open();
    const dialog = screen.getByRole("dialog");
    const controls = within(dialog);
    const initialCalls = fetcher.mock.calls.length;
    expect(
      (
        controls.getByRole("radio", {
          name: "setup.newChild",
        }) as HTMLInputElement
      ).checked,
    ).toBe(true);
    // Text queries avoid recalculating accessible names for the entire expanded
    // command tree in jsdom; the real Collapse controls still handle the clicks.
    for (const button of controls.getAllByText("setup.commands", {
      exact: true,
    })) {
      fireEvent.click(button);
      const commands = button
        .closest(".ant-collapse-item")
        ?.querySelector("pre");
      expect(commands?.getAttribute("role")).toBe("region");
      expect(commands?.getAttribute("aria-label")).toBe("setup.commands");
      expect(commands?.tabIndex).toBe(0);
    }
    expect(dialog.textContent).toContain("vproxy manage setup prepare");
    expect(dialog.textContent).toContain("vproxy manage setup sign");
    expect(dialog.textContent).toContain("vproxy manage setup plan");
    expect(dialog.textContent).toContain("vproxy manage setup check --input");
    expect(dialog.textContent).not.toContain("vproxy manage init");
    fireEvent.click(
      controls.getByRole("radio", { name: "setup.existingChild" }),
    );
    for (const button of controls.getAllByText("setup.commands", {
      exact: true,
    }))
      fireEvent.click(button);
    expect(dialog.textContent).toContain("vproxy manage status --data-dir");
    expect(dialog.textContent).toContain("vproxy manage serve --help");
    expect(dialog.textContent).not.toContain("vproxy manage setup prepare");
    expect(dialog.textContent).not.toContain("vproxy manage setup sign");
    fireEvent.click(controls.getByRole("radio", { name: "setup.newChild" }));
    expect(controls.getByText("setup.offlinePrepare")).toBeTruthy();
    expect(controls.getByText("setup.offlineSign")).toBeTruthy();
    expect(controls.getByText("setup.offlinePlan")).toBeTruthy();
    fireEvent.click(controls.getByRole("button", { name: "setup.next" }));
    expect(
      controls.getByRole("heading", { name: "setup.enroll" }),
    ).toBeTruthy();
    expect(controls.queryByText("setup.verified")).toBeNull();
    expect(fetcher.mock.calls.slice(initialCalls)).toEqual([]);
    expect(view.registered).not.toHaveBeenCalled();
  });

  it("saves a new destination once through the shared real form, then waits for an explicit control read", async () => {
    const saved = deferred<Response>();
    const fetcher = transport(async (path, init) => {
      if (path === "/api/v1/targets" && init?.method === "POST")
        return saved.promise;
      if (path.endsWith("/policy")) return jsonResponse(policy());
      return jsonResponse(target());
    });
    const view = mount(null);
    await view.open();
    const dialog = screen.getByRole("dialog");
    const controls = within(dialog);
    fireEvent.click(controls.getByText("setup.save"));
    fireEvent.change(controls.getByLabelText("control.nodeId"), {
      target: { value: childId },
    });
    fireEvent.change(controls.getByLabelText("control.origin"), {
      target: { value: target().origin },
    });
    const save = controls.getByRole("button", { name: "setup.saveAction" });
    fireEvent.click(save);
    fireEvent.click(save);
    await waitFor(() =>
      expect(callsFor(fetcher, "/api/v1/targets")).toHaveLength(1),
    );
    const close = controls.getByRole("button", {
      name: "setup.close",
    }) as HTMLButtonElement;
    expect(close.disabled).toBe(true);
    fireEvent.click(close);
    expect(view.closed).not.toHaveBeenCalled();
    expect(
      JSON.parse(callsFor(fetcher, "/api/v1/targets")[0][1]?.body as string),
    ).toEqual({
      node_id: childId,
      origin: target().origin,
      active: true,
      server_ip: null,
    });
    await act(async () => {
      saved.resolve(jsonResponse(target(), 201));
    });
    await controls.findByRole("button", { name: "setup.verifyAction" });
    expect(view.registered).toHaveBeenCalledTimes(1);
    expect(callsFor(fetcher, "/api/v1/targets")).toHaveLength(1);
    expect(callsFor(fetcher, `/api/v1/targets/${childId}/policy`)).toHaveLength(
      0,
    );
    expect(controls.queryByText("setup.verified")).toBeNull();
    expect(document.activeElement).toBe(
      controls.getByRole("heading", { name: "setup.verify" }),
    );
    fireEvent.click(controls.getByText("setup.prepare"));
    expect(
      controls.queryByRole("radio", { name: "setup.newChild" }),
    ).toBeNull();
    // Avoid accessible-name scans over expanded command text; click the same
    // labelled, real Collapse controls and check their accessible name locally.
    for (const label of controls.getAllByText("setup.commands", {
      exact: true,
    })) {
      const disclosure = label.closest('[role="button"]');
      expect(disclosure?.getAttribute("role")).toBe("button");
      expect(
        within(disclosure!.parentElement!).getByRole("button", {
          name: "setup.commands",
        }),
      ).toBe(disclosure);
      fireEvent.click(disclosure!);
    }
    expect(dialog.textContent).toContain("vproxy manage status --data-dir");
    expect(dialog.textContent).not.toContain("vproxy manage setup prepare");
    expect(dialog.textContent).not.toContain("vproxy manage init");
    expect(callsFor(fetcher, "/api/v1/targets")).toHaveLength(1);
    expect(callsFor(fetcher, `/api/v1/targets/${childId}/policy`)).toHaveLength(
      0,
    );
    fireEvent.click(controls.getByText("setup.verify"));
    const verify = controls.getByText("setup.verifyAction").closest("button");
    expect(verify?.tagName).toBe("BUTTON");
    expect(
      within(verify!.parentElement!).getByRole("button", {
        name: "setup.verifyAction",
      }),
    ).toBe(verify);
    fireEvent.click(verify!);
    await controls.findByText("setup.verified");
    expect(callsFor(fetcher, `/api/v1/targets/${childId}/policy`)).toHaveLength(
      1,
    );
  });

  it("does not call a node or claim authorization for metadata alone; an explicit verified read may report an API-only child", async () => {
    const fetcher = transport();
    const view = mount();
    await view.open();
    expect(screen.queryByText("setup.verified")).toBeNull();
    expect(callsFor(fetcher, `/api/v1/targets/${childId}/policy`)).toHaveLength(
      0,
    );
    fireEvent.click(screen.getByRole("button", { name: "setup.verifyAction" }));
    await screen.findByText("setup.verified");
    expect(screen.getByText("users.apiOnly")).toBeTruthy();
    expect(
      screen
        .getByRole("link", { name: "control.manageUsers" })
        .getAttribute("href"),
    ).toBe(`/users?target=${childId}`);
    expect(callsFor(fetcher, `/api/v1/targets/${childId}/policy`)).toHaveLength(
      1,
    );
    expect(callsFor(fetcher, `/api/v1/targets/${childId}`)).toHaveLength(2);
    expect(fetcher.mock.calls.every(([, init]) => init?.method === "GET")).toBe(
      true,
    );
  });

  it.each([
    [{ ...target(), active: false }, true],
    [{ ...target(), active: false, retired: true }, true],
    [{ ...target(), rollback_detected: true }, true],
    [target(), false],
  ] as const)(
    "does not permit verification for a disabled destination or missing outbound TLS",
    async (destination, available) => {
      const fetcher = transport();
      const view = mount(destination, available);
      await view.open();
      const button = screen.getByRole("button", {
        name: "setup.verifyAction",
      }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      fireEvent.click(button);
      expect(
        callsFor(fetcher, `/api/v1/targets/${childId}/policy`),
      ).toHaveLength(0);
      expect(screen.queryByText("setup.verified")).toBeNull();
    },
  );

  it("aborts on close and ignores an abort-ignoring late response without issuing the second registry read", async () => {
    const late = deferred<Response>();
    const fetcher = transport(async (path) =>
      path.endsWith("/policy") ? late.promise : jsonResponse(target()),
    );
    const view = mount();
    await view.open();
    fireEvent.click(screen.getByRole("button", { name: "setup.verifyAction" }));
    await waitFor(() =>
      expect(
        callsFor(fetcher, `/api/v1/targets/${childId}/policy`),
      ).toHaveLength(1),
    );
    const signal = callsFor(fetcher, `/api/v1/targets/${childId}/policy`)[0][1]
      ?.signal;
    fireEvent.click(screen.getByRole("button", { name: "setup.close" }));
    expect(signal?.aborted).toBe(true);
    await act(async () => {
      late.resolve(jsonResponse(policy()));
    });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.queryByText("setup.verified")).toBeNull();
    expect(callsFor(fetcher, `/api/v1/targets/${childId}`)).toHaveLength(1);
    expect(view.closed).toHaveBeenCalledTimes(1);
    await view.open();
    expect(screen.queryByText("setup.verified")).toBeNull();
  });

  it("discards an in-flight observation on a real session generation change", async () => {
    const late = deferred<Response>();
    const fetcher = transport(async (path) =>
      path.endsWith("/policy") ? late.promise : jsonResponse(target()),
    );
    const view = mount();
    await view.open();
    fireEvent.click(screen.getByRole("button", { name: "setup.verifyAction" }));
    await waitFor(() =>
      expect(
        callsFor(fetcher, `/api/v1/targets/${childId}/policy`),
      ).toHaveLength(1),
    );
    const signal = callsFor(fetcher, `/api/v1/targets/${childId}/policy`)[0][1]
      ?.signal;
    fireEvent.click(screen.getByRole("button", { name: "recheck-session" }));
    await act(async () => {
      late.resolve(jsonResponse(policy()));
    });
    expect(signal?.aborted).toBe(true);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.queryByText("setup.verified")).toBeNull();
    expect(callsFor(fetcher, `/api/v1/targets/${childId}`)).toHaveLength(1);
  });

  it("shows a local configuration-change reason through the real session sanitizer, not a false success", async () => {
    let reads = 0;
    transport(async (path) =>
      path.endsWith("/policy")
        ? jsonResponse(policy())
        : jsonResponse({ ...target(), revision: ++reads === 1 ? "1" : "2" }),
    );
    const view = mount();
    await view.open();
    fireEvent.click(screen.getByRole("button", { name: "setup.verifyAction" }));
    await screen.findByText("setup.changed");
    expect(screen.queryByText("setup.verified")).toBeNull();
  });

  it("loses the session, rather than displaying control proof, for an authentication-required response", async () => {
    const fetcher = transport(async (path) =>
      path.endsWith("/policy")
        ? jsonResponse({ error: { code: "authentication_required" } }, 403)
        : jsonResponse(target()),
    );
    const view = mount();
    await view.open();
    fireEvent.click(screen.getByRole("button", { name: "setup.verifyAction" }));
    await waitFor(() =>
      expect(screen.getByTestId("session-phase").textContent).toBe("anonymous"),
    );
    expect(screen.queryByText("setup.verified")).toBeNull();
    expect(callsFor(fetcher, `/api/v1/targets/${childId}`)).toHaveLength(1);
  });

  it("blocks another save after an unconfirmed response and recovers only by closing and refreshing the registry", async () => {
    const fetcher = transport(async (path, init) => {
      if (path === "/api/v1/targets" && init?.method === "POST")
        throw new Error("lost response after possible commit");
      throw new Error("unexpected fixture API route");
    });
    const view = mount(null);
    await view.open();
    const dialog = screen.getByRole("dialog");
    const controls = within(dialog);
    fireEvent.click(controls.getByText("setup.save"));
    fireEvent.change(controls.getByLabelText("control.nodeId"), {
      target: { value: childId },
    });
    fireEvent.change(controls.getByLabelText("control.origin"), {
      target: { value: target().origin },
    });
    fireEvent.click(controls.getByRole("button", { name: "setup.saveAction" }));
    await controls.findByText("setup.saveUncertain");
    const button = controls.getByRole("button", {
      name: "setup.saveAction",
    }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(button);
    const form = controls.getByLabelText("control.nodeId").closest("form");
    expect(form).not.toBeNull();
    fireEvent.submit(form!);
    await act(async () => {});
    expect(callsFor(fetcher, "/api/v1/targets")).toHaveLength(1);
    expect(callsFor(fetcher, `/api/v1/targets/${childId}/policy`)).toHaveLength(
      0,
    );
    fireEvent.click(controls.getByText("setup.prepare"));
    expect(
      controls.queryByRole("radio", { name: "setup.newChild" }),
    ).toBeNull();
    for (const label of controls.getAllByText("setup.commands", {
      exact: true,
    })) {
      const disclosure = label.closest('[role="button"]');
      expect(disclosure?.getAttribute("role")).toBe("button");
      expect(
        within(disclosure!.parentElement!).getByRole("button", {
          name: "setup.commands",
        }),
      ).toBe(disclosure);
      fireEvent.click(disclosure!);
    }
    expect(dialog.textContent).toContain("vproxy manage status --data-dir");
    expect(dialog.textContent).not.toContain("vproxy manage setup prepare");
    fireEvent.click(controls.getByText("setup.save"));
    const stillBlocked = controls
      .getByText("setup.saveAction")
      .closest("button");
    expect(stillBlocked?.tagName).toBe("BUTTON");
    expect(stillBlocked).not.toBeNull();
    expect(
      within(stillBlocked!.parentElement!).getByRole("button", {
        name: "setup.saveAction",
      }),
    ).toBe(stillBlocked);
    expect(stillBlocked!.disabled).toBe(true);
    fireEvent.click(stillBlocked!);
    fireEvent.submit(
      controls.getByLabelText("control.nodeId").closest("form")!,
    );
    await act(async () => {});
    expect(callsFor(fetcher, "/api/v1/targets")).toHaveLength(1);
    const recover = controls
      .getByText("setup.recoverRegistry")
      .closest("button");
    expect(recover?.tagName).toBe("BUTTON");
    expect(
      within(recover!.parentElement!).getByRole("button", {
        name: "setup.recoverRegistry",
      }),
    ).toBe(recover);
    fireEvent.click(recover!);
    await waitFor(() => expect(dialog.isConnected).toBe(false));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(view.registered).toHaveBeenCalledTimes(1);
    expect(view.closed).toHaveBeenCalledTimes(1);
  });
});
