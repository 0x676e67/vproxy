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
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ManagementProvider, useManagement } from "../../auth/context";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import {
  capabilityFixture,
  NODE,
  POOL,
  USER,
} from "../../api/presets.fixtures";
import type { ProxyCredential, ProxyUser } from "../../api/proxy";
import type { RoutePermission } from "../../api/routing";
import ConnectionModal, { DIAGNOSTIC_PREVIEW_MS } from "./ConnectionModal";

vi.mock("@umijs/max", async () => ({
  Link: (await import("react-router-dom")).Link,
}));
vi.mock("../../hooks/useMessages", () => ({
  useMessages: () => ({ t: (key: string) => key, intl: { locale: "en-US" } }),
}));

const secret = "A".repeat(43);
const outside = "Q".repeat(22);
const user: ProxyUser = {
  id: USER,
  name: "Connection fixture",
  active: true,
  deleted: false,
  protocols: ["http", "socks5", "masque"],
  concurrent_limit: 8,
  revision: "7",
};
const credential: ProxyCredential = {
  id: POOL,
  user_id: USER,
  login: `vp2_${"ab".repeat(16)}`,
  syntax_version: 2,
  active: true,
  revoked: false,
  verifier_revision: "7",
};
let permission: RoutePermission;
let revision: string;
let reads: string[];
let endpointDelay: Promise<Response> | null;
let endpointSignal: AbortSignal | null;
let passwordReply: (() => Promise<Response>) | null;
let passwordSignal: AbortSignal | null;
let remoteOwner: string | null;
let proxyRunning: boolean;
let publicAddress: string;
let writes: ReturnType<
  typeof vi.fn<(path: string, init?: RequestInit) => void>
>;
let passwordReads: typeof writes;
let clipboard: ReturnType<typeof vi.fn<(value: string) => Promise<void>>>;
let createObjectUrl: ReturnType<typeof vi.fn<(value: Blob) => string>>;
let revokeObjectUrl: ReturnType<typeof vi.fn<(value: string) => void>>;
let startDownload: ReturnType<typeof vi.fn<() => void>>;
let downloadRequests: { href: string; filename: string; connected: boolean }[];
const originalCreateObjectUrl = Object.getOwnPropertyDescriptor(
  URL,
  "createObjectURL",
);
const originalRevokeObjectUrl = Object.getOwnPropertyDescriptor(
  URL,
  "revokeObjectURL",
);

beforeEach(() => {
  revision = "7";
  permission = {
    user_id: USER,
    legacy_allowed: true,
    exits: [NODE, outside],
    pools: [POOL],
  };
  reads = [];
  endpointDelay = null;
  endpointSignal = null;
  passwordReply = null;
  passwordSignal = null;
  remoteOwner = NODE;
  proxyRunning = false;
  publicAddress = "proxy.example:8080";
  writes = vi.fn();
  passwordReads = vi.fn();
  clipboard = vi.fn(async () => {});
  let sequence = 0;
  createObjectUrl = vi.fn(() => `blob:https://localhost/export-${++sequence}`);
  revokeObjectUrl = vi.fn();
  startDownload = vi.fn();
  downloadRequests = [];
  Object.defineProperty(URL, "createObjectURL", {
    configurable: true,
    value: createObjectUrl,
  });
  Object.defineProperty(URL, "revokeObjectURL", {
    configurable: true,
    value: revokeObjectUrl,
  });
  // Only the platform's download handoff is observed. Blob contents and all
  // form, session, endpoint and credential lifecycles remain real.
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    startDownload();
    downloadRequests.push({
      href: this.href,
      filename: this.download,
      connected: this.isConnected,
    });
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      let path = String(input).replace(/^\/api\/v1/, "");
      reads.push(path);
      const remote = path.startsWith(`/targets/${outside}`);
      if (init?.method !== "GET") {
        if (
          init?.method === "POST" &&
          [
            `/proxy/credentials/${POOL}/secret`,
            `/targets/${outside}/proxy/credentials/${POOL}/secret`,
          ].includes(path)
        ) {
          passwordReads(path, init);
          passwordSignal = init.signal ?? null;
          return passwordReply
            ? passwordReply()
            : jsonResponse(
                { error: { code: "credential_secret_not_saved" } },
                409,
              );
        }
        writes(path, init);
        throw new Error("unexpected mutation");
      }
      if (remote) {
        path = path.slice(`/targets/${outside}`.length);
        if (path === "/command") return jsonResponse(null);
        if (path === "")
          return jsonResponse({
            node_id: outside,
            name: "Remote fixture",
            origin: "https://remote.example",
            active: true,
            retired: false,
            revision: "3",
            observed_epoch: "2",
            observed_command: "0",
            observed_policy_revision: revision,
            rollback_detected: false,
          });
        if (path === "/policy")
          return jsonResponse({
            saved_revision: revision,
            applied_revision: null,
            durable_applied_revision: revision,
            proxy_running: false,
            user_count: 1,
            credential_count: 1,
            controller_node_id: remoteOwner,
            controller_epoch: "2",
            last_terminal_command: "0",
          });
      }
      if (path === "/auth/session") return jsonResponse(sessionFixture());
      if (path === "/node")
        return jsonResponse({
          node_id: NODE,
          name: "Local node",
          version: "test",
          os: "linux",
          arch: "x86_64",
          capabilities: [],
        });
      if (path === "/proxy/policy")
        return jsonResponse({
          saved_revision: revision,
          applied_revision: proxyRunning ? revision : null,
          durable_applied_revision: revision,
          proxy_running: proxyRunning,
          user_count: 1,
          credential_count: 1,
        });
      if (path === "/proxy/owner")
        return jsonResponse({
          controller_node_id: null,
          epoch: "1",
          last_terminal_command: "0",
        });
      if (path === "/proxy/presets")
        return jsonResponse({
          ...capabilityFixture(),
          node_id: remote ? outside : NODE,
        });
      if (path === `/proxy/users/${USER}/presets`)
        return jsonResponse({
          revision,
          presets: {
            user_id: USER,
            allowed_presets: ["windows", "linux"],
            default_preset: null,
          },
        });
      if (path === `/proxy/users/${USER}/routing`)
        return jsonResponse({ revision, permission });
      if (path === `/proxy/pools/${POOL}/presets`)
        return jsonResponse({
          revision,
          preset: { pool_id: POOL, default_preset: null },
        });
      if (path === "/proxy/endpoints") {
        endpointSignal = init?.signal ?? null;
        return (
          endpointDelay ??
          jsonResponse({
            node_id: remote ? outside : NODE,
            proxy_running: proxyRunning,
            listeners: [
              {
                protocol: "auto",
                bind: "0.0.0.0:8080",
                public_address: publicAddress,
              },
            ],
          })
        );
      }
      if (path === "/proxy/addresses?limit=50")
        return jsonResponse({
          revision,
          items: [
            {
              id: NODE,
              name: "Named exit",
              ip: "192.0.2.1",
              prefix_id: null,
              state: "draining",
              revision,
            },
          ],
          next_cursor: NODE,
        });
      if (path === "/proxy/pools?limit=50")
        return jsonResponse({
          revision,
          items: [
            {
              id: POOL,
              name: "Named pool",
              family: "v6",
              state: "active",
              member_count: 1,
              revision,
            },
          ],
          next_cursor: POOL,
        });
      throw new Error(`unhandled fixture path: ${path}`);
    }),
  );
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: clipboard },
  });
  // Browser capability scaffolding only; jsdom does not establish layout or
  // pixel correctness. All React, Form, Select and Modal lifecycles are real.
  vi.stubGlobal(
    "matchMedia",
    vi.fn((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener() {},
      removeListener() {},
      addEventListener() {},
      removeEventListener() {},
      dispatchEvent: () => false,
    })),
  );
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  for (const [name, descriptor] of [
    ["createObjectURL", originalCreateObjectUrl],
    ["revokeObjectURL", originalRevokeObjectUrl],
  ] as const) {
    if (descriptor) Object.defineProperty(URL, name, descriptor);
    else Reflect.deleteProperty(URL, name);
  }
  vi.unstubAllGlobals();
});

function mount(
  initialSecret?: string,
  initialPeer: string | null = null,
  inline = false,
) {
  const close = vi.fn();
  const onBusy = vi.fn();
  let props: {
    user?: ProxyUser;
    credential?: ProxyCredential;
    readBlocked?: boolean;
    peer?: string | null;
  } = {};
  let recheck = async () => {};
  function ObserveSession() {
    const { controller } = useManagement();
    recheck = () => controller.check();
    return null;
  }
  const content = () => (
    <MemoryRouter>
      <ManagementProvider>
        <ObserveSession />
        <ConnectionModal
          inline={inline}
          user={props.user ?? user}
          credential={props.credential ?? credential}
          peer={props.peer === undefined ? initialPeer : props.peer}
          initialSecret={initialSecret}
          close={close}
          onBusy={onBusy}
          readBlocked={props.readBlocked}
        />
      </ManagementProvider>
    </MemoryRouter>
  );
  const rendered = render(content());
  return {
    ...rendered,
    close,
    onBusy,
    recheck: () => recheck(),
    update: (changed: typeof props) => {
      props = { ...props, ...changed };
      rendered.rerender(content());
    },
  };
}
function fileText(file: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

describe("saved password connection workspace", () => {
  it("embeds a ready connection without creating a second dialog or copying before a click", async () => {
    const mounted = mount(secret, null, true);
    await ready();
    expect(screen.queryByRole("dialog")).toBeNull();
    const workspace = screen.getByRole("region", {
      name: "connections.preview",
    });
    const focusRegion = workspace.closest(".connection-workspace");
    expect(document.activeElement).toBe(focusRegion);
    expect(
      within(workspace).getByText(
        `http://${credential.login}:${secret}@proxy.example:8080`,
      ),
    ).toBeTruthy();
    expect(
      workspace.querySelector('pre[aria-label="curl"]')!.textContent,
    ).toContain(`${credential.login}:${secret}`);
    expect(clipboard).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole("button", { name: "connections.copyPassword" }),
    );
    expect(clipboard).toHaveBeenCalledExactlyOnceWith(secret);
    const copyCode = namedButton("connections.copyExample");
    const code = workspace.querySelector('pre[aria-label="curl"]')!;
    expect(
      copyCode.compareDocumentPosition(code) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).not.toBe(0);
    fireEvent.click(copyCode);
    expect(clipboard.mock.calls[1][0]).toContain(
      `--proxy-user "${credential.login}:${secret}"`,
    );
    await act(async () => {
      const recheck = mounted.recheck();
      fireEvent.click(copyCode);
      fireEvent.click(
        screen.getByRole("button", { name: "connections.copyPassword" }),
      );
      await recheck;
    });
    expect(clipboard).toHaveBeenCalledTimes(2);
    expectOnlyNonSecretPreferences();
    expect(writes).not.toHaveBeenCalled();
  });
  it("reads a controlled node on opening, using its current registration and epoch", async () => {
    passwordReply = async () =>
      jsonResponse({
        credential_id: POOL,
        user_id: USER,
        verifier_revision: "7",
        secret,
      });
    mount(undefined, outside);
    await ready();
    await waitFor(() =>
      expect(
        (screen.getByLabelText("users.secret") as HTMLInputElement).value,
      ).toBe(secret),
    );
    expect(passwordReads).toHaveBeenCalledTimes(1);
    expect(passwordReads.mock.calls[0][0]).toBe(
      `/targets/${outside}/proxy/credentials/${POOL}/secret`,
    );
    expect(JSON.parse(passwordReads.mock.calls[0][1]!.body as string)).toEqual({
      expected_node_id: outside,
      expected_target_revision: "3",
      user_id: USER,
      controller_epoch: "2",
      verifier_revision: "7",
    });
    expect(clipboard).not.toHaveBeenCalled();
    expectOnlyNonSecretPreferences();
    expect(sessionStorage.length).toBe(0);
  });
  it("does not request a remote password after that target changes its owner", async () => {
    remoteOwner = null;
    mount(undefined, outside);
    await ready();
    fireEvent.click(namedButton("users.readPassword"));
    await screen.findByText("control.denied");
    expect(passwordReads).not.toHaveBeenCalled();
    expect(
      (screen.getByLabelText("users.secret") as HTMLInputElement).value,
    ).toBe("");
  });
  it("cancels and discards a remote password when the selected node changes", async () => {
    let release!: (response: Response) => void;
    passwordReply = () =>
      new Promise((resolve) => {
        release = resolve;
      });
    const mounted = mount(undefined, outside);
    await waitFor(() => expect(passwordSignal).not.toBeNull());
    mounted.update({ peer: null, readBlocked: true });
    expect(passwordSignal!.aborted).toBe(true);
    await act(async () =>
      release(
        jsonResponse({
          credential_id: POOL,
          user_id: USER,
          verifier_revision: "7",
          secret,
        }),
      ),
    );
    await ready();
    expect(
      (screen.getByLabelText("users.secret") as HTMLInputElement).value,
    ).toBe("");
    expect(passwordReads).toHaveBeenCalledTimes(1);
    expect(clipboard).not.toHaveBeenCalled();
  });
  it("withdraws the password when the user changes before credential metadata catches up", async () => {
    const mounted = mount(secret);
    await ready();
    mounted.update({ user: { ...user, id: NODE } });
    expect(
      (screen.getByLabelText("users.secret") as HTMLInputElement).value,
    ).toBe("");
    expect(
      (namedButton("users.readPassword") as HTMLButtonElement).disabled,
    ).toBe(true);
    fireEvent.click(namedButton("users.readPassword"));
    expect(writes).not.toHaveBeenCalled();
    mounted.unmount();
  });
  it("shows the saved password as read-only text without persisting or copying it", async () => {
    passwordReply = async () =>
      jsonResponse({
        credential_id: POOL,
        user_id: USER,
        verifier_revision: "7",
        secret,
      });
    const mounted = mount();
    await ready();
    await waitFor(() =>
      expect(
        (screen.getByLabelText("users.secret") as HTMLInputElement).value,
      ).toBe(secret),
    );
    expect(
      (screen.getByLabelText("users.secret") as HTMLInputElement).type,
    ).toBe("text");
    expect(
      (screen.getByLabelText("users.secret") as HTMLInputElement).readOnly,
    ).toBe(true);
    expect(passwordReads).toHaveBeenCalledTimes(1);
    expect(JSON.parse(passwordReads.mock.calls[0][1]!.body as string)).toEqual({
      expected_node_id: NODE,
      controller_epoch: "1",
      verifier_revision: "7",
    });
    expect(clipboard).not.toHaveBeenCalled();
    expectOnlyNonSecretPreferences();
    expect(sessionStorage.length).toBe(0);
    fireEvent.click(namedButton("connections.close"));
    expect(mounted.close).toHaveBeenCalledTimes(1);
    await waitFor(() =>
      expect(
        (screen.getByLabelText("users.secret") as HTMLInputElement).value,
      ).toBe(""),
    );
  });
  it("explains a legacy missing copy without rotating or retrying", async () => {
    passwordReply = async () =>
      jsonResponse({ error: { code: "credential_secret_not_saved" } }, 409);
    mount();
    await ready();
    await screen.findByText("users.passwordNotSaved");
    expect(
      (screen.getByLabelText("users.secret") as HTMLInputElement).value,
    ).toBe("");
    expect(passwordReads).toHaveBeenCalledTimes(1);
    expect(passwordReads.mock.calls[0][0]).toBe(
      `/proxy/credentials/${POOL}/secret`,
    );
    expect(clipboard).not.toHaveBeenCalled();
  });
  it("cancels and discards a late password when the credential generation changes", async () => {
    let release!: (response: Response) => void;
    passwordReply = () =>
      new Promise((resolve) => {
        release = resolve;
      });
    const mounted = mount();
    await waitFor(() => expect(passwordSignal).not.toBeNull());
    mounted.update({
      credential: { ...credential, verifier_revision: "8" },
      readBlocked: true,
    });
    expect(passwordSignal!.aborted).toBe(true);
    await act(async () => {
      release(
        jsonResponse({
          credential_id: POOL,
          user_id: USER,
          verifier_revision: "7",
          secret,
        }),
      );
    });
    await ready();
    expect(
      (screen.getByLabelText("users.secret") as HTMLInputElement).value,
    ).toBe("");
    expect(passwordReads).toHaveBeenCalledTimes(1);
    expect(clipboard).not.toHaveBeenCalled();
    expect(mounted.onBusy).toHaveBeenLastCalledWith(false);
  });
});
// Keep the role, accessible-name and visibility checks while limiting their
// CSS work to the caption's parent rather than every button in the real form.
function namedButton(name: string | RegExp) {
  const matches = new Set<HTMLElement>();
  for (const caption of screen.queryAllByText(name, { exact: true })) {
    const control = caption.closest('button, [role="button"]');
    const parent = control?.parentElement;
    if (
      control instanceof HTMLElement &&
      parent &&
      within(parent).queryAllByRole("button", { name }).includes(control)
    )
      matches.add(control);
  }
  const [control] = matches;
  if (matches.size !== 1 || !control)
    throw new Error("Expected one accessible fixture button");
  return control;
}
async function ready() {
  await screen.findByText("connections.notTested");
  await waitFor(() =>
    expect(
      namedButton(/presets\.generate$/).hasAttribute("disabled"),
      JSON.stringify({
        recentReads: reads.slice(-16),
        alerts: [...document.querySelectorAll('[role="alert"]')].map(
          (element) => element.textContent,
        ),
        refreshDisabled: namedButton("users.refresh").hasAttribute("disabled"),
      }),
    ).toBe(false),
  );
}
function expectOnlyNonSecretPreferences() {
  expect(localStorage.length).toBeLessThanOrEqual(1);
  for (let index = 0; index < localStorage.length; index++) {
    const key = localStorage.key(index)!;
    expect(key).toMatch(/^vproxy\.connection\.v1\./);
    const raw = localStorage.getItem(key)!;
    expect(Object.keys(JSON.parse(raw)).sort()).toEqual([
      "endpoint",
      "host",
      "port",
      "protocol",
    ]);
    expect(raw).not.toContain(secret);
    expect(raw).not.toContain(credential.login);
    expect(raw).not.toContain(sessionFixture().csrf_token);
  }
}
async function select(label: string, option: string) {
  const input = await screen.findByRole("combobox", {
    name: new RegExp(`^${label.replace(/\./g, "\\.")}`),
    hidden: true,
  });
  fireEvent.mouseDown(input);
  const dropdown = await waitFor(() => {
    expect(input.getAttribute("aria-expanded")).toBe("true");
    const list = document.getElementById(
      input.getAttribute("aria-controls") ?? "",
    );
    const value = list?.closest<HTMLElement>(".ant-select-dropdown");
    expect(value).not.toBeNull();
    return value!;
  });
  fireEvent.click(
    within(dropdown).getByText(option, {
      selector: ".ant-select-item-option-content",
    }),
  );
  await waitFor(() => {
    if (input.isConnected)
      expect(input.getAttribute("aria-expanded")).toBe("false");
  });
}

// Several full AntD interactions take >5s in jsdom's style/role traversal.
// This suite's budget does not change request timeouts or other tests.
describe(
  "connection form production component lifecycle",
  { timeout: 15_000 },
  () => {
    it("leaves a stopped local connection form for service setup without sending its password", async () => {
      const mounted = mount();
      await ready();
      fireEvent.change(screen.getByLabelText("users.secret"), {
        target: { value: secret },
      });
      const action = screen.getByRole("link", {
        name: "connections.openService",
      });
      expect(action.getAttribute("href")).toBe("/service");
      fireEvent.click(action);
      expect(mounted.close).toHaveBeenCalledTimes(1);
      expect(
        (screen.getByLabelText("users.secret") as HTMLInputElement).value,
      ).toBe("");
      expectOnlyNonSecretPreferences();
      expect(writes).not.toHaveBeenCalled();
      expect(clipboard).not.toHaveBeenCalled();
      expect(startDownload).not.toHaveBeenCalled();
    });

    it.each(["remote", "one-time", "running"] as const)(
      "does not offer local service navigation for a %s connection form",
      async (mode) => {
        proxyRunning = mode === "running";
        mount(
          mode === "one-time" ? secret : undefined,
          mode === "remote" ? outside : null,
        );
        await ready();
        expect(
          screen.queryByRole("link", { name: "connections.openService" }),
        ).toBeNull();
        expect(writes).not.toHaveBeenCalled();
      },
    );

    it("submits the body form from the fixed footer and keeps close/credential guards", async () => {
      const mounted = mount(secret);
      await ready();
      const generate = namedButton(/presets\.generate$/) as HTMLButtonElement;
      const body = document.querySelector(".connection-modal-body")!;
      const footer = document.querySelector<HTMLElement>(".ant-modal-footer")!;
      expect(generate.form).not.toBeNull();
      expect(body.contains(generate.form)).toBe(true);
      expect(body.contains(generate)).toBe(false);
      expect(footer.contains(generate)).toBe(true);
      expect(generate.form!.id).toBe(generate.getAttribute("form"));
      fireEvent.click(generate);
      await waitFor(() => namedButton("connections.copyAuthenticatedUrl"));
      expect(writes).not.toHaveBeenCalled();
      fireEvent.click(
        within(footer).getByRole("button", { name: "users.secretClose" }),
      );
      expect(mounted.close).toHaveBeenCalledTimes(1);
      expect(
        (screen.getByLabelText("users.secret") as HTMLInputElement).value,
      ).toBe("");
      mounted.update({ credential: { ...credential, revoked: true } });
      expect(generate.disabled).toBe(true);
      expect(clipboard).not.toHaveBeenCalled();
    });

    it.each(["http", "https", "socks5"] as const)(
      "downloads a non-secret %s CONNECT diagnostic profile without needing a password or performing a test",
      async (protocol) => {
        mount();
        await ready();
        if (protocol !== "http") {
          await select(
            "connections.selectEndpoint",
            `${protocol}://proxy.example:8080`,
          );
          if (protocol === "socks5")
            await select("presets.operation", "presets.socks5_connect");
        }
        fireEvent.click(namedButton(/presets\.generate$/));
        fireEvent.click(
          await waitFor(() => namedButton(/connections.diagnostic$/)),
        );
        const button = await waitFor(() =>
          namedButton("connections.downloadDiagnostic"),
        );
        expect(
          (
            namedButton(
              "connections.downloadAuthenticatedUrl",
            ) as HTMLButtonElement
          ).disabled,
        ).toBe(true);
        expect(button.hasAttribute("disabled")).toBe(false);
        expect(createObjectUrl).not.toHaveBeenCalled();
        const before = reads.slice();
        fireEvent.click(button);
        expect(createObjectUrl).toHaveBeenCalledTimes(1);
        const file = createObjectUrl.mock.calls[0][0];
        expect(file.type).toBe("application/json;charset=utf-8");
        expect(JSON.parse(await fileText(file))).toEqual({
          format_version: 1,
          protocol,
          host: "proxy.example",
          port: 8080,
          username: credential.login,
          operation: "connect",
        });
        expect(downloadRequests[0]).toMatchObject({
          filename: "vproxy-connection-profile.json",
          connected: true,
        });
        expect(
          screen.getByText("connections.diagnosticRequested"),
        ).toBeTruthy();
        expect(screen.getByText("connections.diagnosticMetadata")).toBeTruthy();
        const command = screen.getByLabelText(
          "connections.diagnosticCommand",
        ).textContent;
        expect(command).toContain(
          'vproxy manage test-connection --profile "./vproxy-connection-profile.json"',
        );
        expect(command?.includes("--allow-plaintext")).toBe(
          protocol !== "https",
        );
        expect(command).not.toContain(credential.login);
        expect(reads).toEqual(before);
        expect(writes).not.toHaveBeenCalled();
        expect(clipboard).not.toHaveBeenCalled();
        expectOnlyNonSecretPreferences();
        expect(sessionStorage.length).toBe(0);
        expect(document.querySelector("a[download]")).toBeNull();
      },
    );
    it("rejects stale diagnostic export after credential scope, parent admission or an unrendered session generation change", async () => {
      const mounted = mount(secret);
      const openDiagnostic = async () => {
        await ready();
        fireEvent.click(namedButton(/presets\.generate$/));
        fireEvent.click(
          await waitFor(() => namedButton(/connections.diagnostic$/)),
        );
        return waitFor(() => namedButton("connections.downloadDiagnostic"));
      };
      const button = await openDiagnostic();
      mounted.update({ credential: { ...credential, id: outside } });
      // A new credential invalidates the whole observation and removes the old
      // preview. A detached DOM node cannot reflect subsequent disabled props.
      expect(button.isConnected).toBe(false);
      expect(
        screen.queryByRole("button", {
          name: "connections.downloadDiagnostic",
        }),
      ).toBeNull();
      fireEvent.click(button);
      expect(createObjectUrl).not.toHaveBeenCalled();
      mounted.update({ credential });
      const blocked = await openDiagnostic();
      mounted.update({ readBlocked: true });
      expect(blocked.isConnected).toBe(true);
      expect(blocked.hasAttribute("disabled")).toBe(true);
      fireEvent.click(blocked);
      expect(createObjectUrl).not.toHaveBeenCalled();
      mounted.update({ readBlocked: false });
      const current = await openDiagnostic();
      expect(current.hasAttribute("disabled")).toBe(false);
      await act(async () => {
        const checked = mounted.recheck();
        fireEvent.click(current);
        await checked;
      });
      expect(createObjectUrl).not.toHaveBeenCalled();
      expect(writes).not.toHaveBeenCalled();
    });
    it("expires only the diagnostic preview using a monotonic deadline without reading again", async () => {
      mount(secret);
      await ready();
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
      let monotonic = 1000;
      vi.spyOn(performance, "now").mockImplementation(() => monotonic);
      await act(async () => {
        fireEvent.click(namedButton(/presets\.generate$/));
        await vi.advanceTimersByTimeAsync(0);
      });
      await act(async () => {
        fireEvent.click(namedButton(/connections.diagnostic$/));
        await vi.advanceTimersByTimeAsync(0);
      });
      const button = namedButton("connections.downloadDiagnostic");
      expect(button.hasAttribute("disabled")).toBe(false);
      const before = reads.slice();
      monotonic += DIAGNOSTIC_PREVIEW_MS + 1;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(DIAGNOSTIC_PREVIEW_MS + 1);
      });
      expect(button.hasAttribute("disabled")).toBe(true);
      expect(screen.getByText("connections.diagnosticExpired")).toBeTruthy();
      fireEvent.click(button);
      expect(createObjectUrl).not.toHaveBeenCalled();
      expect(reads).toEqual(before);
      expect(
        (
          namedButton(
            "connections.downloadAuthenticatedUrl",
          ) as HTMLButtonElement
        ).disabled,
      ).toBe(false);
    });
    it("offers no diagnostic download for SOCKS5 UDP even when a preview exists", async () => {
      mount();
      await ready();
      await select("connections.selectEndpoint", "socks5://proxy.example:8080");
      await select("presets.operation", "presets.socks5_udp");
      fireEvent.click(namedButton(/presets\.generate$/));
      fireEvent.click(
        await waitFor(() => namedButton(/connections.diagnostic$/)),
      );
      await screen.findByText("connections.diagnosticUnsupported");
      expect(
        screen.queryByRole("button", {
          name: "connections.downloadDiagnostic",
        }),
      ).toBeNull();
      expect(createObjectUrl).not.toHaveBeenCalled();
    });
    it("downloads one explicit credential URL without clipboard, API writes or a persistent secret link", async () => {
      mount(secret);
      await ready();
      expect(createObjectUrl).not.toHaveBeenCalled();
      fireEvent.click(namedButton(/presets\.generate$/));
      const download = await waitFor(() =>
        namedButton("connections.downloadAuthenticatedUrl"),
      );
      expect(screen.getByText("connections.downloadWarning")).toBeTruthy();
      expect(createObjectUrl).not.toHaveBeenCalled();
      const before = reads.slice();
      fireEvent.click(download);
      expect(createObjectUrl).toHaveBeenCalledTimes(1);
      const file = createObjectUrl.mock.calls[0][0];
      expect(file.type).toBe("text/plain;charset=utf-8");
      expect(await fileText(file)).toBe(
        `http://${credential.login}:${secret}@proxy.example:8080\n`,
      );
      expect(downloadRequests).toEqual([
        {
          href: "blob:https://localhost/export-1",
          filename: "vproxy-proxy-url.txt",
          connected: true,
        },
      ]);
      expect(document.querySelector("a[download]")).toBeNull();
      expect(document.body.textContent).toContain(secret);
      expect(screen.getByText("connections.downloadRequested")).toBeTruthy();
      expect(screen.queryByText("connections.copied")).toBeNull();
      expect(clipboard).not.toHaveBeenCalled();
      expect(writes).not.toHaveBeenCalled();
      expect(reads).toEqual(before);
      expectOnlyNonSecretPreferences();
      expect(sessionStorage.length).toBe(0);
      expect(location.href).not.toContain(secret);
      expect(revokeObjectUrl).not.toHaveBeenCalled();
      await waitFor(
        () =>
          expect(revokeObjectUrl).toHaveBeenCalledWith(
            "blob:https://localhost/export-1",
          ),
        { timeout: 1_500 },
      );
    });

    it("blocks both exports for invalid credential state, parent reads and an unrendered session generation change", async () => {
      const mounted = mount(secret);
      await ready();
      fireEvent.click(namedButton(/presets\.generate$/));
      const copy = await waitFor(() =>
        namedButton("connections.copyAuthenticatedUrl"),
      );
      const download = namedButton("connections.downloadAuthenticatedUrl");
      const before = reads.slice();
      for (const changed of [
        { user: { ...user, active: false }, credential },
        { user, credential: { ...credential, revoked: true } },
        { user, credential: { ...credential, user_id: outside } },
        { user, credential, readBlocked: true },
      ]) {
        mounted.update(changed);
        expect((copy as HTMLButtonElement).disabled).toBe(true);
        expect((download as HTMLButtonElement).disabled).toBe(true);
        fireEvent.click(copy);
        fireEvent.click(download);
      }
      expect(createObjectUrl).not.toHaveBeenCalled();
      expect(clipboard).not.toHaveBeenCalled();
      expect(reads).toEqual(before);
      mounted.update({ readBlocked: false });
      await ready();
      fireEvent.click(namedButton(/presets\.generate$/));
      const currentCopy = await waitFor(() =>
        namedButton("connections.copyAuthenticatedUrl"),
      );
      const currentDownload = namedButton(
        "connections.downloadAuthenticatedUrl",
      );
      expect((currentCopy as HTMLButtonElement).disabled).toBe(false);
      expect((currentDownload as HTMLButtonElement).disabled).toBe(false);
      await act(async () => {
        const checked = mounted.recheck();
        // Keep the old enabled DOM in this batch. The action must read the
        // controller's new generation even before React replaces that view.
        fireEvent.click(currentCopy);
        fireEvent.click(currentDownload);
        await checked;
      });
      expect(createObjectUrl).not.toHaveBeenCalled();
      expect(clipboard).not.toHaveBeenCalled();
      expect(writes).not.toHaveBeenCalled();
    });

    it("reports download handoff failures without reissuing secrets and releases temporary URLs on failure or unmount", async () => {
      const mounted = mount(secret);
      await ready();
      fireEvent.click(namedButton(/presets\.generate$/));
      const download = await waitFor(() =>
        namedButton("connections.downloadAuthenticatedUrl"),
      );
      const before = reads.slice();
      createObjectUrl.mockImplementationOnce(() => {
        throw new Error("fixture browser cannot create a download");
      });
      fireEvent.click(download);
      expect(screen.getByText("connections.downloadFailed")).toBeTruthy();
      expect(screen.queryByText("connections.downloadRequested")).toBeNull();
      expect(startDownload).not.toHaveBeenCalled();
      startDownload.mockImplementationOnce(() => {
        throw new Error("fixture browser rejects the download handoff");
      });
      fireEvent.click(download);
      expect(screen.getByText("connections.downloadFailed")).toBeTruthy();
      expect(revokeObjectUrl).toHaveBeenCalledWith(
        "blob:https://localhost/export-1",
      );
      expect(document.querySelector("a[download]")).toBeNull();
      fireEvent.click(download);
      expect(screen.getByText("connections.downloadRequested")).toBeTruthy();
      expect(revokeObjectUrl).not.toHaveBeenCalledWith(
        "blob:https://localhost/export-2",
      );
      mounted.unmount();
      expect(revokeObjectUrl).toHaveBeenCalledWith(
        "blob:https://localhost/export-2",
      );
      expect(reads).toEqual(before);
      expect(writes).not.toHaveBeenCalled();
      expect(clipboard).not.toHaveBeenCalled();
    });

    it("keeps basic endpoint choices short, reveals manual fields, rechecks generation and never copies implicitly", async () => {
      const mounted = mount(secret);
      await ready();
      const dialog = screen.getByRole("dialog");
      expect(dialog.style.top).toBe("16px");
      expect(dialog.style.marginTop).toBe("0px");
      expect(dialog.style.marginBottom).toBe("0px");
      expect(dialog.style.maxWidth).toBe("calc(100% - 32px)");
      expect(dialog.querySelector(".connection-modal-container")).toBeTruthy();
      expect(dialog.querySelector(".connection-modal-body")).toBeTruthy();
      const actions = dialog.querySelector<HTMLElement>(
        ".ant-modal-footer .connection-form-actions",
      )!;
      expect(actions.style.flexWrap).toBe("wrap");
      expect(within(actions).getAllByRole("button")).toHaveLength(2);
      expect(screen.queryByLabelText("presets.host")).toBeNull();
      expect(screen.queryByText("presets.catalogRevision")).toBeNull();
      expect(screen.getByText("users.secretWarning")).toBeTruthy();
      expect(document.body.textContent).toContain(secret);
      expect(
        screen
          .getByRole("button", { name: /connections.advancedDevice/ })
          .getAttribute("aria-expanded"),
      ).toBe("false");
      fireEvent.click(namedButton(/presets\.generate$/));
      await screen.findByText("presets.endpoint");
      expect(reads.filter((path) => path === "/proxy/endpoints")).toHaveLength(
        3,
      );
      expect(clipboard).not.toHaveBeenCalled();
      await select("connections.selectEndpoint", "connections.manual");
      fireEvent.change(await screen.findByLabelText("presets.host"), {
        target: { value: "manual.example" },
      });
      fireEvent.change(screen.getByLabelText("presets.port"), {
        target: { value: "1080" },
      });
      await select("presets.protocol", "SOCKS5");
      await select("presets.operation", "presets.socks5_connect");
      expect(screen.queryByText("presets.endpoint")).toBeNull();
      fireEvent.click(namedButton(/presets\.generate$/));
      await screen.findByText("socks5://manual.example:1080");
      await select("connections.selectEndpoint", "http://proxy.example:8080");
      expect(screen.queryByLabelText("presets.host")).toBeNull();
      expect(screen.queryByText("presets.endpoint")).toBeNull();
      expect((document.getElementById("host") as HTMLInputElement).value).toBe(
        "proxy.example",
      );
      expect((document.getElementById("port") as HTMLInputElement).value).toBe(
        "8080",
      );
      expect(
        (document.getElementById("protocol") as HTMLInputElement).value,
      ).toBe("http");
      await select("presets.operation", "presets.http_connect");
      fireEvent.click(namedButton(/presets\.generate$/));
      await screen.findByText("http://proxy.example:8080", {
        selector: "code",
      });
      await select("connections.selectEndpoint", "connections.manual");
      expect(
        (screen.getByLabelText("presets.host") as HTMLInputElement).value,
      ).toBe("proxy.example");
      expect(
        (screen.getByLabelText("presets.port") as HTMLInputElement).value,
      ).toBe("8080");
      expect(writes).not.toHaveBeenCalled();
      expect(clipboard).not.toHaveBeenCalled();
      expect(reads.every((path) => !path.includes(secret))).toBe(true);
      expectOnlyNonSecretPreferences();
      expect(sessionStorage.length).toBe(0);
      expect(location.href).not.toContain(secret);
      // The wrapping container retains ProForm's original generated buttons,
      // rather than replacing their submission/reset handlers with lookalikes.
      fireEvent.click(
        within(actions).getByRole("button", { name: "users.secretClose" }),
      );
      expect(mounted.close).toHaveBeenCalledTimes(1);
      expect(
        (screen.getByLabelText("users.secret") as HTMLInputElement).value,
      ).toBe("");
    });

    it("opens advanced routing without selecting a rule and clears derived values when returning to basic routing", async () => {
      mount();
      await ready();
      await select("presets.route", "connections.advancedRouting");
      const derived = await screen.findByRole("combobox", {
        name: "connections.derivedRoute",
      });
      expect(
        derived
          .closest(".ant-select")!
          .querySelector(".ant-select-content-has-value"),
      ).toBeNull();
      await select("connections.derivedRoute", "presets.route.session");
      fireEvent.change(
        await screen.findByLabelText("connections.derivedValue"),
        {
          target: { value: "my_session" },
        },
      );
      fireEvent.click(namedButton(/presets\.generate$/));
      await screen.findByText(`${credential.login}-session-my_session`);
      await select("presets.route", "presets.route.default");
      expect(screen.queryByLabelText("connections.derivedValue")).toBeNull();
      expect(screen.queryByText("presets.endpoint")).toBeNull();
      await select("presets.route", "connections.advancedRouting");
      await select("connections.derivedRoute", "presets.route.session");
      expect(
        (screen.getByLabelText("connections.derivedValue") as HTMLInputElement)
          .value,
      ).toBe("");
      expect(writes).not.toHaveBeenCalled();
    });

    it("preserves compatible operations and explicit presets, requiring a deliberate choice for incompatible changes", async () => {
      mount();
      await ready();
      await select("presets.operation", "presets.http_forward");
      await select("connections.selectEndpoint", "https://proxy.example:8080");
      expect(
        screen
          .getByRole("combobox", { name: "presets.operation" })
          .closest(".ant-select")!.textContent,
      ).toContain("presets.http_forward");
      fireEvent.click(namedButton(/connections.advancedDevice/));
      await select("presets.device", "windows");
      await select("connections.selectEndpoint", "socks5://proxy.example:8080");
      expect(
        screen
          .getByRole("combobox", { name: "presets.operation" })
          .closest(".ant-select")!.textContent,
      ).toContain("presets.socks5_connect");
      expect(namedButton(/connections.advancedDevice/).textContent).toContain(
        "windows",
      );
      await select("presets.operation", "presets.socks5_udp");
      expect(
        screen.getByText("connections.deviceOperationConflict"),
      ).toBeTruthy();
      fireEvent.click(namedButton(/presets\.generate$/));
      await screen.findByText("presets.unknownPolicy");
      expect(screen.queryByText("presets.endpoint")).toBeNull();
      fireEvent.click(namedButton("connections.reviewDevice"));
      await select("presets.device", "presets.automatic");
      expect(
        screen.queryByText("connections.deviceOperationConflict"),
      ).toBeNull();
      fireEvent.click(namedButton(/presets\.generate$/));
      await screen.findByText("presets.endpoint");
      expect(
        screen.queryByText(`${credential.login}-device-windows`),
      ).toBeNull();
      expect(writes).not.toHaveBeenCalled();
    });

    it("retains an address after refresh but invalidates a reused endpoint key until explicit selection", async () => {
      mount();
      await ready();
      await select("presets.operation", "presets.http_forward");
      fireEvent.click(namedButton(/connections.advancedDevice/));
      await select("presets.device", "windows");
      publicAddress = "changed.example:9090";
      fireEvent.click(namedButton("users.refresh"));
      await screen.findByText("connections.endpointChanged");
      expect((document.getElementById("host") as HTMLInputElement).value).toBe(
        "proxy.example",
      );
      expect((document.getElementById("port") as HTMLInputElement).value).toBe(
        "8080",
      );
      expect(
        screen
          .getByRole("combobox", { name: /^connections\.selectEndpoint/ })
          .closest(".ant-select")!
          .querySelector(".ant-select-content-has-value"),
      ).toBeNull();
      expect(
        screen
          .getByRole("combobox", { name: "presets.operation" })
          .closest(".ant-select")!.textContent,
      ).toContain("presets.http_forward");
      expect(namedButton(/connections.advancedDevice/).textContent).toContain(
        "windows",
      );
      const readCount = reads.filter(
        (path) => path === "/proxy/endpoints",
      ).length;
      fireEvent.click(namedButton(/presets\.generate$/));
      // Retaining fields must not bypass required endpoint reconfirmation.
      await waitFor(() => {
        const item = document
          .getElementById("endpoint")
          ?.closest(".ant-form-item");
        expect(item?.classList.contains("ant-form-item-has-error")).toBe(true);
      });
      expect(reads.filter((path) => path === "/proxy/endpoints")).toHaveLength(
        readCount,
      );
      await select("connections.selectEndpoint", "http://changed.example:9090");
      expect(screen.queryByText("connections.endpointChanged")).toBeNull();
      fireEvent.click(namedButton(/presets\.generate$/));
      await screen.findByText("http://changed.example:9090", {
        selector: "code",
      });
      expect(
        screen.getByText(`${credential.login}-device-windows`, {
          selector: "code",
        }),
      ).toBeTruthy();
      expect(writes).not.toHaveBeenCalled();
    });

    it("remembers manual host, port and protocol across remount and refresh without retaining the password", async () => {
      const first = mount(secret);
      await ready();
      await select("connections.selectEndpoint", "connections.manual");
      fireEvent.change(await screen.findByLabelText("presets.host"), {
        target: { value: "manual.example" },
      });
      fireEvent.change(screen.getByLabelText("presets.port"), {
        target: { value: "1080" },
      });
      await select("presets.protocol", "SOCKS5");
      expectOnlyNonSecretPreferences();
      expect(localStorage.length).toBe(1);
      fireEvent.click(namedButton("users.secretClose"));
      expect(first.close).toHaveBeenCalledTimes(1);
      first.unmount();
      mount();
      await ready();
      const check = () => {
        expect(
          (screen.getByLabelText("presets.host") as HTMLInputElement).value,
        ).toBe("manual.example");
        expect(
          (screen.getByLabelText("presets.port") as HTMLInputElement).value,
        ).toBe("1080");
        expect(
          screen
            .getByRole("combobox", { name: "presets.protocol" })
            .closest(".ant-select")!.textContent,
        ).toContain("SOCKS5");
        expect(
          (screen.getByLabelText("users.secret") as HTMLInputElement).value,
        ).toBe("");
      };
      check();
      fireEvent.click(namedButton("users.refresh"));
      await ready();
      check();
      fireEvent.click(namedButton(/presets\.generate$/));
      await screen.findByText("socks5://manual.example:1080");
      expectOnlyNonSecretPreferences();
      expect(writes).not.toHaveBeenCalled();
    });

    it("requires reconfirmation of a remembered catalog endpoint that changed while the window was closed", async () => {
      const first = mount();
      await ready();
      await select("connections.selectEndpoint", "https://proxy.example:8080");
      first.unmount();
      publicAddress = "changed.example:9090";
      mount();
      await screen.findByText("connections.endpointChanged");
      await ready();
      expect(
        (screen.getByLabelText("presets.host") as HTMLInputElement).value,
      ).toBe("proxy.example");
      expect(
        (screen.getByLabelText("presets.port") as HTMLInputElement).value,
      ).toBe("8080");
      fireEvent.click(namedButton(/presets\.generate$/));
      await waitFor(() =>
        expect(
          document
            .getElementById("endpoint")
            ?.closest(".ant-form-item")
            ?.classList.contains("ant-form-item-has-error"),
        ).toBe(true),
      );
      await select(
        "connections.selectEndpoint",
        "https://changed.example:9090",
      );
      fireEvent.click(namedButton(/presets\.generate$/));
      await screen.findByText("https://changed.example:9090", {
        selector: "code",
      });
      expect(writes).not.toHaveBeenCalled();
    });

    it("does not restore a remembered protocol after it is removed from the user's allowed protocols", async () => {
      const first = mount();
      await ready();
      await select("connections.selectEndpoint", "socks5://proxy.example:8080");
      first.unmount();
      const second = mount();
      second.update({ user: { ...user, protocols: ["http"] } });
      await screen.findByText("connections.endpointChanged");
      await ready();
      expect(
        (screen.getByLabelText("presets.host") as HTMLInputElement).value,
      ).toBe("proxy.example");
      fireEvent.click(namedButton(/presets\.generate$/));
      await waitFor(() =>
        expect(
          document
            .getElementById("protocol")
            ?.closest(".ant-form-item")
            ?.classList.contains("ant-form-item-has-error"),
        ).toBe(true),
      );
      expect(screen.queryByText("presets.endpoint")).toBeNull();
      expect(writes).not.toHaveBeenCalled();
    });

    it("does not report an atomic running state when policy and endpoint observations disagree", async () => {
      endpointDelay = Promise.resolve(
        jsonResponse({
          node_id: NODE,
          proxy_running: true,
          listeners: [
            {
              protocol: "http",
              bind: "0.0.0.0:8080",
              public_address: publicAddress,
            },
          ],
        }),
      );
      mount();
      await ready();
      expect(screen.getByText("connections.stateChanged")).toBeTruthy();
      expect(screen.queryByText("users.proxyNotStarted")).toBeNull();
      expect(screen.queryByText("users.running")).toBeNull();
      expect(
        screen.queryByRole("link", { name: "connections.openService" }),
      ).toBeNull();
      expect(writes).not.toHaveBeenCalled();
    });

    it("warns when browser storage rejects a preference but still generates a checked connection", async () => {
      vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
        throw new DOMException("Full", "QuotaExceededError");
      });
      mount();
      await ready();
      await select("connections.selectEndpoint", "https://proxy.example:8080");
      await screen.findByText("connections.rememberFailed");
      fireEvent.click(namedButton(/presets\.generate$/));
      await screen.findByText("https://proxy.example:8080", {
        selector: "code",
      });
      expect(localStorage.length).toBe(0);
      expect(writes).not.toHaveBeenCalled();
    });

    it("keeps every grant available when optional names are bounded, then clears revoked routing on refresh", async () => {
      permission.legacy_allowed = false;
      mount();
      await ready();
      expect(
        screen
          .getByRole("combobox", { name: "presets.route" })
          .closest(".ant-select")!
          .querySelector(".ant-select-content-has-value"),
      ).toBeNull();
      await select("presets.route", "presets.route.exit");
      await select(
        "connections.exitValue",
        `${outside} · connections.nameNotRead`,
      );
      fireEvent.click(namedButton("connections.readNames"));
      await waitFor(() =>
        expect(reads.filter((path) => path.includes("?limit=50"))).toEqual([
          "/proxy/addresses?limit=50",
          "/proxy/pools?limit=50",
        ]),
      );
      await waitFor(() =>
        expect(
          screen
            .getByRole("button", { name: "connections.readNames" })
            .hasAttribute("disabled"),
        ).toBe(false),
      );
      // Loading a page neither drops the outside-page ID nor changes selection.
      expect(
        screen
          .getByRole("combobox", { name: "connections.exitValue" })
          .closest(".ant-select")!.textContent,
      ).toContain(outside);
      await select(
        "connections.exitValue",
        `Named exit · 192.0.2.1 · resources.draining · ${NODE}`,
      );
      permission = { ...permission, exits: [], pools: [] };
      revision = "8";
      fireEvent.click(namedButton(/presets\.generate$/));
      await screen.findByText("presets.unknownPolicy");
      expect(screen.queryByText("presets.endpoint")).toBeNull();
      fireEvent.click(namedButton("users.refresh"));
      await screen.findByText("presets.noRoutes");
      expect(screen.queryByLabelText("connections.exitValue")).toBeNull();
      expect(
        screen
          .getByRole("button", { name: /presets\.generate$/ })
          .hasAttribute("disabled"),
      ).toBe(true);
      expect(writes).not.toHaveBeenCalled();
      expect(clipboard).not.toHaveBeenCalled();
    });

    it("aborts pending observations and releases parent busy state on unmount, even when the transport responds late", async () => {
      let release: (value: Response) => void = () => {};
      endpointDelay = new Promise((resolve) => {
        release = resolve;
      });
      const rendered = mount(secret);
      await waitFor(() => expect(endpointSignal).not.toBeNull());
      rendered.unmount();
      expect(endpointSignal!.aborted).toBe(true);
      release(
        jsonResponse({ node_id: NODE, proxy_running: false, listeners: [] }),
      );
      await Promise.resolve();
      expect(rendered.onBusy).toHaveBeenLastCalledWith(false);
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(clipboard).not.toHaveBeenCalled();
      expect(writes).not.toHaveBeenCalled();
    });
  },
);
