import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../../api/client";
import type { RemotePolicy, Target } from "../../api/targets";
import { SetupIssue, setupCommands, verifySetup } from "./setup";

const controller = "A".repeat(22);
const child = "Q".repeat(22);
const destination = (): Target => ({
  node_id: child,
  name: "child",
  origin: "https://child.example:9443",
  server_ip: null,
  active: true,
  retired: false,
  revision: "5",
  observed_epoch: null,
  observed_command: null,
  observed_policy_revision: null,
  rollback_detected: false,
});
const policy = (): RemotePolicy => ({
  controller_node_id: controller,
  controller_epoch: "27",
  last_terminal_command: "0",
  saved_revision: "9",
  applied_revision: null,
  durable_applied_revision: null,
  proxy_running: false,
  user_count: 0,
  credential_count: 0,
});
const client = () => ({
  target: vi.fn(async () => destination()),
  targetPolicy: vi.fn(async () => policy()),
});

describe("node setup command and verification boundaries", () => {
  it("interpolates only canonical quoted public IDs, never an assumed epoch or executable discovered origin", () => {
    const commands = setupCommands(controller, child);
    expect(commands.grant).toContain(`--controller-node-id '${controller}'`);
    expect(commands.grant).toContain(
      "--expected-epoch '<CURRENT_EPOCH_FROM_STATUS>'",
    );
    expect(commands.registerMain).toContain(`--node-id '${child}'`);
    expect(commands.probeMain).toContain(
      "--endpoint '<CHILD_NODE_MTLS_ORIGIN>'",
    );
    expect(commands.prepare).not.toContain("--proxy-config");
    const all = Object.values(commands).join("\n");
    expect(all).not.toMatch(
      /--password|password-stdin|ssh |curl |--insecure|https:\/\//,
    );
    expect(setupCommands(controller).registerMain).toContain(
      "'<CHILD_NODE_ID_FROM_TRUSTED_CHANNEL>'",
    );
    for (const injected of ["'$(id)'", "A".repeat(21) + "B", child + "\n"])
      expect(() => setupCommands(controller, injected)).toThrow(ApiError);
  });

  it("uses checked offline plans for a new child without rebuilding trust or initializing an existing child", () => {
    const commands = setupCommands(controller, child);
    expect(commands.prepare).toContain("vproxy manage status --data-dir");
    expect(commands.prepare).toContain("vproxy manage serve --help");
    expect(commands.prepare).not.toMatch(
      /manage init|manage setup|manage serve --data-dir/,
    );
    expect(commands.prepareChild).toContain("vproxy manage setup prepare");
    for (const flag of [
      "--authority-public",
      "--authority-sha256",
      "--admin-origin",
      "--node-origin",
    ])
      expect(commands.prepareChild).toContain(flag);
    expect(commands.signChild).toContain("vproxy manage setup sign");
    for (const flag of ["--authority", "--request", "--output"])
      expect(commands.signChild).toContain(flag);
    expect(commands.planChild).toContain("vproxy manage setup plan");
    for (const flag of [
      "--prepared",
      "--response",
      "--admin-bind",
      "--node-bind",
    ])
      expect(commands.planChild).toContain(flag);
    expect(commands.planChild).toContain("vproxy manage setup check --input");
    expect(commands.planChild).not.toContain("--proxy-config");
    expect(commands.proxyChild).toContain("vproxy manage setup proxy");
    expect(commands.proxyChild).toContain("vproxy manage setup plan");
    expect(commands.proxyChild).toContain("--proxy-config");
    expect(commands.proxyChild).toContain("vproxy manage setup check --input");
    expect(commands.proxyChild).not.toContain("--listen");
    expect(commands.serviceChild).toContain(
      "vproxy manage setup service --plan",
    );
    expect(commands.serviceChild).toContain(
      "vproxy manage setup check --input",
    );
    expect(commands.startChild).toMatch(/\bsh [^\n]*start\.sh/);
    expect(commands.startChild).not.toContain("pwsh");
    expect(commands.startChildWindows).toMatch(/\bpwsh -File [^\n]*start\.ps1/);
    expect(Object.values(commands).join("\n")).not.toMatch(
      /manage init|manage setup authority|systemctl|--password|--insecure|--acme/,
    );
  });

  it("performs one policy read against only the selected ID and checks the registry before and after", async () => {
    const api = client();
    const signal = new AbortController().signal;
    const result = await verifySetup(api, destination(), controller, signal);
    expect(result.proxy_running).toBe(false);
    expect(result.controller_node_id).toBe(controller);
    expect(api.target.mock.calls).toEqual([
      [child, signal],
      [child, signal],
    ]);
    expect(api.targetPolicy.mock.calls).toEqual([[child, signal]]);
  });

  it.each([
    { active: false },
    { active: false, retired: true },
    { rollback_detected: true },
    { node_id: "g".repeat(22) },
    { origin: "https://changed.example:9443" },
    { revision: "6" },
  ])(
    "does not request remote policy for an ineligible or changed registry: %j",
    async (change) => {
      const api = client();
      api.target.mockResolvedValue({ ...destination(), ...change });
      await expect(
        verifySetup(
          api,
          destination(),
          controller,
          new AbortController().signal,
        ),
      ).rejects.toBeInstanceOf(SetupIssue);
      expect(api.targetPolicy).not.toHaveBeenCalled();
    },
  );

  it("rejects a changed post-read destination and a different controller without claiming success", async () => {
    const api = client();
    api.target
      .mockResolvedValueOnce(destination())
      .mockResolvedValueOnce({ ...destination(), revision: "6" });
    await expect(
      verifySetup(api, destination(), controller, new AbortController().signal),
    ).rejects.toMatchObject({ messageKey: "setup.changed" });
    const wrongOwner = client();
    wrongOwner.targetPolicy.mockResolvedValue({
      ...policy(),
      controller_node_id: null,
    });
    await expect(
      verifySetup(
        wrongOwner,
        destination(),
        controller,
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ messageKey: "setup.ownerMismatch" });
    expect(wrongOwner.target).toHaveBeenCalledTimes(1);
  });

  it("does not advance a cancelled composite read even when a transport returns late", async () => {
    const api = client();
    const request = new AbortController();
    api.target.mockImplementation(async () => {
      request.abort();
      return destination();
    });
    await expect(
      verifySetup(api, destination(), controller, request.signal),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(api.targetPolicy).not.toHaveBeenCalled();
    const afterPolicy = client();
    const second = new AbortController();
    afterPolicy.targetPolicy.mockImplementation(async () => {
      second.abort();
      return policy();
    });
    await expect(
      verifySetup(afterPolicy, destination(), controller, second.signal),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(afterPolicy.target).toHaveBeenCalledTimes(1);
  });

  it("preserves denied/unsupported API errors rather than guessing which node missed enrollment", async () => {
    for (const failure of [
      new ApiError("server", "peer_not_authorized", 502),
      new ApiError("server", "management_upgrade_required", 503),
    ]) {
      const api = client();
      api.targetPolicy.mockRejectedValue(failure);
      await expect(
        verifySetup(
          api,
          destination(),
          controller,
          new AbortController().signal,
        ),
      ).rejects.toBe(failure);
      expect(api.target).toHaveBeenCalledTimes(1);
    }
  });
});
