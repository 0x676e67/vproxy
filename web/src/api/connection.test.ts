import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ApiError } from "./error";
import {
  connectionHost,
  connectionPreview,
  connectionUsername,
  type ConnectionInput,
} from "./connection";
import { presetNames } from "./presets";
import {
  NODE,
  USER,
  POOL,
  capabilityFixture,
  userPresetFixture,
  poolPresetFixture,
} from "./presets.fixtures";
const login = `vp2_${"ab".repeat(16)}`;
const policy = () => ({
  protocols: ["http", "socks5", "masque"] as ("http" | "socks5" | "masque")[],
  permission: {
    user_id: USER,
    legacy_allowed: true,
    exits: [NODE],
    pools: [POOL],
  },
  user: userPresetFixture(),
  pool: null,
  capability: capabilityFixture(),
});
const input = (): ConnectionInput => ({
  login,
  protocol: "http",
  operation: "http_connect",
  host: "proxy.example",
  port: "8443",
  route: { kind: "default" },
  device: null,
});
describe("managed connection configuration", () => {
  it("places a single device before an unchanged single route, with canonical finite selectors", () => {
    for (const name of presetNames)
      expect(
        connectionUsername(login, { kind: "session", value: "job_1" }, name),
      ).toBe(`${login}-device-${name}-session-job_1`);
    expect(
      connectionUsername(login, { kind: "pool", id: POOL }, "windows"),
    ).toBe(`${login}-device-windows-pool-${"02".repeat(16)}`);
    expect(
      connectionUsername(
        login,
        { kind: "range", value: "a".repeat(128) },
        null,
      ),
    ).toHaveLength(login.length + 7 + 128);
    for (const route of [
      { kind: "session", value: "old-device-ios" },
      { kind: "ttl", value: "0" },
      { kind: "ttl", value: "01" },
      { kind: "ttl", value: "18446744073709551616" },
      { kind: "pool", id: "127.0.0.1" },
      { kind: "default", device: "windows" },
    ])
      expect(() => connectionUsername(login, route as never, null)).toThrow(
        ApiError,
      );
    expect(() =>
      connectionUsername(login, { kind: "default" }, "native" as never),
    ).toThrow(ApiError);
  });
  it("resolves explicit/pool/user/native defaults without allowing pool suggestions to grant permission", () => {
    expect(connectionPreview(input(), policy()).effective_preset).toBe("linux");
    const withPool = { ...policy(), pool: poolPresetFixture() };
    expect(
      connectionPreview(
        { ...input(), route: { kind: "pool", id: POOL } },
        withPool,
      ).effective_preset,
    ).toBe("windows");
    expect(
      connectionPreview(
        { ...input(), device: "linux", route: { kind: "pool", id: POOL } },
        withPool,
      ).effective_preset,
    ).toBe("linux");
    expect(() =>
      connectionPreview(
        { ...input(), route: { kind: "pool", id: POOL } },
        {
          ...withPool,
          user: { ...userPresetFixture(), allowed_presets: ["linux"] },
        },
      ),
    ).toThrow(ApiError);
    expect(
      connectionPreview(input(), {
        ...policy(),
        user: { user_id: USER, default_preset: null, allowed_presets: [] },
      }).effective_preset,
    ).toBeNull();
    expect(() =>
      connectionPreview(
        { ...input(), route: { kind: "exit", id: USER } },
        policy(),
      ),
    ).toThrow(ApiError);
    expect(() =>
      connectionPreview(input(), {
        ...policy(),
        permission: {
          ...policy().permission,
          legacy_allowed: false,
          exits: [],
          pools: [],
        },
      }),
    ).toThrow(ApiError);
  });
  it("ignores TCP defaults for UDP/passive BIND but rejects any explicit device there", () => {
    for (const [protocol, operation] of [
      ["masque", "masque_udp"],
      ["socks5", "socks5_udp"],
      ["socks5", "socks5_bind"],
    ] as const) {
      expect(
        connectionPreview({ ...input(), protocol, operation }, policy())
          .effective_preset,
      ).toBeNull();
      expect(() =>
        connectionPreview(
          { ...input(), protocol, operation, device: "windows" },
          policy(),
        ),
      ).toThrow(ApiError);
    }
    const unavailable = {
      ...policy(),
      capability: {
        ...capabilityFixture(),
        backend_state: "disabled" as const,
        available_presets: [],
        operations: [],
      },
    };
    expect(() => connectionPreview(input(), unavailable)).toThrow(ApiError);
    expect(
      connectionPreview(input(), {
        ...unavailable,
        user: { user_id: USER, default_preset: null, allowed_presets: [] },
      }).effective_preset,
    ).toBeNull();
  });
  it("requires a manual valid endpoint and never emits a password-bearing URI or OS promise", () => {
    expect(connectionHost("[::1]")).toBe("::1");
    expect(connectionHost("PROXY.example")).toBe("proxy.example");
    for (const host of [
      "https://admin.example:443",
      "user:password@proxy.example",
      "proxy.example/path",
      "::1%eth0",
      "0.0.0.0",
      "bad label",
      "proxy.example?secret=value",
    ])
      expect(() => connectionHost(host)).toThrow(ApiError);
    for (const port of ["0", "01", "65536", "443/path"])
      expect(() => connectionPreview({ ...input(), port }, policy())).toThrow(
        ApiError,
      );
    expect(Object.keys(connectionPreview(input(), policy())).sort()).toEqual([
      "effective_preset",
      "host",
      "port",
      "protocol",
      "username",
    ]);
    const source = readFileSync(
      fileURLToPath(
        new URL("../components/Presets/ConnectionModal.tsx", import.meta.url),
      ),
      "utf8",
    );
    // Only the non-secret diagnostic builder's fixed six-field output may be
    // serialized here. Its exact shape and absence of secrets are also checked
    // through the real download DOM flow; this is not a general taint proof.
    const diagnosticSerialization =
      "JSON.stringify(preview.diagnostic, null, 2)";
    expect(source.split(diagnosticSerialization)).toHaveLength(2);
    expect(source.replace(diagnosticSerialization, "")).not.toMatch(
      /localStorage|sessionStorage|document\.cookie|JSON\.stringify|console\./,
    );
    expect(source).toContain('secret.current = ""');
  });
});
