import { describe, expect, it } from "vitest";
import { connectionUsername } from "./connection";
import { diagnosticProfile, type DiagnosticInput } from "./diagnosticProfile";
import { ApiError } from "./error";
import { POOL } from "./presets.fixtures";

const input = (): DiagnosticInput => ({
  protocol: "http",
  host: "proxy.example",
  port: 8080,
  username: `vp2_${"ab".repeat(16)}`,
  operation: "http_connect",
});
describe("non-secret local diagnostic profiles", () => {
  it("exports exactly the fixed CLI shape for HTTP, HTTPS and SOCKS5 CONNECT", () => {
    for (const protocol of ["http", "https", "socks5"] as const) {
      const value = diagnosticProfile({
        ...input(),
        protocol,
        operation: protocol === "socks5" ? "socks5_connect" : "http_connect",
      });
      expect(value).toEqual({
        format_version: 1,
        protocol,
        host: "proxy.example",
        port: 8080,
        username: input().username,
        operation: "connect",
      });
      expect(Object.isFrozen(value)).toBe(true);
      expect(JSON.stringify(value)).not.toMatch(
        /password|secret|target|headers|paths|example\.com|vproxy manage/,
      );
    }
  });
  it("keeps full routing/device usernames but strips IPv6 URL brackets from the host", () => {
    const username = connectionUsername(
      input().username,
      { kind: "pool", id: POOL },
      "ios",
    );
    expect(
      diagnosticProfile({ ...input(), host: "[2001:db8::7]", username }),
    ).toMatchObject({ host: "2001:db8::7", username });
    expect(diagnosticProfile({ ...input(), host: "PROXY.EXAMPLE" })?.host).toBe(
      "proxy.example",
    );
    for (const [source, canonical] of [
      ["127.0.0.1", "127.0.0.1"],
      ["2001:0DB8:0:0:0:0:0:7", "2001:db8::7"],
      ["[2001:DB8::7]", "2001:db8::7"],
      ["::ffff:c000:207", "::ffff:192.0.2.7"],
      ["::ffff:192.0.2.7", "::ffff:192.0.2.7"],
      ["::192.0.2.7", "::c000:207"],
    ])
      expect(diagnosticProfile({ ...input(), host: source })?.host).toBe(
        canonical,
      );
  });
  it("declines unsupported operations and rejects unknown or secret-bearing data instead of copying it", () => {
    for (const [protocol, operation] of [
      ["http", "http_forward"],
      ["https", "http_forward"],
      ["socks5", "socks5_bind"],
      ["socks5", "socks5_udp"],
      ["masque", "masque_udp"],
      ["http", "socks5_connect"],
      ["socks5", "http_connect"],
    ] as const)
      expect(diagnosticProfile({ ...input(), protocol, operation })).toBeNull();
    for (const value of [
      null,
      { ...input(), password: "not-an-input" },
      { ...input(), secret: "not-an-input" },
      { ...input(), target: "https://outside.invalid/" },
      { ...input(), headers: {} },
      { ...input(), path: "private.pem" },
      { ...input(), protocol: "auto" },
      { ...input(), operation: "connect" },
      { ...input(), username: "admin" },
      { ...input(), username: input().username + "\n" },
      { ...input(), host: "user:secret@proxy.example" },
      { ...input(), host: "[fe80::1%3]" },
      { ...input(), host: "proxy.example." },
      { ...input(), host: "127.1" },
      { ...input(), host: "0x7f000001" },
      { ...input(), port: 0 },
      { ...input(), port: 65536 },
    ])
      expect(() => diagnosticProfile(value as never)).toThrow(ApiError);
  });
});
