import { describe, expect, it } from "vitest";
import { connectionUsername } from "./connection";
import {
  clientExamples,
  type ClientExampleInput,
  type ClientExamples,
} from "./clientExamples";
import { ApiError } from "./error";
import { POOL } from "./presets.fixtures";

const login = `vp2_${"ab".repeat(16)}`;
const input = (): ClientExampleInput => ({
  protocol: "http",
  host: "proxy.example",
  port: 8080,
  username: login,
  operation: "http_connect",
});
const supported = (result: ClientExamples) => {
  expect(result.supported).toBe(true);
  if (!result.supported) throw new Error("expected a supported example");
  return result;
};

describe("non-secret client examples", () => {
  it.each(["http", "https", "socks5"] as const)(
    "includes the selected password in ready-to-run %s examples without weakening TLS or DNS",
    (protocol) => {
      const password = "A".repeat(43);
      const result = supported(
        clientExamples(
          {
            ...input(),
            protocol,
            operation:
              protocol === "socks5" ? "socks5_connect" : "http_connect",
          },
          password,
        ),
      );
      expect(result.containsPassword).toBe(true);
      expect(result.curl).toContain(`--proxy-user "${login}:${password}"`);
      expect(result.python).toContain(`password = "${password}"`);
      expect(result.python).not.toContain('getpass("Proxy password: ")');
      expect(result.python).toContain("verify=True");
      expect(result.curl).not.toMatch(/--insecure|--proxy-insecure/);
      expect(result.curl).toContain(
        `--proxy "${protocol === "socks5" ? "socks5h" : protocol}://`,
      );
    },
  );

  it("rejects malformed ready-to-run passwords rather than emitting shell fragments", () => {
    for (const value of [
      "",
      "A".repeat(42),
      "$(command)",
      `${"A".repeat(42)}B`,
      `${"A".repeat(43)}\n`,
    ])
      expect(() => clientExamples(input(), value)).toThrow(ApiError);
  });
  it("offers CONNECT-only recipes with explicit protocol and fixed HTTPS target", () => {
    for (const protocol of ["http", "https", "socks5"] as const) {
      const original: ClientExampleInput = {
        ...input(),
        protocol,
        operation: protocol === "socks5" ? "socks5_connect" : "http_connect",
      };
      const result = supported(clientExamples(original));
      const scheme = protocol === "socks5" ? "socks5h" : protocol;
      expect(result.curl).toContain(`--proxy "${scheme}://proxy.example:8080"`);
      expect(result.curl).toContain(`--proxy-user "${login}"`);
      expect(result.curl).toContain(
        protocol === "socks5" ? "--socks5-basic" : "--proxy-basic",
      );
      expect(result.curl.endsWith('"https://example.com/"')).toBe(true);
      expect(result.python).toContain(`"${scheme}://"`);
      expect(result.pythonDependency).toBe(
        protocol === "socks5" ? "requests[socks]" : "requests",
      );
      expect(result.httpsProxy).toBe(protocol === "https");
      expect(original.protocol).toBe(protocol);
    }
  });

  it("preserves bracketed IPv6 and generated extension usernames without shell fragments", () => {
    const username = connectionUsername(
      login,
      { kind: "pool", id: POOL },
      "ios",
    );
    const result = supported(
      clientExamples({
        ...input(),
        host: "[2001:db8::7]",
        port: 443,
        username,
      }),
    );
    expect(result.curl).toContain('--proxy "http://[2001:db8::7]:443"');
    expect(result.curl).toContain(`--proxy-user "${username}"`);
    expect(result.python).toContain('"@[2001:db8::7]:443"');
    expect(result.python).toContain(`quote("${username}", safe="")`);
    expect(result.python).toContain('quote(password, safe="")');
  });

  it("does not let config files or NO_PROXY silently bypass the selected curl proxy", () => {
    const { curl } = supported(clientExamples(input()));
    expect(curl.startsWith("curl --disable ")).toBe(true);
    expect(curl).toContain('--noproxy ""');
    expect(curl).toContain("--connect-timeout 10 --max-time 30");
    expect(curl).not.toMatch(
      /--insecure|--proxy-insecure|--verbose|--trace|\$\{|%[A-Z_]+%/,
    );
    expect(curl).not.toContain(`${login}:`);
    expect(curl).not.toContain("@");
  });

  it("prompts privately in Python, bounds requests and prints only status", () => {
    const { python } = supported(clientExamples(input()));
    expect(python).toContain('warnings.simplefilter("error", GetPassWarning)');
    expect(python).toContain('password = getpass("Proxy password: ")');
    expect(python).toContain("session.trust_env = False");
    expect(python).toContain('proxies={"https": proxy}');
    expect(python).toContain("timeout=(10, 20)");
    expect(python).toContain("allow_redirects=False");
    expect(python).toContain("stream=True");
    expect(python).toContain("verify=True");
    expect(python.match(/print\([^\n]+/g)).toEqual([
      "print(response.status_code)",
    ]);
    expect(python).toContain(
      "except (requests.RequestException, GetPassWarning, EOFError):",
    );
    expect(python).toContain("from None");
    expect(python).not.toMatch(
      /verify=False|environ|getenv|input\(|repr\(|str\(error|print\(proxy|print\(password/,
    );
    expect(python.endsWith('finally:\n    password = ""\n    proxy = ""')).toBe(
      true,
    );
  });

  it("explicitly declines BIND, UDP, MASQUE, forward-only and mismatched operations", () => {
    for (const [protocol, operation] of [
      ["http", "http_forward"],
      ["https", "http_forward"],
      ["socks5", "socks5_bind"],
      ["socks5", "socks5_udp"],
      ["masque", "masque_udp"],
      ["http", "socks5_connect"],
      ["socks5", "http_connect"],
    ] as const)
      expect(clientExamples({ ...input(), protocol, operation })).toEqual({
        supported: false,
        reason: "operation_unsupported",
      });
  });

  it("rejects password fields, unknown inputs, URL userinfo and command injection", () => {
    for (const value of [
      null,
      { ...input(), password: "not-an-input" },
      { ...input(), secret: "not-an-input" },
      { ...input(), destination: "https://different.example/" },
      { ...input(), operation: "unknown" },
      { ...input(), protocol: "auto" },
      { ...input(), username: "admin" },
      { ...input(), username: `${login}\n` },
      { ...input(), username: `${login}:secret@elsewhere` },
      { ...input(), username: `${login}\";run-command` },
      { ...input(), username: `${login}-session-$(run-command)` },
      { ...input(), username: `${login}-ttl-18446744073709551616` },
      { ...input(), host: "user:secret@proxy.example" },
      { ...input(), host: 'proxy.example";run-command' },
      { ...input(), host: "$(run-command)" },
      { ...input(), host: "[fe80::1%3]" },
      { ...input(), port: "8080" },
    ])
      expect(() => clientExamples(value as never)).toThrow(ApiError);
  });
});
