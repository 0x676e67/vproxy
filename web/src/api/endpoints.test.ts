import { describe, expect, it } from "vitest";
import { connectionUsername } from "./connection";
import {
  connectionUrl,
  endpointCatalog,
  endpointChoices,
  type EndpointChoice,
} from "./endpoints";
import { ApiError } from "./error";
import { NODE, POOL } from "./presets.fixtures";

const login = `vp2_${"ab".repeat(16)}`;
const secret = "A".repeat(43);
const listener = () => ({
  protocol: "http",
  bind: "0.0.0.0:8080",
  public_address: "proxy.example:8080",
});
const catalog = () => ({
  node_id: NODE,
  proxy_running: true,
  listeners: [listener()],
});
const endpoint = (): Pick<EndpointChoice, "protocol" | "host" | "port"> => ({
  protocol: "http",
  host: "proxy.example",
  port: 8080,
});

describe("advertised proxy endpoints", () => {
  it("checks exact response shapes, identity, capacity and runtime state", () => {
    expect(endpointCatalog(catalog(), NODE)).toEqual(catalog());
    expect(
      endpointCatalog({ ...catalog(), proxy_running: false, listeners: [] })
        .listeners,
    ).toEqual([]);
    for (const value of [
      null,
      [],
      { ...catalog(), extra: true },
      { ...catalog(), node_id: "invalid" },
      { ...catalog(), node_id: `${NODE}\n` },
      { ...catalog(), proxy_running: 1 },
      { ...catalog(), listeners: {} },
      { ...catalog(), listeners: [] },
      { ...catalog(), listeners: Array.from({ length: 17 }, listener) },
      { ...catalog(), listeners: [{ ...listener(), tls_key: "private.pem" }] },
      { ...catalog(), listeners: [{ ...listener(), protocol: "quic" }] },
      {
        ...catalog(),
        listeners: [{ ...listener(), public_address: undefined }],
      },
    ])
      expect(() => endpointCatalog(value)).toThrow(ApiError);
    expect(() => endpointCatalog(catalog(), POOL)).toThrow(ApiError);
    expect(() => endpointCatalog(catalog(), "invalid")).toThrow(ApiError);
    expect(
      endpointCatalog({
        ...catalog(),
        listeners: Array.from({ length: 16 }, listener),
      }).listeners,
    ).toHaveLength(16);
  });

  it("allows numeric wildcard binds without inferring a public address", () => {
    const configured = endpointCatalog({
      ...catalog(),
      proxy_running: false,
      listeners: [
        { ...listener(), public_address: null },
        { protocol: "masque", bind: "[::]:8443", public_address: null },
      ],
    });
    expect(endpointChoices(configured)).toEqual([]);
    expect(configured.proxy_running).toBe(false);
    for (const bind of [
      "[fe80::1%3]:1080",
      "[fe80::1%0]:1080",
      "[fe80::1%4294967295]:1080",
    ])
      expect(
        endpointCatalog({
          ...catalog(),
          listeners: [{ ...listener(), bind, public_address: null }],
        }).listeners[0].bind,
      ).toBe(bind);
    for (const bind of [
      "localhost:8080",
      "::1:8080",
      "[127.0.0.1]:8080",
      "127.0.0.1:0",
      "127.0.0.1:01",
      "127.0.0.1:65536",
      "127.0.0.1:80/path",
      "127.0.0.1:80\n",
      "[fe80::1%eth0]:1080",
      "[fe80::1%4294967296]:1080",
      "[fe80::1%12345678901]:1080",
      "[fe80::1%-1]:1080",
      "[fe80::1%+3]:1080",
      "[fe80::1%3%4]:1080",
      "[127.0.0.1%3]:1080",
    ])
      expect(() =>
        endpointCatalog({ ...catalog(), listeners: [{ ...listener(), bind }] }),
      ).toThrow(ApiError);
  });

  it("requires explicit clean public authorities rather than URLs or wildcards", () => {
    for (const public_address of [
      "proxy.example",
      "proxy.example:",
      "https://proxy.example:443",
      "name:secret@proxy.example:443",
      "proxy.example:443/path",
      "proxy.example:443?token=secret",
      "proxy.example:443#fragment",
      " proxy.example:443",
      "proxy.example:443\n",
      "proxy.example\n:443",
      "[::]:443",
      "0.0.0.0:443",
      "[::1%eth0]:443",
      "[proxy.example]:443",
      "[127.0.0.1]:443",
      "127.1:443",
      "proxy.example:00080",
      "proxy.example:0",
      "proxy.example:65536",
    ])
      expect(() =>
        endpointCatalog({
          ...catalog(),
          listeners: [{ ...listener(), public_address }],
        }),
      ).toThrow(ApiError);
  });

  it("expands auto only into its supported protocols and keeps choices distinct", () => {
    const configured = endpointCatalog({
      ...catalog(),
      proxy_running: false,
      listeners: [
        {
          ...listener(),
          protocol: "auto",
          public_address: "PROXY.example:443",
        },
        { protocol: "masque", bind: "[::]:443", public_address: "[::1]:443" },
        { protocol: "socks5", bind: "127.0.0.1:1080", public_address: null },
      ],
    });
    const choices = endpointChoices(configured);
    expect(choices).toEqual([
      { key: "0:http", protocol: "http", host: "proxy.example", port: 443 },
      { key: "0:https", protocol: "https", host: "proxy.example", port: 443 },
      { key: "0:socks5", protocol: "socks5", host: "proxy.example", port: 443 },
      { key: "1:masque", protocol: "masque", host: "::1", port: 443 },
    ]);
    expect(new Set(choices.map(({ key }) => key)).size).toBe(choices.length);
    expect(configured.proxy_running).toBe(false);
    expect(configured.listeners[0].protocol).toBe("auto");
  });

  it("matches public destination exclusions without forbidding internal deployments", () => {
    for (const host of [
      "localhost",
      "127.0.0.1",
      "10.0.0.1",
      "192.168.1.1",
      "[::1]",
      "[fd00::1]",
      "[::ffff:127.0.0.1]",
      "[::ffff:10.0.0.1]",
      "[::ffff:c000:201]",
    ]) {
      const configured = endpointCatalog({
        ...catalog(),
        listeners: [{ ...listener(), public_address: `${host}:1080` }],
      });
      expect(endpointChoices(configured)).toHaveLength(1);
      expect(connectionUrl({ ...endpoint(), host })).not.toContain("@");
    }
    for (const host of [
      "0.0.0.0",
      "224.0.0.1",
      "239.255.255.255",
      "255.255.255.255",
      "[::]",
      "[ff02::1]",
      "[FF0E:0:0:0:0:0:0:1]",
      "[::ffff:0.0.0.0]",
      "[::ffff:224.0.0.1]",
      "[::ffff:255.255.255.255]",
      "[::ffff:0:0]",
      "[::ffff:e000:1]",
      "[::ffff:ffff:ffff]",
      "[fe80::1%3]",
      "2130706433",
      "0177.0.0.1",
      "0x7f000001",
      "0x7f.0.0.1",
      "example.123",
    ]) {
      expect(() =>
        endpointCatalog({
          ...catalog(),
          listeners: [{ ...listener(), public_address: `${host}:1080` }],
        }),
      ).toThrow(ApiError);
      expect(() => connectionUrl({ ...endpoint(), host })).toThrow(ApiError);
    }
  });
});

describe("copyable connection URLs", () => {
  it("defaults to no userinfo and preserves explicit ports and IPv6 brackets", () => {
    for (const protocol of ["http", "https", "socks5"] as const) {
      expect(connectionUrl({ ...endpoint(), protocol })).toBe(
        `${protocol}://proxy.example:8080`,
      );
      expect(connectionUrl({ protocol, host: "[::1]", port: 443 })).toBe(
        `${protocol}://[::1]:443`,
      );
    }
    expect(
      connectionUrl({ ...endpoint(), host: "PROXY.example", port: 1 }),
    ).toBe("http://proxy.example:1");
    for (const value of [
      { ...endpoint(), protocol: "auto" },
      { ...endpoint(), protocol: "quic" },
      { ...endpoint(), host: "0.0.0.0" },
      { ...endpoint(), host: "name:secret@proxy.example" },
      { ...endpoint(), host: "proxy.example/path" },
      { ...endpoint(), host: "[proxy.example]" },
      { ...endpoint(), host: "[127.0.0.1]" },
      { ...endpoint(), host: "proxy.example\n" },
      { ...endpoint(), port: 0 },
      { ...endpoint(), port: 65536 },
      { ...endpoint(), port: 80.5 },
      { ...endpoint(), port: "443" },
      null,
    ])
      expect(() => connectionUrl(value as never)).toThrow(ApiError);
  });

  it("requires a complete canonical managed credential rather than arbitrary userinfo", () => {
    const usernames = [
      connectionUsername(login, { kind: "default" }, null),
      connectionUsername(login, { kind: "pool", id: POOL }, "windows"),
      connectionUsername(login, { kind: "exit", id: NODE }, "ios"),
      connectionUsername(login, { kind: "session", value: "job_1" }, "linux"),
      connectionUsername(
        login,
        { kind: "range", value: "A".repeat(128) },
        null,
      ),
      connectionUsername(
        login,
        { kind: "ttl", value: "18446744073709551615" },
        null,
      ),
    ];
    for (const username of usernames)
      for (const protocol of ["http", "https", "socks5"] as const)
        expect(
          connectionUrl({ ...endpoint(), protocol }, username, secret),
        ).toBe(
          `${protocol}://${encodeURIComponent(username)}:${encodeURIComponent(secret)}@proxy.example:8080`,
        );
    for (const [username, password] of [
      [login, undefined],
      [undefined, secret],
      [login, ""],
      ["", secret],
      ["admin", secret],
      [`${login}\n`, secret],
      [`${login}\r\nX-Secret: value`, secret],
      [`${login}:password@elsewhere`, secret],
      [`${login}-device-native`, secret],
      [`${login}-ttl-18446744073709551616`, secret],
      [`${login}-ttl-01`, secret],
      [`${login}-pool-127.0.0.1`, secret],
      [`${login}-session-${"A".repeat(129)}`, secret],
      [login, "A".repeat(42)],
      [login, `${"A".repeat(42)}B`],
      [login, `${"A".repeat(42)}=`],
      [login, `${"A".repeat(42)}\n`],
      [login, `${secret}\n`],
    ])
      expect(() => connectionUrl(endpoint(), username, password)).toThrow(
        ApiError,
      );
  });

  it("exports the fixed MASQUE HTTPS URI template without credential userinfo", () => {
    const masque = { ...endpoint(), protocol: "masque" as const };
    expect(connectionUrl(masque)).toBe(
      "https://proxy.example:8080/.well-known/masque/udp/{target_host}/{target_port}/",
    );
    expect(connectionUrl({ ...masque, host: "::1", port: 443 })).toBe(
      "https://[::1]:443/.well-known/masque/udp/{target_host}/{target_port}/",
    );
    expect(() => connectionUrl(masque, login, secret)).toThrow(ApiError);
    expect(() => connectionUrl(masque, login)).toThrow(ApiError);
    expect(() => connectionUrl(masque, undefined, secret)).toThrow(ApiError);
  });
});
