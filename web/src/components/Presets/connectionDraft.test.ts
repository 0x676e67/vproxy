import { describe, expect, it } from "vitest";
import { readConnectionDraft, writeConnectionDraft } from "./connectionDraft";

const scope = {
  administrator: "A".repeat(22),
  node: "Q".repeat(22),
  user: "g".repeat(22),
  credential: "w".repeat(22),
};
const value = {
  endpoint: "manual",
  host: "proxy.example",
  port: "1080",
  protocol: "socks5" as const,
};
function browserStorage() {
  const data = new Map<string, string>();
  return {
    data,
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => void data.set(key, value),
  };
}

describe("non-secret connection preferences", () => {
  it("retains only endpoint fields and isolates administrators, nodes, users and credentials", () => {
    const storage = browserStorage();
    expect(
      writeConnectionDraft(
        scope,
        {
          ...value,
          ...{
            password: "do-not-store",
            username: "do-not-store",
            route_value: "do-not-store",
          },
        },
        storage,
      ),
    ).toBe("saved");
    expect([...storage.data.values()]).toEqual([JSON.stringify(value)]);
    expect(readConnectionDraft(scope, storage)).toEqual({
      value,
      unavailable: false,
    });
    for (const field of [
      "administrator",
      "node",
      "user",
      "credential",
    ] as const)
      expect(
        readConnectionDraft(
          { ...scope, [field]: "A".repeat(21) + "Q" },
          storage,
        ),
      ).toEqual({
        value: null,
        unavailable: false,
      });
  });

  it("does not replace the last complete address with partial edits, URLs, userinfo or incompatible ports", () => {
    const storage = browserStorage();
    writeConnectionDraft(scope, value, storage);
    for (const edit of [
      { host: "" },
      { port: "" },
      { port: "65536" },
      { port: "0" },
      { host: "https://proxy.example" },
      { host: "user:password@proxy.example" },
      { endpoint: undefined },
      { endpoint: "16:http" },
      { host: "0.0.0.0" },
    ]) {
      expect(writeConnectionDraft(scope, { ...value, ...edit }, storage)).toBe(
        "incomplete",
      );
      expect(readConnectionDraft(scope, storage).value).toEqual(value);
    }
  });

  it("ignores corrupt, oversized, extra-field and unsupported saved data", () => {
    const storage = browserStorage();
    writeConnectionDraft(scope, value, storage);
    const key = [...storage.data.keys()][0];
    for (const corrupt of [
      "{",
      "x".repeat(1025),
      "null",
      JSON.stringify({ ...value, secret: "do-not-read" }),
      JSON.stringify({ ...value, protocol: "quic" }),
      JSON.stringify({ ...value, port: 1080 }),
    ]) {
      storage.data.set(key, corrupt);
      expect(readConnectionDraft(scope, storage)).toEqual({
        value: null,
        unavailable: false,
      });
    }
  });

  it("reports blocked or quota-limited storage without making the form unusable", () => {
    const storage = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("quota");
      },
    };
    expect(readConnectionDraft(scope, storage)).toEqual({
      value: null,
      unavailable: true,
    });
    expect(writeConnectionDraft(scope, value, storage)).toBe("unavailable");
  });
});
