import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import enUS from "./en-US";
import zhCN from "./zh-CN";
import { healthOutcomes } from "../api/health";
import { alertCodes, alertKinds, alertStatuses } from "../api/alerts";
import { checkpointStages, trafficSourceStates } from "../api/traffic";
import { presetBackendStates } from "../api/presets";
import { acmeActivities, acmeFailures } from "../api/acme";

const catalogs: Record<string, Record<string, string>> = {
  "zh-CN": zhCN,
  "en-US": enUS,
};
const argumentsIn = (value: string) =>
  [
    ...new Set([...value.matchAll(/\{(\w+)\s*[,}]/g)].map((match) => match[1])),
  ].sort();

function sourcesIn(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name.startsWith(".") || entry.name === "locales") return [];
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourcesIn(path);
    return /\.tsx?$/.test(path) && !path.endsWith(".test.ts")
      ? [readFileSync(path, "utf8")]
      : [];
  });
}

describe("bilingual interface contract", () => {
  it("covers the same messages and interpolation inputs in both languages", () => {
    expect(Object.keys(enUS).sort()).toEqual(Object.keys(zhCN).sort());
    for (const [key, message] of Object.entries(zhCN)) {
      expect(argumentsIn(enUS[key as keyof typeof enUS]), key).toEqual(
        argumentsIn(message),
      );
    }
  });

  it("covers static source labels as well as dynamic node states and regions", () => {
    const directory = dirname(fileURLToPath(import.meta.url));
    const sources = sourcesIn(join(directory, "..")).join("\n");
    const staticKeys = [
      // An arbitrary data object's `id` is not an intl message descriptor.
      ...sources.matchAll(
        /(?:\bt\(\s*|\bformatMessage\(\s*\{\s*id:\s*)['"]([\w.]+)['"]/g,
      ),
    ].map((match) => match[1]);
    const dynamicKeys = [
      "menu.nodes",
      "menu.resources",
      "menu.traffic",
      "menu.alerts",
      ...alertCodes.map((code) => `alerts.code.${code}`),
      ...alertKinds.map((kind) => `alerts.kind.${kind}`),
      ...alertStatuses.map((status) => `alerts.status.${status}`),
      ...presetBackendStates.map((state) => `presets.backend.${state}`),
      ...acmeActivities.map((state) => `acme.activity.${state}`),
      ...acmeFailures.map((failure) => `acme.failure.${failure}`),
      ...["staging", "production"].map((value) => `acme.environment.${value}`),
      ...[
        "not_configured",
        "feature_disabled",
        "platform_unsupported",
        "proxy_unavailable",
      ].map((reason) => `presets.reason.${reason}`),
      ...[
        "http_forward",
        "http_connect",
        "socks5_connect",
        "socks5_bind",
        "socks5_udp",
        "masque_udp",
      ].map((operation) => `presets.${operation}`),
      ...["default", "exit", "pool", "session", "range", "ttl"].map(
        (route) => `presets.route.${route}`,
      ),
      ...trafficSourceStates.map((state) => `traffic.source.${state}`),
      ...checkpointStages.map((stage) => `traffic.checkpointStage.${stage}`),
      ...["node", "user", "credential", "pool", "minute", "hour", "day"].map(
        (value) => `traffic.${value}`,
      ),
      ...healthOutcomes.map((outcome) => `resources.${outcome}`),
      ...[
        "prefixes",
        "addresses",
        "pools",
        "registered",
        "active",
        "draining",
        "retired",
      ].map((state) => `resources.${state}`),
      ...["connected", "disconnected", "pending", "running", "unknown"].map(
        (state) => `node.${state}`,
      ),
      ...[
        "hongKong",
        "tokyo",
        "singapore",
        "losAngeles",
        "frankfurt",
        "osaka",
      ].map((region) => `region.${region}`),
    ];
    for (const [locale, catalog] of Object.entries(catalogs)) {
      for (const key of [...staticKeys, ...dynamicKeys]) {
        expect(catalog[key], `${locale}: ${key}`).toBeTypeOf("string");
      }
    }
  });
});
