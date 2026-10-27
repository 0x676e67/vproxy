/**
 * Run against an already compiled feature-enabled build.rs executable. This
 * fixture suite never runs Cargo/npm or touches the real dist tree.
 * VPROXY_WEB_BUILD_GUARD must name the trusted current Web-enabled build script
 * by absolute path; it is not manifest metadata or a PATH lookup.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fixture } from "./fixtures.mjs";
import { finalizeBuild, sourceInventory } from "./manifest.mjs";

const guard = process.env.VPROXY_WEB_BUILD_GUARD;

test("Cargo build guard accepts only complete current API assets", async (t) => {
  assert.ok(
    typeof guard === "string" && path.isAbsolute(guard),
    "VPROXY_WEB_BUILD_GUARD must be an absolute path to the compiled Web build guard",
  );
  const { root, web } = await fixture(t);
  const run = (expectedStatus) => {
    const result = spawnSync(guard, [], {
      env: {
        ...process.env,
        CARGO_MANIFEST_DIR: root,
        CARGO_FEATURE_WEB_UI: "1",
      },
      encoding: "utf8",
      timeout: 10_000,
      windowsHide: true,
    });
    assert.ifError(result.error);
    assert.equal(result.signal, null, "guard must exit without a signal");
    assert.ok(
      Number.isInteger(result.status),
      "guard must have an exit status",
    );
    // Rust main returns io::Result: rejection exits 1, not a crash/loader code.
    assert.equal(result.status, expectedStatus);
  };
  await t.test("rejects a missing manifest", () => run(1));
  await finalizeBuild(web, "api", await sourceInventory(web));
  await t.test("accepts complete current API assets", () => run(0));
  const manifestFile = path.join(web, "dist/vproxy-web.json");
  const manifest = await readFile(manifestFile, "utf8");
  const demo = JSON.parse(manifest);
  demo.mode = "demo";
  await writeFile(manifestFile, JSON.stringify(demo));
  await t.test("rejects a demo bundle", () => run(1));
  await writeFile(manifestFile, manifest);
  const app = path.join(web, "dist/app.js");
  const original = await readFile(app);
  await writeFile(app, "wrong bytes\n");
  await t.test("rejects modified asset bytes", () => run(1));
  await writeFile(app, original);
  const source = path.join(web, "src/index.tsx");
  const originalSource = await readFile(source);
  await writeFile(source, "stale source\n");
  await t.test("rejects stale source bytes", () => run(1));
  await writeFile(source, originalSource);
  await writeFile(path.join(web, "dist/extra.js"), "extra\n");
  await t.test("rejects an extra asset", () => run(1));
  await rm(path.join(web, "dist/extra.js"));
  await rm(path.join(web, "dist/app.js.br"));
  await t.test("rejects a missing compressed asset", () => run(1));
});
