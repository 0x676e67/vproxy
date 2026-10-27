import assert from "node:assert/strict";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { brotliDecompressSync, gunzipSync } from "node:zlib";
import {
  finalizeBuild,
  invalidateManifest,
  sourceInventory,
  validateRelative,
} from "./manifest.mjs";
import { fixture } from "./fixtures.mjs";
import { compilerEnvironment } from "./run.mjs";

test("compiler mode is explicit and development always binds loopback", () => {
  const ambient = {
    VPROXY_WEB_MODE: "demo",
    HOST: "0.0.0.0",
    CUSTOM: "retained",
  };
  assert.deepEqual(compilerEnvironment("dev", "api", ambient), {
    VPROXY_WEB_MODE: "api",
    HOST: "127.0.0.1",
    CUSTOM: "retained",
  });
  assert.equal(compilerEnvironment("dev", "demo", ambient).HOST, "127.0.0.1");
  assert.equal(
    compilerEnvironment("build", "api", ambient).VPROXY_WEB_MODE,
    "api",
  );
  assert.equal(
    compilerEnvironment("build", "demo", ambient).VPROXY_WEB_MODE,
    "demo",
  );
});

test("portable inventory paths reject traversal, host paths and control bytes", () => {
  for (const invalid of [
    "",
    "/index.html",
    "../index.html",
    "a/../b",
    "a//b",
    "a\\b",
    "C:/web/index.html",
    "a\u0000b",
  ]) {
    assert.throws(() => validateRelative(invalid));
  }
  assert.equal(validateRelative("chunks/app.123.js"), "chunks/app.123.js");
});

test("source inventory covers config/tools/public and excludes generated Umi trees", async (t) => {
  const { web } = await fixture(t);
  await mkdir(path.join(web, "src/.umi-production"));
  await writeFile(
    path.join(web, "src/.umi-production/generated.ts"),
    "generated first\n",
  );
  const initial = await sourceInventory(web);
  assert.ok(initial["web/package-lock.json"]);
  assert.ok(initial["web/tsconfig.json"]);
  assert.ok(initial["web/vitest.config.mts"]);
  assert.ok(initial["web/config/config.ts"]);
  assert.ok(initial["web/tools/run.mjs"]);
  assert.ok(!Object.keys(initial).some((file) => file.includes(".umi")));
  await writeFile(
    path.join(web, "src/.umi-production/generated.ts"),
    "generated second\n",
  );
  assert.deepEqual(await sourceInventory(web), initial);
  await mkdir(path.join(web, "public"));
  await writeFile(
    path.join(web, "public/robots.txt"),
    "User-agent: *\nDisallow: /\n",
  );
  assert.ok((await sourceInventory(web))["web/public/robots.txt"]);
});

test("API and demo manifests contain deterministic hashes and real compressed variants", async (t) => {
  const { web } = await fixture(t);
  const sources = await sourceInventory(web);
  const manifest = await finalizeBuild(web, "api", sources);
  assert.equal(manifest.schema, 1);
  assert.equal(manifest.mode, "api");
  assert.ok(!manifest.assets["vproxy-web.json"]);
  for (const name of [
    "index.html",
    "app.js",
    "app.css",
    "icon.svg",
    "data.json",
  ]) {
    const original = await readFile(path.join(web, "dist", name));
    assert.deepEqual(
      brotliDecompressSync(
        await readFile(path.join(web, "dist", `${name}.br`)),
      ),
      original,
    );
    assert.deepEqual(
      gunzipSync(await readFile(path.join(web, "dist", `${name}.gz`))),
      original,
    );
    for (const suffix of ["", ".br", ".gz"]) {
      const entry = manifest.assets[`${name}${suffix}`];
      assert.match(entry.sha256, /^[a-f0-9]{64}$/u);
      assert.ok(Number.isSafeInteger(entry.size));
    }
  }
  assert.ok(manifest.assets["icon.png"]);
  assert.ok(!manifest.assets["icon.png.br"]);
  assert.ok(!manifest.assets["vproxy-web.json.br"]);
  await invalidateManifest(web);
  assert.deepEqual(await finalizeBuild(web, "api", sources), manifest);
  await invalidateManifest(web);
  assert.equal((await finalizeBuild(web, "demo", sources)).mode, "demo");
});

test("concurrent source edits and missing entry point fail without certifying dist", async (t) => {
  const { web } = await fixture(t);
  const sources = await sourceInventory(web);
  await writeFile(
    path.join(web, "src/index.tsx"),
    "changed while compiler ran\n",
  );
  await assert.rejects(finalizeBuild(web, "api", sources), /sources changed/u);
  await rm(path.join(web, "dist/index.html"));
  await assert.rejects(
    finalizeBuild(web, "api", await sourceInventory(web)),
    /missing index/u,
  );
  await assert.rejects(readFile(path.join(web, "dist/vproxy-web.json")), {
    code: "ENOENT",
  });
});

test("symlink sources and output files are rejected without following their targets", async (t) => {
  const { web } = await fixture(t);
  const target = path.join(web, "src/index.tsx");
  const link = path.join(web, "src/alias.tsx");
  try {
    await symlink(target, link, "file");
  } catch (error) {
    if (["EPERM", "EACCES"].includes(error.code)) {
      t.skip("Creating test symlinks requires platform privileges");
      return;
    }
    throw error;
  }
  await assert.rejects(sourceInventory(web), /symlinks/u);
  await rm(link);
  const sources = await sourceInventory(web);
  await symlink(target, path.join(web, "dist/alias.js"), "file");
  await assert.rejects(finalizeBuild(web, "api", sources), /symlinks/u);
  assert.equal(
    await readFile(target, "utf8"),
    "export const greeting = 'hello';\n",
  );
});
