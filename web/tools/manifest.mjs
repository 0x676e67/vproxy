/**
 * Build provenance, not a signature or a substitute for trusted source/deps.
 * Inventory keys are portable relative paths; host paths and build times never
 * enter the document. Symlinks/nonregular files are rejected instead of followed.
 */
import { createHash } from "node:crypto";
import { lstat, readdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { brotliCompress, constants, gzip } from "node:zlib";
import { promisify } from "node:util";

export const MANIFEST_NAME = "vproxy-web.json";
const ROOT_SOURCES = [
  "package.json",
  "package-lock.json",
  "tsconfig.json",
  "vitest.config.mts",
  "LICENSE.ant-design-pro",
];
const SOURCE_DIRECTORIES = ["config", "src", "tools", "public"];
const COMPRESSIBLE = new Set([
  ".js",
  ".mjs",
  ".css",
  ".html",
  ".svg",
  ".json",
  ".txt",
  ".xml",
  ".webmanifest",
  ".wasm",
]);
const compressBrotli = promisify(brotliCompress);
const compressGzip = promisify(gzip);
const MAX_DEPTH = 32;
const MAX_FILES = 20_000;
const MAX_FILE_BYTES = 256 * 1024 * 1024;

/** Validate an inventory key before joining it to any local directory. */
export function validateRelative(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\\") ||
    value.includes(":") ||
    /\p{Cc}/u.test(value) ||
    value
      .split("/")
      .some((part) => part === "" || part === "." || part === "..")
  ) {
    throw new Error("Build inventory contains a non-portable relative path");
  }
  return value;
}

/** lstat deliberately does not follow a substituted leaf or directory symlink. */
async function regularFile(file) {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(
      "Build inputs and assets must be regular non-symlink files",
    );
  }
  if (!Number.isSafeInteger(stat.size) || stat.size > MAX_FILE_BYTES) {
    throw new Error("Build file exceeds the supported size limit");
  }
  return stat;
}

/**
 * Enumerate only the selected tree. Generated .umi* directories do not describe
 * sources, but every other source is included, including tests and build tools.
 */
async function walk(root, excludeGenerated = false, optional = false) {
  let rootStat;
  try {
    rootStat = await lstat(root);
  } catch (error) {
    if (optional && error.code === "ENOENT") return [];
    throw error;
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error("Build trees must be regular non-symlink directories");
  }
  const files = [];
  async function visit(directory, relative, depth) {
    if (depth > MAX_DEPTH)
      throw new Error("Build tree exceeds its depth limit");
    for (const entry of (await readdir(directory)).sort()) {
      const absolute = path.join(directory, entry);
      const key = validateRelative(relative ? `${relative}/${entry}` : entry);
      const stat = await lstat(absolute);
      if (stat.isSymbolicLink()) {
        throw new Error("Build trees must not contain symlinks");
      }
      if (stat.isDirectory()) {
        if (excludeGenerated && entry.startsWith(".umi")) continue;
        await visit(absolute, key, depth + 1);
      } else {
        await regularFile(absolute);
        files.push(key);
        if (files.length > MAX_FILES)
          throw new Error("Build tree exceeds its file limit");
      }
    }
  }
  await visit(root, "", 0);
  return files.sort();
}

async function fingerprint(file) {
  const before = await regularFile(file);
  const bytes = await readFile(file);
  const after = await regularFile(file);
  if (
    bytes.length !== before.size ||
    after.size !== before.size ||
    after.mtimeMs !== before.mtimeMs
  ) {
    throw new Error(
      "Build file changed while being fingerprinted; rebuild from stable sources",
    );
  }
  return {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: bytes.length,
  };
}

function sortedInventory(entries) {
  if (entries.length > MAX_FILES) {
    throw new Error("Build inventory exceeds its file limit");
  }
  const names = new Set();
  for (const [name] of entries) {
    const portable = name.toLowerCase();
    if (names.has(portable))
      throw new Error("Build inventory has case-colliding paths");
    names.add(portable);
  }
  return Object.fromEntries(
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
}

/** Take a deterministic snapshot of all inputs that can invalidate a bundle. */
export async function sourceInventory(webRoot) {
  const stat = await lstat(webRoot);
  if (!stat.isDirectory() || stat.isSymbolicLink())
    throw new Error("Invalid Web source directory");
  const files = [...ROOT_SOURCES];
  for (const directory of SOURCE_DIRECTORIES) {
    for (const file of await walk(
      path.join(webRoot, directory),
      true,
      directory === "public",
    )) {
      files.push(`${directory}/${file}`);
    }
  }
  const entries = [];
  for (const file of files) {
    const key = validateRelative(`web/${file}`);
    entries.push([key, await fingerprint(path.join(webRoot, file))]);
  }
  return sortedInventory(entries);
}

/**
 * Remove only the old regular manifest before a compiler starts. A failed build
 * must not leave a provenance document that certifies an earlier dist directory.
 */
export async function invalidateManifest(webRoot) {
  const dist = path.join(webRoot, "dist");
  try {
    const stat = await lstat(dist);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      throw new Error("Invalid Web output directory");
    const file = path.join(dist, MANIFEST_NAME);
    await regularFile(file);
    await unlink(file);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

/**
 * Precompress public text/wasm assets and bind their actual bytes to schema 1.
 * Expected sources must be captured before the compiler runs: concurrent edits
 * cannot be relabeled as though they were used by the completed compilation.
 * The manifest is not itself compressed or included in its own asset inventory.
 */
export async function finalizeBuild(webRoot, mode, expectedSources) {
  if (mode !== "api" && mode !== "demo")
    throw new Error("Unknown Web build mode");
  const sources = await sourceInventory(webRoot);
  if (
    !expectedSources ||
    JSON.stringify(expectedSources) !== JSON.stringify(sources)
  ) {
    throw new Error(
      "Web sources changed during build; rerun the build after edits finish",
    );
  }
  const dist = path.join(webRoot, "dist");
  const files = await walk(dist);
  if (!files.includes("index.html"))
    throw new Error("Web build is missing index.html");
  const baseFiles = files.filter(
    (file) => file !== MANIFEST_NAME && !/\.(?:br|gz)$/u.test(file),
  );
  for (const file of files.filter((name) => /\.(?:br|gz)$/u.test(name))) {
    const original = file.replace(/\.(?:br|gz)$/u, "");
    if (
      !baseFiles.includes(original) ||
      !COMPRESSIBLE.has(path.posix.extname(original))
    ) {
      throw new Error(
        "Web build contains an orphan or unsupported compressed asset",
      );
    }
  }
  for (const file of baseFiles) {
    if (!COMPRESSIBLE.has(path.posix.extname(file))) continue;
    const bytes = await readFile(path.join(dist, file));
    const brotli = await compressBrotli(bytes, {
      params: { [constants.BROTLI_PARAM_QUALITY]: 11 },
    });
    const zipped = await compressGzip(bytes, { level: 9 });
    for (const [suffix, compressed] of [
      ["br", brotli],
      ["gz", zipped],
    ]) {
      const output = path.join(dist, `${file}.${suffix}`);
      // Recreate exclusively: even a leaf replaced after enumeration must not
      // turn a generated .br/.gz write into a write through a symlink.
      try {
        await regularFile(output);
        await unlink(output);
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      await writeFile(output, compressed, { flag: "wx" });
    }
  }
  const entries = [];
  for (const file of await walk(dist)) {
    if (file !== MANIFEST_NAME)
      entries.push([file, await fingerprint(path.join(dist, file))]);
  }
  const manifest = {
    schema: 1,
    mode,
    sources,
    assets: sortedInventory(entries),
  };
  await writeFile(
    path.join(dist, MANIFEST_NAME),
    `${JSON.stringify(manifest, null, 2)}\n`,
    { flag: "wx" },
  );
  return manifest;
}
