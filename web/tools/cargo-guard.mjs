/** Bind the guard fixture to this successful native Cargo test invocation. */
import { spawn, spawnSync } from "node:child_process";
import { constants } from "node:fs";
import { access, lstat } from "node:fs/promises";
import path from "node:path";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath, pathToFileURL } from "node:url";

const webRoot = fileURLToPath(new URL("..", import.meta.url));
const root = path.dirname(webRoot.replace(/[\\/]$/u, ""));
const programName = `build-script-build${process.platform === "win32" ? ".exe" : ""}`;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function absolute(value) {
  requireValue(
    typeof value === "string" &&
      path.isAbsolute(value) &&
      !/[\u0000-\u001f\u007f]/u.test(value),
    "Cargo supplied an invalid absolute path",
  );
  return path.normalize(value);
}

function samePath(left, right) {
  const normalize = (value) => {
    const normalized = absolute(value);
    return process.platform === "win32" ? normalized.toLowerCase() : normalized;
  };
  return normalize(left) === normalize(right);
}

function customBuild(target, source) {
  return (
    target?.kind?.length === 1 &&
    target.kind[0] === "custom-build" &&
    target.crate_types?.length === 1 &&
    target.crate_types[0] === "bin" &&
    target.name === "build-script-build" &&
    samePath(target.src_path, source)
  );
}

/** Package IDs stay opaque; metadata must describe this checkout, not a peer. */
export function packageContext(metadata, repository) {
  const manifest = path.join(absolute(repository), "Cargo.toml");
  const source = path.join(repository, "build.rs");
  requireValue(metadata?.version === 1, "Unsupported Cargo metadata format");
  requireValue(Array.isArray(metadata.packages), "Missing Cargo packages");
  const packages = metadata.packages.filter((item) =>
    samePath(item.manifest_path, manifest),
  );
  requireValue(packages.length === 1, "Expected one current Cargo package");
  const current = packages[0];
  requireValue(
    current.name === "vproxy" &&
      current.source === null &&
      typeof current.id === "string" &&
      current.id.length > 0 &&
      metadata.workspace_members?.includes(current.id),
    "Cargo metadata does not identify the local vproxy package",
  );
  const targets = current.targets?.filter((item) =>
    item.kind?.includes("custom-build"),
  );
  requireValue(
    targets?.length === 1 && customBuild(targets[0], source),
    "Expected the current package's build.rs target",
  );
  return {
    packageId: current.id,
    name: current.name,
    manifest,
    source,
    targetDirectory: absolute(metadata.target_directory),
  };
}

function buildPath(context, value, basename) {
  const normalized = absolute(value);
  const relative = path.relative(
    path.join(context.targetDirectory, "debug", "build"),
    normalized,
  );
  const pieces = relative.split(path.sep);
  requireValue(
    !path.isAbsolute(relative) &&
      pieces.length === 2 &&
      pieces[0].startsWith(`${context.name}-`) &&
      pieces[0].length > context.name.length + 1 &&
      pieces[1] === basename,
    "Cargo build-script path is outside the current native package output",
  );
  return normalized;
}

/** No target scan: only records emitted before build-finished in this run count. */
export function selectGuard(context, messages, code, signal = null) {
  requireValue(
    code === 0 && signal === null,
    "Cargo test did not exit successfully",
  );
  const finished = messages.filter((item) => item.reason === "build-finished");
  requireValue(
    finished.length === 1 &&
      finished[0].success === true &&
      messages.at(-1) === finished[0],
    "Cargo did not report one successful completed build",
  );
  const artifacts = messages.filter(
    (item) =>
      item.reason === "compiler-artifact" &&
      item.package_id === context.packageId &&
      item.target?.kind?.includes("custom-build"),
  );
  requireValue(
    artifacts.length === 1,
    "Expected one current build-script artifact",
  );
  const artifact = artifacts[0];
  requireValue(
    samePath(artifact.manifest_path, context.manifest) &&
      customBuild(artifact.target, context.source) &&
      Array.isArray(artifact.features) &&
      artifact.features.every((item) => typeof item === "string") &&
      artifact.features.includes("web-ui") &&
      !artifact.features.some((item) =>
        ["ebpf", "ebpf-program"].includes(item),
      ) &&
      artifact.profile?.test === false &&
      typeof artifact.fresh === "boolean",
    "Current build-script artifact is not the Web-only guard target",
  );
  requireValue(
    Array.isArray(artifact.filenames),
    "Missing build-script filenames",
  );
  const programs = artifact.filenames.filter(
    (file) => path.basename(absolute(file)) === programName,
  );
  requireValue(programs.length === 1, "Expected one host build-script program");
  const executable = buildPath(context, programs[0], programName);
  requireValue(
    artifact.executable === null || samePath(artifact.executable, executable),
    "Conflicting Cargo executable metadata",
  );
  const executions = messages.filter(
    (item) =>
      item.reason === "build-script-executed" &&
      item.package_id === context.packageId,
  );
  requireValue(
    executions.length === 1,
    "Expected one current build-script execution record",
  );
  // Cargo can reuse both records. Its run-directory suffix need not equal the
  // compiler-artifact suffix; neither record proves build.rs was freshly run.
  buildPath(context, executions[0].out_dir, "out");
  return executable;
}

/** Retain only bounded control records; render diagnostics and test text live. */
export function cargoOutput(context, emit) {
  const records = [];
  let finished = false;
  return {
    records,
    line(line) {
      if (finished) {
        emit(`${line}\n`);
        return;
      }
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        emit(`${line}\n`);
        return;
      }
      if (message?.reason === "compiler-message") {
        if (typeof message.message?.rendered === "string")
          emit(message.message.rendered);
      } else if (
        message?.reason === "build-finished" ||
        (message?.package_id === context.packageId &&
          (message.reason === "build-script-executed" ||
            (message.reason === "compiler-artifact" &&
              message.target?.kind?.includes("custom-build"))))
      ) {
        requireValue(
          records.length < 16,
          "Too many Cargo build-script records",
        );
        records.push(message);
        if (message.reason === "build-finished") finished = true;
      } else if (
        !["compiler-artifact", "build-script-executed"].includes(
          message?.reason,
        )
      ) {
        emit(`${line}\n`);
      }
    },
  };
}

async function childExit(child) {
  const interrupt = () => child.kill("SIGINT");
  const terminate = () => child.kill("SIGTERM");
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", terminate);
  try {
    return await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
  } finally {
    process.removeListener("SIGINT", interrupt);
    process.removeListener("SIGTERM", terminate);
  }
}

export async function run(arguments_ = []) {
  requireValue(
    arguments_.length === 0 ||
      (arguments_.length === 1 && arguments_[0] === "--offline"),
    "Usage: node web/tools/cargo-guard.mjs [--offline]",
  );
  const offline = arguments_.length ? ["--offline"] : [];
  const manifest = path.join(root, "Cargo.toml");
  const metadata = spawnSync(
    "cargo",
    [
      "metadata",
      "--no-deps",
      "--locked",
      "--format-version",
      "1",
      "--manifest-path",
      manifest,
      ...offline,
    ],
    {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
      timeout: 60_000,
      windowsHide: true,
      stdio: ["ignore", "pipe", "inherit"],
    },
  );
  if (metadata.error) throw metadata.error;
  requireValue(
    metadata.status === 0 && metadata.signal === null,
    "Cargo metadata failed",
  );
  const context = packageContext(JSON.parse(metadata.stdout), root);
  const output = cargoOutput(context, (text) => process.stdout.write(text));
  const child = spawn(
    "cargo",
    [
      "test",
      "--locked",
      "--no-default-features",
      "--features",
      "web-ui",
      "--message-format=json",
      "--manifest-path",
      manifest,
      ...offline,
    ],
    { cwd: root, windowsHide: true, stdio: ["inherit", "pipe", "inherit"] },
  );
  const decoder = new StringDecoder("utf8");
  let pending = "";
  let outputError;
  const receive = (text) => {
    if (outputError) return;
    try {
      pending += text;
      requireValue(
        pending.length <= 2 * 1024 * 1024,
        "Cargo stdout line exceeds limit",
      );
      let newline;
      while ((newline = pending.indexOf("\n")) !== -1) {
        output.line(pending.slice(0, newline).replace(/\r$/u, ""));
        pending = pending.slice(newline + 1);
      }
    } catch (error) {
      outputError = error;
      child.kill("SIGTERM");
    }
  };
  child.stdout.on("data", (chunk) => receive(decoder.write(chunk)));
  child.stdout.on("error", (error) => {
    outputError ??= error;
    child.kill("SIGTERM");
  });
  const result = await childExit(child);
  receive(decoder.end());
  if (pending && !outputError) output.line(pending);
  if (outputError) throw outputError;
  const executable = selectGuard(
    context,
    output.records,
    result.code,
    result.signal,
  );
  const file = await lstat(executable);
  requireValue(
    file.isFile() && !file.isSymbolicLink(),
    "Guard artifact is not a regular file",
  );
  await access(executable, constants.X_OK);
  console.log("Web build guard:", executable);
  const guard = spawn(process.execPath, ["--test", "tools/guard.test.mjs"], {
    cwd: webRoot,
    windowsHide: true,
    stdio: "inherit",
    env: { ...process.env, VPROXY_WEB_BUILD_GUARD: executable },
  });
  const checked = await childExit(guard);
  requireValue(
    checked.code === 0 && checked.signal === null,
    "Compiled Web build-guard fixture failed",
  );
  console.log(
    "Current Cargo invocation and compiled Web build-guard fixture passed",
  );
}

if (
  process.argv[1] &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  run(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
