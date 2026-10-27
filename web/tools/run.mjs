/** Cross-platform Umi entry point: ambient/demo environment never changes build. */
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import {
  finalizeBuild,
  invalidateManifest,
  sourceInventory,
} from "./manifest.mjs";

/** Umi reads HOST from the environment; its dev CLI --host alone is insufficient. */
export function compilerEnvironment(command, mode, environment = process.env) {
  return {
    ...environment,
    VPROXY_WEB_MODE: mode,
    ...(command === "dev" ? { HOST: "127.0.0.1" } : {}),
  };
}

export async function run(command, mode) {
  if (!["dev", "build"].includes(command) || !["api", "demo"].includes(mode)) {
    throw new Error("Usage: node tools/run.mjs <dev|build> <api|demo>");
  }
  const webRoot = fileURLToPath(new URL("..", import.meta.url));
  const sources =
    command === "build" ? await sourceInventory(webRoot) : undefined;
  if (command === "build") await invalidateManifest(webRoot);
  const executable = path.join(
    webRoot,
    "node_modules",
    "@umijs",
    "max",
    "bin",
    "max.js",
  );
  const child = spawn(
    process.execPath,
    [
      executable,
      command,
      ...(command === "dev" ? ["--host", "127.0.0.1", "--port", "8000"] : []),
    ],
    {
      cwd: webRoot,
      env: compilerEnvironment(command, mode),
      stdio: "inherit",
      windowsHide: true,
    },
  );
  const interrupt = () => child.kill("SIGINT");
  const terminate = () => child.kill("SIGTERM");
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", terminate);
  try {
    await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code, signal) => {
        if (code === 0 && signal === null) resolve();
        else
          reject(
            new Error(
              `Web compiler failed (${signal ?? code ?? "unknown exit"})`,
            ),
          );
      });
    });
  } finally {
    process.removeListener("SIGINT", interrupt);
    process.removeListener("SIGTERM", terminate);
  }
  if (command === "build") await finalizeBuild(webRoot, mode, sources);
}

if (
  process.argv[1] &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  run(process.argv[2], process.argv[3]).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
