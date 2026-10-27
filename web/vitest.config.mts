import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  // Worktrees may share installed packages, but never mutable transform caches.
  cacheDir: fileURLToPath(new URL("../target/web-vitest", import.meta.url)),
  // Umi's renderer is ESM. Use the same conditional Router entry for direct
  // test imports; mixing its Node CJS and ESM entries creates two contexts.
  ssr: { resolve: { conditions: ["module", "node"] } },
  resolve: {
    alias: [
      {
        find: /^react-router-dom\/server$/,
        replacement: fileURLToPath(
          new URL("./src/routing/server.ts", import.meta.url),
        ),
      },
    ],
  },
  test: {
    environment: "node",
    setupFiles: ["./src/test/setup.ts"],
    // Each real Ant Design/jsdom worker retains a full component environment.
    // Serialize files instead of turning UI traversal contention into a longer
    // correctness-test deadline; request and test timeouts remain unchanged.
    maxWorkers: 1,
    // DOM-dependent interaction tests opt in per file; protocol/data tests keep
    // Node's globals rather than inheriting a simulated browser environment.
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
  },
});
