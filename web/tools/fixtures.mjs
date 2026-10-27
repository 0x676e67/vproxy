/** Private, randomly named trees shared by the Node/build-script fixture tests. */
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

export async function fixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), "vproxy-web-build-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const web = path.join(root, "web");
  for (const directory of ["config", "src", "tools", "dist"]) {
    await mkdir(path.join(web, directory), { recursive: true });
  }
  for (const file of [
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "vitest.config.mts",
    "LICENSE.ant-design-pro",
  ]) {
    await writeFile(path.join(web, file), `fixture ${file}\n`);
  }
  await writeFile(path.join(web, "config/config.ts"), "export default {};\n");
  await writeFile(
    path.join(web, "src/index.tsx"),
    "export const greeting = 'hello';\n",
  );
  await writeFile(
    path.join(web, "tools/run.mjs"),
    "// fixture compiler wrapper\n",
  );
  await writeFile(
    path.join(web, "dist/index.html"),
    "<!doctype html><title>Fixture</title>\n",
  );
  await writeFile(path.join(web, "dist/app.js"), "console.log('fixture');\n");
  await writeFile(path.join(web, "dist/app.css"), "body{color:#123456}\n");
  await writeFile(
    path.join(web, "dist/icon.svg"),
    '<svg xmlns="http://www.w3.org/2000/svg"/>\n',
  );
  await writeFile(path.join(web, "dist/data.json"), '{"fixture":true}\n');
  await writeFile(path.join(web, "dist/icon.png"), Buffer.from([0, 1, 2, 3]));
  return { root, web };
}
