import path from "node:path";
import type { IApi } from "umi";

/** Keep Umi's existing history/Router bridge; only the removed server import
 * needs an adapter. All other imports use the single locked Router 7 pair.
 */
export default function router(api: IApi) {
  const entry = path.join(api.cwd, "src/routing/server.ts");
  const exactAliases = (config: IApi["config"]) => {
    const {
      "react-router": core,
      "react-router-dom": dom,
      ...aliases
    } = config.alias ?? {};
    return {
      ...config,
      // Umi's package-prefix aliases bypass package exports, breaking Router
      // 7's real /dom entry. Keep its chosen root paths, but match only roots.
      // The one removed /server entry is the only locally adapted subpath.
      alias: {
        "react-router-dom/server$": entry,
        ...(core ? { "react-router$": core } : {}),
        ...(dom ? { "react-router-dom$": dom } : {}),
        ...aliases,
      },
    };
  };
  // Umi merges defaults back after modifyConfig. Tighten both maps so that
  // deep merge cannot restore the package-prefix aliases removed above.
  api.modifyDefaultConfig(exactAliases);
  api.modifyConfig(exactAliases);
  api.modifyTSConfig((config) => ({
    ...config,
    compilerOptions: {
      ...config.compilerOptions,
      paths: {
        ...config.compilerOptions.paths,
        "react-router-dom/server": [entry],
      },
    },
  }));
}
