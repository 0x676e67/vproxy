// Ant Design Pro's Umi Max skeleton, reduced to node management.
// Upstream attribution is retained in ../LICENSE.ant-design-pro.
import { defineConfig } from "@umijs/max";
import defaultSettings from "./defaultSettings";
import routes from "./routes";
import { consolePalette, consoleTokens } from "./theme";

export default defineConfig({
  plugins: ["./config/router.ts"],
  // Demo data is an explicit build choice, never a URL or API-error fallback.
  define: { __VPROXY_DEMO__: process.env.VPROXY_WEB_MODE === "demo" },
  hash: true,
  // Keep minifier helpers scoped to each lazy chunk; Umi checks for collisions.
  esbuildMinifyIIFE: true,
  history: { type: "hash" },
  publicPath: process.env.NODE_ENV === "production" ? "./" : "/",
  routes,
  title: "vproxy",
  // Do not inherit the template's zoom restriction on mobile and low-vision use.
  metas: [
    {
      name: "viewport",
      content: "width=device-width, initial-scale=1, viewport-fit=cover",
    },
    { name: "theme-color", content: consolePalette.canvas },
  ],
  fastRefresh: true,
  layout: { locale: true, ...defaultSettings },
  locale: {
    default: "zh-CN",
    baseNavigator: false,
    antd: true,
    title: false,
  },
  antd: {
    appConfig: {},
    configProvider: {
      theme: {
        token: consoleTokens(),
      },
    },
  },
  // Real mode uses only the same-origin HTTPS API; no mock transport is enabled.
  mock: false,
  npmClient: "npm",
});
