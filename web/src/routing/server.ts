// Umi 4 imports the old /server subpath; Router 7 moved these public exports
// to its root. This adapter does not create a second router or enable SSR.
// https://github.com/remix-run/react-router/blob/react-router%407.18.4/packages/react-router/index.ts#L202-L211
export { StaticRouter, type StaticRouterProps } from "react-router";
