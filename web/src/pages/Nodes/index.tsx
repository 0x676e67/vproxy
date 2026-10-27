import { lazy, Suspense } from "react";
import { Spin } from "antd";
import LiveNodes from "./LiveNodes";

// The production graph drops the sample module; runtime URL parameters cannot enable it.
const DemoNodes = __VPROXY_DEMO__ ? lazy(() => import("./DemoNodes")) : null;

export default function NodesPage() {
  return __VPROXY_DEMO__ && DemoNodes ? (
    <Suspense fallback={<Spin />}>
      <DemoNodes />
    </Suspense>
  ) : (
    <LiveNodes />
  );
}
