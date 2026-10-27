import { useState } from "react";
import { createSampleNodes } from "../../data/samples";
import NodeDashboard from "./Dashboard";

export default function DemoNodes() {
  const [nodes, setNodes] = useState(createSampleNodes);
  return (
    <NodeDashboard
      nodes={nodes}
      onAdd={(node) => setNodes((current) => [...current, node])}
    />
  );
}
