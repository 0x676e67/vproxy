export default [
  { path: "/", redirect: "/nodes" },
  {
    path: "/nodes",
    name: "nodes",
    icon: "ClusterOutlined",
    component: "./Nodes",
  },
  { path: "/users", name: "users", icon: "TeamOutlined", component: "./Users" },
  {
    path: "/service",
    name: "service",
    icon: "ApiOutlined",
    component: "./Service",
  },
  {
    path: "/traffic",
    name: "traffic",
    icon: "AreaChartOutlined",
    component: "./Traffic",
  },
  {
    path: "/alerts",
    name: "alerts",
    icon: "AlertOutlined",
    component: "./Alerts",
  },
  {
    path: "/resources",
    name: "resources",
    icon: "DatabaseOutlined",
    component: "./Resources",
  },
  { path: "*", component: "./NotFound", layout: false },
];
