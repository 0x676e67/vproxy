import type {
  ServiceChange,
  ServiceConfiguration,
  ServiceStatus,
} from "./proxyService";
import { JOB, LOCAL } from "./maintenance.fixtures";
export const serviceConfig = (): ServiceConfiguration => ({
  listeners: [
    {
      protocol: "https",
      bind: "0.0.0.0:18443",
      public_address: "manager.example:18443",
    },
  ],
  workers: 1,
  concurrent: 1024,
  connect_timeout: 10,
});
export const serviceFixture = (): ServiceStatus => ({
  node_id: LOCAL,
  mode: "web",
  saved: { revision: "1", enabled: false, configuration: null },
  runtime: {
    generation: "0",
    configuration_revision: null,
    state: "stopped",
    error: null,
    listeners: [],
  },
});
export const serviceInput = (): ServiceChange => ({
  expected_node_id: LOCAL,
  expected_revision: "1",
  controller_epoch: "2",
  request_id: JOB,
  enabled: true,
  configuration: serviceConfig(),
});
