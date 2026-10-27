import type { AlertPage, EgressAlertPage, OperationAlert } from "./alerts";
import type { NodeAlertPage } from "./nodeAlerts";

export const ALERT_NODE = "A".repeat(22);
export const ALERT_RESOURCE = "AQEBAQEBAQEBAQEBAQEBAQ";
export const ALERT_BOOT = "AgICAgICAgICAgICAgICAg";
export const ALERT_PEER = "AwMDAwMDAwMDAwMDAwMDAw";
export function alertFixture(
  overrides: Partial<OperationAlert> = {},
): OperationAlert {
  return {
    id: "1",
    kind: "egress_check",
    origin_node_id: ALERT_NODE,
    resource_id: ALERT_RESOURCE,
    check: "tcp",
    target: "198.51.100.10:443",
    status: "active",
    code: "egress_connection_refused",
    first_observed_at_unix_ms: "1780000000000",
    last_observed_at_unix_ms: "1780000001000",
    ended_at_unix_ms: null,
    age_millis: "10",
    evidence_sequence: "2",
    evidence_fresh: true,
    ...overrides,
  };
}
export function alertPageFixture(
  overrides: Partial<AlertPage> = {},
): AlertPage {
  return {
    boot_id: ALERT_BOOT,
    revision: "1",
    observed_at_unix_ms: "1780000001000",
    age_millis: "10",
    collection_error: false,
    active_count: 1,
    recent_count: 0,
    dropped: "0",
    coverage: {
      local_egress: true,
      local_traffic: true,
      local_proxy_expected: true,
      local_management_https: false,
      local_node_tls: false,
      local_proxy_tls: false,
      remote_cached: true,
      remote_egress: false,
      remote_observation: false,
    },
    items: [alertFixture()],
    next_cursor: null,
    ...overrides,
  };
}

export function egressAlertPageFixture(
  overrides: Partial<EgressAlertPage> = {},
): EgressAlertPage {
  const { coverage: _coverage, ...page } = alertPageFixture();
  return {
    ...page,
    node_id: ALERT_PEER,
    monitored: true,
    items: [alertFixture({ origin_node_id: ALERT_PEER })],
    ...overrides,
  };
}

export function nodeAlertPageFixture(
  overrides: Partial<NodeAlertPage> = {},
): NodeAlertPage {
  const {
    remote_cached: _cached,
    remote_egress: _egress,
    remote_observation: _observation,
    ...coverage
  } = alertPageFixture().coverage;
  return {
    ...alertPageFixture(),
    node_id: ALERT_PEER,
    coverage,
    items: [alertFixture({ origin_node_id: ALERT_PEER })],
    ...overrides,
  };
}
