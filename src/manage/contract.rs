//! Offline OpenAPI export for the administration listener, not node or proxy APIs.
//!
//! Resource fragments stay next to this exporter and are tested against the
//! actual router. Exporting never loads a database, key, certificate or runtime.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};

use serde_json::{Map, Value};

const FRAGMENTS: &[&str] = &[
    include_str!("contract/users.json"),
    include_str!("contract/routing.json"),
    include_str!("contract/targets.json"),
    include_str!("contract/history.json"),
    include_str!("contract/endpoints.json"),
    include_str!("contract/alerts.json"),
    include_str!("contract/alert-events.json"),
    include_str!("contract/notifications.json"),
    include_str!("contract/egress-alerts.json"),
    include_str!("contract/node-alerts.json"),
    include_str!("contract/acme.json"),
    include_str!("contract/certificates.json"),
    include_str!("contract/maintenance.json"),
    include_str!("contract/runtime.json"),
    include_str!("contract/service.json"),
    include_str!("contract/secrets.json"),
];

/// Write the embedded contract as one JSON document. The automation view has
/// only local user reads and non-secret user operations; it never grants authority.
/// Broken pipes preserve their I/O kind without echoing serialized values.
pub(super) fn write(output: &mut impl Write, automation: bool) -> io::Result<()> {
    let document = document(automation)?;
    serde_json::to_writer_pretty(&mut *output, &document).map_err(|error| {
        io::Error::new(
            error.io_error_kind().unwrap_or(io::ErrorKind::Other),
            "cannot write API contract",
        )
    })?;
    writeln!(output).map_err(|error| io::Error::new(error.kind(), "cannot write API contract"))
}

/// Compose the same resource definitions for both audiences. HEAD is derived
/// from Axum's GET bindings and has no response content, including error bodies.
fn document(automation: bool) -> io::Result<Value> {
    let mut document: Value =
        serde_json::from_str(include_str!("contract/base.json")).map_err(|_| invalid())?;
    for source in FRAGMENTS {
        let Value::Object(mut fragment) = serde_json::from_str(source).map_err(|_| invalid())?
        else {
            return Err(invalid());
        };
        let paths = object(fragment.remove("paths"))?;
        let schemas = object(fragment.remove("schemas"))?;
        if !fragment.is_empty() {
            return Err(invalid());
        }
        merge(
            document
                .get_mut("paths")
                .and_then(Value::as_object_mut)
                .ok_or_else(invalid)?,
            paths,
        )?;
        merge(
            document
                .pointer_mut("/components/schemas")
                .and_then(Value::as_object_mut)
                .ok_or_else(invalid)?,
            schemas,
        )?;
    }
    let paths = document
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?;
    if automation {
        paths.retain(|path, _| {
            matches!(
                path.as_str(),
                "/api/v1/proxy/users"
                    | "/api/v1/proxy/users/search"
                    | "/api/v1/proxy/user-operations"
                    | "/api/v1/proxy/user-operations/context"
                    | "/api/v1/proxy/user-operations/{id}"
                    | "/api/v1/proxy/user-operations/{id}/execute"
            )
        });
        for (name, path) in paths.iter_mut() {
            let read_only = matches!(
                name.as_str(),
                "/api/v1/proxy/users" | "/api/v1/proxy/users/search"
            );
            let path = path.as_object_mut().ok_or_else(invalid)?;
            path.retain(|method, _| {
                method == "parameters" || method == "get" || (!read_only && method == "post")
            });
            for (method, operation) in path.iter_mut() {
                if method == "parameters" {
                    continue;
                }
                let operation = operation.as_object_mut().ok_or_else(invalid)?;
                operation.insert("security".into(), serde_json::json!([{ "Automation": [] }]));
                operation.insert(
                    "x-vproxy-required-scope".into(),
                    Value::from(if read_only {
                        "users:read"
                    } else {
                        "users:write"
                    }),
                );
            }
        }
        let info = document
            .get_mut("info")
            .and_then(Value::as_object_mut)
            .ok_or_else(invalid)?;
        info.insert(
            "title".into(),
            Value::from("vproxy restricted automation API"),
        );
        info.insert("description".into(), Value::from(
            "Local users:read permits user listing/search. Schema 18 users:write also permits caller-bound non-secret user operations and their context; it includes user reads, never credentials, IPAM, ownership, presets or remote control. Send one Authorization: Bearer header, never Cookie, CSRF or Proxy-Authorization. Origin may be absent; when present it must match the configured HTTPS origin. This is not an OAuth token service. Invalid keys return 401 invalid_token before scope checks; a valid read key on a write-scope resource returns 403 insufficient_scope with required scope users:write. Storage failures are not invalid tokens.",
        ));
    }
    let response_components = document
        .pointer("/components/responses")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?
        .clone();
    let paths = document
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?;
    for path in paths.values_mut() {
        let path = path.as_object_mut().ok_or_else(invalid)?;
        if let Some(get) = path.get("get") {
            let mut head = get.as_object().ok_or_else(invalid)?.clone();
            let operation_id = head
                .get("operationId")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            let operation_id = format!("{operation_id}Head");
            head.insert("operationId".into(), Value::from(operation_id));
            head.insert("description".into(), Value::from(
                "Same authorization, validation and status as GET. HEAD returns no response body; it can still perform the underlying read.",
            ));
            let responses = head
                .get_mut("responses")
                .and_then(Value::as_object_mut)
                .ok_or_else(invalid)?;
            for response in responses.values_mut() {
                // Expand local response references so HEAD retains headers
                // such as WWW-Authenticate while omitting JSON error content.
                if let Some(reference) = response.get("$ref") {
                    let name = reference
                        .as_str()
                        .and_then(|value| value.strip_prefix("#/components/responses/"))
                        .ok_or_else(invalid)?;
                    *response = response_components.get(name).ok_or_else(invalid)?.clone();
                }
                response
                    .as_object_mut()
                    .ok_or_else(invalid)?
                    .remove("content");
            }
            if path.insert("head".into(), Value::Object(head)).is_some() {
                return Err(invalid());
            }
        }
    }
    retain_referenced_components(&mut document)?;
    Ok(document)
}

fn object(value: Option<Value>) -> io::Result<Map<String, Value>> {
    match value {
        Some(Value::Object(value)) => Ok(value),
        _ => Err(invalid()),
    }
}

/// Duplicate definitions are maintenance errors, not last-fragment-wins data.
fn merge(target: &mut Map<String, Value>, source: Map<String, Value>) -> io::Result<()> {
    for (name, value) in source {
        if target.insert(name, value).is_some() {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Keep the automation view free of unrelated administrator and secret DTOs.
/// Every reference is local and must resolve; no file or network resolver runs.
fn retain_referenced_components(document: &mut Value) -> io::Result<()> {
    let mut pending = BTreeSet::new();
    collect_references(document.get("paths").ok_or_else(invalid)?, &mut pending)?;
    let mut required: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    while let Some(reference) = pending.pop_first() {
        let (kind, name) = reference.split_once('/').ok_or_else(invalid)?;
        if !required
            .entry(kind.to_owned())
            .or_default()
            .insert(name.to_owned())
        {
            continue;
        }
        let value = document
            .get("components")
            .and_then(|value| value.get(kind))
            .and_then(|value| value.get(name))
            .ok_or_else(invalid)?;
        collect_references(value, &mut pending)?;
    }
    let components = document
        .get_mut("components")
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?;
    for (kind, values) in components.iter_mut() {
        let values = values.as_object_mut().ok_or_else(invalid)?;
        values.retain(|name, _| required.get(kind).is_some_and(|names| names.contains(name)));
    }
    components.retain(|_, value| value.as_object().is_some_and(|value| !value.is_empty()));
    Ok(())
}

fn collect_references(value: &Value, references: &mut BTreeSet<String>) -> io::Result<()> {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref") {
                let reference = reference
                    .as_str()
                    .and_then(|value| value.strip_prefix("#/components/"))
                    .filter(|value| value.split('/').count() == 2)
                    .ok_or_else(invalid)?;
                references.insert(reference.to_owned());
            }
            // Security scheme names are references without a `$ref` spelling.
            if let Some(security) = object.get("security") {
                for alternative in security.as_array().ok_or_else(invalid)? {
                    for name in alternative.as_object().ok_or_else(invalid)?.keys() {
                        references.insert(format!("securitySchemes/{name}"));
                    }
                }
            }
            for value in object.values() {
                collect_references(value, references)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_references(value, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid embedded API contract")
}

#[cfg(test)]
mod tests {
    use super::*;

    mod alert_events {
        use super::*;

        #[test]
        fn history_and_acknowledgement_are_local_session_resources_with_lossless_ids()
        -> io::Result<()> {
            let document = document(false)?;
            let paths = &document["paths"];
            for (path, schema) in [
                ("/api/v1/alert-events", "AlertHistoryPage"),
                ("/api/v1/alert-events/{id}", "AlertHistoryEvent"),
                ("/api/v1/alert-episodes/{id}", "AlertHistoryEpisode"),
                ("/api/v1/alert-summary", "AlertHistorySummary"),
            ] {
                let get = &paths[path]["get"];
                assert_eq!(get["security"], serde_json::json!([{"Session":[]} ]));
                assert_eq!(
                    get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
                    format!("#/components/schemas/{schema}")
                );
                assert!(get.get("requestBody").is_none());
                assert!(paths[path].get("head").is_some());
            }
            let acknowledge = &paths["/api/v1/alert-episodes/{id}/acknowledge"];
            assert!(acknowledge.get("get").is_none() && acknowledge.get("head").is_none());
            assert_eq!(
                acknowledge["post"]["security"],
                serde_json::json!([{"Session":[],"Csrf":[]}])
            );
            assert!(acknowledge["post"]["responses"].get("409").is_some());
            assert_eq!(
                acknowledge["parameters"][0]["schema"]["$ref"],
                "#/components/schemas/Revision"
            );
            assert_eq!(
                paths["/api/v1/alert-events"]["get"]["x-vproxy-max-response-bytes"],
                128 * 1024
            );
            assert_eq!(
                paths["/api/v1/alert-events/{id}"]["get"]["x-vproxy-max-response-bytes"],
                32 * 1024
            );
            let schemas = &document["components"]["schemas"];
            let event = &schemas["AlertHistoryEvent"]["properties"];
            assert_eq!(event["episode_id"]["$ref"], "#/components/schemas/Revision");
            assert_eq!(
                event["incident_id"]["$ref"],
                "#/components/schemas/AlertEpisodeId"
            );
            for key in [
                "slot",
                "payload",
                "digest",
                "secret",
                "status",
                "evidence_fresh",
                "age_millis",
            ] {
                assert!(event.get(key).is_none(), "{key}");
            }
            assert_eq!(
                schemas["AlertHistoryPage"]["properties"]["items"]["maxItems"],
                50
            );
            assert_eq!(
                schemas["AlertHistoryPage"]["properties"]["trimmed"]["$ref"],
                "#/components/schemas/Counter"
            );
            assert_eq!(
                schemas["AlertHistoryAcknowledgementInput"]["additionalProperties"],
                false
            );
            assert_eq!(
                schemas["AlertHistoryAcknowledgementInput"]["required"],
                serde_json::json!(["expected_node_id", "expected_transition_sequence"])
            );
            let automation = super::super::document(true)?;
            assert!(
                !automation["paths"]
                    .as_object()
                    .ok_or_else(invalid)?
                    .keys()
                    .any(|path| path.starts_with("/api/v1/alert-"))
            );
            assert!(
                !automation["components"]["schemas"]
                    .as_object()
                    .ok_or_else(invalid)?
                    .keys()
                    .any(|name| name.starts_with("AlertHistory"))
            );
            Ok(())
        }
    }
    mod node_alerts {
        use super::*;
        use crate::manage::alerts::{LocalCoverage, NodePage};

        #[test]
        fn own_node_alert_contract_matches_both_fixed_session_reads_and_exact_projection()
        -> io::Result<()> {
            let document = document(false)?;
            let automation = super::super::document(true)?;
            let mut operation_ids = BTreeSet::new();
            for item in document["paths"].as_object().ok_or_else(invalid)?.values() {
                for operation in item.as_object().ok_or_else(invalid)?.values() {
                    if let Some(id) = operation.get("operationId").and_then(Value::as_str) {
                        assert!(operation_ids.insert(id), "duplicate operationId: {id}");
                    }
                }
            }
            for path in [
                "/api/v1/operations-alerts",
                "/api/v1/targets/{id}/operations-alerts",
            ] {
                let resource = &document["paths"][path];
                let get = &resource["get"];
                assert_eq!(get["security"], serde_json::json!([{ "Session": [] }]));
                assert_eq!(get["x-vproxy-max-query-bytes"], 768);
                assert_eq!(get["x-vproxy-max-response-bytes"], 32768);
                assert_eq!(get["parameters"][2]["schema"]["maximum"], 16);
                assert_eq!(
                    get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
                    "#/components/schemas/NodeAlertPage"
                );
                assert!(get.get("requestBody").is_none());
                assert!(resource.get("head").is_some());
                assert!(resource.get("post").is_none());
                assert!(automation["paths"].get(path).is_none());
            }
            let page = serde_json::to_value(NodePage {
                node_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
                boot_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
                revision: u64::MAX.to_string(),
                observed_at_unix_ms: None,
                age_millis: None,
                collection_error: false,
                coverage: LocalCoverage {
                    local_egress: false,
                    local_traffic: false,
                    local_proxy_expected: false,
                    local_management_https: false,
                    local_node_tls: false,
                    local_proxy_tls: false,
                },
                active_count: 0,
                recent_count: 0,
                dropped: u64::MAX.to_string(),
                items: Vec::new(),
                next_cursor: None,
            })
            .map_err(io::Error::other)?;
            let schemas = &document["components"]["schemas"];
            for (value, schema) in [
                (&page, &schemas["NodeAlertPage"]),
                (&page["coverage"], &schemas["NodeAlertCoverage"]),
            ] {
                let fields = value
                    .as_object()
                    .ok_or_else(invalid)?
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                let properties = schema["properties"]
                    .as_object()
                    .ok_or_else(invalid)?
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                let required = schema["required"]
                    .as_array()
                    .ok_or_else(invalid)?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>();
                assert_eq!(schema["additionalProperties"], false);
                assert_eq!(fields, properties);
                assert_eq!(fields, required);
            }
            assert_eq!(
                schemas["NodeAlertPage"]["properties"]["items"]["maxItems"],
                16
            );
            let incident = &schemas["NodeAlertIncident"]["allOf"][1];
            let kinds = incident["properties"]["kind"]["enum"]
                .as_array()
                .ok_or_else(invalid)?;
            assert_eq!(kinds.len(), 8);
            assert!(!kinds.contains(&Value::from("remote_job")));
            assert!(!kinds.contains(&Value::from("remote_traffic")));
            let constraints = incident["allOf"].as_array().ok_or_else(invalid)?;
            assert_eq!(constraints.len(), 10);
            assert_eq!(
                constraints[8]["then"]["properties"]["evidence_fresh"]["const"],
                true
            );
            assert_eq!(
                constraints[9]["then"]["properties"]["evidence_fresh"]["const"],
                false
            );
            Ok(())
        }
    }
    mod notifications {
        use super::*;
        use crate::manage::notifications::{DeliveryView, Outcome, View};

        #[test]
        fn webhook_contract_is_local_session_only_and_exposes_no_destination_secrets()
        -> io::Result<()> {
            let full = document(false)?;
            let automation = document(true)?;
            for path in [
                "/api/v1/notifications/webhook",
                "/api/v1/notifications/webhook/retry",
            ] {
                assert!(automation["paths"].get(path).is_none());
                let resource = &full["paths"][path];
                for method in ["get", "post"] {
                    if let Some(operation) = resource.get(method) {
                        let expected = if method == "get" {
                            serde_json::json!([{"Session":[]}])
                        } else {
                            serde_json::json!([{"Session":[],"Csrf":[]}])
                        };
                        assert_eq!(operation["security"], expected);
                    }
                }
            }
            let id = "A".repeat(22);
            let view = View {
                node_id: id.clone(),
                revision: "1".into(),
                enabled: true,
                automatic_retry: true,
                configured: true,
                has_bearer: true,
                operation_id: Some(id.clone()),
                cursor: "0".into(),
                skipped_through: "0".into(),
                last_accepted_delivery_id: None,
                discarded_delivery_id: None,
                pending: Some(DeliveryView {
                    id,
                    attempts: 1,
                    outcome: Outcome::Deferred,
                    http_status: Some(503),
                    after_sequence: "0".into(),
                    through_sequence: "1".into(),
                    history_trimmed_through: "0".into(),
                    event_count: 1,
                    automatic_retry_eligible: false,
                }),
            };
            let value = serde_json::to_value(view).map_err(|_| invalid())?;
            for (name, value) in [
                ("WebhookStatus", &value),
                ("WebhookDelivery", &value["pending"]),
            ] {
                let schema = &full["components"]["schemas"][name];
                assert_eq!(schema["additionalProperties"], false);
                let actual = value
                    .as_object()
                    .ok_or_else(invalid)?
                    .keys()
                    .collect::<BTreeSet<_>>();
                let properties = schema["properties"]
                    .as_object()
                    .ok_or_else(invalid)?
                    .keys()
                    .collect::<BTreeSet<_>>();
                assert_eq!(actual, properties);
                assert_eq!(
                    actual.iter().map(|v| v.as_str()).collect::<BTreeSet<_>>(),
                    schema["required"]
                        .as_array()
                        .ok_or_else(invalid)?
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<BTreeSet<_>>()
                );
                for secret in ["url", "bearer", "digest", "headers", "body"] {
                    assert!(!actual.iter().any(|name| name.as_str() == secret));
                }
            }
            assert_eq!(value["pending"]["outcome"], "deferred");
            assert!(
                full["components"]["schemas"]["WebhookDelivery"]["properties"]["outcome"]["enum"]
                    .as_array()
                    .ok_or_else(invalid)?
                    .contains(&value["pending"]["outcome"])
            );
            Ok(())
        }
    }

    #[test]
    fn traffic_checkpoint_contract_matches_the_bounded_local_stages() -> io::Result<()> {
        use crate::manage::traffic::CheckpointStage;

        let document = document(false)?;
        let schemas = &document["components"]["schemas"];
        let local = &schemas["TrafficTotals"]["allOf"][1];
        let stages = [
            CheckpointStage::Sample,
            CheckpointStage::WriteAdmission,
            CheckpointStage::UpdateGate,
            CheckpointStage::Store,
            CheckpointStage::Worker,
            CheckpointStage::Observation,
        ];
        let mut encoded = serde_json::to_value(stages).map_err(io::Error::other)?;
        encoded
            .as_array_mut()
            .ok_or_else(invalid)?
            .push(Value::Null);
        assert_eq!(
            local["properties"]["checkpoint_failure_stage"]["enum"],
            encoded
        );
        assert!(
            !local["required"]
                .as_array()
                .ok_or_else(invalid)?
                .contains(&Value::from("checkpoint_failure_stage"))
        );
        assert_eq!(
            local["allOf"][0],
            serde_json::json!({
                "if": {
                    "required": ["checkpoint_failure_stage"],
                    "properties": { "checkpoint_failure_stage": { "type": "string" } }
                },
                "then": { "properties": { "checkpoint_error": { "const": true } } }
            })
        );
        assert_eq!(
            schemas["RemoteTrafficTotalsData"]["allOf"][1]["properties"]["checkpoint_failure_stage"],
            serde_json::json!({ "type": "null" })
        );
        assert!(
            super::document(true)?["components"]["schemas"]
                .get("TrafficTotals")
                .is_none()
        );
        Ok(())
    }

    const ROUTERS: [(&str, &str); 26] = [
        ("api.rs", include_str!("api.rs")),
        ("api/acme.rs", include_str!("api/acme.rs")),
        ("api/certificates.rs", include_str!("api/certificates.rs")),
        ("api/alerts.rs", include_str!("api/alerts.rs")),
        ("api/notifications.rs", include_str!("api/notifications.rs")),
        (
            "api/alerts/history.rs",
            include_str!("api/alerts/history.rs"),
        ),
        ("api/endpoints.rs", include_str!("api/endpoints.rs")),
        ("api/health.rs", include_str!("api/health.rs")),
        ("api/maintenance.rs", include_str!("api/maintenance.rs")),
        ("api/runtime.rs", include_str!("api/runtime.rs")),
        ("api/service.rs", include_str!("api/service.rs")),
        ("api/presets.rs", include_str!("api/presets.rs")),
        (
            "api/remote_traffic.rs",
            include_str!("api/remote_traffic.rs"),
        ),
        ("api/routing.rs", include_str!("api/routing.rs")),
        ("api/targets.rs", include_str!("api/targets.rs")),
        (
            "api/targets/secrets.rs",
            include_str!("api/targets/secrets.rs"),
        ),
        (
            "api/targets/history.rs",
            include_str!("api/targets/history.rs"),
        ),
        (
            "api/targets/maintenance.rs",
            include_str!("api/targets/maintenance.rs"),
        ),
        (
            "api/targets/runtime.rs",
            include_str!("api/targets/runtime.rs"),
        ),
        (
            "api/targets/alerts.rs",
            include_str!("api/targets/alerts.rs"),
        ),
        ("api/traffic.rs", include_str!("api/traffic.rs")),
        ("api/users.rs", include_str!("api/users.rs")),
        ("api/users/secrets.rs", include_str!("api/users/secrets.rs")),
        (
            "api/targets/presets.rs",
            include_str!("api/targets/presets.rs"),
        ),
        (
            "api/targets/routing.rs",
            include_str!("api/targets/routing.rs"),
        ),
        (
            "api/users/operations.rs",
            include_str!("api/users/operations.rs"),
        ),
    ];

    type Bindings = BTreeSet<(String, String)>;

    #[test]
    fn credential_secret_contract_is_explicit_session_only_and_never_automation() -> io::Result<()>
    {
        let document = document(false)?;
        let path = "/api/v1/proxy/credentials/{id}/secret";
        assert_eq!(
            document["paths"][path]["post"]["security"],
            serde_json::json!([{ "Session": [], "Csrf": [] }])
        );
        assert!(document["paths"][path].get("get").is_none());
        assert_eq!(
            document["components"]["schemas"]["ProxyPassword"]["properties"]["secret"]["x-vproxy-sensitive"],
            true
        );
        let automation = super::document(true)?;
        assert!(automation["paths"].get(path).is_none());
        let remote = "/api/v1/targets/{id}/proxy/credentials/{credential}/secret";
        assert_eq!(
            document["paths"][remote]["post"]["security"],
            serde_json::json!([{ "Session": [], "Csrf": [] }])
        );
        assert!(document["paths"][remote].get("get").is_none());
        assert!(automation["paths"].get(remote).is_none());
        assert_eq!(
            document["components"]["schemas"]["TargetProxyPasswordRead"]["required"],
            serde_json::json!([
                "expected_node_id",
                "expected_target_revision",
                "user_id",
                "controller_epoch",
                "verifier_revision"
            ])
        );
        assert!(
            automation["components"]["schemas"]
                .get("TargetProxyPasswordRead")
                .is_none()
        );
        assert!(
            automation["components"]["schemas"]
                .get("ProxyPassword")
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn service_control_contract_is_exact_session_only_and_not_an_automation_grant() -> io::Result<()>
    {
        let document = document(false)?;
        let automation = super::document(true)?;
        for (path, method) in [
            ("/api/v1/proxy/service", "get"),
            ("/api/v1/proxy/service", "put"),
            (
                "/api/v1/proxy/service/operations/{revision}/{request_id}",
                "get",
            ),
        ] {
            let operation = &document["paths"][path][method];
            assert_eq!(
                operation["security"],
                if method == "put" {
                    serde_json::json!([{ "Session": [], "Csrf": [] }])
                } else {
                    serde_json::json!([{ "Session": [] }])
                }
            );
            assert!(automation["paths"].get(path).is_none());
        }
        let schemas = &document["components"]["schemas"];
        for name in [
            "ProxyServiceConfiguration",
            "ProxyServiceSaved",
            "ProxyServiceRuntime",
            "ProxyServiceStatus",
            "ProxyServiceInput",
            "ProxyServiceReceipt",
            "ProxyServiceSubmission",
        ] {
            assert_eq!(schemas[name]["additionalProperties"], false);
        }
        assert_eq!(
            schemas["ProxyServiceConfiguration"]["properties"]["listeners"]["maxItems"],
            16
        );
        assert_eq!(
            schemas["ProxyServiceRuntime"]["properties"]["configuration_revision"]["anyOf"][0]["$ref"],
            "#/components/schemas/Revision"
        );
        Ok(())
    }

    fn take<'a>(source: &'a str, expected: &str) -> io::Result<&'a str> {
        source
            .trim_start()
            .strip_prefix(expected)
            .ok_or_else(invalid)
    }

    /// Only an ordinary identifier/path, not a closure, macro or generic argument.
    fn identifier(source: &str) -> io::Result<(&str, &str)> {
        let source = source.trim_start();
        let length = source
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b':'))
            .count();
        let (name, rest) = source.split_at(length);
        if name.split("::").any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }) {
            return Err(invalid());
        }
        Ok((name, rest))
    }

    fn binding_call(source: &str, factory: bool) -> io::Result<(&str, &str)> {
        let (name, rest) = identifier(source)?;
        let method = if factory {
            name.strip_prefix("axum::routing::").unwrap_or(name)
        } else {
            name
        };
        if !matches!(method, "get" | "post" | "put") {
            return Err(invalid());
        }
        let (_, rest) = identifier(take(rest, "(")?)?;
        Ok((method, take(rest, ")")?))
    }

    /// A deliberately narrow source-style guard, not a Rust parser. All current
    /// routers use literal paths and get/post/put(simple_handler_path) chains. A new
    /// binding style must update this guard rather than disappear from coverage.
    fn route_bindings(mut source: &str) -> io::Result<Bindings> {
        let mut result = BTreeSet::new();
        while let Some(position) = source.find(".route") {
            let rest = &source[position + ".route".len()..];
            // route_layer and similarly named methods are not route declarations.
            if rest
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                source = rest;
                continue;
            }
            let rest = take(take(rest, "(")?, "\"")?;
            let end = rest.find('"').ok_or_else(invalid)?;
            let (path, rest) = rest.split_at(end);
            if !path.starts_with("/api/v1/")
                || !path
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"/-_{}".contains(&byte))
            {
                return Err(invalid());
            }
            let rest = take(take(rest, "\"")?, ",")?;
            let (method, mut rest) = binding_call(rest, true)?;
            if !result.insert((path.to_owned(), method.to_owned())) {
                return Err(invalid());
            }
            while let Some(next) = rest.trim_start().strip_prefix('.') {
                let (method, next) = binding_call(next, false)?;
                if !result.insert((path.to_owned(), method.to_owned())) {
                    return Err(invalid());
                }
                rest = next;
            }
            let rest = rest.trim_start();
            let rest = rest.strip_prefix(',').unwrap_or(rest);
            source = take(rest, ")")?;
        }
        Ok(result)
    }

    fn resolved_response<'a>(document: &'a Value, response: &'a Value) -> io::Result<&'a Value> {
        match response.get("$ref") {
            Some(reference) => document
                .pointer(
                    reference
                        .as_str()
                        .and_then(|value| value.strip_prefix('#'))
                        .ok_or_else(invalid)?,
                )
                .ok_or_else(invalid),
            None => Ok(response),
        }
    }

    /// Independently walk the exported value, not the exporter's reference queue.
    fn check_local_references(root: &Value, value: &Value) -> io::Result<()> {
        match value {
            Value::Object(object) => {
                if let Some(reference) = object.get("$ref") {
                    let reference = reference.as_str().ok_or_else(invalid)?;
                    let local = reference
                        .strip_prefix("#/components/")
                        .ok_or_else(invalid)?;
                    if local.split('/').count() != 2 || root.pointer(&reference[1..]).is_none() {
                        return Err(invalid());
                    }
                }
                if let Some(security) = object.get("security") {
                    for alternative in security.as_array().ok_or_else(invalid)? {
                        for name in alternative.as_object().ok_or_else(invalid)?.keys() {
                            if root
                                .pointer("/components/securitySchemes")
                                .and_then(|schemes| schemes.get(name))
                                .is_none()
                            {
                                return Err(invalid());
                            }
                        }
                    }
                }
                for child in object.values() {
                    check_local_references(root, child)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    check_local_references(root, child)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    #[test]
    fn complete_contract_matches_router_bindings_and_derives_bodyless_heads() -> io::Result<()> {
        let mut expected = BTreeSet::new();
        for (name, source) in ROUTERS {
            let bindings = route_bindings(source)?;
            assert!(
                !bindings.is_empty(),
                "router source had no recognized bindings: {name}"
            );
            for binding in bindings {
                assert!(
                    expected.insert(binding),
                    "duplicate production route in {name}"
                );
            }
        }
        for source in [
            ".route(PATH, get(handler))",
            ".route(format!(\"/api/v1/users\"), get(handler))",
            ".route(\"/api/v1/users\", delete(handler))",
            ".route(\"/api/v1/users\", methods(handler))",
            ".route(\"/api/v1/users\", get(|| handler()))",
            ".route(\"/api/v1/users\", get(handler).layer(extra))",
            ".route(\"/api/v1/users\", get(handler).get(other))",
        ] {
            assert!(
                route_bindings(source).is_err(),
                "unsupported binding style was silently accepted"
            );
        }
        let document = document(false)?;
        check_local_references(&document, &document)?;
        let mut actual = BTreeSet::new();
        for (path, item) in document["paths"].as_object().ok_or_else(invalid)? {
            let item = item.as_object().ok_or_else(invalid)?;
            for method in item.keys() {
                match method.as_str() {
                    "get" | "post" | "put" => {
                        actual.insert((path.clone(), method.clone()));
                    }
                    "head" | "parameters" => {}
                    _ => return Err(invalid()),
                }
            }
            if let Some(get) = item.get("get") {
                let head = item.get("head").ok_or_else(invalid)?;
                assert_eq!(
                    head["operationId"],
                    format!("{}Head", get["operationId"].as_str().ok_or_else(invalid)?)
                );
                assert_eq!(head.get("security"), get.get("security"));
                assert_eq!(head.get("parameters"), get.get("parameters"));
                let get_responses = get["responses"].as_object().ok_or_else(invalid)?;
                let head_responses = head["responses"].as_object().ok_or_else(invalid)?;
                assert_eq!(
                    get_responses.keys().collect::<Vec<_>>(),
                    head_responses.keys().collect::<Vec<_>>()
                );
                for (status, response) in get_responses {
                    let mut expected = resolved_response(&document, response)?
                        .as_object()
                        .ok_or_else(invalid)?
                        .clone();
                    expected.remove("content");
                    assert_eq!(
                        head_responses[status],
                        Value::Object(expected),
                        "HEAD response changed headers or retained a body: {path} {status}"
                    );
                    assert!(head_responses[status].get("content").is_none());
                }
            } else {
                assert!(
                    !item.contains_key("head"),
                    "HEAD without a source GET: {path}"
                );
            }
        }
        assert_eq!(actual, expected);
        let error_headers = document
            .pointer("/paths/~1api~1v1~1proxy~1users/head/responses/default/headers")
            .ok_or_else(invalid)?;
        assert!(error_headers.get("WWW-Authenticate").is_some());
        Ok(())
    }

    #[test]
    fn automation_contract_is_only_local_users_and_non_secret_operations() -> io::Result<()> {
        let document = document(true)?;
        let paths = document["paths"].as_object().ok_or_else(invalid)?;
        assert_eq!(
            paths.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "/api/v1/proxy/user-operations",
                "/api/v1/proxy/user-operations/context",
                "/api/v1/proxy/user-operations/{id}",
                "/api/v1/proxy/user-operations/{id}/execute",
                "/api/v1/proxy/users",
                "/api/v1/proxy/users/search"
            ]
        );
        for (name, path) in paths {
            let methods = path.as_object().ok_or_else(invalid)?;
            let expected = match name.as_str() {
                "/api/v1/proxy/user-operations" => BTreeSet::from(["get", "head", "post"]),
                "/api/v1/proxy/user-operations/{id}" => {
                    BTreeSet::from(["get", "head", "parameters"])
                }
                "/api/v1/proxy/user-operations/{id}/execute" => {
                    BTreeSet::from(["post", "parameters"])
                }
                _ => BTreeSet::from(["get", "head"]),
            };
            assert_eq!(
                methods.keys().map(String::as_str).collect::<BTreeSet<_>>(),
                expected
            );
            for (method, operation) in methods {
                if method == "parameters" {
                    continue;
                }
                assert_eq!(
                    operation["security"],
                    serde_json::json!([{ "Automation": [] }])
                );
                assert_eq!(
                    operation["x-vproxy-required-scope"],
                    if name.contains("/user-operations") {
                        "users:write"
                    } else {
                        "users:read"
                    }
                );
                assert_eq!(operation.get("requestBody").is_some(), method == "post");
            }
        }
        let components = document["components"].as_object().ok_or_else(invalid)?;
        assert_eq!(
            components["securitySchemes"]
                .as_object()
                .ok_or_else(invalid)?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["Automation"]
        );
        for name in [
            "PasswordInput",
            "LoginInput",
            "SessionView",
            "Credential",
            "CredentialPage",
            "PolicyChange",
            "AlertPage",
            "AlertIncident",
            "AlertHistoryEvent",
            "AlertHistoryEpisode",
            "AlertHistoryPage",
            "AlertHistorySummary",
            "AlertHistoryAcknowledgementInput",
            "AcmeStatus",
            "ManualTlsStatus",
            "AcmeTlsStatus",
            "AcmeCertificate",
            "AcmeUnixSeconds",
            "TargetJob",
            "TargetJobInput",
            "TargetUserResult",
        ] {
            assert!(
                components["schemas"].get(name).is_none(),
                "unrelated schema retained: {name}"
            );
        }
        assert!(
            components
                .get("parameters")
                .and_then(|parameters| parameters.get("Origin"))
                .is_none()
        );
        check_local_references(&document, &document)?;
        assert_eq!(document["openapi"], "3.1.2");
        assert_eq!(
            document["jsonSchemaDialect"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        for automation in [false, true] {
            let mut bytes = Vec::new();
            write(&mut bytes, automation)?;
            assert!(bytes.ends_with(b"\n"));
            let value: Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            assert_eq!(value, super::document(automation)?);
            let input = &value["components"]["schemas"]["OperationInput"];
            assert_eq!(input["additionalProperties"], false);
            assert_eq!(
                input["required"],
                serde_json::json!(["expected_revision", "expected_epoch", "change"])
            );
            assert_eq!(
                input["properties"]
                    .as_object()
                    .ok_or_else(invalid)?
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([
                    "expected_node_id",
                    "expected_revision",
                    "expected_epoch",
                    "change"
                ])
            );
            assert_eq!(
                input["properties"]["expected_node_id"],
                serde_json::json!({"$ref":"#/components/schemas/Id"})
            );
            assert_eq!(value["components"]["schemas"]["Id"]["type"], "string");
            for path in [
                "/api/v1/proxy/user-operations",
                "/api/v1/proxy/user-operations/{id}/execute",
            ] {
                let operation = &value["paths"][path]["post"];
                assert_eq!(
                    operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
                    "#/components/schemas/OperationInput"
                );
                assert_eq!(
                    operation["security"],
                    if automation {
                        serde_json::json!([{ "Automation": [] }])
                    } else {
                        serde_json::json!([{ "Session": [], "Csrf": [] }, { "Automation": [] }])
                    }
                );
                if automation {
                    assert_eq!(operation["x-vproxy-required-scope"], "users:write");
                }
                assert!(
                    operation["description"]
                        .as_str()
                        .ok_or_else(invalid)?
                        .contains("expected_node_id")
                );
            }
        }
        Ok(())
    }

    #[test]
    fn address_lookup_contract_is_exact_session_only_and_outside_automation() -> io::Result<()> {
        let document = document(false)?;
        let automation = super::document(true)?;
        let local = "/api/v1/proxy/addresses/{id}";
        let target = "/api/v1/targets/{id}/proxy/addresses/{resource}";
        for path in [local, target] {
            let resource = &document["paths"][path];
            let operation = &resource["get"];
            assert_eq!(
                operation["security"],
                serde_json::json!([{ "Session": [] }])
            );
            assert_eq!(operation["parameters"], serde_json::json!([]));
            assert_eq!(operation["x-vproxy-max-query-bytes"], 0);
            assert!(operation.get("requestBody").is_none());
            assert!(resource.get("post").is_none());
            assert_eq!(
                operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/AddressView"
            );
            let missing = &operation["responses"]["404"];
            assert_eq!(
                missing["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/ApiError"
            );
            assert!(
                missing["description"]
                    .as_str()
                    .ok_or_else(invalid)?
                    .contains("resource_not_found")
            );
            let head = &resource["head"];
            assert_eq!(head["security"], operation["security"]);
            assert_eq!(head["parameters"], operation["parameters"]);
            let get_responses = operation["responses"].as_object().ok_or_else(invalid)?;
            let head_responses = head["responses"].as_object().ok_or_else(invalid)?;
            assert_eq!(
                get_responses.keys().collect::<Vec<_>>(),
                head_responses.keys().collect::<Vec<_>>()
            );
            for response in head_responses.values() {
                assert!(response.get("content").is_none());
            }
            assert!(automation["paths"].get(path).is_none());
        }
        assert_eq!(
            document["paths"][local]["parameters"],
            serde_json::json!([{ "$ref": "#/components/parameters/ResourceId" }])
        );
        assert_eq!(
            document["paths"][target]["parameters"],
            serde_json::json!([
                { "$ref": "#/components/parameters/ResourceId" },
                {
                    "name": "resource",
                    "in": "path",
                    "required": true,
                    "schema": { "$ref": "#/components/schemas/Id" }
                }
            ])
        );
        assert!(
            document["paths"][local]["get"]["responses"]
                .get("502")
                .is_none()
        );
        let unsupported = &document["paths"][target]["get"]["responses"]["502"];
        assert_eq!(
            unsupported["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ApiError"
        );
        assert!(
            unsupported["description"]
                .as_str()
                .ok_or_else(invalid)?
                .contains("address_lookup_unsupported")
        );
        let schemas = &document["components"]["schemas"];
        let address_view = &schemas["AddressView"];
        assert_eq!(address_view["additionalProperties"], false);
        assert_eq!(
            address_view["required"],
            serde_json::json!(["revision", "address"])
        );
        assert_eq!(
            address_view["properties"]
                .as_object()
                .ok_or_else(invalid)?
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["revision", "address"])
        );
        assert_eq!(
            address_view["properties"]["revision"]["$ref"],
            "#/components/schemas/Revision"
        );
        assert_eq!(
            address_view["properties"]["address"]["$ref"],
            "#/components/schemas/Address"
        );
        assert_eq!(schemas["Address"]["additionalProperties"], false);
        assert_eq!(
            schemas["Address"]["properties"]["state"]["$ref"],
            "#/components/schemas/ResourceState"
        );
        assert!(
            schemas["ResourceState"]["enum"]
                .as_array()
                .ok_or_else(invalid)?
                .contains(&Value::from("retired"))
        );
        assert!(
            automation["components"]["schemas"]
                .get("AddressView")
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn target_user_result_contract_is_exact_non_secret_and_session_only() -> io::Result<()> {
        let document = document(false)?;
        let path = "/api/v1/targets/{id}/command/user-result";
        let operation = &document["paths"][path]["post"];
        assert_eq!(
            operation["security"],
            serde_json::json!([{ "Session": [], "Csrf": [] }])
        );
        assert_eq!(
            document["paths"][path]["parameters"],
            serde_json::json!([
                { "$ref": "#/components/parameters/ResourceId" }
            ])
        );
        assert_eq!(
            operation["parameters"],
            serde_json::json!([
                { "$ref": "#/components/parameters/Origin" }
            ])
        );
        assert_eq!(operation["requestBody"]["required"], true);
        assert_eq!(
            operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/TargetJobInput"
        );
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/TargetUserResult"
        );
        assert!(document["paths"][path].get("get").is_none());
        assert!(document["paths"][path].get("head").is_none());
        let schemas = &document["components"]["schemas"];
        for (name, fields) in [
            ("TargetJobInput", &["job_id"][..]),
            ("TargetUserResult", &["job", "user_id"][..]),
        ] {
            let schema = &schemas[name];
            assert_eq!(schema["additionalProperties"], false);
            let required = schema["required"]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .map(|value| value.as_str().ok_or_else(invalid))
                .collect::<io::Result<BTreeSet<_>>>()?;
            assert_eq!(required, BTreeSet::from_iter(fields.iter().copied()));
            let properties = schema["properties"]
                .as_object()
                .ok_or_else(invalid)?
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            assert_eq!(properties, required);
        }
        assert_eq!(
            schemas["TargetJobInput"]["properties"]["job_id"]["$ref"],
            "#/components/schemas/Id"
        );
        assert_eq!(
            schemas["TargetUserResult"]["properties"]["user_id"]["$ref"],
            "#/components/schemas/Id"
        );
        let result_job = &schemas["TargetUserResult"]["properties"]["job"]["allOf"];
        assert_eq!(result_job[0]["$ref"], "#/components/schemas/TargetJob");
        assert_eq!(
            result_job[1]["required"],
            serde_json::json!(["user_creation"])
        );
        assert_eq!(result_job[1]["properties"]["user_creation"]["const"], true);
        assert_eq!(
            result_job[1]["properties"]["state"]["enum"],
            serde_json::json!(["saved", "applied"])
        );
        let job = &schemas["TargetJob"];
        assert_eq!(job["additionalProperties"], false);
        assert_eq!(job["properties"]["user_creation"]["type"], "boolean");
        assert_eq!(job["properties"]["user_creation"]["default"], false);
        assert!(
            !job["required"]
                .as_array()
                .ok_or_else(invalid)?
                .contains(&Value::from("user_creation"))
        );
        assert_eq!(
            job["allOf"][0],
            serde_json::json!({
                "if": { "required": ["user_creation"], "properties": { "user_creation": { "const": true } } },
                "then": { "not": { "anyOf": [
                    { "required": ["resource"] }, { "required": ["routing"] }, { "required": ["preset"] },
                    { "required": ["maintenance"] }
                ] } }
            })
        );
        // Metadata submissions share this one strict job schema; the new flag
        // must not introduce a second, more permissive endpoint ticket shape.
        for name in ["EndpointDeliveredSubmission", "EndpointPendingSubmission"] {
            assert_eq!(
                schemas[name]["properties"]["job"]["$ref"],
                "#/components/schemas/TargetJob"
            );
        }
        assert!(super::document(true)?["paths"].get(path).is_none());
        Ok(())
    }

    #[test]
    fn alerts_contract_matches_wire_fields_and_remains_session_only() -> io::Result<()> {
        let document = document(false)?;
        let operation = &document["paths"]["/api/v1/alerts"]["get"];
        assert_eq!(
            operation["security"],
            serde_json::json!([{ "Session": [] }])
        );
        assert_eq!(operation["x-vproxy-max-response-bytes"], 32768);
        assert_eq!(operation["x-vproxy-max-query-bytes"], 768);
        let parameters = operation["parameters"].as_array().ok_or_else(invalid)?;
        assert_eq!(parameters.len(), 3);
        assert_eq!(parameters[0]["name"], "state");
        assert_eq!(parameters[0]["schema"]["default"], "active");
        assert_eq!(parameters[1]["name"], "after");
        assert_eq!(parameters[2]["name"], "limit");
        assert_eq!(parameters[2]["schema"]["default"], 10);
        assert_eq!(parameters[2]["schema"]["maximum"], 16);
        assert_eq!(
            document["components"]["schemas"]["AlertPage"]["properties"]["items"]["maxItems"],
            16
        );
        assert_eq!(
            document["components"]["schemas"]["AlertKind"]["enum"],
            serde_json::json!([
                "egress_check",
                "health_catalog",
                "policy",
                "traffic_checkpoint",
                "traffic_continuity",
                "remote_traffic",
                "remote_job",
                "remote_observation",
                "management_https",
                "node_tls",
                "proxy_tls"
            ])
        );
        assert_eq!(
            document["components"]["schemas"]["AlertCoverage"]["properties"]["local_management_https"]
                ["type"],
            "boolean"
        );
        assert_eq!(
            document["components"]["schemas"]["AlertPage"]["properties"]["active_count"]["maximum"],
            12_288
        );
        assert_eq!(
            document["components"]["schemas"]["AlertCoverage"]["properties"]["remote_observation"]
                ["type"],
            "boolean"
        );
        for (schema, expected) in [
            (
                "AlertPage",
                &[
                    "boot_id",
                    "revision",
                    "observed_at_unix_ms",
                    "age_millis",
                    "collection_error",
                    "coverage",
                    "active_count",
                    "recent_count",
                    "dropped",
                    "items",
                    "next_cursor",
                ][..],
            ),
            (
                "AlertIncident",
                &[
                    "id",
                    "kind",
                    "origin_node_id",
                    "resource_id",
                    "check",
                    "target",
                    "status",
                    "code",
                    "first_observed_at_unix_ms",
                    "last_observed_at_unix_ms",
                    "ended_at_unix_ms",
                    "age_millis",
                    "evidence_sequence",
                    "evidence_fresh",
                ][..],
            ),
            (
                "AlertCoverage",
                &[
                    "local_egress",
                    "local_traffic",
                    "local_proxy_expected",
                    "remote_cached",
                    "remote_egress",
                    "remote_observation",
                ][..],
            ),
        ] {
            let definition = &document["components"]["schemas"][schema];
            assert_eq!(definition["additionalProperties"], false);
            let required = definition["required"]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .map(|value| value.as_str().ok_or_else(invalid))
                .collect::<io::Result<BTreeSet<_>>>()?;
            assert_eq!(
                required,
                BTreeSet::from_iter(expected.iter().copied()),
                "required {schema}"
            );
            let properties = definition["properties"]
                .as_object()
                .ok_or_else(invalid)?
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let mut expected_properties = required;
            if schema == "AlertCoverage" {
                // Legacy TLS coverage remains optional. Current schema22 servers
                // always emit the separately configured background coverage flag.
                expected_properties.extend([
                    "local_management_https",
                    "local_node_tls",
                    "local_proxy_tls",
                ]);
            }
            assert_eq!(properties, expected_properties, "wire properties {schema}");
        }
        assert!(
            super::document(true)?["paths"]
                .get("/api/v1/alerts")
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn egress_alert_contract_matches_the_scoped_wire_and_is_not_an_automation_grant()
    -> io::Result<()> {
        use crate::manage::alerts::EgressPage;

        let document = document(false)?;
        let path = "/api/v1/targets/{id}/egress-alerts";
        let operation = &document["paths"][path]["get"];
        assert_eq!(
            operation["security"],
            serde_json::json!([{ "Session": [] }])
        );
        assert_eq!(operation["x-vproxy-max-query-bytes"], 768);
        assert_eq!(operation["x-vproxy-max-response-bytes"], 32768);
        assert_eq!(operation["parameters"][2]["schema"]["maximum"], 16);
        let page = serde_json::to_value(EgressPage {
            node_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            boot_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            revision: "1".into(),
            observed_at_unix_ms: None,
            age_millis: None,
            collection_error: false,
            monitored: false,
            active_count: 0,
            recent_count: 0,
            dropped: "0".into(),
            items: Vec::new(),
            next_cursor: None,
        })
        .map_err(io::Error::other)?;
        let fields = page
            .as_object()
            .ok_or_else(invalid)?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let schema = &document["components"]["schemas"]["EgressAlertPage"];
        assert_eq!(schema["additionalProperties"], false);
        let properties = schema["properties"]
            .as_object()
            .ok_or_else(invalid)?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let required = schema["required"]
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(fields, properties);
        assert_eq!(fields, required);
        assert_eq!(schema["properties"]["items"]["maxItems"], 16);
        assert!(super::document(true)?["paths"].get(path).is_none());
        Ok(())
    }

    #[test]
    fn acme_contract_matches_public_snapshots_and_stays_outside_automation() -> io::Result<()> {
        use crate::manage::acme::{Handle, View};

        let document = document(false)?;
        let operation = &document["paths"]["/api/v1/tls/acme"]["get"];
        assert_eq!(
            operation["security"],
            serde_json::json!([{ "Session": [] }])
        );
        assert_eq!(operation["parameters"], serde_json::json!([]));
        assert_eq!(operation["x-vproxy-max-query-bytes"], 0);
        assert_eq!(operation["x-vproxy-max-response-bytes"], 2048);
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/AcmeStatus"
        );
        assert_eq!(
            serde_json::to_value(View::manual()).map_err(io::Error::other)?,
            serde_json::json!({ "mode": "manual" })
        );
        let snapshot = serde_json::to_value(Handle::testing().view()?).map_err(io::Error::other)?;
        for (schema, expected) in [
            ("ManualTlsStatus", &["mode"][..]),
            (
                "AcmeTlsStatus",
                &[
                    "mode",
                    "environment",
                    "challenge",
                    "certificate",
                    "activity",
                    "next_attempt_at_unix_s",
                    "last_failure",
                    "observed_at_unix_s",
                ][..],
            ),
            (
                "AcmeCertificate",
                &["not_before_unix_s", "not_after_unix_s", "available"][..],
            ),
        ] {
            let definition = &document["components"]["schemas"][schema];
            assert_eq!(definition["additionalProperties"], false);
            let required = definition["required"]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .map(|value| value.as_str().ok_or_else(invalid))
                .collect::<io::Result<BTreeSet<_>>>()?;
            assert_eq!(required, BTreeSet::from_iter(expected.iter().copied()));
            assert_eq!(
                definition["properties"]
                    .as_object()
                    .ok_or_else(invalid)?
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                required
            );
            if schema == "AcmeTlsStatus" {
                assert_eq!(
                    snapshot
                        .as_object()
                        .ok_or_else(invalid)?
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>(),
                    required
                );
            }
        }
        let schemas = &document["components"]["schemas"];
        assert_eq!(
            schemas["AcmeTlsStatus"]["properties"]["environment"]["enum"],
            serde_json::json!(["staging", "production"])
        );
        assert_eq!(
            schemas["AcmeTlsStatus"]["properties"]["challenge"]["enum"],
            serde_json::json!(["tls-alpn-01", "http-01"])
        );
        assert_eq!(
            schemas["AcmeUnixSeconds"]["$ref"],
            "#/components/schemas/Counter"
        );
        assert_eq!(
            schemas["Counter"]["x-vproxy-maximum-decimal"],
            u64::MAX.to_string()
        );
        assert!(
            super::document(true)?["paths"]
                .get("/api/v1/tls/acme")
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn merge_and_reference_failures_are_not_silently_exported() -> io::Result<()> {
        let mut target = object(Some(serde_json::json!({ "Name": { "type": "string" } })))?;
        let duplicate = object(Some(serde_json::json!({ "Name": { "type": "integer" } })))?;
        assert!(merge(&mut target, duplicate).is_err());
        for reference in [
            "#/components/schemas/Missing",
            "#/components/schemas/Too/Deep",
            "#/paths/other",
            "https://private-writer-marker.invalid/schema",
        ] {
            let mut value = serde_json::json!({
                "paths": { "/api/v1/test": { "get": { "responses": { "200": { "$ref": reference } } } } },
                "components": { "schemas": {}, "responses": {}, "securitySchemes": {} }
            });
            let error = retain_referenced_components(&mut value)
                .err()
                .ok_or_else(|| io::Error::other("expected invalid contract reference"))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "invalid embedded API contract");
        }
        let mut unknown_security = serde_json::json!({
            "paths": { "/api/v1/test": { "get": { "security": [{ "Unknown": [] }] } } },
            "components": { "securitySchemes": {} }
        });
        assert!(retain_referenced_components(&mut unknown_security).is_err());
        Ok(())
    }

    /// A fake sink fails either during JSON or only on the final newline. Its error
    /// deliberately contains a synthetic private marker that must not be propagated.
    struct BrokenOutput {
        remaining: usize,
    }

    impl Write for BrokenOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "private-writer-marker",
                ));
            }
            let written = self.remaining.min(bytes.len());
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn output_failures_preserve_kind_without_echoing_writer_errors() -> io::Result<()> {
        let length = serde_json::to_vec_pretty(&document(true)?)
            .map_err(io::Error::other)?
            .len();
        for remaining in [0, length] {
            let mut output = BrokenOutput { remaining };
            let error = write(&mut output, true)
                .err()
                .ok_or_else(|| io::Error::other("expected contract output failure"))?;
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(error.to_string(), "cannot write API contract");
            assert!(!error.to_string().contains("private-writer-marker"));
            assert_eq!(output.remaining, 0);
        }
        Ok(())
    }

    #[test]
    fn loaded_tls_contract_is_session_only_bounded_signed_and_absent_from_automation()
    -> io::Result<()> {
        let document = super::document(false)?;
        let automation = super::document(true)?;
        let path = "/api/v1/tls/status";
        let resource = &document["paths"][path];
        let get = &resource["get"];
        assert_eq!(get["security"], serde_json::json!([{"Session":[]}]));
        assert_eq!(get["parameters"], serde_json::json!([]));
        assert_eq!(get["x-vproxy-max-query-bytes"], 0);
        assert_eq!(get["x-vproxy-max-response-bytes"], 16384);
        assert_eq!(
            get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/TlsIdentityStatus"
        );
        let head = &resource["head"];
        assert_eq!(head["security"], get["security"]);
        for response in head["responses"].as_object().ok_or_else(invalid)?.values() {
            assert!(
                resolved_response(&document, response)?
                    .get("content")
                    .is_none()
            );
        }
        let schemas = &document["components"]["schemas"];
        assert_eq!(schemas["TlsUnixSeconds"]["type"], "string");
        assert_eq!(
            schemas["TlsUnixSeconds"]["pattern"],
            "^(0|-?[1-9][0-9]{0,18})$"
        );
        assert_eq!(schemas["TlsUnixSeconds"]["maxLength"], 20);
        assert_eq!(
            schemas["TlsIdentityStatus"]["properties"]["entries"]["minItems"],
            2
        );
        assert_eq!(
            schemas["TlsIdentityStatus"]["properties"]["entries"]["maxItems"],
            18
        );
        assert_eq!(
            schemas["TlsLeafMetadata"]["properties"]["not_before_unix_s"]["$ref"],
            "#/components/schemas/TlsUnixSeconds"
        );
        assert_eq!(
            schemas["TlsLeafMetadata"]["properties"]["not_after_unix_s"]["$ref"],
            "#/components/schemas/TlsUnixSeconds"
        );
        for schema in ["TlsIdentityStatus", "TlsIdentityEntry", "TlsLeafMetadata"] {
            assert_eq!(schemas[schema]["additionalProperties"], false);
        }
        assert!(automation["paths"].get(path).is_none());
        for schema in [
            "TlsIdentityStatus",
            "TlsIdentityEntry",
            "TlsLeafMetadata",
            "TlsUnixSeconds",
        ] {
            assert!(automation["components"]["schemas"].get(schema).is_none());
        }
        Ok(())
    }

    #[test]
    fn maintenance_contract_keeps_session_authority_unknown_runtime_and_typed_job_intent()
    -> io::Result<()> {
        let document = super::document(false)?;
        let automation = super::document(true)?;
        for path in [
            "/api/v1/proxy/maintenance",
            "/api/v1/targets/{id}/proxy/maintenance",
            "/api/v1/targets/{id}/maintenance/commands",
            "/api/v1/targets/{id}/maintenance/commands/refresh",
        ] {
            assert!(automation["paths"].get(path).is_none());
            let resource = &document["paths"][path];
            if let Some(get) = resource.get("get") {
                assert_eq!(get["security"], serde_json::json!([{"Session":[]}]));
                assert!(resource.get("head").is_some());
            }
            if let Some(post) = resource.get("post") {
                assert_eq!(
                    post["security"],
                    serde_json::json!([{"Session":[],"Csrf":[]}])
                );
            }
        }
        let schemas = &document["components"]["schemas"];
        let required = schemas["MaintenanceStatus"]["required"]
            .as_array()
            .ok_or_else(invalid)?;
        for name in [
            "durable_applied_revision",
            "applied_revision",
            "runtime_accepting",
            "active_operations",
        ] {
            assert!(required.iter().any(|value| value == name));
        }
        assert!(
            schemas["MaintenanceStatus"]["properties"]
                .get("drained")
                .is_none()
        );
        assert_eq!(
            schemas["MaintenanceStatus"]["oneOf"][0]["properties"]["active_operations"]["type"],
            "null"
        );
        assert_eq!(
            schemas["MaintenanceMutation"]["properties"]["action"]["const"],
            "set_admission"
        );
        assert_eq!(
            schemas["MaintenanceCommandReply"]["properties"]["secret_available"]["const"],
            false
        );
        assert_eq!(
            schemas["MaintenanceReceipt"]["properties"]["user_id"]["type"],
            "null"
        );
        assert_eq!(
            schemas["TargetJob"]["properties"]["maintenance"]["$ref"],
            "#/components/schemas/MaintenanceIntent"
        );
        assert_eq!(
            schemas["TargetJob"]["allOf"][1]["if"]["required"],
            serde_json::json!(["maintenance"])
        );
        assert!(
            automation["components"]["schemas"]
                .get("MaintenanceStatus")
                .is_none()
        );
        assert!(
            automation["components"]["schemas"]
                .get("MaintenanceIntent")
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn runtime_contract_binds_transient_identity_and_never_expands_automation() -> io::Result<()> {
        let document = super::document(false)?;
        let automation = super::document(true)?;
        let paths = &document["paths"];
        for path in [
            "/api/v1/proxy/runtime",
            "/api/v1/proxy/runtime/drain",
            "/api/v1/proxy/runtime/drains/{runtime_id}/{request_id}",
            "/api/v1/targets/{id}/proxy/runtime",
            "/api/v1/targets/{id}/proxy/runtime/drain",
            "/api/v1/targets/{id}/proxy/runtime/drains/{runtime_id}/{request_id}",
        ] {
            assert!(automation["paths"].get(path).is_none());
            let resource = &paths[path];
            let mutation = path.ends_with("/drain");
            let operation = &resource[if mutation { "post" } else { "get" }];
            assert_eq!(operation["x-vproxy-max-query-bytes"], 0);
            assert_eq!(
                operation["security"],
                if mutation {
                    serde_json::json!([{"Session":[],"Csrf":[]}])
                } else {
                    serde_json::json!([{"Session":[]}])
                }
            );
            assert_eq!(operation.get("requestBody").is_some(), mutation);
            let success = if mutation { "202" } else { "200" };
            assert_eq!(
                operation["responses"][success]["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/ProxyRuntimeStatus"
            );
            if mutation {
                assert_eq!(operation["x-vproxy-max-body-bytes"], 4096);
                assert!(operation["responses"].get("200").is_none());
                assert!(operation["responses"].get("409").is_some());
                assert!(resource.get("head").is_none());
            } else {
                assert!(resource.get("head").is_some());
            }
            if path.contains("{runtime_id}") {
                for name in ["runtime_id", "request_id"] {
                    let parameter = resource["parameters"]
                        .as_array()
                        .ok_or_else(invalid)?
                        .iter()
                        .find(|parameter| parameter["name"] == name)
                        .ok_or_else(invalid)?;
                    assert_eq!(parameter["in"], "path");
                    assert_eq!(parameter["required"], true);
                    assert_eq!(parameter["schema"]["$ref"], "#/components/schemas/Id");
                }
            }
        }
        let local = &paths["/api/v1/proxy/runtime/drain"]["post"];
        let remote = &paths["/api/v1/targets/{id}/proxy/runtime/drain"]["post"];
        assert_eq!(
            local["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ProxyRuntimeDrainRequest"
        );
        assert_eq!(
            remote["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/TargetProxyRuntimeDrainInput"
        );
        assert!(
            remote["responses"]["202"]["headers"]
                .get("Location")
                .is_some()
        );
        assert!(
            remote["responses"]["502"]["description"]
                .as_str()
                .ok_or_else(invalid)?
                .contains("runtime_outcome_unknown")
        );
        assert!(
            paths["/api/v1/proxy/runtime/drains/{runtime_id}/{request_id}"]["get"]["responses"]
                .get("404")
                .is_some()
        );
        let schemas = &document["components"]["schemas"];
        for (name, expected) in [
            (
                "ProxyRuntimeDrainRequest",
                &[
                    "expected_node_id",
                    "expected_epoch",
                    "expected_revision",
                    "runtime_id",
                    "request_id",
                ][..],
            ),
            (
                "TargetProxyRuntimeDrainInput",
                &["expected_target_revision", "request"][..],
            ),
            (
                "ProxyRuntimeState",
                &["runtime_id", "phase", "request", "active_operations"][..],
            ),
            (
                "ProxyRuntimeStatus",
                &[
                    "node_id",
                    "ownership",
                    "saved_revision",
                    "saved_accepting",
                    "runtime",
                ][..],
            ),
        ] {
            let schema = &schemas[name];
            let required = schema["required"]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .map(|value| value.as_str().ok_or_else(invalid))
                .collect::<io::Result<BTreeSet<_>>>()?;
            assert_eq!(required, BTreeSet::from_iter(expected.iter().copied()));
            assert_eq!(
                schema["properties"]
                    .as_object()
                    .ok_or_else(invalid)?
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
                required
            );
            assert_eq!(schema["additionalProperties"], false);
            assert!(schema["properties"].get("runtime_stopped").is_none());
            assert!(automation["components"]["schemas"].get(name).is_none());
        }
        let request = &schemas["ProxyRuntimeDrainRequest"]["properties"];
        for name in ["expected_node_id", "runtime_id", "request_id"] {
            assert_eq!(request[name]["$ref"], "#/components/schemas/Id");
        }
        for name in ["expected_epoch", "expected_revision"] {
            assert_eq!(request[name]["$ref"], "#/components/schemas/Revision");
        }
        assert_eq!(
            schemas["TargetProxyRuntimeDrainInput"]["properties"]["expected_target_revision"]["$ref"],
            "#/components/schemas/Revision"
        );
        assert_eq!(
            schemas["ProxyRuntimeState"]["properties"]["phase"]["enum"],
            serde_json::json!(["serving", "draining", "drained", "interrupted", "failed"])
        );
        assert_eq!(
            schemas["ProxyRuntimeState"]["properties"]["request"]["anyOf"][1]["type"],
            "null"
        );
        assert_eq!(
            schemas["ProxyRuntimeState"]["properties"]["active_operations"]["anyOf"],
            serde_json::json!([{"$ref":"#/components/schemas/Counter"},{"type":"null"}])
        );
        assert_eq!(
            schemas["Counter"]["x-vproxy-maximum-decimal"],
            u64::MAX.to_string()
        );
        assert_eq!(
            schemas["ProxyRuntimeStatus"]["properties"]["runtime"]["anyOf"][1]["type"],
            "null"
        );
        assert_eq!(
            schemas["ProxyRuntimeState"]["oneOf"][0]["properties"]["request"]["type"],
            "null"
        );
        assert_eq!(
            schemas["ProxyRuntimeStatus"]["allOf"][0]["then"]["properties"]["saved_accepting"]["const"],
            false
        );
        assert!(
            paths["/api/v1/proxy/maintenance"]["post"]["description"]
                .as_str()
                .ok_or_else(invalid)?
                .contains("proxy_restart_required")
        );
        Ok(())
    }
}
