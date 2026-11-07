//! Offline OpenAPI export for the administration listener, not node or proxy APIs.
//!
//! Resource fragments stay next to this exporter and are tested against the
//! actual router. Exporting never loads a database, key, certificate or runtime.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};

use serde_json::{Map, Value};

pub(super) fn id() -> utoipa::openapi::Ref {
    utoipa::openapi::Ref::from_schema_name("Id")
}

pub(super) fn revision() -> utoipa::openapi::Ref {
    utoipa::openapi::Ref::from_schema_name("Revision")
}

pub(super) fn nullable_revision() -> utoipa::openapi::Ref {
    utoipa::openapi::Ref::from_schema_name("NullableRevision")
}

pub(super) fn nullable_sequence() -> utoipa::openapi::schema::AnyOfBuilder {
    utoipa::openapi::schema::AnyOfBuilder::new()
        .item(utoipa::openapi::Ref::from_schema_name("Sequence"))
        .item(
            utoipa::openapi::schema::ObjectBuilder::new()
                .schema_type(utoipa::openapi::schema::Type::Null),
        )
}

pub(super) fn target_origin() -> utoipa::openapi::Ref {
    utoipa::openapi::Ref::from_schema_name("TargetOrigin")
}

pub(super) fn target_server_ip() -> utoipa::openapi::Ref {
    utoipa::openapi::Ref::from_schema_name("TargetServerIp")
}

pub(super) fn counter() -> utoipa::openapi::Ref {
    utoipa::openapi::Ref::from_schema_name("Counter")
}

pub(super) fn nullable_id() -> utoipa::openapi::schema::AnyOfBuilder {
    utoipa::openapi::schema::AnyOfBuilder::new()
        .item(id())
        .item(
            utoipa::openapi::schema::ObjectBuilder::new()
                .schema_type(utoipa::openapi::schema::Type::Null),
        )
}

pub(super) fn address_family() -> utoipa::openapi::Ref {
    utoipa::openapi::Ref::from_schema_name("AddressFamily")
}

pub(super) fn name() -> utoipa::openapi::Ref {
    utoipa::openapi::Ref::from_schema_name("Name")
}

pub(super) fn resource_state() -> utoipa::openapi::Ref {
    utoipa::openapi::Ref::from_schema_name("ResourceState")
}

pub(super) fn routing_cidr() -> utoipa::openapi::Ref {
    utoipa::openapi::Ref::from_schema_name("RoutingCidr")
}

pub(super) fn routing_ip() -> utoipa::openapi::Ref {
    utoipa::openapi::Ref::from_schema_name("RoutingIpAddress")
}

pub(super) fn route_ids() -> utoipa::openapi::schema::ArrayBuilder {
    utoipa::openapi::schema::ArrayBuilder::new()
        .items(id())
        .max_items(Some(32))
        .unique_items(true)
}

pub(super) struct NoStore;
impl utoipa::PartialSchema for NoStore {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .enum_values(Some(["no-store"]))
            .into()
    }
}
impl utoipa::ToSchema for NoStore {}

pub(super) struct Error;
impl<'r> utoipa::ToResponse<'r> for Error {
    fn response() -> (&'r str, utoipa::openapi::RefOr<utoipa::openapi::Response>) {
        (
            "Error",
            utoipa::openapi::Ref::new("#/components/responses/Error").into(),
        )
    }
}

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
    let generated = super::api::contract();
    let generated = serde_json::json!({
        "paths": generated.paths,
        "schemas": generated.components.map(|components| components.schemas).unwrap_or_default(),
    });
    for source in FRAGMENTS
        .iter()
        .map(|source| serde_json::from_str(source))
        .chain(std::iter::once(Ok(generated)))
    {
        let Value::Object(mut fragment) = source.map_err(|_| invalid())? else {
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
