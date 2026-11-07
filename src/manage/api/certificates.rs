//! Session-only facts from this process's actual TLS identities. Reading never
//! loads a file, probes a listener, starts issuance or changes certificate state.

use super::*;
use crate::manage::contract;
use crate::manage::{
    certificates::{Role, Snapshot, Source, State as IdentityState},
    proxy::Protocol,
};
use utoipa_axum::{router::OpenApiRouter, routes};

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    definition()
        .split_for_parts()
        .0
        .route_layer(middleware::from_fn_with_state(state, users::authenticated))
}

pub(super) fn definition() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new().routes(routes!(status))
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = TlsIdentityStatus)]
struct View {
    #[schema(schema_with = contract::id)]
    node_id: String,
    #[schema(required)]
    observed_at_unix_s: Option<UnixSeconds>,
    #[schema(min_items = 2, max_items = 18)]
    entries: Vec<Entry>,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = TlsIdentityEntry, description = "Only proxy entries have a non-null canonical endpoint id and protocol. Other roles have both null. Node sources and plaintext proxy sources are manual; encrypted Web proxies may follow the node's normal ACME identity across renewal, never a challenge identity. Non-loaded entries have null certificate/valid_now; loaded has metadata, and valid_now is null exactly when observation time is null. not_before <= not_after; valid_now equals the inclusive interval comparison. Management cannot be disabled; node/proxy cannot be pending. HTTP/SOCKS5 proxy entries are disabled; HTTPS/auto/MASQUE are loaded or unavailable.")]
struct Entry {
    #[schema(inline)]
    role: Role,
    #[schema(inline)]
    source: Source,
    #[schema(schema_with = contract::nullable_id, required)]
    id: Option<String>,
    #[schema(inline, required)]
    protocol: Option<Protocol>,
    #[schema(schema_with = identity_states)]
    state: &'static str,
    #[schema(required)]
    certificate: Option<Certificate>,
    #[schema(required)]
    valid_now: Option<bool>,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(as = TlsLeafMetadata)]
struct Certificate {
    /// SHA-256 of the actual installed leaf DER; not a trust decision or a public key pin.
    #[schema(pattern = "^[0-9a-f]{64}$")]
    sha256: String,
    not_before_unix_s: UnixSeconds,
    not_after_unix_s: UnixSeconds,
}

/// Canonical signed i64 Unix seconds. Producer enforces -9223372036854775808 through 9223372036854775807; preserve exact decimals. Pre-epoch values are valid.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(transparent)]
#[schema(as = TlsUnixSeconds, pattern = "^(0|-?[1-9][0-9]{0,18})$", max_length = 20)]
struct UnixSeconds(String);

fn identity_states() -> utoipa::openapi::schema::ObjectBuilder {
    utoipa::openapi::schema::ObjectBuilder::new()
        .schema_type(utoipa::openapi::schema::Type::String)
        .enum_values(Some(["disabled", "pending", "unavailable", "loaded"]))
}

impl From<Snapshot> for View {
    fn from(snapshot: Snapshot) -> Self {
        let entries = snapshot
            .entries
            .into_iter()
            .map(|entry| {
                let (state, certificate) = match entry.state {
                    IdentityState::Disabled => ("disabled", None),
                    IdentityState::Pending => ("pending", None),
                    IdentityState::Unavailable => ("unavailable", None),
                    IdentityState::Loaded(leaf) => (
                        "loaded",
                        Some(Certificate {
                            sha256: leaf.sha256,
                            not_before_unix_s: UnixSeconds(leaf.not_before_unix_s.to_string()),
                            not_after_unix_s: UnixSeconds(leaf.not_after_unix_s.to_string()),
                        }),
                    ),
                };
                Entry {
                    role: entry.role,
                    source: entry.source,
                    id: entry.id,
                    protocol: entry.protocol,
                    state,
                    certificate,
                    valid_now: entry.valid_now,
                }
            })
            .collect();
        Self {
            node_id: snapshot.node_id,
            observed_at_unix_s: snapshot
                .observed_at_unix_s
                .map(|value| UnixSeconds(value.to_string())),
            entries,
        }
    }
}

#[utoipa::path(
    get, path = "/api/v1/tls/status",
    operation_id = "browserTlsIdentityStatus", tag = "TLS",
    summary = "Read this process's actual loaded TLS identity metadata",
    description = "Session only. No query, including an empty query. Reads the installed manual management identity or current ACME normal publication, node mTLS identity, and up to sixteen managed listeners. No file, certificate cache or challenge identity is inspected; no issuance, reload, probe or remote operation is started. Snapshot readiness is separate from listener health. Times include both validity endpoints (RFC 5280 section 4.1.2.5); valid_now says nothing about trust, names, revocation or reachability. Unknown time or metadata is never healthy. No names, subjects, issuers, paths, keys, PEM/DER bytes, accounts or raw errors are returned. Existing /tls/acme remains unchanged. Timestamps are canonical signed i64 decimal seconds, not JavaScript numbers.",
    security(("Session" = [])),
    params(),
    extensions(("x-vproxy-max-query-bytes" = json!(0)), ("x-vproxy-max-response-bytes" = json!(16384))),
    responses(
        (status = 200, description = "One local snapshot; each entry uses the same observation time. Management first, node second, then unique configured proxy endpoints. Disabled node means no node listener; disabled proxies are plaintext HTTP/SOCKS5. Pending is only management ACME before normal publication; unavailable means metadata could not be read, not a TLS failure.", body = View, headers(("Cache-Control" = inline(contract::NoStore)))),
        (status = 400, description = "invalid_query: no query accepted.", body = ref("#/components/schemas/ApiError")),
        (status = 503, description = "tls_status_unavailable: source missing or complete proxy bind publication unavailable. No partial healthy inventory is returned; outer deadline can instead return request_timeout.", body = ref("#/components/schemas/ApiError")),
        (status = "default", response = contract::Error),
    )
)]
async fn status(State(state): State<Arc<AppState>>, uri: Uri) -> Result<Response, ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    let snapshot = state
        .certificates
        .as_ref()
        .ok_or_else(unavailable)?
        .snapshot()
        .map_err(|_| unavailable())?;
    Ok(Json(View::from(snapshot)).into_response())
}

fn unavailable() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "tls_status_unavailable")
}
