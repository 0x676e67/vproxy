//! Caller-bound local user operations. IDs identify records, not capabilities;
//! every store snapshot rechecks the administrator or current machine key.

use super::*;
use crate::manage::store::operations::{
    self, Caller, Operation, State as OperationState, UserChange,
};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/proxy/user-operations", get(list).post(reserve))
        .route("/api/v1/proxy/user-operations/context", get(context))
        .route("/api/v1/proxy/user-operations/{id}", get(find))
        .route("/api/v1/proxy/user-operations/{id}/execute", post(execute))
}

/// Revisions stay lossless decimal strings, with the actual actor supplied only
/// by authentication middleware. No credential mutation or client-selected ID can
/// enter a reservation through this vocabulary.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    #[serde(default, deserialize_with = "node_binding")]
    expected_node_id: Option<String>,
    expected_revision: String,
    expected_epoch: String,
    change: UserChange,
}

impl Input {
    fn into_store(self) -> Result<operations::Input, ApiError> {
        if self
            .expected_node_id
            .as_deref()
            .is_some_and(|id| !store::valid_id(id))
        {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_operation"));
        }
        Ok(operations::Input {
            expected_node_id: self.expected_node_id,
            expected_revision: revision(&self.expected_revision)?,
            expected_epoch: revision(&self.expected_epoch)?,
            change: self.change,
        })
    }
}

/// Missing keeps legacy clients compatible; a present null is not a binding.
fn node_binding<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

/// A historical, non-secret result; Saved deliberately says nothing about the
/// current running proxy or later edits. Input names and secrets are not stored
/// in, or reconstructed by, these responses.
#[derive(Serialize)]
struct View {
    id: String,
    node_id: String,
    sequence: String,
    expected_revision: String,
    expected_epoch: String,
    action: String,
    user_id: Option<String>,
    state: &'static str,
    saved_revision: Option<String>,
    rejection: Option<String>,
}

impl From<Operation> for View {
    fn from(operation: Operation) -> Self {
        Self {
            id: operation.id,
            node_id: operation.node_id,
            sequence: operation.sequence.to_string(),
            expected_revision: operation.expected_revision.to_string(),
            expected_epoch: operation.expected_epoch.to_string(),
            action: operation.action.to_string(),
            user_id: operation.user_id,
            state: match operation.state {
                OperationState::Reserved => "reserved",
                OperationState::Saved => "saved",
                OperationState::Rejected => "rejected",
            },
            saved_revision: operation.saved_revision.map(|value| value.to_string()),
            rejection: operation.rejection.map(|value| value.to_string()),
        }
    }
}

fn storage(error: io::Error) -> ApiError {
    if let Some(known) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<operations::Error>())
    {
        let status = match known {
            operations::Error::UpgradeRequired => StatusCode::SERVICE_UNAVAILABLE,
            operations::Error::InvalidOperation => StatusCode::BAD_REQUEST,
            operations::Error::NotQueryable => StatusCode::NOT_FOUND,
            operations::Error::Conflict | operations::Error::Capacity => StatusCode::CONFLICT,
            operations::Error::Denied => StatusCode::FORBIDDEN,
        };
        return ApiError::new(status, known.code());
    }
    automation::storage_error(error)
}

fn caller(
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
) -> Result<Caller, ApiError> {
    match (administrator, key) {
        (Some(Extension(Administrator(id))), None) => Ok(Caller::Administrator(id)),
        (None, Some(Extension(key))) => Ok(Caller::Automation(key)),
        _ => Err(ApiError::authentication_required()),
    }
}

/// One authenticated snapshot for preparing a reservation, not a reusable
/// authorization. Reserve and execute recheck caller, ownership and revision.
async fn context(
    State(state): State<Arc<AppState>>,
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let caller = caller(administrator, key)?;
    if uri.query().is_some_and(|query| !query.is_empty()) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    let context = coordinator(&state)?
        .read(move |directory| operations::context(directory, &caller))
        .await
        .map_err(storage)?;
    #[derive(Serialize)]
    struct Context {
        node_id: String,
        policy_revision: String,
        expected_epoch: String,
        local: bool,
    }
    Ok(Json(Context {
        node_id: context.node_id,
        policy_revision: context.policy_revision.to_string(),
        expected_epoch: context.expected_epoch.to_string(),
        local: context.local,
    })
    .into_response())
}

async fn reserve(
    State(state): State<Arc<AppState>>,
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
    request: Request,
) -> Result<Response, ApiError> {
    let actor = caller(administrator, key)?;
    let input = json::<Input>(request).await?.into_store()?;
    let operation = coordinator(&state)?
        .reserve_user_operation(actor, input)
        .await
        .map_err(storage)?;
    Ok((StatusCode::CREATED, Json(View::from(operation))).into_response())
}

async fn execute(
    State(state): State<Arc<AppState>>,
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Result<Response, ApiError> {
    let actor = caller(administrator, key)?;
    let id = resource_id(path)?;
    let input = json::<Input>(request).await?.into_store()?;
    let operation = coordinator(&state)?
        .execute_user_operation(actor, id, input)
        .await
        .map_err(storage)?;
    Ok(Json(View::from(operation)).into_response())
}

async fn find(
    State(state): State<Arc<AppState>>,
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Response, ApiError> {
    let actor = caller(administrator, key)?;
    let id = resource_id(path)?;
    let operation = coordinator(&state)?
        .read(move |directory| match &actor {
            Caller::Administrator(administrator) => operations::get(directory, administrator, &id),
            Caller::Automation(_) => operations::get_as(directory, &actor, &id),
        })
        .await
        .map_err(storage)?;
    Ok(Json(View::from(operation)).into_response())
}

/// List only the authenticated caller's bounded records in descending durable
/// sequence order. The cursor is an exclusive sequence bound, never a claim
/// that the newest record belongs to a previously lost browser request.
async fn list(
    State(state): State<Arc<AppState>>,
    administrator: Option<Extension<Administrator>>,
    key: Option<Extension<automation::Key>>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let actor = caller(administrator, key)?;
    let (before, limit) = pagination(&uri)?;
    let page = coordinator(&state)?
        .read(move |directory| match &actor {
            Caller::Administrator(administrator) => {
                operations::list(directory, administrator, before, limit)
            }
            Caller::Automation(_) => operations::list_as(directory, &actor, before, limit),
        })
        .await
        .map_err(storage)?;
    #[derive(Serialize)]
    struct Page {
        items: Vec<View>,
        next_cursor: Option<String>,
    }
    Ok(Json(Page {
        items: page.items.into_iter().map(View::from).collect(),
        next_cursor: page.next_cursor.map(|value| value.to_string()),
    })
    .into_response())
}

fn pagination(uri: &Uri) -> Result<(Option<u64>, u32), ApiError> {
    let invalid = || ApiError::new(StatusCode::BAD_REQUEST, "invalid_pagination");
    let query = uri.query().unwrap_or_default();
    if query.len() > 1024 {
        return Err(invalid());
    }
    let mut before = None;
    let mut limit = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "before" if before.is_none() => before = Some(revision(&value)?),
            "limit" if limit.is_none() => {
                let parsed = revision(&value)?;
                limit = Some(
                    u32::try_from(parsed)
                        .ok()
                        .filter(|n| *n <= 50)
                        .ok_or_else(invalid)?,
                );
            }
            _ => return Err(invalid()),
        }
    }
    Ok((before, limit.unwrap_or(25)))
}
