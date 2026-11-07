//! An additive, read-only search operation. Old v1 listing parameters and
//! envelopes remain unchanged; a missing search route never falls back to a
//! different scope or silently drops the query.

use super::*;
use crate::manage::user_search::{self, Mode, Query};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/node/v1/proxy/users/search", get(users))
}

async fn users(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<VerifiedPeer>,
    uri: http::Uri,
) -> Result<Response, ApiError> {
    let query = Query::parse(uri.query()).map_err(storage_error)?;
    let authorization = peer.authorization();
    let page = coordinator(&state)?
        .read(move |directory| store::remote_search_users(directory, &authorization, &query))
        .await
        .map_err(storage_error)?;
    respond(
        &state.node_id,
        StatusCode::OK,
        Page {
            revision: page.revision.to_string(),
            items: page.items.into_iter().map(User::from).collect::<Vec<_>>(),
            next_cursor: page.next_cursor,
        },
    )
}

/// Cursor mismatch is client input; a changed snapshot requires an explicit
/// restart. Authorization and internal I/O retain the existing node errors.
pub(in crate::manage) fn storage_error(error: io::Error) -> ApiError {
    if let Some(kind) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<user_search::Error>())
    {
        return ApiError::new(
            if matches!(kind, user_search::Error::Changed) {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            },
            kind.code(),
        );
    }
    super::storage_error(error)
}

/// A TLS-authenticated peer can still send an inconsistent search page. Check
/// the actual rows and both cursor boundaries, rather than trusting the route
/// name or accepting the old plain-ID page codec.
pub(super) fn decode(query: &Query, bytes: &[u8], expected: &str) -> io::Result<Reply> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "inconsistent node user search page",
        )
    };
    let page: Page<User> = client::envelope(bytes, expected, VERSION)?;
    let revision = client::number(&page.revision, false)?;
    let mut previous = query
        .check_cursor(expected, revision)
        .map_err(|_| invalid())?;
    if page.items.len() > query.limit() as usize
        || (query.mode() == Mode::Id && page.next_cursor.is_some())
    {
        return Err(invalid());
    }
    for user in &page.items {
        client::validate_user(user)?;
        if client::number(&user.revision, false)? > revision
            || (!query.include_deleted() && user.deleted)
            || !query.matches(&user.id, &user.name)
            || previous.is_some_and(|id| user.id.as_str() <= id)
        {
            return Err(invalid());
        }
        previous = Some(&user.id);
    }
    if let Some(cursor) = &page.next_cursor {
        let last = page.items.last().ok_or_else(invalid)?;
        // Equality with the canonical encoding checks every binding without
        // reparsing or lowercasing a second copy of the original request.
        let expected_cursor = query
            .next_cursor(expected, revision, &last.id)
            .map_err(|_| invalid())?;
        if page.items.len() != query.limit() as usize || *cursor != expected_cursor {
            return Err(invalid());
        }
    }
    Ok(Reply::UsersSearch(page))
}
