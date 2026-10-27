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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const NODE: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const FIRST: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    const SECOND: &str = "AgICAgICAgICAgICAgICAg";

    fn search_query(after: Option<String>) -> Query {
        Query::new(Mode::Name, "Alİce_%".into(), false, 1, after).unwrap()
    }

    fn user(id: &str) -> Value {
        json!({"id":id,"name":"test ALİCE_% literal","active":true,"deleted":false,"protocols":["http"],"concurrent_limit":1,"revision":"1"})
    }

    fn wire(data: Value) -> Vec<u8> {
        serde_json::to_vec(
            &json!({"version":1,"node_id":NODE,"resource":"proxy_policy","data":data}),
        )
        .unwrap()
    }

    #[test]
    fn user_search_checks_rows_and_every_cursor_binding_not_only_the_page_shape() {
        let query = search_query(None);
        let cursor = query.next_cursor(NODE, 7, FIRST).unwrap();
        let data = json!({"revision":"7","items":[user(FIRST)],"next_cursor":cursor});
        assert!(matches!(
            decode(&query, &wire(data.clone()), NODE),
            Ok(Reply::UsersSearch(_))
        ));

        let mut invalid = Vec::new();
        for replacement in [json!("AlİceX%"), json!("another user")] {
            let mut page = data.clone();
            page["items"][0]["name"] = replacement;
            invalid.push(page);
        }
        for (key, replacement) in [
            ("revision", json!("8")),
            ("next_cursor", json!(FIRST)),
            ("items", json!([])),
            ("items", json!([user(FIRST), user(SECOND)])),
        ] {
            let mut page = data.clone();
            page[key] = replacement;
            invalid.push(page);
        }
        for (key, replacement) in [
            ("deleted", json!(true)),
            ("revision", json!("8")),
            ("secret", json!("not allowed")),
        ] {
            let mut page = data.clone();
            page["items"][0][key] = replacement;
            invalid.push(page);
        }
        for wrong in [
            Query::new(Mode::Name, "other".into(), false, 1, None).unwrap(),
            Query::new(Mode::Name, query.q().into(), true, 1, None).unwrap(),
            Query::new(Mode::Name, query.q().into(), false, 2, None).unwrap(),
        ] {
            let mut page = data.clone();
            page["next_cursor"] = json!(wrong.next_cursor(NODE, 7, FIRST).unwrap());
            invalid.push(page);
        }
        for (node, revision, last) in [(SECOND, 7, FIRST), (NODE, 8, FIRST), (NODE, 7, SECOND)] {
            let mut page = data.clone();
            page["next_cursor"] = json!(query.next_cursor(node, revision, last).unwrap());
            invalid.push(page);
        }
        for page in invalid {
            assert!(decode(&query, &wire(page), NODE).is_err());
        }

        let after = query.next_cursor(NODE, 7, FIRST).unwrap();
        let next_query = search_query(Some(after));
        assert!(decode(&next_query, &wire(data), NODE).is_err());
        let valid = json!({"revision":"7","items":[user(SECOND)],"next_cursor":null});
        assert!(matches!(
            decode(&next_query, &wire(valid.clone()), NODE),
            Ok(Reply::UsersSearch(_))
        ));
        let mut stale = valid;
        stale["revision"] = json!("8");
        assert!(decode(&next_query, &wire(stale), NODE).is_err());
    }

    #[test]
    fn user_search_encoder_keeps_valid_raw_unicode_query_and_fixed_read_path() {
        for term in [
            "İ".repeat(64),
            "%".repeat(128),
            "\"".repeat(128),
            "\\".repeat(128),
        ] {
            let initial = Query::new(Mode::Name, term.clone(), true, 50, None).unwrap();
            let after = initial.next_cursor(NODE, 7, FIRST).unwrap();
            let query = Query::new(Mode::Name, term, true, 50, Some(after)).unwrap();
            let (method, path, body) =
                client::encode(&Request::UsersSearch(query.clone())).unwrap();
            assert_eq!(method, Method::GET);
            assert!(path.starts_with("/node/v1/proxy/users/search?"));
            assert!(body.is_empty());
            let raw = path.split_once('?').unwrap().1;
            assert!(raw.len() <= 1024);
            let parsed = Query::parse(Some(raw)).unwrap();
            assert_eq!(parsed.q(), query.q());
            assert_eq!(parsed.check_cursor(NODE, 7).unwrap(), Some(FIRST));
            assert!(parsed.matches(FIRST, query.q()));
        }
    }

    #[test]
    fn user_id_search_is_case_sensitive_and_cannot_claim_another_id_or_next_page() {
        let query = Query::new(Mode::Id, FIRST.into(), true, 25, None).unwrap();
        let data = json!({"revision":"1","items":[user(FIRST)],"next_cursor":null});
        assert!(matches!(
            decode(&query, &wire(data.clone()), NODE),
            Ok(Reply::UsersSearch(_))
        ));
        let mut invalid = data;
        invalid["items"][0]["id"] = json!(SECOND);
        assert!(decode(&query, &wire(invalid), NODE).is_err());
    }
}
