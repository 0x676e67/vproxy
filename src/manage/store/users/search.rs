//! Bounded, non-secret user search inside the caller's read transaction.

use rusqlite::{OptionalExtension as _, types::ValueRef};

use super::{
    Page, UserRecord, UserView, invalid_data, open_existing, read_overview, read_state, read_user,
    sqlite_error, validate_user,
};
use crate::{
    access::MAX_USERS,
    manage::user_search::{Mode, Query},
};
use std::{io, path::Path};

/// Reads a search page without loading credentials or changing policy. Name
/// search scans at most MAX_USERS+1 metadata rows; ID mode uses the primary key.
/// The query, cursor, identity and revision are checked in one read snapshot.
pub(in crate::manage) fn search_users(
    directory: &Path,
    query: &Query,
) -> io::Result<Page<UserView>> {
    let mut connection = open_existing(directory, false)?;
    let transaction = connection
        .transaction()
        .map_err(|error| sqlite_error("cannot begin user search", error))?;
    let page = search_users_in(&transaction, query)?;
    transaction
        .commit()
        .map_err(|error| sqlite_error("cannot complete user search", error))?;
    Ok(page)
}

/// Remote callers authorize exact DER/current ownership in this same snapshot
/// before calling here. A cursor never grants permission to read its node.
pub(in crate::manage::store) fn search_users_in(
    connection: &rusqlite::Connection,
    query: &Query,
) -> io::Result<Page<UserView>> {
    let revision = read_state(connection)?.0;
    let node_id = read_overview(connection)?.node_id;
    let after = query.check_cursor(&node_id, revision)?;
    if query.mode() == Mode::Id {
        let user = connection
            .query_row(
                "SELECT id, name, active, deleted, protocols, concurrent_limit, revision
             FROM proxy_users WHERE id = ?1",
                [query.q()],
                bounded_read_user,
            )
            .optional()
            .map_err(|error| sqlite_error("cannot read exact user search", error))?;
        let mut items = Vec::new();
        if let Some(user) = user {
            validate_user(&user, revision)?;
            if query.include_deleted() || !user.deleted {
                items.push(UserView::from(&user));
            }
        }
        return Ok(Page {
            revision,
            items,
            next_cursor: None,
        });
    }

    // Filtering in SQL, or stopping after enough matches, would hide corrupt
    // rows and deleted tombstones beyond that page from the capacity boundary.
    const MAX_SCAN_ROWS: usize = MAX_USERS + 1;
    let scan_limit = i64::try_from(MAX_SCAN_ROWS)
        .map_err(|_| invalid_data("user search capacity is out of range"))?;
    let mut statement = connection
        .prepare(
            "SELECT id, name, active, deleted, protocols, concurrent_limit, revision
         FROM proxy_users ORDER BY id LIMIT ?1",
        )
        .map_err(|error| sqlite_error("cannot prepare user search", error))?;
    let mut rows = statement
        .query([scan_limit])
        .map_err(|error| sqlite_error("cannot query user search", error))?;
    let limit = query.limit() as usize;
    let retained = limit
        .checked_add(1)
        .ok_or_else(|| invalid_data("user search page capacity is out of range"))?;
    let mut items = Vec::with_capacity(retained);
    let mut scanned = 0;
    while let Some(row) = rows
        .next()
        .map_err(|error| sqlite_error("cannot scan user search", error))?
    {
        if scanned == MAX_USERS {
            // No value from this over-capacity row is copied or interpreted.
            return Err(invalid_data("user search exceeds policy capacity"));
        }
        scanned += 1;
        let user = bounded_read_user(row)
            .map_err(|error| sqlite_error("cannot read user search metadata", error))?;
        validate_user(&user, revision)?;
        if items.len() < retained
            && (query.include_deleted() || !user.deleted)
            && after.is_none_or(|after| user.id.as_str() > after)
            && query.matches(&user.id, &user.name)
        {
            items.push(UserView::from(&user));
        }
    }
    let more = items.len() > limit;
    if more {
        items.pop();
    }
    let next_cursor = if more {
        items
            .last()
            .map(|user| query.next_cursor(&node_id, revision, &user.id))
            .transpose()?
    } else {
        None
    };
    Ok(Page {
        revision,
        items,
        next_cursor,
    })
}

/// Check borrowed SQLite TEXT before `read_user` allocates owned strings. A
/// malformed database cannot turn one bounded metadata row into a giant copy.
fn bounded_read_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserRecord> {
    for (column, minimum, maximum) in [(0, 22, 22), (1, 1, 128)] {
        let value = row.get_ref(column)?;
        if !matches!(value, ValueRef::Text(bytes)
            if (minimum..=maximum).contains(&bytes.len()) && std::str::from_utf8(bytes).is_ok())
        {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                column,
                value.data_type(),
                Box::new(invalid_data("user search text metadata is malformed")),
            ));
        }
    }
    read_user(row)
}
