//! Bounded user-search inputs shared by browser and node transports.
//!
//! Cursors bind an observation, not authority: current authentication and node
//! ownership must still be checked before reading the corresponding snapshot.

use std::io;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};

const MAX_QUERY_BYTES: usize = 1_024;
const MAX_TERM_BYTES: usize = 128;
const CURSOR_BYTES: usize = 73;
const CURSOR_LENGTH: usize = 102;
const CURSOR_PREFIX: &str = "us1_";

/// Explicit interpretation prevents an ID-shaped display name changing modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mode {
    Name,
    Id,
}

impl Mode {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Id => "id",
        }
    }
}

/// Stable transport errors do not include submitted names or cursor contents.
#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("user search query is invalid")]
    InvalidQuery,
    #[error("user search cursor is invalid")]
    InvalidCursor,
    #[error("user search snapshot changed")]
    Changed,
}

impl Error {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::InvalidQuery => "invalid_user_search",
            Self::InvalidCursor => "invalid_user_search_cursor",
            Self::Changed => "user_search_changed",
        }
    }

    fn error(self) -> io::Error {
        let kind = match self {
            Self::InvalidQuery | Self::InvalidCursor => io::ErrorKind::InvalidInput,
            Self::Changed => io::ErrorKind::AlreadyExists,
        };
        io::Error::new(kind, self)
    }
}

/// A decoded, fixed-size continuation. The original canonical wire value is
/// retained for forwarding; callers cannot independently change its components.
#[derive(Clone)]
struct Cursor {
    wire: String,
    node_id: String,
    fingerprint: [u8; 32],
    revision: u64,
    after: String,
}

impl Cursor {
    fn parse(wire: String) -> io::Result<Self> {
        let encoded = wire
            .strip_prefix(CURSOR_PREFIX)
            .filter(|_| wire.len() == CURSOR_LENGTH)
            .ok_or_else(|| Error::InvalidCursor.error())?;
        let mut bytes = [0; CURSOR_BYTES];
        if !matches!(
            URL_SAFE_NO_PAD.decode_slice(encoded, &mut bytes),
            Ok(CURSOR_BYTES)
        ) || bytes[0] != 1
            || URL_SAFE_NO_PAD.encode(bytes) != encoded
        {
            return Err(Error::InvalidCursor.error());
        }
        let revision = u64::from_be_bytes(
            bytes[49..57]
                .try_into()
                .map_err(|_| Error::InvalidCursor.error())?,
        );
        if revision == 0 || revision > i64::MAX as u64 {
            return Err(Error::InvalidCursor.error());
        }
        Ok(Self {
            node_id: URL_SAFE_NO_PAD.encode(&bytes[1..17]),
            fingerprint: bytes[17..49]
                .try_into()
                .map_err(|_| Error::InvalidCursor.error())?,
            revision,
            after: URL_SAFE_NO_PAD.encode(&bytes[57..73]),
            wire,
        })
    }
}

/// One validated read request. `q` stays unchanged for remote forwarding;
/// lowercasing it could expand a valid 128-byte term beyond the input limit.
#[derive(Clone)]
pub(super) struct Query {
    mode: Mode,
    q: String,
    needle: String,
    include_deleted: bool,
    limit: u32,
    cursor: Option<Cursor>,
    fingerprint: [u8; 32],
}

impl Query {
    /// Parses an allowlisted form query with strict percent and UTF-8 decoding.
    /// Both `mode` and nonempty `q` are required; duplicate decoded names fail.
    pub(super) fn parse(raw: Option<&str>) -> io::Result<Self> {
        let raw = raw
            .filter(|value| !value.is_empty() && value.len() <= MAX_QUERY_BYTES)
            .ok_or_else(|| Error::InvalidQuery.error())?;
        let mut mode = None;
        let mut q = None;
        let mut after = None;
        let mut limit = 25;
        let mut include_deleted = false;
        let mut seen = [false; 5];
        for pair in raw.split('&') {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| Error::InvalidQuery.error())?;
            let key = decode_component(key)?;
            let value = decode_component(value)?;
            let index = match key.as_str() {
                "mode" => 0,
                "q" => 1,
                "after" => 2,
                "limit" => 3,
                "include_deleted" => 4,
                _ => return Err(Error::InvalidQuery.error()),
            };
            if seen[index] {
                return Err(Error::InvalidQuery.error());
            }
            seen[index] = true;
            match index {
                0 => {
                    mode = Some(match value.as_str() {
                        "name" => Mode::Name,
                        "id" => Mode::Id,
                        _ => return Err(Error::InvalidQuery.error()),
                    });
                }
                1 => q = Some(value),
                2 => after = Some(value),
                3 => {
                    if value.is_empty()
                        || value.starts_with('0')
                        || !value.bytes().all(|byte| byte.is_ascii_digit())
                    {
                        return Err(Error::InvalidQuery.error());
                    }
                    limit = value.parse().map_err(|_| Error::InvalidQuery.error())?;
                }
                4 => {
                    include_deleted = match value.as_str() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(Error::InvalidQuery.error()),
                    };
                }
                _ => return Err(Error::InvalidQuery.error()),
            }
        }
        Self::new(
            mode.ok_or_else(|| Error::InvalidQuery.error())?,
            q.ok_or_else(|| Error::InvalidQuery.error())?,
            include_deleted,
            limit,
            after,
        )
    }

    /// Constructs a bounded request before any blocking work is admitted.
    /// Name matching uses Unicode lowercase, not normalization or full casefold.
    pub(super) fn new(
        mode: Mode,
        q: String,
        include_deleted: bool,
        limit: u32,
        after: Option<String>,
    ) -> io::Result<Self> {
        if q.is_empty()
            || q.len() > MAX_TERM_BYTES
            || q.trim() != q
            || q.chars().any(char::is_control)
            || !(1..=50).contains(&limit)
            || (mode == Mode::Id && identity(&q).is_none())
        {
            return Err(Error::InvalidQuery.error());
        }
        if mode == Mode::Id && after.is_some() {
            return Err(Error::InvalidCursor.error());
        }
        let needle = match mode {
            Mode::Name => q.to_lowercase(),
            Mode::Id => q.clone(),
        };
        let mut hash = Sha256::new();
        hash.update(b"vproxy-user-search-v1\0");
        hash.update([
            match mode {
                Mode::Name => 0,
                Mode::Id => 1,
            },
            u8::from(include_deleted),
            u8::try_from(limit).map_err(|_| Error::InvalidQuery.error())?,
        ]);
        hash.update(
            u16::try_from(needle.len())
                .map_err(|_| Error::InvalidQuery.error())?
                .to_be_bytes(),
        );
        hash.update(needle.as_bytes());
        let fingerprint: [u8; 32] = hash.finalize().into();
        let cursor = after.map(Cursor::parse).transpose()?;
        if cursor
            .as_ref()
            .is_some_and(|value| value.fingerprint != fingerprint)
        {
            return Err(Error::InvalidCursor.error());
        }
        Ok(Self {
            mode,
            q,
            needle,
            include_deleted,
            limit,
            cursor,
            fingerprint,
        })
    }

    pub(super) const fn mode(&self) -> Mode {
        self.mode
    }
    pub(super) fn q(&self) -> &str {
        &self.q
    }
    pub(super) const fn include_deleted(&self) -> bool {
        self.include_deleted
    }
    pub(super) const fn limit(&self) -> u32 {
        self.limit
    }
    pub(super) fn after(&self) -> Option<&str> {
        self.cursor.as_ref().map(|value| value.wire.as_str())
    }

    /// Check an origin-authenticated API page without inventing a node-ID claim.
    ///
    /// IDs must already be validated and strictly ordered by the caller. A prior
    /// cursor binds the revision/lower bound and any next cursor's node; on the
    /// first page the encoded node is only an observation. The server still
    /// authenticates the next request and checks its own node/ownership context.
    pub(super) fn check_page(
        &self,
        revision: u64,
        first_id: Option<&str>,
        last_id: Option<&str>,
        next_cursor: Option<&str>,
    ) -> io::Result<()> {
        if let Some(previous) = &self.cursor {
            if previous.revision != revision {
                return Err(Error::Changed.error());
            }
            if first_id.is_some_and(|id| id <= previous.after.as_str()) {
                return Err(Error::InvalidCursor.error());
            }
        }
        if let Some(wire) = next_cursor {
            let next = Cursor::parse(wire.to_owned())?;
            if self.mode == Mode::Id
                || next.fingerprint != self.fingerprint
                || next.revision != revision
                || Some(next.after.as_str()) != last_id
                || self
                    .cursor
                    .as_ref()
                    .is_some_and(|previous| previous.node_id != next.node_id)
            {
                return Err(Error::InvalidCursor.error());
            }
        }
        Ok(())
    }

    /// Literal matching deliberately gives `%` and `_` no SQL wildcard meaning.
    pub(super) fn matches(&self, id: &str, name: &str) -> bool {
        match self.mode {
            Mode::Name => name.to_lowercase().contains(&self.needle),
            Mode::Id => id == self.q,
        }
    }

    /// Checks the already-authorized snapshot. A changed revision requires a new
    /// search; this does not silently continue through a different policy state.
    pub(super) fn check_cursor(&self, node_id: &str, revision: u64) -> io::Result<Option<&str>> {
        context(node_id, revision)?;
        let Some(cursor) = &self.cursor else {
            return Ok(None);
        };
        if cursor.node_id != node_id || cursor.fingerprint != self.fingerprint {
            return Err(Error::InvalidCursor.error());
        }
        if cursor.revision != revision {
            return Err(Error::Changed.error());
        }
        Ok(Some(&cursor.after))
    }

    /// Encodes one fixed-size observation marker. It is not signed and must
    /// never replace authentication, ownership checks, or the actual filter.
    pub(super) fn next_cursor(
        &self,
        node_id: &str,
        revision: u64,
        last_id: &str,
    ) -> io::Result<String> {
        let node = context(node_id, revision)?;
        let after = identity(last_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "user search row identity is malformed",
            )
        })?;
        let mut bytes = [0; CURSOR_BYTES];
        bytes[0] = 1;
        bytes[1..17].copy_from_slice(&node);
        bytes[17..49].copy_from_slice(&self.fingerprint);
        bytes[49..57].copy_from_slice(&revision.to_be_bytes());
        bytes[57..73].copy_from_slice(&after);
        Ok(format!("{CURSOR_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
    }
}

fn identity(value: &str) -> Option<[u8; 16]> {
    let mut bytes = [0; 16];
    (value.len() == 22
        && matches!(URL_SAFE_NO_PAD.decode_slice(value, &mut bytes), Ok(16))
        && URL_SAFE_NO_PAD.encode(bytes) == value)
        .then_some(bytes)
}

fn context(node_id: &str, revision: u64) -> io::Result<[u8; 16]> {
    if revision == 0 || revision > i64::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "user search policy revision is malformed",
        ));
    }
    identity(node_id).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "user search node identity is malformed",
        )
    })
}

/// Strict form decoding shared with the local target-list adapter. Callers
/// bound the complete query first and map failures into their own API errors.
pub(super) fn decode_component(value: &str) -> io::Result<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = bytes
                    .next()
                    .and_then(hex)
                    .ok_or_else(|| Error::InvalidQuery.error())?;
                let low = bytes
                    .next()
                    .and_then(hex)
                    .ok_or_else(|| Error::InvalidQuery.error())?;
                (high << 4) | low
            }
            value => value,
        });
    }
    String::from_utf8(decoded).map_err(|_| Error::InvalidQuery.error())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NODE: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const OTHER: &str = "AQEBAQEBAQEBAQEBAQEBAQ";

    #[test]
    fn strict_query_decoding_preserves_literals_and_rejects_aliases() -> io::Result<()> {
        let query = Query::parse(Some(
            "mode=name&q=A%2B%20%2F%25_&limit=50&include_deleted=true",
        ))?;
        assert_eq!(query.q(), "A+ /%_");
        assert!(query.matches(NODE, "prefix a+ /%_ suffix"));
        assert!(!query.matches(NODE, "prefix ab cd suffix"));
        assert!(query.include_deleted());
        assert_eq!(query.limit(), 50);
        let cursor = query.next_cursor(NODE, 9, OTHER)?;
        let equivalent = Query::parse(Some(&format!(
            "mode=name&q=a%2b+%2f%25_&limit=50&include_deleted=true&after={cursor}"
        )))?;
        assert_eq!(equivalent.check_cursor(NODE, 9)?, Some(OTHER));
        for raw in [
            "mode=name&q=%FF",
            "mode=name&q=%",
            "mode=name&q=%A",
            "mode=name&q=%GG",
            "mode=name&q=a&q=b",
            "mode=name&q=a&%71=b",
            "mode=name&q=a&extra=x",
            "mode=name&q=a&limit=01",
            "mode=name&q=a&limit=51",
            "mode=name&q=a&include_deleted=1",
            "mode=name&q=+a",
            "mode=name&q=a+",
            "mode=name&q=a%00",
            "mode=name&q=",
            "q=a",
            "mode=id&q=not-id",
            "mode=name&q=a&&limit=2",
        ] {
            assert!(Query::parse(Some(raw)).is_err(), "accepted invalid query");
        }
        assert!(Query::parse(None).is_err());
        assert!(Query::parse(Some(&"x".repeat(MAX_QUERY_BYTES + 1))).is_err());
        assert!(Query::new(Mode::Name, "界".repeat(43), false, 1, None).is_err());
        Ok(())
    }

    #[test]
    fn cursor_binds_canonical_query_node_flags_limit_and_revision() -> io::Result<()> {
        let query = Query::new(Mode::Name, "İ_ABC".into(), false, 2, None)?;
        let cursor = query.next_cursor(NODE, 9, OTHER)?;
        assert_eq!(cursor.len(), CURSOR_LENGTH);
        let next = Query::new(
            Mode::Name,
            "i\u{307}_abc".into(),
            false,
            2,
            Some(cursor.clone()),
        )?;
        assert_eq!(next.check_cursor(NODE, 9)?, Some(OTHER));
        assert_eq!(next.after(), Some(cursor.as_str()));
        assert!(next.check_cursor(OTHER, 9).is_err());
        let changed = next.check_cursor(NODE, 10).unwrap_err();
        assert!(matches!(
            changed
                .get_ref()
                .and_then(|error| error.downcast_ref::<Error>()),
            Some(Error::Changed)
        ));
        for (mode, q, deleted, limit) in [
            (Mode::Name, "other", false, 2),
            (Mode::Name, "İ_ABC", true, 2),
            (Mode::Name, "İ_ABC", false, 3),
            (Mode::Id, OTHER, false, 2),
        ] {
            assert!(Query::new(mode, q.into(), deleted, limit, Some(cursor.clone())).is_err());
        }
        for bad in [
            String::new(),
            "A".repeat(CURSOR_LENGTH),
            format!("{cursor}="),
            cursor.replacen("us1_", "us2_", 1),
        ] {
            assert!(Query::new(Mode::Name, "İ_ABC".into(), false, 2, Some(bad)).is_err());
        }
        let original = URL_SAFE_NO_PAD
            .decode(&cursor[CURSOR_PREFIX.len()..])
            .unwrap();
        for revision in [0, u64::MAX] {
            let mut invalid = original.clone();
            invalid[49..57].copy_from_slice(&revision.to_be_bytes());
            let bad = format!("{CURSOR_PREFIX}{}", URL_SAFE_NO_PAD.encode(invalid));
            assert!(Query::new(Mode::Name, "İ_ABC".into(), false, 2, Some(bad)).is_err());
        }
        Ok(())
    }

    #[test]
    fn explicit_mode_and_raw_term_survive_lowercase_expansion() -> io::Result<()> {
        let id = Query::new(Mode::Id, NODE.into(), false, 25, None)?;
        assert!(id.matches(NODE, "unrelated"));
        assert!(!id.matches(OTHER, NODE));
        let name = Query::new(Mode::Name, NODE.into(), false, 25, None)?;
        assert!(name.matches(OTHER, NODE));
        let expanded = Query::new(Mode::Name, "İ".repeat(64), false, 25, None)?;
        assert_eq!(expanded.q().len(), 128);
        assert!(expanded.needle.len() > 128);
        assert!(expanded.matches(OTHER, &"İ".repeat(64)));
        assert!(
            !Query::new(Mode::Name, "STRASSE".into(), false, 25, None)?.matches(OTHER, "Straße")
        );
        assert!(
            !Query::new(Mode::Name, "cafe\u{301}".into(), false, 25, None)?.matches(OTHER, "café")
        );
        assert_eq!(Mode::Id.as_str(), "id");
        Ok(())
    }
}
