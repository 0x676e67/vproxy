//! Exact-byte replay with an independent comparison of the actual net changes.
//! SQLite apply may skip incompatible tables without error; its success alone
//! is not admission. Session row order and indirect flags are not semantics.

use super::*;
use rusqlite::{
    fallible_streaming_iterator::FallibleStreamingIterator,
    hooks::Action,
    session::{ChangesetIter, ConflictAction},
    types::ValueRef,
};
use std::collections::BTreeMap;

/// A bounded normalization index, containing only row/key digests, not a second
/// vector of verifiers. The same limit applies before reserve and on replay.
const MAX_CHANGES: usize = 65_536;

#[derive(Eq, PartialEq)]
struct Row {
    key: [u8; 32],
    change: [u8; 32],
}

/// Validated table shape cached once per table, without retaining column names
/// or searching the composite PK again for every row/column in a batch.
struct Shape {
    columns: usize,
    primary_key: Vec<bool>,
    policy: super::impact::Table,
}

#[derive(Eq, PartialEq)]
pub(super) struct Delta {
    rows: Vec<Row>,
    effect: Option<super::impact::Effect>,
    history_only: bool,
    source_only: bool,
}

impl Delta {
    pub(super) fn source_only(&self) -> bool {
        self.source_only && self.rows.len() == 1
    }
    pub(super) fn row_count(&self) -> usize {
        self.rows.len()
    }
    pub(super) fn history_only(&self) -> bool {
        self.history_only
    }
    pub(super) fn has_business_change(&self) -> bool {
        // One change is always the source singleton appended by the kernel.
        self.rows.len() > 1
    }

    pub(super) fn effect(&self) -> io::Result<super::impact::Effect> {
        self.effect.ok_or_else(invalid)
    }
}

/// Validate each table/column/PK against the exact checked main schema. Sort
/// independent row fingerprints so an equivalent recapture need not reproduce
/// SQLite's unspecified within-table byte order. UPDATE's undefined fields are
/// distinct from SQL NULL; insert/delete values must all be present. Patchsets,
/// duplicate keys, unsupported actions and oversized indexes fail closed.
pub(super) fn delta(connection: &Connection, payload: &[u8]) -> io::Result<Delta> {
    if payload.first() != Some(&b'T') || payload.len() > MAX_PAYLOAD {
        return Err(invalid());
    }
    let mut input = io::Cursor::new(payload);
    // Keep this named fat-pointer slot at the same location until iterator Drop:
    // rusqlite's streaming adapter passes its address to SQLite's read callback.
    let reader: &mut dyn io::Read = &mut input;
    let mut iter = ChangesetIter::start_strm(&reader)
        .map_err(|e| sqlite_error("cannot inspect source changeset", e))?;
    let mut shapes = BTreeMap::new();
    let mut rows = Vec::new();
    let mut policy = super::impact::Tracker::new();
    let mut history_only = true;
    let mut source_only = true;
    while let Some(item) = iter
        .next()
        .map_err(|e| sqlite_error("cannot scan source changeset", e))?
    {
        if rows.len() >= MAX_CHANGES {
            return Err(invalid());
        }
        let op = item
            .op()
            .map_err(|e| sqlite_error("cannot inspect changeset operation", e))?;
        let action = match op.code() {
            Action::SQLITE_INSERT => 1,
            Action::SQLITE_UPDATE => 2,
            Action::SQLITE_DELETE => 3,
            _ => return Err(invalid()),
        };
        let table = op.table_name();
        source_only &= table == "recovery_source";
        history_only &= matches!(
            table,
            "alert_history_state" | "alert_episodes" | "alert_events" | "recovery_source"
        );
        if !super::super::backup::tables(SCHEMA_VERSION).any(|name| name == table) {
            return Err(invalid());
        }
        if !shapes.contains_key(table) {
            let columns = content::columns(connection, table, &mut Sha256::new())?;
            let mut primary_key = vec![false; columns.count];
            for (index, _) in columns.primary_key {
                *primary_key.get_mut(index).ok_or_else(invalid)? = true;
            }
            shapes.insert(
                table.to_owned(),
                Shape {
                    columns: columns.count,
                    primary_key,
                    policy: super::impact::table(connection, table)?,
                },
            );
        }
        let shape = shapes.get(table).ok_or_else(invalid)?;
        policy.row(shape.policy, action);
        if usize::try_from(op.number_of_columns()).ok() != Some(shape.columns) {
            return Err(invalid());
        }
        let pk = item
            .pk()
            .map_err(|e| sqlite_error("cannot inspect changeset primary key", e))?;
        if pk.len() != shape.columns
            || pk
                .iter()
                .zip(&shape.primary_key)
                .any(|(b, expected)| (*b != 0) != *expected)
        {
            return Err(invalid());
        }
        let mut key = Sha256::new();
        key.update(b"vproxy.source.delta.key.v1\0");
        framed(&mut key, table.as_bytes())?;
        let mut change = Sha256::new();
        change.update(b"vproxy.source.delta.row.v1\0");
        framed(&mut change, table.as_bytes())?;
        change.update([action]);
        change.update(
            u64::try_from(shape.columns)
                .map_err(|_| invalid())?
                .to_be_bytes(),
        );
        for (i, is_pk) in pk.iter().map(|b| *b != 0).enumerate() {
            change.update([u8::from(is_pk)]);
            let old = if action == 1 {
                None
            } else {
                slot(item.old_value(i), i, action == 2)?
            };
            let new = if action == 3 {
                None
            } else {
                slot(item.new_value(i), i, action == 2)?
            };
            if action == 2
                && ((is_pk && (old.is_none() || new.is_some()))
                    || (!is_pk && old.is_some() != new.is_some()))
            {
                return Err(invalid());
            }
            policy.cell(shape.policy, i, old, new);
            for value in [old, new] {
                match value {
                    None => change.update([0]),
                    Some(value) => {
                        change.update([1]);
                        content::cell(&mut change, value)?;
                    }
                }
            }
            if is_pk {
                let value = (if action == 1 { new } else { old }).ok_or_else(invalid)?;
                if matches!(value, ValueRef::Null) {
                    return Err(invalid());
                }
                key.update(u64::try_from(i).map_err(|_| invalid())?.to_be_bytes());
                content::cell(&mut key, value)?;
            }
        }
        rows.try_reserve(1)
            .map_err(|_| io::Error::other("cannot reserve bounded changeset index"))?;
        rows.push(Row {
            key: key.finalize().into(),
            change: change.finalize().into(),
        });
    }
    drop(iter);
    if rows.is_empty() {
        return Err(invalid());
    }
    rows.sort_unstable_by_key(|r| r.key);
    if rows.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return Err(invalid());
    }
    Ok(Delta {
        rows,
        effect: policy.finish(),
        history_only,
        source_only,
    })
}

fn slot<'a>(
    result: rusqlite::Result<ValueRef<'a>>,
    index: usize,
    undefined: bool,
) -> io::Result<Option<ValueRef<'a>>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(rusqlite::Error::InvalidColumnIndex(i)) if undefined && i == index => Ok(None),
        Err(e) => Err(sqlite_error("cannot inspect changeset value", e)),
    }
}

fn framed(hash: &mut Sha256, bytes: &[u8]) -> io::Result<()> {
    hash.update(
        u64::try_from(bytes.len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    hash.update(bytes);
    Ok(())
}

/// A zeroizing, capped capture used only while verifying a replay. It does not
/// cap SQLite Session's internal C heap/time or remain across network waits.
struct Capture(Zeroizing<Vec<u8>>);

/// Export one Session through the existing capped, zeroizing Rust buffer.
/// This bounds the exported image, not Session's internal C allocations.
pub(super) fn session_payload(session: &mut Session<'_>) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut output = Capture(Zeroizing::new(Vec::new()));
    session
        .changeset_strm(&mut output)
        .map_err(|e| sqlite_error("cannot export bounded source changes", e))?;
    Ok(output.0)
}
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let total = self
            .0
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_PAYLOAD)
            .ok_or_else(invalid)?;
        if total > self.0.capacity() {
            let capacity = self
                .0
                .capacity()
                .max(1024)
                .checked_mul(2)
                .unwrap_or(MAX_PAYLOAD)
                .max(total)
                .min(MAX_PAYLOAD);
            let additional = capacity.checked_sub(self.0.len()).ok_or_else(invalid)?;
            self.0
                .try_reserve_exact(additional)
                .map_err(|_| io::Error::other("cannot reserve bounded replay capture"))?;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Apply only an exact Pending operation to its original local preimage. No
/// business callback runs and no replacement ID, payload or secret is created.
/// Conflicts always abort. Actual net changes, schema, FK, source floor, key pin
/// and candidate authority are rechecked before the existing one-use COMMIT.
/// Every commit error remains unknown; confirmation is still separately needed.
pub(super) fn restore<'a>(
    scope: Scope<'a>,
    connection: &'a mut Connection,
    intent: Intent,
    pending: &Fetched<Record>,
) -> io::Result<Committed<'a, ()>> {
    if !connection.is_autocommit() {
        return Err(invalid());
    }
    scope.validate(connection)?;
    intent.metadata.validate(scope.enrollment)?;
    intent.verify_payload()?;
    let veto = Veto::new(connection)?;
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin original source replay", e))?;
    scope.authorize(&tx, pending)?;
    if !intent.metadata.matches(&pending.value, Phase::Pending)
        || scope.state(&tx)? != intent.metadata.before_state()
        || content::schema(&tx)? != intent.metadata.schema_sha256
        || recovery::startup_in(&tx)? != intent.metadata.recovery_key_sha256
    {
        return Err(denied());
    }
    let (tx, effect) = if let Some(seal) = &intent.metadata.segmented {
        let mut input = segments::Input::open(&intent.directory, seal)?;
        (
            segments::replay(tx, &veto, &mut input)?,
            Some(Effect::Unchanged),
        )
    } else {
        let execution = execution::Execution::new(
            &tx,
            if intent.metadata.snapshot.is_some() {
                execution::Limits::SNAPSHOT
            } else {
                execution::Limits::MUTATION
            },
        )?;
        let payload = intent.payload()?;
        if let Some(snapshot) = &intent.metadata.snapshot {
            super::snapshot::check_payload(&tx, &intent)?;
            if content::calculate(&tx, None)? != snapshot.database_content_sha256 {
                return Err(denied());
            }
        }
        if intent.metadata.format == 5 {
            super::snapshot::check_payload(&tx, &intent)?;
        }
        let effect = apply_raw(
            &tx,
            &payload,
            intent.metadata.snapshot.is_some() || intent.metadata.format == 5,
        )?;
        execution.finish()?;
        (tx, effect)
    };
    if content::schema(&tx)? != intent.metadata.schema_sha256 {
        return Err(invalid());
    }
    Prepared {
        transaction: tx,
        veto,
        scope,
        intent,
        value: (),
        effect,
    }
    .commit(pending)
}

fn apply_raw(tx: &Transaction<'_>, payload: &[u8], snapshot: bool) -> io::Result<Option<Effect>> {
    let connection: &Connection = tx;
    let expected = delta(tx, payload)?;
    if if snapshot {
        !expected.source_only()
    } else {
        !expected.has_business_change()
    } {
        return Err(invalid());
    }
    let mut session =
        Session::new(connection).map_err(|e| sqlite_error("cannot capture original replay", e))?;
    for table in super::super::backup::tables(SCHEMA_VERSION) {
        session
            .attach(Some(table))
            .map_err(|e| sqlite_error("cannot attach replay table", e))?;
    }
    tx.apply_strm(
        &mut io::Cursor::new(payload),
        None::<fn(&str) -> bool>,
        |_, _| ConflictAction::SQLITE_CHANGESET_ABORT,
    )
    .map_err(|e| sqlite_error("cannot apply original source intent", e))?;
    let actual = session_payload(&mut session)?;
    drop(session);
    let fk: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot verify replay foreign keys", e))?;
    if fk || expected != delta(tx, &actual)? {
        return Err(invalid());
    }
    drop(actual);
    Ok(expected.effect)
}
