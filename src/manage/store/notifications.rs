//! Single bounded webhook destination and durable request, schema23. Secrets
//! inherit the management database's private permissions and backup boundary.
//! No database transaction or per-operation writer permit is held during HTTP.

use std::{io, path::Path};

use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{
    UpdateGuard, invalid_data, peers::open_existing, read_overview, sqlite_error, valid_id,
};
use crate::manage::notifications::{
    self, Change, DeliveryView, Destination, Envelope, Event, Outcome, Pending, Retry, View,
};

const MAX_STATE: usize = 48 * 1024;

mod write;
pub(in crate::manage) use write::Writer;

/// Configuration receipts bind an exact request and administrator. Only the
/// latest receipt is retained; a later revision cannot prove an older outcome.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    id: String,
    actor: String,
    digest: [u8; 32],
}

/// Canonical singleton snapshot: one configuration generation, its current
/// delivery cursor and at most one immutable pending body. Publication is one
/// FULL-durability SQLite transaction; no unbounded notification queue is kept.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    revision: u64,
    enabled: bool,
    automatic_retry: bool,
    destination: Destination,
    receipt: Option<Receipt>,
    cursor: u64,
    skipped: u64,
    accepted: Option<String>,
    discarded: Option<String>,
    pending: Option<Pending>,
}

/// Sanitized failures only; transport URLs, tokens, SQL and paths are excluded.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(in crate::manage) enum Error {
    #[error("invalid webhook input")]
    Invalid,
    #[error("webhook state changed")]
    Conflict,
    #[error("webhook administrator denied")]
    Denied,
    #[error("webhook schema upgrade required")]
    UpgradeRequired,
}
impl Error {
    pub(in crate::manage) fn error(self) -> io::Error {
        io::Error::new(
            match self {
                Self::Invalid => io::ErrorKind::InvalidInput,
                Self::Conflict => io::ErrorKind::AlreadyExists,
                Self::Denied => io::ErrorKind::PermissionDenied,
                Self::UpgradeRequired => io::ErrorKind::Unsupported,
            },
            self,
        )
    }
}

pub(super) fn create_schema(connection: &Connection) -> io::Result<()> {
    connection.execute_batch("CREATE TABLE webhook_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1), payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 49152)) STRICT;")
        .map_err(|e| sqlite_error("cannot create webhook state", e))?;
    connection
        .execute(
            "INSERT INTO webhook_state VALUES(1,?1)",
            [encode(&State::default())?.as_slice()],
        )
        .map_err(|e| sqlite_error("cannot initialize webhook state", e))?;
    Ok(())
}

fn corrupt() -> io::Error {
    invalid_data("webhook state is malformed")
}
fn decimal(value: &str) -> io::Result<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|n| n.to_string() == value && *n <= i64::MAX as u64)
        .ok_or_else(corrupt)
}
fn encode<T: Serialize>(value: &T) -> io::Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| corrupt())?);
    if bytes.is_empty() || bytes.len() > MAX_STATE {
        return Err(corrupt());
    }
    Ok(bytes)
}

fn load(connection: &Connection) -> io::Result<State> {
    let count: i64 = connection
        .query_row("SELECT count(*) FROM webhook_state", [], |r| r.get(0))
        .map_err(|e| sqlite_error("cannot inspect webhook state", e))?;
    if count != 1 {
        return Err(corrupt());
    }
    let bytes = Zeroizing::new(
        connection
            .query_row(
                "SELECT payload FROM webhook_state WHERE singleton=1",
                [],
                |r| match r.get_ref(0)? {
                    rusqlite::types::ValueRef::Blob(v) if !v.is_empty() && v.len() <= MAX_STATE => {
                        Ok(v.to_vec())
                    }
                    _ => Err(rusqlite::Error::InvalidQuery),
                },
            )
            .map_err(|e| sqlite_error("cannot read webhook state", e))?,
    );
    let state: State = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
    if *encode(&state)? != *bytes {
        return Err(corrupt());
    }
    validate(&state)?;
    if let Some(p) = &state.pending {
        let node: String = connection
            .query_row(
                "SELECT node_id FROM node_identity WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(|e| sqlite_error("cannot bind webhook observer", e))?;
        if p.envelope.observer_node_id != node {
            return Err(corrupt());
        }
    }
    Ok(state)
}

fn validate(s: &State) -> io::Result<()> {
    if s.revision == 0
        && (s.enabled
            || s.automatic_retry
            || !s.destination.url.is_empty()
            || s.cursor != 0
            || s.skipped != 0
            || s.accepted.is_some()
            || s.discarded.is_some()
            || s.pending.is_some())
    {
        return Err(corrupt());
    }
    if s.revision > i64::MAX as u64
        || s.cursor > i64::MAX as u64
        || s.skipped > s.cursor
        || s.enabled && s.destination.url.is_empty()
        || !s.destination.url.is_empty() && !notifications::transport::validate(&s.destination)
        || s.destination.url.is_empty() && !s.destination.bearer.is_empty()
        || s.accepted.as_ref().is_some_and(|id| !valid_id(id))
        || s.discarded.as_ref().is_some_and(|id| !valid_id(id))
        || (s.revision == 0) != s.receipt.is_none()
        || s.receipt
            .as_ref()
            .is_some_and(|r| !valid_id(&r.id) || !valid_id(&r.actor))
    {
        return Err(corrupt());
    }
    if let Some(p) = &s.pending {
        let e = &p.envelope;
        let after = decimal(&e.after_sequence)?;
        let through = decimal(&e.through_sequence)?;
        let trimmed = decimal(&e.history_trimmed_through)?;
        if !s.enabled
            || e.version != 1
            || !valid_id(&e.delivery_id)
            || !valid_id(&e.observer_node_id)
            || after != s.cursor
            || through <= after
            || trimmed > through
            || e.events.len() > notifications::MAX_EVENTS
            || serde_json::to_vec(e).map_err(|_| corrupt())?.len() > notifications::MAX_BODY
            || p.outcome == Outcome::Accepted
            || p.attempts == 0 && p.outcome != Outcome::Ready
            || p.http_status
                .is_some_and(|code| !(100..=599).contains(&code))
            || match p.outcome {
                Outcome::Rejected | Outcome::Deferred => {
                    p.http_status.is_none_or(|code| (200..=299).contains(&code))
                }
                _ => p.http_status.is_some(),
            }
        {
            return Err(corrupt());
        }
        let mut previous = after.max(trimmed);
        for item in &e.events {
            let sequence = decimal(&item.sequence)?;
            if sequence != previous.checked_add(1).ok_or_else(corrupt)?
                || !valid_id(&item.origin_node_id)
                || decimal(&item.episode_id)? == 0
                || decimal(&item.episode_id)? > sequence
                || item.code.is_empty()
                || item.code.len() > 96
                || !item
                    .code
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
                || item.resource_id.as_ref().is_some_and(|id| !valid_id(id))
                || item
                    .observed_at_unix_ms
                    .as_ref()
                    .is_some_and(|v| v.parse::<u64>().ok().is_none_or(|n| n.to_string() != *v))
            {
                return Err(corrupt());
            }
            previous = sequence;
        }
        if previous != through {
            return Err(corrupt());
        }
    }
    Ok(())
}

fn save(connection: &Connection, state: &State) -> io::Result<()> {
    validate(state)?;
    let bytes = encode(state)?;
    let written = connection
        .execute(
            "UPDATE webhook_state SET payload=?1 WHERE singleton=1",
            [bytes.as_slice()],
        )
        .map_err(|e| sqlite_error("cannot write webhook state", e))?;
    // A malformed schema/trigger must not produce an HTTP permit without the
    // exact durable attempt marker. Read back before the enclosing commit.
    if written != 1 || *encode(&load(connection)?)? != *bytes {
        return Err(corrupt());
    }
    Ok(())
}

pub(super) fn validate_schema(connection: &Connection, version: u32) -> io::Result<()> {
    let present: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='webhook_state'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect webhook namespace", e))?;
    if version < 23 {
        return if present == 0 { Ok(()) } else { Err(corrupt()) };
    }
    if present != 1 {
        return Err(corrupt());
    }
    load(connection).map(|_| ())
}

fn require(connection: &Connection) -> io::Result<String> {
    let overview = read_overview(connection)?;
    if overview.schema_version < 23 {
        return Err(Error::UpgradeRequired.error());
    }
    Ok(overview.node_id)
}
fn administrator(connection: &Connection, actor: &str) -> io::Result<()> {
    let yes: bool = valid_id(actor)
        && connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM administrators WHERE id=?1)",
                [actor],
                |r| r.get(0),
            )
            .map_err(|e| sqlite_error("cannot authorize webhook administrator", e))?;
    if !yes {
        return Err(Error::Denied.error());
    }
    Ok(())
}
fn view(node: String, s: &State) -> View {
    View {
        node_id: node,
        revision: s.revision.to_string(),
        enabled: s.enabled,
        automatic_retry: s.automatic_retry,
        configured: !s.destination.url.is_empty(),
        has_bearer: !s.destination.bearer.is_empty(),
        operation_id: s.receipt.as_ref().map(|r| r.id.clone()),
        cursor: s.cursor.to_string(),
        skipped_through: s.skipped.to_string(),
        last_accepted_delivery_id: s.accepted.clone(),
        discarded_delivery_id: s.discarded.clone(),
        pending: s.pending.as_ref().map(|p| DeliveryView {
            id: p.envelope.delivery_id.clone(),
            attempts: p.attempts,
            outcome: p.outcome,
            http_status: p.http_status,
            after_sequence: p.envelope.after_sequence.clone(),
            through_sequence: p.envelope.through_sequence.clone(),
            history_trimmed_through: p.envelope.history_trimmed_through.clone(),
            event_count: p.envelope.events.len(),
            automatic_retry_eligible: eligible(s, p),
        }),
    }
}

pub(in crate::manage) fn status(directory: &Path, actor: &str) -> io::Result<View> {
    let mut connection = open_existing(directory, false)?;
    let tx = connection
        .transaction()
        .map_err(|e| sqlite_error("cannot begin webhook read", e))?;
    let node = require(&tx)?;
    administrator(&tx, actor)?;
    Ok(view(node, &load(&tx)?))
}

/// CAS writes never perform DNS or HTTP. Changing configuration skips existing
/// history; discarding an in-flight request requires explicit acknowledgement.
/// The last exact receipt supports read-after-unknown without repeating secrets.
pub(in crate::manage) fn change(
    directory: &Path,
    gate: &UpdateGuard,
    actor: &str,
    input: &Change,
) -> io::Result<View> {
    let (revision, digest) = validate_change(input)?;
    gate.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin webhook change", e))?;
    let (view, changed) = change_in(&tx, actor, input, revision, digest)?;
    if changed {
        tx.commit()
            .map_err(|e| sqlite_error("cannot commit webhook change", e))?;
    }
    Ok(view)
}

fn validate_change(input: &Change) -> io::Result<(u64, [u8; 32])> {
    if !valid_id(&input.operation_id)
        || !valid_id(&input.expected_node_id)
        || input.bearer.is_some() && input.clear_bearer
        || input.url.as_ref().is_some_and(|v| v.is_empty())
        || input.bearer.as_ref().is_some_and(|v| v.is_empty())
        || input.clear_destination
            && (input.enabled
                || input.url.is_some()
                || input.bearer.is_some()
                || input.clear_bearer)
    {
        return Err(Error::Invalid.error());
    }
    let revision = decimal(&input.expected_revision).map_err(|_| Error::Invalid.error())?;
    let digest: [u8; 32] = Sha256::digest(encode(input)?.as_slice()).into();
    Ok((revision, digest))
}

/// Stage one exact administrator/CAS change. The bool marks changed SQL, not
/// confirmation; a duplicate receipt has no new sequence or secret output.
fn change_in(
    tx: &Connection,
    actor: &str,
    input: &Change,
    revision: u64,
    digest: [u8; 32],
) -> io::Result<(View, bool)> {
    require_transaction(tx)?;
    let node = require(tx)?;
    administrator(tx, actor)?;
    let mut state = load(tx)?;
    if node != input.expected_node_id {
        return Err(Error::Conflict.error());
    }
    if let Some(receipt) = &state.receipt
        && receipt.id == input.operation_id
    {
        return if receipt.actor == actor && receipt.digest == digest {
            Ok((view(node, &state), false))
        } else {
            Err(Error::Conflict.error())
        };
    }
    if state.revision != revision || state.pending.is_some() && !input.discard_pending {
        return Err(Error::Conflict.error());
    }
    if let Some(url) = &input.url {
        state.destination.url.zeroize();
        state.destination.url = url.clone();
    }
    if let Some(bearer) = &input.bearer {
        state.destination.bearer.zeroize();
        state.destination.bearer = bearer.clone();
    }
    if input.clear_bearer {
        state.destination.bearer.zeroize();
    }
    if input.clear_destination {
        state.destination = Destination::default();
    }
    if (input.enabled || !state.destination.url.is_empty())
        && !notifications::transport::validate(&state.destination)
    {
        return Err(Error::Invalid.error());
    }
    let last = super::alerts::history::notification_watermark(tx)?;
    if last < state.cursor {
        return Err(corrupt());
    }
    state.revision = state
        .revision
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(|| Error::Conflict.error())?;
    state.enabled = input.enabled;
    state.automatic_retry = input.automatic_retry;
    state.cursor = last;
    state.skipped = last;
    if let Some(p) = state.pending.take() {
        state.discarded = Some(p.envelope.delivery_id);
    }
    state.receipt = Some(Receipt {
        id: input.operation_id.clone(),
        actor: actor.to_owned(),
        digest,
    });
    save(tx, &state)?;
    Ok((view(node, &state), true))
}

pub(in crate::manage) fn retry(
    directory: &Path,
    gate: &UpdateGuard,
    actor: &str,
    input: &Retry,
) -> io::Result<View> {
    gate.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin webhook retry", e))?;
    let result = retry_in(&tx, actor, input)?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit webhook retry", e))?;
    Ok(result)
}

/// Grant one attempt only for the exact pending generation and attempt count.
/// A stale or repeated grant fails before writing; it never recreates a body.
fn retry_in(tx: &Connection, actor: &str, input: &Retry) -> io::Result<View> {
    require_transaction(tx)?;
    let node = require(tx)?;
    administrator(tx, actor)?;
    let mut s = load(tx)?;
    if input.expected_node_id != node
        || decimal(&input.expected_revision).map_err(|_| Error::Invalid.error())? != s.revision
    {
        return Err(Error::Conflict.error());
    }
    let pending = s.pending.as_mut().ok_or_else(|| Error::Conflict.error())?;
    if pending.envelope.delivery_id != input.delivery_id
        || pending.attempts != input.expected_attempts
        || pending.attempts == u32::MAX
        || !matches!(
            pending.outcome,
            Outcome::Unknown | Outcome::Rejected | Outcome::Deferred | Outcome::DestinationBlocked
        )
    {
        return Err(Error::Conflict.error());
    }
    pending.outcome = Outcome::Ready;
    pending.http_status = None;
    save(tx, &s)?;
    Ok(view(node, &s))
}

/// Owned attempt, emitted only after its Sending marker commits and any Source
/// witness confirms. Persistence failure or ambiguity grants no HTTP request.
pub(in crate::manage) struct Attempt {
    pub(in crate::manage) destination: Destination,
    pub(in crate::manage) body: Vec<u8>,
    pub(in crate::manage) id: String,
    revision: u64,
    attempt: u32,
}

/// Only this persisted attempt/configuration generation can receive the
/// worker's elapsed-delay permission. A configuration change invalidates it.
#[derive(Clone, Eq, PartialEq)]
pub(in crate::manage) struct RetryFence {
    revision: u64,
    id: String,
    attempt: u32,
}
impl RetryFence {
    pub(in crate::manage) fn delay(&self) -> std::time::Duration {
        std::time::Duration::from_secs(30 * (1_u64 << self.attempt.saturating_sub(1).min(4)))
    }
}
pub(in crate::manage) enum Work {
    Send(Attempt),
    Wait(RetryFence),
}

/// SQL decisions remain private until the enclosing transaction confirms.
/// Interrupted changes Sending to Unknown but deliberately grants no HTTP work.
enum Prepared {
    Idle,
    Wait(RetryFence),
    Interrupted,
    Send(Attempt),
}

fn eligible(s: &State, p: &Pending) -> bool {
    s.enabled
        && s.automatic_retry
        && p.attempts < 6
        && (p.outcome == Outcome::Unknown
            || p.outcome == Outcome::Rejected
                && p.http_status
                    .is_some_and(|v| v == 408 || v == 429 || (500..=599).contains(&v)))
}

pub(in crate::manage) fn prepare(
    directory: &Path,
    gate: &UpdateGuard,
    permission: Option<&RetryFence>,
) -> io::Result<Option<Work>> {
    gate.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin webhook attempt", e))?;
    match prepare_in(&tx, permission)? {
        Prepared::Idle => Ok(None),
        Prepared::Wait(fence) => Ok(Some(Work::Wait(fence))),
        Prepared::Interrupted => {
            tx.commit()
                .map_err(|e| sqlite_error("cannot record interrupted webhook", e))?;
            Ok(None)
        }
        Prepared::Send(attempt) => {
            tx.commit()
                .map_err(|e| sqlite_error("cannot commit webhook attempt", e))?;
            Ok(Some(Work::Send(attempt)))
        }
    }
}

/// Stage the immutable body and Sending marker together. Only the owning
/// worker may return Send after confirmation; cancelling a waiter loses that
/// permit, so the next observation conservatively records Unknown, not a resend.
fn prepare_in(tx: &Connection, permission: Option<&RetryFence>) -> io::Result<Prepared> {
    require_transaction(tx)?;
    let node = require(tx)?;
    let mut s = load(tx)?;
    if !s.enabled {
        return Ok(Prepared::Idle);
    }
    if let Some(p) = s.pending.as_mut() {
        if p.outcome == Outcome::Sending {
            p.outcome = Outcome::Unknown;
            save(tx, &s)?;
            return Ok(Prepared::Interrupted);
        }
    } else {
        let (_, trimmed, events) = super::alerts::history::notification_page(tx, s.cursor)?;
        if events.is_empty() && trimmed <= s.cursor {
            return Ok(Prepared::Idle);
        }
        let through = events.last().map(|e| e.sequence).unwrap_or(trimmed);
        s.pending = Some(Pending {
            attempts: 0,
            outcome: Outcome::Ready,
            http_status: None,
            envelope: Envelope {
                version: 1,
                delivery_id: super::random_id()?,
                observer_node_id: node,
                after_sequence: s.cursor.to_string(),
                through_sequence: through.to_string(),
                history_trimmed_through: trimmed.to_string(),
                events: events
                    .into_iter()
                    .map(|e| Event {
                        sequence: e.sequence.to_string(),
                        episode_id: e.episode_id.to_string(),
                        origin_node_id: e.observation.origin_node_id,
                        kind: e.observation.kind,
                        transition: e.kind,
                        code: e.observation.code,
                        resource_id: e.observation.resource_id,
                        target: e.observation.target,
                        observed_at_unix_ms: e.observed_at_unix_ms.map(|v| v.to_string()),
                    })
                    .collect(),
            },
        });
    }
    if let Some(p) = &s.pending
        && p.outcome != Outcome::Ready
    {
        if !eligible(&s, p) {
            return Ok(Prepared::Idle);
        }
        let fence = RetryFence {
            revision: s.revision,
            id: p.envelope.delivery_id.clone(),
            attempt: p.attempts,
        };
        if permission != Some(&fence) {
            return Ok(Prepared::Wait(fence));
        }
    }
    let p = s.pending.as_mut().ok_or_else(corrupt)?;
    p.attempts = p.attempts.checked_add(1).ok_or_else(corrupt)?;
    p.outcome = Outcome::Sending;
    p.http_status = None;
    let id = p.envelope.delivery_id.clone();
    let attempt = p.attempts;
    let body = serde_json::to_vec(&p.envelope).map_err(|_| corrupt())?;
    if body.len() > notifications::MAX_BODY {
        return Err(corrupt());
    }
    save(tx, &s)?;
    Ok(Prepared::Send(Attempt {
        destination: s.destination,
        body,
        id,
        revision: s.revision,
        attempt,
    }))
}

/// A response only advances this exact pending generation. Late acknowledgements
/// cannot mark a replacement destination or another attempt accepted.
pub(in crate::manage) fn finish(
    directory: &Path,
    gate: &UpdateGuard,
    attempt: &Attempt,
    result: (Outcome, Option<u16>),
) -> io::Result<()> {
    validate_result(result)?;
    gate.ensure(directory)?;
    let mut connection = open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin webhook result", e))?;
    if finish_in(&tx, attempt, result)? {
        tx.commit()
            .map_err(|e| sqlite_error("cannot commit webhook result", e))?;
    }
    Ok(())
}

fn validate_result(result: (Outcome, Option<u16>)) -> io::Result<()> {
    let valid = match result {
        (Outcome::Accepted, Some(200..=299)) => true,
        (Outcome::Rejected | Outcome::Deferred, Some(code)) => {
            (100..=599).contains(&code) && !(200..=299).contains(&code)
        }
        (Outcome::Unknown | Outcome::DestinationBlocked, None) => true,
        _ => false,
    };
    if !valid {
        return Err(Error::Invalid.error());
    }
    Ok(())
}

/// Stage a result only for the original Sending marker. A late answer after
/// reconfiguration, another attempt or accepted completion is a read-only no-op.
fn finish_in(
    tx: &Connection,
    attempt: &Attempt,
    result: (Outcome, Option<u16>),
) -> io::Result<bool> {
    require_transaction(tx)?;
    require(tx)?;
    let mut s = load(tx)?;
    if s.revision != attempt.revision
        || s.pending.as_ref().is_none_or(|p| {
            p.envelope.delivery_id != attempt.id
                || p.attempts != attempt.attempt
                || p.outcome != Outcome::Sending
        })
    {
        return Ok(false);
    }
    if result.0 == Outcome::Accepted {
        let pending = s.pending.take().ok_or_else(corrupt)?;
        s.cursor = decimal(&pending.envelope.through_sequence)?;
        s.accepted = Some(pending.envelope.delivery_id);
    } else {
        let pending = s.pending.as_mut().ok_or_else(corrupt)?;
        pending.outcome = result.0;
        pending.http_status = result.1;
    }
    save(tx, &s)?;
    Ok(true)
}

fn require_transaction(connection: &Connection) -> io::Result<()> {
    if connection.is_autocommit() {
        return Err(Error::Invalid.error());
    }
    Ok(())
}

/// Older test fixtures may remove only an untouched default namespace. Issued
/// settings/attempt identities must never be relabelled as historical state.
#[cfg(test)]
pub(in crate::manage) fn remove_schema_for_test(connection: &Connection) -> io::Result<()> {
    ensure_unused_for_test(connection)?;
    super::witness::remove_schema_for_test(connection)?;
    let present: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='webhook_state')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect webhook fixture", e))?;
    if present {
        let s = load(connection)?;
        if *encode(&s)? != *encode(&State::default())? {
            return Err(corrupt());
        }
        connection
            .execute_batch("DROP TABLE webhook_state;")
            .map_err(|e| sqlite_error("cannot reconstruct pre-webhook fixture", e))?;
    }
    Ok(())
}

/// Bounded identity exclusion for restore-as-new. Old delivery IDs remain
/// unavailable even if their source event was pruned from the history table.
pub(super) fn collect_source_ids(
    connection: &Connection,
    ids: &mut std::collections::HashSet<String>,
) -> io::Result<()> {
    let s = load(connection)?;
    if let Some(r) = s.receipt {
        ids.insert(r.id);
        ids.insert(r.actor);
    }
    for id in [s.accepted, s.discarded].into_iter().flatten() {
        ids.insert(id);
    }
    if let Some(p) = s.pending {
        ids.insert(p.envelope.delivery_id);
        ids.insert(p.envelope.observer_node_id);
        for event in p.envelope.events {
            ids.insert(event.origin_node_id);
            if let Some(id) = event.resource_id {
                ids.insert(id);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::manage) fn ensure_unused_for_test(connection: &Connection) -> io::Result<()> {
    super::witness::ensure_unused_for_test(connection)?;
    let present: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='webhook_state')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect webhook fixture", e))?;
    if present && *encode(&load(connection)?)? != *encode(&State::default())? {
        return Err(corrupt());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::{
        alerts::Kind,
        store::{self, alerts::history, update_lock},
    };

    #[cfg(feature = "witness-journal")]
    mod source {
        //! Real loopback witness confirmation with synthetic incidents. No webhook
        //! destination is resolved or contacted, and no system trust is modified.

        use super::*;
        use crate::manage::{node, store::journal::SourceFixture};
        use rusqlite::{
            fallible_streaming_iterator::FallibleStreamingIterator, session::ChangesetIter,
        };
        use std::{fs, sync::Arc, time::Duration};
        use tokio::time::timeout;

        fn unavailable() -> io::Error {
            io::Error::other("source webhook fixture failed")
        }

        async fn live(fault: node::tests::CutResponse) -> io::Result<SourceFixture> {
            SourceFixture::new_with(fault, |_| Ok(())).await
        }

        async fn configure(live: &SourceFixture, automatic: bool) -> io::Result<Arc<Change>> {
            let input = Arc::new(Change {
                expected_node_id: live.fixture.client_id.clone(),
                expected_revision: "0".into(),
                operation_id: store::random_id()?,
                enabled: true,
                automatic_retry: automatic,
                url: Some("https://hooks.example/private-test-path".into()),
                bearer: Some("source-fixture-token".into()),
                clear_bearer: false,
                clear_destination: false,
                discard_pending: false,
            });
            let (saved, actor) = (input.clone(), live.administrator.clone());
            live.source
                .notifications_write(move |w| w.change(&actor, &saved))
                .await?;
            Ok(input)
        }

        async fn event(live: &SourceFixture) -> io::Result<()> {
            let batch = history::Batch {
                boot_id: store::random_id()?,
                sequence: 1,
                transitions: vec![history::Transition {
                    kind: history::TransitionKind::Opened,
                    observation: history::Observation {
                        incident_id: 1,
                        kind: Kind::HealthCatalog,
                        origin_node_id: live.fixture.client_id.clone(),
                        resource_id: None,
                        slot: "catalog".into(),
                        check: None,
                        target: None,
                        code: "health_catalog_unavailable".into(),
                        first_observed_at_unix_ms: Some(1),
                        last_observed_at_unix_ms: Some(1),
                        evidence_sequence: None,
                    },
                    observed_at_unix_ms: Some(1),
                    ended_reason: None,
                }],
            };
            live.source
                .history_write(move |w| {
                    w.start(&batch.boot_id)?;
                    w.record(&batch, None)
                })
                .await?;
            Ok(())
        }

        async fn prepare(live: &SourceFixture) -> io::Result<Option<Work>> {
            live.source.notifications_write(|w| w.prepare(None)).await
        }

        async fn send(live: &SourceFixture) -> io::Result<Arc<Attempt>> {
            match prepare(live).await? {
                Some(Work::Send(attempt)) => Ok(Arc::new(attempt)),
                _ => Err(unavailable()),
            }
        }

        fn current(live: &SourceFixture) -> io::Result<View> {
            status(&live.fixture.client_state, &live.administrator)
        }

        async fn finish(
            live: &SourceFixture,
            attempt: &Arc<Attempt>,
            outcome: (Outcome, Option<u16>),
        ) -> io::Result<()> {
            let attempt = attempt.clone();
            live.source
                .notifications_write(move |w| w.finish(&attempt, outcome))
                .await
        }

        async fn retry(live: &SourceFixture, attempt: &Attempt) -> io::Result<View> {
            let input = Retry {
                expected_node_id: live.fixture.client_id.clone(),
                expected_revision: attempt.revision.to_string(),
                delivery_id: attempt.id.clone(),
                expected_attempts: attempt.attempt,
            };
            let actor = live.administrator.clone();
            live.source
                .notifications_write(move |w| w.retry(&actor, &input))
                .await
        }

        async fn idle(live: &SourceFixture) -> io::Result<()> {
            timeout(Duration::from_secs(15), async {
                while live.source.write_work().available_permits() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(io::Error::other)
        }

        fn pending(live: &SourceFixture) -> io::Result<Pending> {
            let c = Connection::open(live.fixture.client_state.join("management.sqlite3"))
                .map_err(io::Error::other)?;
            load(&c)?.pending.ok_or_else(unavailable)
        }

        fn delta(live: &SourceFixture) -> io::Result<()> {
            let root = live.fixture.client_state.join("witness-intents");
            let location: serde_json::Value =
                serde_json::from_slice(&fs::read(root.join("3.json"))?)
                    .map_err(io::Error::other)?;
            let path = root
                .join(location["intent_id"].as_str().ok_or_else(unavailable)?)
                .join("changeset.bin");
            // One bounded singleton's old/new value plus the bounded Source floor.
            // This checks this real fixture, not a universal C-heap or latency limit.
            assert!(fs::metadata(&path)?.len() < 128 * 1024);
            let bytes = fs::read(path)?;
            let mut input = bytes.as_slice();
            let reader: &mut dyn io::Read = &mut input;
            let mut iter = ChangesetIter::start_strm(&reader).map_err(io::Error::other)?;
            let mut tables = Vec::new();
            while let Some(item) = iter.next().map_err(io::Error::other)? {
                tables.push(item.op().map_err(io::Error::other)?.table_name().to_owned());
            }
            tables.sort();
            assert_eq!(tables, ["recovery_source", "webhook_state"]);
            Ok(())
        }

        #[tokio::test]
        async fn source_webhook_authority_exact_receipts_and_retry_generation_preserve_original_body()
        -> io::Result<()> {
            let live = live(Default::default()).await?;
            let result = async {
                assert!(prepare(&live).await?.is_none());
                let input = configure(&live, true).await?;
                let (again, actor) = (input.clone(), live.administrator.clone());
                let repeated = live
                    .source
                    .notifications_write(move |w| w.change(&actor, &again))
                    .await?;
                assert_eq!(repeated.revision, "1");
                let public = serde_json::to_string(&repeated).map_err(io::Error::other)?;
                assert!(
                    !public.contains("hooks.example") && !public.contains("source-fixture-token")
                );
                let wrong = live.fixture.server_id.clone();
                assert_eq!(
                    live.source
                        .notifications_write(move |w| w.change(&wrong, &input))
                        .await
                        .err()
                        .map(|e| e.kind()),
                    Some(io::ErrorKind::PermissionDenied)
                );
                assert_eq!(live.floor()?.sequence, "1");
                event(&live).await?;
                let first = send(&live).await?;
                assert_eq!(live.floor()?.sequence, "3");
                delta(&live)?;
                finish(&live, &first, (Outcome::Rejected, Some(503))).await?;
                let Some(Work::Wait(fence)) = prepare(&live).await? else {
                    return Err(unavailable());
                };
                assert_eq!(fence.delay(), Duration::from_secs(30));
                let saved = fence.clone();
                let wrong = RetryFence {
                    revision: fence.revision + 1,
                    ..fence
                };
                assert!(matches!(
                    live.source
                        .notifications_write(move |w| w.prepare(Some(&wrong)))
                        .await?,
                    Some(Work::Wait(_))
                ));
                assert_eq!(live.floor()?.sequence, "4");
                let Some(Work::Send(second)) = live
                    .source
                    .notifications_write(move |w| w.prepare(Some(&saved)))
                    .await?
                else {
                    return Err(unavailable());
                };
                let second = Arc::new(second);
                assert_eq!(
                    (&second.id, &second.body, second.attempt),
                    (&first.id, &first.body, 2)
                );
                finish(&live, &first, (Outcome::Accepted, Some(204))).await?;
                assert_eq!(live.floor()?.sequence, "5");
                finish(&live, &second, (Outcome::Deferred, Some(429))).await?;
                assert!(prepare(&live).await?.is_none());
                assert_eq!(live.floor()?.sequence, "6");
                retry(&live, &second).await?;
                assert!(retry(&live, &second).await.is_err());
                let third = send(&live).await?;
                assert_eq!(
                    (&third.id, &third.body, third.attempt),
                    (&first.id, &first.body, 3)
                );
                let actor = live.administrator.clone();
                let disable = Change {
                    expected_node_id: live.fixture.client_id.clone(),
                    expected_revision: "1".into(),
                    operation_id: store::random_id()?,
                    enabled: false,
                    automatic_retry: false,
                    url: None,
                    bearer: None,
                    clear_bearer: false,
                    clear_destination: true,
                    discard_pending: true,
                };
                live.source
                    .notifications_write(move |w| w.change(&actor, &disable))
                    .await?;
                finish(&live, &third, (Outcome::Accepted, Some(204))).await?;
                let state = current(&live)?;
                assert!(!state.enabled && !state.configured && !state.has_bearer);
                assert_eq!(state.discarded_delivery_id.as_ref(), Some(&first.id));
                assert!(prepare(&live).await?.is_none());
                assert_eq!(live.floor()?.sequence, "9");
                Ok(())
            }
            .await;
            let closed = live.close().await;
            result.and(closed)
        }

        #[tokio::test]
        async fn cancelled_source_webhook_prepare_loses_http_permit_without_losing_durable_marker()
        -> io::Result<()> {
            let pause = Arc::new(node::tests::ResponsePause::default());
            let live = live(node::tests::CutResponse {
                witness_only: true,
                witness_confirm: true,
                witness_sequence: Some(3),
                pause: Some(pause.clone()),
                ..Default::default()
            })
            .await?;
            let result = async {
                configure(&live, false).await?;
                event(&live).await?;
                live.arm();
                let mut request = Box::pin(prepare(&live));
                assert!(futures_util::poll!(&mut request).is_pending());
                timeout(Duration::from_secs(15), pause.entered.notified())
                    .await
                    .map_err(io::Error::other)?;
                assert_eq!(live.source.write_work().available_permits(), 0);
                assert!(live.source.ensure_source_confirmed().is_err());
                assert_eq!(pending(&live)?.outcome, Outcome::Sending);
                drop(request);
                pause.release.notify_one();
                idle(&live).await?;
                let original = pending(&live)?;
                assert!(prepare(&live).await?.is_none());
                let current = pending(&live)?;
                assert_eq!(current.outcome, Outcome::Unknown);
                assert_eq!(current.attempts, 1);
                assert_eq!(current.envelope.delivery_id, original.envelope.delivery_id);
                assert!(prepare(&live).await?.is_none());
                assert_eq!(live.floor()?.sequence, "4");
                Ok(())
            }
            .await;
            pause.release.notify_one();
            let closed = live.close().await;
            result.and(closed)
        }

        #[tokio::test]
        async fn source_webhook_unknown_prepare_never_returns_send_and_reconciles_only_original_attempt()
        -> io::Result<()> {
            for reserve in [true, false] {
                let live = live(node::tests::CutResponse {
                    witness_only: true,
                    witness_reserve: reserve,
                    witness_confirm: !reserve,
                    witness_sequence: Some(3),
                    ..Default::default()
                })
                .await?;
                let result = async {
                    configure(&live, false).await?;
                    event(&live).await?;
                    live.arm();
                    assert!(prepare(&live).await.is_err());
                    assert!(live.source.ensure_source_confirmed().is_err());
                    assert!(prepare(&live).await.is_err());
                    live.source.reconcile_source().await?;
                    let original = pending(&live)?;
                    let body = serde_json::to_vec(&original.envelope).map_err(io::Error::other)?;
                    assert_eq!(original.outcome, Outcome::Sending);
                    assert!(prepare(&live).await?.is_none());
                    assert_eq!(pending(&live)?.outcome, Outcome::Unknown);
                    let input = Retry {
                        expected_node_id: live.fixture.client_id.clone(),
                        expected_revision: "1".into(),
                        delivery_id: original.envelope.delivery_id.clone(),
                        expected_attempts: 1,
                    };
                    let actor = live.administrator.clone();
                    live.source
                        .notifications_write(move |w| w.retry(&actor, &input))
                        .await?;
                    let attempt = send(&live).await?;
                    assert_eq!(attempt.id, original.envelope.delivery_id);
                    assert_eq!(attempt.body, body);
                    assert_eq!(attempt.attempt, 2);
                    finish(&live, &attempt, (Outcome::Accepted, Some(204))).await?;
                    assert!(prepare(&live).await?.is_none());
                    assert_eq!(live.floor()?.sequence, "7");
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)?;
            }
            Ok(())
        }

        #[tokio::test]
        async fn source_webhook_lost_accepted_result_and_restart_never_resend_or_advance_another_cursor()
        -> io::Result<()> {
            for reserve in [true, false] {
                let mut live = live(node::tests::CutResponse {
                    witness_only: true,
                    witness_reserve: reserve,
                    witness_confirm: !reserve,
                    witness_sequence: Some(4),
                    ..Default::default()
                })
                .await?;
                let result = async {
                    configure(&live, false).await?;
                    event(&live).await?;
                    let attempt = send(&live).await?;
                    live.arm();
                    assert!(
                        finish(&live, &attempt, (Outcome::Accepted, Some(204)))
                            .await
                            .is_err()
                    );
                    assert!(prepare(&live).await.is_err());
                    live.source.reconcile_source().await?;
                    let after = current(&live)?;
                    assert_eq!(after.cursor, "1");
                    assert_eq!(after.last_accepted_delivery_id.as_ref(), Some(&attempt.id));
                    assert!(after.pending.is_none());
                    finish(&live, &attempt, (Outcome::Accepted, Some(204))).await?;
                    assert!(prepare(&live).await?.is_none());
                    live.restart_source().await?;
                    assert!(prepare(&live).await?.is_none());
                    assert_eq!(current(&live)?.cursor, "1");
                    assert_eq!(live.floor()?.sequence, "4");
                    Ok(())
                }
                .await;
                let closed = live.close().await;
                result.and(closed)?;
            }
            Ok(())
        }
    }

    struct Fixture {
        directory: std::path::PathBuf,
        node: String,
        actor: String,
        boot: String,
    }
    impl Fixture {
        fn new() -> io::Result<Self> {
            let directory =
                std::env::temp_dir().join(format!("vproxy-webhook-{}", store::random_id()?));
            let node = store::initialize(&directory, "webhook test", "admin", "fixture PHC bytes")?
                .node_id;
            let connection = open_existing(&directory, false)?;
            let actor = connection
                .query_row("SELECT id FROM administrators", [], |r| r.get(0))
                .map_err(io::Error::other)?;
            Ok(Self {
                directory,
                node,
                actor,
                boot: store::random_id()?,
            })
        }
        fn change(&self, input: &Change) -> io::Result<View> {
            change(
                &self.directory,
                &update_lock(&self.directory)?,
                &self.actor,
                input,
            )
        }
        fn input(&self, revision: &str) -> io::Result<Change> {
            Ok(Change {
                expected_node_id: self.node.clone(),
                expected_revision: revision.into(),
                operation_id: store::random_id()?,
                enabled: true,
                automatic_retry: false,
                url: Some("https://hooks.example/secret-path?key=private-query".into()),
                bearer: Some("fake-test-token".into()),
                clear_bearer: false,
                clear_destination: false,
                discard_pending: false,
            })
        }
        fn event(&self, sequence: u64) -> io::Result<()> {
            let gate = update_lock(&self.directory)?;
            history::start(&self.directory, &gate, &self.boot)?;
            history::record(
                &self.directory,
                &gate,
                &history::Batch {
                    boot_id: self.boot.clone(),
                    sequence,
                    transitions: vec![history::Transition {
                        kind: history::TransitionKind::Opened,
                        observation: history::Observation {
                            incident_id: sequence,
                            kind: Kind::HealthCatalog,
                            origin_node_id: self.node.clone(),
                            resource_id: None,
                            slot: "catalog".into(),
                            check: None,
                            target: None,
                            code: "health_catalog_unavailable".into(),
                            first_observed_at_unix_ms: Some(1),
                            last_observed_at_unix_ms: Some(1),
                            evidence_sequence: None,
                        },
                        observed_at_unix_ms: Some(1),
                        ended_reason: None,
                    }],
                },
            )?;
            Ok(())
        }
        fn prepare(&self) -> io::Result<Option<Attempt>> {
            match prepare(&self.directory, &update_lock(&self.directory)?, None)? {
                Some(Work::Send(attempt)) => Ok(Some(attempt)),
                None => Ok(None),
                Some(Work::Wait(_)) => Err(corrupt()),
            }
        }
        fn finish(&self, a: &Attempt, result: (Outcome, Option<u16>)) -> io::Result<()> {
            finish(&self.directory, &update_lock(&self.directory)?, a, result)
        }
        fn status(&self) -> io::Result<View> {
            status(&self.directory, &self.actor)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn disabled_default_cas_exact_receipt_and_secret_redaction() -> io::Result<()> {
        let f = Fixture::new()?;
        assert!(!f.status()?.enabled);
        assert!(f.prepare()?.is_none());
        let mut input = f.input("0")?;
        let first = f.change(&input)?;
        assert_eq!(first.revision, "1");
        assert_eq!(f.change(&input)?.operation_id, first.operation_id);
        let serialized = serde_json::to_string(&first).map_err(io::Error::other)?;
        for secret in [
            "hooks.example",
            "secret-path",
            "private-query",
            "fake-test-token",
            "digest",
        ] {
            assert!(!serialized.contains(secret));
        }
        input.enabled = false;
        assert!(f.change(&input).is_err());
        assert_eq!(f.status()?.revision, "1");
        input.operation_id = store::random_id()?;
        assert!(f.change(&input).is_err());
        input.expected_revision = "1".into();
        input.expected_node_id = store::random_id()?;
        assert!(f.change(&input).is_err());
        input.expected_node_id = f.node.clone();
        assert_eq!(f.change(&input)?.revision, "2");
        assert!(!f.status()?.enabled);
        assert!(status(&f.directory, &store::random_id()?).is_err());
        Ok(())
    }

    #[test]
    fn interrupted_attempt_requires_explicit_exact_retry_and_keeps_body() -> io::Result<()> {
        let f = Fixture::new()?;
        f.change(&f.input("0")?)?;
        f.event(1)?;
        let first = f.prepare()?.ok_or_else(corrupt)?;
        assert_eq!(
            f.status()?.pending.ok_or_else(corrupt)?.outcome,
            Outcome::Sending
        );
        // A lost response/crash marker is not permission for automatic replay.
        assert!(f.prepare()?.is_none());
        assert_eq!(
            f.status()?.pending.ok_or_else(corrupt)?.outcome,
            Outcome::Unknown
        );
        assert!(f.prepare()?.is_none());
        let mut input = Retry {
            expected_node_id: f.node.clone(),
            expected_revision: "1".into(),
            delivery_id: first.id.clone(),
            expected_attempts: 2,
        };
        assert!(retry(&f.directory, &update_lock(&f.directory)?, &f.actor, &input).is_err());
        input.expected_attempts = 1;
        retry(&f.directory, &update_lock(&f.directory)?, &f.actor, &input)?;
        assert!(retry(&f.directory, &update_lock(&f.directory)?, &f.actor, &input).is_err());
        let second = f.prepare()?.ok_or_else(corrupt)?;
        assert_eq!(first.body, second.body);
        assert_eq!(first.id, second.id);
        assert_eq!(second.attempt, 2);
        // An old result cannot acknowledge the replacement attempt.
        f.finish(&first, (Outcome::Accepted, Some(204)))?;
        assert_eq!(f.status()?.cursor, "0");
        f.finish(&second, (Outcome::Accepted, Some(204)))?;
        let view = f.status()?;
        assert_eq!(view.cursor, "1");
        assert_eq!(view.last_accepted_delivery_id.as_ref(), Some(&second.id));
        assert!(view.pending.is_none());
        assert!(f.prepare()?.is_none());
        Ok(())
    }

    #[test]
    fn manual_retry_allows_the_last_attempt_but_never_commits_an_exhausted_permit() -> io::Result<()>
    {
        let f = Fixture::new()?;
        f.change(&f.input("0")?)?;
        f.event(1)?;
        let first = f.prepare()?.ok_or_else(corrupt)?;
        f.finish(&first, (Outcome::Unknown, None))?;
        // Reconstruct the counter boundary without billions of network attempts.
        let mut connection = open_existing(&f.directory, true)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io::Error::other)?;
        let mut state = load(&tx)?;
        state.pending.as_mut().ok_or_else(corrupt)?.attempts = u32::MAX - 1;
        save(&tx, &state)?;
        tx.commit().map_err(io::Error::other)?;
        let mut input = Retry {
            expected_node_id: f.node.clone(),
            expected_revision: "1".into(),
            delivery_id: first.id.clone(),
            expected_attempts: u32::MAX - 1,
        };
        retry(&f.directory, &update_lock(&f.directory)?, &f.actor, &input)?;
        let last = f.prepare()?.ok_or_else(corrupt)?;
        assert_eq!(last.attempt, u32::MAX);
        assert_eq!(last.body, first.body);
        f.finish(&last, (Outcome::Unknown, None))?;
        input.expected_attempts = u32::MAX;
        let error = retry(&f.directory, &update_lock(&f.directory)?, &f.actor, &input)
            .err()
            .ok_or_else(corrupt)?;
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        let pending = f.status()?.pending.ok_or_else(corrupt)?;
        assert_eq!(pending.attempts, u32::MAX);
        assert_eq!(pending.outcome, Outcome::Unknown);
        assert!(f.prepare()?.is_none());
        Ok(())
    }

    #[test]
    fn rejection_and_reconfiguration_do_not_replay_or_accept_late_response() -> io::Result<()> {
        let f = Fixture::new()?;
        f.change(&f.input("0")?)?;
        f.event(1)?;
        let attempt = f.prepare()?.ok_or_else(corrupt)?;
        f.finish(&attempt, (Outcome::Rejected, Some(503)))?;
        assert!(f.prepare()?.is_none());
        let view = f.status()?.pending.ok_or_else(corrupt)?;
        assert_eq!(
            (view.outcome, view.http_status),
            (Outcome::Rejected, Some(503))
        );
        let mut change = f.input("1")?;
        change.enabled = false;
        assert!(f.change(&change).is_err());
        change.discard_pending = true;
        let state = f.change(&change)?;
        assert_eq!(state.discarded_delivery_id.as_ref(), Some(&attempt.id));
        f.finish(&attempt, (Outcome::Accepted, Some(204)))?;
        assert!(f.status()?.last_accepted_delivery_id.is_none());
        assert!(!f.status()?.enabled);
        assert!(f.prepare()?.is_none());
        Ok(())
    }

    #[test]
    fn enable_starts_now_and_retention_gap_is_an_explicit_stable_delivery() -> io::Result<()> {
        let f = Fixture::new()?;
        f.event(1)?;
        assert_eq!(f.change(&f.input("0")?)?.skipped_through, "1");
        assert!(f.prepare()?.is_none());
        // A valid all-trimmed prefix, equivalent to bounded event retention.
        let c = open_existing(&f.directory, true)?;
        c.execute_batch(
            "DELETE FROM alert_events; UPDATE alert_history_state SET last_sequence=5,trimmed=5;",
        )
        .map_err(io::Error::other)?;
        let attempt = f.prepare()?.ok_or_else(corrupt)?;
        let value: serde_json::Value =
            serde_json::from_slice(&attempt.body).map_err(io::Error::other)?;
        assert_eq!(value["after_sequence"], "1");
        assert_eq!(value["through_sequence"], "5");
        assert_eq!(value["history_trimmed_through"], "5");
        assert_eq!(value["events"].as_array().map(Vec::len), Some(0));
        f.finish(&attempt, (Outcome::Unknown, None))?;
        assert!(f.prepare()?.is_none());
        Ok(())
    }

    #[test]
    fn malformed_state_and_invalid_destination_fail_closed() -> io::Result<()> {
        let f = Fixture::new()?;
        let mut input = f.input("0")?;
        for url in [
            "http://hooks.example/",
            "https://127.0.0.1/",
            "https://user:secret@hooks.example/",
            "https://hooks.example/#token",
        ] {
            input.url = Some(url.into());
            assert!(f.change(&input).is_err());
            assert_eq!(f.status()?.revision, "0");
        }
        let c = open_existing(&f.directory, true)?;
        c.execute("UPDATE webhook_state SET payload=?1", [b"{}".as_slice()])
            .map_err(io::Error::other)?;
        assert!(store::inspect(&f.directory).is_err());
        assert!(f.prepare().is_err());
        Ok(())
    }

    #[test]
    fn schema22_migration_preserves_history_and_backup_stays_original() -> io::Result<()> {
        let f = Fixture::new()?;
        let c = open_existing(&f.directory, true)?;
        super::super::recovery::restore_schema_twenty_two_for_test(&c)?;
        f.event(1)?;
        let backup = f.directory.join("before23.sqlite3");
        assert_eq!(
            store::migrate(&f.directory, &backup)?.schema_version,
            store::SCHEMA_VERSION
        );
        assert_eq!(
            Connection::open(backup)
                .map_err(io::Error::other)?
                .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .map_err(io::Error::other)?,
            22
        );
        assert!(!f.status()?.enabled);
        assert_eq!(history::summary(&f.directory, &f.actor)?.event_count, 1);
        Ok(())
    }

    #[test]
    fn deduplicated_retry_is_generation_bound_bounded_and_keeps_the_request() -> io::Result<()> {
        let f = Fixture::new()?;
        let mut input = f.input("0")?;
        input.automatic_retry = true;
        f.change(&input)?;
        f.event(1)?;
        let mut attempt = f.prepare()?.ok_or_else(corrupt)?;
        let body = attempt.body.clone();
        let id = attempt.id.clone();
        for count in 1..=6 {
            assert_eq!(attempt.attempt, count);
            f.finish(&attempt, (Outcome::Unknown, None))?;
            let next = prepare(&f.directory, &update_lock(&f.directory)?, None)?;
            if count == 6 {
                assert!(next.is_none());
                break;
            }
            let Some(Work::Wait(fence)) = next else {
                return Err(corrupt());
            };
            assert_eq!(fence.delay().as_secs(), 30 * (1 << (count - 1).min(4)));
            let wrong = RetryFence {
                revision: fence.revision + 1,
                ..fence.clone()
            };
            assert!(matches!(
                prepare(&f.directory, &update_lock(&f.directory)?, Some(&wrong))?,
                Some(Work::Wait(_))
            ));
            let Some(Work::Send(next)) =
                prepare(&f.directory, &update_lock(&f.directory)?, Some(&fence))?
            else {
                return Err(corrupt());
            };
            assert_eq!(next.id, id);
            assert_eq!(next.body, body);
            attempt = next;
        }
        assert_eq!(f.status()?.pending.ok_or_else(corrupt)?.attempts, 6);
        assert!(
            !f.status()?
                .pending
                .ok_or_else(corrupt)?
                .automatic_retry_eligible
        );
        Ok(())
    }

    #[test]
    fn forgetting_a_destination_clears_current_authority_not_its_receipt() -> io::Result<()> {
        let f = Fixture::new()?;
        f.change(&f.input("0")?)?;
        let mut input = f.input("1")?;
        input.clear_destination = true;
        assert!(f.change(&input).is_err());
        input.enabled = false;
        input.url = None;
        input.bearer = None;
        let view = f.change(&input)?;
        assert!(!view.configured && !view.has_bearer && !view.enabled);
        assert_eq!(view.operation_id.as_ref(), Some(&input.operation_id));
        assert!(f.prepare()?.is_none());
        Ok(())
    }

    #[test]
    fn forward_batches_advance_only_after_acceptance_and_keep_the_sixteen_event_bound()
    -> io::Result<()> {
        let f = Fixture::new()?;
        f.change(&f.input("0")?)?;
        for n in 1..=18 {
            f.event(n)?;
        }
        let first = f.prepare()?.ok_or_else(corrupt)?;
        let envelope: Envelope = serde_json::from_slice(&first.body).map_err(io::Error::other)?;
        assert_eq!(envelope.events.len(), 16);
        assert_eq!(envelope.through_sequence, "16");
        assert_eq!(f.status()?.cursor, "0");
        f.finish(&first, (Outcome::Accepted, Some(202)))?;
        let second = f.prepare()?.ok_or_else(corrupt)?;
        let envelope: Envelope = serde_json::from_slice(&second.body).map_err(io::Error::other)?;
        assert_eq!(envelope.after_sequence, "16");
        assert_eq!(envelope.through_sequence, "18");
        assert_eq!(envelope.events.len(), 2);
        assert_ne!(first.id, second.id);
        Ok(())
    }

    #[test]
    fn only_retryable_responses_without_receiver_wait_instructions_are_automatic() -> io::Result<()>
    {
        for (outcome, code, eligible) in [
            (Outcome::Rejected, 403, false),
            (Outcome::Rejected, 429, true),
            (Outcome::Deferred, 503, false),
        ] {
            let f = Fixture::new()?;
            let mut input = f.input("0")?;
            input.automatic_retry = true;
            f.change(&input)?;
            f.event(1)?;
            let attempt = f.prepare()?.ok_or_else(corrupt)?;
            f.finish(&attempt, (outcome, Some(code)))?;
            assert_eq!(
                f.status()?
                    .pending
                    .ok_or_else(corrupt)?
                    .automatic_retry_eligible,
                eligible
            );
            assert_eq!(
                matches!(
                    prepare(&f.directory, &update_lock(&f.directory)?, None)?,
                    Some(Work::Wait(_))
                ),
                eligible
            );
        }
        Ok(())
    }

    #[test]
    fn a_suppressed_or_replaced_state_write_never_emits_a_send_permit() -> io::Result<()> {
        for action in ["SELECT RAISE(IGNORE);", "DELETE FROM webhook_state;"] {
            let f = Fixture::new()?;
            f.change(&f.input("0")?)?;
            f.event(1)?;
            let c = open_existing(&f.directory, true)?;
            let when = if action.starts_with("SELECT") {
                "BEFORE"
            } else {
                "AFTER"
            };
            c.execute_batch(&format!(
                "CREATE TRIGGER faulty_state {when} UPDATE ON webhook_state BEGIN {action} END;"
            ))
            .map_err(io::Error::other)?;
            assert!(f.prepare().is_err());
            assert!(f.status()?.pending.is_none());
            assert_eq!(f.status()?.cursor, "0");
        }
        Ok(())
    }

    #[test]
    fn disabling_does_not_require_decoding_a_corrupted_old_event_payload() -> io::Result<()> {
        let f = Fixture::new()?;
        f.change(&f.input("0")?)?;
        f.event(1)?;
        let attempt = f.prepare()?.ok_or_else(corrupt)?;
        let c = open_existing(&f.directory, true)?;
        c.execute("UPDATE alert_events SET payload=x'7b7d'", [])
            .map_err(io::Error::other)?;
        let mut input = f.input("1")?;
        input.enabled = false;
        input.discard_pending = true;
        let view = f.change(&input)?;
        assert!(!view.enabled);
        assert_eq!(view.discarded_delivery_id.as_ref(), Some(&attempt.id));
        assert_eq!(view.cursor, "1");
        assert!(f.prepare()?.is_none());
        Ok(())
    }
}
