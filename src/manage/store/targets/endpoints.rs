//! Metadata delivery uses the same single peer row and command sequence. Its
//! independent revision can never become a proxy-policy rollback floor.

use super::*;
use crate::manage::store::{ControlIntent, endpoint_control};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    resource: String,
    command: endpoint_control::Command,
}

fn bounded_blob(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Vec<u8>> {
    match row.get_ref(index)? {
        ValueRef::Blob(bytes) if !bytes.is_empty() && bytes.len() <= MAX_COMMAND_BYTES => {
            Ok(bytes.to_vec())
        }
        value => Err(rusqlite::Error::InvalidColumnType(
            index,
            "command".into(),
            value.data_type(),
        )),
    }
}

fn encode(command: &endpoint_control::Command) -> io::Result<Vec<u8>> {
    endpoint_control::validate(command)?;
    let bytes = serde_json::to_vec(&Stored {
        version: 4,
        resource: "proxy_endpoints".into(),
        command: command.clone(),
    })
    .map_err(|_| input())?;
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(input());
    }
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> io::Result<endpoint_control::Command> {
    if bytes.is_empty() || bytes.len() > MAX_COMMAND_BYTES {
        return Err(corrupt());
    }
    let stored: Stored = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
    if stored.version != 4 || stored.resource != "proxy_endpoints" {
        return Err(corrupt());
    }
    endpoint_control::validate(&stored.command).map_err(|_| corrupt())?;
    Ok(stored.command)
}

pub(in crate::manage) fn enqueue_intent(
    directory: &Path,
    administrator: &str,
    target_revision: u64,
    intent: ControlIntent,
) -> io::Result<Job> {
    match intent {
        ControlIntent::Policy(command) => {
            super::enqueue(directory, administrator, target_revision, command)
        }
        ControlIntent::Endpoint(command) => {
            enqueue(directory, administrator, target_revision, command)
        }
    }
}

/// Dispatch only the two existing typed command families inside the source's
/// held transaction. Encoding/input checks still precede the business SQL.
#[cfg(feature = "witness-journal")]
pub(super) fn enqueue_intent_in(
    tx: &Connection,
    administrator: &str,
    target_revision: u64,
    intent: ControlIntent,
) -> io::Result<Job> {
    match intent {
        ControlIntent::Policy(command) => {
            let payload = super::encode(&command)?;
            super::enqueue_in(tx, administrator, target_revision, command, payload)
        }
        ControlIntent::Endpoint(command) => {
            let payload = encode(&command)?;
            enqueue_in(tx, administrator, target_revision, command, payload)
        }
    }
}

fn enqueue(
    directory: &Path,
    administrator: &str,
    target_revision: u64,
    command: endpoint_control::Command,
) -> io::Result<Job> {
    let payload = encode(&command)?;
    let _gate = super::super::update_lock(directory)?;
    let mut connection = super::super::peers::open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin endpoint controller intent", e))?;
    let job = enqueue_in(&tx, administrator, target_revision, command, payload)?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit endpoint controller intent", e))?;
    Ok(job)
}

/// Shared endpoint outbox core. The caller retains its validated input and
/// immediate transaction; this function never commits or delivers a secret.
pub(super) fn enqueue_in(
    tx: &Connection,
    administrator: &str,
    target_revision: u64,
    command: endpoint_control::Command,
    payload: Vec<u8>,
) -> io::Result<Job> {
    require_transaction(tx)?;
    if read_overview(tx)?.schema_version < 15 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            super::super::endpoints::Error::UpgradeRequired,
        ));
    }
    authorize_administrator(tx, administrator)?;
    if command.source_administrator_id != administrator {
        return Err(denied());
    }
    let target = find_target(tx, &command.target_node_id)?.ok_or_else(missing)?;
    require_peer(tx, &target.peer_id)?;
    if !target.active || target.retired || target.rollback_detected {
        return Err(denied());
    }
    if target.revision != target_revision
        || target.observed_epoch != Some(command.epoch)
        || target.observed_command.and_then(|n| n.checked_add(1)) != Some(command.command_id)
        || super::current_job(tx, &target.peer_id)?.is_some_and(|job| job.state.unsettled())
    {
        return Err(conflict());
    }
    let job_id = random_id()?;
    let affected=tx.execute("INSERT INTO control_outbox(peer_id,job_id,administrator_id,controller_epoch,command_id,expected_policy_revision,command,state,attempts,next_attempt,resource,expected_metadata_revision) VALUES(?1,?2,?3,?4,?5,NULL,?6,'pending',0,0,'proxy_endpoints',?7) ON CONFLICT(peer_id) DO UPDATE SET job_id=excluded.job_id,administrator_id=excluded.administrator_id,controller_epoch=excluded.controller_epoch,command_id=excluded.command_id,expected_policy_revision=NULL,command=excluded.command,state='pending',policy_revision=NULL,outcome_code=NULL,attempts=0,next_attempt=0,routing_kind=NULL,routing_id=NULL,preset_kind=NULL,preset_id=NULL,resource='proxy_endpoints',expected_metadata_revision=excluded.expected_metadata_revision,metadata_revision=NULL",params![target.peer_id,job_id,administrator,sql(command.epoch)?,sql(command.command_id)?,payload,sql(command.expected_metadata_revision)?]).map_err(|e|sqlite_error("cannot save endpoint controller intent",e))?;
    if affected != 1 {
        return Err(corrupt());
    }
    audit(tx, administrator, "enqueue", &target, &job_id, &command)?;
    let job = super::current_job(tx, &target.peer_id)?.ok_or_else(corrupt)?;
    super::history::insert_current(tx, &job)?;
    Ok(job)
}

pub(super) fn read_intent(connection: &Connection, job: &Job) -> io::Result<ControlIntent> {
    if job.endpoint.is_none() {
        return super::read_command(connection, job).map(ControlIntent::Policy);
    }
    read_metadata(connection, job).map(ControlIntent::Endpoint)
}
fn read_metadata(connection: &Connection, job: &Job) -> io::Result<endpoint_control::Command> {
    let (bytes, administrator): (Vec<u8>, String) = connection
        .query_row(
            "SELECT command,administrator_id FROM control_outbox WHERE peer_id=?1 AND job_id=?2",
            params![job.peer_id, job.job_id],
            |row| Ok((bounded_blob(row, 0)?, row.get(1)?)),
        )
        .map_err(|e| sqlite_error("cannot read endpoint controller payload", e))?;
    let command = decode(&bytes)?;
    if command.target_node_id != job.peer_id
        || command.epoch != job.epoch
        || command.command_id != job.command_id
        || Some(command.expected_metadata_revision) != job.expected_metadata_revision
        || command.source_administrator_id != administrator
        || !valid_id(&administrator)
        || job.endpoint.as_ref().is_none_or(|reference| {
            reference.listener_id != command.change.listener_id
                || reference.generation != command.generation
        })
    {
        return Err(corrupt());
    }
    Ok(command)
}

pub(super) fn current_job(connection: &Connection, peer: &str) -> io::Result<Option<Job>> {
    let row=connection.query_row("SELECT peer_id,job_id,controller_epoch,command_id,expected_metadata_revision,metadata_revision,state,outcome_code,attempts,next_attempt,command,administrator_id FROM control_outbox WHERE peer_id=?1 AND resource='proxy_endpoints'",[peer],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?,row.get::<_,Option<i64>>(5)?,row.get::<_,String>(6)?,row.get::<_,Option<String>>(7)?,row.get::<_,u32>(8)?,row.get::<_,i64>(9)?,bounded_blob(row,10)?,row.get::<_,String>(11)?))).optional().map_err(|e|sqlite_error("cannot inspect endpoint controller job",e))?;
    row.map(
        |(
            peer_id,
            job_id,
            epoch,
            id,
            expected,
            revision,
            state,
            code,
            attempts,
            next_attempt,
            bytes,
            administrator,
        )| {
            let positive = |n| u64::try_from(n).ok().filter(|n| *n > 0).ok_or_else(corrupt);
            let epoch = positive(epoch)?;
            let command_id = positive(id)?;
            let expected = positive(expected)?;
            let metadata_revision = revision.map(positive).transpose()?;
            let next_attempt = u64::try_from(next_attempt).map_err(|_| corrupt())?;
            let state = JobState::parse(&state)?;
            let valid = match state {
                JobState::Pending => {
                    metadata_revision.is_none()
                        && matches!(code.as_deref(), None | Some("node_unavailable"))
                }
                JobState::Blocked => {
                    metadata_revision.is_none()
                        && code.as_deref() == Some("node_permission_or_state")
                }
                JobState::Saved => {
                    metadata_revision == expected.checked_add(1).filter(|n| *n <= i64::MAX as u64)
                        && metadata_revision.is_some()
                        && code.is_none()
                }
                JobState::Rejected => {
                    metadata_revision.is_none() && code.as_deref() == Some("remote_rejected")
                }
                JobState::Superseded => metadata_revision.is_none() && code.is_none(),
                JobState::Applied => false,
            };
            if !valid
                || !valid_id(&peer_id)
                || !valid_id(&job_id)
                || !valid_id(&administrator)
                || (!state.unsettled() && next_attempt != 0)
            {
                return Err(corrupt());
            }
            let command = decode(&bytes)?;
            if command.target_node_id != peer_id
                || command.epoch != epoch
                || command.command_id != command_id
                || command.expected_metadata_revision != expected
                || command.source_administrator_id != administrator
            {
                return Err(corrupt());
            }
            Ok(Job {
                maintenance: None,
                user_creation: false,
                peer_id,
                job_id,
                epoch,
                command_id,
                expected_policy_revision: None,
                expected_metadata_revision: Some(expected),
                metadata_revision,
                endpoint: Some(endpoint_control::Reference {
                    listener_id: command.change.listener_id,
                    generation: command.generation,
                }),
                state,
                policy_revision: None,
                outcome_code: code,
                attempts,
                next_attempt,
                routing: None,
                preset: None,
            })
        },
    )
    .transpose()
}

pub(in crate::manage) fn complete_endpoint(
    directory: &Path,
    peer: &str,
    job_id: &str,
    receipt: &endpoint_control::Receipt,
) -> io::Result<Job> {
    if !valid_id(peer) || !valid_id(job_id) {
        return Err(input());
    }
    let _gate = super::super::update_lock(directory)?;
    let mut connection = super::super::peers::open_existing(directory, true)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin endpoint delivery receipt", e))?;
    let job = complete_endpoint_in(&tx, peer, job_id, receipt)?;
    tx.commit()
        .map_err(|e| sqlite_error("cannot commit endpoint delivery receipt", e))?;
    Ok(job)
}

/// Shared endpoint outbox core. The caller retains its validated input and
/// immediate transaction; this function never commits or delivers a secret.
pub(super) fn complete_endpoint_in(
    tx: &Connection,
    peer: &str,
    job_id: &str,
    receipt: &endpoint_control::Receipt,
) -> io::Result<Job> {
    require_transaction(tx)?;
    let previous = super::current_job(tx, peer)?.ok_or_else(missing)?;
    if previous.job_id != job_id
        || previous.epoch != receipt.epoch
        || previous.command_id != receipt.command_id
        || previous.endpoint.is_none()
    {
        return Err(conflict());
    }
    let command = read_metadata(tx, &previous)?;
    let rejected = receipt.rejection.is_some();
    if rejected {
        if receipt.metadata_revision.is_some()
            || receipt.listener_id.is_some()
            || receipt.generation.is_some()
            || receipt.rejection.is_none_or(|code| {
                !matches!(
                    code,
                    "invalid_endpoint"
                        | "endpoint_revision_changed"
                        | "endpoint_configuration_changed"
                        | "endpoint_capacity"
                )
            })
        {
            return Err(corrupt());
        }
    } else if receipt.metadata_revision
        != command
            .expected_metadata_revision
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
        || receipt.metadata_revision.is_none()
        || receipt.listener_id.as_deref() != Some(command.change.listener_id.as_str())
        || receipt.generation.as_deref() != Some(command.generation.as_str())
    {
        return Err(corrupt());
    }
    let state = if rejected {
        JobState::Rejected
    } else {
        JobState::Saved
    };
    if !previous.state.unsettled()
        && !(previous.state == state && previous.metadata_revision == receipt.metadata_revision)
    {
        return Err(conflict());
    }
    let outcome = if rejected {
        Some("remote_rejected")
    } else {
        None
    };
    if previous.state != state
        || previous.metadata_revision != receipt.metadata_revision
        || previous.outcome_code.as_deref() != outcome
        || previous.next_attempt != 0
    {
        let changed=tx.execute("UPDATE control_outbox SET state=?1,metadata_revision=?2,outcome_code=?3,next_attempt=0 WHERE peer_id=?4 AND job_id=?5 AND resource='proxy_endpoints'",params![state.as_str(),receipt.metadata_revision.map(sql).transpose()?,outcome,peer,job_id]).map_err(|e|sqlite_error("cannot save endpoint delivery receipt",e))?;
        if changed != 1 {
            return Err(corrupt());
        }
    }
    // Shared sequence advances, but a public-address edit says nothing about
    // the target's independently versioned access policy or runtime activation.
    tx.execute("UPDATE managed_targets SET observed_command=max(observed_command,?1) WHERE peer_id=?2 AND observed_epoch=?3 AND observed_command<?1",params![sql(receipt.command_id)?,peer,sql(receipt.epoch)?]).map_err(|e|sqlite_error("cannot record endpoint command observation",e))?;
    let job = super::current_job(tx, peer)?.ok_or_else(corrupt)?;
    super::history::update_current(tx, &job, None)?;
    Ok(job)
}

pub(super) fn audit(
    connection: &Connection,
    administrator: &str,
    action: &str,
    target: &Target,
    job_id: &str,
    command: &endpoint_control::Command,
) -> io::Result<()> {
    let sequence: i64 = connection
        .query_row(
            "SELECT coalesce(max(sequence),0) FROM controller_audit",
            [],
            |row| row.get(0),
        )
        .map_err(|e| sqlite_error("cannot inspect endpoint controller audit sequence", e))?;
    let next = sequence.checked_add(1).ok_or_else(conflict)?;
    let changed=connection.execute("INSERT INTO controller_audit(sequence,administrator_id,action,peer_id,target_revision,job_id,controller_epoch,command_id,mutation_action,recorded_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'set_public_address',unixepoch())",params![next,administrator,action,target.peer_id,sql(target.revision)?,job_id,sql(command.epoch)?,sql(command.command_id)?]).map_err(|e|sqlite_error("cannot record endpoint controller audit",e))?;
    if changed != 1 {
        return Err(corrupt());
    }
    connection.execute("DELETE FROM controller_audit WHERE sequence IN (SELECT sequence FROM controller_audit ORDER BY sequence DESC LIMIT -1 OFFSET ?1)",[MAX_AUDIT]).map_err(|e|sqlite_error("cannot bound endpoint controller audit",e))?;
    Ok(())
}

pub(super) fn audit_intent(
    connection: &Connection,
    administrator: &str,
    action: &str,
    target: &Target,
    job_id: &str,
    command: &ControlIntent,
) -> io::Result<()> {
    match command {
        ControlIntent::Policy(command) => super::audit(
            connection,
            administrator,
            action,
            &target.peer_id,
            target.revision,
            Some(job_id),
            Some(command),
        ),
        ControlIntent::Endpoint(command) => {
            audit(connection, administrator, action, target, job_id, command)
        }
    }
}
