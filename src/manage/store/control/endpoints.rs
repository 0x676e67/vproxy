//! Metadata commands share owner authority and terminal command ordering, not
//! the access-policy revision or Reader publication. Source witness uncertainty
//! follows the same conservative admission suspension as other source writes.

use super::*;
use crate::manage::store::endpoints::{self as metadata, AddressSelection, Change, Inventory};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Command {
    pub(in crate::manage) target_node_id: String,
    pub(in crate::manage) epoch: u64,
    pub(in crate::manage) command_id: u64,
    pub(in crate::manage) expected_metadata_revision: u64,
    pub(in crate::manage) source_administrator_id: String,
    pub(in crate::manage) generation: String,
    pub(in crate::manage) change: Change,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct Receipt {
    pub(in crate::manage) epoch: u64,
    pub(in crate::manage) command_id: u64,
    pub(in crate::manage) metadata_revision: Option<u64>,
    pub(in crate::manage) rejection: Option<&'static str>,
    pub(in crate::manage) listener_id: Option<String>,
    pub(in crate::manage) generation: Option<String>,
}
pub(in crate::manage) struct Outcome {
    pub(in crate::manage) receipt: Receipt,
    pub(in crate::manage) replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Reference {
    pub(in crate::manage) listener_id: String,
    pub(in crate::manage) generation: String,
}

pub(in crate::manage) fn validate(command: &Command) -> io::Result<()> {
    if !valid_id(&command.target_node_id)
        || !valid_id(&command.source_administrator_id)
        || !valid_id(&command.change.listener_id)
        || command.generation.len() != 64
        || !command
            .generation
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(input("invalid endpoint command"));
    }
    positive(command.epoch)?;
    positive(command.command_id)?;
    positive(command.expected_metadata_revision)?;
    if let AddressSelection::Custom { public_address } = &command.change.selection {
        crate::manage::proxy::public_address(public_address)
            .map_err(|_| input("invalid endpoint public address"))?;
    }
    Ok(())
}

fn digest(command: &Command) -> io::Result<[u8; 32]> {
    validate(command)?;
    fn text(hash: &mut Sha256, value: &str) {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    let mut hash = Sha256::new();
    hash.update(b"vproxy.endpoint-command.v4\0");
    text(&mut hash, &command.target_node_id);
    hash.update(command.epoch.to_be_bytes());
    hash.update(command.command_id.to_be_bytes());
    hash.update(command.expected_metadata_revision.to_be_bytes());
    text(&mut hash, &command.source_administrator_id);
    text(&mut hash, &command.generation);
    text(&mut hash, &command.change.listener_id);
    match &command.change.selection {
        AddressSelection::Inherit => hash.update([0]),
        AddressSelection::Hidden => hash.update([1]),
        AddressSelection::Custom { public_address } => {
            hash.update([2]);
            text(&mut hash, public_address);
        }
    }
    Ok(hash.finalize().into())
}

pub(super) fn receipt_version(
    connection: &Connection,
    epoch: u64,
    id: u64,
) -> io::Result<Option<u8>> {
    connection
        .query_row(
            "SELECT version FROM control_receipts WHERE epoch=?1 AND command_id=?2",
            params![positive(epoch)?, positive(id)?],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| sqlite_error("cannot inspect command receipt resource", e))
}

fn rejection(value: &str) -> io::Result<&'static str> {
    match value {
        "invalid_endpoint" => Ok("invalid_endpoint"),
        "endpoint_revision_changed" => Ok("endpoint_revision_changed"),
        "endpoint_configuration_changed" => Ok("endpoint_configuration_changed"),
        "endpoint_capacity" => Ok("endpoint_capacity"),
        _ => Err(data("invalid endpoint receipt rejection")),
    }
}

fn find(connection: &Connection, epoch: u64, id: u64) -> io::Result<Option<(Receipt, [u8; 32])>> {
    let row=connection.query_row("SELECT status,metadata_revision,rejection,endpoint_id,endpoint_generation,digest,policy_revision IS NULL AND user_id IS NULL AND credential_id IS NULL AND routing_kind IS NULL AND routing_id IS NULL AND preset_kind IS NULL AND preset_id IS NULL FROM control_receipts WHERE epoch=?1 AND command_id=?2 AND version=4",params![positive(epoch)?,positive(id)?],|row|{
        let value=row.get_ref(5)?;let digest=match value {ValueRef::Blob(bytes) if bytes.len()==32=>{let mut digest=[0;32];digest.copy_from_slice(bytes);digest},_=>return Err(rusqlite::Error::InvalidColumnType(5,"digest".into(),value.data_type()))};
        Ok((row.get::<_,String>(0)?,row.get::<_,Option<i64>>(1)?,row.get::<_,Option<String>>(2)?,row.get::<_,Option<String>>(3)?,row.get::<_,Option<String>>(4)?,digest,row.get::<_,bool>(6)?))
    }).optional().map_err(|e|sqlite_error("cannot inspect endpoint receipt",e))?;
    row.map(
        |(status, revision, code, listener, generation, digest, separated)| {
            let revision = revision
                .map(|n| {
                    u64::try_from(n)
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(|| data("invalid endpoint receipt revision"))
                })
                .transpose()?;
            let rejection = code.as_deref().map(rejection).transpose()?;
            let saved = status == "saved";
            if !separated
                || (!saved && status != "rejected")
                || saved != (revision.is_some())
                || saved != (listener.is_some())
                || saved != (generation.is_some())
                || saved == rejection.is_some()
                || listener.as_deref().is_some_and(|id| !valid_id(id))
                || generation.as_deref().is_some_and(|hash| {
                    hash.len() != 64
                        || !hash
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            {
                return Err(data("invalid endpoint receipt"));
            }
            Ok((
                Receipt {
                    epoch,
                    command_id: id,
                    metadata_revision: revision,
                    rejection,
                    listener_id: listener,
                    generation,
                },
                digest,
            ))
        },
    )
    .transpose()
}

/// Authorization precedes replay; replay precedes current catalog CAS. A saved
/// historical result therefore remains recoverable after restart/config change.
pub(in crate::manage) fn apply(
    directory: &Path,
    guard: &UpdateGuard,
    authorization: &RemoteAuthorization,
    inventory: &Inventory,
    command: Command,
) -> io::Result<Outcome> {
    guard.ensure(directory)?;
    let digest = digest(&command)?;
    let mut connection = peers::open_existing(directory, true)?;
    let mut tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_error("cannot begin endpoint command", e))?;
    let outcome = apply_with_digest(&mut tx, authorization, inventory, command, digest)?;
    let context = if outcome.replayed {
        "cannot complete endpoint command replay"
    } else {
        "cannot commit endpoint command"
    };
    tx.commit().map_err(|e| sqlite_error(context, e))?;
    Ok(outcome)
}

/// Apply under the source worker's transaction without committing or publishing
/// policy. Terminal replay rechecks current peer/owner authority, then only reads
/// its original v4 receipt; it consumes neither command nor witness sequence.
#[cfg(feature = "witness-journal")]
pub(in crate::manage) fn apply_in(
    tx: &mut rusqlite::Transaction<'_>,
    authorization: &RemoteAuthorization,
    inventory: &Inventory,
    command: Command,
) -> io::Result<Outcome> {
    let digest = digest(&command)?;
    apply_with_digest(tx, authorization, inventory, command, digest)
}

fn apply_with_digest(
    tx: &mut rusqlite::Transaction<'_>,
    authorization: &RemoteAuthorization,
    inventory: &Inventory,
    command: Command,
    digest: [u8; 32],
) -> io::Result<Outcome> {
    let owner = authorize_in(tx, authorization)?;
    if read_overview(tx)?.schema_version < 15 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            metadata::Error::UpgradeRequired,
        ));
    }
    if read_overview(tx)?.node_id != command.target_node_id {
        return Err(ControlError::TargetMismatch.error());
    }
    if owner.epoch != command.epoch {
        return Err(ControlError::EpochConflict.error());
    }
    if command.command_id <= owner.last_terminal_command {
        if receipt_version(tx, command.epoch, command.command_id)?
            .is_some_and(|version| version != 4)
        {
            return Err(ControlError::CommandConflict.error());
        }
        let (receipt, old_digest) = find(tx, command.epoch, command.command_id)?
            .ok_or_else(|| ControlError::ReceiptExpired.error())?;
        if old_digest != digest {
            return Err(ControlError::CommandConflict.error());
        }
        return Ok(Outcome {
            receipt,
            replayed: true,
        });
    }
    if command.command_id != next(owner.last_terminal_command)? {
        return Err(ControlError::CommandOutOfOrder.error());
    }
    let result = {
        let mut savepoint = tx
            .savepoint()
            .map_err(|e| sqlite_error("cannot begin endpoint command savepoint", e))?;
        match metadata::apply_in(
            &savepoint,
            inventory,
            command.expected_metadata_revision,
            &command.generation,
            &command.change,
            users::Actor::Remote {
                node_id: &authorization.node_id,
                epoch: command.epoch,
                command_id: command.command_id,
                source_administrator_id: &command.source_administrator_id,
            },
        ) {
            Ok(state) => {
                savepoint
                    .commit()
                    .map_err(|e| sqlite_error("cannot release endpoint command savepoint", e))?;
                Ok(state.revision)
            }
            Err(error) => {
                if let Some(code) = error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<metadata::Error>())
                    .filter(|e| !matches!(e, metadata::Error::UpgradeRequired))
                    .map(|e| e.code())
                {
                    savepoint.rollback().map_err(|e| {
                        sqlite_error("cannot roll back rejected endpoint command", e)
                    })?;
                    Err(code)
                } else {
                    return Err(error);
                }
            }
        }
    };
    let receipt = match result {
        Ok(revision) => Receipt {
            epoch: command.epoch,
            command_id: command.command_id,
            metadata_revision: Some(revision),
            rejection: None,
            listener_id: Some(command.change.listener_id),
            generation: Some(command.generation),
        },
        Err(code) => Receipt {
            epoch: command.epoch,
            command_id: command.command_id,
            metadata_revision: None,
            rejection: Some(code),
            listener_id: None,
            generation: None,
        },
    };
    let changed=tx.execute("INSERT INTO control_receipts(epoch,command_id,controller_node_id,digest,status,version,metadata_revision,rejection,endpoint_id,endpoint_generation) VALUES(?1,?2,?3,?4,?5,4,?6,?7,?8,?9)",params![positive(receipt.epoch)?,positive(receipt.command_id)?,authorization.node_id,&digest[..],if receipt.rejection.is_some(){"rejected"}else{"saved"},receipt.metadata_revision.map(positive).transpose()?,receipt.rejection,receipt.listener_id,receipt.generation]).map_err(|e|sqlite_error("cannot save endpoint command receipt",e))?;
    if changed != 1 {
        return Err(data(
            "endpoint receipt insertion affected invalid row count",
        ));
    }
    let changed=tx.execute("UPDATE control_ownership SET last_terminal_command=?1 WHERE singleton=1 AND epoch=?2 AND last_terminal_command=?3",params![positive(command.command_id)?,positive(command.epoch)?,i64::try_from(owner.last_terminal_command).map_err(|_|data("invalid command high water"))?]).map_err(|e|sqlite_error("cannot advance endpoint command high water",e))?;
    if changed != 1 {
        return Err(data("endpoint command high water changed"));
    }
    if let Some(code) = receipt.rejection {
        let changed=tx.execute("INSERT INTO control_audit(action,controller_node_id,epoch,command_id,source_administrator_id,rejection) VALUES('command_rejected',?1,?2,?3,?4,?5)",params![authorization.node_id,positive(receipt.epoch)?,positive(receipt.command_id)?,command.source_administrator_id,code]).map_err(|e|sqlite_error("cannot audit rejected endpoint command",e))?;
        if changed != 1 {
            return Err(data("endpoint rejection audit did not persist"));
        }
    }
    tx.execute("DELETE FROM control_receipts WHERE (epoch,command_id) IN (SELECT epoch,command_id FROM control_receipts ORDER BY coalesce(status='saved' AND policy_revision=(SELECT revision FROM proxy_policy_state WHERE singleton=1),0) DESC,epoch DESC,command_id DESC LIMIT -1 OFFSET ?1)",[MAX_RECEIPTS]).map_err(|e|sqlite_error("cannot bound endpoint command receipts",e))?;
    prune_audit(tx)?;
    Ok(Outcome {
        receipt,
        replayed: false,
    })
}

pub(in crate::manage) fn receipt(
    directory: &Path,
    authorization: &RemoteAuthorization,
    epoch: u64,
    id: u64,
) -> io::Result<Receipt> {
    read_snapshot(directory, |connection| {
        let owner = authorize_in(connection, authorization)?;
        require_schema(connection)?;
        if owner.epoch != epoch {
            return Err(ControlError::EpochConflict.error());
        }
        find(connection, epoch, id)?
            .map(|(receipt, _)| receipt)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "endpoint receipt not found"))
    })
}

pub(in crate::manage) fn state(
    directory: &Path,
    authorization: &RemoteAuthorization,
) -> io::Result<metadata::State> {
    read_snapshot(directory, |connection| {
        authorize_in(connection, authorization)?;
        require_schema(connection)?;
        metadata::read_in(connection)
    })
}

fn require_schema(connection: &Connection) -> io::Result<()> {
    if read_overview(connection)?.schema_version < 15 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            metadata::Error::UpgradeRequired,
        ));
    }
    Ok(())
}
