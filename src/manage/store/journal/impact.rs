//! Policy dependencies of users::read_policy, routing::read, presets::read and
//! admission::read_in for the current source schema. Unknown tables refuse;
//! adding a durable table requires an explicit classification, not a default
//! assumption that it cannot affect a compiled Reader.

use super::*;
use rusqlite::types::ValueRef;

/// Derived from the original changeset, never supplied by an API caller. An
/// unchanged revision by itself cannot establish `Unchanged`: every Reader
/// dependency must also be absent from the net changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manage::store) enum Effect {
    Unchanged,
    Changed { before: u64, after: u64 },
}

#[derive(Clone, Copy)]
pub(super) enum Table {
    Other,
    Policy,
    Revision(usize),
    /// Native-only socket settings have no witnessed activation contract yet.
    /// Recognise their catalog but refuse every row change, even alongside a
    /// valid policy revision. They are not harmless descriptive metadata.
    Unsupported,
}

pub(super) fn table(connection: &Connection, name: &str) -> io::Result<Table> {
    match name {
        "proxy_service_state" | "proxy_service_operations" => Ok(Table::Unsupported),
        "proxy_users"
        | "proxy_credentials"
        | "routing_prefixes"
        | "routing_addresses"
        | "routing_pools"
        | "routing_pool_members"
        | "routing_permissions"
        | "routing_exit_grants"
        | "routing_pool_grants"
        | "user_presets"
        | "pool_presets"
        | "proxy_admission_state" => Ok(Table::Policy),
        "proxy_policy_state" => {
            let mut statement = connection
                .prepare(
                    "SELECT cid,name,pk FROM pragma_table_xinfo('proxy_policy_state') ORDER BY cid",
                )
                .map_err(|e| sqlite_error("cannot inspect source policy columns", e))?;
            let mut rows = statement
                .query([])
                .map_err(|e| sqlite_error("cannot read source policy columns", e))?;
            let mut count = 0;
            let mut revision = None;
            while let Some(row) = rows
                .next()
                .map_err(|e| sqlite_error("cannot read source policy column", e))?
            {
                let cid: i64 = row
                    .get(0)
                    .map_err(|e| sqlite_error("cannot decode source policy column", e))?;
                let name: String = row
                    .get(1)
                    .map_err(|e| sqlite_error("cannot decode source policy column", e))?;
                let pk: i64 = row
                    .get(2)
                    .map_err(|e| sqlite_error("cannot decode source policy key", e))?;
                let index = usize::try_from(cid).map_err(|_| invalid())?;
                if count >= 3 || index != count || pk != i64::from(name == "singleton") {
                    return Err(invalid());
                }
                match name.as_str() {
                    "revision" => revision = Some(index),
                    "singleton" | "applied_revision" => {}
                    _ => return Err(invalid()),
                }
                count += 1;
            }
            if count != 3 {
                return Err(invalid());
            }
            Ok(Table::Revision(revision.ok_or_else(invalid)?))
        }
        "node_identity"
        | "administrators"
        | "administrator_audit_state"
        | "administrator_audit"
        | "peers"
        | "peer_certificates"
        | "peer_audit"
        | "proxy_policy_audit"
        | "control_ownership"
        | "control_receipts"
        | "control_audit"
        | "managed_targets"
        | "control_outbox"
        | "controller_audit"
        | "routing_audit"
        | "traffic_state"
        | "traffic_series"
        | "traffic_windows"
        | "remote_traffic_sources"
        | "preset_audit"
        | "recovery_state"
        | "endpoint_state"
        | "endpoint_overrides"
        | "endpoint_audit"
        | "operations_state"
        | "user_operations"
        | "automation_state"
        | "automation_principals"
        | "automation_audit"
        | "proxy_admission_audit"
        | "controller_history_state"
        | "controller_history"
        | "alert_history_state"
        | "alert_episodes"
        | "alert_events"
        | "webhook_state"
        | "recovery_witness"
        // Ciphertext is witnessed with its credential mutation, but never
        // enters Reader compilation or the forwarding/authentication path.
        | "proxy_credential_secrets"
        | "recovery_source" => Ok(Table::Other),
        _ => Err(invalid()),
    }
}

/// Small order-independent accumulation, separate from the row fingerprints.
/// Malformed/unversioned legacy changesets remain comparable as deltas, but
/// cannot authorize a new source write or same-process policy restoration.
pub(super) struct Tracker {
    touched: bool,
    version: Option<(u64, u64)>,
    state_seen: bool,
    valid: bool,
}

impl Tracker {
    pub(super) fn new() -> Self {
        Self {
            touched: false,
            version: None,
            state_seen: false,
            valid: true,
        }
    }
    pub(super) fn row(&mut self, table: Table, action: u8) {
        match table {
            Table::Other => {}
            Table::Unsupported => self.valid = false,
            Table::Policy => self.touched = true,
            Table::Revision(_) => {
                self.valid &= action == 2 && !self.state_seen;
                self.state_seen = true;
            }
        }
    }
    pub(super) fn cell(
        &mut self,
        table: Table,
        index: usize,
        old: Option<ValueRef<'_>>,
        new: Option<ValueRef<'_>>,
    ) {
        if let Table::Revision(revision) = table
            && revision == index
            && (old.is_some() || new.is_some())
        {
            self.touched = true;
            match (number(old), number(new)) {
                (Some(before), Some(after)) if after > before && self.version.is_none() => {
                    self.version = Some((before, after))
                }
                _ => self.valid = false,
            }
        }
    }
    pub(super) fn finish(self) -> Option<Effect> {
        if !self.valid {
            return None;
        }
        match (self.touched, self.version) {
            (false, None) => Some(Effect::Unchanged),
            (_, Some((before, after))) => Some(Effect::Changed { before, after }),
            _ => None,
        }
    }
}

fn number(value: Option<ValueRef<'_>>) -> Option<u64> {
    match value {
        Some(ValueRef::Integer(n)) if n > 0 => u64::try_from(n).ok(),
        _ => None,
    }
}
