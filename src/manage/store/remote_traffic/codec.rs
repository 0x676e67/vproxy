//! Private, versioned canonical cache representation. JSON is only a bounded
//! typed encoding here, not an accepted remote request/body or generic payload.

use super::{MAX_BYTES, NodeSnapshot, invalid_data};
use crate::{
    manage::store::traffic::{Status, Window},
    traffic::Snapshot,
};
use serde::{Deserialize, Serialize};
use std::io;

const MAX_TIME: u64 = 9_007_199_254_740_991;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    node: String,
    epoch: String,
    run: Option<String>,
    cursor: u64,
    clean: bool,
    loss: bool,
    gap: bool,
    uncertain: bool,
    checkpoint: Option<u64>,
    started: Option<u64>,
    totals: [Value; 3],
    minute: Vec<StoredWindow>,
    hour: Vec<StoredWindow>,
    day: Vec<StoredWindow>,
    floors: [Option<u64>; 3],
}
#[derive(Serialize, Deserialize)]
struct Value(u64, u64, bool);
#[derive(Serialize, Deserialize)]
struct StoredWindow(u64, [Option<Value>; 3]);
impl Value {
    fn new(value: Snapshot) -> Self {
        Self(value.upload, value.download, value.saturated)
    }
    fn value(self) -> Snapshot {
        Snapshot {
            upload: self.0,
            download: self.1,
            saturated: self.2,
        }
    }
}

pub(super) fn validate(snapshot: &NodeSnapshot) -> io::Result<()> {
    let status = &snapshot.status;
    if !super::valid_id(&status.node_id)
        || !super::valid_id(&status.meter_epoch)
        || status
            .run_id
            .as_ref()
            .is_some_and(|id| !super::valid_id(id))
        || !status.clean && status.run_id.is_none()
        || status.cursor > i64::MAX as u64
        || status
            .last_checkpoint_at
            .is_some_and(|time| time > MAX_TIME)
        || status.meter_started_at.is_some_and(|time| time > MAX_TIME)
    {
        return Err(invalid_data("invalid remote traffic metadata"));
    }
    for ((windows, limit, width), floor) in [
        (&snapshot.minute, 60, 60_000),
        (&snapshot.hour, 48, 3_600_000),
        (&snapshot.day, 30, 86_400_000),
    ]
    .into_iter()
    .zip(snapshot.floors)
    {
        if floor.is_some_and(|floor| floor > MAX_TIME || !floor.is_multiple_of(width)) {
            return Err(invalid_data("invalid remote traffic retention floor"));
        }
        if windows.len() > limit {
            return Err(invalid_data("remote traffic window capacity exceeded"));
        }
        let mut previous = None;
        let mut uploads = [0u128; 3];
        let mut downloads = [0u128; 3];
        for window in windows {
            if window.window_id > MAX_TIME
                || !window.window_id.is_multiple_of(width)
                || floor.is_some_and(|floor| window.window_id < floor)
                || previous.is_some_and(|old| old >= window.window_id)
                || window.values.iter().all(Option::is_none)
            {
                return Err(invalid_data("invalid remote traffic window ordering"));
            }
            previous = Some(window.window_id);
            for (index, (value, total)) in window.values.iter().zip(snapshot.totals).enumerate() {
                if value.is_some_and(|value| {
                    value.upload > total.upload
                        || value.download > total.download
                        || value.saturated && !total.saturated
                }) {
                    return Err(invalid_data(
                        "remote traffic window exceeds cumulative total",
                    ));
                }
                if let Some(value) = value {
                    uploads[index] = uploads[index]
                        .checked_add(u128::from(value.upload))
                        .ok_or_else(|| invalid_data("remote traffic window sum overflow"))?;
                    downloads[index] = downloads[index]
                        .checked_add(u128::from(value.download))
                        .ok_or_else(|| invalid_data("remote traffic window sum overflow"))?;
                }
            }
        }
        for ((upload, download), total) in uploads.into_iter().zip(downloads).zip(snapshot.totals) {
            // A saturated lifetime is only a lower bound. Otherwise disjoint
            // windows in one resolution cannot collectively exceed it.
            if !total.saturated
                && (upload > u128::from(total.upload) || download > u128::from(total.download))
            {
                return Err(invalid_data("remote traffic window sum exceeds lifetime"));
            }
        }
    }
    Ok(())
}

pub(super) fn encode(snapshot: &NodeSnapshot) -> io::Result<Vec<u8>> {
    validate(snapshot)?;
    let stored = Stored {
        version: 1,
        node: snapshot.status.node_id.clone(),
        epoch: snapshot.status.meter_epoch.clone(),
        run: snapshot.status.run_id.clone(),
        cursor: snapshot.status.cursor,
        clean: snapshot.status.clean,
        loss: snapshot.status.loss_possible,
        gap: snapshot.status.history_gap,
        uncertain: snapshot.status.time_uncertain,
        checkpoint: snapshot.status.last_checkpoint_at,
        started: snapshot.status.meter_started_at,
        totals: snapshot.totals.map(Value::new),
        minute: windows(&snapshot.minute),
        hour: windows(&snapshot.hour),
        day: windows(&snapshot.day),
        floors: snapshot.floors,
    };
    let bytes = serde_json::to_vec(&stored)
        .map_err(|_| invalid_data("cannot encode typed remote traffic cache"))?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid_data(
            "remote traffic cache exceeds representation budget",
        ));
    }
    Ok(bytes)
}
fn windows(values: &[Window]) -> Vec<StoredWindow> {
    values
        .iter()
        .map(|window| {
            StoredWindow(
                window.window_id,
                window.values.map(|value| value.map(Value::new)),
            )
        })
        .collect()
}
fn restore(values: Vec<StoredWindow>) -> Vec<Window> {
    values
        .into_iter()
        .map(|window| Window {
            window_id: window.0,
            values: window.1.map(|value| value.map(Value::value)),
        })
        .collect()
}

pub(super) fn decode(bytes: &[u8]) -> io::Result<NodeSnapshot> {
    if bytes.len() > MAX_BYTES {
        return Err(invalid_data(
            "remote traffic cache exceeds representation budget",
        ));
    }
    let stored: Stored = serde_json::from_slice(bytes)
        .map_err(|_| invalid_data("invalid typed remote traffic cache"))?;
    if stored.version != 1 {
        return Err(invalid_data("unsupported remote traffic cache version"));
    }
    let snapshot = NodeSnapshot {
        status: Status {
            node_id: stored.node,
            meter_epoch: stored.epoch,
            run_id: stored.run,
            cursor: stored.cursor,
            clean: stored.clean,
            loss_possible: stored.loss,
            history_gap: stored.gap,
            time_uncertain: stored.uncertain,
            last_checkpoint_at: stored.checkpoint,
            meter_started_at: stored.started,
        },
        totals: stored.totals.map(Value::value),
        minute: restore(stored.minute),
        hour: restore(stored.hour),
        day: restore(stored.day),
        floors: stored.floors,
    };
    if encode(&snapshot)? != bytes {
        return Err(invalid_data("remote traffic cache is not canonical"));
    }
    Ok(snapshot)
}

pub(super) fn check_progress(old: &NodeSnapshot, new: &NodeSnapshot) -> io::Result<()> {
    if old.status.node_id != new.status.node_id
        || old.status.meter_epoch != new.status.meter_epoch
        || new.status.cursor < old.status.cursor
        || old.status.loss_possible && !new.status.loss_possible
        || old.status.history_gap && !new.status.history_gap
        || old.status.time_uncertain && !new.status.time_uncertain
        || old.status.meter_started_at.is_some()
            && old.status.meter_started_at != new.status.meter_started_at
    {
        return Err(invalid_data("remote traffic continuity changed"));
    }
    if old.status.cursor == new.status.cursor && encode(old)? != encode(new)? {
        return Err(invalid_data("remote traffic same-cursor snapshot changed"));
    }
    for (old, new) in old.totals.into_iter().zip(new.totals) {
        monotonic(old, new)?;
    }
    for (((old_windows, new_windows), old_floor), floor) in [
        (&old.minute, &new.minute),
        (&old.hour, &new.hour),
        (&old.day, &new.day),
    ]
    .into_iter()
    .zip(old.floors)
    .zip(new.floors)
    {
        if old_floor.is_some_and(|old| floor.is_none_or(|floor| floor < old)) {
            return Err(invalid_data("remote traffic retention floor regressed"));
        }
        for old_window in old_windows {
            match new_windows.binary_search_by_key(&old_window.window_id, |window| window.window_id)
            {
                Ok(index) => {
                    for (old, new) in old_window.values.into_iter().zip(new_windows[index].values) {
                        match (old, new) {
                            (Some(old), Some(new)) => monotonic(old, new)?,
                            (Some(_), None) => {
                                return Err(invalid_data(
                                    "remote traffic protocol window disappeared",
                                ));
                            }
                            _ => {}
                        }
                    }
                }
                // Only an explicit retention cutoff authorizes disappearance.
                // Empty/missing rows alone are never a deletion instruction.
                Err(_) => {
                    if !floor.is_some_and(|floor| old_window.window_id < floor) {
                        return Err(invalid_data(
                            "remote traffic history disappeared before retention floor",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
fn monotonic(old: Snapshot, new: Snapshot) -> io::Result<()> {
    if new.upload < old.upload || new.download < old.download || old.saturated && !new.saturated {
        return Err(invalid_data("remote traffic counter regressed"));
    }
    Ok(())
}
