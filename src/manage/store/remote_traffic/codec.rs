//! Private, versioned canonical cache representation. JSON is only a bounded
//! typed encoding here, not an accepted remote request/body or generic payload.

use super::{MAX_BYTES, NodeSnapshot, invalid_data};
use crate::access::traffic::{PROTOCOL_COUNT, legacy_values, legacy_window};
use crate::{
    manage::store::traffic::{Status, Window},
    traffic::Snapshot,
};
use serde::{Deserialize, Serialize};
use std::io;

const ZERO: Snapshot = Snapshot {
    upload: 0,
    download: 0,
    saturated: false,
};

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
    totals: Vec<Value>,
    minute: Vec<StoredWindow>,
    hour: Vec<StoredWindow>,
    day: Vec<StoredWindow>,
    floors: [Option<u64>; 3],
}
#[derive(Serialize, Deserialize)]
struct Value(u64, u64, bool);
#[derive(Serialize, Deserialize)]
struct StoredWindow(u64, Vec<Option<Value>>);
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
    if !snapshot.status.http_split
        && (snapshot.totals[3..].iter().any(|value| *value != ZERO)
            || snapshot
                .minute
                .iter()
                .chain(&snapshot.hour)
                .chain(&snapshot.day)
                .any(|window| window.values[3..].iter().any(Option::is_some)))
    {
        return Err(invalid_data(
            "legacy traffic contains split protocol counters",
        ));
    }
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
        let mut uploads = [0u128; PROTOCOL_COUNT];
        let mut downloads = [0u128; PROTOCOL_COUNT];
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
        version: if snapshot.status.http_split { 2 } else { 1 },
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
        totals: if snapshot.status.http_split {
            snapshot.totals.into_iter().map(Value::new).collect()
        } else {
            legacy_values(snapshot.totals)
                .into_iter()
                .map(Value::new)
                .collect()
        },
        minute: windows(&snapshot.minute, snapshot.status.http_split),
        hour: windows(&snapshot.hour, snapshot.status.http_split),
        day: windows(&snapshot.day, snapshot.status.http_split),
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
fn windows(values: &[Window], split: bool) -> Vec<StoredWindow> {
    values
        .iter()
        .map(|window| {
            StoredWindow(
                window.window_id,
                if split {
                    window
                        .values
                        .into_iter()
                        .map(|value| value.map(Value::new))
                        .collect()
                } else {
                    legacy_window(window.values)
                        .into_iter()
                        .map(|value| value.map(Value::new))
                        .collect()
                },
            )
        })
        .collect()
}
fn restore(values: Vec<StoredWindow>, split: bool) -> io::Result<Vec<Window>> {
    values
        .into_iter()
        .map(|window| {
            Ok(Window {
                window_id: window.0,
                values: {
                    let expected = if split { PROTOCOL_COUNT } else { 3 };
                    if window.1.len() != expected {
                        return Err(invalid_data("invalid cached traffic protocol count"));
                    }
                    let mut restored = [None; PROTOCOL_COUNT];
                    for (slot, value) in restored.iter_mut().zip(window.1) {
                        *slot = value.map(Value::value);
                    }
                    restored
                },
            })
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
    if !matches!(stored.version, 1 | 2) {
        return Err(invalid_data("unsupported remote traffic cache version"));
    }
    let split = stored.version == 2;
    if stored.totals.len() != if split { PROTOCOL_COUNT } else { 3 } {
        return Err(invalid_data("invalid cached traffic total count"));
    }
    let mut totals = [ZERO; PROTOCOL_COUNT];
    for (slot, value) in totals.iter_mut().zip(stored.totals) {
        *slot = value.value();
    }
    let snapshot = NodeSnapshot {
        status: Status {
            http_split: split,
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
        totals,
        minute: restore(stored.minute, split)?,
        hour: restore(stored.hour, split)?,
        day: restore(stored.day, split)?,
        floors: stored.floors,
    };
    if encode(&snapshot)? != bytes {
        return Err(invalid_data("remote traffic cache is not canonical"));
    }
    Ok(snapshot)
}

pub(super) fn check_progress(old: &NodeSnapshot, new: &NodeSnapshot) -> io::Result<()> {
    if old.status.http_split && !new.status.http_split {
        return Err(invalid_data("remote traffic protocol format regressed"));
    }
    if !old.status.http_split && new.status.http_split {
        // Compare the old representation against an equivalent family view,
        // not the smaller, preserved legacy slot alone. The accepted value is
        // still the original validated split snapshot, never this projection.
        validate(new)?;
        let mut status = new.status.clone();
        status.http_split = false;
        let [http, socks, masque] = legacy_values(new.totals);
        let project = |windows: &[Window]| {
            windows
                .iter()
                .map(|window| {
                    let [http, socks, masque] = legacy_window(window.values);
                    Window {
                        window_id: window.window_id,
                        values: [http, socks, masque, None, None],
                    }
                })
                .collect()
        };
        return check_progress(
            old,
            &NodeSnapshot {
                status,
                totals: [http, socks, masque, ZERO, ZERO],
                floors: new.floors,
                minute: project(&new.minute),
                hour: project(&new.hour),
                day: project(&new.day),
            },
        );
    }
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
