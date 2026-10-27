//! Keep current/predecessor intent evidence and collect only older indexed,
//! dispatched records under a fresh confirmed local/witness floor. A durable
//! retirement marker owns partial deletion; no recursive delete or adoption of
//! unindexed/unknown files is allowed. Existing ancestors remain trusted.

use super::*;

// Room for two protected maximum containers plus the next reservation/control
// records. Unknown contents consume this same budget; free disk is separate.
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 256;
const NEW_ENTRIES: usize = 6; // directory, payload, metadata, locator, sent, retirement
const KEEP: u64 = 2;
const COLLECT_RECORDS: usize = 4;
const COLLECT_BYTES: u64 = segments::MAX_BYTES + 4 * MAX_META as u64;

/// Logical regular-file bytes/entries, not allocated blocks, free disk space,
/// Session memory or time. Unknown files consume the same finite budget.
#[derive(Default)]
struct Inventory {
    bytes: u64,
    entries: usize,
    locations: Vec<u64>,
    retired: Vec<u64>,
}

impl Inventory {
    fn add(&mut self, bytes: u64) -> io::Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .filter(|n| *n <= MAX_ENTRIES)
            .ok_or_else(full)?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|n| *n <= MAX_BYTES)
            .ok_or_else(full)?;
        Ok(())
    }
}

fn full() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "private source journal capacity reached; inspect retained operations",
    )
}

fn number(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0 && *n <= i64::MAX as u64 && n.to_string() == value)
}

fn retired_name(number: u64) -> String {
    format!("retired-{number}.json")
}

fn scan(root: &Path) -> io::Result<Inventory> {
    files::check_directory(root, true)?;
    let mut value = Inventory::default();
    for row in fs::read_dir(root)? {
        let row = row?;
        let metadata = fs::symlink_metadata(row.path())?;
        if metadata.file_type().is_symlink() {
            return Err(invalid());
        }
        if metadata.is_dir() {
            value.add(0)?;
            files::check_directory(&row.path(), true)?;
            for child in fs::read_dir(row.path())? {
                let child = child?;
                let metadata = fs::symlink_metadata(child.path())?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(invalid());
                }
                value.add(metadata.len())?;
            }
        } else if metadata.is_file() {
            value.add(metadata.len())?;
            let name = row.file_name();
            if let Some(name) = name.to_str() {
                if let Some(n) = name
                    .strip_prefix("retired-")
                    .and_then(|v| v.strip_suffix(".json"))
                    .and_then(number)
                {
                    value.retired.push(n);
                } else if let Some(n) = name.strip_suffix(".json").and_then(number) {
                    value.locations.push(n);
                }
            }
        } else {
            return Err(invalid());
        }
    }
    Ok(value)
}

/// Reserve worst-case logical bytes before any intent output/Reserve. Candidate
/// SQL rolls back on refusal; any business pre-change backup remains private.
pub(in crate::manage::store::journal) fn check_capacity(scope: &Scope<'_>) -> io::Result<()> {
    check_capacity_for(scope, MAX_PAYLOAD as u64)
}
pub(in crate::manage::store::journal) fn check_capacity_for(
    scope: &Scope<'_>,
    payload: u64,
) -> io::Result<()> {
    if payload == 0 || payload > segments::MAX_BYTES {
        return Err(invalid());
    }
    scope.author.ensure(scope.directory)?;
    scope.gate.ensure(scope.directory)?;
    let inventory = scan(&scope.directory.join(ROOT))?;
    inventory
        .bytes
        .checked_add(payload.checked_add(4 * MAX_META as u64).ok_or_else(full)?)
        .filter(|n| *n <= MAX_BYTES)
        .ok_or_else(full)?;
    inventory
        .entries
        .checked_add(NEW_ENTRIES)
        .filter(|n| *n <= MAX_ENTRIES)
        .ok_or_else(full)?;
    Ok(())
}

/// Non-secret evidence that this exact old directory was validated before
/// deletion. It permits resuming only these files after interruption, never
/// recreating missing content or weakening the current witness/local floor.
#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Retired {
    format: u8,
    location: Location,
    marked_at: source::Floor,
    metadata_sha256: String,
    payload_sha256: String,
    payload_bytes: u64,
}

impl Retired {
    fn read(path: &Path, enrollment: &Enrollment) -> io::Result<Self> {
        let bytes = files::read(path, MAX_META, true)?;
        let value: Self = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        value.location.transition.validate()?;
        value.marked_at.validate()?;
        if value.format != 1
            || value.location.format != 1
            || !super::super::super::valid_id(&value.location.intent_id)
            || value.location.transition.witness_node_id != enrollment.witness_node_id
            || value.location.transition.binding_id != enrollment.binding_id
            || value.location.transition.writer_id != enrollment.writer_id
            || !digest(&value.metadata_sha256)
            || !digest(&value.payload_sha256)
            || value.payload_bytes == 0
            || value.payload_bytes > segments::MAX_BYTES
            || serde_json::to_vec(&value)
                .map_err(|_| invalid())?
                .as_slice()
                != bytes.as_slice()
        {
            return Err(invalid());
        }
        Ok(value)
    }
}

impl Journal<'_> {
    /// Simulate interruption immediately after durable marking in a fresh test
    /// journal; production enters this path only through confirmed collection.
    #[cfg(test)]
    pub(in crate::manage::store::journal) fn stage_retirement(
        &self,
        connection: &Connection,
        number: u64,
    ) -> io::Result<()> {
        let floor = self.scope.state(connection)?.floor;
        let current = self.current(connection)?.ok_or_else(invalid)?;
        self.mark_retired(
            number,
            &floor,
            current.metadata.before.intent_id.as_deref(),
            COLLECT_BYTES,
        )?
        .ok_or_else(invalid)?;
        Ok(())
    }

    /// Maintenance errors retain evidence and never change a confirmed business
    /// result into an unknown/failure. Capacity still bounds the next changed
    /// candidate. Log once until a successful sweep, without paths or secrets.
    pub(in crate::manage::store::journal) fn maintain_confirmed(
        &self,
        connection: &Connection,
        confirmed: &Fetched<Record>,
    ) {
        if self.collect(connection, confirmed).is_err() {
            if !self.collection_warned.swap(true, Ordering::AcqRel) {
                tracing::warn!("source journal cleanup deferred; original records retained");
            }
        } else {
            self.collection_warned.store(false, Ordering::Release);
        }
    }

    fn collect(&self, connection: &Connection, confirmed: &Fetched<Record>) -> io::Result<()> {
        self.ensure()?;
        if !connection.is_autocommit() {
            return Err(invalid());
        }
        self.scope.authorize(connection, confirmed)?;
        let state = self.scope.state(connection)?;
        let floor = &state.floor;
        if confirmed.value.phase != Phase::Confirmed
            || confirmed.value.sequence != floor.sequence.to_string()
            || self.pending(connection)?.is_some()
        {
            return Err(denied());
        }
        // Driver ready/confirm has just checked the actual current payload.
        // Repeat its locator/floor binding without another full payload scan.
        let predecessor = if floor.sequence == 0 {
            if confirmed.value.commitment != self.scope.enrollment.baseline {
                return Err(denied());
            }
            None
        } else {
            let current = Location::read(
                &self.root.join(Self::name(floor.sequence, false)?),
                self.scope.enrollment,
            )?;
            if floor.intent_id.as_ref() != Some(&current.intent_id)
                || floor.previous.as_ref() != Some(&current.transition.previous)
                || current.transition.sequence != floor.sequence.to_string()
                || current.transition.commitment != confirmed.value.commitment
            {
                return Err(denied());
            }
            let directory = self.root.join(&current.intent_id);
            files::check_directory(&directory, true)?;
            let bytes = files::read(&directory.join(META), MAX_META, true)?;
            let metadata: Metadata = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            metadata.validate(self.scope.enrollment)?;
            let intent = Intent {
                directory,
                metadata,
            };
            if Location::of(&intent) != current
                || intent.metadata.after_state()? != state
                || serde_json::to_vec(&intent.metadata)
                    .map_err(|_| invalid())?
                    .as_slice()
                    != bytes.as_slice()
            {
                return Err(denied());
            }
            // The current witness commitment binds this predecessor's random
            // identity. A damaged old locator/retirement marker must not alias
            // that directory even when its sequence looks collectable.
            intent.metadata.before.intent_id
        };
        let cutoff = floor.sequence.saturating_sub(KEEP - 1);
        let inventory = scan(&self.root)?;
        // Normal admission reserves this space already. Also refuse to grow a
        // legacy/externally filled root beyond its cap just to mark a deletion.
        // Successful retirements only release space; a conservative refusal can
        // be reconsidered on the next freshly inventoried sweep.
        let can_mark = inventory.entries < MAX_ENTRIES
            && inventory
                .bytes
                .checked_add(MAX_META as u64)
                .is_some_and(|n| n <= MAX_BYTES);
        let mut candidates = inventory.retired;
        candidates.sort_unstable();
        let mut locations = inventory.locations;
        locations.sort_unstable();
        candidates.extend(locations);
        let mut seen = std::collections::HashSet::new();
        let mut bytes = 0_u64;
        for candidate in candidates.into_iter().filter(|n| *n < cutoff) {
            if !seen.insert(candidate) {
                continue;
            }
            if seen.len() > COLLECT_RECORDS {
                break;
            }
            let marker_path = self.root.join(retired_name(candidate));
            let (record, fresh) = match fs::symlink_metadata(&marker_path) {
                Ok(_) => (Retired::read(&marker_path, self.scope.enrollment)?, false),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if !can_mark {
                        return Err(full());
                    }
                    let Some(record) = self.mark_retired(
                        candidate,
                        floor,
                        predecessor.as_deref(),
                        COLLECT_BYTES - bytes,
                    )?
                    else {
                        break;
                    };
                    (record, true)
                }
                Err(error) => return Err(error),
            };
            let charge = record
                .payload_bytes
                .checked_add(4 * MAX_META as u64)
                .ok_or_else(invalid)?;
            let Some(next) = bytes.checked_add(charge).filter(|n| *n <= COLLECT_BYTES) else {
                break;
            };
            self.remove_retired(candidate, floor, predecessor.as_deref(), &record, fresh)?;
            bytes = next;
        }
        Ok(())
    }

    /// Validate a dispatched old operation and read back its durable deletion
    /// ownership before returning. `None` leaves it untouched for a later sweep.
    fn mark_retired(
        &self,
        number: u64,
        floor: &source::Floor,
        predecessor: Option<&str>,
        budget: u64,
    ) -> io::Result<Option<Retired>> {
        let location = Location::read(
            &self.root.join(Self::name(number, false)?),
            self.scope.enrollment,
        )?;
        if number.checked_add(KEEP).is_none_or(|n| n > floor.sequence)
            || floor.intent_id.as_ref() == Some(&location.intent_id)
            || predecessor == Some(location.intent_id.as_str())
        {
            return Err(denied());
        }
        let size = fs::symlink_metadata(self.root.join(&location.intent_id).join(PAYLOAD))?.len();
        if size > segments::MAX_BYTES {
            return Err(invalid());
        }
        if size
            .checked_add(4 * MAX_META as u64)
            .is_none_or(|n| n > budget)
        {
            return Ok(None);
        }
        let intent = self.load(number)?;
        if !self.was_dispatched(&intent)? {
            return Err(denied());
        }
        let metadata = files::read(&intent.directory.join(META), MAX_META, true)?;
        let record = Retired {
            format: 1,
            location,
            marked_at: floor.clone(),
            metadata_sha256: hex(&Sha256::digest(metadata.as_slice())),
            payload_sha256: intent.metadata.payload_sha256.clone(),
            payload_bytes: intent.metadata.payload_bytes,
        };
        let encoded = serde_json::to_vec(&record).map_err(|_| invalid())?;
        if encoded.len() > MAX_META {
            return Err(invalid());
        }
        let name = retired_name(number);
        files::write(&self.root, &name, &encoded)?;
        let actual = Retired::read(&self.root.join(name), self.scope.enrollment)?;
        if actual != record {
            return Err(denied());
        }
        Ok(Some(actual))
    }

    fn remove_retired(
        &self,
        number: u64,
        floor: &source::Floor,
        predecessor: Option<&str>,
        retired: &Retired,
        fresh: bool,
    ) -> io::Result<()> {
        self.ensure()?;
        if sequence(&retired.location.transition.sequence)? != number
            || number
                .checked_add(KEEP)
                .is_none_or(|n| n > retired.marked_at.sequence)
            || retired.marked_at.sequence > floor.sequence
            || retired.marked_at.intent_id.as_ref() == Some(&retired.location.intent_id)
            || floor.intent_id.as_ref() == Some(&retired.location.intent_id)
            || predecessor == Some(retired.location.intent_id.as_str())
        {
            return Err(denied());
        }
        for sent in [false, true] {
            let path = self.root.join(Self::name(number, sent)?);
            if exists(&path)? && Location::read(&path, self.scope.enrollment)? != retired.location {
                return Err(denied());
            }
        }
        let directory = self.root.join(&retired.location.intent_id);
        if exists(&directory)? {
            files::check_directory(&directory, true)?;
            if fs::canonicalize(&directory)?.parent() != Some(self.root.as_path()) {
                return Err(denied());
            }
            let mut count = 0_usize;
            for row in fs::read_dir(&directory)? {
                let row = row?;
                count += 1;
                if count > 2 || (row.file_name() != META && row.file_name() != PAYLOAD) {
                    return Err(invalid());
                }
            }
            let metadata_path = directory.join(META);
            let payload_path = directory.join(PAYLOAD);
            if exists(&metadata_path)? {
                let bytes = files::read(&metadata_path, MAX_META, true)?;
                if hex(&Sha256::digest(bytes.as_slice())) != retired.metadata_sha256 {
                    return Err(denied());
                }
                let metadata: Metadata = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
                metadata.validate(self.scope.enrollment)?;
                let intent = Intent {
                    directory: directory.clone(),
                    metadata,
                };
                if Location::of(&intent) != retired.location
                    || intent.metadata.payload_sha256 != retired.payload_sha256
                    || intent.metadata.payload_bytes != retired.payload_bytes
                {
                    return Err(denied());
                }
            } else if exists(&payload_path)? {
                return Err(invalid());
            }
            // Fresh marking already validated this payload under the same
            // exclusive guards. Resume after interruption hashes it once here.
            // Hostile races by the same OS principal remain outside the file
            // helper's trust model, not a reason to double-read each payload.
            if !fresh && exists(&payload_path)? {
                drop(segments::verified_file(
                    &payload_path,
                    retired.payload_bytes,
                    &retired.payload_sha256,
                )?);
            }
            // All surviving content has been validated before the first unlink.
            remove_file(&payload_path)?;
            files::sync_directory(&directory)?;
            remove_file(&metadata_path)?;
            files::sync_directory(&directory)?;
            fs::remove_dir(&directory)?; // never recurse into unknown content
            files::sync_directory(&self.root)?;
        }
        for sent in [true, false] {
            remove_file(&self.root.join(Self::name(number, sent)?))?;
        }
        files::sync_directory(&self.root)?;
        remove_file(&self.root.join(retired_name(number)))?;
        files::sync_directory(&self.root)
    }
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
