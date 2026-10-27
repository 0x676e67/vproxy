//! Offline, bounded preservation of exactly one selected ACME namespace. Cache
//! bytes include private account/pending keys; they are never serialized into
//! metadata or interpreted as consent to retry an unknown CA operation.

use std::{io, path::Path, sync::Arc};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{PlanOptions, storage::Cache};
use crate::manage::{files, store};

/// Presence is explicit, including an existing but empty cache. Names identify
/// retained committed or temporary files, not an elected recovery candidate.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Metadata {
    namespace: String,
    present: bool,
    names: Vec<String>,
}

pub(in crate::manage) struct Capture {
    pub(in crate::manage) metadata: Metadata,
    pub(in crate::manage) entries: Vec<(String, Zeroizing<Vec<u8>>)>,
}

/// Read without creating cache directories or constructing any ACME transport.
/// The supplied author must belong to this source; it excludes real workers
/// until their last guard owner, not merely their async waiter, has finished.
pub(in crate::manage) fn capture(
    directory: &Path,
    author: Arc<store::Guard>,
    origin: &str,
    options: &PlanOptions,
) -> io::Result<Capture> {
    author.ensure(directory)?;
    let namespace = namespace(origin, options)?;
    let cache = Cache::open_existing(directory, author, &namespace)?;
    let present = cache.is_some();
    let entries = cache
        .map(|cache| cache.snapshot_entries())
        .transpose()?
        .unwrap_or_default();
    let names = entries.iter().map(|(name, _)| name.clone()).collect();
    Ok(Capture {
        metadata: Metadata {
            namespace,
            present,
            names,
        },
        entries,
    })
}

/// Check presence, canonical namespace, bounded exact names and temporary-file
/// checksums. Account/order semantics and CA truth remain a separate recovery
/// review: a byte-perfect unknown newOrder response is not permission to replay.
pub(in crate::manage) fn verify(
    metadata: &Metadata,
    origin: &str,
    options: &PlanOptions,
    directory: &Path,
) -> io::Result<Vec<String>> {
    if metadata.namespace != namespace(origin, options)?
        || metadata.names.len() > 128
        || (!metadata.present && !metadata.names.is_empty())
        || metadata.names.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("invalid archived ACME namespace or inventory"));
    }
    for name in &metadata.names {
        Cache::check_snapshot_name(name)?;
        let bytes = files::read(&directory.join(format!("acme-{name}")), 256 * 1024, true)?;
        Cache::check_snapshot_entry(name, &bytes)?;
    }
    Ok(metadata.names.clone())
}

fn namespace(origin: &str, options: &PlanOptions) -> io::Result<String> {
    let configuration = options
        .options()
        .configure(origin)?
        .ok_or_else(|| invalid("an ACME snapshot must explicitly select ACME"))?;
    Ok(super::namespace(&configuration))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Synthetic bodies for file-only tests, not usable credentials or consent to
/// contact a CA. Return exact bytes so preservation is asserted, not just count.
#[cfg(test)]
pub(in crate::manage) fn seed_test_cache(
    directory: &Path,
    author: Arc<store::Guard>,
    origin: &str,
    options: &PlanOptions,
) -> io::Result<Vec<(String, Vec<u8>)>> {
    let cache = Cache::open(directory, author, &namespace(origin, options)?)?;
    cache.create("account.der", b"opaque test account material")?;
    cache.create(
        "order.json",
        br#"{"phase":"intent","test":"not a replay instruction"}"#,
    )?;
    cache.create_snapshot_temporary_for_test(
        "order.json",
        br#"{"phase":"ordered","test":"unresolved bytes"}"#,
    )?;
    Ok(cache
        .snapshot_entries()?
        .into_iter()
        .map(|(name, bytes)| (name, bytes.to_vec()))
        .collect())
}
