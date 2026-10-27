//! In-memory managed proxy admission. Complete policies are built off the data
//! plane; authentication never opens SQLite or runs a password KDF.

pub(crate) mod presets;
pub(crate) mod routing;
pub(crate) mod traffic;

#[cfg(feature = "witness-journal")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "Source runtime activation waits for complete writer admission"
    )
)]
pub(crate) mod suspension;

use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
    sync::{
        Arc, RwLock, Weak,
        atomic::{AtomicU32, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::ext::Extension;

pub(crate) const MAX_USERS: usize = 1_024;
pub(crate) const MAX_CREDENTIALS: usize = 8_192;

/// Application protocol permission. `Http` includes HTTP carried over TLS;
/// listener transport security remains a separate deployment setting.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Protocol {
    Http,
    Socks5,
    Masque,
}

/// Durable user facts required for admission, not administrator credentials.
#[derive(Clone)]
pub(crate) struct UserRecord {
    /// Persistent canonical 128-bit identity, never a display name or wire login.
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) active: bool,
    /// A soft-deleted user stays in durable history but cannot start new flows.
    pub(crate) deleted: bool,
    pub(crate) protocols: Vec<Protocol>,
    pub(crate) concurrent_limit: u32,
    /// This user's CAS revision, distinct from the whole policy revision.
    pub(crate) revision: u64,
}

/// Versioned high-entropy machine verifier. Deliberately neither `Debug` nor
/// `Serialize`: API projections must explicitly omit this digest.
#[derive(Clone)]
pub(crate) struct CredentialRecord {
    pub(crate) id: String,
    pub(crate) user_id: String,
    pub(crate) login: String,
    /// Version 2 chooses the strict grammar, never the legacy prefix parser.
    pub(crate) syntax_version: u8,
    /// Version 1 is the domain-separated generated-secret SHA-256 verifier.
    pub(crate) verifier_version: u8,
    pub(crate) secret_digest: [u8; 32],
    pub(crate) active: bool,
    pub(crate) revoked: bool,
    /// Secret rotation generation; enabling/disabling is not a new verifier.
    pub(crate) verifier_revision: u64,
}

/// A whole committed candidate. No partial mutation is published to readers.
#[derive(Clone)]
pub(crate) struct PolicyData {
    pub(crate) revision: u64,
    /// A committed node-wide pause rejects new operations, not existing leases.
    pub(crate) accepting: bool,
    pub(crate) users: Vec<UserRecord>,
    pub(crate) credentials: Vec<CredentialRecord>,
    pub(crate) routing: routing::RoutingData,
    pub(crate) presets: presets::PresetData,
}

/// Credential failure, policy denial and resource failure remain distinct at
/// protocol boundaries; no variant contains supplied credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    InvalidCredentials,
    Denied,
    Unavailable,
    Capacity,
}

/// Process-local managed operation ownership under one published policy.
/// Counters are sampled individually, not as an atomic multi-user total. Zero
/// does not prove that protocol drivers or transport buffers have flushed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Admission {
    pub(crate) revision: u64,
    pub(crate) accepting: bool,
    /// One count per admitted operation, independent of its lease clone count.
    pub(crate) active_operations: u64,
}

/// The complete publication identity and admission mode, sampled without
/// walking operation counters. A saved pause alone does not establish either.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionState {
    pub(crate) revision: u64,
    pub(crate) accepting: bool,
}

/// One admitted operation's routing intent and small lifetime handle. It does
/// not keep the policy snapshot or any credential verifier alive.
pub(crate) struct Authorization {
    pub(crate) extension: Extension,
    /// One explicitly authorized source, selected once before the flow starts.
    pub(crate) source: Option<IpAddr>,
    /// A copied, unresolved TCP choice; UDP/BIND authentication ignores defaults.
    pub(crate) presets: presets::Selection,
    pub(crate) lease: Arc<FlowLease>,
}

/// All clones represent the *same* admitted operation. The user count falls
/// only when its final owner (including both HTTP bodies) releases this lease.
pub(crate) struct FlowLease {
    /// Stable accounting owner, independent of renaming or credential rotation.
    pub(crate) user_id: Arc<str>,
    /// The exact admitted credential, without its login, secret or verifier.
    pub(crate) credential_id: Arc<str>,
    counter: Arc<Counter>,
    traffic: Arc<crate::traffic::Counter>,
    pool_traffic: Option<Arc<crate::traffic::Counter>>,
}

impl FlowLease {
    /// A direction-bound accepted-payload handle for this admitted credential
    /// and protocol. It survives policy replacement without retaining a secret.
    pub(crate) fn meter(&self, direction: crate::traffic::Direction) -> crate::traffic::Meter {
        crate::traffic::Meter::new(self.traffic.clone(), direction)
            .with_secondary(self.pool_traffic.clone())
    }
}

impl Drop for FlowLease {
    fn drop(&mut self) {
        self.counter.active.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Counter {
    active: AtomicU32,
}
struct User {
    record: UserRecord,
    id: Arc<str>,
    counter: Arc<Counter>,
}
struct Credential {
    record: CredentialRecord,
    id: Arc<str>,
    // Candidate compilation also serves validation, without allocating meters.
    // Every Reader entry point binds the complete candidate before publication.
    traffic: Option<[Arc<crate::traffic::Counter>; 3]>,
}
struct Policy {
    revision: u64,
    accepting: bool,
    users: HashMap<String, User>,
    credentials: HashMap<String, Credential>,
    routing: routing::Compiled,
    presets: presets::Compiled,
    pool_ids: Vec<Arc<str>>,
    pool_traffic: HashMap<String, [Arc<crate::traffic::Counter>; 3]>,
}
struct State {
    revision: u64,
    policy: Option<Policy>,
    // Weak history preserves a removed user's count while its flows are alive,
    // without retaining every obsolete policy or inactive identity forever.
    counters: HashMap<String, Weak<Counter>>,
    // Only the outstanding source publication owner can restore this policy.
    // Pointer identity avoids a wrapping generation or an ABA after fail_closed.
    #[cfg(feature = "witness-journal")]
    suspension: Option<Arc<()>>,
}

/// Cheap reader shared by every protocol and by the single publishing owner.
/// The short read guard covers verification and admission, never an `.await`.
#[derive(Clone)]
pub(crate) struct Reader {
    state: Arc<RwLock<State>>,
    traffic: Arc<traffic::Registry>,
}

impl Reader {
    /// Validate a full bounded policy before making the first reader available.
    #[cfg(test)]
    pub(crate) fn new(data: PolicyData) -> io::Result<Self> {
        Self::with_traffic(data, traffic::Registry::new(Vec::new())?)
    }

    /// Bind a validated policy to a strongly held, optionally restored registry.
    /// Invalid identities, ownership changes or capacity failures publish
    /// nothing and leave the caller's registry unchanged.
    pub(crate) fn with_traffic(
        data: PolicyData,
        traffic: Arc<traffic::Registry>,
    ) -> io::Result<Self> {
        let mut policy = compile(data)?;
        traffic.bind(&mut policy)?;
        let counters = policy
            .users
            .iter()
            .map(|(id, user)| (id.clone(), Arc::downgrade(&user.counter)))
            .collect();
        Ok(Self {
            state: Arc::new(RwLock::new(State {
                revision: policy.revision,
                policy: Some(policy),
                counters,
                #[cfg(feature = "witness-journal")]
                suspension: None,
            })),
            traffic,
        })
    }

    /// Return the bounded accounting owner, including inactive identities and
    /// accepted bytes whose final forwarding lease has already been dropped.
    pub(crate) fn traffic_registry(&self) -> Arc<traffic::Registry> {
        self.traffic.clone()
    }

    /// Atomically publish a validated, strictly newer revision. Stable user
    /// counters survive disable/delete/rotation and concurrent-limit changes.
    /// Invalid candidates leave the previous policy and revision untouched.
    pub(crate) fn publish(&self, data: PolicyData) -> io::Result<()> {
        let mut policy = compile(data)?;
        let mut state = self.state.write().map_err(|_| unavailable())?;
        #[cfg(feature = "witness-journal")]
        if state.suspension.is_some() {
            return Err(unavailable());
        }
        self.bind_publication(&mut state, &mut policy)?;
        state.revision = policy.revision;
        let previous = state.policy.replace(policy);
        drop(state);
        drop(previous);
        Ok(())
    }

    /// Bind a strictly newer candidate's stable counters under the caller's
    /// publication lock. The caller installs it before releasing that lock.
    fn bind_publication(&self, state: &mut State, policy: &mut Policy) -> io::Result<()> {
        if policy.revision <= state.revision {
            return Err(invalid("managed policy revision must increase"));
        }
        self.traffic.bind(policy)?;
        state
            .counters
            .retain(|_, counter| counter.strong_count() != 0);
        for (id, user) in &mut policy.users {
            if let Some(counter) = state.counters.get(id).and_then(Weak::upgrade) {
                user.counter = counter;
            }
            state
                .counters
                .insert(id.clone(), Arc::downgrade(&user.counter));
        }
        Ok(())
    }

    /// Last published revision; an unavailable policy never masquerades as 0.
    pub(crate) fn revision(&self) -> io::Result<u64> {
        let state = self.state.read().map_err(|_| unavailable())?;
        state
            .policy
            .as_ref()
            .map(|_| state.revision)
            .ok_or_else(unavailable)
    }

    /// Read the published revision and mode under one short guard. Unavailable
    /// or poisoned policy returns an error, never an accepting/paused default.
    pub(crate) fn admission_state(&self) -> io::Result<AdmissionState> {
        let state = self.state.read().map_err(|_| unavailable())?;
        let policy = state.policy.as_ref().ok_or_else(unavailable)?;
        Ok(AdmissionState {
            revision: policy.revision,
            accepting: policy.accepting,
        })
    }

    /// Sample the published revision, admission mode and retained operation
    /// counters under the existing policy read guard. Removed users remain
    /// included while any old lease owns their counter; expired weak entries
    /// contribute zero. Poison, unavailable policy or overflow return an error,
    /// never a fabricated zero. This cold observation adds no forwarding work.
    pub(crate) fn admission(&self) -> io::Result<Admission> {
        let state = self.state.read().map_err(|_| unavailable())?;
        let policy = state.policy.as_ref().ok_or_else(unavailable)?;
        let active_operations = state.counters.values().try_fold(0_u64, |total, counter| {
            let active = counter
                .upgrade()
                .map_or(0, |counter| counter.active.load(Ordering::Relaxed));
            total.checked_add(u64::from(active)).ok_or_else(unavailable)
        })?;
        Ok(Admission {
            revision: policy.revision,
            accepting: policy.accepting,
            active_operations,
        })
    }

    /// Reject new admissions after a committed activation cannot be represented.
    /// Existing flows keep their lease; a newer validated publication can recover.
    pub(crate) fn fail_closed(&self) {
        if let Ok(mut state) = self.state.write() {
            #[cfg(feature = "witness-journal")]
            {
                state.suspension = None;
            }
            let previous = state.policy.take();
            drop(state);
            drop(previous);
        }
    }

    /// Verify one bounded v2 machine credential and reserve one user slot.
    /// Invalid secrets are rejected before revealing admission or user policy.
    /// A committed pause returns Unavailable before reserving a slot. Lowering
    /// a limit does not evict existing flows or reset their count.
    pub(crate) fn authenticate(
        &self,
        username: &str,
        secret: &[u8],
        protocol: Protocol,
    ) -> Result<Authorization, Error> {
        let state = self.state.read().map_err(|_| Error::Unavailable)?;
        let policy = state.policy.as_ref().ok_or(Error::Unavailable)?;
        if username.len() > 255 || !valid_secret(secret) {
            return Err(Error::InvalidCredentials);
        }
        let (login, suffix) = username.split_once('-').unwrap_or((username, ""));
        let credential = policy
            .credentials
            .get(login)
            .ok_or(Error::InvalidCredentials)?;
        let digest = digest_secret(&credential.record.id, secret);
        if !bool::from(digest.ct_eq(&credential.record.secret_digest)) {
            return Err(Error::InvalidCredentials);
        }
        if !policy.accepting {
            return Err(Error::Unavailable);
        }
        let user = policy
            .users
            .get(&credential.record.user_id)
            .ok_or(Error::Unavailable)?;
        if !credential.record.active
            || credential.record.revoked
            || !user.record.active
            || user.record.deleted
            || !user.record.protocols.contains(&protocol)
        {
            return Err(Error::Denied);
        }
        if suffix.is_empty() && username.len() != login.len() {
            return Err(Error::Denied);
        }
        let (requested, suffix) = presets::split(suffix)?;
        let selection = policy.routing.source(&user.record.id, suffix)?;
        let presets = policy
            .presets
            .select(&user.record.id, selection.pool_id, requested)?;
        let source = selection.source;
        let pool_traffic = selection
            .pool_id
            .map(|id| {
                policy
                    .pool_traffic
                    .get(id)
                    .map(|values| values[traffic::protocol_index(protocol)].clone())
                    .ok_or(Error::Unavailable)
            })
            .transpose()?;
        let extension = if source.is_some() {
            Extension::None
        } else {
            extension(suffix, &user.record.id, &credential.record.id)?
        };
        let traffic = credential.traffic.as_ref().ok_or(Error::Unavailable)?
            [traffic::protocol_index(protocol)]
        .clone();
        let counter = &user.counter.active;
        // Only a numeric budget is synchronized here. Policy publication is
        // already ordered by the guard; no payload memory relies on this CAS.
        // Validation bounds the limit to 1_000_000, so adding below it is safe.
        counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                (active < user.record.concurrent_limit).then(|| active + 1)
            })
            .map_err(|_| Error::Capacity)?;
        Ok(Authorization {
            extension,
            source,
            presets,
            lease: Arc::new(FlowLease {
                user_id: user.id.clone(),
                credential_id: credential.id.clone(),
                counter: user.counter.clone(),
                traffic,
                pool_traffic,
            }),
        })
    }
}

/// Version 1 domain-separated SHA-256 for a generated 256-bit secret's canonical
/// 43-byte base64url text. This is not a verifier for human-chosen passwords.
pub(crate) fn digest_secret(credential_id: &str, secret: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"vproxy.machine-secret.v1\0");
    hash.update((credential_id.len() as u64).to_be_bytes());
    hash.update(credential_id.as_bytes());
    hash.update(secret);
    hash.finalize().into()
}

/// Apply exactly the reader's complete validation before a durable transaction
/// commits. This cold-path check does not publish or alter admission counters.
pub(crate) fn validate_policy(data: &PolicyData) -> io::Result<()> {
    compile(data.clone()).map(|_| ())
}

fn compile(data: PolicyData) -> io::Result<Policy> {
    if !valid_revision(data.revision)
        || data.users.len() > MAX_USERS
        || data.credentials.len() > MAX_CREDENTIALS
    {
        return Err(invalid(
            "managed policy exceeds its revision or capacity bounds",
        ));
    }
    let mut users = HashMap::with_capacity(data.users.len());
    for record in data.users {
        if !valid_id(&record.id)
            || !valid_name(&record.name)
            || !valid_revision(record.revision)
            || !(1..=1_000_000).contains(&record.concurrent_limit)
            || record.protocols.len() > 3
            || record.protocols.iter().collect::<HashSet<_>>().len() != record.protocols.len()
        {
            return Err(invalid("invalid managed proxy user"));
        }
        let id: Arc<str> = Arc::from(record.id.as_str());
        let key = record.id.clone();
        if users
            .insert(
                key,
                User {
                    record,
                    id,
                    counter: Arc::new(Counter {
                        active: AtomicU32::new(0),
                    }),
                },
            )
            .is_some()
        {
            return Err(invalid("duplicate managed proxy user"));
        }
    }
    let mut credentials = HashMap::with_capacity(data.credentials.len());
    let mut ids = HashSet::with_capacity(data.credentials.len());
    for record in data.credentials {
        if !valid_id(&record.id)
            || !ids.insert(record.id.clone())
            || !users.contains_key(&record.user_id)
            || !valid_login(&record.login)
            || record.syntax_version != 2
            || record.verifier_version != 1
            || !valid_revision(record.verifier_revision)
        {
            return Err(invalid("invalid managed proxy credential"));
        }
        let id = Arc::from(record.id.as_str());
        let login = record.login.clone();
        if credentials
            .insert(
                login,
                Credential {
                    record,
                    id,
                    traffic: None,
                },
            )
            .is_some()
        {
            return Err(invalid("duplicate managed proxy login"));
        }
    }
    let pool_ids = data
        .routing
        .pools
        .iter()
        .map(|pool| Arc::from(pool.id.as_str()))
        .collect();
    let presets = presets::compile(
        data.presets,
        &users.keys().map(String::as_str).collect::<HashSet<_>>(),
        &data
            .routing
            .pools
            .iter()
            .map(|pool| pool.id.as_str())
            .collect::<HashSet<_>>(),
    )?;
    let routing = routing::compile(
        data.routing,
        &users.keys().map(String::as_str).collect::<HashSet<_>>(),
        data.revision,
    )?;
    Ok(Policy {
        revision: data.revision,
        accepting: data.accepting,
        users,
        credentials,
        routing,
        presets,
        pool_ids,
        pool_traffic: HashMap::new(),
    })
}

fn valid_revision(revision: u64) -> bool {
    (1..=i64::MAX as u64).contains(&revision)
}
fn valid_id(value: &str) -> bool {
    let mut bytes = [0; 16];
    value.len() == 22
        && URL_SAFE_NO_PAD
            .decode_slice(value, &mut bytes)
            .is_ok_and(|length| length == bytes.len())
}
fn valid_login(login: &str) -> bool {
    login.len() == 36
        && login.strip_prefix("vp2_").is_some_and(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.trim() == name
        && !name.chars().any(char::is_control)
}
fn valid_secret(secret: &[u8]) -> bool {
    let mut bytes = [0; 32];
    secret.len() == 43
        && URL_SAFE_NO_PAD
            .decode_slice(secret, &mut bytes)
            .is_ok_and(|length| length == bytes.len())
}

/// V2 has exactly one extension. `-` is a delimiter, not part of a value; this
/// deliberately does not reinterpret legacy session strings. A validated
/// leading device has already been removed without changing these route bytes.
fn extension(suffix: &str, user: &str, credential: &str) -> Result<Extension, Error> {
    if suffix.is_empty() {
        return Ok(Extension::None);
    }
    let (kind, value) = suffix.split_once('-').ok_or(Error::Denied)?;
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(Error::Denied);
    }
    let mut hash = Sha256::new();
    hash.update(b"vproxy.route.v2\0");
    hash.update(user.as_bytes());
    hash.update(credential.as_bytes());
    hash.update(kind.as_bytes());
    match kind {
        "session" | "range" => hash.update(value.as_bytes()),
        "ttl" => {
            let ttl = value.parse::<u64>().map_err(|_| Error::Denied)?;
            if ttl == 0 || value.starts_with('0') {
                return Err(Error::Denied);
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Unavailable)?
                .as_secs();
            hash.update(ttl.to_be_bytes());
            hash.update((now - now % ttl).to_be_bytes());
        }
        _ => return Err(Error::Denied),
    }
    let digest = hash.finalize();
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&digest[..8]);
    let value = u64::from_be_bytes(bytes);
    Ok(match kind {
        "session" => Extension::Session(value),
        "range" => Extension::Range(value),
        _ => Extension::TTL(value),
    })
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn unavailable() -> io::Error {
    io::Error::other("managed access policy is unavailable")
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    const USER: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    const CREDENTIAL: &str = "AgICAgICAgICAgICAgICAg";
    pub(crate) const LOGIN: &str = "vp2_02020202020202020202020202020202";
    pub(crate) const ROUTED_LOGIN: &str =
        "vp2_02020202020202020202020202020202-exit-14141414141414141414141414141414";

    /// Common protocol fixture: legacy routes are forbidden, so a handler that
    /// loses the authorized source cannot accidentally pass via default routing.
    pub(crate) fn routed_policy(revision: u64, limit: u32) -> PolicyData {
        let mut policy = policy(revision, limit);
        let id = URL_SAFE_NO_PAD.encode([20; 16]);
        policy.routing.addresses.push(routing::AddressRecord {
            id: id.clone(),
            name: "Owned loopback".into(),
            ip: "127.0.0.2".parse().unwrap(),
            prefix_id: None,
            state: routing::ResourceState::Active,
            revision,
        });
        policy.routing.permissions[0].legacy_allowed = false;
        policy.routing.permissions[0].exits.push(id);
        policy
    }

    pub(crate) fn secret() -> Vec<u8> {
        URL_SAFE_NO_PAD.encode([7; 32]).into_bytes()
    }
    pub(crate) fn policy(revision: u64, limit: u32) -> PolicyData {
        PolicyData {
            revision,
            accepting: true,
            presets: presets::PresetData::native([USER.into()], []),
            routing: routing::RoutingData {
                permissions: vec![routing::RoutePermission::legacy(USER.into())],
                ..Default::default()
            },
            users: vec![UserRecord {
                id: USER.into(),
                name: "Proxy user".into(),
                active: true,
                deleted: false,
                protocols: vec![Protocol::Http, Protocol::Socks5, Protocol::Masque],
                concurrent_limit: limit,
                revision,
            }],
            credentials: vec![CredentialRecord {
                id: CREDENTIAL.into(),
                user_id: USER.into(),
                login: LOGIN.into(),
                syntax_version: 2,
                verifier_version: 1,
                secret_digest: digest_secret(CREDENTIAL, &secret()),
                active: true,
                revoked: false,
                verifier_revision: 1,
            }],
        }
    }
    fn attempt(
        reader: &Reader,
        username: &str,
        protocol: Protocol,
    ) -> Result<Authorization, Error> {
        reader.authenticate(username, &secret(), protocol)
    }

    #[test]
    fn managed_device_is_leading_authorized_and_keeps_route_hashes_exact() {
        let mut data = policy(1, 32);
        data.presets.users[0].allowed_presets =
            vec![crate::ebpf::Profile::Linux, crate::ebpf::Profile::Windows];
        data.presets.users[0].default_preset = Some(crate::ebpf::Profile::Linux);
        let reader = Reader::new(data).unwrap();
        for suffix in ["session-same", "range-same", "ttl-18446744073709551615"] {
            let native = attempt(&reader, &format!("{LOGIN}-{suffix}"), Protocol::Socks5).unwrap();
            let selected = attempt(
                &reader,
                &format!("{LOGIN}-device-windows-{suffix}"),
                Protocol::Socks5,
            )
            .unwrap();
            assert_eq!(native.extension.route(), selected.extension.route());
            assert!(
                selected.extension.profile().is_none(),
                "managed routing must not smuggle an unchecked preset"
            );
            assert_eq!(
                selected.presets.tcp(),
                Ok(Some(crate::ebpf::Profile::Windows))
            );
            assert!(selected.presets.explicit());
            assert!(!native.presets.explicit());
        }
        let default = attempt(&reader, LOGIN, Protocol::Socks5).unwrap();
        assert_eq!(default.presets.tcp(), Ok(Some(crate::ebpf::Profile::Linux)));
        assert!(!default.presets.explicit());
        for suffix in [
            "device-ios",
            "device-native",
            "device-windows-device-linux",
            "session-same-device-windows",
            "device-windows-session-a-range-b",
            "device-windows-",
            "device-Windows",
        ] {
            assert!(matches!(
                attempt(&reader, &format!("{LOGIN}-{suffix}"), Protocol::Socks5),
                Err(Error::Denied)
            ));
        }
    }

    #[test]
    fn strict_v2_syntax_has_exact_login_boundaries_and_isolates_routing() {
        let reader = Reader::new(policy(1, 10)).unwrap();
        assert!(matches!(
            attempt(&reader, LOGIN, Protocol::Http).unwrap().extension,
            Extension::None
        ));
        for suffix in ["session-same", "range-same", "ttl-60"] {
            assert!(attempt(&reader, &format!("{LOGIN}-{suffix}"), Protocol::Http).is_ok());
        }
        for suffix in [
            "",
            "session-",
            "session-a-b",
            "session-a-range-b",
            "range-a-session-b",
            "ttl-0",
            "ttl-01",
            "ttl-18446744073709551616",
            "device-ios",
            "pool-any",
            "session-中文",
            "session-a.b",
        ] {
            assert!(
                matches!(
                    attempt(&reader, &format!("{LOGIN}-{suffix}"), Protocol::Http),
                    Err(Error::Denied)
                ),
                "suffix={suffix}"
            );
        }
        for username in [
            format!("{LOGIN}x"),
            format!("x{LOGIN}"),
            "legacy-session-any".into(),
        ] {
            assert!(matches!(
                attempt(&reader, &username, Protocol::Http),
                Err(Error::InvalidCredentials)
            ));
        }
        let first = attempt(&reader, &format!("{LOGIN}-session-same"), Protocol::Http).unwrap();
        let again = attempt(&reader, &format!("{LOGIN}-session-same"), Protocol::Socks5).unwrap();
        assert!(
            matches!((first.extension, again.extension), (Extension::Session(a), Extension::Session(b)) if a == b)
        );
        let mut candidate = policy(2, 10);
        candidate.credentials[0].id = URL_SAFE_NO_PAD.encode([3; 16]);
        candidate.credentials[0].secret_digest =
            digest_secret(&candidate.credentials[0].id, &secret());
        reader.publish(candidate).unwrap();
        let rotated = attempt(&reader, &format!("{LOGIN}-session-same"), Protocol::Http).unwrap();
        assert!(
            matches!((first.extension, rotated.extension), (Extension::Session(a), Extension::Session(b)) if a != b)
        );
        let mut other_user = policy(3, 10);
        other_user.users[0].id = URL_SAFE_NO_PAD.encode([8; 16]);
        other_user.credentials[0].user_id = other_user.users[0].id.clone();
        other_user.routing.permissions[0].user_id = other_user.users[0].id.clone();
        other_user.presets.users[0].user_id = other_user.users[0].id.clone();
        // One node cannot reassign a retained accounting credential to a new user.
        // A separate catalog still proves that the routing hash includes its user,
        // even when the credential's identifier and secret happen to be identical.
        assert!(reader.publish(other_user.clone()).is_err());
        let other_reader = Reader::new(other_user).unwrap();
        let isolated = attempt(
            &other_reader,
            &format!("{LOGIN}-session-same"),
            Protocol::Http,
        )
        .unwrap();
        assert!(
            matches!((first.extension, isolated.extension), (Extension::Session(a), Extension::Session(b)) if a != b)
        );
        assert_ne!(
            digest_secret(CREDENTIAL, &secret()),
            digest_secret(USER, &secret())
        );
    }

    #[test]
    fn secret_precedes_policy_denial_and_no_failure_downgrades_authentication() {
        let mut data = policy(1, 1);
        data.users[0].active = false;
        let reader = Reader::new(data).unwrap();
        assert!(matches!(
            reader.authenticate(LOGIN, b"wrong", Protocol::Http),
            Err(Error::InvalidCredentials)
        ));
        assert!(matches!(
            reader.authenticate(
                LOGIN,
                URL_SAFE_NO_PAD.encode([9; 32]).as_bytes(),
                Protocol::Http
            ),
            Err(Error::InvalidCredentials)
        ));
        assert!(matches!(
            attempt(&reader, LOGIN, Protocol::Http),
            Err(Error::Denied)
        ));
        let mut data = policy(2, 1);
        data.users[0].protocols = vec![Protocol::Socks5];
        reader.publish(data).unwrap();
        assert!(matches!(
            attempt(&reader, LOGIN, Protocol::Http),
            Err(Error::Denied)
        ));
        assert!(attempt(&reader, LOGIN, Protocol::Socks5).is_ok());
        reader.fail_closed();
        assert!(reader.revision().is_err());
        assert!(matches!(
            attempt(&reader, LOGIN, Protocol::Socks5),
            Err(Error::Unavailable)
        ));
        reader.publish(policy(3, 1)).unwrap();
        assert!(attempt(&reader, LOGIN, Protocol::Http).is_ok());
    }

    #[test]
    fn shared_lease_and_hot_revisions_never_reset_the_user_count() {
        let reader = Reader::new(policy(1, 2)).unwrap();
        let first = attempt(&reader, LOGIN, Protocol::Http).unwrap();
        let second = attempt(&reader, LOGIN, Protocol::Masque).unwrap();
        assert_eq!(&*first.lease.user_id, USER);
        assert_eq!(&*first.lease.credential_id, CREDENTIAL);
        let retained = first.lease.clone();
        drop(first);
        reader.publish(policy(2, 1)).unwrap();
        assert!(matches!(
            attempt(&reader, LOGIN, Protocol::Socks5),
            Err(Error::Capacity)
        ));
        drop(second);
        assert!(matches!(
            attempt(&reader, LOGIN, Protocol::Socks5),
            Err(Error::Capacity)
        ));
        // Removing/reintroducing a user while an old flow lives must preserve its
        // count, even though the active policy no longer owns the counter.
        reader
            .publish(PolicyData {
                revision: 3,
                accepting: true,
                users: vec![],
                credentials: vec![],
                routing: routing::RoutingData::default(),
                presets: presets::PresetData::default(),
            })
            .unwrap();
        reader.publish(policy(4, 1)).unwrap();
        assert!(matches!(
            attempt(&reader, LOGIN, Protocol::Http),
            Err(Error::Capacity)
        ));
        drop(retained);
        assert!(attempt(&reader, LOGIN, Protocol::Http).is_ok());
    }

    #[test]
    fn published_pause_rejects_new_operations_but_keeps_old_leases_across_revisions() {
        let reader = Reader::new(policy(1, 4)).unwrap();
        let first = attempt(&reader, LOGIN, Protocol::Http).unwrap();
        let second = attempt(&reader, LOGIN, Protocol::Socks5).unwrap();
        let third = attempt(&reader, LOGIN, Protocol::Masque).unwrap();
        let retained = first.lease.clone();
        drop(first);
        let mut paused = policy(2, 1);
        paused.accepting = false;
        reader.publish(paused).unwrap();
        let expected = Admission {
            revision: 2,
            accepting: false,
            active_operations: 3,
        };
        assert_eq!(reader.admission().unwrap(), expected);
        let wrong_secret = URL_SAFE_NO_PAD.encode([9; 32]);
        for protocol in [Protocol::Http, Protocol::Socks5, Protocol::Masque] {
            assert!(matches!(
                attempt(&reader, LOGIN, protocol),
                Err(Error::Unavailable)
            ));
            for invalid in [b"wrong".as_slice(), wrong_secret.as_bytes()] {
                assert!(matches!(
                    reader.authenticate(LOGIN, invalid, protocol),
                    Err(Error::InvalidCredentials)
                ));
            }
        }
        assert_eq!(reader.admission().unwrap(), expected);
        // A pause changes admission only: the original accounting owner remains
        // usable and no new policy lookup or new slot is needed to record a write.
        retained.meter(crate::traffic::Direction::Upload).add(7);
        assert_eq!(
            reader
                .traffic_registry()
                .snapshot()
                .unwrap()
                .into_iter()
                .find(|row| row.protocol == Protocol::Http)
                .unwrap()
                .value
                .upload,
            7
        );
        let mut disabled = policy(3, 1);
        disabled.accepting = false;
        disabled.users[0].active = false;
        disabled.credentials[0].revoked = true;
        reader.publish(disabled).unwrap();
        assert_eq!(reader.admission().unwrap().active_operations, 3);
        let mut removed = policy(4, 1);
        removed.accepting = false;
        removed.users.clear();
        removed.credentials.clear();
        removed.routing = routing::RoutingData::default();
        removed.presets = presets::PresetData::default();
        reader.publish(removed).unwrap();
        assert_eq!(
            reader.admission().unwrap(),
            Admission {
                revision: 4,
                accepting: false,
                active_operations: 3,
            }
        );
        reader.publish(policy(5, 4)).unwrap();
        let resumed = attempt(&reader, LOGIN, Protocol::Http).unwrap();
        assert_eq!(
            reader.admission().unwrap(),
            Admission {
                revision: 5,
                accepting: true,
                active_operations: 4,
            }
        );
        drop((second, third, retained, resumed));
        assert_eq!(reader.admission().unwrap().active_operations, 0);
    }

    #[test]
    fn unavailable_admission_is_not_zero_and_recovery_publishes_the_complete_mode() {
        let reader = Reader::new(policy(1, 1)).unwrap();
        assert_eq!(
            reader.admission_state().unwrap(),
            AdmissionState {
                revision: 1,
                accepting: true
            }
        );
        let retained = attempt(&reader, LOGIN, Protocol::Http).unwrap();
        reader.fail_closed();
        assert!(reader.admission().is_err());
        assert!(reader.admission_state().is_err());
        let mut paused = policy(2, 1);
        paused.accepting = false;
        reader.publish(paused).unwrap();
        assert_eq!(
            reader.admission_state().unwrap(),
            AdmissionState {
                revision: 2,
                accepting: false
            }
        );
        assert_eq!(
            reader.admission().unwrap(),
            Admission {
                revision: 2,
                accepting: false,
                active_operations: 1,
            }
        );
        drop(retained);
        assert_eq!(reader.admission().unwrap().active_operations, 0);
        assert!(matches!(
            attempt(&reader, LOGIN, Protocol::Http),
            Err(Error::Unavailable)
        ));
        let state = reader.state.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = state.write().unwrap();
                panic!("poison the isolated admission fixture");
            })
            .join()
            .is_err()
        );
        assert!(reader.admission().is_err());
        assert!(reader.admission_state().is_err());
        assert!(matches!(
            attempt(&reader, LOGIN, Protocol::Http),
            Err(Error::Unavailable)
        ));
    }

    #[test]
    fn concurrent_admission_is_a_single_cas_budget() {
        let reader = Reader::new(policy(1, 1)).unwrap();
        let start = Arc::new(Barrier::new(9));
        let finish = Arc::new(Barrier::new(9));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let reader = reader.clone();
            let start = start.clone();
            let finish = finish.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                let admission = attempt(&reader, LOGIN, Protocol::Http);
                let success = admission.is_ok();
                finish.wait();
                drop(admission);
                success
            }));
        }
        start.wait();
        finish.wait();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|success| *success)
                .count(),
            1
        );
        assert!(attempt(&reader, LOGIN, Protocol::Http).is_ok());
    }

    #[test]
    fn candidate_errors_leave_the_previous_revision_and_admission_intact() {
        let reader = Reader::new(policy(1, 2)).unwrap();
        for mut data in [policy(1, 1), policy(2, 0), policy(2, 1)] {
            if data.revision == 2 && data.users[0].concurrent_limit == 1 {
                data.credentials[0].syntax_version = 1;
            }
            assert!(reader.publish(data).is_err());
            assert_eq!(reader.revision().unwrap(), 1);
        }
        let mut duplicate = policy(2, 1);
        duplicate.credentials.push(duplicate.credentials[0].clone());
        assert!(validate_policy(&duplicate).is_err());
        let mut orphan = policy(2, 1);
        orphan.credentials[0].user_id = URL_SAFE_NO_PAD.encode([8; 16]);
        assert!(validate_policy(&orphan).is_err());
        assert!(attempt(&reader, LOGIN, Protocol::Http).is_ok());
    }
}
