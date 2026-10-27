//! Built-in outbound TCP profiles and the optional Linux eBPF backend.
//!
//! Profile values are kept in this module instead of command-line options. The
//! socket path gives the host kernel every setting it can express, while the
//! Linux TC program validates the kernel's negotiated transport state and then
//! normalizes compatible initial SYNs on configured egress interfaces.

use std::{fmt, io, str::FromStr};

use tokio::net::TcpSocket;

// Userspace and the eBPF program deliberately exchange an octet array instead
// of a Rust struct. Kernel and host builds can have different endianness and
// alignment, whereas this fixed layout is stable and already implements
// `aya::Pod` without an unsafe impl. The first 12 bytes are scalar metadata and
// the remaining 40 bytes are the largest TCP option area allowed by the
// four-bit TCP Data Offset field (RFC 9293 section 3.1).
const PROFILE_VALUE_LEN: usize = 52;
const TCP_OPTIONS_LEN: usize = 40;
const INVALID_OPTION_OFFSET: u8 = u8::MAX;

// Byte 7 of the encoded map value is a bit field. These constants are part of
// the private userspace-to-eBPF ABI and must stay in sync with
// `src/bin/vproxy-ebpf.rs`.
const PROFILE_FLAG_IPV4_DF: u8 = 1 << 0;
const PROFILE_FLAG_TCP_TIMESTAMPS: u8 = 1 << 1;
const PROFILE_FLAG_DERIVE_IPV4_ID: u8 = 1 << 2;
const TCP_OPTION_END: u8 = 0;
const TCP_OPTION_NOP: u8 = 1;
const TCP_OPTION_MSS: u8 = 2;
const TCP_OPTION_MSS_LEN: u8 = 4;
const TCP_OPTION_WINDOW_SCALE: u8 = 3;
const TCP_OPTION_WINDOW_SCALE_LEN: u8 = 3;
const TCP_OPTION_SACK_PERMITTED: u8 = 4;
const TCP_OPTION_SACK_PERMITTED_LEN: u8 = 2;
const TCP_OPTION_TIMESTAMP: u8 = 8;
const TCP_OPTION_TIMESTAMP_LEN: u8 = 10;

/// Endian-neutral value stored in `SOCKET_PROFILES`, indexed by socket cookie.
type EncodedProfile = [u8; PROFILE_VALUE_LEN];

/// Default number of profiled connect attempts that can be registered at once.
///
/// One entry remains present for the whole `connect(2)` attempt, including
/// initial-SYN retransmissions, and is released after success, error, timeout,
/// or cancellation.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub(crate) const DEFAULT_MAP_CAPACITY: u32 = 65_536;

/// Oldest supported kernel, based on the audited predecessor's verifier load,
/// legacy attachment, traffic and cleanup evidence. A new compiler or object
/// still requires real load/traffic validation; host tests cannot prove it.
///
/// Bounded loops existed earlier, but that feature boundary does not guarantee
/// that an older verifier accepts LLVM's complete output.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub(crate) const MINIMUM_KERNEL_VERSION: aya::util::KernelVersion =
    aya::util::KernelVersion::new(6, 1, 0);

#[cfg(all(target_os = "linux", feature = "ebpf"))]
/// Userspace ownership for the embedded program, cookie map, TC/TCX links, and
/// legacy-TC process locks. Packet parsing and mutation live in the second bin.
mod linux {
    use super::{EncodedProfile, MINIMUM_KERNEL_VERSION, PROFILE_VALUE_LEN};
    use std::{
        fs::{DirBuilder, File, OpenOptions},
        io,
        num::{NonZeroU32, NonZeroU64},
        os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
        path::Path,
        sync::{Arc, Mutex, MutexGuard},
    };

    use aya::{
        Ebpf, EbpfLoader,
        maps::{HashMap, IterableMap, MapData, MapType},
        programs::{
            LinkOrder, ProgramError, SchedClassifier, TcAttachType,
            tc::{NlOptions, SchedClassifierLink, TcAttachOptions, TcHandle},
        },
        util::KernelVersion,
    };
    use rustix::{
        fs::{FlockOperation, flock},
        process::geteuid,
    };
    use socket2::SockRef;
    use tokio::net::TcpSocket;

    // These names are exported by the embedded ELF object and form the loader
    // contract with `src/bin/vproxy-ebpf.rs`.
    const SOCKET_PROFILES_MAP: &str = "SOCKET_PROFILES";
    const PROGRAM_NAME: &str = "apply_profile";
    static PROGRAM: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/vproxy-ebpf"));

    // Kernel BPF map flags are duplicated here because Aya's high-level insert
    // API accepts their numeric form. NOEXIST makes registration collision-safe.
    // NO_PREALLOC also satisfies Aya HashMap::get's safety contract: removing a
    // preallocated element may let another key alias the borrowed value while
    // the BPF invocation is still reading it. Exact flag validation below must
    // therefore remain coupled to `registered_profile`'s unsafe lookup.
    // https://docs.rs/aya-ebpf/0.2.1/aya_ebpf/maps/struct.HashMap.html#method.get
    const BPF_NOEXIST: u64 = 1;
    const BPF_F_NO_PREALLOC: u32 = 1;

    // Legacy TC lacks TCX's link-fd ownership. vproxy uses this fixed classifier
    // tuple and protects it with a process-lifetime advisory lock. The tuple is
    // a vproxy convention, not a kernel reservation; explicit replacement can
    // therefore take over an unrelated filter at the same priority and handle.
    const LEGACY_LOCK_DIRECTORY: &str = "/run/vproxy";
    const LEGACY_TC_PRIORITY: u16 = 49_152;
    const LEGACY_TC_HANDLE: TcHandle = TcHandle::new(0, 1);

    /// Loaded classifier, its per-socket profile map, and attachment resources.
    ///
    /// One engine is shared by every connector. Keeping the `Ebpf` owner here
    /// ties all TC/TCX links to the server lifetime, while the mutex serializes
    /// map syscalls made by concurrent outbound connection attempts.
    pub(super) struct Engine {
        /// Userspace handle for the cookie-to-profile BPF hash map.
        profiles: Mutex<HashMap<MapData, u64, EncodedProfile>>,
        /// `true` for netlink-managed clsact TC; `false` for link-based TCX.
        legacy_tc: bool,
        /// Owns the loaded program and every link created during this load.
        ///
        /// Closing a TCX link fd deterministically detaches that link. Legacy TC
        /// instead asks netlink to detach during `Drop`; Aya cannot report a
        /// failure from that destructor, and process abort/crash skips Rust
        /// destructors entirely. A legacy filter explicitly replaced at the
        /// fixed tuple also cannot be reconstructed by dropping this object.
        ///
        /// This field must remain before `_legacy_interface_locks`: Rust drops
        /// struct fields in declaration order, so the netlink detach attempt
        /// must run while the process still owns every interface lock.
        _ebpf: Ebpf,
        /// Advisory lock held for each network-namespace/interface pair.
        ///
        /// These descriptors coordinate vproxy processes that resolve the same
        /// `/run/vproxy` lock inode. A process in a separate mount namespace can
        /// resolve another inode and is therefore outside this userspace lock.
        /// Keep this field after `_ebpf`; see that field's drop-order contract.
        _legacy_interface_locks: Vec<File>,
    }

    /// RAII ownership of one `SOCKET_PROFILES` entry.
    ///
    /// The cookie is inserted before `connect(2)` can emit a SYN. Dropping this
    /// value attempts to remove the entry on success, error, timeout, or future
    /// cancellation. If removal fails, `BPF_NOEXIST` prevents a later
    /// registration from silently overwriting the stale cookie key.
    pub(super) struct Registration {
        /// Nonzero `SO_COOKIE` value used as the BPF hash-map key.
        cookie: NonZeroU64,
        /// Keeps the program/map alive and provides map access during `drop`.
        engine: Arc<Engine>,
    }

    /// Operator-controlled Linux attachment settings.
    ///
    /// Profile contents are intentionally absent: clients select one of the
    /// audited built-ins through authentication metadata, while these fields
    /// only control where and how the packet program is attached.
    pub(crate) struct Config<'a> {
        /// Ethernet egress interfaces on which initial SYNs can be observed.
        pub(crate) interfaces: &'a [String],
        /// Explicit opt-in to netlink TC on kernels without TCX support.
        pub(crate) allow_legacy_tc: bool,
        /// Whether vproxy may replace whatever occupies its fixed legacy-TC
        /// priority/handle tuple. The kernel does not reserve that tuple.
        pub(crate) replace_stale_legacy_tc: bool,
        /// Maximum profiled connect attempts retained in the cookie map at once,
        /// including attempts waiting through initial-SYN retransmissions.
        pub(crate) map_capacity: u32,
    }

    impl Engine {
        /// Loads, validates, and attaches the embedded classifier.
        ///
        /// TCX is preferred because its link file descriptor gives the process
        /// unambiguous attachment ownership. Older kernels use legacy clsact TC
        /// only after explicit opt-in and acquire per-netns/interface advisory
        /// locks before loading. Kernel version selects one mode; a TCX attach
        /// failure on Linux 6.6 or newer does not fall back to legacy TC. Closing
        /// a partially created TCX link detaches it. Legacy cleanup is a best-
        /// effort netlink operation whose destructor cannot return an error.
        /// Legacy replacement is not a transaction: a filter taken over at the
        /// fixed tuple cannot be reconstructed if a subsequent attach fails.
        pub(super) fn load(config: Config<'_>) -> io::Result<Arc<Self>> {
            validate_config(&config)?;

            let kernel = KernelVersion::current()
                .map_err(|error| other_error("read the Linux kernel version", error))?;
            // The generated object contains verifier-bounded loops. Linux added
            // that capability in 5.3, but older verifiers can reject otherwise
            // valid LLVM output differently. Linux 6.1 is the oldest release on
            // which the audited predecessor passed load, legacy attach, and traffic
            // tests, so accepting an older kernel would publish an unverified
            // compatibility promise.
            // https://git.kernel.org/torvalds/c/94079b64255f
            if kernel < MINIMUM_KERNEL_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "eBPF profiles require Linux 6.1 or newer",
                ));
            }
            let legacy_tc = kernel < KernelVersion::new(6, 6, 0);
            if legacy_tc && !config.allow_legacy_tc {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "this kernel needs legacy TC; configure clsact and pass \
                     --ebpf-allow-legacy-tc to opt in",
                ));
            }
            // This local must be created before `ebpf` below. Locals drop in
            // reverse declaration order, so every early-return path attempts
            // legacy netlink detach before releasing the coordinating locks.
            let legacy_interface_locks = if legacy_tc {
                acquire_legacy_interface_locks(config.interfaces)?
            } else {
                Vec::new()
            };

            let mut loader = EbpfLoader::new();
            loader.map_max_entries(SOCKET_PROFILES_MAP, config.map_capacity);
            let mut ebpf = loader
                .load(PROGRAM)
                .map_err(|error| other_error("load the embedded eBPF program", error))?;

            let profiles = ebpf
                .take_map(SOCKET_PROFILES_MAP)
                .ok_or_else(|| invalid_object("missing SOCKET_PROFILES map"))?;
            let profiles: HashMap<MapData, u64, EncodedProfile> =
                profiles.try_into().map_err(|error| {
                    invalid_object(&format!("invalid SOCKET_PROFILES map: {error}"))
                })?;
            validate_map_abi(profiles.map(), config.map_capacity)?;

            let program: &mut SchedClassifier = ebpf
                .program_mut(PROGRAM_NAME)
                .ok_or_else(|| invalid_object("missing apply_profile program"))?
                .try_into()
                .map_err(|error| invalid_object(&format!("invalid TC classifier: {error}")))?;
            program
                .load()
                .map_err(|error| other_error("load eBPF profile classifier", error))?;

            for interface in config.interfaces {
                if legacy_tc
                    && config.replace_stale_legacy_tc
                    && replace_legacy_filter(program, interface)?
                {
                    continue;
                }

                let options = if legacy_tc {
                    TcAttachOptions::Netlink(NlOptions {
                        priority: LEGACY_TC_PRIORITY,
                        handle: LEGACY_TC_HANDLE,
                        classid: None,
                    })
                } else {
                    TcAttachOptions::TcxOrder(LinkOrder::default())
                };
                program
                    .attach_with_options(interface, TcAttachType::Egress, options)
                    .map_err(|error| {
                        let legacy_hint = if legacy_tc {
                            format!(
                                "; verify `tc qdisc add dev {interface} clsact` was run; if priority 49152 / handle 0:1 is occupied, remove that filter explicitly or opt in to replacing that exact tuple with --ebpf-replace-stale-legacy-tc"
                            )
                        } else {
                            String::new()
                        };
                        other_error(
                            &format!("attach eBPF profile program to {interface}{legacy_hint}"),
                            error,
                        )
                    })?;
            }

            tracing::info!(
                interfaces = ?config.interfaces,
                map_capacity = config.map_capacity,
                mode = if legacy_tc {
                    "legacy-tc"
                } else {
                    "tcx"
                },
                "eBPF profile backend attached"
            );

            Ok(Arc::new(Self {
                profiles: Mutex::new(profiles),
                legacy_tc,
                _ebpf: ebpf,
                _legacy_interface_locks: legacy_interface_locks,
            }))
        }

        /// Associates a not-yet-connected socket with its encoded profile.
        ///
        /// `SO_COOKIE` is stable for the socket lifetime and is also available
        /// to a TC classifier through `bpf_get_socket_cookie`. These are the two
        /// sides of the cookie-to-profile ABI. `BPF_NOEXIST` makes an unexpected
        /// duplicate a hard error instead of overwriting a live connection's
        /// policy. `profile` is already encoded for this socket's IP family,
        /// including its IPv4- or IPv6-sized MSS.
        ///
        /// Sources: Linux [`socket(7)`](https://man7.org/linux/man-pages/man7/socket.7.html)
        /// for `SO_COOKIE`, and the kernel
        /// [`bpf_get_socket_cookie` helper contract](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/bpf.h).
        pub(super) fn register(
            self: &Arc<Self>,
            socket: &TcpSocket,
            profile: EncodedProfile,
        ) -> io::Result<Registration> {
            let cookie = NonZeroU64::new(SockRef::from(socket).cookie()?).ok_or_else(|| {
                io::Error::other("the kernel returned an invalid zero socket cookie")
            })?;

            lock(&self.profiles)
                .insert(cookie.get(), profile, BPF_NOEXIST)
                .map_err(|error| {
                    other_error(
                        "register socket profile; increase --ebpf-map-capacity if the map is full",
                        error,
                    )
                })?;

            Ok(Registration {
                cookie,
                engine: Arc::clone(self),
            })
        }

        /// Reports whether runtime cleanup still needs `CAP_NET_ADMIN`.
        ///
        /// TCX links detach by closing their file descriptors. Legacy TC is
        /// managed through netlink and therefore retains the capability until
        /// shutdown.
        pub(super) const fn uses_legacy_tc(&self) -> bool {
            self.legacy_tc
        }
    }

    impl Drop for Registration {
        /// Attempts to retire the cookie entry when the connect attempt ends.
        ///
        /// `Drop` cannot return an error, so a failed map syscall is logged. The
        /// stale key remains collision-safe because registration never replaces
        /// an existing entry (`BPF_NOEXIST`).
        fn drop(&mut self) {
            if let Err(error) = lock(&self.engine.profiles).remove(&self.cookie.get()) {
                tracing::debug!(
                    cookie = self.cookie.get(),
                    "failed to remove socket profile from eBPF map: {error}"
                );
            }
        }
    }

    /// Rejects configurations that cannot provide deterministic attachment.
    ///
    /// Interface names and cross-option requirements are checked before any BPF
    /// object is loaded. Attachment still has its own cleanup rules documented
    /// by `Engine::load`, especially when legacy replacement is enabled.
    fn validate_config(config: &Config<'_>) -> io::Result<()> {
        if config.interfaces.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one --ebpf-interface is required to enable the eBPF backend",
            ));
        }
        if config.map_capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "eBPF map capacity must be non-zero",
            ));
        }
        if config.replace_stale_legacy_tc && !config.allow_legacy_tc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--ebpf-replace-stale-legacy-tc requires --ebpf-allow-legacy-tc",
            ));
        }
        for (index, interface) in config.interfaces.iter().enumerate() {
            if interface.is_empty()
                || interface.len() > libc::IF_NAMESIZE.saturating_sub(1)
                || matches!(interface.as_str(), "." | "..")
                || interface.contains('/')
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid eBPF interface name {interface:?}"),
                ));
            }
            if config.interfaces[..index].contains(interface) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("duplicate eBPF interface {interface:?}"),
                ));
            }
            validate_ethernet_interface(interface)?;
        }
        Ok(())
    }

    /// Confirms that the parser's expected layer-2 header matches the device.
    ///
    /// The packet program starts at an Ethernet header and understands only the
    /// VLAN forms documented there. Attaching it to loopback, a tunnel, or a
    /// different ARPHRD type would make every network-header offset invalid.
    fn validate_ethernet_interface(interface: &str) -> io::Result<()> {
        let path = Path::new("/sys/class/net").join(interface).join("type");
        let link_type = std::fs::read_to_string(&path)
            .map_err(|error| other_error(&format!("read {}", path.display()), error))?;
        let link_type = link_type.trim().parse::<u16>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid link type in {}: {error}", path.display()),
            )
        })?;
        if link_type != libc::ARPHRD_ETHER {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "the eBPF profile backend supports Ethernet interfaces only; \
                     {interface:?} has ARPHRD type {link_type}"
                ),
            ));
        }
        Ok(())
    }

    /// Acquires a process-lifetime advisory lock for each intended filter slot.
    ///
    /// `flock(2)` locks disappear after process death, unlike a legacy netlink
    /// filter. The key includes network-namespace identity and ifindex so equal
    /// interface names in different namespaces do not collide. This only
    /// coordinates processes that share the same `/run/vproxy` mount and lock
    /// inode; another mount namespace is outside the lock's scope.
    fn acquire_legacy_interface_locks(interfaces: &[String]) -> io::Result<Vec<File>> {
        let directory = prepare_legacy_lock_directory()?;
        let namespace = network_namespace_id()?;
        interfaces
            .iter()
            .map(|interface| {
                let ifindex = interface_index(interface)?;
                lock_legacy_interface(&directory, namespace, ifindex).map_err(|error| {
                    if error.kind() == io::ErrorKind::AddrInUse {
                        io::Error::new(
                            io::ErrorKind::AddrInUse,
                            format!(
                                "another vproxy legacy TC instance owns interface {interface:?}"
                            ),
                        )
                    } else {
                        other_error(
                            &format!("acquire legacy TC ownership for {interface:?}"),
                            error,
                        )
                    }
                })
            })
            .collect()
    }

    /// Creates and verifies the private directory used for TC ownership locks.
    ///
    /// Ownership and mode checks, `O_NOFOLLOW`, and per-file checks prevent a
    /// less-privileged local user from redirecting or pre-opening a lock path
    /// used by a privileged vproxy process.
    fn prepare_legacy_lock_directory() -> io::Result<std::path::PathBuf> {
        let directory = Path::new(LEGACY_LOCK_DIRECTORY);
        match DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(other_error(
                    &format!("create legacy TC lock directory {}", directory.display()),
                    error,
                ));
            }
        }

        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "legacy TC lock directory {} must be owned by the service user and have mode 0700",
                    directory.display()
                ),
            ));
        }
        Ok(directory.to_path_buf())
    }

    /// Returns the device/inode pair that identifies the current network
    /// namespace for the lifetime of the namespace object.
    fn network_namespace_id() -> io::Result<(u64, u64)> {
        let metadata = std::fs::metadata("/proc/self/ns/net")?;
        Ok((metadata.dev(), metadata.ino()))
    }

    /// Resolves an interface to the nonzero index used by the kernel TC API.
    fn interface_index(interface: &str) -> io::Result<NonZeroU32> {
        let path = Path::new("/sys/class/net").join(interface).join("ifindex");
        let index = std::fs::read_to_string(&path)
            .map_err(|error| other_error(&format!("read {}", path.display()), error))?
            .trim()
            .parse::<u32>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid interface index in {}: {error}", path.display()),
                )
            })?;
        NonZeroU32::new(index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("interface index in {} is zero", path.display()),
            )
        })
    }

    /// Opens one hardened lock file and takes a non-blocking exclusive lock.
    /// The returned descriptor must live as long as the attached filter;
    /// dropping it releases ownership automatically.
    fn lock_legacy_interface(
        directory: &Path,
        namespace: (u64, u64),
        ifindex: NonZeroU32,
    ) -> io::Result<File> {
        let path = directory.join(format!(
            "ebpf-{}-{}-{}.lock",
            namespace.0,
            namespace.1,
            ifindex.get()
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "legacy TC lock {} must be owned by the service user and not accessible by other users",
                    path.display()
                ),
            ));
        }
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                io::Error::new(io::ErrorKind::AddrInUse, error)
            } else {
                io::Error::from(error)
            }
        })?;
        Ok(file)
    }

    /// Verifies that the embedded program and userspace agree on the map ABI.
    ///
    /// Aya checks key/value widths when converting the map. This extra check
    /// also catches a wrong embedded object and a capacity that the loader failed
    /// to rewrite before load. Requiring exactly `BPF_F_NO_PREALLOC` is a memory
    /// safety invariant for the BPF-side `HashMap::get`, not an allocation
    /// preference: a preallocated hash slot may be reused after concurrent
    /// userspace deletion while the program still holds Aya's shared reference.
    fn validate_map_abi(map: &MapData, capacity: u32) -> io::Result<()> {
        let info = map
            .info()
            .map_err(|error| invalid_object(&format!("read SOCKET_PROFILES map info: {error}")))?;
        let map_type = info
            .map_type()
            .map_err(|error| invalid_object(&format!("read SOCKET_PROFILES map type: {error}")))?;
        if map_type != MapType::Hash
            || info.key_size() != u64::BITS / u8::BITS
            || usize::try_from(info.value_size()).ok() != Some(PROFILE_VALUE_LEN)
            || info.max_entries() != capacity
            || info.map_flags() != BPF_F_NO_PREALLOC
        {
            return Err(invalid_object(&format!(
                "SOCKET_PROFILES ABI mismatch: type={map_type:?}, key_size={}, \
                 value_size={}, max_entries={}, flags={:#x}",
                info.key_size(),
                info.value_size(),
                info.max_entries(),
                info.map_flags()
            )));
        }
        Ok(())
    }

    /// Replaces only vproxy's fixed legacy priority/handle tuple.
    ///
    /// No qdisc or other tuple is deleted. The tuple is conventional rather than
    /// kernel-reserved, so the caller's explicit opt-in may replace an unrelated
    /// classifier that uses the same values. `false` means the tuple did not
    /// exist and the caller should perform a normal attach; every other lookup
    /// or replacement failure is reported to the operator.
    fn replace_legacy_filter(program: &mut SchedClassifier, interface: &str) -> io::Result<bool> {
        let link = SchedClassifierLink::attached(
            interface,
            TcAttachType::Egress,
            LEGACY_TC_PRIORITY,
            LEGACY_TC_HANDLE,
            None,
        )
        .map_err(|error| {
            other_error(
                &format!("locate the fixed eBPF filter tuple on {interface}"),
                error,
            )
        })?;

        match program.attach_to_link(link) {
            Ok(_) => {
                tracing::warn!(
                    interface,
                    "replaced the legacy TC filter at vproxy's fixed tuple"
                );
                Ok(true)
            }
            Err(ProgramError::NetlinkError(error))
                if error.raw_os_error() == Some(libc::ENOENT) =>
            {
                Ok(false)
            }
            Err(error) => Err(other_error(
                &format!("replace the fixed eBPF filter tuple on {interface}"),
                error,
            )),
        }
    }

    /// Recovers access after an unrelated task panics while holding the mutex.
    /// BPF map calls do not depend on a compound userspace invariant, so mutex
    /// poisoning does not make the kernel map inconsistent.
    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Classifies an embedded-object ABI mismatch as invalid startup data.
    fn invalid_object(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
    }

    /// Adds loader context while preserving a single `io::Error` boundary.
    fn other_error(context: &str, error: impl std::error::Error) -> io::Error {
        io::Error::other(format!("{context}: {error}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn program_is_embedded_as_an_elf_object() {
            assert_eq!(PROGRAM.get(..4), Some(b"\x7fELF".as_slice()));
        }

        #[test]
        fn legacy_interface_lock_has_process_lifetime() -> io::Result<()> {
            struct Directory(std::path::PathBuf);
            impl Drop for Directory {
                fn drop(&mut self) {
                    let _ = std::fs::remove_file(self.0.join(format!(
                        "ebpf-{}-{}-{}.lock",
                        u64::MAX,
                        u64::MAX,
                        u32::MAX,
                    )));
                    let _ = std::fs::remove_dir(&self.0);
                }
            }
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos();
            let directory = Directory(
                std::env::temp_dir()
                    .join(format!("vproxy-ebpf-lock-{}-{nonce}", std::process::id())),
            );
            DirBuilder::new().mode(0o700).create(&directory.0)?;
            let ifindex = NonZeroU32::new(u32::MAX).expect("test ifindex is non-zero");
            let namespace = (u64::MAX, u64::MAX);
            let first = lock_legacy_interface(&directory.0, namespace, ifindex)
                .expect("first owner acquires the lock");
            let error = lock_legacy_interface(&directory.0, namespace, ifindex)
                .expect_err("a second live owner must be rejected");
            assert_eq!(error.kind(), io::ErrorKind::AddrInUse);

            drop(first);
            lock_legacy_interface(&directory.0, namespace, ifindex)
                .expect("dropping the owner releases the lock");
            Ok(())
        }
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
/// Startup-to-runtime capability reduction for an actually attached backend.
mod linux_privileges {
    use std::io;

    use rustix::thread::{CapabilitySet, capabilities, set_capabilities, set_no_new_privs};

    /// Drops startup-only Linux capabilities before worker threads are created.
    ///
    /// Loading and attaching eBPF happens earlier. Only capabilities required
    /// by the selected runtime paths are retained, and `no_new_privs` prevents
    /// a later `execve(2)` from regaining a dropped privilege.
    pub(super) fn restrict(
        legacy_tc: bool,
        privileged_bind: bool,
        interface_fallback: bool,
    ) -> io::Result<()> {
        let retained = runtime_capabilities(legacy_tc, privileged_bind, interface_fallback);
        let mut sets =
            capabilities(None).map_err(|error| other_error("read Linux capabilities", error))?;
        sets.effective &= retained;
        sets.permitted &= retained;
        sets.inheritable &= retained;
        set_capabilities(None, sets)
            .map_err(|error| other_error("restrict Linux runtime capabilities", error))?;
        // This runs before the worker threads are created, so they inherit the
        // restriction and cannot regain dropped privileges through execve(2).
        set_no_new_privs(true).map_err(|error| other_error("enable Linux no_new_privs", error))?;

        tracing::debug!(
            retained_net_admin = legacy_tc,
            retained_net_raw = interface_fallback,
            retained_net_bind_service = privileged_bind,
            "restricted Linux runtime privileges"
        );
        Ok(())
    }

    /// Computes the bounded capability set for the active runtime features.
    ///
    /// Legacy TC needs netlink administration until its filter is detached;
    /// privileged listeners and raw interface binding independently retain
    /// their corresponding network capability. Linux 6.1, the oldest supported
    /// eBPF kernel, checks `CAP_NET_RAW` for `SO_BINDTODEVICE`; this must stay in
    /// sync with `TcpConnector::bind_interface` and systemd unit generation.
    /// <https://github.com/torvalds/linux/blob/v6.1/net/core/sock.c>
    fn runtime_capabilities(
        legacy_tc: bool,
        privileged_bind: bool,
        interface_fallback: bool,
    ) -> CapabilitySet {
        // Direct root starts may still need to read operator-owned TLS files
        // after this point. Keep only those file-read capabilities plus the
        // network capabilities used during the server's runtime.
        let mut retained = CapabilitySet::DAC_READ_SEARCH;
        if legacy_tc {
            retained |= CapabilitySet::NET_ADMIN;
        }
        if privileged_bind {
            retained |= CapabilitySet::NET_BIND_SERVICE;
        }
        if interface_fallback {
            retained |= CapabilitySet::NET_RAW;
        }
        retained
    }

    /// Adds privilege-transition context to a platform-neutral I/O error.
    fn other_error(context: &str, error: impl std::error::Error) -> io::Error {
        io::Error::other(format!("{context}: {error}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn runtime_capabilities_are_limited_to_active_features() {
            assert_eq!(
                runtime_capabilities(false, false, false),
                CapabilitySet::DAC_READ_SEARCH
            );
            assert_eq!(
                runtime_capabilities(true, true, true),
                CapabilitySet::DAC_READ_SEARCH
                    | CapabilitySet::NET_ADMIN
                    | CapabilitySet::NET_BIND_SERVICE
                    | CapabilitySet::NET_RAW
            );
        }
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub(crate) use linux::Config as LinuxConfig;

/// Startup attachment settings shared by standalone and managed listeners.
/// There are no externally configurable packet templates or preset scalars.
/// On unsupported builds the flattened group is empty, rather than exposing
/// switches whose effects would silently be ignored.
#[derive(clap::Args, Clone, Default)]
pub(crate) struct Args {
    /// Ethernet egress interface for the built-in profile backend.
    /// Repeat for every possible egress interface; no interface disables it.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[arg(long = "ebpf-interface", id = "ebpf_interface", verbatim_doc_comment)]
    interfaces: Vec<String>,
    /// Permit legacy TC on Linux 6.1 through 6.5, using existing clsact qdiscs.
    /// Linux 6.6+ never falls back after a failed TCX attachment.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[arg(
        long = "ebpf-allow-legacy-tc",
        requires = "ebpf_interface",
        verbatim_doc_comment
    )]
    allow_legacy_tc: bool,
    /// Replace priority 49152 / handle 0:1 only after verifying slot ownership.
    /// This tuple is not reserved; replacement cannot restore the old filter
    /// if a later attachment or startup step fails.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[arg(
        long = "ebpf-replace-stale-legacy-tc",
        requires = "allow_legacy_tc",
        verbatim_doc_comment
    )]
    replace_stale_legacy_tc: bool,
    /// Maximum profiled connect attempts (default: 65536).
    /// A full map rejects new attempts before a SYN; entries are not evicted.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    #[arg(
        long = "ebpf-map-capacity",
        requires = "ebpf_interface",
        verbatim_doc_comment
    )]
    map_capacity: Option<std::num::NonZeroU32>,
}

impl Args {
    /// Load and attach on the startup thread, before spawning workers. Empty
    /// settings return a native config without kernel or privilege changes.
    pub(crate) fn load(&self) -> io::Result<Config> {
        Config::try_new(
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            if self.interfaces.is_empty() {
                None
            } else {
                Some(LinuxConfig {
                    interfaces: &self.interfaces,
                    allow_legacy_tc: self.allow_legacy_tc,
                    replace_stale_legacy_tc: self.replace_stale_legacy_tc,
                    map_capacity: self
                        .map_capacity
                        .map_or(DEFAULT_MAP_CAPACITY, std::num::NonZeroU32::get),
                })
            },
        )
    }
}

/// Actual startup backend state, not a guess based on flags, privileges or the
/// node identity endpoint. Ready only means this process owns a loaded engine;
/// it does not assert interface reachability or every route's MSS/WS readiness.
#[cfg(feature = "management")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackendState {
    Ready,
    NotConfigured,
    FeatureDisabled,
    PlatformUnsupported,
}

#[cfg(feature = "management")]
pub(crate) struct Catalog {
    pub(crate) state: BackendState,
    /// Never advertise executable presets without an actually active engine.
    pub(crate) available_presets: &'static [Profile],
}

/// Built-in synthetic platform baseline selected by the authentication
/// extension.
///
/// These variants name stable vproxy presets, not promises that every release
/// or configuration of the named operating system emits the same SYN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "management", derive(serde::Serialize, serde::Deserialize))]
pub enum Profile {
    /// Windows 10/11-style baseline derived from the pinned upstream presets.
    #[cfg_attr(feature = "management", serde(rename = "windows"))]
    Windows,
    /// Linux-style baseline derived from the pinned upstream preset.
    #[cfg_attr(feature = "management", serde(rename = "linux"))]
    Linux,
    /// Android baseline, currently a separate alias of the Linux-style values.
    #[cfg_attr(feature = "management", serde(rename = "android"))]
    Android,
    /// macOS-style baseline derived from the pinned upstream preset.
    #[cfg_attr(feature = "management", serde(rename = "macos"))]
    MacOs,
    /// iOS baseline, currently a separate alias of the macOS-style values.
    #[cfg_attr(feature = "management", serde(rename = "ios"))]
    Ios,
}

/// Complete profile-controlled initial-SYN settings for one built-in device
/// family.
///
/// This is the single source of truth for both the socket configuration and
/// the Linux eBPF map value. TCP option kinds and lengths follow
/// [RFC 9293, section 3.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1),
/// while Window Scale and Timestamp follow
/// [RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html). The structure stays
/// private so startup arguments and downstream callers cannot construct
/// arbitrary combinations that the packet program has not validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProfileSettings {
    /// Initial IPv4 Time To Live or IPv6 Hop Limit, measured in router hops.
    /// Each forwarding router decrements this byte and discards the packet at
    /// zero, as described by [RFC 8200 section 3](https://www.rfc-editor.org/rfc/rfc8200.html#section-3)
    /// and [RFC 791 section 3.1](https://www.rfc-editor.org/rfc/rfc791.html#section-3.1).
    hop_limit: u8,
    /// Full eight-bit IPv4 DS field or IPv6 Traffic Class field.
    ///
    /// The high six bits carry DSCP and the low two bits carry ECN. Keeping the
    /// complete octet avoids changing either part independently. See
    /// [RFC 2474 section 3](https://www.rfc-editor.org/rfc/rfc2474.html#section-3),
    /// [RFC 3168 section 5](https://www.rfc-editor.org/rfc/rfc3168.html#section-5),
    /// and [RFC 8200 section 3](https://www.rfc-editor.org/rfc/rfc8200.html#section-3).
    traffic_class: u8,
    /// Unscaled 16-bit receive window advertised by the SYN.
    ///
    /// Per [RFC 7323 section 2.2](https://www.rfc-editor.org/rfc/rfc7323.html#section-2.2),
    /// the scale factor is never applied to the window field of a segment with
    /// SYN set; it only affects later segments.
    tcp_window: u16,
    /// Maximum TCP payload, in octets, advertised on IPv4.
    ///
    /// The 1460-byte built-in value is a standard 1500-byte Ethernet MTU minus
    /// the 20-byte IPv4 and TCP fixed headers. It is a ceiling rather than a
    /// path-MTU promise, per
    /// [RFC 6691 section 2](https://www.rfc-editor.org/rfc/rfc6691.html#section-2).
    tcp_mss_v4: u16,
    /// Maximum TCP payload, in octets, advertised on IPv6.
    ///
    /// IPv6 has a 40-byte fixed header, so the corresponding standard-Ethernet
    /// value is 1440. Keeping this separate prevents an IPv4-sized 1460 option
    /// from disagreeing with the IPv6 route and Linux TCP control block.
    tcp_mss_v6: u16,
    /// Base-2 shift count carried by the three-byte Window Scale option.
    /// A value of `n` makes post-handshake window fields represent multiples of
    /// `2^n`; RFC 7323 restricts the usable range to 0 through 14.
    tcp_window_scale: u8,
    /// Whether to set the IPv4 Don't Fragment flag on the SYN.
    /// IPv6 has no corresponding header bit and ignores this setting.
    ipv4_df: bool,
    /// Whether the wire template contains the RFC 7323 Timestamp option.
    /// The packet program preserves the kernel-generated TSval/TSecr bytes so
    /// PAWS and RTT measurement remain consistent with the TCP control block.
    tcp_timestamps: bool,
    /// Whether to derive the IPv4 Identification field from the connection.
    ///
    /// This is meaningful only for an IPv4 SYN and is accepted only together
    /// with DF. That keeps the non-fragmentation use within RFC 6864's updated
    /// IPv4 ID semantics; IPv6 has no Identification field in its fixed header.
    /// See [RFC 6864](https://www.rfc-editor.org/rfc/rfc6864.html).
    derive_ipv4_id: bool,
    /// Number of bytes emitted from the start of `options`.
    ///
    /// TCP allows up to 40 bytes in four-byte units. The built-in encoder emits
    /// only 12-, 20-, and 24-byte templates. The BPF decoder matches each class
    /// against its complete built-in scalar metadata, fixed option words, and
    /// zero ABI padding; length alone is never treated as proof of a preset.
    options_len: u8,
    /// Zero-based byte offset of the two-byte MSS payload inside `options`.
    /// The offset points after the option kind and length bytes, not at the MSS
    /// option itself.
    mss_value_offset: u8,
    /// Zero-based byte offset of the eight TSval-and-TSecr bytes inside
    /// `options`.
    ///
    /// The eBPF program replaces all eight bytes with the values created by the
    /// Linux TCP stack. `INVALID_OPTION_OFFSET` means that this profile has no
    /// Timestamp option. The built-in layouts place it at byte 8 or 12, and the
    /// BPF exact-profile validator accepts only those audited layouts. RFC 7323
    /// itself does not require Timestamp values to begin on a four-byte boundary.
    timestamp_value_offset: u8,
    /// Zero-based byte offset of the one-byte shift count inside `options`.
    /// The offset points after the option kind and length bytes, not at the
    /// Window Scale option itself.
    window_scale_value_offset: u8,
    /// Fixed-width TCP option template in exact wire order.
    ///
    /// MSS and Window Scale payload bytes are placeholders filled from their
    /// typed fields by `encode`. A Timestamp payload is filled by the packet
    /// program when enabled. Bytes after `options_len` are ABI padding and stay
    /// zero; they are never emitted on the wire.
    options: [u8; TCP_OPTIONS_LEN],
}

impl ProfileSettings {
    /// Selects the MSS that belongs to the socket's network-layer header size.
    /// Both the socket option and map encoding call this method, so TC validates
    /// the same family-specific ceiling that was given to the kernel.
    const fn tcp_mss(self, version: IpVersion) -> u16 {
        match version {
            IpVersion::V4 => self.tcp_mss_v4,
            IpVersion::V6 => self.tcp_mss_v6,
        }
    }

    /// Encodes the stable userspace-to-eBPF map ABI without native-endian fields.
    ///
    /// The layout is:
    ///
    /// - byte 0: TTL / Hop Limit;
    /// - byte 1: TOS / Traffic Class;
    /// - bytes 2..=3: advertised TCP window, big-endian;
    /// - bytes 4..=5: MSS, big-endian;
    /// - byte 6: Window Scale shift count;
    /// - byte 7: profile flags;
    /// - bytes 8..=11: option length followed by MSS, Timestamp-value, and
    ///   Window-Scale-value offsets;
    /// - bytes 12..=51: the fixed 40-byte TCP option area.
    ///
    /// Using octets keeps the ABI identical for `bpfel` and `bpfeb` and avoids
    /// an unsafe `aya::Pod` implementation.
    /// `version` selects the actual MSS written to ABI bytes 4..=5 and to the
    /// option template. No separate family flag is needed because each map entry
    /// belongs to one already-created IPv4 or IPv6 socket.
    const fn encode(self, version: IpVersion) -> EncodedProfile {
        let mut encoded = [0; PROFILE_VALUE_LEN];
        encoded[0] = self.hop_limit;
        encoded[1] = self.traffic_class;
        let [window_high, window_low] = self.tcp_window.to_be_bytes();
        encoded[2] = window_high;
        encoded[3] = window_low;
        let [mss_high, mss_low] = self.tcp_mss(version).to_be_bytes();
        encoded[4] = mss_high;
        encoded[5] = mss_low;
        encoded[6] = self.tcp_window_scale;
        encoded[7] = ((self.ipv4_df as u8) * PROFILE_FLAG_IPV4_DF)
            | ((self.tcp_timestamps as u8) * PROFILE_FLAG_TCP_TIMESTAMPS)
            | ((self.derive_ipv4_id as u8) * PROFILE_FLAG_DERIVE_IPV4_ID);
        encoded[8] = self.options_len;
        encoded[9] = self.mss_value_offset;
        encoded[10] = self.timestamp_value_offset;
        encoded[11] = self.window_scale_value_offset;

        let mut index = 0;
        while index < TCP_OPTIONS_LEN {
            encoded[12 + index] = self.options[index];
            index += 1;
        }
        let mss_offset = self.mss_value_offset as usize;
        if mss_offset + 1 < TCP_OPTIONS_LEN {
            encoded[12 + mss_offset] = mss_high;
            encoded[12 + mss_offset + 1] = mss_low;
        }
        let window_scale_offset = self.window_scale_value_offset as usize;
        if window_scale_offset < TCP_OPTIONS_LEN {
            encoded[12 + window_scale_offset] = self.tcp_window_scale;
        }
        encoded
    }
}

/// MSS,NOP,Window Scale,NOP,NOP,SACK Permitted.
const WINDOWS_OPTIONS: [u8; TCP_OPTIONS_LEN] = {
    let mut options = [0; TCP_OPTIONS_LEN];
    options[0] = TCP_OPTION_MSS;
    options[1] = TCP_OPTION_MSS_LEN;
    options[4] = TCP_OPTION_NOP;
    options[5] = TCP_OPTION_WINDOW_SCALE;
    options[6] = TCP_OPTION_WINDOW_SCALE_LEN;
    options[8] = TCP_OPTION_NOP;
    options[9] = TCP_OPTION_NOP;
    options[10] = TCP_OPTION_SACK_PERMITTED;
    options[11] = TCP_OPTION_SACK_PERMITTED_LEN;
    options
};

/// MSS,SACK Permitted,Timestamp,NOP,Window Scale.
const LINUX_OPTIONS: [u8; TCP_OPTIONS_LEN] = {
    let mut options = [0; TCP_OPTIONS_LEN];
    options[0] = TCP_OPTION_MSS;
    options[1] = TCP_OPTION_MSS_LEN;
    options[4] = TCP_OPTION_SACK_PERMITTED;
    options[5] = TCP_OPTION_SACK_PERMITTED_LEN;
    options[6] = TCP_OPTION_TIMESTAMP;
    options[7] = TCP_OPTION_TIMESTAMP_LEN;
    options[16] = TCP_OPTION_NOP;
    options[17] = TCP_OPTION_WINDOW_SCALE;
    options[18] = TCP_OPTION_WINDOW_SCALE_LEN;
    options
};

/// MSS,NOP,Window Scale,NOP,NOP,Timestamp,SACK Permitted,EOL, then one zero
/// padding byte as required by
/// [RFC 9293 section 3.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1)
/// (MUST-69).
const DARWIN_OPTIONS: [u8; TCP_OPTIONS_LEN] = {
    let mut options = [0; TCP_OPTIONS_LEN];
    options[0] = TCP_OPTION_MSS;
    options[1] = TCP_OPTION_MSS_LEN;
    options[4] = TCP_OPTION_NOP;
    options[5] = TCP_OPTION_WINDOW_SCALE;
    options[6] = TCP_OPTION_WINDOW_SCALE_LEN;
    options[8] = TCP_OPTION_NOP;
    options[9] = TCP_OPTION_NOP;
    options[10] = TCP_OPTION_TIMESTAMP;
    options[11] = TCP_OPTION_TIMESTAMP_LEN;
    options[20] = TCP_OPTION_SACK_PERMITTED;
    options[21] = TCP_OPTION_SACK_PERMITTED_LEN;
    options[22] = TCP_OPTION_END;
    options
};

// Profile sources are pinned so later upstream changes do not silently redefine
// these selectors. 404 supplies TOS and exact option order as well as the scalar
// TCP/IP fields; httpcloak independently supplies TTL, MSS, Window, Window Scale,
// and DF:
//
// - https://github.com/un-nf/404/blob/10ee191ec3f7132ac51b359988d3326f9cd2aab2/src/STATIC_proxy/src/ebpf.rs#L85-L127
// - https://github.com/sardanioss/httpcloak/blob/8a8f2be1e79121b082351db71295406b32615a63/fingerprint/presets.go#L141-L164
//
// vproxy keeps the upstream fixed layout but uses 1440 for IPv6 MSS, preserves
// Linux's TSval/TSecr and IPv6 Flow Label, and derives a stable retransmission ID
// from the socket cookie and initial sequence number instead of injecting random
// per-packet values. Those differences keep the wire rewrite consistent with the
// Linux TCP control block and IPv6 flow semantics.

/// Windows 10/11-style baseline shared by the pinned 404 and httpcloak sources.
const WINDOWS_PROFILE: ProfileSettings = ProfileSettings {
    hop_limit: 128,
    traffic_class: 0x10,
    tcp_window: 64_240,
    tcp_mss_v4: 1_460,
    tcp_mss_v6: 1_440,
    tcp_window_scale: 8,
    ipv4_df: true,
    tcp_timestamps: false,
    derive_ipv4_id: true,
    options_len: 12,
    mss_value_offset: 2,
    timestamp_value_offset: INVALID_OPTION_OFFSET,
    window_scale_value_offset: 7,
    options: WINDOWS_OPTIONS,
};

/// Linux-style baseline shared by the pinned 404 and httpcloak sources.
const LINUX_PROFILE: ProfileSettings = ProfileSettings {
    hop_limit: 64,
    traffic_class: 0x10,
    tcp_window: 65_535,
    tcp_mss_v4: 1_460,
    tcp_mss_v6: 1_440,
    tcp_window_scale: 7,
    ipv4_df: true,
    tcp_timestamps: true,
    derive_ipv4_id: true,
    options_len: 20,
    mss_value_offset: 2,
    timestamp_value_offset: 8,
    window_scale_value_offset: 19,
    options: LINUX_OPTIONS,
};

/// Android baseline, currently a local alias of the Linux-style values.
///
/// It remains a separate constant so later Android packet captures can evolve
/// without silently changing the Linux selector.
const ANDROID_PROFILE: ProfileSettings = ProfileSettings {
    hop_limit: 64,
    traffic_class: 0x10,
    tcp_window: 65_535,
    tcp_mss_v4: 1_460,
    tcp_mss_v6: 1_440,
    tcp_window_scale: 7,
    ipv4_df: true,
    tcp_timestamps: true,
    derive_ipv4_id: true,
    options_len: 20,
    mss_value_offset: 2,
    timestamp_value_offset: 8,
    window_scale_value_offset: 19,
    options: LINUX_OPTIONS,
};

/// macOS-style baseline shared by the pinned 404 and httpcloak sources.
///
/// vproxy intentionally preserves Linux's TSval/TSecr and IPv6 Flow Label. The
/// final byte is zero, rather than upstream 404's NOP-like padding, because
/// RFC 9293 MUST-69 requires zero after EOL.
const MACOS_PROFILE: ProfileSettings = ProfileSettings {
    hop_limit: 64,
    traffic_class: 0x10,
    tcp_window: 65_535,
    tcp_mss_v4: 1_460,
    tcp_mss_v6: 1_440,
    tcp_window_scale: 6,
    ipv4_df: true,
    tcp_timestamps: true,
    derive_ipv4_id: true,
    options_len: 24,
    mss_value_offset: 2,
    timestamp_value_offset: 12,
    window_scale_value_offset: 7,
    options: DARWIN_OPTIONS,
};

/// iOS baseline, currently a local alias of the macOS-style values.
///
/// It remains separate so future iOS packet captures need not change macOS.
const IOS_PROFILE: ProfileSettings = ProfileSettings {
    hop_limit: 64,
    traffic_class: 0x10,
    tcp_window: 65_535,
    tcp_mss_v4: 1_460,
    tcp_mss_v6: 1_440,
    tcp_window_scale: 6,
    ipv4_df: true,
    tcp_timestamps: true,
    derive_ipv4_id: true,
    options_len: 24,
    mss_value_offset: 2,
    timestamp_value_offset: 12,
    window_scale_value_offset: 7,
    options: DARWIN_OPTIONS,
};

impl Profile {
    /// Resolves the public selector to its immutable, audited wire settings.
    /// Keeping this mapping exhaustive prevents a newly added selector from
    /// silently falling back to another platform family.
    const fn settings(self) -> ProfileSettings {
        match self {
            Self::Windows => WINDOWS_PROFILE,
            Self::Linux => LINUX_PROFILE,
            Self::Android => ANDROID_PROFILE,
            Self::MacOs => MACOS_PROFILE,
            Self::Ios => IOS_PROFILE,
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Android => "android",
            Self::MacOs => "macos",
            Self::Ios => "ios",
        })
    }
}

impl FromStr for Profile {
    type Err = ParseProfileError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "windows" => Ok(Self::Windows),
            "linux" => Ok(Self::Linux),
            "android" => Ok(Self::Android),
            "macos" => Ok(Self::MacOs),
            "ios" => Ok(Self::Ios),
            _ => Err(ParseProfileError),
        }
    }
}

/// Error returned when authentication metadata names an unknown profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseProfileError;

impl fmt::Display for ParseProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected windows, linux, android, macos, or ios")
    }
}

impl std::error::Error for ParseProfileError {}

/// Exposes the real userspace encoder to the kernel-validator contract test.
/// Production code reaches the same path through `Config::register`.
#[cfg(test)]
pub(crate) fn encode_profile_for_test(profile: Profile, version: IpVersion) -> EncodedProfile {
    profile.settings().encode(version)
}

/// Network-layer version of a newly-created outbound TCP socket.
///
/// Callers normalize IPv4-mapped IPv6 destinations before choosing this value,
/// so it describes the packet emitted on the wire and selects the matching MSS,
/// rather than merely reflecting the input address representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IpVersion {
    /// IPv4 socket; profile fields map to `IP_TTL` and `IP_TOS`.
    V4,
    /// IPv6 socket; profile fields map to Hop Limit and Traffic Class.
    V6,
}

/// Runtime policy shared by all outbound connectors.
///
/// An active Linux engine owns the classifier for the server lifetime and
/// receives short-lived registrations from profiled connection attempts.
/// Without that engine only native requests are available; socket-only hints
/// are deliberately not presented as a complete preset.
#[derive(Clone, Default)]
pub(crate) struct Config {
    /// Shared owner of the loaded program, attachments, and socket-profile map.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    engine: Option<std::sync::Arc<linux::Engine>>,
}

/// Keeps a socket-cookie map entry alive while `connect(2)` may emit or
/// retransmit the initial SYN.
///
/// Dropping the connect future also drops this guard and attempts to remove the
/// entry for canceled Happy Eyeballs attempts. A removal syscall can still
/// fail; registration uses `BPF_NOEXIST` so any stale key is reported instead
/// of being silently reused.
#[must_use]
pub(crate) struct SocketGuard {
    /// Linux map entry; the empty state is allocation-free native behavior.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    _registration: Option<linux::Registration>,
}

impl Config {
    /// Whether this process owns a successfully loaded and attached backend.
    /// This is a local lifecycle fact, not an external network health probe.
    pub(crate) fn is_active(&self) -> bool {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            self.engine.is_some()
        }
        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            false
        }
    }

    /// Return the immutable vocabulary and actual runtime availability. Startup
    /// errors fail initialization; they are never disguised as a ready catalog.
    #[cfg(feature = "management")]
    pub(crate) fn catalog(&self) -> Catalog {
        let state = if self.is_active() {
            BackendState::Ready
        } else if !cfg!(target_os = "linux") {
            BackendState::PlatformUnsupported
        } else if !cfg!(feature = "ebpf") {
            BackendState::FeatureDisabled
        } else {
            BackendState::NotConfigured
        };
        Catalog {
            state,
            available_presets: if state == BackendState::Ready {
                &[
                    Profile::Windows,
                    Profile::Linux,
                    Profile::Android,
                    Profile::MacOs,
                    Profile::Ios,
                ]
            } else {
                &[]
            },
        }
    }

    /// Builds the connector policy and, when configured, loads the Linux
    /// backend before the server begins accepting traffic.
    pub(crate) fn try_new(
        #[cfg(all(target_os = "linux", feature = "ebpf"))] ebpf: Option<LinuxConfig<'_>>,
    ) -> io::Result<Self> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        let engine = ebpf.map(linux::Engine::load).transpose()?;

        Ok(Self {
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            engine,
        })
    }

    /// Returns whether this request should use the host TCP/IP defaults.
    /// Absence of authentication profile metadata is the only native selector;
    /// there is deliberately no externally named `native` profile.
    pub(crate) fn is_native(&self, requested: Option<Profile>) -> bool {
        requested.is_none()
    }

    /// Rejects a requested preset unless the complete Linux packet backend is
    /// active. Socket-only hints cannot implement the promised SYN layout and
    /// must never silently substitute for it. Native requests do no kernel work.
    pub(crate) fn require_backend(&self, requested: Option<Profile>) -> io::Result<()> {
        if requested.is_none() {
            return Ok(());
        }
        if self.is_active() {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the requested profile requires an active Linux eBPF backend",
        ))
    }

    /// Applies the preset's kernel-supported fields before the first SYN.
    ///
    /// Only a newly created, unconnected socket is valid input. An absent
    /// preset returns without changing any socket option. A preset without an
    /// attached backend is Unsupported, not a partial socket-only emulation.
    /// Linux's real route, sysctls and TCP state still constrain the SYN: the
    /// classifier must reject incompatible MSS/Window/Scale/options rather than
    /// contradicting the kernel's connection state. A capped receive buffer is
    /// rejected here before connect can emit any packet.
    pub(crate) fn apply(
        &self,
        socket: &TcpSocket,
        version: IpVersion,
        requested: Option<Profile>,
    ) -> io::Result<()> {
        self.require_backend(requested)?;
        let Some(profile) = requested else {
            return Ok(());
        };
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let settings = profile.settings();
            let socket = socket2::SockRef::from(socket);
            match version {
                IpVersion::V4 => {
                    socket
                        .set_ttl_v4(u32::from(settings.hop_limit))
                        .map_err(|error| socket_option_error("IP_TTL", error))?;
                    socket
                        .set_tos_v4(u32::from(settings.traffic_class))
                        .map_err(|error| socket_option_error("IP_TOS", error))?;
                }
                IpVersion::V6 => {
                    socket
                        .set_unicast_hops_v6(u32::from(settings.hop_limit))
                        .map_err(|error| socket_option_error("IPV6_UNICAST_HOPS", error))?;
                    socket
                        .set_tclass_v6(u32::from(settings.traffic_class))
                        .map_err(|error| socket_option_error("IPV6_TCLASS", error))?;
                }
            }
            socket
                .set_tcp_mss(u32::from(settings.tcp_mss(version)))
                .map_err(|error| socket_option_error("TCP_MAXSEG", error))?;
            set_linux_receive_buffer_for_scale(&socket, settings.tcp_window_scale)?;
        }
        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        let _ = (socket, version, profile);
        Ok(())
    }

    /// Registers the socket-cookie map entry used by the egress classifier.
    ///
    /// The returned guard must be held across `TcpSocket::connect`; its drop
    /// path attempts removal after success, error, timeout, and cancellation.
    /// A failed removal leaves a collision-safe stale key because the next
    /// insertion uses `BPF_NOEXIST`.
    /// `version` must describe this socket; it selects the MSS embedded in both
    /// the scalar ABI field and TCP option template.
    /// Native requests return an empty guard without allocating. A preset
    /// without an active backend is rejected before reading the socket cookie.
    pub(crate) fn register(
        &self,
        socket: &TcpSocket,
        version: IpVersion,
        requested: Option<Profile>,
    ) -> io::Result<SocketGuard> {
        self.require_backend(requested)?;
        let profile = requested.map(|profile| profile.settings().encode(version));

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        let registration = match (self.engine.as_ref(), profile) {
            (Some(engine), Some(profile)) => Some(engine.register(socket, profile)?),
            _ => None,
        };

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        let _ = (socket, profile);

        Ok(SocketGuard {
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            _registration: registration,
        })
    }

    /// Drops Linux capabilities that are no longer needed after startup.
    /// This must run before spawning worker threads so every thread inherits
    /// the same restricted credentials and `no_new_privs` state.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(crate) fn restrict_runtime_privileges(
        &self,
        privileged_bind: bool,
        interface_fallback: bool,
    ) -> io::Result<()> {
        let Some(engine) = self.engine.as_deref() else {
            // Default/native operation must not change capabilities or
            // no_new_privs merely because support was compiled into the bin.
            return Ok(());
        };
        let legacy_tc = engine.uses_legacy_tc();

        linux_privileges::restrict(legacy_tc, privileged_bind, interface_fallback)
    }
}

/// Adds the kernel option name while preserving the original I/O error kind.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn socket_option_error(option: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("failed to set {option}: {error}"))
}

/// Sets the requested receive-buffer size with a consistent option name in
/// errors. Linux-specific scale validation is layered on top of this helper.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn set_receive_buffer_size(socket: &socket2::SockRef<'_>, size: usize) -> io::Result<()> {
    socket
        .set_recv_buffer_size(size)
        .map_err(|error| socket_option_error("SO_RCVBUF", error))
}

/// Sizes a Linux receive buffer so the kernel can select the requested Window
/// Scale before the eBPF program reorders the SYN options.
///
/// Linux reports twice the value passed to `SO_RCVBUF`, while
/// `tcp_full_space` is approximately half of that reported value. Requesting
/// `1 << (15 + scale)` places the request at the corresponding
/// `ilog2(space) - 15` boundary used by `tcp_select_initial_window` under the
/// ordinary Linux receive-space accounting. The kernel may cap the request at
/// `net.core.rmem_max`; checking the effective doubled value catches that silent
/// clamp before connect. This check alone cannot account for disabled Window
/// Scaling, route window clamps, or kernel-version-specific accounting. The TC
/// program therefore compares the actual SYN option and drops a registered,
/// parsed SYN when the kernel did not choose the requested scale.
/// See Linux `tcp_select_initial_window` in `net/ipv4/tcp_output.c`.
/// <https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_output.c>
#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn set_linux_receive_buffer_for_scale(socket: &socket2::SockRef<'_>, scale: u8) -> io::Result<()> {
    let requested_size = 1_usize
        .checked_shl(
            15_u32
                .checked_add(u32::from(scale))
                .ok_or_else(|| io::Error::other("profile receive buffer shift overflow"))?,
        )
        .ok_or_else(|| io::Error::other("profile receive buffer size overflow"))?;
    let effective_size = requested_size
        .checked_mul(2)
        .ok_or_else(|| io::Error::other("profile receive buffer size overflow"))?;
    set_receive_buffer_size(socket, requested_size)?;

    let actual_size = socket
        .recv_buffer_size()
        .map_err(|error| socket_option_error("SO_RCVBUF", error))?;
    if actual_size < effective_size {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Linux capped SO_RCVBUF at {actual_size} bytes; Window Scale {scale} requires at least {effective_size} bytes (raise net.core.rmem_max to at least {requested_size})"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> io::Result<Config> {
        Config::try_new(
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            None,
        )
    }

    #[test]
    fn profile_names_are_strict_and_stable() {
        for (name, profile) in [
            ("windows", Profile::Windows),
            ("linux", Profile::Linux),
            ("android", Profile::Android),
            ("macos", Profile::MacOs),
            ("ios", Profile::Ios),
        ] {
            assert_eq!(name.parse::<Profile>(), Ok(profile));
            assert_eq!(profile.to_string(), name);
        }
        assert!("native".parse::<Profile>().is_err());
        assert!("Windows".parse::<Profile>().is_err());
        assert!("freebsd".parse::<Profile>().is_err());
    }

    #[test]
    fn profiles_match_the_upstream_platform_families() {
        for (profile, expected) in [
            (Profile::Windows, (128, 64_240, 8, 12)),
            (Profile::Linux, (64, 65_535, 7, 20)),
            (Profile::Android, (64, 65_535, 7, 20)),
            (Profile::MacOs, (64, 65_535, 6, 24)),
            (Profile::Ios, (64, 65_535, 6, 24)),
        ] {
            let settings = profile.settings();
            assert_eq!(
                (
                    settings.hop_limit,
                    settings.tcp_window,
                    settings.tcp_window_scale,
                    settings.options_len,
                ),
                expected
            );
            assert_eq!(settings.traffic_class, 0x10);
            assert_eq!(settings.tcp_mss(IpVersion::V4), 1_460);
            assert_eq!(settings.tcp_mss(IpVersion::V6), 1_440);
            assert!(settings.ipv4_df);
        }
    }

    #[test]
    fn encoded_profile_keeps_the_complete_syn_layout() {
        let windows = encode_profile_for_test(Profile::Windows, IpVersion::V4);
        assert_eq!(
            &windows[..12],
            &[128, 0x10, 0xfa, 0xf0, 0x05, 0xb4, 8, 5, 12, 2, 255, 7]
        );
        assert_eq!(&windows[12..24], &[2, 4, 5, 180, 1, 3, 3, 8, 1, 1, 4, 2]);

        let linux = encode_profile_for_test(Profile::Linux, IpVersion::V4);
        assert_eq!(
            &linux[..12],
            &[64, 0x10, 0xff, 0xff, 0x05, 0xb4, 7, 7, 20, 2, 8, 19]
        );
        assert_eq!(
            &linux[12..32],
            &[
                2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7
            ]
        );

        let linux_v6 = encode_profile_for_test(Profile::Linux, IpVersion::V6);
        assert_eq!(&linux_v6[4..6], &1_440_u16.to_be_bytes());
        assert_eq!(&linux_v6[14..16], &1_440_u16.to_be_bytes());
    }

    #[test]
    fn absence_is_the_only_native_selection() {
        let config = config().expect("empty runtime profile config is valid");
        assert!(config.is_native(None));
        assert!(!config.is_native(Some(Profile::Windows)));
    }

    #[tokio::test]
    async fn absent_backend_rejects_presets_before_mutating_native_socket() -> io::Result<()> {
        let config = config()?;
        let socket = TcpSocket::new_v4()?;
        let before = socket2::SockRef::from(&socket);
        let ttl = before.ttl_v4()?;
        let receive_buffer = before.recv_buffer_size()?;
        config.apply(&socket, IpVersion::V4, None)?;
        let _native_guard = config.register(&socket, IpVersion::V4, None)?;
        assert_eq!(
            config
                .apply(&socket, IpVersion::V4, Some(Profile::Windows))
                .expect_err("no partial preset")
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert!(
            matches!(config.register(&socket, IpVersion::V4, Some(Profile::Windows)),
            Err(error) if error.kind() == io::ErrorKind::Unsupported)
        );
        assert_eq!(before.ttl_v4()?, ttl);
        assert_eq!(before.recv_buffer_size()?, receive_buffer);
        Ok(())
    }
}
