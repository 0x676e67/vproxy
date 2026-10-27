#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
#![deny(unsafe_code)]

//! Linux TC egress program embedded into the `vproxy` userspace binary.
//!
//! This is not a separately operated service. `build.rs` compiles it for
//! the host-endian `bpf{el,eb}-unknown-none` target in release mode, and the
//! userspace loader embeds the ELF object. Before `connect(2)`, userspace records
//! an audited profile under the
//! socket cookie; this classifier sees the initial SYN, verifies that changing
//! its wire layout will not disagree with Linux TCP state, and then updates the
//! IP/TCP fields, lengths, and checksums as one fail-closed operation.
//!
//! The parser is deliberately bounded for the eBPF verifier: Ethernet with at
//! most two inline VLAN tags, unfragmented IPv4 or IPv6 without extension
//! headers, and a payload-free initial SYN. Frames outside that scope remain
//! unchanged. Once a registered SYN is accepted for mutation, any compatibility
//! or helper failure drops it so a partial profile never reaches the network.

use aya_ebpf::{
    EbpfContext,
    bindings::{
        BPF_F_NO_PREALLOC, BPF_F_PSEUDO_HDR, BPF_F_RECOMPUTE_CSUM, TC_ACT_SHOT, TC_ACT_UNSPEC,
    },
    helpers::{bpf_get_socket_cookie, bpf_skb_change_tail},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};

// Host tests include the production userspace encoder directly. This is not
// part of the BPF object: it prevents the separately compiled encoder and fixed
// kernel validator from drifting while keeping the runtime ABI as plain bytes.
#[cfg(test)]
#[path = "../ebpf.rs"]
#[allow(
    dead_code,
    reason = "the contract test includes the complete userspace module but exercises only its production encoder"
)]
mod userspace_ebpf;

// The map-value layout is a private ABI shared with `src/ebpf.rs`. Keep these
// sizes and flag bits synchronized with the userspace encoder.
// This is the ELF's standalone default. `Engine::load` rewrites `max_entries`
// from operator configuration before BPF_PROG_LOAD, then validates the loaded
// map capacity and ABI before attaching the classifier.
const SOCKET_PROFILE_CAPACITY: u32 = 65_536;
const PROFILE_VALUE_LEN: usize = 52;
const PROFILE_OPTIONS_OFFSET: usize = 12;
// The ABI reserves TCP's full 40-byte option capacity, but the built-in
// whitelist emits at most the 24-byte Darwin layout. Keeping that tighter bound
// separate makes dynamic map-value indices provably in-bounds to the verifier.
const PROFILE_OPTIONS_LEN: usize = 40;
const PROFILE_TEMPLATE_MAX_LEN: usize = 24;
const INVALID_OPTION_OFFSET: u8 = u8::MAX;
const PROFILE_FLAG_IPV4_DF: u8 = 1 << 0;
const PROFILE_FLAG_TCP_TIMESTAMPS: u8 = 1 << 1;
const PROFILE_FLAG_DERIVE_IPV4_ID: u8 = 1 << 2;
const PROFILE_FLAGS: u8 =
    PROFILE_FLAG_IPV4_DF | PROFILE_FLAG_TCP_TIMESTAMPS | PROFILE_FLAG_DERIVE_IPV4_ID;

// Wire offsets are spelled out instead of casting packet bytes to C structs.
// Aya's skb load/store helpers then provide verifier-visible bounds checks and
// avoid alignment assumptions on VLAN, IPv4, IPv6, or TCP headers.
const ETHERNET_HEADER_LEN: usize = 14;
const ETHERNET_PROTOCOL_OFFSET: usize = 12;
const VLAN_HEADER_LEN: usize = 4;
const VLAN_INNER_PROTOCOL_OFFSET: usize = 2;
const ETHERNET_PROTOCOL_802_1Q: u16 = 0x8100;
const ETHERNET_PROTOCOL_802_1AD: u16 = 0x88a8;
const ETHERNET_PROTOCOL_IPV4: u16 = 0x0800;
const ETHERNET_PROTOCOL_IPV6: u16 = 0x86dd;

const IPV4_VERSION_IHL_OFFSET: usize = 0;
const IPV4_TOTAL_LENGTH_OFFSET: usize = 2;
const IPV4_ID_OFFSET: usize = 4;
const IPV4_FRAGMENT_OFFSET: usize = 6;
const IPV4_TTL_PROTOCOL_OFFSET: usize = 8;
const IPV4_PROTOCOL_OFFSET: usize = 9;
const IPV4_CHECKSUM_OFFSET: usize = 10;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_RESERVED_FLAG: u16 = 0x8000;
const IPV4_DF_FLAG: u16 = 0x4000;
const IPV4_FRAGMENTED_MASK: u16 = 0x3fff;
// Family-specific MSS values for the built-in 1500-byte Ethernet baseline.
// The packet parser checks the actual IP version before accepting either value.
const PROFILE_MSS_IPV4: u16 = 1_460;
const PROFILE_MSS_IPV6: u16 = 1_440;

const IPV6_VERSION_TRAFFIC_FLOW_OFFSET: usize = 0;
const IPV6_PAYLOAD_LENGTH_OFFSET: usize = 4;
const IPV6_NEXT_HEADER_OFFSET: usize = 6;
const IPV6_HOP_LIMIT_OFFSET: usize = 7;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_FLOW_LABEL_MASK: u32 = 0x000f_ffff;

const IP_PROTOCOL_TCP: u8 = 6;
const TCP_SEQUENCE_OFFSET: usize = 4;
const TCP_DATA_OFFSET_OFFSET: usize = 12;
const TCP_FLAGS_OFFSET: usize = 13;
#[cfg(test)]
const TCP_WINDOW_OFFSET: usize = 14;
const TCP_CHECKSUM_OFFSET: usize = 16;
const TCP_OPTIONS_OFFSET: usize = 20;
const TCP_MIN_HEADER_LEN: usize = 20;
const TCP_MAX_HEADER_LEN: usize = 60;
const TCP_MIN_DATA_OFFSET: u8 = 5;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_URG: u8 = 0x20;
// ECE and CWR are valid on the first SYN for ECN negotiation. Every other
// control flag except SYN is excluded from this narrow rewrite path.
const TCP_INITIAL_SYN_PROHIBITED_FLAGS: u8 =
    TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_PSH | TCP_FLAG_ACK | TCP_FLAG_URG;
// The checksum loop must cover all ten words of the source SYN's protocol-wide
// 40-byte option capacity, including words removed by a shorter target profile.
// `store_tcp_rewrite` stops at the target length, but `update_tcp_checksum` must
// still subtract every old word. This fixed bound is also verifier-visible.
const TCP_OPTION_WORDS: usize = PROFILE_OPTIONS_LEN / 4;

// The low four flag bits accepted by bpf_l3_csum_replace and
// bpf_l4_csum_replace encode the old/new operand width in bytes.
const CHECKSUM_REPLACE_U16: u64 = 2;
const CHECKSUM_REPLACE_U32: u64 = 4;
const TCP_OPTION_NOP: u8 = 1;
const TCP_OPTION_MSS: u8 = 2;
const TCP_OPTION_WINDOW_SCALE: u8 = 3;
const TCP_OPTION_SACK_PERMITTED: u8 = 4;
const TCP_OPTION_TIMESTAMP: u8 = 8;

// vproxy creates an ordinary Linux active-open socket. This source recognizer
// accepts only MSS, SACK, and Window Scale as emitted by that path. With
// Timestamp enabled, Linux `tcp_options_write` uses this stable 20-byte sequence:
//
//   MSS(4), SACK-Permitted(2), Timestamp(10), NOP(1), Window-Scale(3)
//
// With Timestamp disabled it emits 12 bytes:
//
//   MSS(4), NOP(2), SACK-Permitted(2), NOP(1), Window-Scale(3)
//
// Matching at most five fixed 32-bit words is intentional. A variable-offset
// TCP-option loop multiplies verifier states until BPF_PROG_LOAD reaches the
// one-million-instruction complexity limit. MD5/AO, MPTCP/SMC, cgroup sockops
// header options, a payload-free Fast Open option, or disabled SACK/Window Scale
// change this source layout and make a registered SYN fail closed. A SYN with
// ACK or Fast Open data is rejected earlier as an unsupported frame and remains
// unchanged.
// See Linux `tcp_options_write` and `tcp_syn_options`:
// https://github.com/torvalds/linux/blob/v6.18/net/ipv4/tcp_output.c
const SOURCE_OPTIONS_WITH_TIMESTAMP_LEN: usize = 20;
const SOURCE_OPTIONS_WITHOUT_TIMESTAMP_LEN: usize = 12;
const SOURCE_MSS_PREFIX: u16 = u16::from_be_bytes([TCP_OPTION_MSS, 4]);
const SOURCE_SACK_TIMESTAMP_PREFIX: u32 =
    u32::from_be_bytes([TCP_OPTION_SACK_PERMITTED, 2, TCP_OPTION_TIMESTAMP, 10]);
const SOURCE_PADDED_SACK: u32 =
    u32::from_be_bytes([TCP_OPTION_NOP, TCP_OPTION_NOP, TCP_OPTION_SACK_PERMITTED, 2]);
const SOURCE_WINDOW_SCALE_PREFIX: u32 =
    u32::from_be_bytes([0, TCP_OPTION_NOP, TCP_OPTION_WINDOW_SCALE, 3]);

/// Endian-neutral userspace-to-eBPF map value described by `SOCKET_PROFILES`.
type EncodedProfile = [u8; PROFILE_VALUE_LEN];

/// Scalar return encoding shared by option-word helpers.
///
/// Bit 32 marks success and bits 0..31 carry a network-order word. A plain
/// `u64` returns through BPF R0; Rust `Option<u32>` or `Result<u32, _>` may use
/// a hidden caller-stack pointer that the verifier rejects across subprograms.
const OPTION_WORD_VALID: u64 = 1_u64 << 32;

/// Maps the kernel socket cookie of one outbound connection to its built-in
/// profile. Userspace installs the entry before `connect(2)` can emit a SYN.
///
/// The 52-byte value is the ABI shared with `src/ebpf.rs`:
///
/// - `0`: IPv4 TTL / IPv6 Hop Limit, in hops;
/// - `1`: IPv4 TOS / IPv6 Traffic Class;
/// - `2..4`: TCP window and `4..6`: MSS, both big-endian `u16`;
/// - `6`: Window Scale shift count, `7`: feature bits;
/// - `8`: option length in bytes (`12`, `20`, or `24`);
/// - `9..12`: value offsets for MSS, Timestamp, and Window Scale, relative to
///   the option area; `255` means that Timestamp is absent;
/// - `12..52`: the TCP option template followed by zero padding.
///
/// Flag bit 0 selects IPv4 DF, bit 1 says the template contains Timestamp, and
/// bit 2 derives the initial IPv4 ID from this connection. A byte array makes
/// those offsets explicit without adding an unsafe `Pod` implementation.
/// Storing these bytes only records an intended profile; it becomes an on-wire
/// SYN profile only after `prepare_rewrite` accepts the kernel-generated state
/// and every mutation helper succeeds.
///
/// The default 65,536 entries are an ELF placeholder; userspace rewrites and
/// validates `max_entries` before load. One entry remains live across initial
/// SYN retransmissions and its RAII guard removes it when `connect(2)` finishes
/// or is canceled. Cookie zero is the helper's no-associated-socket sentinel
/// and is never a map key.
#[map]
pub static SOCKET_PROFILES: HashMap<u64, EncodedProfile> =
    HashMap::with_max_entries(SOCKET_PROFILE_CAPACITY, BPF_F_NO_PREALLOC);

/// Rewrites registered outbound, payload-free initial SYN packets at TC egress.
///
/// Non-target frames and cookie map misses continue to later classifiers with
/// `TC_ACT_UNSPEC`. That value is `-1`, which is both the classic TC
/// "unspecified/continue" action and TCX's `TCX_NEXT`. A registered profile that
/// fails any compatibility check before mutation, or any helper call after
/// mutation starts, returns `TC_ACT_SHOT` (`2`, also TCX drop) so neither a
/// mismatched nor partially rewritten SYN reaches the wire.
///
/// The numeric action ABI is defined by Linux
/// [`pkt_cls.h`](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/pkt_cls.h)
/// and the TCX return values in
/// [`bpf.h`](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/bpf.h).
#[classifier]
pub fn apply_profile(ctx: TcContext) -> i32 {
    let rewrite = match prepare_rewrite(&ctx) {
        Ok(Some(rewrite)) => rewrite,
        Ok(None) => return TC_ACT_UNSPEC,
        Err(()) => return TC_ACT_SHOT,
    };

    if apply_rewrite(&ctx, &rewrite).is_err() {
        // A failed helper after the mutation phase starts must not release a
        // partially rewritten SYN onto the wire.
        TC_ACT_SHOT
    } else {
        TC_ACT_UNSPEC
    }
}

/// A validated view of one userspace-created profile map value.
///
/// The reference points into a `BPF_F_NO_PREALLOC` hash-map entry and never
/// escapes this classifier invocation. With preallocation, a concurrently
/// removed element can be recycled for another key while a borrowed Aya value
/// is still in use. Non-preallocated deletion is RCU-deferred, which makes this
/// short-lived reference safe. Userspace rewrites the map capacity before load
/// and validates the map type, widths, capacity, and `NO_PREALLOC` flag before
/// attaching the program. Borrowing rather than copying all 52 bytes also
/// matters because TC programs have only 512 bytes of BPF stack.
#[derive(Clone, Copy)]
struct Profile<'a> {
    /// Borrowed, endian-neutral map value; it never escapes this invocation.
    encoded: &'a EncodedProfile,
}

impl<'a> Profile<'a> {
    /// Accepts only ABI values whose scalar fields, option bytes, and recorded
    /// value offsets describe the same bounded TCP option sequence.
    fn decode(encoded: &'a EncodedProfile) -> Option<Self> {
        let profile = Self { encoded };
        profile.is_valid().then_some(profile)
    }

    /// Returns ABI byte 0, in router hops.
    const fn hop_limit(self) -> u8 {
        self.encoded[0]
    }

    /// Returns the full DS/Traffic Class octet from ABI byte 1.
    const fn traffic_class(self) -> u8 {
        self.encoded[1]
    }

    /// Decodes the unscaled SYN Window field from ABI bytes 2..4.
    const fn tcp_window(self) -> u16 {
        u16::from_be_bytes([self.encoded[2], self.encoded[3]])
    }

    /// Decodes the advertised MSS from ABI bytes 4..6.
    const fn tcp_mss(self) -> u16 {
        u16::from_be_bytes([self.encoded[4], self.encoded[5]])
    }

    /// Returns the RFC 7323 Window Scale shift count from ABI byte 6.
    const fn tcp_window_scale(self) -> u8 {
        self.encoded[6]
    }

    /// Returns the validated feature-bit octet from ABI byte 7.
    const fn flags(self) -> u8 {
        self.encoded[7]
    }

    /// Returns the emitted TCP option length, excluding ABI padding.
    const fn options_len(self) -> usize {
        self.encoded[8] as usize
    }

    /// Returns the option-relative offset of the two MSS payload bytes.
    const fn mss_value_offset(self) -> u8 {
        self.encoded[9]
    }

    /// Returns the option-relative start of the eight TSval/TSecr bytes, or
    /// `INVALID_OPTION_OFFSET` when Timestamp is absent.
    const fn timestamp_value_offset(self) -> u8 {
        self.encoded[10]
    }

    /// Returns the option-relative offset of the Window Scale shift byte.
    const fn window_scale_value_offset(self) -> u8 {
        self.encoded[11]
    }

    /// Tests whether the target IPv4 SYN carries Don't Fragment.
    const fn ipv4_df(self) -> bool {
        self.flags() & PROFILE_FLAG_IPV4_DF != 0
    }

    /// Tests whether the target template contains an RFC 7323 Timestamp.
    const fn tcp_timestamps(self) -> bool {
        self.flags() & PROFILE_FLAG_TCP_TIMESTAMPS != 0
    }

    /// Tests whether the initial IPv4 ID is derived per connection.
    const fn derive_ipv4_id(self) -> bool {
        self.flags() & PROFILE_FLAG_DERIVE_IPV4_ID != 0
    }

    /// Reads one byte from the audited prefix of the fixed 40-byte ABI area.
    ///
    /// The ABI reserves TCP's full option capacity, but every built-in template
    /// is at most 24 bytes. `inline(never)` is part of the verifier contract here:
    /// it keeps the range check in the same BPF subprogram as the map load. When
    /// this function is inlined into a 40-byte packet loop, LLVM can discard the
    /// tighter check using Rust-level facts that do not survive as verifier
    /// instructions. The caller still checks the logical option length because
    /// bytes after it are zero ABI padding, not TCP header bytes.
    #[inline(never)]
    fn option(self, index: usize) -> Option<u8> {
        if index >= PROFILE_TEMPLATE_MAX_LEN {
            return None;
        }
        Some(self.encoded[PROFILE_OPTIONS_OFFSET + index])
    }

    /// Reads one of the ten fixed option words through a scalar BPF return ABI.
    ///
    /// `inline(never)` keeps the word-index range check beside all four map
    /// loads. The scalar success bit avoids Rust's aggregate return convention,
    /// which can expose a caller-stack pointer across a BPF-to-BPF call.
    #[inline(never)]
    fn option_word(self, word_index: usize) -> u64 {
        if word_index >= TCP_OPTION_WORDS {
            return 0;
        }
        let byte_index = word_index * 4;
        OPTION_WORD_VALID
            | u64::from(u32::from_be_bytes([
                self.encoded[PROFILE_OPTIONS_OFFSET + byte_index],
                self.encoded[PROFILE_OPTIONS_OFFSET + byte_index + 1],
                self.encoded[PROFILE_OPTIONS_OFFSET + byte_index + 2],
                self.encoded[PROFILE_OPTIONS_OFFSET + byte_index + 3],
            ]))
    }

    /// Matches the complete Windows built-in, including unused zero words.
    fn is_windows(self) -> bool {
        let [mss_high, mss_low] = self.tcp_mss().to_be_bytes();
        self.hop_limit() == 128
            && self.traffic_class() == 0x10
            && self.tcp_window() == 64_240
            && matches!(self.tcp_mss(), PROFILE_MSS_IPV4 | PROFILE_MSS_IPV6)
            && self.tcp_window_scale() == 8
            && self.flags() == (PROFILE_FLAG_IPV4_DF | PROFILE_FLAG_DERIVE_IPV4_ID)
            && self.options_len() == 12
            && self.mss_value_offset() == 2
            && self.timestamp_value_offset() == INVALID_OPTION_OFFSET
            && self.window_scale_value_offset() == 7
            && self.option_word(0)
                == OPTION_WORD_VALID | u64::from(u32::from_be_bytes([2, 4, mss_high, mss_low]))
            && self.option_word(1)
                == OPTION_WORD_VALID | u64::from(u32::from_be_bytes([1, 3, 3, 8]))
            && self.option_word(2)
                == OPTION_WORD_VALID | u64::from(u32::from_be_bytes([1, 1, 4, 2]))
            && self.option_word(3) == OPTION_WORD_VALID
            && self.option_word(4) == OPTION_WORD_VALID
            && self.option_word(5) == OPTION_WORD_VALID
            && self.option_word(6) == OPTION_WORD_VALID
            && self.option_word(7) == OPTION_WORD_VALID
            && self.option_word(8) == OPTION_WORD_VALID
            && self.option_word(9) == OPTION_WORD_VALID
    }

    /// Matches the complete Linux/Android built-in, including zero Timestamp
    /// placeholders and unused ABI words.
    fn is_linux(self) -> bool {
        let [mss_high, mss_low] = self.tcp_mss().to_be_bytes();
        self.hop_limit() == 64
            && self.traffic_class() == 0x10
            && self.tcp_window() == 65_535
            && matches!(self.tcp_mss(), PROFILE_MSS_IPV4 | PROFILE_MSS_IPV6)
            && self.tcp_window_scale() == 7
            && self.flags() == PROFILE_FLAGS
            && self.options_len() == 20
            && self.mss_value_offset() == 2
            && self.timestamp_value_offset() == 8
            && self.window_scale_value_offset() == 19
            && self.option_word(0)
                == OPTION_WORD_VALID | u64::from(u32::from_be_bytes([2, 4, mss_high, mss_low]))
            && self.option_word(1)
                == OPTION_WORD_VALID | u64::from(u32::from_be_bytes([4, 2, 8, 10]))
            && self.option_word(2) == OPTION_WORD_VALID
            && self.option_word(3) == OPTION_WORD_VALID
            && self.option_word(4)
                == OPTION_WORD_VALID | u64::from(u32::from_be_bytes([1, 3, 3, 7]))
            && self.option_word(5) == OPTION_WORD_VALID
            && self.option_word(6) == OPTION_WORD_VALID
            && self.option_word(7) == OPTION_WORD_VALID
            && self.option_word(8) == OPTION_WORD_VALID
            && self.option_word(9) == OPTION_WORD_VALID
    }

    /// Matches the complete macOS/iOS built-in, including its EOL byte, one
    /// zero alignment byte, zero Timestamp placeholders, and unused ABI words.
    fn is_darwin(self) -> bool {
        let [mss_high, mss_low] = self.tcp_mss().to_be_bytes();
        self.hop_limit() == 64
            && self.traffic_class() == 0x10
            && self.tcp_window() == 65_535
            && matches!(self.tcp_mss(), PROFILE_MSS_IPV4 | PROFILE_MSS_IPV6)
            && self.tcp_window_scale() == 6
            && self.flags() == PROFILE_FLAGS
            && self.options_len() == 24
            && self.mss_value_offset() == 2
            && self.timestamp_value_offset() == 12
            && self.window_scale_value_offset() == 7
            && self.option_word(0)
                == OPTION_WORD_VALID | u64::from(u32::from_be_bytes([2, 4, mss_high, mss_low]))
            && self.option_word(1)
                == OPTION_WORD_VALID | u64::from(u32::from_be_bytes([1, 3, 3, 6]))
            && self.option_word(2)
                == OPTION_WORD_VALID | u64::from(u32::from_be_bytes([1, 1, 8, 10]))
            && self.option_word(3) == OPTION_WORD_VALID
            && self.option_word(4) == OPTION_WORD_VALID
            && self.option_word(5)
                == OPTION_WORD_VALID | u64::from(u32::from_be_bytes([4, 2, 0, 0]))
            && self.option_word(6) == OPTION_WORD_VALID
            && self.option_word(7) == OPTION_WORD_VALID
            && self.option_word(8) == OPTION_WORD_VALID
            && self.option_word(9) == OPTION_WORD_VALID
    }

    /// Accepts only one of the three exact built-in wire layouts.
    ///
    /// Linux/Android and macOS/iOS intentionally share layouts. The only
    /// family-dependent scalar is MSS, which is 1460 for IPv4 or 1440 for IPv6.
    /// Fixed word checks avoid repeatedly walking untrusted map bytes, which
    /// multiplies verifier states when combined with the source SYN parser.
    /// Timestamp value words must be zero in the map; `target_option_byte`
    /// replaces them with the source TCP stack's TSval/TSecr before emission.
    fn is_valid(self) -> bool {
        match self.options_len() {
            12 => self.is_windows(),
            20 => self.is_linux(),
            24 => self.is_darwin(),
            _ => false,
        }
    }
}

/// Semantic fields recovered from one validated SYN option sequence.
///
/// Every byte is initialized in both source layouts. Linux 6.1's verifier does
/// not always prove that the inactive payload of a Rust `Option<[u8; 8]>` is
/// unreachable when LLVM copies the surrounding aggregate. Keeping an explicit
/// presence byte and a zero-filled value for the no-Timestamp layout avoids an
/// otherwise harmless read from uninitialized inactive payload storage.
/// Timestamp bytes remain raw so this parser does not invent an endian
/// interpretation for values owned by Linux.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(C)]
struct ParsedTcpOptions {
    /// Raw TSval followed by TSecr; all zero when Timestamp was not offered.
    timestamp: [u8; 8],
    /// Advertised MSS extracted from the first fixed option word.
    mss: u16,
    /// Window Scale shift count extracted from the last fixed option word.
    window_scale: u8,
    /// One when `timestamp` came from a Timestamp option, otherwise zero.
    timestamp_present: u8,
}

// This guards the old-verifier contract above: every byte of the aggregate is
// represented by an initialized field, with no tail padding for LLVM to copy.
const _: () = assert!(core::mem::size_of::<ParsedTcpOptions>() == 12);

/// Validates the exact ordinary-Linux option layout used by vproxy sockets and
/// extracts the three connection-specific values without copying a TCP header.
///
/// The first word contains the dynamic MSS and the low byte of the final word
/// contains the dynamic Window Scale. In the 20-byte layout, words two and three
/// also contain the dynamic TSval/TSecr. Every kind, length, and alignment byte
/// around those values is compared with Linux's fixed sequence. SACK-Permitted
/// is therefore a structural guarantee rather than a boolean in the result.
///
/// This narrow recognizer is also a verifier contract: five constant-offset skb
/// loads have a small finite state space, whereas a protocol-general option
/// iterator exceeded Linux's verifier complexity budget even with an eight-step
/// bound. A different but valid RFC 9293 option sequence is not partially
/// understood; for a registered SYN it is rejected before mutation and dropped.
#[inline(always)]
fn parse_source_options(
    ctx: &TcContext,
    tcp_offset: usize,
    tcp_header_len: usize,
) -> Result<ParsedTcpOptions, ()> {
    let options_len = tcp_header_len.checked_sub(TCP_OPTIONS_OFFSET).ok_or(())?;
    let options_offset = tcp_offset.checked_add(TCP_OPTIONS_OFFSET).ok_or(())?;
    let mss_word = load_be_u32_at(ctx, options_offset, 0)?;
    if mss_word >> 16 != u32::from(SOURCE_MSS_PREFIX) {
        return Err(());
    }

    match options_len {
        SOURCE_OPTIONS_WITH_TIMESTAMP_LEN => {
            let sack_timestamp_prefix = load_be_u32_at(ctx, options_offset, 4)?;
            let timestamp_high = load_be_u32_at(ctx, options_offset, 8)?;
            let timestamp_low = load_be_u32_at(ctx, options_offset, 12)?;
            let window_scale_word = load_be_u32_at(ctx, options_offset, 16)?;
            if sack_timestamp_prefix != SOURCE_SACK_TIMESTAMP_PREFIX
                || window_scale_word >> 8 != SOURCE_WINDOW_SCALE_PREFIX
            {
                return Err(());
            }

            let [timestamp_0, timestamp_1, timestamp_2, timestamp_3] = timestamp_high.to_be_bytes();
            let [timestamp_4, timestamp_5, timestamp_6, timestamp_7] = timestamp_low.to_be_bytes();
            Ok(ParsedTcpOptions {
                timestamp: [
                    timestamp_0,
                    timestamp_1,
                    timestamp_2,
                    timestamp_3,
                    timestamp_4,
                    timestamp_5,
                    timestamp_6,
                    timestamp_7,
                ],
                mss: mss_word as u16,
                window_scale: window_scale_word as u8,
                timestamp_present: 1,
            })
        }
        SOURCE_OPTIONS_WITHOUT_TIMESTAMP_LEN => {
            let padded_sack = load_be_u32_at(ctx, options_offset, 4)?;
            let window_scale_word = load_be_u32_at(ctx, options_offset, 8)?;
            if padded_sack != SOURCE_PADDED_SACK
                || window_scale_word >> 8 != SOURCE_WINDOW_SCALE_PREFIX
            {
                return Err(());
            }
            Ok(ParsedTcpOptions {
                timestamp: [0; 8],
                mss: mss_word as u16,
                window_scale: window_scale_word as u8,
                timestamp_present: 0,
            })
        }
        _ => Err(()),
    }
}

/// Network-layer fields captured before any helper mutates the skb.
///
/// Only unfragmented IPv4 and IPv6 with TCP as the immediate next header are
/// represented. IPv6 extension-header chains deliberately remain unchanged.
#[derive(Clone, Copy)]
enum NetworkPacket {
    /// IPv4 header fields that participate in the rewrite or its checksum.
    Ipv4 {
        /// Absolute byte offset of the IPv4 header in the Ethernet frame.
        ip_offset: usize,
        /// IPv4 header length in bytes, including any preserved IP options.
        header_len: usize,
        /// Original IPv4 Total Length in host byte order.
        total_len: u16,
        /// Original Version/IHL and TOS octets treated as one checksum word.
        version_tos: u16,
        /// Original IPv4 Identification field.
        id: u16,
        /// Original flags and fragment-offset checksum word.
        fragment: u16,
        /// Original TTL and Protocol octets treated as one checksum word.
        ttl_protocol: u16,
    },
    /// Fixed IPv6 header fields needed for the payload-length rewrite.
    Ipv6 {
        /// Absolute byte offset of the fixed IPv6 header.
        ip_offset: usize,
        /// Original Version, Traffic Class, and Flow Label word.
        version_traffic_flow: u32,
    },
}

/// A fully bounded, payload-free initial SYN and its byte offsets in the skb.
/// `frame_len` includes Ethernet and up to two VLAN headers.
#[derive(Clone, Copy)]
struct InitialSynPacket {
    /// Parsed IP-family-specific fields captured before mutation.
    network: NetworkPacket,
    /// Absolute byte offset of the TCP header.
    tcp_offset: usize,
    /// Original TCP header length in bytes, including options.
    tcp_header_len: usize,
    /// Complete skb length before any tail resize.
    frame_len: u32,
}

/// Identifies which fully initialized field group in `NetworkRewrite` is used.
///
/// The explicit one-byte representation occupies the last byte of the
/// padding-free C layout below. It is an internal construction tag, not a wire
/// value or userspace ABI.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
enum NetworkVersion {
    /// Use the IPv4 checksum-word fields.
    Ipv4 = 4,
    /// Use the IPv6 fixed-header fields.
    Ipv6 = 6,
}

/// Old and target IP fields needed for incremental checksum updates.
///
/// This is a single, fully initialized, padding-free C layout rather than a
/// Rust enum with different-sized variant payloads. LLVM may copy an enum's
/// whole union storage even though only the active variant will later read it.
/// Linux 6.18 can prove that such an inactive read is harmless, but Linux 6.1
/// rejects the generated load as an uninitialized BPF stack access. The fields
/// for the other address family are therefore explicitly zeroed by each
/// constructor. Field order is deliberate: 8 + 4 + 4 + eleven 2-byte fields +
/// two 1-byte fields is exactly 40 bytes on the 64-bit BPF target, with no
/// implicit padding for LLVM to copy.
#[derive(Clone, Copy)]
#[repr(C)]
struct NetworkRewrite {
    /// Absolute offset of the IPv4 or IPv6 header in the Ethernet frame.
    ip_offset: usize,
    /// Original IPv6 Version, Traffic Class, and Flow Label word; zero for IPv4.
    old_version_traffic_flow: u32,
    /// Target IPv6 Traffic Class with Version and Flow Label preserved; zero for IPv4.
    new_version_traffic_flow: u32,
    /// Original IPv4 Version/IHL plus TOS checksum word; zero for IPv6.
    old_version_tos: u16,
    /// Target IPv4 Version/IHL plus TOS checksum word; zero for IPv6.
    new_version_tos: u16,
    /// Original IPv4 Total Length; zero for IPv6.
    old_total_len: u16,
    /// IPv4 Total Length after resizing the TCP option area; zero for IPv6.
    new_total_len: u16,
    /// Kernel-selected IPv4 Identification; zero for IPv6.
    old_id: u16,
    /// Per-connection IPv4 Identification; zero for IPv6.
    new_id: u16,
    /// Original IPv4 flags and fragment-offset checksum word; zero for IPv6.
    old_fragment: u16,
    /// Target IPv4 flags and fragment-offset word; zero for IPv6.
    new_fragment: u16,
    /// Original IPv4 TTL and Protocol checksum word; zero for IPv6.
    old_ttl_protocol: u16,
    /// Target IPv4 TTL with the original Protocol octet; zero for IPv6.
    new_ttl_protocol: u16,
    /// IPv6 Payload Length after resizing the TCP option area; zero for IPv4.
    new_payload_len: u16,
    /// Target IPv6 Hop Limit; zero for IPv4.
    new_hop_limit: u8,
    /// Selects the IPv4 or IPv6 fields above.
    version: NetworkVersion,
}

// eBPF uses 64-bit pointers. Failing this assertion would mean the documented
// padding-free layout changed and must be re-audited on the oldest verifier.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<NetworkRewrite>() == 40);

/// A rewrite plan produced entirely before packet mutation starts.
///
/// It stores only semantic state and a borrowed profile. In particular, it
/// does not keep old/new 60-byte TCP headers on the 512-byte BPF stack. The
/// apply phase reads each old 32-bit option word before resizing the skb.
#[derive(Clone, Copy)]
struct Rewrite<'a> {
    /// Borrowed, validated target profile map entry.
    profile: Profile<'a>,
    /// Precomputed network-layer old/new values.
    network: NetworkRewrite,
    /// Absolute offset of the TCP header in the skb.
    tcp_offset: usize,
    /// Kernel-generated TCP header length in bytes.
    old_tcp_header_len: usize,
    /// Profile TCP header length in bytes.
    new_tcp_header_len: usize,
    /// Target TCP bytes 12..16 as one checksum word.
    ///
    /// Data Offset is rebuilt from `new_tcp_header_len`, its four reserved bits
    /// are forced to zero, SYN/ECE/CWR are preserved from the source, and the
    /// 16-bit Window is replaced by the profile value.
    new_tcp_control: u32,
    /// Original TSval/TSecr when Linux offered Timestamp, otherwise eight zero
    /// bytes. Compatibility checks prevent a target Timestamp from using zeros
    /// that did not come from the source SYN.
    timestamp: [u8; 8],
    /// skb length against which the read-only plan was prepared.
    old_frame_len: u32,
    /// Checked skb length passed to `bpf_skb_change_tail`.
    new_frame_len: u32,
}

/// Performs every parse and compatibility check before packet mutation.
///
/// `Ok(None)` means the frame is outside the bounded parser or has no cookie
/// registration, so it remains byte-for-byte unchanged. `Err(())` means a
/// registered profile cannot be applied exactly enough to preserve TCP state;
/// that SYN is dropped instead of silently emitting a partial profile.
fn prepare_rewrite<'a>(ctx: &'a TcContext) -> Result<Option<Rewrite<'a>>, ()> {
    // Established connections have no map entry after connect(2) completes.
    // Check that cheap discriminator first so ordinary egress traffic avoids
    // the bounded Ethernet/IP/TCP parser entirely. Decode stays after parsing:
    // a stale or corrupt value must not turn an unsupported non-SYN frame into
    // a drop.
    let Some((cookie, encoded)) = registered_profile(ctx) else {
        return Ok(None);
    };
    let Ok(packet) = initial_syn_packet(ctx) else {
        return Ok(None);
    };
    let profile = Profile::decode(encoded).ok_or(())?;
    // The private ABI permits the two MSS values used by the IPv4 and IPv6
    // encodings of each preset. Bind that value to the packet parsed here so a
    // userspace family-selection bug cannot authorize the other family's MSS.
    let expected_mss = match packet.network {
        NetworkPacket::Ipv4 { .. } => PROFILE_MSS_IPV4,
        NetworkPacket::Ipv6 { .. } => PROFILE_MSS_IPV6,
    };
    if profile.tcp_mss() != expected_mss {
        return Err(());
    }
    let source = parse_source_options(ctx, packet.tcp_offset, packet.tcp_header_len)?;
    let old_control = load_be_u32_at(ctx, packet.tcp_offset, TCP_DATA_OFFSET_OFFSET)?;
    let [
        _old_data_offset,
        flags,
        source_window_high,
        source_window_low,
    ] = old_control.to_be_bytes();
    let source_window = u16::from_be_bytes([source_window_high, source_window_low]);

    // Window Scale is connection state, not merely a SYN byte. RFC 7323 makes
    // the peer apply the advertised shift to every later window. Only reorder
    // the option when Linux already selected the requested value.
    // https://www.rfc-editor.org/rfc/rfc7323.html#section-2.2
    if source.window_scale != profile.tcp_window_scale() {
        return Err(());
    }

    // Raising the kernel-selected MSS can exceed the route MTU. A profile may
    // lower it, but it must never advertise more than Linux selected. Absence
    // is also rejected: every target template contains MSS, and adding one to a
    // source SYN without it would invent negotiation state the TCP control
    // block did not select.
    // https://www.rfc-editor.org/rfc/rfc6691.html#section-2
    if profile.tcp_mss() > source.mss {
        return Err(());
    }

    // `parse_source_options` accepted the exact word containing
    // SACK-Permitted. Adding it when Linux did not enable SACK would make the
    // peer send SACK blocks the TCP control block did not negotiate. RFC 2018
    // section 2 confines this option to SYN segments.
    // https://www.rfc-editor.org/rfc/rfc2018.html#section-2
    // Timestamp values belong to Linux's PAWS/RTT state. Preserve the value
    // generated for this connection instead of synthesizing an unrelated one.
    // A target without Timestamp may remove Linux's offer: the peer then omits
    // Timestamp from SYN-ACK and Linux completes this connection with the option
    // disabled. The reverse is unsafe because it creates wire state the TCP
    // control block never offered.
    // https://www.rfc-editor.org/rfc/rfc7323.html#section-3.2
    if profile.tcp_timestamps() && source.timestamp_present == 0 {
        return Err(());
    }

    // The raw SYN Window is also receive-side connection state. Shrinking the
    // offer is safe, but increasing it above Linux's value could let the peer
    // send data beyond the kernel's initial advertised credit.
    if profile.tcp_window() > source_window {
        return Err(());
    }

    let new_tcp_header_len = TCP_OPTIONS_OFFSET
        .checked_add(profile.options_len())
        .ok_or(())?;
    let new_frame_len =
        resized_length(packet.frame_len, packet.tcp_header_len, new_tcp_header_len).ok_or(())?;
    let sequence = load_be_u32_at(ctx, packet.tcp_offset, TCP_SEQUENCE_OFFSET)?;
    let entropy = connection_entropy(cookie, sequence);
    let network = network_rewrite(
        packet.network,
        profile,
        packet.tcp_header_len,
        new_tcp_header_len,
        entropy,
    )
    .ok_or(())?;
    let data_offset = u8::try_from(new_tcp_header_len / 4).map_err(|_| ())?;
    let [window_high, window_low] = profile.tcp_window().to_be_bytes();
    let new_tcp_control = u32::from_be_bytes([data_offset << 4, flags, window_high, window_low]);

    Ok(Some(Rewrite {
        profile,
        network,
        tcp_offset: packet.tcp_offset,
        old_tcp_header_len: packet.tcp_header_len,
        new_tcp_header_len,
        new_tcp_control,
        timestamp: source.timestamp,
        old_frame_len: packet.frame_len,
        new_frame_len,
    }))
}

/// Computes network-layer target fields for a payload-free TCP header resize.
///
/// IPv4 Total Length becomes the IPv4 header, including options, plus the new
/// TCP header. IPv6 Payload Length becomes the TCP header alone because this
/// parser accepts no extension headers or SYN data. IPv4 ID derivation is stable
/// for this SYN; taking the low 16 bits of `entropy` matches the field width.
/// The IPv6 Flow Label is always preserved because this cookie entry does not
/// live long enough to rewrite every later packet in the flow.
fn network_rewrite(
    packet: NetworkPacket,
    profile: Profile<'_>,
    old_tcp_header_len: usize,
    new_tcp_header_len: usize,
    entropy: u32,
) -> Option<NetworkRewrite> {
    if old_tcp_header_len < TCP_MIN_HEADER_LEN {
        return None;
    }

    match packet {
        NetworkPacket::Ipv4 {
            ip_offset,
            header_len,
            total_len,
            version_tos,
            id,
            fragment,
            ttl_protocol,
        } => {
            let new_total_len = header_len.checked_add(new_tcp_header_len)?;
            let new_total_len = u16::try_from(new_total_len).ok()?;
            let [version_ihl, _old_tos] = version_tos.to_be_bytes();
            let [_old_ttl, protocol] = ttl_protocol.to_be_bytes();
            let new_id = if profile.derive_ipv4_id() {
                entropy as u16
            } else {
                id
            };
            let new_fragment = if profile.ipv4_df() {
                fragment | IPV4_DF_FLAG
            } else {
                fragment & !IPV4_DF_FLAG
            };

            Some(NetworkRewrite {
                ip_offset,
                old_version_traffic_flow: 0,
                new_version_traffic_flow: 0,
                old_version_tos: version_tos,
                new_version_tos: u16::from_be_bytes([version_ihl, profile.traffic_class()]),
                old_total_len: total_len,
                new_total_len,
                old_id: id,
                new_id,
                old_fragment: fragment,
                new_fragment,
                old_ttl_protocol: ttl_protocol,
                new_ttl_protocol: u16::from_be_bytes([profile.hop_limit(), protocol]),
                new_payload_len: 0,
                new_hop_limit: 0,
                version: NetworkVersion::Ipv4,
            })
        }
        NetworkPacket::Ipv6 {
            ip_offset,
            version_traffic_flow,
        } => {
            let new_payload_len = u16::try_from(new_tcp_header_len).ok()?;
            // RFC 6437 requires one flow label to remain stable for the whole
            // flow. This classifier sees only the initial SYN, so it preserves
            // the kernel-selected label instead of creating a SYN-only value.
            // https://www.rfc-editor.org/rfc/rfc6437.html#section-3
            let flow_label = version_traffic_flow & IPV6_FLOW_LABEL_MASK;
            let new_version_traffic_flow =
                6_u32 << 28 | u32::from(profile.traffic_class()) << 20 | flow_label;

            Some(NetworkRewrite {
                ip_offset,
                old_version_traffic_flow: version_traffic_flow,
                new_version_traffic_flow,
                old_version_tos: 0,
                new_version_tos: 0,
                old_total_len: 0,
                new_total_len: 0,
                old_id: 0,
                new_id: 0,
                old_fragment: 0,
                new_fragment: 0,
                old_ttl_protocol: 0,
                new_ttl_protocol: 0,
                new_payload_len,
                new_hop_limit: profile.hop_limit(),
                version: NetworkVersion::Ipv6,
            })
        }
    }
}

/// Mixes the socket cookie and initial sequence number into a per-connection
/// value for the initial IPv4 ID. This is derivation, not a random-number
/// generator. Using two values that remain fixed for the connection also keeps
/// the ID stable across initial-SYN retransmissions while the map guard lives.
fn connection_entropy(cookie: u64, sequence: u32) -> u32 {
    let mut value = sequence ^ cookie as u32 ^ (cookie >> 32) as u32;
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb_352d);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846c_a68b);
    value ^ value >> 16
}

/// Applies a prepared plan. From the first checksum helper onward every error
/// is fail-closed and the classifier drops the skb, because returning it after
/// only part of the delta sequence could put a malformed SYN on the wire.
///
/// The order is part of the checksum and verifier contract:
///
/// 1. read every old TCP option word and apply the complete TCP plus
///    pseudo-header delta while the original skb bytes still exist;
/// 2. resize the tail, which can reallocate storage and turns
///    `CHECKSUM_COMPLETE` into `CHECKSUM_NONE` while preserving
///    `CHECKSUM_PARTIAL`;
/// 3. write IP fields and lengths against the final skb size;
/// 4. write the target TCP control word and option prefix after its checksum
///    field already contains the corresponding delta.
///
/// Reordering these phases can read trimmed bytes, double-count COMPLETE
/// metadata, or expose a checksum that describes a different packet length.
fn apply_rewrite(ctx: &TcContext, rewrite: &Rewrite<'_>) -> Result<(), ()> {
    if ctx.len() != rewrite.old_frame_len {
        return Err(());
    }

    // Removed option bytes must still participate in the old side of the
    // checksum delta, so update the checksum before shortening the tail.
    update_tcp_checksum(ctx, rewrite)?;
    if rewrite.new_frame_len != rewrite.old_frame_len {
        change_tail(ctx, rewrite.new_frame_len)?;
        if ctx.len() != rewrite.new_frame_len {
            return Err(());
        }
    }

    apply_network_rewrite(ctx, rewrite.network)?;
    store_tcp_rewrite(ctx, rewrite)
}

/// Applies complete old-to-new TCP checksum deltas in 32-bit words.
///
/// Ordinary replacements update the TCP checksum field. The later TCP byte
/// stores use flags zero: their data-field delta and the checksum-field delta
/// cancel in a `CHECKSUM_COMPLETE` raw packet sum. Asking the store helper to
/// recompute metadata would apply only the data half a second time. Linux treats
/// ordinary L4 deltas as no-ops for `CHECKSUM_PARTIAL`, where the device checksums
/// the final bytes. The pseudo-header length delta is separate and is required
/// so the offload seed tracks a 32/40/44-byte TCP SYN.
///
/// Sources: Linux
/// [`bpf_l4_csum_replace`](https://github.com/torvalds/linux/blob/v6.18/net/core/filter.c),
/// the [checksum offload contract](https://docs.kernel.org/networking/checksum-offloads.html),
/// and the kernel's [TC checksum sample](https://github.com/torvalds/linux/blob/v6.18/samples/bpf/tcbpf1_kern.c).
fn update_tcp_checksum(ctx: &TcContext, rewrite: &Rewrite<'_>) -> Result<(), ()> {
    let checksum_offset = rewrite
        .tcp_offset
        .checked_add(TCP_CHECKSUM_OFFSET)
        .ok_or(())?;

    let old_control = load_be_u32_at(ctx, rewrite.tcp_offset, TCP_DATA_OFFSET_OFFSET)?;
    replace_tcp_word(ctx, checksum_offset, old_control, rewrite.new_tcp_control)?;

    let old_options_len = rewrite
        .old_tcp_header_len
        .checked_sub(TCP_OPTIONS_OFFSET)
        .ok_or(())?;
    let new_options_len = rewrite.profile.options_len();
    let options_offset = rewrite
        .tcp_offset
        .checked_add(TCP_OPTIONS_OFFSET)
        .ok_or(())?;
    let mut word_index = 0;
    while word_index < TCP_OPTION_WORDS {
        let byte_index = word_index.checked_mul(4).ok_or(())?;
        let old = if byte_index < old_options_len {
            load_be_u32_at(ctx, options_offset, byte_index)?
        } else {
            0
        };
        let new = if byte_index < new_options_len {
            let encoded = target_option_word(rewrite, byte_index);
            if encoded & OPTION_WORD_VALID == 0 {
                return Err(());
            }
            encoded as u32
        } else {
            0
        };
        replace_tcp_word(ctx, checksum_offset, old, new)?;
        word_index += 1;
    }

    if rewrite.old_tcp_header_len != rewrite.new_tcp_header_len {
        let pseudo_flag = u64::from(BPF_F_PSEUDO_HDR);
        match rewrite.network.version {
            NetworkVersion::Ipv4 => {
                let old = u16::try_from(rewrite.old_tcp_header_len).map_err(|_| ())?;
                let new = u16::try_from(rewrite.new_tcp_header_len).map_err(|_| ())?;
                // IPv4's TCP pseudo-header carries TCP Length as a 16-bit
                // field, so the helper's low flag bits select a two-byte
                // replacement. See RFC 9293 section 3.1.
                // https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1
                ctx.l4_csum_replace(
                    checksum_offset,
                    u64::from(old.to_be()),
                    u64::from(new.to_be()),
                    pseudo_flag | CHECKSUM_REPLACE_U16,
                )
                .map_err(|_| ())?;
            }
            NetworkVersion::Ipv6 => {
                let old = u32::try_from(rewrite.old_tcp_header_len).map_err(|_| ())?;
                let new = u32::try_from(rewrite.new_tcp_header_len).map_err(|_| ())?;
                // IPv6's pseudo-header carries Upper-Layer Packet Length as a
                // 32-bit field, so this delta uses a four-byte replacement.
                // This program accepts no extension headers, making that value
                // exactly the TCP header length. See RFC 8200 section 8.1.
                // https://www.rfc-editor.org/rfc/rfc8200.html#section-8.1
                // Newer UAPI headers define BPF_F_IPV6, but Linux 5.3 does not
                // accept it. The four-byte pseudo-length form used here works on
                // the full supported range; adding the new flag unconditionally
                // would make the helper return EINVAL on older kernels.
                ctx.l4_csum_replace(
                    checksum_offset,
                    u64::from(old.to_be()),
                    u64::from(new.to_be()),
                    pseudo_flag | CHECKSUM_REPLACE_U32,
                )
                .map_err(|_| ())?;
            }
        }
    }

    Ok(())
}

/// Applies one four-byte transport checksum delta. Passing raw network-order
/// scalars (`to_be`) matches the helper ABI on little- and big-endian BPF hosts.
fn replace_tcp_word(ctx: &TcContext, checksum_offset: usize, old: u32, new: u32) -> Result<(), ()> {
    if old == new {
        return Ok(());
    }
    ctx.l4_csum_replace(
        checksum_offset,
        u64::from(old.to_be()),
        u64::from(new.to_be()),
        CHECKSUM_REPLACE_U32,
    )
    .map_err(|_| ())
}

/// Returns one target option byte. Template MSS/WS bytes were validated against
/// their scalar ABI fields. Timestamp bytes are replaced with Linux's original
/// TSval/TSecr so PAWS and RTT state remain coherent after option reordering.
fn target_option_byte(rewrite: &Rewrite<'_>, index: usize) -> Option<u8> {
    if index >= rewrite.profile.options_len() {
        return None;
    }
    if rewrite.profile.tcp_timestamps() {
        let timestamp_offset = usize::from(rewrite.profile.timestamp_value_offset());
        let timestamp_end = timestamp_offset.checked_add(8)?;
        if (timestamp_offset..timestamp_end).contains(&index) {
            let timestamp_index = index.checked_sub(timestamp_offset)?;
            return rewrite.timestamp.get(timestamp_index).copied();
        }
    }
    rewrite.profile.option(index)
}

/// Builds one network-order option word without allocating a complete header.
/// Profile lengths are multiples of four, so a requested word is either fully
/// present or reported as invalid to the checksum caller.
///
/// Rust may lower an aggregate `Result` return through a hidden pointer into the
/// caller's stack even when inlining is requested. A BPF-to-BPF call may return
/// a scalar in R0, but the verifier rejects returning that stack pointer. This
/// helper therefore encodes success in bit 32 and the option word in bits 0..31.
fn target_option_word(rewrite: &Rewrite<'_>, offset: usize) -> u64 {
    let (Some(first), Some(second), Some(third), Some(fourth)) = (
        target_option_byte(rewrite, offset),
        target_option_byte(rewrite, offset + 1),
        target_option_byte(rewrite, offset + 2),
        target_option_byte(rewrite, offset + 3),
    ) else {
        return 0;
    };
    OPTION_WORD_VALID | u64::from(u32::from_be_bytes([first, second, third, fourth]))
}

/// Stores the prepared IP fields after the skb has its final length.
///
/// IPv4 fields go through RFC 1624-style helper deltas before their bytes are
/// stored. IPv6 has no header checksum, so its changed bytes update
/// `CHECKSUM_COMPLETE` metadata through `BPF_F_RECOMPUTE_CSUM`. Updating IPv6
/// Payload Length this way also pairs with the transport pseudo-header delta.
/// See [RFC 1624](https://www.rfc-editor.org/rfc/rfc1624.html) for incremental
/// Internet-checksum replacement, including the negative-zero edge case.
fn apply_network_rewrite(ctx: &TcContext, rewrite: NetworkRewrite) -> Result<(), ()> {
    match rewrite.version {
        NetworkVersion::Ipv4 => {
            replace_ipv4_word(
                ctx,
                rewrite.ip_offset,
                rewrite.ip_offset,
                rewrite.old_version_tos,
                rewrite.new_version_tos,
            )?;
            replace_ipv4_word(
                ctx,
                rewrite.ip_offset,
                rewrite
                    .ip_offset
                    .checked_add(IPV4_TOTAL_LENGTH_OFFSET)
                    .ok_or(())?,
                rewrite.old_total_len,
                rewrite.new_total_len,
            )?;
            replace_ipv4_word(
                ctx,
                rewrite.ip_offset,
                rewrite.ip_offset.checked_add(IPV4_ID_OFFSET).ok_or(())?,
                rewrite.old_id,
                rewrite.new_id,
            )?;
            replace_ipv4_word(
                ctx,
                rewrite.ip_offset,
                rewrite
                    .ip_offset
                    .checked_add(IPV4_FRAGMENT_OFFSET)
                    .ok_or(())?,
                rewrite.old_fragment,
                rewrite.new_fragment,
            )?;
            replace_ipv4_word(
                ctx,
                rewrite.ip_offset,
                rewrite
                    .ip_offset
                    .checked_add(IPV4_TTL_PROTOCOL_OFFSET)
                    .ok_or(())?,
                rewrite.old_ttl_protocol,
                rewrite.new_ttl_protocol,
            )
        }
        NetworkVersion::Ipv6 => {
            if rewrite.old_version_traffic_flow != rewrite.new_version_traffic_flow {
                let value = rewrite.new_version_traffic_flow.to_be();
                store_with_checksum_update(ctx, rewrite.ip_offset, &value)?;
            }
            let payload_offset = rewrite
                .ip_offset
                .checked_add(IPV6_PAYLOAD_LENGTH_OFFSET)
                .ok_or(())?;
            let payload = rewrite.new_payload_len.to_be();
            // The pseudo-header helper changes the TCP checksum field and its
            // COMPLETE metadata contribution. This IPv6 length write supplies
            // the matching packet-byte delta.
            store_with_checksum_update(ctx, payload_offset, &payload)?;
            let hop_limit_offset = rewrite
                .ip_offset
                .checked_add(IPV6_HOP_LIMIT_OFFSET)
                .ok_or(())?;
            store_with_checksum_update(ctx, hop_limit_offset, &rewrite.new_hop_limit)
        }
    }
}

/// Replaces one network-order 16-bit IPv4 field and updates the header checksum
/// through `bpf_l3_csum_replace` before exposing the new bytes. The field write
/// then uses flags zero. Its raw-sum delta is paired with the checksum-field
/// delta already made by the helper; `BPF_F_RECOMPUTE_CSUM` would count only the
/// data side again for `CHECKSUM_COMPLETE`.
/// This is the kernel-helper form of the RFC 1624 incremental update.
/// <https://www.rfc-editor.org/rfc/rfc1624.html>
fn replace_ipv4_word(
    ctx: &TcContext,
    ip_offset: usize,
    field_offset: usize,
    old: u16,
    new: u16,
) -> Result<(), ()> {
    if old == new {
        return Ok(());
    }
    let checksum_offset = ip_offset.checked_add(IPV4_CHECKSUM_OFFSET).ok_or(())?;
    ctx.l3_csum_replace(
        checksum_offset,
        u64::from(old.to_be()),
        u64::from(new.to_be()),
        CHECKSUM_REPLACE_U16,
    )
    .map_err(|_| ())?;
    let value = new.to_be();
    store_after_checksum_replace(ctx, field_offset, &value)
}

/// Writes only changed TCP bytes, leaving the helper-updated checksum at bytes
/// 16..18 intact. These stores use flags zero because `update_tcp_checksum`
/// already folded every old-to-new byte delta into that field. For
/// `CHECKSUM_COMPLETE`, the data and checksum-field changes are a neutral pair;
/// for `CHECKSUM_PARTIAL`, the device sees the final bytes.
fn store_tcp_rewrite(ctx: &TcContext, rewrite: &Rewrite<'_>) -> Result<(), ()> {
    let control_offset = rewrite
        .tcp_offset
        .checked_add(TCP_DATA_OFFSET_OFFSET)
        .ok_or(())?;
    let control = rewrite.new_tcp_control.to_be();
    store_after_checksum_replace(ctx, control_offset, &control)?;

    let options_offset = rewrite
        .tcp_offset
        .checked_add(TCP_OPTIONS_OFFSET)
        .ok_or(())?;
    let mut word_index = 0;
    while word_index < TCP_OPTION_WORDS {
        let byte_index = word_index.checked_mul(4).ok_or(())?;
        if byte_index >= rewrite.profile.options_len() {
            break;
        }
        let encoded = target_option_word(rewrite, byte_index);
        if encoded & OPTION_WORD_VALID == 0 {
            return Err(());
        }
        let word = (encoded as u32).to_be();
        let offset = options_offset.checked_add(byte_index).ok_or(())?;
        store_after_checksum_replace(ctx, offset, &word)?;
        word_index += 1;
    }
    Ok(())
}

/// Stores bytes whose Internet-checksum delta has already been applied to the
/// packet checksum field. Flags zero preserve the checksum-neutral pairing in
/// `CHECKSUM_COMPLETE` metadata.
#[inline(always)]
fn store_after_checksum_replace<T>(ctx: &TcContext, offset: usize, value: &T) -> Result<(), ()> {
    ctx.store(offset, value, 0).map_err(|_| ())
}

/// Stores changed IPv6 header bytes and updates the skb's raw checksum sum.
///
/// IPv6 has no L3 header checksum. Traffic Class and Hop Limit therefore have
/// no checksum field with which their byte delta can pair. Payload Length also
/// needs this store update even though its semantic change was already applied
/// to the TCP pseudo-header: that earlier helper changed the TCP checksum field,
/// while this call accounts for the actual IPv6 header bytes in
/// `CHECKSUM_COMPLETE`. `BPF_F_RECOMPUTE_CSUM` updates only `skb->csum`; it does
/// not replace the L3/L4 checksum helpers.
#[inline(always)]
fn store_with_checksum_update<T>(ctx: &TcContext, offset: usize, value: &T) -> Result<(), ()> {
    ctx.store(offset, value, u64::from(BPF_F_RECOMPUTE_CSUM))
        .map_err(|_| ())
}

/// Applies the signed TCP-header delta to the full Ethernet frame length using
/// checked arithmetic before it is passed to `bpf_skb_change_tail`.
fn resized_length(frame_len: u32, old_header_len: usize, new_header_len: usize) -> Option<u32> {
    if new_header_len >= old_header_len {
        let growth = u32::try_from(new_header_len - old_header_len).ok()?;
        frame_len.checked_add(growth)
    } else {
        let shrink = u32::try_from(old_header_len - new_header_len).ok()?;
        frame_len.checked_sub(shrink)
    }
}

/// Resolves the current socket cookie to its borrowed 52-byte map value.
///
/// Aya exposes a shared reference although userspace may remove entries while
/// this program runs. The map therefore uses `BPF_F_NO_PREALLOC`: deletion of a
/// non-preallocated hash element is RCU-deferred instead of immediately
/// recycling the same value storage for another key. The reference is read-only
/// and cannot escape this invocation. The userspace loader rewrites only
/// `max_entries`, then verifies the loaded map still has this exact flag and ABI
/// before attachment. BPF hash lookup runs under the program invocation's RCU
/// read-side protection. For a non-preallocated hash, the BPF allocator defers
/// deleted storage until readers are safe; a preallocated map can return its
/// fixed element directly to the per-CPU freelist and reuse the borrowed value.
/// See Linux [`hashtab.c`](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/hashtab.c)
/// and Aya's [`HashMap::get` safety contract](https://docs.rs/aya-ebpf/0.2.1/aya_ebpf/maps/struct.HashMap.html#method.get).
#[allow(
    unsafe_code,
    reason = "Aya 0.2.1 has no safe TC socket-cookie helper and HashMap::get requires an audited lookup"
)]
fn registered_profile(ctx: &TcContext) -> Option<(u64, &EncodedProfile)> {
    // SAFETY: `ctx.as_ptr()` is the live `__sk_buff` supplied by the kernel.
    // `SOCKET_PROFILES` uses BPF_F_NO_PREALLOC, so a concurrent userspace delete
    // cannot recycle this value before an RCU grace period. The returned shared
    // reference is never mutated or allowed to survive this BPF invocation.
    unsafe {
        let cookie = bpf_get_socket_cookie(ctx.as_ptr());
        if cookie == 0 {
            None
        } else {
            SOCKET_PROFILES.get(cookie).map(|encoded| (cookie, encoded))
        }
    }
}

/// Resizes the packet tail. Aya 0.2.1 does not expose a safe wrapper for this
/// helper. The caller has already proved that this SYN carries no payload, so
/// the TCP options are the only bytes moved at the tail. The helper may
/// reallocate skb storage and invalidates packet pointers; this program keeps no
/// direct packet pointer and uses Aya load/store helpers again after the call.
/// It is also an intentional slow path: the kernel may linearize and unclone the
/// skb, make it writable, and reset GSO/offload metadata. Restricting it to one
/// small, payload-free initial SYN avoids paying that cost on established data.
/// A real grow or trim changes `CHECKSUM_COMPLETE` to `CHECKSUM_NONE`, so the
/// packet checksum field must already be correct; `CHECKSUM_PARTIAL` remains in
/// place, so the caller updates its pseudo-header length seed before resizing.
/// The equal-length path does not call this helper at all, which is why ordinary
/// stores still maintain COMPLETE metadata for an option reorder of the same
/// size.
///
/// Sources: the Linux
/// [`bpf_skb_change_tail` helper contract](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/bpf.h)
/// and [`__skb_grow_rcsum` / `__skb_trim_rcsum`](https://github.com/torvalds/linux/blob/v6.18/include/linux/skbuff.h).
#[allow(
    unsafe_code,
    reason = "Aya 0.2.1 does not wrap bpf_skb_change_tail; the live context and checked target length satisfy the helper contract"
)]
fn change_tail(ctx: &TcContext, new_len: u32) -> Result<(), ()> {
    // SAFETY: the pointer belongs to this classifier invocation, `new_len` was
    // derived with checked arithmetic, and flags zero is the only valid mode.
    let result = unsafe { bpf_skb_change_tail(ctx.as_ptr().cast(), new_len, 0) };
    (result == 0).then_some(()).ok_or(())
}

/// Selects the bounded IPv4/IPv6 parser after resolving the Ethernet protocol.
/// Any unsupported encapsulation is a read-only error handled as unchanged.
fn initial_syn_packet(ctx: &TcContext) -> Result<InitialSynPacket, ()> {
    let (protocol, network_offset) = network_protocol(ctx)?;
    match protocol {
        ETHERNET_PROTOCOL_IPV4 => parse_ipv4_initial_syn(ctx, network_offset),
        ETHERNET_PROTOCOL_IPV6 => parse_ipv6_initial_syn(ctx, network_offset),
        _ => Err(()),
    }
}

/// Returns `(EtherType, network_header_offset)` for Ethernet with at most two
/// inline 802.1Q/802.1ad tags. The explicit two-step bound avoids a verifier-
/// hostile variable-depth header walk; a third tag remains untouched.
fn network_protocol(ctx: &TcContext) -> Result<(u16, usize), ()> {
    let mut protocol = load_be_u16(ctx, ETHERNET_PROTOCOL_OFFSET)?;
    let mut network_offset = ETHERNET_HEADER_LEN;

    if is_vlan(protocol) {
        protocol = load_vlan_inner_protocol(ctx, network_offset)?;
        network_offset = network_offset.checked_add(VLAN_HEADER_LEN).ok_or(())?;
    }
    if is_vlan(protocol) {
        protocol = load_vlan_inner_protocol(ctx, network_offset)?;
        network_offset = network_offset.checked_add(VLAN_HEADER_LEN).ok_or(())?;
    }
    if is_vlan(protocol) {
        return Err(());
    }

    Ok((protocol, network_offset))
}

/// Recognizes the two VLAN EtherTypes whose four-byte inline header layout is
/// understood by `network_protocol`.
const fn is_vlan(protocol: u16) -> bool {
    protocol == ETHERNET_PROTOCOL_802_1Q || protocol == ETHERNET_PROTOCOL_802_1AD
}

/// Loads the encapsulated EtherType at byte 2 of one VLAN header.
fn load_vlan_inner_protocol(ctx: &TcContext, vlan_offset: usize) -> Result<u16, ()> {
    let offset = vlan_offset
        .checked_add(VLAN_INNER_PROTOCOL_OFFSET)
        .ok_or(())?;
    load_be_u16(ctx, offset)
}

/// Parses an unfragmented IPv4 initial SYN whose IP payload is exactly its TCP
/// header. IPv4 options are preserved, while reserved/fragment bits, truncation,
/// padding, and TCP Fast Open payloads leave the packet outside this first-stage
/// rewrite.
fn parse_ipv4_initial_syn(ctx: &TcContext, ip_offset: usize) -> Result<InitialSynPacket, ()> {
    let version_ihl = load_u8_at(ctx, ip_offset, IPV4_VERSION_IHL_OFFSET)?;
    if version_ihl >> 4 != 4 {
        return Err(());
    }
    let header_len = usize::from(version_ihl & 0x0f).checked_mul(4).ok_or(())?;
    if header_len < IPV4_MIN_HEADER_LEN {
        return Err(());
    }

    let total_len = load_be_u16_at(ctx, ip_offset, IPV4_TOTAL_LENGTH_OFFSET)?;
    let total_len_usize = usize::from(total_len);
    let minimum_len = header_len.checked_add(TCP_MIN_HEADER_LEN).ok_or(())?;
    if total_len_usize < minimum_len || !packet_ends_at(ctx, ip_offset, total_len_usize)? {
        return Err(());
    }

    let fragment = load_be_u16_at(ctx, ip_offset, IPV4_FRAGMENT_OFFSET)?;
    let protocol = load_u8_at(ctx, ip_offset, IPV4_PROTOCOL_OFFSET)?;
    if fragment & IPV4_RESERVED_FLAG != 0 || !is_unfragmented_tcp(fragment, protocol) {
        return Err(());
    }

    let tcp_offset = ip_offset.checked_add(header_len).ok_or(())?;
    let tcp_header_len = initial_syn_header_len(ctx, tcp_offset)?;
    if !header_lengths_match(header_len, tcp_header_len, total_len_usize) {
        return Err(());
    }

    Ok(InitialSynPacket {
        network: NetworkPacket::Ipv4 {
            ip_offset,
            header_len,
            total_len,
            version_tos: load_be_u16(ctx, ip_offset)?,
            id: load_be_u16_at(ctx, ip_offset, IPV4_ID_OFFSET)?,
            fragment,
            ttl_protocol: load_be_u16_at(ctx, ip_offset, IPV4_TTL_PROTOCOL_OFFSET)?,
        },
        tcp_offset,
        tcp_header_len,
        frame_len: ctx.len(),
    })
}

/// Parses an IPv6 initial SYN only when TCP is the immediate Next Header and the
/// payload contains no data after TCP options. Extension headers are left
/// unchanged because their variable chain needs a separately bounded parser.
/// A zero Payload Length is also rejected: it denotes an IPv6 jumbogram only
/// when a Hop-by-Hop Jumbo Payload option supplies the real length, and that
/// extension-header path is outside this parser. See
/// [RFC 2675](https://www.rfc-editor.org/rfc/rfc2675.html) and
/// [RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5).
fn parse_ipv6_initial_syn(ctx: &TcContext, ip_offset: usize) -> Result<InitialSynPacket, ()> {
    let version_traffic_flow = load_be_u32_at(ctx, ip_offset, IPV6_VERSION_TRAFFIC_FLOW_OFFSET)?;
    if version_traffic_flow >> 28 != 6 {
        return Err(());
    }
    // Extension headers are deliberately left untouched by this bounded
    // parser. RFC 8200 does not guarantee a fixed transport offset for them.
    // https://www.rfc-editor.org/rfc/rfc8200.html#section-4
    if load_u8_at(ctx, ip_offset, IPV6_NEXT_HEADER_OFFSET)? != IP_PROTOCOL_TCP {
        return Err(());
    }

    let payload_len = load_be_u16_at(ctx, ip_offset, IPV6_PAYLOAD_LENGTH_OFFSET)?;
    if usize::from(payload_len) < TCP_MIN_HEADER_LEN {
        return Err(());
    }
    let packet_len = IPV6_HEADER_LEN
        .checked_add(usize::from(payload_len))
        .ok_or(())?;
    if !packet_ends_at(ctx, ip_offset, packet_len)? {
        return Err(());
    }

    let tcp_offset = ip_offset.checked_add(IPV6_HEADER_LEN).ok_or(())?;
    let tcp_header_len = initial_syn_header_len(ctx, tcp_offset)?;
    if tcp_header_len != usize::from(payload_len) {
        return Err(());
    }

    Ok(InitialSynPacket {
        network: NetworkPacket::Ipv6 {
            ip_offset,
            version_traffic_flow,
        },
        tcp_offset,
        tcp_header_len,
        frame_len: ctx.len(),
    })
}

/// Accepts IPv4 TCP only when MF and the fragment offset are both zero.
const fn is_unfragmented_tcp(fragment: u16, protocol: u8) -> bool {
    fragment & IPV4_FRAGMENTED_MASK == 0 && protocol == IP_PROTOCOL_TCP
}

/// Proves that the IP packet ends after the TCP header, excluding SYN data and
/// making tail growth/shrink affect options only.
const fn header_lengths_match(ip_header_len: usize, tcp_header_len: usize, total: usize) -> bool {
    match ip_header_len.checked_add(tcp_header_len) {
        Some(header_length) => header_length == total,
        None => false,
    }
}

/// Validates the TCP Data Offset, four reserved bits, and initial-SYN flags,
/// then reads the final claimed header byte so later code can rely on the whole
/// option area existing.
fn initial_syn_header_len(ctx: &TcContext, tcp_offset: usize) -> Result<usize, ()> {
    let data_offset = load_u8_at(ctx, tcp_offset, TCP_DATA_OFFSET_OFFSET)?;
    let header_len = tcp_header_len(data_offset).ok_or(())?;
    let flags = load_u8_at(ctx, tcp_offset, TCP_FLAGS_OFFSET)?;
    if !is_initial_syn(flags) {
        return Err(());
    }

    let final_byte = header_len.checked_sub(1).ok_or(())?;
    let _byte = load_u8_at(ctx, tcp_offset, final_byte)?;
    Ok(header_len)
}

/// Converts the combined Data Offset/reserved octet to a TCP header length.
/// RFC 9293 section 3.1 requires all four reserved bits to be zero in generated
/// segments; retaining a nonzero bit while replacing Data Offset would emit a
/// non-conforming profile.
/// <https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1>
const fn tcp_header_len(data_offset: u8) -> Option<usize> {
    let words = data_offset >> 4;
    if data_offset & 0x0f != 0 || words < TCP_MIN_DATA_OFFSET {
        return None;
    }
    let length = words as usize * 4;
    if length > TCP_MAX_HEADER_LEN {
        None
    } else {
        Some(length)
    }
}

/// Accepts a first SYN with optional ECE/CWR negotiation bits and rejects every
/// other TCP control flag. In particular, ACK/FIN/RST change connection state,
/// while PSH/URG have no meaning for the payload-free packet this parser needs.
/// RFC 3168 section 6.1.1 defines ECE and CWR on an ECN-setup SYN.
/// <https://www.rfc-editor.org/rfc/rfc3168.html#section-6.1.1>
const fn is_initial_syn(flags: u8) -> bool {
    flags & TCP_FLAG_SYN != 0 && flags & TCP_INITIAL_SYN_PROHIBITED_FLAGS == 0
}

/// Requires the declared IP packet to end exactly at `skb->len`; equality keeps
/// resize calculations from accidentally retaining unparsed trailing bytes.
fn packet_ends_at(ctx: &TcContext, offset: usize, length: usize) -> Result<bool, ()> {
    let end = offset.checked_add(length).ok_or(())?;
    let packet_len = usize::try_from(ctx.len()).map_err(|_| ())?;
    Ok(end == packet_len)
}

/// Adds a relative protocol offset with overflow checking before asking the skb
/// load helper to perform the verifier-visible bounds check.
fn load_u8_at(ctx: &TcContext, base: usize, relative: usize) -> Result<u8, ()> {
    let offset = base.checked_add(relative).ok_or(())?;
    ctx.load(offset).map_err(|_| ())
}

/// Loads a network-order `u16` through the skb helper after checked offset math.
fn load_be_u16_at(ctx: &TcContext, base: usize, relative: usize) -> Result<u16, ()> {
    let offset = base.checked_add(relative).ok_or(())?;
    load_be_u16(ctx, offset)
}

/// Loads a network-order `u32` through the skb helper after checked offset math.
fn load_be_u32_at(ctx: &TcContext, base: usize, relative: usize) -> Result<u32, ()> {
    let offset = base.checked_add(relative).ok_or(())?;
    ctx.load(offset).map(u32::from_be).map_err(|_| ())
}

/// Converts Aya's native scalar load into a host-logical network value.
fn load_be_u16(ctx: &TcContext, offset: usize) -> Result<u16, ()> {
    ctx.load(offset).map(u16::from_be).map_err(|_| ())
}

#[cfg(test)]
/// Pure RFC 1624-style checksum replacement used to verify helper deltas in
/// host unit tests without requiring a kernel eBPF context.
const fn replace_checksum_word(checksum: u16, old_word: u16, new_word: u16) -> u16 {
    !ones_complement_add(ones_complement_add(!checksum, !old_word), new_word)
}

#[cfg(test)]
/// Adds two 16-bit values with end-around carry for Internet checksums.
const fn ones_complement_add(left: u16, right: u16) -> u16 {
    let (sum, carry) = left.overflowing_add(right);
    if carry { sum.wrapping_add(1) } else { sum }
}

#[cfg(not(target_arch = "bpf"))]
// The host stub lets Cargo compile and unit-test this `--bin` target. The
// embedded BPF build uses `no_main` and enters only through `apply_profile`.
fn main() {}

#[cfg(target_arch = "bpf")]
#[panic_handler]
// eBPF has no unwinder or output channel. Valid production paths return an
// action code; this loop only satisfies `core` if an impossible panic remains.
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BPF_OBJECT_NAME_MAX_LEN: usize = 15;
    const SOCKET_PROFILE_MAP_NAME: &str = stringify!(SOCKET_PROFILES);
    const PROFILE_PROGRAM_NAME: &str = stringify!(apply_profile);

    fn encoded_profile(
        hop_limit: u8,
        tcp_window: u16,
        tcp_window_scale: u8,
        flags: u8,
        options: &[u8],
        timestamp_offset: u8,
        window_scale_offset: u8,
    ) -> EncodedProfile {
        let mut encoded = [0; PROFILE_VALUE_LEN];
        encoded[0] = hop_limit;
        encoded[1] = 0x10;
        encoded[2..4].copy_from_slice(&tcp_window.to_be_bytes());
        encoded[4..6].copy_from_slice(&1_460_u16.to_be_bytes());
        encoded[6] = tcp_window_scale;
        encoded[7] = flags;
        encoded[8] = u8::try_from(options.len()).expect("test options fit");
        encoded[9] = 2;
        encoded[10] = timestamp_offset;
        encoded[11] = window_scale_offset;
        encoded[12..12 + options.len()].copy_from_slice(options);
        encoded
    }

    fn windows_profile() -> EncodedProfile {
        encoded_profile(
            128,
            64_240,
            8,
            PROFILE_FLAG_IPV4_DF | PROFILE_FLAG_DERIVE_IPV4_ID,
            &[2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2],
            INVALID_OPTION_OFFSET,
            7,
        )
    }

    fn linux_profile() -> EncodedProfile {
        encoded_profile(
            64,
            65_535,
            7,
            PROFILE_FLAGS,
            &[
                2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7,
            ],
            8,
            19,
        )
    }

    fn macos_profile() -> EncodedProfile {
        encoded_profile(
            64,
            65_535,
            6,
            PROFILE_FLAGS,
            &[
                2, 4, 0x05, 0xb4, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 4, 2, 0, 0,
            ],
            12,
            7,
        )
    }

    fn internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for word in bytes.chunks(2) {
            let low = word.get(1).copied().unwrap_or(0);
            sum += u32::from(u16::from_be_bytes([word[0], low]));
        }
        while sum >> 16 != 0 {
            sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn tcp_checksum_ipv4(header: &[u8], source: [u8; 4], destination: [u8; 4]) -> u16 {
        let mut input = Vec::from(source);
        input.extend(destination);
        input.extend([0, IP_PROTOCOL_TCP]);
        input.extend(
            u16::try_from(header.len())
                .expect("test header fits")
                .to_be_bytes(),
        );
        input.extend(header);
        internet_checksum(&input)
    }

    fn apply_header_checksum_changes(
        mut checksum: u16,
        old: &[u8; TCP_MAX_HEADER_LEN],
        new: &[u8; TCP_MAX_HEADER_LEN],
        old_len: usize,
        new_len: usize,
    ) -> u16 {
        for index in (0..TCP_MAX_HEADER_LEN).step_by(2) {
            if index == TCP_CHECKSUM_OFFSET {
                continue;
            }
            let old_word = u16::from_be_bytes([old[index], old[index + 1]]);
            let new_word = u16::from_be_bytes([new[index], new[index + 1]]);
            checksum = replace_checksum_word(checksum, old_word, new_word);
        }
        replace_checksum_word(checksum, old_len as u16, new_len as u16)
    }

    fn tcp_header(encoded: &EncodedProfile) -> [u8; TCP_MAX_HEADER_LEN] {
        let profile = Profile::decode(encoded).expect("valid profile");
        let mut header = [0; TCP_MAX_HEADER_LEN];
        header[0..2].copy_from_slice(&40_000_u16.to_be_bytes());
        header[2..4].copy_from_slice(&443_u16.to_be_bytes());
        header[4..8].copy_from_slice(&0x1234_5678_u32.to_be_bytes());
        header[TCP_FLAGS_OFFSET] = TCP_FLAG_SYN;
        for index in 0..profile.options_len() {
            header[TCP_OPTIONS_OFFSET + index] = profile.option(index).expect("profile option");
        }
        if profile.tcp_timestamps() {
            let timestamp_offset =
                TCP_OPTIONS_OFFSET + usize::from(profile.timestamp_value_offset());
            header[timestamp_offset..timestamp_offset + 8]
                .copy_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
        }
        header[TCP_DATA_OFFSET_OFFSET] =
            u8::try_from((TCP_OPTIONS_OFFSET + profile.options_len()) / 4)
                .expect("test offset fits")
                << 4;
        header[TCP_WINDOW_OFFSET..TCP_WINDOW_OFFSET + 2]
            .copy_from_slice(&profile.tcp_window().to_be_bytes());
        header
    }

    fn timestamp_from_header(
        header: &[u8; TCP_MAX_HEADER_LEN],
        profile: Profile<'_>,
    ) -> Option<[u8; 8]> {
        if !profile.tcp_timestamps() {
            return None;
        }
        let offset = TCP_OPTIONS_OFFSET + usize::from(profile.timestamp_value_offset());
        header.get(offset..offset + 8)?.try_into().ok()
    }

    fn rewritten_header(
        old: &[u8; TCP_MAX_HEADER_LEN],
        encoded: &EncodedProfile,
        timestamp: Option<[u8; 8]>,
    ) -> [u8; TCP_MAX_HEADER_LEN] {
        let profile = Profile::decode(encoded).expect("valid target profile");
        let new_len = TCP_OPTIONS_OFFSET + profile.options_len();
        let old_control = u32::from_be_bytes(
            old[TCP_DATA_OFFSET_OFFSET..TCP_DATA_OFFSET_OFFSET + 4]
                .try_into()
                .expect("control word"),
        );
        let [_old_data_offset, flags, _window_high, _window_low] = old_control.to_be_bytes();
        let [window_high, window_low] = profile.tcp_window().to_be_bytes();
        let rewrite = Rewrite {
            profile,
            network: NetworkRewrite {
                ip_offset: 0,
                old_version_traffic_flow: 0,
                new_version_traffic_flow: 0,
                old_version_tos: 0,
                new_version_tos: 0,
                old_total_len: 0,
                new_total_len: 0,
                old_id: 0,
                new_id: 0,
                old_fragment: 0,
                new_fragment: 0,
                old_ttl_protocol: 0,
                new_ttl_protocol: 0,
                new_payload_len: 0,
                new_hop_limit: 0,
                version: NetworkVersion::Ipv4,
            },
            tcp_offset: 0,
            old_tcp_header_len: 0,
            new_tcp_header_len: new_len,
            new_tcp_control: u32::from_be_bytes([
                u8::try_from(new_len / 4).expect("test data offset") << 4,
                flags,
                window_high,
                window_low,
            ]),
            timestamp: timestamp.unwrap_or([0; 8]),
            old_frame_len: 0,
            new_frame_len: 0,
        };
        let mut new = [0; TCP_MAX_HEADER_LEN];
        new[..TCP_OPTIONS_OFFSET].copy_from_slice(&old[..TCP_OPTIONS_OFFSET]);
        new[TCP_DATA_OFFSET_OFFSET..TCP_DATA_OFFSET_OFFSET + 4]
            .copy_from_slice(&rewrite.new_tcp_control.to_be_bytes());
        for index in 0..profile.options_len() {
            new[TCP_OPTIONS_OFFSET + index] =
                target_option_byte(&rewrite, index).expect("target option");
        }
        new
    }

    #[test]
    fn object_names_and_map_abi_match_userspace() {
        assert_eq!(SOCKET_PROFILE_MAP_NAME, "SOCKET_PROFILES");
        assert_eq!(PROFILE_PROGRAM_NAME, "apply_profile");
        assert!(SOCKET_PROFILE_MAP_NAME.len() <= BPF_OBJECT_NAME_MAX_LEN);
        assert!(PROFILE_PROGRAM_NAME.len() <= BPF_OBJECT_NAME_MAX_LEN);
        assert_eq!(core::mem::size_of::<EncodedProfile>(), PROFILE_VALUE_LEN);
        assert!(Profile::decode(&windows_profile()).is_some());
        assert!(Profile::decode(&linux_profile()).is_some());
        assert!(Profile::decode(&macos_profile()).is_some());

        let windows = windows_profile();
        let profile = Profile::decode(&windows).expect("valid Windows profile");
        assert_eq!(profile.option(PROFILE_TEMPLATE_MAX_LEN), None);
        assert_eq!(profile.option(PROFILE_OPTIONS_LEN - 1), None);
    }

    #[test]
    fn userspace_encoder_matches_the_kernel_profile_validator() {
        use userspace_ebpf::{IpVersion as UserIpVersion, Profile as UserProfile};

        for profile in [
            UserProfile::Windows,
            UserProfile::Linux,
            UserProfile::Android,
            UserProfile::MacOs,
            UserProfile::Ios,
        ] {
            for (version, expected_mss) in [
                (UserIpVersion::V4, PROFILE_MSS_IPV4),
                (UserIpVersion::V6, PROFILE_MSS_IPV6),
            ] {
                let encoded = userspace_ebpf::encode_profile_for_test(profile, version);
                let decoded = Profile::decode(&encoded)
                    .expect("the kernel validator must accept every userspace built-in");
                assert_eq!(decoded.tcp_mss(), expected_mss, "{profile} {version:?}");
            }
        }
    }

    #[test]
    fn profile_validation_rejects_corrupt_option_metadata() {
        let mut corrupt = linux_profile();
        corrupt[11] = 18;
        assert!(Profile::decode(&corrupt).is_none());

        corrupt = linux_profile();
        corrupt[PROFILE_OPTIONS_OFFSET + 5] = 3;
        assert!(Profile::decode(&corrupt).is_none());

        corrupt = windows_profile();
        corrupt[7] |= 0x80;
        assert!(Profile::decode(&corrupt).is_none());

        corrupt = windows_profile();
        corrupt[7] &= !PROFILE_FLAG_IPV4_DF;
        assert!(Profile::decode(&corrupt).is_none());

        corrupt = macos_profile();
        corrupt[PROFILE_OPTIONS_OFFSET + 23] = TCP_OPTION_NOP;
        assert!(Profile::decode(&corrupt).is_none());

        corrupt = macos_profile();
        corrupt[PROFILE_OPTIONS_OFFSET + 22] = 30;
        corrupt[PROFILE_OPTIONS_OFFSET + 23] = 2;
        assert!(Profile::decode(&corrupt).is_none());

        corrupt = linux_profile();
        corrupt[PROFILE_OPTIONS_OFFSET + 8] = 1;
        assert!(Profile::decode(&corrupt).is_none());

        corrupt = windows_profile();
        corrupt[PROFILE_OPTIONS_OFFSET + PROFILE_OPTIONS_LEN - 1] = 1;
        assert!(Profile::decode(&corrupt).is_none());

        let mut ipv6 = linux_profile();
        let [mss_high, mss_low] = 1_440_u16.to_be_bytes();
        ipv6[4] = mss_high;
        ipv6[5] = mss_low;
        ipv6[PROFILE_OPTIONS_OFFSET + 2] = mss_high;
        ipv6[PROFILE_OPTIONS_OFFSET + 3] = mss_low;
        assert!(Profile::decode(&ipv6).is_some());
    }

    #[test]
    fn rewrite_reorders_options_but_preserves_kernel_timestamp() {
        let linux = linux_profile();
        let macos = macos_profile();
        let old = tcp_header(&linux);
        let source_timestamp =
            timestamp_from_header(&old, Profile::decode(&linux).expect("valid Linux profile"));
        let rewritten = rewritten_header(&old, &macos, source_timestamp);

        assert_eq!(&rewritten[32..40], source_timestamp.as_ref().unwrap());
        assert_eq!(rewritten[27], 6);
        assert_eq!(&rewritten[40..44], &[4, 2, 0, 0]);
    }

    #[test]
    fn complete_header_delta_covers_grow_and_shrink() {
        let source = [192, 0, 2, 1];
        let destination = [198, 51, 100, 2];
        for (old_encoded, new_encoded) in [
            (linux_profile(), windows_profile()),
            (windows_profile(), macos_profile()),
        ] {
            let mut old = tcp_header(&old_encoded);
            let old_profile = Profile::decode(&old_encoded).expect("old profile");
            let old_len = TCP_OPTIONS_OFFSET + old_profile.options_len();
            let old_checksum = tcp_checksum_ipv4(&old[..old_len], source, destination);
            old[TCP_CHECKSUM_OFFSET..TCP_CHECKSUM_OFFSET + 2]
                .copy_from_slice(&old_checksum.to_be_bytes());

            let new_profile = Profile::decode(&new_encoded).expect("new profile");
            let source_timestamp = timestamp_from_header(&old, old_profile).or(new_profile
                .tcp_timestamps()
                .then_some([0, 0, 0, 1, 0, 0, 0, 0]));
            let mut new = rewritten_header(&old, &new_encoded, source_timestamp);
            let new_len = TCP_OPTIONS_OFFSET + new_profile.options_len();
            let checksum =
                apply_header_checksum_changes(old_checksum, &old, &new, old_len, new_len);
            new[TCP_CHECKSUM_OFFSET..TCP_CHECKSUM_OFFSET + 2]
                .copy_from_slice(&checksum.to_be_bytes());

            assert_eq!(
                tcp_checksum_ipv4(&new[..new_len], source, destination),
                0,
                "{old_len}-byte header to {new_len}-byte header"
            );
        }
    }

    #[test]
    fn parser_and_length_guards_cover_supported_frames() {
        const TCP_FLAG_ECE: u8 = 0x40;
        const TCP_FLAG_CWR: u8 = 0x80;

        assert!(is_initial_syn(TCP_FLAG_SYN | TCP_FLAG_ECE | TCP_FLAG_CWR));
        assert!(!is_initial_syn(TCP_FLAG_SYN | TCP_FLAG_ACK));
        assert!(!is_initial_syn(TCP_FLAG_SYN | TCP_FLAG_RST));
        assert!(!is_initial_syn(TCP_FLAG_SYN | TCP_FLAG_FIN));
        assert!(!is_initial_syn(TCP_FLAG_SYN | TCP_FLAG_PSH));
        assert!(!is_initial_syn(TCP_FLAG_SYN | TCP_FLAG_URG));
        assert!(!is_initial_syn(0));

        assert_eq!(tcp_header_len(5 << 4), Some(TCP_MIN_HEADER_LEN));
        assert_eq!(tcp_header_len(15 << 4), Some(TCP_MAX_HEADER_LEN));
        assert_eq!(tcp_header_len(4 << 4), None);
        assert_eq!(tcp_header_len(5 << 4 | 1), None);

        assert!(is_unfragmented_tcp(0, IP_PROTOCOL_TCP));
        assert!(!is_unfragmented_tcp(1, IP_PROTOCOL_TCP));
        assert!(!is_unfragmented_tcp(0x2000, IP_PROTOCOL_TCP));
        assert!(!is_unfragmented_tcp(0, 17));
        assert!(header_lengths_match(20, 40, 60));
        assert!(!header_lengths_match(20, 40, 61));
        assert!(!header_lengths_match(usize::MAX, 1, 0));

        assert!(is_vlan(ETHERNET_PROTOCOL_802_1Q));
        assert!(is_vlan(ETHERNET_PROTOCOL_802_1AD));
        assert!(!is_vlan(ETHERNET_PROTOCOL_IPV4));
        assert!(!is_vlan(ETHERNET_PROTOCOL_IPV6));
    }

    #[test]
    fn rfc1624_update_matches_full_ipv4_checksum() {
        let mut original = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let original_checksum = internet_checksum(&original).to_be_bytes();
        original[10..12].copy_from_slice(&original_checksum);
        let old_word = u16::from_be_bytes([original[8], original[9]]);
        let old_checksum = u16::from_be_bytes([original[10], original[11]]);

        for target_ttl in u8::MIN..=u8::MAX {
            let checksum = replace_checksum_word(
                old_checksum,
                old_word,
                u16::from_be_bytes([target_ttl, original[9]]),
            );
            let mut updated = original;
            updated[8] = target_ttl;
            updated[10..12].copy_from_slice(&checksum.to_be_bytes());
            assert_eq!(internet_checksum(&updated), 0, "TTL {target_ttl}");
        }
        assert_eq!(replace_checksum_word(0xdd2f, 0x5555, 0x3285), 0x0000);
    }
}
