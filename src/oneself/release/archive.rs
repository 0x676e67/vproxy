//! Streaming validation of the fixed published release layout. Only executable
//! bytes reach the caller's private candidate; no archive path is ever opened.

use std::{
    cell::Cell,
    io::{self, BufRead, Read, Write},
};

use flate2::bufread::GzDecoder;
use tar::{Archive, Header};

use super::Variant;

const BLOCK: u64 = 512;
const MAX_EXPANDED: u64 = 256 * 1024 * 1024;
const MAX_BINARY: u64 = 128 * 1024 * 1024;
const MAX_DOCUMENT: u64 = 2 * 1024 * 1024;

/// Validate one SHA-verified, caller-bounded gzip input and copy only its binary
/// into an already-created private candidate. The caller must not install that
/// candidate until this returns success: a late CRC, framing, document or output
/// error can follow partial candidate writes. No installed executable is read
/// or replaced here. Published API/Web assets are USTAR, unlike native smoke
/// packages that may contain PAX metadata and are not self-update inputs.
pub(super) fn extract(
    input: impl BufRead,
    output: &mut impl Write,
    variant: Variant,
    bin_name: &str,
) -> io::Result<()> {
    if !matches!(bin_name, "vproxy" | "vproxy.exe") {
        return Err(invalid());
    }
    let names: &[&str] = match variant {
        Variant::Proxy => &[bin_name],
        Variant::Api => &[bin_name, "LICENSE", "README.md"],
        Variant::Web => &[bin_name, "LICENSE", "README.md", "LICENSE.ant-design-pro"],
    };
    let padding = Cell::new((0, 0));
    let mut archive = Archive::new(Bounded::with_padding(
        GzDecoder::new(input),
        MAX_EXPANDED,
        &padding,
    ));
    let mut member_end = 0u64;
    {
        // Raw iteration prevents GNU/PAX metadata from being silently consumed
        // or applied to a later otherwise-ordinary member.
        let mut entries = archive.entries().map_err(|_| invalid())?.raw(true);
        for (index, name) in names.iter().enumerate() {
            let mut entry = entries.next().ok_or_else(invalid)?.map_err(|_| invalid())?;
            let size = validate(entry.header(), name, variant, index == 0)?;
            let data_start = member_end.checked_add(BLOCK).ok_or_else(invalid)?;
            if entry.raw_header_position() != member_end || entry.raw_file_position() != data_start
            {
                return Err(invalid());
            }
            if index == 0 {
                copy_binary(&mut entry, output, size)?;
            } else {
                let mut document = Vec::new();
                entry.read_to_end(&mut document).map_err(|_| invalid())?;
                if u64::try_from(document.len()).map_err(|_| invalid())? != size
                    || std::str::from_utf8(&document)
                        .map_err(|_| invalid())?
                        .trim()
                        .is_empty()
                {
                    return Err(invalid());
                }
            }
            let padded = size
                .checked_add(BLOCK - 1)
                .and_then(|value| (value / BLOCK).checked_mul(BLOCK))
                .ok_or_else(invalid)?;
            member_end = member_end
                .checked_add(BLOCK)
                .and_then(|value| value.checked_add(padded))
                .ok_or_else(invalid)?;
            // The iterator skips unused member padding before its next header.
            // Validate that exact window in the reader, without treating actual
            // payload bytes as padding or replacing the library's tar parser.
            padding.set((
                data_start.checked_add(size).ok_or_else(invalid)?,
                member_end,
            ));
        }
        // Even a duplicate regular member is outside the exact release layout.
        if entries.next().is_some() {
            return Err(invalid());
        }
    }
    let mut expanded = archive.into_inner();
    // tar 0.4 stops after its first zero header, and also accepts naked EOF.
    // Its consumed-byte count distinguishes those cases without reimplementing
    // header parsing. Require the second zero block and consume every remaining
    // byte ourselves; tar blocking padding is allowed only when entirely zero.
    if expanded.used != member_end.checked_add(BLOCK).ok_or_else(invalid)? {
        return Err(invalid());
    }
    let mut buffer = [0; 8192];
    loop {
        let length = expanded.read(&mut buffer).map_err(|_| invalid())?;
        if length == 0 {
            break;
        }
        if buffer[..length].iter().any(|byte| *byte != 0) {
            return Err(invalid());
        }
    }
    if expanded.used < member_end.checked_add(2 * BLOCK).ok_or_else(invalid)?
        || !expanded.used.is_multiple_of(BLOCK)
    {
        return Err(invalid());
    }
    // bufread::GzDecoder consumes exactly one member and checks its trailer at
    // EOF. Its original BufRead preserves any bytes after that member, so a
    // concatenated gzip or compressed trailing junk cannot be accepted.
    let mut compressed = expanded.inner.into_inner();
    if !compressed.fill_buf().map_err(|_| invalid())?.is_empty() {
        return Err(invalid());
    }
    Ok(())
}

fn validate(header: &Header, name: &str, variant: Variant, binary: bool) -> io::Result<u64> {
    let old = header.as_old();
    if !header.entry_type().is_file()
        || old
            .name
            .strip_prefix(name.as_bytes())
            .is_none_or(|tail| tail.iter().any(|byte| *byte != 0))
        || old.linkname.iter().any(|byte| *byte != 0)
        || header.path_bytes().as_ref() != name.as_bytes()
    {
        return Err(invalid());
    }
    if let Some(ustar) = header.as_ustar() {
        if ustar.prefix.iter().any(|byte| *byte != 0) {
            return Err(invalid());
        }
    } else if variant != Variant::Proxy {
        return Err(invalid());
    } else if let Some(gnu) = header.as_gnu() {
        if gnu.isextended.iter().any(|byte| *byte != 0)
            || gnu.realsize.iter().any(|byte| *byte != 0)
            || gnu.offset.iter().any(|byte| *byte != 0)
            || gnu.longnames.iter().any(|byte| *byte != 0)
            || gnu.sparse.iter().any(|sparse| {
                sparse
                    .offset
                    .iter()
                    .chain(&sparse.numbytes)
                    .any(|byte| *byte != 0)
            })
        {
            return Err(invalid());
        }
    } else if old.pad.iter().any(|byte| *byte != 0) {
        return Err(invalid());
    }
    let mode = header.mode().map_err(|_| invalid())?;
    let expected_mode = if binary { 0o755 } else { 0o644 };
    // Legacy proxy tar headers can include S_IFREG. No other type/special bits
    // are allowed, and richer published profiles use exact USTAR permissions.
    if mode != expected_mode && !(variant == Variant::Proxy && mode == (expected_mode | 0o100_000))
    {
        return Err(invalid());
    }
    let size = header.entry_size().map_err(|_| invalid())?;
    let maximum = if binary { MAX_BINARY } else { MAX_DOCUMENT };
    if size == 0 || size > maximum {
        return Err(invalid());
    }
    Ok(size)
}

fn copy_binary(input: &mut impl Read, output: &mut impl Write, expected: u64) -> io::Result<()> {
    let mut buffer = [0; 8192];
    let mut copied = 0u64;
    loop {
        let length = input.read(&mut buffer).map_err(|_| invalid())?;
        if length == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(length).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if copied > expected {
            return Err(invalid());
        }
        // Preserve an actual candidate-output error; no archive-supplied text
        // is formatted into diagnostics when parsing input fails.
        output.write_all(&buffer[..length])?;
    }
    if copied != expected {
        return Err(invalid());
    }
    Ok(())
}

/// Unlike Take, reaching this limit cannot masquerade as valid decoder EOF.
/// One extra byte is inspected but never returned, including for zero padding.
struct Bounded<'a, R> {
    inner: R,
    used: u64,
    limit: u64,
    padding: Option<&'a Cell<(u64, u64)>>,
}

impl<'a, R> Bounded<'a, R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            used: 0,
            limit,
            padding: None,
        }
    }

    fn with_padding(inner: R, limit: u64, padding: &'a Cell<(u64, u64)>) -> Self {
        Self {
            padding: Some(padding),
            ..Self::new(inner, limit)
        }
    }
}

impl<R: Read> Read for Bounded<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.checked_sub(self.used).ok_or_else(invalid)?;
        if remaining == 0 {
            return match self.inner.read(&mut [0; 1])? {
                0 => Ok(0),
                _ => Err(invalid()),
            };
        }
        let length =
            usize::try_from(remaining.min(u64::try_from(output.len()).map_err(|_| invalid())?))
                .map_err(|_| invalid())?;
        let read = self.inner.read(&mut output[..length])?;
        let end = self
            .used
            .checked_add(u64::try_from(read).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if let Some(padding) = self.padding {
            let (start, stop) = padding.get();
            let overlap_start = self.used.max(start);
            let overlap_end = end.min(stop);
            if overlap_start < overlap_end {
                let start =
                    usize::try_from(overlap_start.checked_sub(self.used).ok_or_else(invalid)?)
                        .map_err(|_| invalid())?;
                let stop = usize::try_from(overlap_end.checked_sub(self.used).ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
                if output[start..stop].iter().any(|byte| *byte != 0) {
                    return Err(invalid());
                }
            }
        }
        self.used = end;
        Ok(read)
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid release archive")
}
