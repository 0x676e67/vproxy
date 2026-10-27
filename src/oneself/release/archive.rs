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

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, EntryType};

    use super::*;

    const BINARY: &[u8] = b"synthetic candidate, never executed\n";

    fn header(name: &[u8], size: u64, mode: u32, format: u8) -> Header {
        let mut header = match format {
            0 => Header::new_old(),
            1 => Header::new_gnu(),
            _ => Header::new_ustar(),
        };
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_size(size);
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(EntryType::Regular);
        header.set_cksum();
        header
    }

    fn members(entries: Vec<(Header, Vec<u8>)>) -> io::Result<Vec<u8>> {
        let mut archive = Builder::new(Vec::new());
        for (header, data) in entries {
            archive.append(&header, Cursor::new(data))?;
        }
        archive.into_inner()
    }

    fn member(name: &str, bytes: &[u8]) -> (Header, Vec<u8>) {
        (
            header(
                name.as_bytes(),
                bytes.len() as u64,
                if name.starts_with("vproxy") {
                    0o755
                } else {
                    0o644
                },
                2,
            ),
            bytes.to_vec(),
        )
    }

    fn published(variant: Variant, name: &str) -> io::Result<Vec<u8>> {
        let mut entries = vec![member(name, BINARY)];
        if variant != Variant::Proxy {
            entries.extend([
                member("LICENSE", b"License\n"),
                member("README.md", b"Read me\n"),
            ]);
        }
        if variant == Variant::Web {
            entries.push(member(
                "LICENSE.ant-design-pro",
                b"Ant Design Pro license\n",
            ));
        }
        members(entries)
    }

    fn gzip(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes)?;
        encoder.finish()
    }

    fn rejected(bytes: Vec<u8>, variant: Variant, name: &str) -> io::Result<()> {
        let mut output = Vec::new();
        assert!(extract(Cursor::new(bytes), &mut output, variant, name).is_err());
        Ok(())
    }

    #[test]
    fn exact_published_layouts_and_legacy_proxy_headers_copy_only_the_binary() -> io::Result<()> {
        for name in ["vproxy", "vproxy.exe"] {
            for variant in [Variant::Proxy, Variant::Api, Variant::Web] {
                let mut raw = published(variant, name)?;
                // GNU tar's blocking factor may add more than the mandatory pair.
                raw.resize(raw.len() + 7 * 512, 0);
                let compressed = gzip(&raw)?;
                let mut output = Vec::new();
                extract(
                    BufReader::with_capacity(1, Cursor::new(compressed)),
                    &mut output,
                    variant,
                    name,
                )?;
                assert_eq!(output, BINARY);
            }
        }
        for format in [0, 1] {
            let raw = members(vec![(
                header(b"vproxy", BINARY.len() as u64, 0o100_755, format),
                BINARY.to_vec(),
            )])?;
            let mut output = Vec::new();
            extract(
                Cursor::new(gzip(&raw)?),
                &mut output,
                Variant::Proxy,
                "vproxy",
            )?;
            assert_eq!(output, BINARY);
            rejected(gzip(&raw)?, Variant::Api, "vproxy")?;
            rejected(gzip(&raw)?, Variant::Web, "vproxy")?;
        }
        rejected(
            gzip(&published(Variant::Proxy, "vproxy")?)?,
            Variant::Proxy,
            "../vproxy",
        )?;
        Ok(())
    }

    #[test]
    fn extensions_links_special_members_duplicates_and_path_aliases_are_not_normalized()
    -> io::Result<()> {
        for flag in *b"1234567LKSxgX" {
            let mut item = header(b"vproxy", BINARY.len() as u64, 0o755, 2);
            item.set_entry_type(EntryType::new(flag));
            item.set_cksum();
            rejected(
                gzip(&members(vec![(item, BINARY.to_vec())])?)?,
                Variant::Proxy,
                "vproxy",
            )?;
        }
        for name in [
            b"./vproxy".as_slice(),
            b"../vproxy",
            b"/vproxy",
            b"folder/vproxy",
            b"vproxy/",
            b"vproxy\\file",
            b"VPROXY",
            b"vproxy.exe:stream",
            b"vproxy\0../hidden",
        ] {
            let raw = members(vec![(
                header(name, BINARY.len() as u64, 0o755, 2),
                BINARY.to_vec(),
            )])?;
            rejected(gzip(&raw)?, Variant::Proxy, "vproxy")?;
        }
        let mut prefixed = header(b"vproxy", BINARY.len() as u64, 0o755, 2);
        prefixed.as_ustar_mut().expect("USTAR fixture").prefix[..2].copy_from_slice(b"./");
        prefixed.set_cksum();
        let mut linked = header(b"vproxy", BINARY.len() as u64, 0o755, 2);
        linked.as_old_mut().linkname[0] = b'x';
        linked.set_cksum();
        let mut sparse = header(b"vproxy", BINARY.len() as u64, 0o755, 1);
        sparse.as_gnu_mut().expect("GNU fixture").sparse[0].offset[0] = b'1';
        sparse.set_cksum();
        for item in [prefixed, linked, sparse] {
            rejected(
                gzip(&members(vec![(item, BINARY.to_vec())])?)?,
                Variant::Proxy,
                "vproxy",
            )?;
        }
        for extra in ["vproxy", "extra"] {
            rejected(
                gzip(&members(vec![
                    member("vproxy", BINARY),
                    member(extra, b"extra"),
                ])?)?,
                Variant::Proxy,
                "vproxy",
            )?;
        }
        rejected(
            gzip(&members(vec![
                member("vproxy", BINARY),
                member("README.md", b"Read me"),
                member("LICENSE", b"License"),
            ])?)?,
            Variant::Api,
            "vproxy",
        )?;
        rejected(
            gzip(&members(vec![
                member("vproxy", BINARY),
                member("LICENSE", b"License"),
            ])?)?,
            Variant::Api,
            "vproxy",
        )?;
        Ok(())
    }

    #[test]
    fn modes_declared_sizes_bad_checksums_and_non_text_documents_fail_before_acceptance()
    -> io::Result<()> {
        for mode in [0o644, 0o4755, 0o2755, 0o1755, 0o060_755, 0o200_755] {
            let raw = members(vec![(
                header(b"vproxy", BINARY.len() as u64, mode, 2),
                BINARY.to_vec(),
            )])?;
            rejected(gzip(&raw)?, Variant::Proxy, "vproxy")?;
        }
        for size in [0, MAX_BINARY + 1, u64::MAX] {
            let item = header(b"vproxy", size, 0o755, 2);
            let mut raw = item.as_bytes().to_vec();
            raw.resize(1536, 0);
            rejected(gzip(&raw)?, Variant::Proxy, "vproxy")?;
        }
        let mut raw = published(Variant::Proxy, "vproxy")?;
        raw[0] ^= 1;
        rejected(gzip(&raw)?, Variant::Proxy, "vproxy")?;
        let mut raw = published(Variant::Proxy, "vproxy")?;
        raw.truncate(raw.len() - 1024);
        raw.extend_from_slice(header(b"LICENSE", MAX_DOCUMENT + 1, 0o644, 2).as_bytes());
        raw.resize(raw.len() + 1024, 0);
        rejected(gzip(&raw)?, Variant::Api, "vproxy")?;
        for document in [b" \n\t".as_slice(), &[0xff], b""] {
            let raw = members(vec![
                member("vproxy", BINARY),
                member("LICENSE", document),
                member("README.md", b"Read me"),
            ])?;
            rejected(gzip(&raw)?, Variant::Api, "vproxy")?;
        }
        // API/Web have no legacy permission-bit or GNU-format compatibility.
        let mut entries = vec![
            member("vproxy", BINARY),
            member("LICENSE", b"License"),
            member("README.md", b"Read me"),
        ];
        entries[0].0.set_mode(0o100_755);
        entries[0].0.set_cksum();
        rejected(gzip(&members(entries)?)?, Variant::Api, "vproxy")?;
        for format in [0, 1] {
            let raw = members(vec![
                (
                    header(b"vproxy", BINARY.len() as u64, 0o755, format),
                    BINARY.to_vec(),
                ),
                member("LICENSE", b"License"),
                member("README.md", b"Read me"),
            ])?;
            rejected(gzip(&raw)?, Variant::Api, "vproxy")?;
        }
        Ok(())
    }

    #[test]
    fn tar_requires_two_zero_blocks_and_entire_gzip_crc_eof_without_trailing_data() -> io::Result<()>
    {
        for (variant, offset) in [
            (Variant::Proxy, 512 + BINARY.len()),
            (Variant::Api, 512 + BINARY.len()),
            (Variant::Api, 3 * 512 + b"License\n".len()),
        ] {
            let mut padded = published(variant, "vproxy")?;
            // Change only unused padding: both the header checksum and every
            // declared payload remain valid, including the next API member.
            assert_eq!(padded[offset], 0);
            padded[offset] = 1;
            rejected(gzip(&padded)?, variant, "vproxy")?;
        }
        let raw = published(Variant::Proxy, "vproxy")?;
        for removed in [1, 511, 512, 1023, 1024] {
            rejected(gzip(&raw[..raw.len() - removed])?, Variant::Proxy, "vproxy")?;
        }
        for length in [511, 512, 512 + BINARY.len() - 1] {
            rejected(gzip(&raw[..length])?, Variant::Proxy, "vproxy")?;
        }
        let mut unaligned = raw.clone();
        unaligned.push(0);
        let mut junk = raw.clone();
        junk.extend_from_slice(&[1; 512]);
        let mut second_tar = raw.clone();
        second_tar.extend_from_slice(&raw);
        for bytes in [unaligned, junk, second_tar] {
            rejected(gzip(&bytes)?, Variant::Proxy, "vproxy")?;
        }
        let compressed = gzip(&raw)?;
        for removed in [1, 4, 8, 12] {
            rejected(
                compressed[..compressed.len() - removed].to_vec(),
                Variant::Proxy,
                "vproxy",
            )?;
        }
        for offset in [1, 5, 8] {
            let mut corrupt = compressed.clone();
            let index = corrupt.len() - offset;
            corrupt[index] ^= 1;
            rejected(corrupt, Variant::Proxy, "vproxy")?;
        }
        for tail in [b"junk".as_slice(), &[0], compressed.as_slice()] {
            let mut appended = compressed.clone();
            appended.extend_from_slice(tail);
            rejected(appended, Variant::Proxy, "vproxy")?;
        }
        rejected(b"not gzip".to_vec(), Variant::Proxy, "vproxy")?;
        Ok(())
    }

    #[test]
    fn expanded_limit_is_not_a_silent_eof_and_candidate_write_errors_are_preserved()
    -> io::Result<()> {
        let raw = published(Variant::Proxy, "vproxy")?;
        let compressed = gzip(&raw)?;
        let mut limited = Bounded::new(GzDecoder::new(Cursor::new(compressed.clone())), BLOCK);
        assert!(io::copy(&mut limited, &mut io::sink()).is_err());
        assert_eq!(limited.used, BLOCK);
        let mut exact = Bounded::new(
            GzDecoder::new(Cursor::new(compressed.clone())),
            raw.len() as u64,
        );
        assert_eq!(io::copy(&mut exact, &mut io::sink())?, raw.len() as u64);
        struct Failed;
        impl Write for Failed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "candidate fixture failure",
                ))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let error = extract(
            Cursor::new(compressed),
            &mut Failed,
            Variant::Proxy,
            "vproxy",
        )
        .expect_err("candidate write failure");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        Ok(())
    }
}
