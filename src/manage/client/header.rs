//! Read one private automation header without accepting arbitrary request headers.

use std::{
    fs::{self, Metadata, OpenOptions},
    io::{self, Read},
    path::Path,
};

use http::HeaderValue;
use zeroize::Zeroizing;

use crate::manage::{automation, store::automation::Credential};

const MAX_HEADER_BYTES: usize = 256;
const PREFIX: &[u8] = b"Authorization: Bearer ";
const ERROR: &str = "cannot read private automation header";

/// A single sensitive Authorization value, moved into one explicit request.
///
/// Temporary file bytes are zeroized. `HeaderValue` and the HTTP/TLS stack may
/// retain their own allocations; sensitive marking prevents ordinary header
/// Debug output, not a promise to erase every transport copy from memory.
pub(super) struct Authorization(HeaderValue);

impl Authorization {
    /// Read a bounded F1 `Authorization: Bearer TOKEN` line with an optional final
    /// LF, never CRLF, extra headers or whitespace. Token parsing checks syntax
    /// only: the remote node still decides whether the credential is authorized.
    ///
    /// Ancestors must be controlled by the operator. The immediate parent must
    /// be real and private (normally 0700); Unix leaves require 0600, one hard
    /// link and the same owner as that parent. Windows rejects reparse points
    /// but relies on the operator's private parent ACL, which is not audited.
    /// All failures preserve the I/O kind and use one static, nonsecret message.
    pub(super) fn read(path: &Path) -> io::Result<Self> {
        read_value(path)
            .map(Self)
            .map_err(|error| io::Error::new(error.kind(), ERROR))
    }

    pub(super) fn into_value(self) -> HeaderValue {
        self.0
    }
}

fn read_value(path: &Path) -> io::Result<HeaderValue> {
    if path.as_os_str().is_empty() {
        return Err(invalid());
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let name = absolute.file_name().ok_or_else(invalid)?;
    let parent = absolute.parent().ok_or_else(invalid)?;
    automation::validate_parent(&fs::symlink_metadata(parent)?)?;
    let parent = fs::canonicalize(parent)?;
    automation::validate_parent(&fs::symlink_metadata(&parent)?)?;
    let path = parent.join(name);
    validate_file(&fs::symlink_metadata(&path)?)?;

    #[cfg(unix)]
    let parent = {
        use std::os::unix::fs::OpenOptionsExt as _;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&parent)?;
        automation::validate_parent(&file.metadata()?)?;
        file
    };
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // Open a substituted reparse leaf itself so the FD check can reject it,
        // rather than following it to an otherwise valid regular file.
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    validate_file(&metadata)?;
    if metadata.len() > MAX_HEADER_BYTES as u64 {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != parent.metadata()?.uid() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, ERROR));
        }
    }

    // The extra byte detects growth after metadata inspection. A fixed owner
    // avoids reallocation leaving earlier copies of the token outside zeroize.
    let mut bytes = Zeroizing::new([0; MAX_HEADER_BYTES + 1]);
    let mut length = 0;
    loop {
        let count = file.read(&mut bytes[length..])?;
        if count == 0 {
            break;
        }
        length += count;
        if length > MAX_HEADER_BYTES {
            return Err(invalid());
        }
    }
    validate_file(&file.metadata()?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let parent_metadata = parent.metadata()?;
        automation::validate_parent(&parent_metadata)?;
        if file.metadata()?.uid() != parent_metadata.uid() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, ERROR));
        }
    }
    let line = bytes[..length]
        .strip_suffix(b"\n")
        .unwrap_or(&bytes[..length]);
    let token = line.strip_prefix(PREFIX).ok_or_else(invalid)?;
    let token = std::str::from_utf8(token).map_err(|_| invalid())?;
    let _credential = Credential::parse(token)?;
    let mut value =
        HeaderValue::from_bytes(&line[b"Authorization: ".len()..]).map_err(|_| invalid())?;
    value.set_sensitive(true);
    Ok(value)
}

fn validate_file(metadata: &Metadata) -> io::Result<()> {
    automation::validate_file(metadata)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, ERROR));
        }
    }
    Ok(())
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, ERROR)
}
