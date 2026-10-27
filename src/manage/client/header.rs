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

#[cfg(test)]
mod tests {
    use std::{fs::DirBuilder, io::Write, path::PathBuf};

    use super::*;

    const TOKEN: &str = "vpa1.AAAAAAAAAAAAAAAAAAAAAA.1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// Each test owns a new private directory and synthetic, non-authorized token.
    /// No runtime directory, existing credential or external file is read.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("test entropy unavailable"))?;
            let path = std::env::temp_dir().join(format!(
                "vproxy-query-header-{:032x}",
                u128::from_be_bytes(random)
            ));
            let builder = DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&path)?;
            Ok(Self(path))
        }

        fn header(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
            let path = self.0.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options.open(&path)?;
            file.write_all(bytes)?;
            Ok(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn rejected(path: &Path) -> io::Result<io::Error> {
        let error = Authorization::read(path)
            .err()
            .ok_or_else(|| io::Error::other("expected private header rejection"))?;
        assert_eq!(error.to_string(), ERROR);
        Ok(error)
    }

    #[test]
    fn exact_f1_header_becomes_one_sensitive_value_without_modifying_file() -> io::Result<()> {
        let fixture = Fixture::new()?;
        for (name, ending) in [("f1.header", "\n"), ("no-lf.header", "")] {
            let bytes = format!("Authorization: Bearer {TOKEN}{ending}");
            let path = fixture.header(name, bytes.as_bytes())?;
            let value = Authorization::read(&path)?.into_value();
            assert!(value.is_sensitive());
            assert_eq!(value.as_bytes(), format!("Bearer {TOKEN}").as_bytes());
            assert!(!format!("{value:?}").contains(TOKEN));
            assert_eq!(fs::read(path)?, bytes.as_bytes());
        }
        Ok(())
    }

    #[test]
    fn malformed_tokens_and_injected_headers_are_rejected_with_static_errors() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let cases = [
            Vec::new(),
            format!("authorization: Bearer {TOKEN}\n").into_bytes(),
            format!("Authorization: bearer {TOKEN}\n").into_bytes(),
            format!("Authorization: Bearer {TOKEN}\r\n").into_bytes(),
            format!("Authorization: Bearer {TOKEN}\nCookie: other\n").into_bytes(),
            format!("Authorization: Bearer {TOKEN}\n\n").into_bytes(),
            format!("Authorization: Bearer {TOKEN} \n").into_bytes(),
            format!(" Authorization: Bearer {TOKEN}\n").into_bytes(),
            b"Authorization: Bearer \n".to_vec(),
            format!(
                "Authorization: Bearer {}\n",
                TOKEN.replacen(".1.", ".01.", 1)
            )
            .into_bytes(),
            b"Authorization: Bearer \xff\n".to_vec(),
            vec![b'x'; MAX_HEADER_BYTES],
            vec![b'x'; MAX_HEADER_BYTES + 1],
        ];
        for (index, bytes) in cases.into_iter().enumerate() {
            let path = fixture.header(&format!("invalid-{index}.header"), &bytes)?;
            rejected(&path)?;
            assert_eq!(fs::read(path)?, bytes);
        }
        Ok(())
    }

    #[test]
    fn absent_directory_and_empty_paths_do_not_expose_path_diagnostics() -> io::Result<()> {
        let fixture = Fixture::new()?;
        assert_eq!(
            rejected(&fixture.0.join("missing.header"))?.kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            rejected(&fixture.0)?.kind(),
            io::ErrorKind::PermissionDenied
        );
        let error = Authorization::read(Path::new(""))
            .err()
            .ok_or_else(|| io::Error::other("expected empty path rejection"))?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), ERROR);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_leaves_and_parents_are_not_followed_or_repaired() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new()?;
        let bytes = format!("Authorization: Bearer {TOKEN}\n");
        let original = fixture.header("original.header", bytes.as_bytes())?;
        let link = fixture.0.join("linked.header");
        symlink(&original, &link)?;
        assert_eq!(rejected(&link)?.kind(), io::ErrorKind::PermissionDenied);
        assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
        assert_eq!(fs::read(&original)?, bytes.as_bytes());

        let dangling = fixture.0.join("dangling.header");
        let missing = fixture.0.join("missing.header");
        symlink(&missing, &dangling)?;
        assert_eq!(rejected(&dangling)?.kind(), io::ErrorKind::PermissionDenied);
        assert!(!missing.exists());

        let linked_parent = fixture.0.join("linked-parent");
        symlink(&fixture.0, &linked_parent)?;
        assert_eq!(
            rejected(&linked_parent.join("original.header"))?.kind(),
            io::ErrorKind::PermissionDenied
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn nonprivate_modes_and_hard_links_are_rejected_without_permission_changes() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new()?;
        let bytes = format!("Authorization: Bearer {TOKEN}\n");
        let path = fixture.header("modes.header", bytes.as_bytes())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert_eq!(rejected(&path)?.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o640);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        fs::hard_link(&path, fixture.0.join("second-link.header"))?;
        assert_eq!(rejected(&path)?.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_file(fixture.0.join("second-link.header"))?;
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o750))?;
        let error = rejected(&path);
        let unchanged = fs::metadata(&fixture.0)?.permissions().mode() & 0o777;
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700))?;
        assert_eq!(error?.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(unchanged, 0o750);
        assert_eq!(fs::read(path)?, bytes.as_bytes());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn read_only_private_parent_is_sufficient() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new()?;
        let path = fixture.header(
            "readable.header",
            format!("Authorization: Bearer {TOKEN}\n").as_bytes(),
        )?;
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o500))?;
        let result = Authorization::read(&path);
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700))?;
        assert!(result?.into_value().is_sensitive());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fifo_is_rejected_without_waiting_for_a_writer() -> io::Result<()> {
        use std::os::unix::fs::FileTypeExt as _;

        let fixture = Fixture::new()?;
        let path = fixture.0.join("pipe.header");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )?;
        assert_eq!(rejected(&path)?.kind(), io::ErrorKind::PermissionDenied);
        assert!(fs::symlink_metadata(path)?.file_type().is_fifo());
        Ok(())
    }
}
