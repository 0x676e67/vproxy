//! Licensing text travels with the executable even when an installer/updater
//! publishes only that file. This is not a complete dependency license inventory.

use std::io::{self, Write};

const SCOPE: &[u8] =
    b"Project license and build-specific notices; not a complete dependency inventory.\n\n";
const PROJECT_HEADING: &[u8] = b"=== Project license (GPL-3.0) ===\n";
const PROJECT_LICENSE: &[u8] = include_bytes!("../../LICENSE");

// Keep the include itself behind the feature: proxy/API builds must not read a
// Web tree merely to expose the project's existing license.
#[cfg(feature = "web-ui")]
const WEB_HEADING: &[u8] = b"\n\n=== Embedded Web template notice (Ant Design Pro, MIT) ===\n";
#[cfg(feature = "web-ui")]
const WEB_NOTICE: &[u8] = include_bytes!("../../web/LICENSE.ant-design-pro");

/// Write complete original license bytes with fixed section headings and flush.
/// Partial writes or a failed flush are errors, not a successful notice delivery;
/// output is not atomic. Only compile-time inputs are used, without parsing or
/// normalizing their UTF-8, line endings or whitespace.
pub(super) fn write(output: &mut impl Write) -> io::Result<()> {
    output.write_all(SCOPE)?;
    output.write_all(PROJECT_HEADING)?;
    output.write_all(PROJECT_LICENSE)?;
    #[cfg(feature = "web-ui")]
    {
        output.write_all(WEB_HEADING)?;
        output.write_all(WEB_NOTICE)?;
    }
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SCOPE);
        bytes.extend_from_slice(PROJECT_HEADING);
        bytes.extend_from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/LICENSE"
        )));
        #[cfg(feature = "web-ui")]
        {
            bytes.extend_from_slice(WEB_HEADING);
            bytes.extend_from_slice(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/web/LICENSE.ant-design-pro"
            )));
        }
        bytes
    }

    #[test]
    fn complete_original_license_bytes_match_the_selected_build_capability() -> io::Result<()> {
        let mut output = Vec::new();
        write(&mut output)?;
        // The inactive feature has no Web include above or in this expected
        // value: a proxy/API source package need not contain the Web tree.
        assert_eq!(output, expected());
        Ok(())
    }

    struct FailingWriter {
        bytes: Vec<u8>,
        limit: usize,
        fail_flush: bool,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.bytes.len() == self.limit {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "fixture write failure",
                ));
            }
            let count = bytes.len().min(self.limit - self.bytes.len());
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("fixture flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn write_and_flush_errors_never_report_success() {
        let complete = expected();
        for limit in [0, SCOPE.len() + PROJECT_HEADING.len() + 7] {
            let mut output = FailingWriter {
                bytes: Vec::new(),
                limit,
                fail_flush: false,
            };
            let error = write(&mut output).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(output.bytes, complete[..limit]);
        }
        let mut output = FailingWriter {
            bytes: Vec::new(),
            limit: usize::MAX,
            fail_flush: true,
        };
        let error = write(&mut output).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(output.bytes, complete);
    }
}
