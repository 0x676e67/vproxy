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
