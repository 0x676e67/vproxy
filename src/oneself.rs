mod notices;
mod release;

/// Print only embedded licensing text; no installed file, database or network is read.
pub(super) fn notices() -> crate::Result<()> {
    notices::write(&mut std::io::stdout().lock()).map_err(Into::into)
}

/// Updates the current executable to the latest version available.
pub(super) fn update() -> crate::Result<()> {
    const BIN_NAME: &str = env!("CARGO_PKG_NAME");

    println!("Checking update packages for this build...");
    match release::update()? {
        release::Outcome::Updated(version) => println!("{BIN_NAME} upgraded to {version}"),
        release::Outcome::UpToDate => println!("{BIN_NAME} is up-to-date"),
    }

    Ok(())
}

/// HTTP loopback tests use an explicit provider instead of racing over a
/// process-wide default. No CA is trusted here: a test needing HTTPS must supply
/// its own roots rather than accidentally trusting a public or system issuer.
#[cfg(test)]
pub(crate) fn test_http_client_builder() -> std::io::Result<reqwest::ClientBuilder> {
    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(std::io::Error::other)?
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    Ok(reqwest::Client::builder().use_preconfigured_tls(tls))
}

/// Uninstalls the current executable.
pub(super) fn uninstall() -> crate::Result<()> {
    let current_exe = std::env::current_exe()?;
    println!("Uninstalling {}", current_exe.display());

    std::fs::remove_file(current_exe)?;

    println!("Uninstallation complete.");
    Ok(())
}
