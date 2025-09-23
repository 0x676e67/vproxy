use self_update::{backends::github, cargo_crate_version, update::UpdateStatus};

/// Updates the current executable to the latest version available.
pub(super) fn update() -> crate::Result<()> {
    const BIN_NAME: &str = env!("CARGO_PKG_NAME");

    let status = github::Update::configure()
        .repo_owner("0x676e67")
        .repo_name(BIN_NAME)
        .bin_name(BIN_NAME)
        .target(self_update::get_target())
        .show_output(true)
        .show_download_progress(true)
        .no_confirm(true)
        .current_version(cargo_crate_version!())
        .build()?
        .update_extended()?;

    if let UpdateStatus::Updated(ref release) = status {
        if let Some(body) = &release.body {
            if !body.trim().is_empty() {
                println!("{} upgraded to {}:\n", BIN_NAME, release.version);
                println!("{body}");
            } else {
                println!("{} upgraded to {}", BIN_NAME, release.version);
            }
        }
    } else {
        println!("{BIN_NAME} is up-to-date");
    }

    Ok(())
}

/// Uninstalls the current executable.
pub(super) fn uninstall() -> crate::Result<()> {
    let current_exe = std::env::current_exe()?;
    println!("Uninstalling {}", current_exe.display());

    std::fs::remove_file(current_exe)?;

    println!("Uninstallation complete.");
    Ok(())
}
