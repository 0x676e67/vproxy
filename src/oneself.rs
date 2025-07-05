use crate::BIN_NAME;
use self_update::cargo_crate_version;
use self_update::update::UpdateStatus;

/// Updates the current executable to the latest version available.
///
/// This function uses the `self_update` crate to check for updates and apply them if available.
/// It configures the update process with various options such as repository name, binary name,
/// target platform, and current version. If an update is found, it downloads and applies the update,
/// and then prints the release notes or a message indicating that the update was successful.
///
/// # Errors
///
/// This function returns an error if the update process fails at any step, such as building the updater,
/// checking for updates, or applying the update.
pub(super) fn update() -> crate::Result<()> {
    let status = self_update::backends::github::Update::configure()
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
///
/// This function deletes the currently running executable from the file system.
/// It retrieves the path to the current executable using `std::env::current_exe` and then
/// removes the file at that path. This operation requires appropriate file system permissions.
///
/// # Errors
///
/// This function returns an error if it fails to retrieve the current executable path or if it
/// fails to delete the file.
pub(super) fn uninstall() -> crate::Result<()> {
    let current_exe = std::env::current_exe()?;
    println!("Uninstalling {}", current_exe.display());

    std::fs::remove_file(current_exe)?;

    println!("Uninstallation complete.");
    Ok(())
}
