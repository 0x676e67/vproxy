use self_update::cargo_crate_version;
use self_update::update::UpdateStatus;

use crate::BIN_NAME;

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
                println!("{}", body);
            } else {
                println!("{} upgraded to {}", BIN_NAME, release.version);
            }
        }
    } else {
        println!("{} is up-to-date", BIN_NAME);
    }

    Ok(())
}
