use self_update::cargo_crate_version;
use self_update::update::UpdateStatus;

pub(super) fn update() -> Result<(), Box<dyn std::error::Error>> {
    let status = self_update::backends::github::Update::configure()
        .repo_owner("0x676e67")
        .repo_name("vproxy")
        .bin_name("vproxy")
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
                println!("vproxy upgraded to {}:\n", release.version);
                println!("{}", body);
            } else {
                println!("vproxy upgraded to {}", release.version);
            }
        }
    } else {
        println!("vproxy is up-to-date");
    }

    Ok(())
}
