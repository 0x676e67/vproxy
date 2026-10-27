//! Verified self-update coordination. All remote inputs are bounded and the
//! current executable is touched only by the final, single replacement call.

mod archive;
mod fetch;
mod staging;

use std::{
    io::{self, BufReader, Write as _},
    path::Path,
};

use self_update::update::Release;

/// One bounded release source. The production implementation owns its TLS
/// client and common deadline; tests inject faults without installing code.
trait Source {
    fn releases(&self, current: &str) -> io::Result<Vec<Release>>;
    fn read_checksum(&self, url: &str, name: &str) -> io::Result<[u8; 32]>;
    fn download(&self, url: &str, digest: [u8; 32], output: &mut std::fs::File) -> io::Result<()>;
    fn check_deadline(&self) -> io::Result<()>;
}

impl Source for fetch::Client {
    fn releases(&self, current: &str) -> io::Result<Vec<Release>> {
        fetch::Client::releases(self, current)
    }
    fn read_checksum(&self, url: &str, name: &str) -> io::Result<[u8; 32]> {
        fetch::Client::read_checksum(self, url, name)
    }
    fn download(&self, url: &str, digest: [u8; 32], output: &mut std::fs::File) -> io::Result<()> {
        fetch::Client::download(self, url, digest, output)
    }
    fn check_deadline(&self) -> io::Result<()> {
        fetch::Client::check_deadline(self)
    }
}

/// Release capability comes from this executable, never from asset metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Variant {
    Proxy,
    Api,
    Web,
}

impl Variant {
    /// eBPF builds have no matching automatic-update artifact.
    fn current() -> io::Result<Self> {
        if cfg!(feature = "ebpf") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "automatic updates are unavailable for eBPF-enabled builds",
            ));
        }
        Ok(if cfg!(feature = "web-ui") {
            Self::Web
        } else if cfg!(feature = "management") {
            Self::Api
        } else {
            Self::Proxy
        })
    }

    /// Both components are fixed/bounded before becoming an exact basename.
    fn archive_name(self, version: &str, target: &str) -> Option<String> {
        if !component(version, 128, true) || !component(target, 96, false) {
            return None;
        }
        let suffix = match self {
            Self::Proxy => "",
            Self::Api => "-api",
            Self::Web => "-web",
        };
        Some(format!("vproxy-{version}{suffix}-{target}.tar.gz"))
    }
}

fn component(value: &str, limit: usize, dots: bool) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') || dots && byte == b'.'
        })
}

/// Only the version is printed. Remote release notes never enter the terminal.
pub(super) enum Outcome {
    UpToDate,
    Updated(String),
}

/// Preserve the dependency's API-order, greater-version and compatible-first
/// policy. Selection precedes asset checks: a missing package never selects an
/// older release or a less capable profile.
fn select(releases: Vec<Release>, current: &str) -> io::Result<Option<Release>> {
    self_update::version::bump_is_greater(current, current)
        .map_err(|_| invalid("invalid compiled update version"))?;
    let mut greater = releases
        .into_iter()
        .filter(|release| {
            self_update::version::bump_is_greater(current, &release.version).unwrap_or(false)
        })
        .collect::<Vec<_>>();
    let selected = greater
        .iter()
        .position(|release| {
            self_update::version::bump_is_compatible(current, &release.version).unwrap_or(false)
        })
        .or_else(|| (!greater.is_empty()).then_some(0));
    Ok(selected.map(|index| greater.swap_remove(index)))
}

/// Require one archive and one sidecar from this same selected release.
fn assets(release: &Release, name: &str) -> io::Result<(String, String)> {
    let sidecar = format!("{name}.sha256");
    let mut archive_url = None;
    let mut checksum_url = None;
    for asset in &release.assets {
        let slot = if asset.name == name {
            &mut archive_url
        } else if asset.name == sidecar {
            &mut checksum_url
        } else {
            continue;
        };
        if slot.replace(asset.download_url.clone()).is_some() {
            return Err(invalid("release contains duplicate update assets"));
        }
    }
    match (archive_url, checksum_url) {
        (Some(archive), Some(checksum)) => Ok((archive, checksum)),
        _ => Err(invalid(
            "release is missing the exact package or checksum for this build",
        )),
    }
}

/// Run only from the explicit `self update` command. Tests inject replacement;
/// they never execute a downloaded program or replace the running test binary.
pub(super) fn update() -> io::Result<Outcome> {
    let variant = Variant::current()?;
    let client = fetch::Client::new()?;
    install(
        &client,
        variant,
        env!("CARGO_PKG_VERSION"),
        self_update::get_target(),
        |path| self_update::self_replace::self_replace(path),
    )
}

fn install(
    client: &impl Source,
    variant: Variant,
    current: &str,
    target: &str,
    replace: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<Outcome> {
    if !component(target, 96, false) {
        return Err(invalid("invalid compiled update target"));
    }
    self_update::version::bump_is_greater(current, current)
        .map_err(|_| invalid("invalid compiled update version"))?;
    let Some(release) = select(client.releases(current)?, current)? else {
        return Ok(Outcome::UpToDate);
    };
    let name = variant
        .archive_name(&release.version, target)
        .ok_or_else(|| {
            invalid("release version or build target is not a valid package component")
        })?;
    let (archive_url, checksum_url) = assets(&release, &name)?;
    let digest = client.read_checksum(&checksum_url, &name)?;
    let mut stage =
        staging::Stage::new().map_err(|_| invalid("cannot create private update staging"))?;
    let archive_name = "download.tar.gz";
    {
        let mut output = stage
            .create(archive_name)
            .map_err(|_| invalid("cannot create private update download"))?;
        client.download(&archive_url, digest, &mut output)?;
        output
            .sync_all()
            .map_err(|_| invalid("cannot flush verified update download"))?;
    }
    let binary = if target.contains("-windows-") {
        "vproxy.exe"
    } else {
        "vproxy"
    };
    {
        let input = stage
            .open(archive_name)
            .map_err(|_| invalid("cannot reopen verified update download"))?;
        let mut output = stage
            .create(binary)
            .map_err(|_| invalid("cannot create private update candidate"))?;
        archive::extract(BufReader::new(input), &mut output, variant, binary)
            .map_err(|_| invalid("update archive failed validation"))?;
        output
            .flush()
            .and_then(|()| output.sync_all())
            .map_err(|_| invalid("cannot flush verified update candidate"))?;
    }
    let candidate = stage
        .open(binary)
        .map_err(|_| invalid("cannot verify private update candidate"))?;
    let path = stage
        .path(binary)
        .map_err(|_| invalid("cannot resolve private update candidate"))?;
    client.check_deadline()?;
    // Windows replacement can move the old executable before a later failure.
    // An error at this boundary is unconfirmed installation state, not a safe
    // pre-install rejection. Never call the replacement closure a second time.
    replace(&path).map_err(|_| io::Error::other(
        "executable replacement failed; installation state is unconfirmed; inspect it before retrying",
    ))?;
    drop(candidate);
    Ok(Outcome::Updated(release.version))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use self_update::update::ReleaseAsset;
    use sha2::{Digest as _, Sha256};
    use std::{
        cell::{Cell, RefCell},
        io::{Cursor, Read as _},
    };

    const TARGET: &str = "x86_64-unknown-linux-musl";
    const WINDOWS: &str = "x86_64-pc-windows-msvc";

    fn release(version: &str, variant: Variant, target: &str) -> Release {
        let name = variant.archive_name(version, target).unwrap();
        Release {
            name: version.into(),
            version: version.into(),
            date: String::new(),
            body: Some("untrusted terminal controls must not be printed".into()),
            assets: [name.clone(), format!("{name}.sha256")]
                .into_iter()
                .map(|name| ReleaseAsset {
                    download_url: format!(
                        "https://github.com/0x676e67/vproxy/releases/download/v{version}/{name}"
                    ),
                    name,
                })
                .collect(),
        }
    }

    fn archive(variant: Variant, target: &str) -> Vec<u8> {
        let mut archive = tar::Builder::new(Vec::new());
        let binary = if target.contains("-windows-") {
            "vproxy.exe"
        } else {
            "vproxy"
        };
        let mut members = vec![(binary, 0o755)];
        if variant != Variant::Proxy {
            members.extend([("LICENSE", 0o644), ("README.md", 0o644)]);
        }
        if variant == Variant::Web {
            members.push(("LICENSE.ant-design-pro", 0o644));
        }
        for (name, mode) in members {
            let mut header = tar::Header::new_ustar();
            header.set_size(7);
            header.set_mode(mode);
            header.set_cksum();
            archive
                .append_data(&mut header, name, Cursor::new(b"payload"))
                .unwrap();
        }
        let raw = archive.into_inner().unwrap();
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&raw).unwrap();
        gzip.finish().unwrap()
    }

    struct Fake {
        releases: RefCell<Option<Vec<Release>>>,
        bytes: Vec<u8>,
        calls: RefCell<Vec<&'static str>>,
        fail: Option<&'static str>,
    }
    impl Fake {
        fn new(variant: Variant, target: &str) -> Self {
            Self {
                releases: RefCell::new(Some(vec![release("2.6.0", variant, target)])),
                bytes: archive(variant, target),
                calls: RefCell::new(Vec::new()),
                fail: None,
            }
        }
        fn step(&self, name: &'static str) -> io::Result<()> {
            self.calls.borrow_mut().push(name);
            if self.fail == Some(name) {
                Err(io::Error::other("synthetic source failure"))
            } else {
                Ok(())
            }
        }
    }
    impl Source for Fake {
        fn releases(&self, _: &str) -> io::Result<Vec<Release>> {
            self.step("metadata")?;
            Ok(self.releases.borrow_mut().take().unwrap())
        }
        fn read_checksum(&self, url: &str, name: &str) -> io::Result<[u8; 32]> {
            self.step("checksum")?;
            assert!(url.ends_with(&format!("/{name}.sha256")));
            Ok(Sha256::digest(&self.bytes).into())
        }
        fn download(
            &self,
            url: &str,
            expected: [u8; 32],
            output: &mut std::fs::File,
        ) -> io::Result<()> {
            self.step("download")?;
            assert!(url.ends_with(".tar.gz"));
            assert_eq!(expected, <[u8; 32]>::from(Sha256::digest(&self.bytes)));
            output.write_all(&self.bytes)
        }
        fn check_deadline(&self) -> io::Result<()> {
            self.step("deadline")
        }
    }

    #[test]
    fn variant_and_components_are_fixed_and_unsupported_builds_fail_before_network() {
        let current = Variant::current();
        if cfg!(feature = "ebpf") {
            assert_eq!(current.err().unwrap().kind(), io::ErrorKind::Unsupported);
        } else {
            assert_eq!(
                current.unwrap(),
                if cfg!(feature = "web-ui") {
                    Variant::Web
                } else if cfg!(feature = "management") {
                    Variant::Api
                } else {
                    Variant::Proxy
                }
            );
        }
        for value in ["", "../1.0", "x/y", "x\\y", "-1", "é", "1\n"] {
            assert!(Variant::Proxy.archive_name(value, TARGET).is_none());
            assert!(Variant::Proxy.archive_name("2.6.0", value).is_none());
        }
        let source = Fake::new(Variant::Proxy, TARGET);
        assert!(
            install(&source, Variant::Proxy, "2.5.5", "../target", |_| panic!(
                "no replacement"
            ))
            .is_err()
        );
        assert!(source.calls.borrow().is_empty());
    }

    #[test]
    fn selection_preserves_api_order_and_compatible_first_without_asset_fallback() {
        let entries = || {
            vec![
                release("3.0.0", Variant::Web, TARGET),
                release("2.7.0", Variant::Web, TARGET),
                release("2.6.0", Variant::Web, TARGET),
            ]
        };
        assert_eq!(
            select(entries(), "2.5.5").unwrap().unwrap().version,
            "2.7.0"
        );
        assert_eq!(
            select(entries(), "1.0.0").unwrap().unwrap().version,
            "3.0.0"
        );
        assert!(select(entries(), "4.0.0").unwrap().is_none());
        assert!(select(entries(), "invalid").is_err());
        for variant in [Variant::Proxy, Variant::Api, Variant::Web] {
            let name = variant.archive_name("2.6.0", TARGET).unwrap();
            let selected = release("2.6.0", variant, TARGET);
            assert!(assets(&selected, &name).is_ok());
            for bad in [
                vec![selected.assets[0].clone()],
                vec![selected.assets[1].clone()],
                vec![
                    selected.assets[0].clone(),
                    selected.assets[0].clone(),
                    selected.assets[1].clone(),
                ],
            ] {
                assert!(
                    assets(
                        &Release {
                            assets: bad,
                            ..selected.clone()
                        },
                        &name
                    )
                    .is_err()
                );
            }
            assert!(assets(&selected, &format!("extra-{name}")).is_err());
        }
    }

    #[test]
    fn validated_profiles_replace_once_without_executing_the_candidate() -> io::Result<()> {
        for variant in [Variant::Proxy, Variant::Api, Variant::Web] {
            for target in [TARGET, WINDOWS] {
                let source = Fake::new(variant, target);
                let calls = Cell::new(0);
                let mut candidate = None;
                let outcome = install(&source, variant, "2.5.5", target, |path| {
                    calls.set(calls.get() + 1);
                    candidate = Some(path.to_owned());
                    let mut bytes = Vec::new();
                    std::fs::File::open(path)?.read_to_end(&mut bytes)?;
                    assert_eq!(bytes, b"payload");
                    Ok(())
                })?;
                assert!(matches!(outcome, Outcome::Updated(ref version) if version=="2.6.0"));
                assert_eq!(calls.get(), 1);
                assert_eq!(
                    *source.calls.borrow(),
                    ["metadata", "checksum", "download", "deadline"]
                );
                assert!(
                    !candidate.unwrap().exists(),
                    "only this owned staging file is cleaned"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn every_pre_install_failure_has_zero_replacements_and_replacement_error_is_unconfirmed() {
        for failure in [
            "metadata",
            "checksum",
            "download",
            "deadline",
            "archive",
            "missing_pair",
        ] {
            let mut source = Fake::new(Variant::Api, TARGET);
            match failure {
                "archive" => source.bytes = b"not gzip".to_vec(),
                "missing_pair" => {
                    let mut rows = source.releases.borrow_mut();
                    let rows = rows.as_mut().unwrap();
                    rows[0].assets.clear();
                    rows.push(release("2.5.6", Variant::Api, TARGET));
                }
                _ => source.fail = Some(failure),
            }
            let calls = Cell::new(0);
            assert!(
                install(&source, Variant::Api, "2.5.5", TARGET, |_| {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(calls.get(), 0, "{failure}");
            if failure == "missing_pair" {
                assert_eq!(*source.calls.borrow(), ["metadata"]);
            }
        }
        let source = Fake::new(Variant::Proxy, TARGET);
        let calls = Cell::new(0);
        let error = install(&source, Variant::Proxy, "2.5.5", TARGET, |_| {
            calls.set(calls.get() + 1);
            Err(io::Error::other("private install path"))
        })
        .err()
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert!(
            error
                .to_string()
                .contains("installation state is unconfirmed")
        );
        assert!(!error.to_string().contains("private install path"));
        let source = Fake::new(Variant::Proxy, TARGET);
        *source.releases.borrow_mut() = Some(Vec::new());
        assert!(matches!(
            install(&source, Variant::Proxy, "2.5.5", TARGET, |_| panic!(
                "no replacement"
            ))
            .unwrap(),
            Outcome::UpToDate
        ));
        assert_eq!(*source.calls.borrow(), ["metadata"]);
    }
}
