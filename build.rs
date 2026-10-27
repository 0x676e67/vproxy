//! Build the optional kernel object and validate an explicitly built Web bundle.
//!
//! Ordinary/API-only Cargo builds do not inspect Web files or compile the
//! optional validation dependencies. This is a freshness check, not a signature:
//! release builders must still trust the checkout, dependencies and local paths.

#![forbid(unsafe_code)]

fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=CARGO_FEATURE_WEB_UI");
    #[cfg(feature = "ebpf")]
    embedded_ebpf::build()?;
    #[cfg(feature = "web-ui")]
    embedded_web::validate()?;
    Ok(())
}

#[cfg(feature = "ebpf")]
mod embedded_ebpf {
    /// This internal feature selects only the no_std kernel binary in the same
    /// Cargo package. It cannot recursively enable this userspace build step.
    const PROGRAM_FEATURE: &str = "ebpf-program";
    /// Keep the compiler fixed: changing LLVM can change verifier acceptance
    /// even when host tests and the 52-byte map ABI remain unchanged.
    const TOOLCHAIN: &str = "nightly-2026-08-12";

    pub(super) fn build() -> std::io::Result<()> {
        if std::env::var_os("CARGO_CFG_TARGET_OS").as_deref() != Some(std::ffi::OsStr::new("linux"))
        {
            return Ok(());
        }
        for path in ["Cargo.toml", "Cargo.lock"] {
            println!("cargo::rerun-if-changed={path}");
        }
        aya_build::build_ebpf(
            [aya_build::Package {
                name: env!("CARGO_PKG_NAME"),
                // Aya uses this path for change tracking, not as a second
                // package. Do not watch the repository root and its target/.
                root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/vproxy-ebpf.rs"),
                no_default_features: true,
                features: &[PROGRAM_FEATURE],
            }],
            aya_build::Toolchain::Custom(TOOLCHAIN),
        )
        .map_err(std::io::Error::other)
    }
}

#[cfg(feature = "web-ui")]
mod embedded_web {
    use std::{
        collections::{BTreeMap, BTreeSet},
        env, fs,
        io::{self, Read},
        path::Path,
    };

    use serde::Deserialize;
    use sha2::{Digest, Sha256};

    const MANIFEST: &str = "vproxy-web.json";
    const MAX_FILES: usize = 20_000;
    const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
    const ROOT_SOURCES: [&str; 5] = [
        "web/package.json",
        "web/package-lock.json",
        "web/tsconfig.json",
        "web/vitest.config.mts",
        "web/LICENSE.ant-design-pro",
    ];
    const SOURCE_DIRECTORIES: [&str; 4] = ["config", "src", "tools", "public"];

    /// Both dictionaries use forward-slash relative paths. Sources are rooted at
    /// the Cargo package; assets are rooted at web/dist, excluding this manifest.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        schema: u32,
        mode: String,
        sources: BTreeMap<String, Fingerprint>,
        assets: BTreeMap<String, Fingerprint>,
    }

    /// SHA-256 covers exact file bytes, including their line endings. No host
    /// timestamp or absolute path participates in the portable build inventory.
    #[derive(Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Fingerprint {
        sha256: String,
        size: u64,
    }

    fn invalid(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message.into())
    }

    /// Missing, stale, demo or structurally ambiguous bundles fail closed. Cargo
    /// package builds apply the same comparison as a working-tree release build.
    pub(super) fn validate() -> io::Result<()> {
        let root = env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| invalid("Cargo package directory is unavailable"))?;
        let root = Path::new(&root);
        directory(&root.join("web"))?;
        let dist = root.join("web/dist");
        directory(&dist).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot validate web/dist ({error}); run npm ci && npm run build in web/ before enabling web-ui"
                ),
            )
        })?;
        println!("cargo::rerun-if-changed=web/dist");
        let manifest_path = dist.join(MANIFEST);
        let metadata = regular_file(&manifest_path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot validate web/dist/vproxy-web.json ({error}); run npm ci && npm run build in web/ before enabling web-ui"
                ),
            )
        })?;
        if metadata.len() > 8 * 1024 * 1024 {
            return Err(invalid("Web build manifest exceeds its size limit"));
        }
        let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)
            .map_err(|_| invalid("Web build manifest is not valid schema-1 JSON"))?;
        if manifest.schema != 1 || manifest.mode != "api" {
            return Err(invalid(
                "web-ui requires a schema-1 API bundle; run npm ci && npm run build in web/ (not build:demo)",
            ));
        }
        check_inventory(&manifest.sources)?;
        check_inventory(&manifest.assets)?;
        if !manifest.assets.contains_key("index.html") {
            return Err(invalid("Web build manifest is missing index.html"));
        }
        if manifest.assets.contains_key(MANIFEST) {
            return Err(invalid("Web build manifest cannot inventory itself"));
        }
        for key in manifest.assets.keys() {
            if let Some(original) = key.strip_suffix(".br").or_else(|| key.strip_suffix(".gz")) {
                if !compressible(original) || !manifest.assets.contains_key(original) {
                    return Err(invalid("Web build has an orphan compressed asset"));
                }
            } else if compressible(key)
                && (!manifest.assets.contains_key(&format!("{key}.br"))
                    || !manifest.assets.contains_key(&format!("{key}.gz")))
            {
                return Err(invalid("Web build is missing precompressed asset variants"));
            }
        }

        let mut sources = BTreeMap::new();
        for name in ROOT_SOURCES {
            println!("cargo::rerun-if-changed={name}");
            sources.insert(name.to_owned(), fingerprint(&root.join(name))?);
        }
        for name in SOURCE_DIRECTORIES {
            let relative = format!("web/{name}");
            println!("cargo::rerun-if-changed={relative}");
            let path = root.join(&relative);
            if name == "public" {
                match fs::symlink_metadata(&path) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                    Ok(_) => {}
                }
            }
            scan(&path, &relative, true, false, 0, &mut sources)?;
        }
        if sources != manifest.sources {
            return Err(invalid(
                "Web build sources are missing, added or modified; rebuild web/ after edits finish",
            ));
        }
        let mut assets = BTreeMap::new();
        scan(&dist, "", false, true, 0, &mut assets)?;
        if assets != manifest.assets {
            return Err(invalid(
                "Web build assets are missing, extra or modified; rebuild web/ before enabling web-ui",
            ));
        }
        Ok(())
    }

    /// Reject path traversal, platform separators and case-colliding file names
    /// before comparing against the enumerated filesystem tree.
    fn check_inventory(inventory: &BTreeMap<String, Fingerprint>) -> io::Result<()> {
        if inventory.len() > MAX_FILES {
            return Err(invalid("Web build inventory exceeds its file limit"));
        }
        let mut names = BTreeSet::new();
        for (name, file) in inventory {
            relative_path(name)?;
            if !names.insert(name.to_lowercase()) {
                return Err(invalid("Web build inventory has case-colliding paths"));
            }
            if file.size > MAX_FILE_BYTES
                || file.sha256.len() != 64
                || !file
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid("Web build inventory has an invalid fingerprint"));
            }
        }
        Ok(())
    }

    fn relative_path(value: &str) -> io::Result<()> {
        if value.is_empty()
            || value.contains(['\\', ':'])
            || value.chars().any(char::is_control)
            || value.split('/').any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(invalid("Web build contains a non-portable relative path"));
        }
        Ok(())
    }

    fn directory(path: &Path) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("Web build trees must be non-symlink directories"));
        }
        Ok(())
    }

    fn regular_file(path: &Path) -> io::Result<fs::Metadata> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid("Web build files must be regular non-symlink files"));
        }
        if metadata.len() > MAX_FILE_BYTES {
            return Err(invalid("Web build file exceeds its size limit"));
        }
        Ok(metadata)
    }

    /// Hash bounded files in fixed-size chunks, not one allocation per JS bundle.
    fn fingerprint(path: &Path) -> io::Result<Fingerprint> {
        let before = regular_file(path)?;
        let mut file = fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut buffer = [0; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let read_size = u64::try_from(read)
                .map_err(|_| invalid("Web build file read size is not representable"))?;
            size = size
                .checked_add(read_size)
                .filter(|size| *size <= MAX_FILE_BYTES)
                .ok_or_else(|| invalid("Web build file grew beyond its size limit"))?;
            hasher.update(&buffer[..read]);
        }
        let after = regular_file(path)?;
        if before.len() != size || after.len() != size || before.modified()? != after.modified()? {
            return Err(invalid("Web build file changed during validation"));
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut sha256 = String::with_capacity(64);
        for byte in hasher.finalize().iter() {
            sha256.push(char::from(HEX[usize::from(byte >> 4)]));
            sha256.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(Fingerprint { sha256, size })
    }

    /// Enumerate exact contents, refusing symlinks and special files rather than
    /// silently dropping them. Only generated source .umi* directories are skipped.
    fn scan(
        path: &Path,
        prefix: &str,
        generated: bool,
        assets: bool,
        depth: usize,
        inventory: &mut BTreeMap<String, Fingerprint>,
    ) -> io::Result<()> {
        if depth > 32 {
            return Err(invalid("Web build tree exceeds its depth limit"));
        }
        directory(path)?;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("Web build path is not UTF-8"))?;
            let key = if prefix.is_empty() {
                file_name.clone()
            } else {
                format!("{prefix}/{file_name}")
            };
            relative_path(&key)?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(invalid("Web build trees must not contain symlinks"));
            }
            if metadata.is_dir() {
                if generated && file_name.starts_with(".umi") {
                    continue;
                }
                scan(&entry.path(), &key, generated, assets, depth + 1, inventory)?;
            } else if !(assets && prefix.is_empty() && file_name == MANIFEST) {
                inventory.insert(key, fingerprint(&entry.path())?);
                if inventory.len() > MAX_FILES {
                    return Err(invalid("Web build inventory exceeds its file limit"));
                }
            }
        }
        Ok(())
    }

    fn compressible(path: &str) -> bool {
        matches!(
            Path::new(path).extension().and_then(|value| value.to_str()),
            Some(
                "js" | "mjs"
                    | "css"
                    | "html"
                    | "svg"
                    | "json"
                    | "txt"
                    | "xml"
                    | "webmanifest"
                    | "wasm"
            )
        )
    }
}
