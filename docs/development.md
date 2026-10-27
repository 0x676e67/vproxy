# Development

## Build and test

Use Rust 1.97 or newer. Work from a checkout and use the existing lockfile:

```sh
cargo test --locked
cargo test --locked --no-default-features --features management
cargo test --locked --no-default-features --features web-ui
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo +nightly fmt --all --check
```

Web tests and builds need a current frontend bundle. See [Installation](installation.md)
for the build commands. The experimental `witness-journal` feature additionally
requires the SQLite Session build and bindgen's libclang headers; test that feature
when changing its gated code. Use native Windows tests for Windows-specific behavior.

## Frontend

Node.js 22.12 or newer is required only for development:

```sh
cd web
npm ci
npm run dev:demo
```

Demo mode uses marked browser-local samples and resets added data on reload.
`npm run dev` uses the real same-origin HTTPS management API. To check and build it:

```sh
npm run typecheck
npm test
npm run build
npm run preview
```

Cargo never invokes npm implicitly. `build:demo` output cannot be embedded in a
management binary. The frontend supports English and Simplified Chinese.

## Release checks

The repository has local helpers for proxy, API and Web packages, matching-host
CLI checks and selected loopback runtime checks. They validate archive membership,
checksums, feature dependencies and the source package used to build them.
Their artifacts are build checks, not signatures or a published release.

Use `.github/release_profiles.py --help` and `.github/cross_artifacts.py --help`
for local selection. Cross builds use the pinned Rust, Zig and cargo-zigbuild
versions in the release workflow. Choose only the target and profile you intend
to verify rather than assuming a cross build also exercised its runtime.

## Organize source modules

The management implementation lives in `src/manage.rs` and `src/manage/`, matching
the `vproxy manage` command. Its Cargo feature remains named `management`.
Keep methods on the same coordinator together and shared response types in
`manage/views.rs`; a small adapter rarely needs its own file.

Use `name.rs` as a module entry; this project does not use `mod.rs` files.
Keep a `name/` directory only when it contains actual child modules.
Put unit tests in inline test modules in the corresponding source file rather
than separate `tests.rs`, `*_tests.rs` files or test-only directories.
Remove directories that become empty after moving their tests.

Changes should preserve module visibility, feature gates and platform-specific
behavior. Keep generated data, runtime state and credentials outside `src/`.
