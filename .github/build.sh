#!/usr/bin/env bash
# Linux cross-release builder. No upload is performed here. Every invocation
# owns a fresh target/ directory and hands off one complete, new bin/ directory.
set -Eeuo pipefail
umask 077

fail() {
  printf 'Build error: %s\n' "$1" >&2
  exit 1
}

failed() {
  local status=$?
  printf 'Build failed (%s); private work retained at %s\n' "$status" "${build_stage:-not-created}" >&2
  exit "$status"
}
trap failed ERR

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
build_root=$(cd -- "${root:-$script_directory/..}" && pwd -P)
build_tag=${tag:-latest}
build_os=${os:-linux}
build_profiles=${profiles:-proxy}
build_target_filter=${targets-}
build_target_filter_set=${targets+x}
[[ ${name:-vproxy} == vproxy ]] || fail 'Only the vproxy binary is supported'
[[ $build_tag =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail 'Invalid release tag'
[[ -f "$build_root/Cargo.toml" && -f "$build_root/Cargo.lock" ]] || fail 'Expected the vproxy source root'
[[ ! -e "$build_root/bin" && ! -L "$build_root/bin" ]] || fail 'bin already exists; use a fresh checkout'
case "$build_profiles" in
  proxy|api|web) selected_profiles=("$build_profiles") ;;
  all) selected_profiles=(proxy api web) ;;
  *) fail 'Unsupported profiles; choose proxy, api, web or all' ;;
esac
if [[ $build_profiles != proxy ]]; then
  for document in LICENSE README.md; do
    [[ -f "$build_root/$document" && ! -L "$build_root/$document" && -s "$build_root/$document" ]] || fail "Missing release document: $document"
  done
fi
if [[ $build_profiles == web || $build_profiles == all ]]; then
  for document in web/LICENSE.ant-design-pro web/dist/vproxy-web.json web/dist/index.html; do
    [[ -f "$build_root/$document" && ! -L "$build_root/$document" && -s "$build_root/$document" ]] || fail "Missing Web release input: $document"
  done
fi

# Explicit userspace keeps --no-default-features from silently skipping the
# feature-gated main binary. Keep the established nine release target names.
windows_targets=(
  'x86_64-pc-windows-gnu:userspace'
  'i686-pc-windows-gnu:userspace'
)
macos_targets=(
  'x86_64-apple-darwin:userspace'
  'aarch64-apple-darwin:userspace'
)
linux_targets=(
  'x86_64-unknown-linux-musl:userspace,mimalloc'
  'aarch64-unknown-linux-musl:userspace,mimalloc'
  'armv7-unknown-linux-musleabihf:userspace,jemalloc'
  'arm-unknown-linux-musleabihf:userspace,jemalloc'
  'i686-unknown-linux-musl:userspace,jemalloc'
)
case "$build_os" in
  windows) targets=("${windows_targets[@]}") ;;
  macos) targets=("${macos_targets[@]}") ;;
  linux) targets=("${linux_targets[@]}") ;;
  all) targets=("${windows_targets[@]}" "${macos_targets[@]}" "${linux_targets[@]}") ;;
  *) fail "Unsupported os: $build_os" ;;
esac

if [[ -n $build_target_filter_set ]]; then
  [[ $build_target_filter =~ ^[A-Za-z0-9_-]+(,[A-Za-z0-9_-]+)*$ ]] || fail 'Invalid target subset'
  IFS=, read -r -a requested_targets <<< "$build_target_filter"
  filtered_targets=()
  for requested_target in "${requested_targets[@]}"; do
    matched_target=
    for entry in "${targets[@]}"; do
      if [[ ${entry%%:*} == "$requested_target" ]]; then
        matched_target=$entry
        break
      fi
    done
    [[ -n $matched_target ]] || fail "Target is not in the selected OS group: $requested_target"
    for entry in "${filtered_targets[@]}"; do
      [[ ${entry%%:*} != "$requested_target" ]] || fail "Duplicate target: $requested_target"
    done
    filtered_targets+=("$matched_target")
  done
  targets=("${filtered_targets[@]}")
fi

for tool in cargo rustup cp chmod tar shasum mktemp mv stat grep dirname mkdir env printenv; do
  command -v "$tool" >/dev/null || fail "Required tool is unavailable: $tool"
done
if [[ " ${targets[*]} " == *-windows-* ]]; then
  # AWS-LC has no prebuilt Win32 NASM fallback. Check before doing any build.
  command -v nasm >/dev/null || fail 'Required tool is unavailable: nasm'
  nasm -v >/dev/null || fail 'Required tool cannot run: nasm'
fi
# Release artifacts use the Cargo.lock-bundled AWS-LC, never host pkg-config
# discovery. Per-target variables take precedence in aws-lc-sys 0.46.
export AWS_LC_SYS_USE_SYSTEM=0
[[ ! -L "$build_root/target" ]] || fail 'target must not be a symlink'
mkdir -p -- "$build_root/target"
build_stage=$(mktemp -d "$build_root/target/cross-release.XXXXXXXX")
mkdir -- "$build_stage/artifacts"
mkdir -- "$build_stage/previous"
# Final handoff must be a same-filesystem rename, not mv's recursive-copy fallback.
stage_device=$(stat -c '%d' -- "$build_stage/artifacts")
root_device=$(stat -c '%d' -- "$build_root")
[[ $stage_device =~ ^[0-9]+$ && $root_device =~ ^[0-9]+$ && $stage_device == "$root_device" ]] || fail 'target and output must share a filesystem'
installed_targets=$(rustup target list --installed)

build_one() {
  local target=$1 features=$2 profile=$3 binary_name=vproxy method=zigbuild suffix=
  local binary target_stage archive listing expected_listing document
  local members
  local aws_policy_key="AWS_LC_SYS_USE_SYSTEM_${target//-/_}"
  export "$aws_policy_key=0"
  # Keep each target's allocator policy for all capabilities. Neither richer
  # profile silently changes the allocator used by its proxy listeners.
  case "$profile" in
    api) features+=,management; suffix=-api ;;
    web) features+=,web-ui; suffix=-web ;;
  esac
  if [[ $target == *windows* ]]; then
    binary_name=vproxy.exe
    method=build
  fi
  if ! grep -Fxq -- "$target" <<< "$installed_targets"; then
    rustup target add "$target"
  fi
  binary="$build_stage/build/$target/release/$binary_name"
  if [[ -e $binary || -L $binary ]]; then
    # Cargo's capability selection can otherwise leave the preceding profile's
    # executable in a shared target directory. Preserve it, then require a new
    # output leaf. Dependencies still share this invocation's build cache.
    [[ -f $binary && ! -L $binary && -s $binary ]] || fail 'Invalid preceding build output'
    local previous="$build_stage/previous/$target-before-$profile"
    [[ ! -e $previous && ! -L $previous ]] || fail 'Previous output path already exists'
    mv -T --no-clobber -- "$binary" "$previous"
    [[ ! -e $binary && ! -L $binary && -f $previous && ! -L $previous ]] || fail 'Previous output was not preserved'
  fi
  printf 'Building %s/%s (%s)\n' "$profile" "$target" "$features"
  local arguments=(
    "$method" --manifest-path "$build_root/Cargo.toml"
    --release --locked --no-default-features --bin vproxy
    --target "$target" --target-dir "$build_stage/build" --features "$features"
  )
  local cc_key="CC_${target//-/_}" linker_key="CARGO_TARGET_${target^^}_LINKER"
  linker_key=${linker_key//-/_}
  if [[ $target == armv7-unknown-linux-musleabihf || $target == arm-unknown-linux-musleabihf ]] &&
      [[ ! ${!cc_key+x} ]] && ! printenv "CC_$target" >/dev/null; then
    # The default CC and Rust linker are the same cargo-zigbuild wrapper. Leave
    # the linker untouched so its ARM ABI helpers still run on real links.
    [[ ! ${!linker_key+x} ]] || fail 'Custom ARM linker requires an explicit target CC'
    local cc_adapter="$build_stage/cc-$target"
    cp -- "$script_directory/zig-cc.sh" "$cc_adapter"
    chmod 755 -- "$cc_adapter"
    env "$cc_key=$cc_adapter" cargo "${arguments[@]}"
  elif [[ $target == *apple-darwin ]]; then
    CARGO_PROFILE_RELEASE_STRIP=none cargo "${arguments[@]}"
  else
    cargo "${arguments[@]}"
  fi
  binary="$build_stage/build/$target/release/$binary_name"
  [[ -f $binary && ! -L $binary && -s $binary ]] || fail "No binary was produced for $target"
  target_stage="$build_stage/$target$suffix"
  mkdir -- "$target_stage"
  cp -- "$binary" "$target_stage/$binary_name"
  chmod 755 -- "$target_stage/$binary_name"
  # Keep the linked bytes intact, so native checks exercise the same executable
  # that is archived. The gzip archive handles transfer compression.
  printf 'Keeping native executable for %s\n' "$target"
  [[ -f "$target_stage/$binary_name" && ! -L "$target_stage/$binary_name" && -s "$target_stage/$binary_name" ]] || fail "Invalid packaged binary for $target"
  members=("$binary_name")
  if [[ $profile != proxy ]]; then
    for document in LICENSE README.md; do
      cp -- "$build_root/$document" "$target_stage/$document"
      chmod 644 -- "$target_stage/$document"
      members+=("$document")
    done
  fi
  if [[ $profile == web ]]; then
    cp -- "$build_root/web/LICENSE.ant-design-pro" "$target_stage/LICENSE.ant-design-pro"
    chmod 644 -- "$target_stage/LICENSE.ant-design-pro"
    members+=(LICENSE.ant-design-pro)
  fi
  archive="vproxy-$build_tag$suffix-$target.tar.gz"
  tar --format=ustar -czf "$build_stage/artifacts/$archive" -C "$target_stage" "${members[@]}"
  listing=$(tar -tzf "$build_stage/artifacts/$archive")
  expected_listing=$(printf '%s\n' "${members[@]}")
  [[ $listing == "$expected_listing" ]] || fail "Unexpected archive contents for $profile/$target"
  (
    cd -- "$build_stage/artifacts"
    shasum -a 256 "$archive" > "$archive.sha256"
    shasum -a 256 -c "$archive.sha256"
  )
}

for entry in "${targets[@]}"; do
  for profile in "${selected_profiles[@]}"; do
    build_one "${entry%%:*}" "${entry#*:}" "$profile"
  done
done

# No target is visible under bin/ until the complete invocation succeeds.
# Never merge into or replace an existing directory, even if it appeared late.
[[ ! -e "$build_root/bin" && ! -L "$build_root/bin" ]] || fail 'bin appeared during the build; refusing to replace it'
mv -T --no-clobber -- "$build_stage/artifacts" "$build_root/bin"
[[ ! -e "$build_stage/artifacts" && -d "$build_root/bin" && ! -L "$build_root/bin" ]] || fail 'Output handoff did not complete'
printf 'Build complete: %s targets x %s profiles in %s/bin\n' "${#targets[@]}" "${#selected_profiles[@]}" "$build_root"
