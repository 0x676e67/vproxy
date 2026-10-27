#!/usr/bin/env bash
# cargo-zigbuild 0.23.4 mistakes -M/-MM for ARM linking and adds a second C input.
# Keep dependency generation, CPU settings and true linking intact by making the
# preprocessing mode explicit before delegating to its original compiler.
set -Eeuo pipefail

case ${TARGET:-} in
  armv7-unknown-linux-musleabihf) compiler_key=CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER ;;
  arm-unknown-linux-musleabihf) compiler_key=CARGO_TARGET_ARM_UNKNOWN_LINUX_MUSLEABIHF_LINKER ;;
  *) printf 'Unsupported dependency compiler target\n' >&2; exit 2 ;;
esac
compiler=${!compiler_key:-}
if [[ $compiler != /* || ! -f $compiler || ! -x $compiler || $compiler -ef $0 ]]; then
  printf 'Missing original target compiler\n' >&2
  exit 2
fi
dependencies=false
preprocessing=false
for argument in "$@"; do
  case "$argument" in
    -M|-MM) dependencies=true ;;
    -E) preprocessing=true ;;
  esac
done
if $dependencies && ! $preprocessing; then
  set -- -E "$@"
fi
exec "$compiler" "$@"
