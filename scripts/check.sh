#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
if [ -z "${BUNTRAIL_STATE_DIR:-}" ]; then
  state=$(mktemp -d "${TMPDIR:-/tmp}/buntrail-check.XXXXXXXX")
  trap 'rm -rf "$state"' EXIT HUP INT TERM
  export BUNTRAIL_STATE_DIR="$state"
fi
cargo fmt --all --check
case "$(uname -s)" in
  Darwin|Linux)
    rg_binary=${BUNTRAIL_RIPGREP_BINARY:-$(command -v rg)}
    "$rg_binary" --version | head -1 | grep -qx 'ripgrep 15.1.0'
    cargo test --all-targets --all-features --no-run --offline
    target=$(cargo metadata --no-deps --format-version 1 --offline | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')
    mkdir -p "$target/debug/deps"
    cp "$rg_binary" "$target/debug/rg"
    cp "$rg_binary" "$target/debug/deps/rg"
    ;;
  *) echo 'Unix-specific checks unavailable on this platform' >&2 ;;
esac
cargo test --all-features --offline
cargo test --examples --all-features --offline
cargo clippy --all-targets --all-features --offline -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --offline
