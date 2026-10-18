#!/bin/bash
set -euo pipefail
component_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# The original sandbox activated a pinned toolchain; elsewhere cargo on PATH is used.
activate="${RUST_ACTIVATE:-/workspace/rust-optimization/activate.sh}"
if [[ -f "$activate" ]]; then
    source "$activate"
fi
export CARGO_TARGET_DIR="$component_dir/target"
export RUSTFLAGS=''
unset CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
exec cargo build --manifest-path "$component_dir/Cargo.toml" --offline --locked --release "$@"
