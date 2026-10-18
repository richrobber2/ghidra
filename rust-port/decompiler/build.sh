#!/bin/bash
set -euo pipefail
component_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source /workspace/rust-optimization/activate.sh
export CARGO_TARGET_DIR="$component_dir/target"
export RUSTFLAGS=''
unset CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
exec cargo build --manifest-path "$component_dir/Cargo.toml" --offline --locked --release "$@"
