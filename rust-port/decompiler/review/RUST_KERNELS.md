# Optimized Rust leaf demonstration

`rust_kernels.py` is a separate, fixed four-function gate. It preserves the
original C compiler matrix and its receipts. The Rust source covers explicit
wrapping arithmetic, variable rotates, unsigned conditional selection and a
bounded unsigned loop. Every export has six `u64` arguments and a `u64` result.

The runner compiles `fixtures/rust-kernels.rs` as an edition-2024 `cdylib` with
`opt-level=3`, retained debug/symbol information and `panic=abort`. It passes no
CPU-specific or LTO flags. The standard library is allowed in the binary, while
the four selected kernels remain scalar leaf functions. This demonstrates
analysis of optimized Rust machine code rather than Rust source reconstruction.

After the root agent grants the serial execution slot:

```bash
python3 review/rust_kernels.py --cli /absolute/path/to/rust-ghidra \
    --rustc /absolute/path/to/rustc --output results/NEW
```

All compilation products stay under the fresh output directory. The runner
snapshots the candidate executable and relevant sources, retains every command
and output, invokes the native Rust decompiler for each fixed export, recompiles
its generated C, and compares native Rust and generated C with independent
integer formulas. It uses the original matrix's fixed boundary/random input
vectors and timeout/resource-limited execution children. Unsupported functions
and every build/execution/semantic failure remain recorded; any incomplete gate
exits nonzero. There are no retries or fixture selection changes based on output.

These four kernels do not establish general optimized-Rust support: allocation,
trait dispatch, panics, unwinding, pointers, slices and normal Rust ABI recovery
are outside the demonstrated boundary. Generated C deliberately uses the
specified C-compatible ABI and does not recover Rust types or ownership.
