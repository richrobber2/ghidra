# Six-function original Ghidra reference, 2026-10-18

The corrected [reference-02 receipt](../results/reference-02/results.json) passes
two fresh Ghidra imports and all six requested native decompilations. The same
frozen standalone Rust executable produced each reachable instruction graph and
guarded C artifact independently of Ghidra. All 77 reachable instruction starts,
sizes and original bytes match Ghidra, as do supported direct branch destinations,
conditional/unconditional fallthroughs and return termination.

| Exact semantic-test input | Function | Matched reachable instructions | Matched instruction bytes |
|---|---|---:|---:|
| C GCC O2 shared object | `add_mix` | 8 | 30 |
| C GCC O2 shared object | `select_signed` | 7 | 21 |
| C GCC O2 shared object | `loop_accumulate` | 16 | 48 |
| Rust optimized shared object | `rust_arithmetic` | 7 | 21 |
| Rust optimized shared object | `rust_branch` | 5 | 15 |
| Rust optimized shared object | `rust_loop` | 34 | 117 |

Both imports chose image base `0x100000`; that base is explicitly subtracted
before comparing original ELF VMAs. There are no Ghidra-only instruction starts
and no native decompiler messages on the selected targets. Ghidra leaves 13 bytes
of unreachable alignment padding undisassembled inside `loop_accumulate`'s ELF
symbol extent. Neither Rust nor Ghidra includes those bytes as reachable
instructions; this is preserved in the selected report, not called missing
function coverage.

All requested/attempted/decompiled counts are three per import, failed counts
are zero, and export-complete flags and log footers pass. Process/function
timeouts, cancellation, analysis timeout, instruction truncation and boundary
crossing flags are false. The export's separate `scope_truncated:true` marks
selected-only scope by design; it does not mean a selected function timed out.
Automatic analysis is disabled, the trusted symbol body extent is set only in
the new project, and each function has a 45-second native limit. Original Ghidra
source, languages, native engine and older projects remain unchanged.

The frozen Rust CLI SHA-256 is
`ad94c92ffcddf363c37b849525fcae2e7d79cbb42792c1932987aaae71682ac4`.
The engine SHA-256 is
`876c28d48c07126e5db94946c10719eeb96b057c9271daa0114df34e598f262a`
before and after both imports. Input hashes, source snapshots, all ten command
records and per-function listings/raw p-code/C remain under `reference-02`.

The initial [reference-01 receipt](../results/reference-01/results.json) remains
failed and unchanged. Its first original Ghidra import exported all three C
functions successfully, then the Python comparison raised `KeyError:
'fallthrough'`: the unchanged Java exporter's Gson omits properties whose values
are null, including `RET`/unconditional `JMP` fallthrough. The runner correction
reads that nullable property with `.get()`. The corrected fresh run uses the
same candidate and input bytes. These are validation runs; their diagnostic
durations are not benchmark samples and are not compared as speed evidence.

This check establishes selected instruction/control-flow agreement, not complete
Ghidra parity or equivalence of inferred C expressions/types. The Ghidra exports
recover structured arithmetic, conditions and loops, while Rust currently emits
guarded machine-state C with explicit labels. The independent execution suites
separately compare the recompiled Rust output with original C/Rust executions
and integer formulas. No whole-program coverage or speed claim follows.
