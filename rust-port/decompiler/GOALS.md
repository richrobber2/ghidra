# Goal: a better Rust decompiler

User direction, 2026-10-18: **“Does not have to be exact if it's better.”**

Build a useful standalone Rust decompiler. Ghidra supplies valuable source,
inspection tools and comparison evidence; its implementation architecture,
p-code format, recovered C text, GUI and every historical feature are not
requirements to copy. Choose Rust libraries, data structures, IR and recovery
algorithms for the results they produce.

Better means broader useful real-binary coverage, clearer recovered code,
measurably lower latency/resource use on comparable work, and dependable agent
interfaces. Keep those measurements separate: faster rejection is not faster
decompilation, an emitted artifact is not execution-validated coverage, and a
prettier expression is not evidence of preserved behavior.

Machine behavior within each declared support contract remains the correctness
target. Recompile and execute reconstructed code against original functions and
independent expectations. Different valid C is welcome; silently invented memory,
types, calls or return values are not an improvement. Preserve unsupported cases,
guards, failures, resource limits and every frozen denominator.

## Current memory slice and next stage

The current slice implements **read-only image memory with explicit pointer
provenance**. Next implement direct calls/prototypes, then SSA/expression and
structured-C recovery. This is
a useful dependency order, not a commitment to reproduce Ghidra's internal passes.

The [frozen zlib census](review/next-priorities-01.json) records 28 call failures,
14 outgoing-branch failures, 16 global/pointer-memory failures and other missing
instructions among 85 first rejections. These are censored first failures, not
predicted gains from fixing a single category. Outgoing branches have not all
been established as tail calls. Calls are the largest visible category; usable
memory/prototype modeling is needed before supporting many real callees.

The bounded first memory targets are file-backed read-only loads and addresses,
including `zlibVersion` and `get_crc_table`. Returned pointers require an explicit
pointer result model: compare contents/object offsets, not unrelated addresses
in separately loaded libraries. Keep relocations, writable global state and
external pointers unsupported until their semantics are modeled.

Acceptance requires that the existing numeric and guard suites still pass,
new load/index/alias/boundary cases match native execution, and newly supported
pointer results pass content-based checks. Preserve the original 88-function
zlib inventory and report artifact versus validated coverage separately. Measure
performance after matching supported work; no speed improvement is claimed by
this direction change.
