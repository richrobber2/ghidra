# Original Ghidra instruction and control-flow reference

`run.py --output NEW` copies the current standalone Rust executable and two exact
previously tested C/Rust binaries into a fresh result directory. It decompiles six
selected functions with Rust, then imports each binary into its own fresh Ghidra
project and exports only those selected functions without automatic analysis.
The original native engine SHA is checked before and after the work. Heavy work
runs serially, with one Ghidra CPU and a 45-second native limit per function.

```bash
python3 /workspace/ghidra-rust-port/decompiler/reference/run.py \
  --output /workspace/ghidra-rust-port/decompiler/results/reference-NEW
```

The comparison checks every Rust-reachable instruction start, size and original
file bytes against Ghidra's bounded instruction export. It also checks direct
branch destinations, fallthroughs and returns after subtracting the explicit
Ghidra import image base. The chosen shared objects have an ELF image base of
zero. Ghidra-only instruction starts and all native decompiler messages stay in
the report. Undisassembled unreachable padding is not missing Rust coverage.

Ghidra C and raw instruction p-code are retained as review aids. C text and
inferred prototypes/types are not a semantic equivalence oracle. The independent
`review/validate.py` and `review/rust_kernels.py` execution suites provide separate
semantic checks on original versus recompiled guarded C. Selected-only scope is
explicit; this does not establish whole-program coverage or speed.

The exporter is an unchanged copy of
`/workspace/ghidra-rust-port/lower-level/tools/SelectedExport.java`, under its
Apache-2.0 license. It explicitly bounds instruction listings to trusted ELF
symbol extents and sets those extents only in the new imports. It does not edit
any retained analysis project, installed Ghidra source, engine or language.
Runner and source snapshots, input hashes, full command logs, exporter footers,
timeouts, target flags and native warnings are retained in each new result.

The completed first reference is recorded in [RESULTS.md](RESULTS.md), including
the preserved initial harness failure and the corrected six-function check.
