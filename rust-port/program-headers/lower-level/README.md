# Selected compiled-code review

This workflow inspects the final portable release CLI artifact. It does not
rebuild the parser, execute the imported binary, or edit the installed Ghidra.
The completed [selected-01 review](RESULTS.md) records three successful exports,
their exact artifact identity, five undisassembled NOP gaps and an explicit
lost-argument limitation in the inferred C.
Run it only in the serial heavy-work slot, after the final release build:

```sh
python3 /workspace/ghidra-rust-port/program-headers/lower-level/run.py \
  --output /workspace/ghidra-rust-port/program-headers/lower-level/results/selected-01
```

Every output directory must be new. Existing results are refused. The runner
copies the CLI, records its SHA-256 and source/tool provenance, and resolves the
actual `nm -S -C` extents for `parse_program_headers`, `ProgramHeaders::raw`, and
`ProgramHeaderIter::next`. Missing standalone symbols are reported as a failure;
an inlined function is never assigned an invented extent. Each selected function
is limited to 64 KiB. The retained artifact is imported into a new headless
project with `-noanalysis`; the shared original `SelectedExport.java` supplies
bounded instruction listings, raw p-code and C with explicit symbol bodies.
There is a 45-second limit per function and a 360-second command limit. A timed
out command group is terminated, and incomplete exports remain failures.

`summary.json` requires all selected statuses, one exact completion footer,
matching artifact hashes, no cancellation, timeout or export truncation, exact
function bodies and unchanged source/engine hashes. Instruction coverage is
reported separately; padding or data gaps do not by themselves invalidate a
complete selected export, but every gap needs review against objdump and source.
`scope_truncated:true` in the original report is expected: only the three
chosen functions are requested. Warnings, missing instruction ranges, actual
prototypes and calling conventions remain recorded. `commands.json` and stdout/
stderr logs preserve failures as well as success; no failed run is replaced.

The source controls the contract. The parser checks header/count/table bounds,
the raw accessor decodes one record, and the iterator advances a running offset
when the Java-compatible rewrite applies. Inspect comparisons and overflow
branches against these paths, endian swaps against ELF class and byte order,
and any calls before making allocation claims. A call-free accessor does not
prove that the whole CLI avoids allocation: file buffers and JSON output own
storage, and unselected helpers may call other code.

Rust's hidden return pointer, result/option discriminants and internal calling
convention are not verified by Ghidra's default inferred C types. SIMD stores
can become wide synthetic concatenations, and unknown panic/no-return metadata
can make C appear to continue into unrelated paths. Requested instruction and
p-code listings are bounded; reconstructed C flow can still leave the requested
extent. Review the actual instructions and original Rust before treating any
inferred parameter, structure or control-flow expression as established.

Instruction counts, object size and diagnostic export times do not establish
execution cost or a Java/Rust speed ratio. The separate equivalent-work benchmark
measures that component boundary; neither workflow measures whole-Ghidra speed.
