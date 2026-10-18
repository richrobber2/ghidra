# Original program-header parser oracle

`python3 oracle/run.py --output /absolute/fresh/result/java` creates its own
fixture corpus, manifest, compiled classes, normalized `baseline.json`, raw
compiler/oracle stdout and stderr, and hash/command/status `provenance.json`.
Existing output directories are rejected. Earlier header-lab outputs and build
artifacts are never used as writable paths. Run builds and experiments serially.

The oracle constructs the actual original `ElfHeader(ByteArrayProvider, warnings)`
and invokes its private `parseProgramHeaders()` with one cached reflective
`Method`. It does not call `parse()`, create a Ghidra Program, select a loader
adapter, execute an input, or adjust addresses using a PRE trailer. Raw virtual
and physical fields are read reflectively because their public getters lazily
inspect the PRE trailer. Other fields use the original getters. Raw offsets come
from an additional original `ElfProgramHeader` constructor after the private
table parser succeeds; effective offsets come from the table parser. This extra
record parse is oracle normalization work, not suitable for equivalent timing.

The wrapper rejects decoded counts over **4096 before invoking the table parser**.
This is an explicit test resource bound, not an original Ghidra restriction.
The original table parser uses signed-short stride, warns once when a declared
entry region is missing, zero-fills reads beyond EOF, and applies the historical
offset rewrite when the wrapping signed-long sum of file sizes equals file
length. `offsets_rewritten` records application of that rule even if all offset
values happen already to match. It does not validate segment payloads.

Fixtures cover both classes and byte orders, canonical and signed/noncanonical
stride, partial/missing tables and headers, unsigned field bits, extended count
resolution/cap, PRE trailer scope and malformed-file offset rewriting. Every
fixture has a group, SHA-256, length, explicit strict-policy note where relevant,
and `expected_difference`. The latter is nonnull only for separately retained
checked signed-address overflow policy cases; comparison must report them
individually rather than silently treating them as compatibility matches.

The Java process intentionally exits zero after collecting ordinary per-file
parser errors. A compiler/process error, timeout, malformed JSON or incomplete
fixture inventory fails the runner and preserves raw diagnostics. Normal parser
errors include original exception class/message and original warnings. The
production Rust CLI's nonzero status for rejected files is a different CLI policy.
