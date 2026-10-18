# Independent contract and source review

The review boundary is the original `ElfHeader` constructor followed by its
private `parseProgramHeaders()`, including actual `ElfProgramHeader` decoding,
the declared-stride missing-region warning and the legacy file-size-sum offset
rewrite. It does not invoke the full loader or adjust addresses for PRE trailers.

Initial source review found no blocking discrepancy in the supported arithmetic
domain. The new library preserves the two record layouts and effective header
endianness, Java's signed-short stride, the difference between declared-stride
warning checks and actual 32/56-byte reads, and wrapping file-size arithmetic.
Its view borrows bytes, keeps iteration state private, and bounds resolved counts
at 4096 before performing count-dependent work. Both normal decoding and the
error paths use stack storage without input-dependent allocation. Strict mode
first uses the existing strict header checks, then checks the complete canonical
program-table extent; segment payloads and section-table bodies remain outside
this validation boundary.

The 4096 count limit makes `index * signed_stride` fit Java's signed `int`, so the
Rust implementation's widened multiplication preserves the original product on
all admitted indices. Program field values retain their unsigned bit patterns,
including 64-bit values whose Java `long` representation is negative. The legacy
sum and effective-offset prefix intentionally wrap modulo 2^64.

The signed address overflow exception needs precise reporting. The implementation
checks the last byte of each complete record, while Java's unlimited provider
can accept a final fixed-width read whose starting address is nonnegative even
when its last byte crosses `Long.MAX_VALUE`: an out-of-file read returns zeros
before adding the requested length. Consequently, Rust also deliberately rejects
some final-span cases in addition to wrapped record-start calculations. These
cases must remain separately recorded as safety exceptions, not counted as
matching Java acceptance. The earlier header parser's section-zero safety
exceptions are inherited and likewise remain distinct.

The JSON CLI's 64 MiB input cap is a CLI resource policy. The library's borrowed
view has only the independent 4096-header cap. Allocation-free library behavior
does not imply allocation-free CLI operation: reading files and serializing JSON
allocate by design. Nor does a faster independent component establish Ghidra
loader or decompiler speed before integration.

The original-Java oracle source was also reviewed. It invokes the actual private
table parser, enforces the explicit wrapper count cap before invocation, and
uses additional actual record constructors only in untimed correctness work to
recover pre-rewrite offsets. It reads raw address fields to avoid public getters'
PRE-trailer behavior. Neither the oracle nor the benchmark calls full `parse()`.

## Independent edge validation

The single fresh run at `results/adversarial-01/summary.json` passes all 370
independently generated fixtures. Of these, 366 have matching original-Java
acceptance, warning text/order and all normalized emitted fields. Four are
separately asserted Java-accepts/Rust-`RecordOffsetOverflow` safety exceptions:
64-bit records at `Long.MAX_VALUE - 48` and `Long.MAX_VALUE - 54`, in each byte
order. They are excluded from the matching-parity count. A separate Python
`struct` decoder and unsigned extent model verifies all 370 strict-policy
expectations, plus compatibility fields and zero-fill counts.

The generated set covers all four class/endianness layouts, zero/small counts,
unknown type/flag bits, maximum-width field values, every byte truncation through
one record and the following record boundary, overlapping/zero/out-of-file table
offsets, zero/negative/noncanonical strides, exact/one-byte-short table extents,
extended counts through unsigned 32-bit extremes, a complete 4096-entry table,
and tiny files declaring counts above the wrapper bound. Two additional 64-bit
examples exercise a file-size sum that wraps into equality and therefore causes
the legacy prefix-offset rewrite. Payload-invalid fields remain accepted by
strict mode, as its narrower contract requires.

Near signed boundaries, the driver independently checks original Java acceptance
before classifying an exception. Extreme cases that both implementations reject
remain ordinary acceptance/warning parity cases, while Rust error kinds are
checked separately against the model. All fixture bytes, source snapshots,
classpath identities, exact commands, process exits, stdout/stderr and normalized
results are retained. The reported source and Rust binary identities are unchanged
throughout the run. There were no failed or repeated adversarial executions.

This validation establishes the bounded parsing contract, not segment loading,
ABI compatibility, integration or whole-Ghidra performance. Library allocation
claims follow from the reviewed code path and absence of allocating operations;
this test does not instrument an allocator or measure persistent-process memory.

## Benchmark review guidance

Equivalent work includes construction of the same ELF header, the entire program
table, and a digest over the shared header and every emitted record field. The
Java reference must invoke its production private method by a cached handle,
with the wrapper count check before that invocation; it must use raw address
fields because public getters can lazily apply PRE adjustments. Rust iteration
must be included because its borrowed view defers record materialization.

Preloaded inputs, frozen process order, ten-second per-process warmup, five
500-ms samples and three serial processes per arm provide a bounded component
comparison. Require per-input digests before timing and validate every timed
checksum. Keep startup, file I/O and formatting excluded equally. Preserve all
processes, sample durations, failures and spread; no favorable retiming. Different
representations, original Java allocations, cached bridge/field-access costs and
cache-resident corpus behavior remain part of the measured comparison.
