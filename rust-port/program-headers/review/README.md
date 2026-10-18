# Independent program-header review

`findings.md` records the source, original-Java oracle and contract review.
`adversarial.py` independently generates bounded cases, compiles the existing
original-Java oracle into a fresh directory and compares it with a retained Rust
CLI. Its own `struct` decoder and unsigned extent model also check strict policy.
It does not build or edit either Rust crate, the installed Ghidra checkout or old
experiment outputs.

Run only with the exclusive serial test slot, after building the separate crate:

```sh
python3 /workspace/ghidra-rust-port/program-headers/review/adversarial.py \
  --output /workspace/ghidra-rust-port/program-headers/review/results/adversarial-02
```

Every output path must be new. The accepted first run is
`results/adversarial-01/summary.json`: 370 fixtures, 366 Java parity cases,
four separately recorded intentional signed-record-span safety exceptions and
370 independently checked strict expectations. Complete input bytes, source and
classpath identities, raw command output and the copied Rust executable are
retained there. Preserve that evidence before changing any source or binaries.

The 4096-header count limit is an explicit wrapper policy, checked by the oracle
before calling the production Java parser. Above-limit tests use small files and
do not invoke its unbounded table allocation. Payload and full-loader behavior
remain outside this review. This is correctness evidence and contains no timing
acceptance threshold or performance conclusion.
