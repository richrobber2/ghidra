# Rust decompiler improvement plan

The user's priority is a better result, not exact replication. Follow
[GOALS.md](GOALS.md): correctness, useful coverage, readable output and measured
efficiency guide design. Original Ghidra remains a source and comparison tool;
its internal representations, recovered C text and full product feature list do
not define the required implementation.

The current command genuinely loads, lifts and emits C in Rust. Its validated
boundary is scalar x86-64 leaf functions, bounded read-only image memory and
typed pointer results under an explicit integer-input ABI model.
It is not yet a general Ghidra replacement: the frozen installed zlib inventory
(88 function extents) remains the denominator for coverage. See README.md for
current artifact and execution-validated counts.

1. **Read-only image memory and pointer results.** Start with validated,
   file-backed image bytes and explicit image-object provenance. Cover simple
   read-only loads/tables and address-producing leaf functions before mutable
   globals or general pointers. Validate returned contents/object offsets;
   never invent an absolute pointer from an ELF VMA. Implemented in the current
   memory slice; mutable/relocated/external memory remains deferred.
2. **Calls and explicit prototypes.** Add direct intra-image calls and validated
   scalar signatures, caller/callee register effects, call-stack/return tokens,
   and conservative handling of unknown arguments/flags. Retain failures for
   imports, indirect calls, tail calls and unsupported ABI types until modeled.
   Require multilevel calls, recursion bounds, stack arguments and callee-saved
   lifecycle tests before declaring general interprocedural support.
3. **Broader global memory and pointer types.** Extend image-object provenance,
   load bias, file-backed/NOBITS storage and relocations. A raw ELF address is not
   a valid reconstructed host pointer. Validate read-only tables and strings,
   mutable globals, aliasing and exported pointer results with appropriate typed
   equivalence rather than comparing unrelated loaded-library addresses.
4. **SSA and data flow.** Introduce a stable typed IR with definitions, use lists,
   basic blocks, phi nodes and memory effects. Use original Ghidra `op.cc`,
   `varnode.cc` and `heritage.cc` as source references and frozen original p-code
   as a differential aid, without copying its representation or algorithms.
   Existing profiler bank/phi captures can guide realistic
   workloads; their C++ timing results do not establish Rust port performance.
5. **Structured C and type recovery.** Recover arithmetic expressions, simplify
   flag predicates, structure reducible loops/conditionals and preserve explicit
   gotos when structure is unproven. Add recovered prototypes/names and widths
   only with evidence. Recompile and execute output after every transformation.
6. **Broader code discovery and instruction coverage.** Add bounded stripped
   discovery from entry/call targets and explicit ambiguity handling; then indirect
   dispatch, SIMD/floating point, atomics, exceptions and real Rust ABI/runtime
   patterns. Each new category needs distinct unsupported and semantic gates.
7. **Additional architectures and product capabilities, when useful.** Generalize
   address spaces and the IR only as new targets require; Ghidra's p-code and
   language support are references rather than mandatory formats to reproduce.
   Loaders, relocation/symbol/type systems, analyzers, projects and the GUI are
   separate large ports; accepting an ELF file does not implement those layers.

Keep original Ghidra installed for source/differential inspection and retain the
two original Rust ELF components as frozen references. Use new result directories,
source/artifact hashes and serial heavy work. Compare performance only after
matching work, outputs, calling conventions and supported selections. Avoid speed
claims from lower coverage, omitted analysis or source/assembly size alone.
