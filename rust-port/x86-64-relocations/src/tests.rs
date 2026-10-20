use super::*;

/// One relocation in isolation: a flat memory window, one symbol and fixed
/// GOT answers.
struct RecordEnv {
    base: u64,
    memory: Vec<u8>,
    symbol: SymbolInfo,
    symbol_address: Option<u64>,
    got: Option<u64>,
    got_entry: Option<u64>,
    adjust: u64,
    log: Vec<String>,
    bookmarks: Vec<String>,
    artificial: Vec<(u64, u32)>,
}

impl RecordEnv {
    fn new(symbol_address: Option<u64>) -> Self {
        Self {
            base: 0x10_0000,
            memory: vec![0; 0x100],
            symbol: SymbolInfo {
                handle: 1,
                name: Some("target".to_owned()),
                size: 24,
                symbol_type: 1,
            },
            symbol_address,
            got: None,
            got_entry: None,
            adjust: 0x10_0000,
            log: Vec::new(),
            bookmarks: Vec::new(),
            artificial: Vec::new(),
        }
    }
    fn at(&self, address: u64, length: usize) -> &[u8] {
        let start = (address - self.base) as usize;
        &self.memory[start..start + length]
    }
}

impl Environment for RecordEnv {
    fn symbol(&self, index: i32) -> Option<SymbolInfo> {
        (index == 0 || index == 1).then(|| self.symbol.clone())
    }
    fn symbol_name(&self, index: i32) -> Option<String> {
        self.symbol(index).and_then(|s| s.name)
    }
    fn symbol_address(&self, _: &SymbolInfo) -> Option<u64> {
        self.symbol_address
    }
    fn symbol_value(&mut self, _: &SymbolInfo) -> u64 {
        self.symbol_address.unwrap_or(0)
    }
    fn got_value(&mut self) -> Result<u64, String> {
        self.got
            .ok_or_else(|| "Failed to identify _GLOBAL_OFFSET_TABLE_".to_owned())
    }
    fn got_entry_address(&mut self, _: &SymbolInfo) -> Option<u64> {
        self.got_entry
    }
    fn image_base_adjustment(&self) -> u64 {
        self.adjust
    }
    fn is_prelinked(&self) -> bool {
        false
    }
    fn read(&mut self, address: u64, out: &mut [u8]) -> Result<(), MemoryError> {
        let start = address.wrapping_sub(self.base) as usize;
        let bytes = self.memory.get(start..start + out.len()).ok_or_else(|| {
            MemoryError(format!(
                "Address {} does not exist in memory",
                format_address(address)
            ))
        })?;
        out.copy_from_slice(bytes);
        Ok(())
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let start = address.wrapping_sub(self.base) as usize;
        let target = self
            .memory
            .get_mut(start..start + bytes.len())
            .ok_or_else(|| {
                MemoryError(format!(
                    "Address {} does not exist in memory",
                    format_address(address)
                ))
            })?;
        target.copy_from_slice(bytes);
        Ok(())
    }
    fn is_external_address(&self, _: u64) -> bool {
        false
    }
    fn add_artificial_relocation(&mut self, address: u64, length: u32) {
        self.artificial.push((address, length));
    }
    fn log(&mut self, message: String) {
        self.log.push(message);
    }
    fn loader_log(&mut self, _: String) {}
    fn bookmark(&mut self, _: u64, kind: &'static str, _: &'static str, comment: String) {
        self.bookmarks.push(format!("{kind} {comment}"));
    }
    fn console(&mut self, _: &'static str, _: String) {}
}

fn record(type_id: u32, symbol: u32, offset: u64, addend: i64) -> Record {
    Record {
        offset,
        info: (u64::from(symbol) << 32) | u64::from(type_id),
        addend,
        has_addend: true,
    }
}

#[test]
fn type_table_is_sorted_and_named() {
    assert!(RELOCATION_TYPES.windows(2).all(|w| w[0].0 < w[1].0));
    assert_eq!(type_name(8), Some("R_X86_64_RELATIVE"));
    assert_eq!(type_name(52), None);
    assert_eq!(type_name(-1), None);
}

#[test]
fn absolute_and_pc_relative_values() {
    let mut env = RecordEnv::new(Some(0x20_0000));
    let r = record(1, 1, 0x10, 5);
    let result = process_relocation(&mut env, &r, 0x10_0010).unwrap();
    assert_eq!(result, RelocationResult::applied(8));
    assert_eq!(env.at(0x10_0010, 8), &0x20_0005u64.to_le_bytes());

    let r = record(2, 1, 0x20, -4);
    let result = process_relocation(&mut env, &r, 0x10_0020).unwrap();
    assert_eq!(result.byte_length, 4);
    let expected = (0x20_0000i64 - 4 - 0x10_0020) as u32;
    assert_eq!(env.at(0x10_0020, 4), &expected.to_le_bytes());
}

#[test]
fn relative_uses_the_image_base_adjustment() {
    let mut env = RecordEnv::new(None);
    let r = record(8, 0, 0x30, 0x1234);
    process_relocation(&mut env, &r, 0x10_0030).unwrap();
    assert_eq!(env.at(0x10_0030, 8), &0x10_1234u64.to_le_bytes());
}

#[test]
fn gotpcrelx_mov_becomes_lea() {
    let mut env = RecordEnv::new(Some(0x10_0080));
    env.memory[0x40 - 2] = 0x8b;
    env.memory[0x40 - 1] = 0x05;
    let r = record(42, 1, 0x40, -4);
    let result = process_relocation(&mut env, &r, 0x10_0040).unwrap();
    assert_eq!(result, RelocationResult::applied(4));
    assert_eq!(env.memory[0x3e], 0x8d);
    assert_eq!(env.artificial, vec![(0x10_003e, 2)]);
    assert_eq!(env.at(0x10_0040, 4), &(0x80u32 - 4 - 0x40).to_le_bytes());
}

#[test]
fn unresolved_unknown_and_tls_symbols() {
    let mut env = RecordEnv::new(None);
    let result = process_relocation(&mut env, &record(1, 1, 0, 0), 0x10_0000).unwrap();
    assert_eq!(result, RelocationResult::FAILURE);
    assert_eq!(
        env.log,
        vec![
            "Unhandled ELF Relocation: R_X86_64_64 (1, 0x1) at 00100000 (Symbol = target)",
            "Elf Relocation Failure: R_X86_64_64 (1, 0x1) at 00100000 (Symbol = target) - Failed to resolve relocation symbol",
        ]
    );

    let mut env = RecordEnv::new(Some(0));
    let result = process_relocation(&mut env, &record(99, 1, 0, 0), 0x10_0000).unwrap();
    assert_eq!(result, RelocationResult::UNSUPPORTED);
    assert_eq!(
        env.bookmarks,
        vec!["Error Undefined ELF Relocation: Type = 99 (0x63) Symbol = target (0x1)"]
    );

    let mut env = RecordEnv::new(Some(0));
    env.symbol.symbol_type = STT_TLS;
    let result = process_relocation(&mut env, &record(1, 1, 0, 0), 0x10_0000).unwrap();
    assert_eq!(result, RelocationResult::UNSUPPORTED);
}

#[test]
fn memory_failures_are_processing_failures() {
    let mut env = RecordEnv::new(Some(0));
    let result = process_relocation(&mut env, &record(1, 1, 0, 0), 0x10_00fc).unwrap();
    assert_eq!(result, RelocationResult::FAILURE);
    assert!(env.log[0].ends_with("Processing Failure - Address 001000fc does not exist in memory"));
}

#[test]
fn invalid_names_are_replaced_like_ghidra() {
    assert_eq!(
        replace_invalid_chars(Some("a b\u{1}\u{7f}\u{a0}c")).as_deref(),
        Some("a_b^A^?c")
    );
    assert_eq!(replace_invalid_chars(None), None);
}
