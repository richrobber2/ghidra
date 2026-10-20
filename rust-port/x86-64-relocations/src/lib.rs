//! Port of Ghidra's x86-64 ELF relocation handler.
//!
//! [`process_relocation`] follows `ElfRelocationContext.processRelocation`,
//! `AbstractElfRelocationHandler.relocate` and
//! `X86_64_ElfRelocationHandler.relocate` for one relocation record: the bytes
//! written, the status and byte length reported, and every log line, bookmark
//! and console message the Java code produces on the way. Everything the
//! handler asks its context, program and load helper for goes through the
//! [`Environment`] trait. [`model`] implements it for a whole ELF file, with a
//! port of `ElfGotRelocationContext`'s `%got` allocation and a documented
//! stand-in for the loader's memory image and symbol map.
#![forbid(unsafe_code)]

pub mod model;

pub const EM_X86_64: u16 = 62;
pub const GOT_SYMBOL_NAME: &str = "_GLOBAL_OFFSET_TABLE_";
pub const STT_SECTION: u8 = 3;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;

/// `X86_64_ElfRelocationType`: every type id the handler's enum defines.
pub const RELOCATION_TYPES: &[(u32, &str)] = &[
    (0, "R_X86_64_NONE"),
    (1, "R_X86_64_64"),
    (2, "R_X86_64_PC32"),
    (3, "R_X86_64_GOT32"),
    (4, "R_X86_64_PLT32"),
    (5, "R_X86_64_COPY"),
    (6, "R_X86_64_GLOB_DAT"),
    (7, "R_X86_64_JUMP_SLOT"),
    (8, "R_X86_64_RELATIVE"),
    (9, "R_X86_64_GOTPCREL"),
    (10, "R_X86_64_32"),
    (11, "R_X86_64_32S"),
    (12, "R_X86_64_16"),
    (13, "R_X86_64_PC16"),
    (14, "R_X86_64_8"),
    (15, "R_X86_64_PC8"),
    (16, "R_X86_64_DTPMOD64"),
    (17, "R_X86_64_DTPOFF64"),
    (18, "R_X86_64_TPOFF64"),
    (19, "R_X86_64_TLSGD"),
    (20, "R_X86_64_TLSLD"),
    (21, "R_X86_64_DTPOFF32"),
    (22, "R_X86_64_GOTTPOFF"),
    (23, "R_X86_64_TPOFF32"),
    (24, "R_X86_64_PC64"),
    (25, "R_X86_64_GOTOFF64"),
    (26, "R_X86_64_GOTPC32"),
    (27, "R_X86_64_GOT64"),
    (28, "R_X86_64_GOTPCREL64"),
    (29, "R_X86_64_GOTPC64"),
    (30, "R_X86_64_GOTPLT64"),
    (31, "R_X86_64_PLTOFF64"),
    (32, "R_X86_64_SIZE32"),
    (33, "R_X86_64_SIZE64"),
    (34, "R_X86_64_GOTPC32_TLSDESC"),
    (35, "R_X86_64_TLSDESC_CALL"),
    (36, "R_X86_64_TLSDESC"),
    (37, "R_X86_64_IRELATIVE"),
    (38, "R_X86_64_RELATIVE64"),
    (39, "R_X86_64_PC32_BND"),
    (40, "R_X86_64_PLT32_BND"),
    (41, "R_X86_64_GOTPCRELX"),
    (42, "R_X86_64_REX_GOTPCRELX"),
    (43, "R_X86_64_CODE_4_GOTPCRELX"),
    (44, "R_X86_64_CODE_4_GOTTPOFF"),
    (45, "R_X86_64_CODE_4_GOTPC32_TLSDESC"),
    (46, "R_X86_64_CODE_5_GOTPCRELX"),
    (47, "R_X86_64_CODE_5_GOTPC32_TLSDESC"),
    (48, "R_X86_64_CODE_5_GOTTPOFF"),
    (49, "R_X86_64_CODE_6_GOTPCRELX"),
    (50, "R_X86_64_CODE_6_GOTTPOFF"),
    (51, "R_X86_64_CODE_6_GOTPC32_TLSDESC"),
    (250, "R_X86_64_GNU_VTINHERIT"),
    (251, "R_X86_64_GNU_VTENTRY"),
];

/// `getRelrRelocationType()`: RELR entries are `R_X86_64_RELATIVE`.
pub const RELR_RELOCATION_TYPE: i32 = 8;

/// The enum constant name for a type id, or `None` where Ghidra's lookup
/// returns null.
pub fn type_name(type_id: i32) -> Option<&'static str> {
    let id = u32::try_from(type_id).ok()?;
    RELOCATION_TYPES
        .binary_search_by_key(&id, |&(value, _)| value)
        .ok()
        .map(|index| RELOCATION_TYPES[index].1)
}

/// `ElfGotRelocationContext.requiresGotEntry` for the x86-64 context.
pub fn requires_got_entry(type_id: i32) -> bool {
    matches!(type_id, 9 | 28 | 41 | 42)
}

/// `Relocation.Status`, limited to the values this handler reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Status {
    Skipped,
    Applied,
    Unsupported,
    Failure,
}

impl Status {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Skipped => "SKIPPED",
            Self::Applied => "APPLIED",
            Self::Unsupported => "UNSUPPORTED",
            Self::Failure => "FAILURE",
        }
    }
}

/// `RelocationResult`: status and the number of bytes the relocation covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationResult {
    pub status: Status,
    pub byte_length: u32,
}

impl RelocationResult {
    pub const SKIPPED: Self = Self::of(Status::Skipped);
    pub const UNSUPPORTED: Self = Self::of(Status::Unsupported);
    pub const FAILURE: Self = Self::of(Status::Failure);
    const fn of(status: Status) -> Self {
        Self {
            status,
            byte_length: 0,
        }
    }
    const fn applied(byte_length: u32) -> Self {
        Self {
            status: Status::Applied,
            byte_length,
        }
    }
}

/// One ELF64 relocation record, as `ElfRelocation` holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub offset: u64,
    pub info: u64,
    pub addend: i64,
    pub has_addend: bool,
}

impl Record {
    /// `getSymbolIndex()`: `(int) (r_info >> 32)`.
    pub const fn symbol_index(&self) -> i32 {
        (self.info >> 32) as i32
    }
    /// `getType()`: `(int) (r_info & 0xffffffff)`.
    pub const fn type_id(&self) -> i32 {
        self.info as u32 as i32
    }
    /// `setType(long)`.
    pub fn set_type(&mut self, type_id: i32) {
        self.info = (self.info & !0xffff_ffff) | u64::from(type_id as u32);
    }
}

/// What the handler needs to know about an `ElfSymbol`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    /// Opaque to the handler; identifies the symbol to the environment.
    pub handle: usize,
    /// `getNameAsString()`, which can be null.
    pub name: Option<String>,
    pub size: u64,
    /// `st_info & 0xf`.
    pub symbol_type: u8,
}

/// A Java exception that leaves the relocation code: an
/// `AddressOutOfBoundsException` from `Address.add`/`subtract`, which no
/// caller catches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abort {
    pub exception: &'static str,
    pub message: String,
}

/// Exceptions `processRelocation` catches.
enum Fault {
    /// `MemoryAccessException` with its message.
    Memory(String),
    Abort(Abort),
}

impl From<MemoryError> for Fault {
    fn from(error: MemoryError) -> Self {
        Fault::Memory(error.0)
    }
}

/// A failed memory access: the `MemoryAccessException` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryError(pub String);

/// Bookmark types as Ghidra's `BookmarkType` names them.
pub const BOOKMARK_ERROR: &str = "Error";
pub const BOOKMARK_WARNING: &str = "Warning";

/// The relocation context, program and load helper as the handler sees them.
pub trait Environment {
    /// `getSymbol(symbolIndex)`; `None` where Java returns null.
    fn symbol(&self, index: i32) -> Option<SymbolInfo>;
    /// `getSymbolName(symbolIndex)`, before `replaceInvalidChars`.
    fn symbol_name(&self, index: i32) -> Option<String>;
    /// `getSymbolAddress(symbol)`.
    fn symbol_address(&self, symbol: &SymbolInfo) -> Option<u64>;
    /// `getSymbolValue(symbol)`, which may allocate the `%got` block.
    fn symbol_value(&mut self, symbol: &SymbolInfo) -> u64;
    /// `getGOTValue()`; `Err` carries the `NotFoundException` message.
    fn got_value(&mut self) -> Result<u64, String>;
    /// `getGotEntryAddress(symbol)`.
    fn got_entry_address(&mut self, symbol: &SymbolInfo) -> Option<u64>;
    /// `getImageBaseWordAdjustmentOffset()`.
    fn image_base_adjustment(&self) -> u64;
    /// `getElfHeader().isPreLinked()`.
    fn is_prelinked(&self) -> bool;
    /// Little-endian program memory.
    fn read(&mut self, address: u64, out: &mut [u8]) -> Result<(), MemoryError>;
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError>;
    /// `Memory.isExternalBlockAddress`.
    fn is_external_address(&self, address: u64) -> bool;
    /// `ElfLoadHelper.addArtificialRelocTableEntry`.
    fn add_artificial_relocation(&mut self, address: u64, length: u32);
    /// `MessageLog.appendMsg`.
    fn log(&mut self, message: String);
    /// `ElfLoadHelper.log`.
    fn loader_log(&mut self, message: String);
    /// `BookmarkManager.setBookmark`.
    fn bookmark(
        &mut self,
        address: u64,
        kind: &'static str,
        category: &'static str,
        comment: String,
    );
    /// `Msg.error`/`Msg.warn`, with the level name.
    fn console(&mut self, level: &'static str, message: String);
}

/// `Address.toString()` in a 64-bit space whose name is not shown.
pub fn format_address(address: u64) -> String {
    format!("{address:08x}")
}

/// `SymbolUtilities.isInvalidCodePoint`, exact for ASCII and the C1 controls;
/// beyond them only the listed separator, format and private-use ranges.
fn is_invalid_code_point(cp: u32) -> bool {
    matches!(cp,
        0..=0x20 | 0x7f..=0xa0 | 0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x1680
        | 0x180e | 0x2000..=0x200f | 0x2028..=0x202f | 0x205f..=0x2064 | 0x2066..=0x206f
        | 0x3000 | 0xd800..=0xf8ff | 0xfeff | 0xfff9..=0xfffb | 0xf0000..=0x10ffff
        | 0x2800 | 0x115f | 0x1160 | 0x3164 | 0xffa0 | 0xfffc)
}

/// `ElfSymbolNameUtils.replaceInvalidChars`.
pub fn replace_invalid_chars(name: Option<&str>) -> Option<String> {
    let name = name?;
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        let cp = ch as u32;
        if !is_invalid_code_point(cp) {
            out.push(ch);
        } else if cp < 0x20 {
            out.push('^');
            out.push(char::from(b'@' + cp as u8));
        } else if cp == 0x7f {
            out.push_str("^?");
        } else if cp == 0x20 {
            out.push('_');
        }
    }
    Some(out)
}

fn default_type_detail(type_id: i32) -> String {
    format!("Type = {} (0x{:x})", type_id as u32, type_id as u32)
}

fn type_detail(type_id: i32, name: &str) -> String {
    format!("{name} ({type_id}, 0x{:x})", type_id as u32)
}

/// `ElfRelocationHandler.markupErrorOrWarning`.
#[allow(clippy::too_many_arguments)]
fn markup(
    env: &mut dyn Environment,
    main: &str,
    tail: Option<&str>,
    address: u64,
    detail: &str,
    symbol_index: i32,
    symbol_name: Option<&str>,
    kind: &'static str,
) {
    let tail = match tail {
        Some(text) if !text.is_empty() => format!(" - {text}"),
        _ => String::new(),
    };
    let name = match symbol_name {
        Some(text) if !text.is_empty() => text,
        _ => "<no name>",
    };
    let index = if symbol_index < 0 {
        String::new()
    } else {
        format!(" (0x{:x})", symbol_index)
    };
    let at = format_address(address);
    env.log(format!("{main}: {detail} at {at} (Symbol = {name}){tail}"));
    env.bookmark(
        address,
        kind,
        "Relocation",
        format!("{main}: {detail} Symbol = {name}{index}{tail}"),
    );
}

/// `ElfRelocationHandler.markAsError(Program, Address, int, ...)`.
pub fn mark_relocation_error(
    env: &mut dyn Environment,
    address: u64,
    type_id: i32,
    symbol_name: Option<&str>,
    symbol_index: i32,
    message: &str,
) {
    markup(
        env,
        "ELF Relocation Error",
        Some(message),
        address,
        &default_type_detail(type_id),
        symbol_index,
        symbol_name,
        BOOKMARK_ERROR,
    );
}

/// Typed markup methods of `AbstractElfRelocationHandler`.
struct Typed {
    type_id: i32,
    name: &'static str,
}

impl Typed {
    fn detail(&self) -> String {
        type_detail(self.type_id, self.name)
    }
    fn unhandled(&self, env: &mut dyn Environment, at: u64, index: i32, name: Option<&str>) {
        let detail = self.detail();
        markup(
            env,
            "Unhandled ELF Relocation",
            None,
            at,
            &detail,
            index,
            name,
            BOOKMARK_ERROR,
        );
    }
    fn warning(
        &self,
        env: &mut dyn Environment,
        at: u64,
        name: Option<&str>,
        index: i32,
        msg: &str,
    ) {
        let detail = self.detail();
        markup(
            env,
            "ELF Relocation Failure",
            Some(msg),
            at,
            &detail,
            index,
            name,
            BOOKMARK_WARNING,
        );
    }
    fn error(&self, env: &mut dyn Environment, at: u64, name: Option<&str>, index: i32, msg: &str) {
        let detail = self.detail();
        markup(
            env,
            "Elf Relocation Failure",
            Some(msg),
            at,
            &detail,
            index,
            name,
            BOOKMARK_ERROR,
        );
    }
}

/// `ElfRelocationContext.processRelocation(relocation, relocationAddress)`.
///
/// `Err` is an exception that escapes the Java method.
pub fn process_relocation(
    env: &mut dyn Environment,
    record: &Record,
    address: u64,
) -> Result<RelocationResult, Abort> {
    let symbol_index = record.symbol_index();
    let Some(symbol) = env.symbol(symbol_index) else {
        mark_relocation_error(
            env,
            address,
            record.type_id(),
            None,
            -1,
            &format!("Invalid symbol index ({symbol_index})"),
        );
        return Ok(RelocationResult::FAILURE);
    };
    if symbol.symbol_type == STT_TLS {
        markup(
            env,
            "ELF Relocation Warning",
            Some("Relocation for TLS Symbol not supported"),
            address,
            &default_type_detail(record.type_id()),
            symbol_index,
            symbol.name.as_deref(),
            BOOKMARK_WARNING,
        );
        return Ok(RelocationResult::UNSUPPORTED);
    }
    match relocate(env, record, address, &symbol) {
        Ok(result) => Ok(result),
        Err(Fault::Abort(abort)) => Err(abort),
        Err(Fault::Memory(message)) => {
            env.loader_log(format!("exception: MemoryAccessException: {message}"));
            mark_relocation_error(
                env,
                address,
                record.type_id(),
                symbol.name.as_deref(),
                symbol_index,
                &format!("Processing Failure - {message}"),
            );
            Ok(RelocationResult::FAILURE)
        }
    }
}

fn read_u64(env: &mut dyn Environment, address: u64) -> Result<u64, Fault> {
    let mut bytes = [0u8; 8];
    env.read(address, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_u8(env: &mut dyn Environment, address: u64) -> Result<u8, Fault> {
    let mut bytes = [0u8; 1];
    env.read(address, &mut bytes)?;
    Ok(bytes[0])
}

fn write(env: &mut dyn Environment, address: u64, bytes: &[u8]) -> Result<(), Fault> {
    env.write(address, bytes)?;
    Ok(())
}

/// `Address.subtract(long)` for a small positive displacement.
fn subtract(address: u64, displacement: u64) -> Result<u64, Fault> {
    address.checked_sub(displacement).ok_or_else(|| {
        Fault::Abort(Abort {
            exception: "AddressOutOfBoundsException",
            message: format!(
                "Address Overflow in subtract: {} - 0x{displacement:x}",
                format_address(address)
            ),
        })
    })
}

/// `Address.add(long)` for a small positive displacement.
fn add(address: u64, displacement: u64) -> Result<u64, Fault> {
    address.checked_add(displacement).ok_or_else(|| {
        Fault::Abort(Abort {
            exception: "AddressOutOfBoundsException",
            message: format!(
                "Address Overflow in add: {} 0x{displacement:x}",
                format_address(address)
            ),
        })
    })
}

/// `ElfRelocationHandler.warnExternalOffsetRelocation`, with no memory block
/// reported for the relocation address (see the model's `getBlock`).
fn warn_external_offset(
    env: &mut dyn Environment,
    address: u64,
    symbol_address: Option<u64>,
    symbol_name: Option<&str>,
    adjustment: i64,
) {
    let Some(symbol_address) = symbol_address else {
        return;
    };
    if adjustment == 0 || !env.is_external_address(symbol_address) {
        return;
    }
    let (sign, magnitude) = if adjustment < 0 {
        ("-", adjustment.wrapping_neg())
    } else {
        ("+", adjustment)
    };
    let name = match symbol_name {
        Some(text) if !text.is_empty() => text,
        _ => "<no name>",
    };
    env.console(
        "error",
        format!(
            "EXTERNAL Data ELF Relocation with offset: at {} (External Location = {name}{sign}0x{:x})",
            format_address(address),
            magnitude as u64
        ),
    );
}

/// `AbstractElfRelocationHandler.relocate(context, relocation, address)`.
fn relocate(
    env: &mut dyn Environment,
    record: &Record,
    address: u64,
    symbol: &SymbolInfo,
) -> Result<RelocationResult, Fault> {
    let symbol_index = record.symbol_index();
    let symbol_address = env.symbol_address(symbol);
    let symbol_value = env.symbol_value(symbol);
    let symbol_name = replace_invalid_chars(env.symbol_name(symbol_index).as_deref());
    let type_id = record.type_id();
    if type_id == 0 {
        return Ok(RelocationResult::SKIPPED);
    }
    let Some(name) = type_name(type_id) else {
        markup(
            env,
            "Undefined ELF Relocation",
            None,
            address,
            &default_type_detail(type_id),
            symbol_index,
            symbol_name.as_deref(),
            BOOKMARK_ERROR,
        );
        return Ok(RelocationResult::UNSUPPORTED);
    };
    let typed = Typed { type_id, name };
    relocate_x86_64(
        env,
        record,
        &typed,
        address,
        symbol,
        symbol_address,
        symbol_value as i64,
        symbol_name.as_deref(),
    )
}

/// `X86_64_ElfRelocationHandler.relocate`.
#[allow(clippy::too_many_arguments)]
fn relocate_x86_64(
    env: &mut dyn Environment,
    record: &Record,
    typed: &Typed,
    address: u64,
    symbol: &SymbolInfo,
    symbol_address: Option<u64>,
    symbol_value: i64,
    symbol_name: Option<&str>,
) -> Result<RelocationResult, Fault> {
    let mut addend = if record.has_addend {
        record.addend
    } else {
        read_u64(env, address)? as i64
    };
    let offset = address as i64;
    let symbol_index = record.symbol_index();
    let type_id = typed.type_id;

    match type_id {
        // R_X86_64_RELATIVE, R_X86_64_RELATIVE64
        8 | 38 => {
            let adjustment = env.image_base_adjustment() as i64;
            let value = if env.is_prelinked() {
                (read_u64(env, address)? as i64).wrapping_add(adjustment)
            } else {
                addend.wrapping_add(adjustment)
            };
            write(env, address, &value.to_le_bytes())?;
            return Ok(RelocationResult::applied(8));
        }
        // R_X86_64_IRELATIVE
        37 => {
            let value = addend.wrapping_add(env.image_base_adjustment() as i64);
            write(env, address, &value.to_le_bytes())?;
            return Ok(RelocationResult::applied(8));
        }
        // DTPMOD64, DTPOFF64, TPOFF64, TLSDESC
        16 | 17 | 18 | 36 => {
            typed.warning(
                env,
                address,
                symbol_name,
                symbol_index,
                "Thread Local Symbol relocation not supported",
            );
            return Ok(RelocationResult::UNSUPPORTED);
        }
        // R_X86_64_COPY
        5 => {
            let message = format!("Runtime copy not supported ({}-bytes)", symbol.size as i64);
            typed.warning(env, address, symbol_name, symbol_index, &message);
            return Ok(RelocationResult::UNSUPPORTED);
        }
        _ => {}
    }

    // handleUnresolvedSymbol, which looks the symbol address up again.
    if symbol_index != 0 && env.symbol_address(symbol).is_none() {
        let name = replace_invalid_chars(env.symbol_name(symbol_index).as_deref());
        typed.unhandled(env, address, symbol_index, name.as_deref());
        typed.error(
            env,
            address,
            name.as_deref(),
            symbol_index,
            "Failed to resolve relocation symbol",
        );
        return Ok(RelocationResult::FAILURE);
    }

    let s = symbol_value;
    let size = symbol.size as i64;
    let mut byte_length = 8;
    match type_id {
        // R_X86_64_64
        1 => {
            let value = s.wrapping_add(addend);
            write(env, address, &value.to_le_bytes())?;
            if symbol_index != 0 && addend != 0 && symbol.symbol_type != STT_SECTION {
                warn_external_offset(env, address, symbol_address, symbol_name, addend);
                // applyComponentOffsetPointer returns at once: no block is reported.
            }
        }
        // R_X86_64_16
        12 => {
            let value = s.wrapping_add(addend) as u16;
            write(env, address, &value.to_le_bytes())?;
            byte_length = 2;
        }
        // R_X86_64_8
        14 => {
            write(env, address, &[s.wrapping_add(addend) as u8])?;
            byte_length = 1;
        }
        // PC32, PLT32 (same bits written)
        2 | 4 => {
            let value = s.wrapping_add(addend).wrapping_sub(offset) as u32;
            write(env, address, &value.to_le_bytes())?;
            byte_length = 4;
        }
        // R_X86_64_PC16
        13 => {
            let value = s.wrapping_add(addend).wrapping_sub(offset) as u16;
            write(env, address, &value.to_le_bytes())?;
            byte_length = 2;
        }
        // R_X86_64_PC8
        15 => {
            write(
                env,
                address,
                &[s.wrapping_add(addend).wrapping_sub(offset) as u8],
            )?;
            byte_length = 1;
        }
        // GOT32, 32, 32S
        3 | 10 | 11 => {
            let value = s.wrapping_add(addend) as u32;
            write(env, address, &value.to_le_bytes())?;
            byte_length = 4;
        }
        // GLOB_DAT, JUMP_SLOT
        6 | 7 => {
            write(env, address, &s.wrapping_add(addend).to_le_bytes())?;
        }
        // R_X86_64_GOTOFF64
        25 => match env.got_value() {
            Ok(dotgot) => {
                let value = s.wrapping_add(addend).wrapping_sub(dotgot as i64);
                write(env, address, &value.to_le_bytes())?;
            }
            Err(_) => {
                typed.error(
                    env,
                    address,
                    symbol_name,
                    symbol_index,
                    "GOT allocation failure",
                );
                return Ok(RelocationResult::FAILURE);
            }
        },
        // R_X86_64_SIZE32
        32 => {
            let value = size.wrapping_add(addend) as u32;
            write(env, address, &value.to_le_bytes())?;
            byte_length = 4;
        }
        // R_X86_64_SIZE64
        33 => {
            write(env, address, &size.wrapping_add(addend).to_le_bytes())?;
        }
        // R_X86_64_GOTPC32
        26 => match env.got_value() {
            Ok(dotgot) => {
                let value = (dotgot as i64).wrapping_add(addend).wrapping_sub(offset) as u32;
                write(env, address, &value.to_le_bytes())?;
                byte_length = 4;
            }
            Err(message) => {
                typed.error(env, address, symbol_name, symbol_index, &message);
                return Ok(RelocationResult::FAILURE);
            }
        },
        // GOTPCRELX, REX_GOTPCRELX, then GOTPCREL when not relaxed
        41 | 42 | 9 => {
            if type_id != 9 {
                let op_address = subtract(address, 2)?;
                let mod_rm_address = subtract(address, 1)?;
                let op = read_u8(env, op_address)?;
                let mod_rm = read_u8(env, mod_rm_address)?;
                let mut direct = None;
                if symbol.symbol_type > STT_COMMON {
                    // OS-specific symbol types are not transformed.
                } else if op == 0x8b {
                    env.add_artificial_relocation(op_address, 2);
                    write(env, op_address, &[0x8d])?;
                    direct = Some(address);
                } else if op == 0xff {
                    if mod_rm == 0x25 {
                        env.add_artificial_relocation(op_address, 2);
                        write(env, op_address, &[0xe9])?;
                        let nop = add(address, 3)?;
                        write(env, nop, &[0x90])?;
                        direct = Some(mod_rm_address);
                        addend = addend.wrapping_add(1);
                    } else if mod_rm == 0x15 {
                        env.add_artificial_relocation(op_address, 2);
                        write(env, op_address, &[0x67])?;
                        write(env, mod_rm_address, &[0xe8])?;
                        direct = Some(address);
                    }
                }
                if let Some(target) = direct {
                    let value = s.wrapping_add(addend).wrapping_sub(offset) as u32;
                    write(env, target, &value.to_le_bytes())?;
                    return Ok(RelocationResult::applied(4));
                }
            }
            let Some(entry) = env.got_entry_address(symbol) else {
                typed.error(
                    env,
                    address,
                    symbol_name,
                    symbol_index,
                    "GOT allocation failure",
                );
                return Ok(RelocationResult::FAILURE);
            };
            let value = (entry as i64).wrapping_add(addend).wrapping_sub(offset) as u32;
            write(env, address, &value.to_le_bytes())?;
            byte_length = 4;
        }
        // GOTPCREL64, GOT64
        28 | 27 => {
            let Some(entry) = env.got_entry_address(symbol) else {
                typed.error(
                    env,
                    address,
                    symbol_name,
                    symbol_index,
                    "GOT allocation failure",
                );
                return Ok(RelocationResult::FAILURE);
            };
            let mut value = (entry as i64).wrapping_add(addend);
            if type_id == 28 {
                value = value.wrapping_sub(offset);
            }
            write(env, address, &value.to_le_bytes())?;
        }
        // R_X86_64_PLTOFF64
        31 => {
            let Ok(dotgot) = env.got_value() else {
                typed.error(
                    env,
                    address,
                    symbol_name,
                    symbol_index,
                    "GOT allocation failure",
                );
                return Ok(RelocationResult::FAILURE);
            };
            let value = s.wrapping_sub(dotgot as i64).wrapping_add(addend);
            write(env, address, &value.to_le_bytes())?;
        }
        _ => {
            typed.unhandled(env, address, symbol_index, symbol_name);
            return Ok(RelocationResult::UNSUPPORTED);
        }
    }
    Ok(RelocationResult::applied(byte_length))
}

#[cfg(test)]
mod tests;
