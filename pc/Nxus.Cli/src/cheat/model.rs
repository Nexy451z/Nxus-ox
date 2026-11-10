//! Data model for Atmosphere cheat files and the PC-side cheat VM.
//!
//! The module is deliberately dependency-free (std only) so it can be unit
//! tested without the GUI, the network client, or a Switch.  The parser and
//! manager build on the types below.

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Atmosphere refuses programs with more than 0x400 opcodes.
pub const MAX_PROGRAM_OPCODES: usize = 0x400;
/// Upper bound on one VM evaluation; keeps a broken loop from hanging the PC.
pub const VM_STEP_LIMIT: usize = 65_536;
/// A cheat code line carries one instruction: 1..=4 dwords.
pub const MAX_WORDS_PER_CODE_LINE: usize = 4;
/// Refuse absurdly large text files before allocating a document.
pub const MAX_CHEAT_FILE_BYTES: u64 = 1024 * 1024;

// ---------------------------------------------------------------------------
// Keys, modes and small enums
// ---------------------------------------------------------------------------

/// Stable identity of one cheat section inside a document.
///
/// Duplicate names are legal in Atmosphere files, so the key is an FNV-1a
/// hash of the normalised name plus the occurrence index of that name.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheatKey(pub u64);

impl CheatKey {
    pub fn from_name(name: &str, occurrence: usize) -> Self {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in name.trim().to_lowercase().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        // Domain separator so ("a", 1) and ("a1", 0) cannot collide trivially.
        hash ^= 0x1f;
        hash = hash.wrapping_mul(0x100_0000_01b3);
        for byte in (occurrence as u64).to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        CheatKey(hash)
    }
}

impl fmt::Debug for CheatKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CheatKey({:016X})", self.0)
    }
}

impl fmt::Display for CheatKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016X}", self.0)
    }
}

impl std::str::FromStr for CheatKey {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let trimmed = text.trim();
        let trimmed = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        u64::from_str_radix(trimmed, 16)
            .map(CheatKey)
            .map_err(|_| format!("invalid cheat key: {text}"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheatExecMode {
    /// Write once when enabled, restore originals when disabled.
    Patch,
    /// Evaluate periodically while enabled.
    Loop,
}

impl Default for CheatExecMode {
    fn default() -> Self {
        CheatExecMode::Patch
    }
}

impl CheatExecMode {
    pub fn as_str(self) -> &'static str {
        match self {
            CheatExecMode::Patch => "patch",
            CheatExecMode::Loop => "loop",
        }
    }
}

impl fmt::Display for CheatExecMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where the block's execution mode came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeSource {
    /// Derived from Opcode 8 / C4 auto-detection.
    Auto,
    /// `@patch` / `[patch]` or a header tag was present.
    ExplicitPatch,
    /// `@loop` / `[loop]` or a header tag was present.
    ExplicitLoop,
}

impl Default for ModeSource {
    fn default() -> Self {
        ModeSource::Auto
    }
}

impl ModeSource {
    pub fn explicit(mode: CheatExecMode) -> Self {
        match mode {
            CheatExecMode::Patch => ModeSource::ExplicitPatch,
            CheatExecMode::Loop => ModeSource::ExplicitLoop,
        }
    }

    pub fn explicit_mode(self) -> Option<CheatExecMode> {
        match self {
            ModeSource::Auto => None,
            ModeSource::ExplicitPatch => Some(CheatExecMode::Patch),
            ModeSource::ExplicitLoop => Some(CheatExecMode::Loop),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheatKind {
    /// `{Master Name}` — the master code is normally enabled with the file.
    Master,
    /// `[Cheat Name]`.
    Regular,
}

impl CheatKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CheatKind::Master => "master",
            CheatKind::Regular => "cheat",
        }
    }
}

/// How an explicit restore/off block was written in the source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OffStyle {
    None,
    /// `[Name]` … `--off` / `@off` … `off code`.
    Inline,
    /// `[Name]` … `[Name:OFF]` … `off code`.
    SeparateSection,
}

impl Default for OffStyle {
    fn default() -> Self {
        OffStyle::None
    }
}

// ---------------------------------------------------------------------------
// Instruction operands
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryRegion {
    Main,
    Heap,
    Alias,
    Aslr,
    /// Region 4: the relative address is an absolute address.
    Absolute,
}

impl MemoryRegion {
    pub fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(MemoryRegion::Main),
            1 => Some(MemoryRegion::Heap),
            2 => Some(MemoryRegion::Alias),
            3 => Some(MemoryRegion::Aslr),
            4 => Some(MemoryRegion::Absolute),
            _ => None,
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            MemoryRegion::Main => 0,
            MemoryRegion::Heap => 1,
            MemoryRegion::Alias => 2,
            MemoryRegion::Aslr => 3,
            MemoryRegion::Absolute => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MemoryRegion::Main => "main",
            MemoryRegion::Heap => "heap",
            MemoryRegion::Alias => "alias",
            MemoryRegion::Aslr => "aslr",
            MemoryRegion::Absolute => "absolute",
        }
    }
}

impl Default for MemoryRegion {
    fn default() -> Self {
        MemoryRegion::Main
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    Equal,
    NotEqual,
}

impl Comparison {
    pub fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            1 => Some(Comparison::Greater),
            2 => Some(Comparison::GreaterEqual),
            3 => Some(Comparison::Less),
            4 => Some(Comparison::LessEqual),
            5 => Some(Comparison::Equal),
            6 => Some(Comparison::NotEqual),
            _ => None,
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            Comparison::Greater => 1,
            Comparison::GreaterEqual => 2,
            Comparison::Less => 3,
            Comparison::LessEqual => 4,
            Comparison::Equal => 5,
            Comparison::NotEqual => 6,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Comparison::Greater => ">",
            Comparison::GreaterEqual => ">=",
            Comparison::Less => "<",
            Comparison::LessEqual => "<=",
            Comparison::Equal => "==",
            Comparison::NotEqual => "!=",
        }
    }

    pub fn evaluate(self, left: u64, right: u64) -> bool {
        match self {
            Comparison::Greater => left > right,
            Comparison::GreaterEqual => left >= right,
            Comparison::Less => left < right,
            Comparison::LessEqual => left <= right,
            Comparison::Equal => left == right,
            Comparison::NotEqual => left != right,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArithmeticOp {
    Add,
    Sub,
    Multiply,
    LeftShift,
    RightShift,
    And,
    Or,
    Not,
    Xor,
    None,
    FloatAdd,
    FloatSub,
    FloatMultiply,
    FloatDivide,
}

impl ArithmeticOp {
    pub fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(ArithmeticOp::Add),
            1 => Some(ArithmeticOp::Sub),
            2 => Some(ArithmeticOp::Multiply),
            3 => Some(ArithmeticOp::LeftShift),
            4 => Some(ArithmeticOp::RightShift),
            5 => Some(ArithmeticOp::And),
            6 => Some(ArithmeticOp::Or),
            7 => Some(ArithmeticOp::Not),
            8 => Some(ArithmeticOp::Xor),
            9 => Some(ArithmeticOp::None),
            10 => Some(ArithmeticOp::FloatAdd),
            11 => Some(ArithmeticOp::FloatSub),
            12 => Some(ArithmeticOp::FloatMultiply),
            13 => Some(ArithmeticOp::FloatDivide),
            _ => None,
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            ArithmeticOp::Add => 0,
            ArithmeticOp::Sub => 1,
            ArithmeticOp::Multiply => 2,
            ArithmeticOp::LeftShift => 3,
            ArithmeticOp::RightShift => 4,
            ArithmeticOp::And => 5,
            ArithmeticOp::Or => 6,
            ArithmeticOp::Not => 7,
            ArithmeticOp::Xor => 8,
            ArithmeticOp::None => 9,
            ArithmeticOp::FloatAdd => 10,
            ArithmeticOp::FloatSub => 11,
            ArithmeticOp::FloatMultiply => 12,
            ArithmeticOp::FloatDivide => 13,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ArithmeticOp::Add => "+",
            ArithmeticOp::Sub => "-",
            ArithmeticOp::Multiply => "*",
            ArithmeticOp::LeftShift => "<<",
            ArithmeticOp::RightShift => ">>",
            ArithmeticOp::And => "&",
            ArithmeticOp::Or => "|",
            ArithmeticOp::Not => "~",
            ArithmeticOp::Xor => "^",
            ArithmeticOp::None => "none",
            ArithmeticOp::FloatAdd => "f+",
            ArithmeticOp::FloatSub => "f-",
            ArithmeticOp::FloatMultiply => "f*",
            ArithmeticOp::FloatDivide => "f/",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArithmeticOperand {
    Register(u8),
    Immediate(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveRestoreOp {
    Restore,
    Save,
    ClearSaved,
    ClearRegisters,
}

impl SaveRestoreOp {
    pub fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(SaveRestoreOp::Restore),
            1 => Some(SaveRestoreOp::Save),
            2 => Some(SaveRestoreOp::ClearSaved),
            3 => Some(SaveRestoreOp::ClearRegisters),
            _ => None,
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            SaveRestoreOp::Restore => 0,
            SaveRestoreOp::Save => 1,
            SaveRestoreOp::ClearSaved => 2,
            SaveRestoreOp::ClearRegisters => 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConditionalOperand {
    MemoryRelative {
        region: MemoryRegion,
        rel_address: u64,
    },
    MemoryOffset {
        region: MemoryRegion,
        offset_register: u8,
    },
    RegisterRelative {
        address_register: u8,
        rel_address: u64,
    },
    RegisterOffset {
        address_register: u8,
        offset_register: u8,
    },
    Immediate(u64),
    Register(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreOffset {
    None,
    Register(u8),
    Immediate(u64),
    MemoryRegister(MemoryRegion),
    MemoryImmediate {
        region: MemoryRegion,
        rel_address: u64,
    },
    MemoryImmediateRegister {
        region: MemoryRegion,
        rel_address: u64,
    },
}

impl StoreOffset {
    pub fn code(&self) -> u32 {
        match self {
            StoreOffset::None => 0,
            StoreOffset::Register(_) => 1,
            StoreOffset::Immediate(_) => 2,
            StoreOffset::MemoryRegister(_) => 3,
            StoreOffset::MemoryImmediate { .. } => 4,
            StoreOffset::MemoryImmediateRegister { .. } => 5,
        }
    }
}

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

/// Fully decoded Atmosphere opcode.
///
/// `Unsupported` keeps a file loadable when it contains an opcode this PC
/// implementation does not execute.  The containing block is then refused by
/// the manager rather than silently mis-executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    StoreStatic {
        width: u8,
        region: MemoryRegion,
        offset_register: u8,
        rel_address: u64,
        value: u64,
    },
    BeginConditional {
        width: u8,
        region: MemoryRegion,
        comparison: Comparison,
        include_offset_register: bool,
        offset_register: u8,
        rel_address: u64,
        value: u64,
    },
    EndConditional {
        is_else: bool,
    },
    LoopStart {
        register: u8,
        count: u32,
    },
    LoopEnd {
        register: u8,
    },
    LoadRegisterImmediate {
        register: u8,
        value: u64,
    },
    LoadRegisterMemory {
        width: u8,
        region: MemoryRegion,
        register: u8,
        load_from_register: u8,
        offset_register: u8,
        rel_address: u64,
    },
    StoreStaticToRegister {
        width: u8,
        register: u8,
        increment: bool,
        add_offset_register: bool,
        offset_register: u8,
        value: u64,
    },
    LegacyArithmetic {
        width: u8,
        register: u8,
        operation: ArithmeticOp,
        value: u32,
    },
    KeypressConditional {
        key_mask: u32,
    },
    RegisterArithmetic {
        width: u8,
        operation: ArithmeticOp,
        destination_register: u8,
        source_register_1: u8,
        operand: ArithmeticOperand,
    },
    StoreRegisterToMemory {
        width: u8,
        source_register: u8,
        address_register: u8,
        increment: bool,
        offset: StoreOffset,
    },
    RegisterConditional {
        width: u8,
        comparison: Comparison,
        value_register: u8,
        operand: ConditionalOperand,
    },
    SaveRestoreRegister {
        destination: u8,
        source: u8,
        operation: SaveRestoreOp,
    },
    SaveRestoreRegisterMask {
        operation: SaveRestoreOp,
        mask: u16,
    },
    StaticRegister {
        static_index: u8,
        register: u8,
    },
    PauseProcess,
    ResumeProcess,
    Unsupported {
        opcode: u16,
        words: Vec<u32>,
    },
}

fn push_u64(words: &mut Vec<u32>, value: u64) {
    words.push((value >> 32) as u32);
    words.push(value as u32);
}

fn push_vm_int(words: &mut Vec<u32>, width: u8, value: u64) {
    if width == 8 {
        push_u64(words, value);
    } else {
        words.push(value as u32);
    }
}

impl Instruction {
    /// Atmosphere opcode number, used for mode auto-detection and diagnostics.
    pub fn opcode(&self) -> u16 {
        match self {
            Instruction::StoreStatic { .. } => 0x0,
            Instruction::BeginConditional { .. } => 0x1,
            Instruction::EndConditional { .. } => 0x2,
            Instruction::LoopStart { .. } | Instruction::LoopEnd { .. } => 0x3,
            Instruction::LoadRegisterImmediate { .. } => 0x4,
            Instruction::LoadRegisterMemory { .. } => 0x5,
            Instruction::StoreStaticToRegister { .. } => 0x6,
            Instruction::LegacyArithmetic { .. } => 0x7,
            Instruction::KeypressConditional { .. } => 0x8,
            Instruction::RegisterArithmetic { .. } => 0x9,
            Instruction::StoreRegisterToMemory { .. } => 0xA,
            Instruction::RegisterConditional { .. } => 0xC0,
            Instruction::SaveRestoreRegister { .. } => 0xC1,
            Instruction::SaveRestoreRegisterMask { .. } => 0xC2,
            Instruction::StaticRegister { .. } => 0xC3,
            Instruction::PauseProcess => 0xFF0,
            Instruction::ResumeProcess => 0xFF1,
            Instruction::Unsupported { opcode, .. } => *opcode,
        }
    }

    /// Re-encode the decoded instruction in Atmosphere's word encoding.
    pub fn encode(&self) -> Vec<u32> {
        let mut words = Vec::with_capacity(4);
        match self {
            Instruction::StoreStatic {
                width,
                region,
                offset_register,
                rel_address,
                value,
            } => {
                words.push(
                    ((*width as u32) << 24)
                        | ((region.bits()) << 20)
                        | ((*offset_register as u32) << 16)
                        | (((*rel_address >> 32) & 0xFF) as u32),
                );
                words.push(*rel_address as u32);
                push_vm_int(&mut words, *width, *value);
            }
            Instruction::BeginConditional {
                width,
                region,
                comparison,
                include_offset_register,
                offset_register,
                rel_address,
                value,
            } => {
                words.push(
                    (1u32 << 28)
                        | ((*width as u32) << 24)
                        | ((region.bits()) << 20)
                        | ((comparison.bits()) << 16)
                        | ((*include_offset_register as u32) << 12)
                        | ((*offset_register as u32) << 8)
                        | (((*rel_address >> 32) & 0xFF) as u32),
                );
                words.push(*rel_address as u32);
                push_vm_int(&mut words, *width, *value);
            }
            Instruction::EndConditional { is_else } => {
                words.push((2u32 << 28) | ((*is_else as u32) << 24));
            }
            Instruction::LoopStart { register, count } => {
                words.push((3u32 << 28) | ((*register as u32) << 16));
                words.push(*count);
            }
            Instruction::LoopEnd { register } => {
                words.push((3u32 << 28) | (1u32 << 24) | ((*register as u32) << 16));
            }
            Instruction::LoadRegisterImmediate { register, value } => {
                words.push((4u32 << 28) | ((*register as u32) << 16));
                push_u64(&mut words, *value);
            }
            Instruction::LoadRegisterMemory {
                width,
                region,
                register,
                load_from_register,
                offset_register,
                rel_address,
            } => {
                words.push(
                    (5u32 << 28)
                        | ((*width as u32) << 24)
                        | ((region.bits()) << 20)
                        | ((*register as u32) << 16)
                        | ((*load_from_register as u32) << 12)
                        | ((*offset_register as u32) << 8)
                        | (((*rel_address >> 32) & 0xFF) as u32),
                );
                words.push(*rel_address as u32);
            }
            Instruction::StoreStaticToRegister {
                width,
                register,
                increment,
                add_offset_register,
                offset_register,
                value,
            } => {
                words.push(
                    (6u32 << 28)
                        | ((*width as u32) << 24)
                        | ((*register as u32) << 16)
                        | ((*increment as u32) << 12)
                        | ((*add_offset_register as u32) << 8)
                        | ((*offset_register as u32) << 4),
                );
                push_u64(&mut words, *value);
            }
            Instruction::LegacyArithmetic {
                width,
                register,
                operation,
                value,
            } => {
                words.push(
                    (7u32 << 28)
                        | ((*width as u32) << 24)
                        | ((*register as u32) << 16)
                        | ((operation.bits()) << 12),
                );
                words.push(*value);
            }
            Instruction::KeypressConditional { key_mask } => {
                words.push((8u32 << 28) | (*key_mask & 0x0FFF_FFFF));
            }
            Instruction::RegisterArithmetic {
                width,
                operation,
                destination_register,
                source_register_1,
                operand,
            } => {
                let (has_immediate, src2) = match operand {
                    ArithmeticOperand::Immediate(_) => (1u32, 0u32),
                    ArithmeticOperand::Register(register) => (0, u32::from(*register)),
                };
                words.push(
                    (9u32 << 28)
                        | ((*width as u32) << 24)
                        | ((operation.bits()) << 20)
                        | ((*destination_register as u32) << 16)
                        | ((*source_register_1 as u32) << 12)
                        | (has_immediate << 8)
                        | (src2 << 4),
                );
                if let ArithmeticOperand::Immediate(value) = operand {
                    push_vm_int(&mut words, *width, *value);
                }
            }
            Instruction::StoreRegisterToMemory {
                width,
                source_register,
                address_register,
                increment,
                offset,
            } => {
                let mut first = (0xAu32 << 28)
                    | ((*width as u32) << 24)
                    | ((*source_register as u32) << 20)
                    | ((*address_register as u32) << 16)
                    | ((*increment as u32) << 12)
                    | (offset.code() << 8);
                match offset {
                    StoreOffset::None => {}
                    StoreOffset::Register(offset_register) => {
                        first |= 1 << 8;
                        first |= u32::from(*offset_register) << 4;
                    }
                    StoreOffset::Immediate(rel_address) => {
                        first |= 2 << 8;
                        first |= (((*rel_address >> 32) & 0xF) as u32) << 4;
                        words.push(*rel_address as u32);
                    }
                    StoreOffset::MemoryRegister(region) => {
                        first |= 3 << 8;
                        first |= region.bits() << 4;
                    }
                    StoreOffset::MemoryImmediate {
                        region,
                        rel_address,
                    } => {
                        first |= 4 << 8;
                        first |= region.bits() << 4;
                        first |= ((*rel_address >> 32) & 0xF) as u32;
                        words.push(*rel_address as u32);
                    }
                    StoreOffset::MemoryImmediateRegister {
                        region,
                        rel_address,
                    } => {
                        first |= 5 << 8;
                        first |= region.bits() << 4;
                        first |= ((*rel_address >> 32) & 0xF) as u32;
                        words.push(*rel_address as u32);
                    }
                }
                words.insert(0, first);
            }
            Instruction::RegisterConditional {
                width,
                comparison,
                value_register,
                operand,
            } => {
                let mut first = (0xC0u32 << 24)
                    | ((*width as u32) << 20)
                    | (comparison.bits() << 16)
                    | ((*value_register as u32) << 12);
                match operand {
                    ConditionalOperand::MemoryRelative {
                        region,
                        rel_address,
                    } => {
                        first |= region.bits() << 4;
                        first |= ((*rel_address >> 32) & 0xF) as u32;
                        words.push(*rel_address as u32);
                    }
                    ConditionalOperand::MemoryOffset {
                        region,
                        offset_register,
                    } => {
                        first |= 1 << 8;
                        first |= region.bits() << 4;
                        first |= u32::from(*offset_register);
                    }
                    ConditionalOperand::RegisterRelative {
                        address_register,
                        rel_address,
                    } => {
                        first |= 2 << 8;
                        first |= u32::from(*address_register) << 4;
                        first |= ((*rel_address >> 32) & 0xF) as u32;
                        words.push(*rel_address as u32);
                    }
                    ConditionalOperand::RegisterOffset {
                        address_register,
                        offset_register,
                    } => {
                        first |= 3 << 8;
                        first |= u32::from(*address_register) << 4;
                        first |= u32::from(*offset_register);
                    }
                    ConditionalOperand::Immediate(value) => {
                        first |= 4 << 8;
                        push_vm_int(&mut words, *width, *value);
                    }
                    ConditionalOperand::Register(register) => {
                        first |= 5 << 8;
                        first |= u32::from(*register) << 4;
                    }
                }
                words.insert(0, first);
            }
            Instruction::SaveRestoreRegister {
                destination,
                source,
                operation,
            } => {
                words.push(
                    (0xC1u32 << 24)
                        | ((*destination as u32) << 16)
                        | ((*source as u32) << 8)
                        | ((operation.bits()) << 4),
                );
            }
            Instruction::SaveRestoreRegisterMask { operation, mask } => {
                words.push(
                    (0xC2u32 << 24) | ((operation.bits()) << 20) | (u32::from(*mask) & 0xFFFF),
                );
            }
            Instruction::StaticRegister {
                static_index,
                register,
            } => {
                words.push(
                    (0xC3u32 << 24) | ((u32::from(*static_index)) << 4) | u32::from(*register),
                );
            }
            Instruction::PauseProcess => words.push(0xFF00_0000),
            Instruction::ResumeProcess => words.push(0xFF10_0000),
            Instruction::Unsupported { words: raw, .. } => words.extend_from_slice(raw),
        }
        words
    }
}

// ---------------------------------------------------------------------------
// Parsed code and control-flow metadata
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseIssue {
    pub source_line: usize,
    pub message: String,
}

impl ParseIssue {
    pub fn new(source_line: usize, message: impl Into<String>) -> Self {
        ParseIssue {
            source_line,
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.source_line > 0 {
            write!(f, "line {}: {}", self.source_line, self.message)
        } else {
            f.write_str(&self.message)
        }
    }
}

/// One raw source line of a block body (comment-only lines included).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeLine {
    pub text: String,
    pub source_line: usize,
}

impl CodeLine {
    pub fn new(text: impl Into<String>, source_line: usize) -> Self {
        CodeLine {
            text: text.into(),
            source_line,
        }
    }
}

/// Precomputed control-flow targets, parallel to `CheatCode::instructions`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JumpInfo {
    /// For a condition start: first instruction of the false branch.
    pub false_target: Option<usize>,
    /// For an `else`: first instruction after the matching `end`.
    pub else_target: Option<usize>,
    /// For a loop start: the matching loop end index.
    pub loop_end: Option<usize>,
    /// For a loop end: the matching loop start index.
    pub loop_start: Option<usize>,
}

/// A decoded ON or OFF block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheatCode {
    /// All body lines, verbatim, excluding directives and the `--off` divider.
    pub lines: Vec<CodeLine>,
    pub instructions: Vec<Instruction>,
    pub jumps: Vec<JumpInfo>,
    pub issues: Vec<ParseIssue>,
}

impl CheatCode {
    pub fn new() -> Self {
        Self::default()
    }

    /// True when every line decoded and the control-flow structure is sound.
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty() && self.jumps.len() == self.instructions.len()
    }

    /// True when this code can actually be run (valid and at least one opcode).
    pub fn is_executable(&self) -> bool {
        self.is_valid() && !self.instructions.is_empty()
    }

    pub fn push_line(&mut self, text: impl Into<String>, source_line: usize) {
        self.lines.push(CodeLine::new(text, source_line));
    }

    pub fn raw_text(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push_str(&line.text);
            out.push('\n');
        }
        out
    }

    pub fn has_keypress_conditional(&self) -> bool {
        self.instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::KeypressConditional { .. }))
    }

    pub fn first_issue(&self) -> Option<&ParseIssue> {
        self.issues.first()
    }
}

// ---------------------------------------------------------------------------
// Blocks and documents
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CheatBlock {
    pub key: CheatKey,
    pub name: String,
    pub kind: CheatKind,
    pub mode: CheatExecMode,
    pub mode_source: ModeSource,
    /// Runtime state: `true` only while the manager has this block applied.
    ///
    /// Loading a file always leaves it `false` — a cheat file cannot start a
    /// cheat — and the writer never turns it into an ON marker on disk.
    pub enabled: bool,
    /// What the file said when it was parsed (`[Name:ON]` / `@on`).
    ///
    /// Display only ("saved: ON").  It is never applied at startup and is
    /// cleared on every save, because the writer always stores every block as
    /// OFF.
    pub saved_enabled: bool,
    pub on: CheatCode,
    pub off: Option<CheatCode>,
    pub explicit_off: bool,
    pub off_style: OffStyle,
    /// Text after the closing bracket on the header line, e.g. a comment.
    pub header_extra: String,
    /// 1-based source line of the header.
    pub source_line: usize,
}

impl CheatBlock {
    pub fn new(key: CheatKey, name: impl Into<String>, kind: CheatKind) -> Self {
        CheatBlock {
            key,
            name: name.into(),
            kind,
            mode: CheatExecMode::Patch,
            mode_source: ModeSource::Auto,
            enabled: false,
            saved_enabled: false,
            on: CheatCode::new(),
            off: None,
            explicit_off: false,
            off_style: OffStyle::None,
            header_extra: String::new(),
            source_line: 0,
        }
    }

    pub fn is_master(&self) -> bool {
        self.kind == CheatKind::Master
    }

    /// A block whose ON half is empty is an orphan `[Name:OFF]` restore-only
    /// section and cannot be enabled.
    pub fn is_restore_only(&self) -> bool {
        self.on.lines.is_empty() && self.on.instructions.is_empty()
    }

    pub fn is_enableable(&self) -> bool {
        !self.is_restore_only() && self.on.is_executable()
    }

    pub fn has_keypad_trigger(&self) -> bool {
        self.on.has_keypress_conditional()
            || self
                .off
                .as_ref()
                .map(CheatCode::has_keypress_conditional)
                .unwrap_or(false)
    }

    /// Recompute the automatic mode unless the file pinned one explicitly.
    pub fn refresh_mode(&mut self) {
        if self.mode_source == ModeSource::Auto {
            self.mode = if self.has_keypad_trigger() {
                CheatExecMode::Loop
            } else {
                CheatExecMode::Patch
            };
        } else if let Some(mode) = self.mode_source.explicit_mode() {
            self.mode = mode;
        }
    }

    pub fn set_mode(&mut self, mode: CheatExecMode, explicit: bool) {
        self.mode = mode;
        self.mode_source = if explicit {
            ModeSource::explicit(mode)
        } else {
            ModeSource::Auto
        };
        self.refresh_mode();
    }

    pub fn all_issues(&self) -> Vec<&ParseIssue> {
        let mut issues: Vec<&ParseIssue> = self.on.issues.iter().collect();
        if let Some(off) = &self.off {
            issues.extend(off.issues.iter());
        }
        issues
    }
}

/// In-memory representation of `<BuildID>.txt`.
///
/// `raw_text` keeps the file exactly as it was loaded, so a reload never loses
/// a comment or a line.  Saving normalises newlines, mode directives and the
/// OFF spelling, and writes every block as OFF — the state is never stored.
#[derive(Clone, Debug)]
pub struct CheatDocument {
    pub build_id: String,
    pub path: Option<PathBuf>,
    /// Lines before the first section header.
    pub preamble: Vec<String>,
    pub blocks: Vec<CheatBlock>,
    /// Structural / header issues.  Code issues live on each `CheatCode`.
    pub issues: Vec<ParseIssue>,
    /// Last loaded/saved text, used for raw editing and dirty detection.
    pub raw_text: String,
    pub generation: u64,
}

impl Default for CheatDocument {
    fn default() -> Self {
        CheatDocument {
            build_id: String::new(),
            path: None,
            preamble: Vec::new(),
            blocks: Vec::new(),
            issues: Vec::new(),
            raw_text: String::new(),
            generation: 0,
        }
    }
}

impl CheatDocument {
    pub fn new(build_id: impl Into<String>) -> Self {
        CheatDocument {
            build_id: build_id.into(),
            ..Default::default()
        }
    }

    /// Parse an in-memory document.
    pub fn parse(text: &str, build_id: &str) -> Self {
        crate::cheat::parser::parse_document(text, build_id)
    }

    /// Load a document from disk.
    pub fn load(path: &Path, build_id: &str) -> Result<Self, String> {
        crate::cheat::parser::parse_file(path, build_id)
    }

    pub fn is_dirty(&self) -> bool {
        self.raw_text != self.to_text()
    }

    pub fn block(&self, key: CheatKey) -> Option<&CheatBlock> {
        self.blocks.iter().find(|block| block.key == key)
    }

    pub fn block_mut(&mut self, key: CheatKey) -> Option<&mut CheatBlock> {
        self.blocks.iter_mut().find(|block| block.key == key)
    }

    pub fn block_by_name(&self, name: &str) -> Option<&CheatBlock> {
        let needle = name.trim();
        self.blocks
            .iter()
            .find(|block| block.name.eq_ignore_ascii_case(needle))
    }

    pub fn block_by_name_mut(&mut self, name: &str) -> Option<&mut CheatBlock> {
        let needle = name.trim().to_lowercase();
        self.blocks
            .iter_mut()
            .find(|block| block.name.to_lowercase() == needle)
    }

    pub fn index_of(&self, key: CheatKey) -> Option<usize> {
        self.blocks.iter().position(|block| block.key == key)
    }

    pub fn occurrence_count(&self, name: &str) -> usize {
        let needle = name.trim().to_lowercase();
        self.blocks
            .iter()
            .filter(|block| block.name.to_lowercase() == needle)
            .count()
    }

    /// Append a block and assign a key that respects duplicate names.
    pub fn add_block(&mut self, mut block: CheatBlock) -> CheatKey {
        let occurrence = self.occurrence_count(&block.name);
        block.key = CheatKey::from_name(&block.name, occurrence);
        let key = block.key;
        self.blocks.push(block);
        key
    }

    /// Create and append a simple block from raw code text.
    pub fn add_cheat(
        &mut self,
        name: &str,
        code_lines: &[String],
        mode: Option<CheatExecMode>,
    ) -> CheatKey {
        let mut block = CheatBlock::new(CheatKey(0), name, CheatKind::Regular);
        if let Some(mode) = mode {
            block.mode_source = ModeSource::explicit(mode);
            block.mode = mode;
        }
        let occurrence = self.occurrence_count(name);
        block.key = CheatKey::from_name(name, occurrence);
        block.on = crate::cheat::parser::parse_code_lines(code_lines, 0);
        block.refresh_mode();
        let key = block.key;
        self.blocks.push(block);
        key
    }

    pub fn remove_block(&mut self, key: CheatKey) -> Option<CheatBlock> {
        let removed = self
            .blocks
            .iter()
            .position(|block| block.key == key)
            .map(|index| self.blocks.remove(index));
        if removed.is_some() {
            self.rekey_duplicates();
        }
        removed
    }

    pub fn remove_block_at(&mut self, index: usize) -> Option<CheatBlock> {
        if index < self.blocks.len() {
            let removed = self.blocks.remove(index);
            self.rekey_duplicates();
            Some(removed)
        } else {
            None
        }
    }

    /// Keep occurrence-indexed keys stable after a deletion shifts the
    /// occurrence numbers of same-named blocks.
    pub fn rekey_duplicates(&mut self) {
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for block in &mut self.blocks {
            let normalized = block.name.trim().to_lowercase();
            let occurrence = counts.entry(normalized).or_insert(0);
            block.key = CheatKey::from_name(&block.name, *occurrence);
            *occurrence += 1;
        }
    }

    pub fn replace_on_code(&mut self, key: CheatKey, lines: &[String]) -> Result<(), String> {
        let block = self
            .blocks
            .iter_mut()
            .find(|block| block.key == key)
            .ok_or_else(|| format!("cheat {key} not found"))?;
        let first_line = block
            .on
            .lines
            .first()
            .map(|line| line.source_line)
            .unwrap_or(0);
        block.on = crate::cheat::parser::parse_code_lines(lines, first_line);
        block.refresh_mode();
        Ok(())
    }

    pub fn replace_off_code(
        &mut self,
        key: CheatKey,
        lines: Option<&[String]>,
    ) -> Result<(), String> {
        let block = self
            .blocks
            .iter_mut()
            .find(|block| block.key == key)
            .ok_or_else(|| format!("cheat {key} not found"))?;
        match lines {
            Some(lines) => {
                let first_line = block
                    .off
                    .as_ref()
                    .and_then(|code| code.lines.first())
                    .map(|line| line.source_line)
                    .unwrap_or(0);
                block.off = Some(crate::cheat::parser::parse_code_lines(lines, first_line));
                block.explicit_off = true;
                if block.off_style == OffStyle::None {
                    block.off_style = OffStyle::Inline;
                }
            }
            None => {
                block.off = None;
                block.explicit_off = false;
                block.off_style = OffStyle::None;
            }
        }
        block.refresh_mode();
        Ok(())
    }

    pub fn set_block_enabled(&mut self, key: CheatKey, enabled: bool) -> bool {
        match self.block_mut(key) {
            Some(block) => {
                block.enabled = enabled;
                true
            }
            None => false,
        }
    }

    pub fn set_block_mode(&mut self, key: CheatKey, mode: CheatExecMode, explicit: bool) -> bool {
        match self.block_mut(key) {
            Some(block) => {
                block.set_mode(mode, explicit);
                true
            }
            None => false,
        }
    }

    pub fn set_block_name(&mut self, key: CheatKey, name: impl Into<String>) -> bool {
        match self.block_mut(key) {
            Some(block) => {
                block.name = name.into();
                self.rekey_duplicates();
                true
            }
            None => false,
        }
    }

    pub fn issues_with_block(&self) -> Vec<ParseIssue> {
        let mut issues = self.issues.clone();
        for block in &self.blocks {
            issues.extend(block.on.issues.iter().cloned());
            if let Some(off) = &block.off {
                issues.extend(off.issues.iter().cloned());
            }
        }
        issues
    }

    /// Serialise the structured document.
    ///
    /// Comments and blank lines inside bodies are emitted verbatim.  Only
    /// header state, explicit mode directives and the OFF divider style are
    /// normalised.  The state is always written as OFF: a cheat file never
    /// records which cheats were on in the previous session.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for line in &self.preamble {
            out.push_str(line);
            out.push('\n');
        }

        for block in &self.blocks {
            let orphan_off = block.on.lines.is_empty()
                && block.on.instructions.is_empty()
                && block.explicit_off
                && block.off_style == OffStyle::SeparateSection;

            if !orphan_off {
                out.push_str(&render_header(block));
                out.push_str(&block.header_extra);
                out.push('\n');

                // Every block is written as OFF, even one that is ON in memory.
                // The state is not persisted: after the title or the console
                // restarts the applied bytes are gone, so a saved ON would come
                // back as a lie.  `@off` is the unambiguous OFF spelling;
                // `[Name:OFF]` is reserved for a real restore section, so it can
                // never swallow the ON code on reload.
                out.push_str("@off\n");
                match block.mode_source {
                    ModeSource::ExplicitLoop => out.push_str("@loop\n"),
                    ModeSource::ExplicitPatch => out.push_str("@patch\n"),
                    ModeSource::Auto => {}
                }
                for line in &block.on.lines {
                    out.push_str(&line.text);
                    out.push('\n');
                }
            }

            if let Some(off) = &block.off {
                match block.off_style {
                    OffStyle::SeparateSection => {
                        out.push_str(&format!(
                            "{}{}:OFF{}\n",
                            header_open(block.kind),
                            block.name,
                            header_close(block.kind)
                        ));
                    }
                    _ => out.push_str("--off\n"),
                }
                for line in &off.lines {
                    out.push_str(&line.text);
                    out.push('\n');
                }
            }
        }

        out
    }

    /// Write the document atomically to `path` (tmp + flush + rename).
    ///
    /// Every block is stored as OFF; the in-memory `saved_enabled` markers are
    /// dropped because they no longer describe the file that was written.
    pub fn save_to(&mut self, path: &Path) -> Result<(), String> {
        let text = self.to_text();
        save_text_atomic(path, &text).map_err(|error| format!("{}: {error}", path.display()))?;
        self.path = Some(path.to_path_buf());
        self.raw_text = text;
        for block in &mut self.blocks {
            block.saved_enabled = false;
        }
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// Write to the document's current path.
    pub fn save(&mut self) -> Result<(), String> {
        let path = self
            .path
            .clone()
            .ok_or_else(|| "cheat document has no path".to_string())?;
        self.save_to(&path)
    }
}

fn header_open(kind: CheatKind) -> char {
    match kind {
        CheatKind::Master => '{',
        CheatKind::Regular => '[',
    }
}

fn header_close(kind: CheatKind) -> char {
    match kind {
        CheatKind::Master => '}',
        CheatKind::Regular => ']',
    }
}

fn render_header(block: &CheatBlock) -> String {
    // `[Name:OFF]` is the restore-section spelling, never the disabled marker;
    // the writer emits `@off` for a disabled block instead.
    format!(
        "{}{}{}",
        header_open(block.kind),
        block.name,
        header_close(block.kind)
    )
}

/// Atomically replace `path` with `text`.
///
/// A sibling `.bak` copy is kept when a previous file exists.  On Windows a
/// rename over an existing file can fail, so the destination is removed and
/// the rename retried; the temporary file always lives on the same volume.
pub fn save_text_atomic(path: &Path, text: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "cheats.txt".to_string());
    let temp_path = path.with_file_name(format!("{file_name}.tmp"));
    let backup_path = path.with_file_name(format!("{file_name}.bak"));

    {
        let mut file = fs::File::create(&temp_path)?;
        file.write_all(text.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
    }

    if path.exists() {
        // Best-effort previous-generation copy; a failure here must not stop
        // the actual save.
        let _ = fs::copy(path, &backup_path);
    }

    match fs::rename(&temp_path, path) {
        Ok(()) => Ok(()),
        Err(first_error) => {
            if path.exists() {
                fs::remove_file(path)?;
            }
            fs::rename(&temp_path, path).map_err(|second_error| {
                io::Error::new(
                    second_error.kind(),
                    format!(
                        "rename failed ({first_error}); after removing destination: {second_error}"
                    ),
                )
            })
        }
    }
}

/// Atomically replace `path` with cheat-file `text`, stripping ON markers.
///
/// Use this for text that did not go through [`CheatDocument::to_text`] (the
/// raw editor, a new file): the store must never say a block is ON, or the next
/// launch would show cheats that are not applied.  All other formatting is left
/// exactly as typed — see [`crate::cheat::parser::sanitize_on_markers`].
pub fn save_cheat_text_atomic(path: &Path, text: &str) -> io::Result<()> {
    save_text_atomic(path, &crate::cheat::parser::sanitize_on_markers(text))
}

/// Format decoded instructions as canonical uppercase code lines.
pub fn instructions_to_lines(instructions: &[Instruction]) -> Vec<String> {
    instructions
        .iter()
        .map(|instruction| {
            instruction
                .encode()
                .iter()
                .map(|word| format!("{word:08X}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cheat_keys_distinguish_duplicate_names() {
        let first = CheatKey::from_name("Money", 0);
        let second = CheatKey::from_name("Money", 1);
        let other = CheatKey::from_name("money ", 0);
        assert_ne!(first, second);
        assert_eq!(first, other);
        assert_eq!(first.to_string(), format!("{:016X}", first.0));
    }

    #[test]
    fn instruction_encode_decode_shape_is_stable() {
        let instruction = Instruction::StoreStatic {
            width: 4,
            region: MemoryRegion::Main,
            offset_register: 0,
            rel_address: 0x42CA_1DC4,
            value: 0x0098_967F,
        };
        assert_eq!(
            instruction.encode(),
            vec![0x0400_0000, 0x42CA_1DC4, 0x0098_967F]
        );
    }

    #[test]
    fn atomic_save_keeps_previous_generation() {
        let dir = std::env::temp_dir().join(format!(
            "nxus-model-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ABC.txt");
        save_text_atomic(&path, "first\n").unwrap();
        save_text_atomic(&path, "second\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second\n");
        assert_eq!(
            fs::read_to_string(dir.join("ABC.txt.bak")).unwrap(),
            "first\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cheat_text_save_strips_on_markers() {
        let dir = std::env::temp_dir().join(format!(
            "nxus-model-on-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ABC.txt");
        save_cheat_text_atomic(&path, "[A:ON]\n04000000 10000000 00000001\n@on\n").unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("[A]\n@off\n04000000"), "{text}");
        assert!(!text.to_ascii_lowercase().contains(":on"), "{text}");
        assert!(
            !text.lines().any(|line| line.trim().eq_ignore_ascii_case("@on")),
            "{text}"
        );
        let document = CheatDocument::parse(&text, "0123456789ABCDEF");
        assert!(document.blocks.iter().all(|block| !block.enabled));
        assert!(document.blocks.iter().all(|block| !block.saved_enabled));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_regions_round_trip() {
        for bits in 0..=4 {
            let region = MemoryRegion::from_bits(bits).unwrap();
            assert_eq!(region.bits(), bits);
        }
        assert!(MemoryRegion::from_bits(5).is_none());
    }
}
