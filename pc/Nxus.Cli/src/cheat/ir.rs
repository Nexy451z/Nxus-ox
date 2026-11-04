//! Linked cheat programs for the on-console interpreter.
//!
//! The PC already parses an Atmosphere `<BUILDID>.txt` into a
//! [`CheatDocument`]; this module turns that document into the **wire program**
//! described by `core/nxus_cheatvm.h`, so the console needs no assembler and no
//! linker: every branch target is already resolved to an **instruction index**
//! in the flat instruction array.
//!
//! The wire layout is a header, one block descriptor per cheat, and then the
//! instructions of every block, back to back.  All integers are little endian
//! and all structures are packed (no padding):
//!
//! ```text
//! NxusCheatProgramHeader (32 bytes)
//!   u32 magic, u32 version, u64 build_id, u64 program_id,
//!   u16 block_count, u16 insn_count, u16 total_bytes, u16 reserved
//! NxusCheatBlockDesc (24 bytes) x block_count
//!   u32 index, u32 mode, u32 first, u32 count, u32 enabled, u32 reserved
//! NxusCheatInsn (24 bytes) x insn_count
//!   u16 op, u8 width, u8 region, u8 cmp, u8 reg_a, u8 reg_b, u8 flags,
//!   u32 target, u32 address, u64 value
//! ```
//!
//! `core/nxus_cheatvm.h` declares the four header counters as `u32`, which sums
//! to 40 bytes and contradicts the `sizeof(...) == 32` assertion right below
//! them.  This module follows the asserted size (32 bytes; also the size the
//! console budget was computed from), so those four counters are 16-bit.  Every
//! legal value fits: at most 128 blocks, 512 instructions and 48 KiB.
//!
//! ## Instruction mapping
//!
//! `target` is a program-wide instruction index; it is `0` for instructions
//! that never branch.  `address` holds the low 32 bits of a relative address
//! (always `0` when unused) and `value` holds an immediate, a key mask or a
//! register mask.
//!
//! | `Instruction` (model.rs) | `op` | fields |
//! |---|---|---|
//! | `StoreStatic` | 1 | `width`, `region`, `address`, `value`, `reg_b` = offset register |
//! | `BeginConditional` | 2 | `width`, `region`, `cmp`, `address`, `value`, `reg_b`, [`FLAG_OFFSET_REGISTER`] |
//! | `EndConditional { is_else: true }` | 3 | `target` = first instruction after the matching end |
//! | `EndConditional { is_else: false }` | 4 | falls through, `target` = 0 |
//! | `LoopStart` | 5 | `reg_a` = counter, `value` = count, `target` = first body instruction |
//! | `LoopEnd` | 6 | `reg_a` = counter, `target` = the matching `LoopStart` |
//! | `LoadRegisterImmediate` | 7 | `reg_a`, `value` |
//! | `LoadRegisterMemory` modes 0..3 | 8, 11, 12, 13 | `width`, `reg_a` = destination, `reg_b` = base register, `region`, `address` |
//! | `StoreStaticToRegister` | 9 | `width`, `reg_a`, `reg_b`, `value`, [`FLAG_INCREMENT`] / [`FLAG_OFFSET_REGISTER`] |
//! | `LegacyArithmetic` | 10 | `width`, `reg_a`, `cmp` = arithmetic, `value` |
//! | `RegisterArithmetic` (immediate, in place) | 10 | `width`, `reg_a`, `cmp` = arithmetic, `value` |
//! | `RegisterArithmetic` (register, in place) | 14 | `width`, `reg_a`, `cmp` = arithmetic, `reg_b` = operand |
//! | `StoreRegisterToMemory` | 15 | `width`, `reg_a` = address register, `reg_b` = source register, `flags` = mode, [`FLAG_INCREMENT`], offset register; `region`/`address` for the offset forms |
//! | `RegisterConditional` | 16 | `width`, `cmp`, `reg_a` = value register, `flags` = operand form, `reg_b`/`region`/`address`/`value` per form |
//! | `SaveRestoreRegisterMask` (save/restore) | 17, 18 | `value` = mask |
//! | `StaticRegister` | 19 | `reg_a`, `value` = static index, [`FLAG_STATIC_WRITE`] when writing |
//! | `PauseProcess` / `ResumeProcess` | 20, 21 | — |
//! | `KeypressConditional` | 22 | `value` = key mask, `target` = false branch |
//!
//! Anything the wire format cannot express is an **error**, never a silent
//! drop: `Unsupported` opcodes, single-register save/restore, out-of-range
//! arithmetic, 3-operand register arithmetic (the wire opcodes are in place),
//! and relative addresses wider than 32 bits.
//!
//! A conditional whose false/else branch leaves the block at its very end would
//! point one past the last instruction.  Such a block gets a trailing
//! [`OP_NOP`] so every target names an instruction the console can validate;
//! the interpreter stops at the end of the block either way.
//!
//! The OFF half of a block is deliberately not part of the program: the console
//! journals the original bytes and restores them when a block is disabled.

use std::collections::BTreeSet;

use super::model::{
    ArithmeticOp, ArithmeticOperand, CheatCode, CheatDocument, CheatExecMode, CheatKey, Comparison,
    ConditionalOperand, Instruction, MemoryRegion, SaveRestoreOp, StoreOffset,
};

// ---------------------------------------------------------------------------
// Limits and format constants (mirror of `core/nxus_cheatvm.h`)
// ---------------------------------------------------------------------------

/// `NXUS_CHEATVM_MAGIC` - the bytes `N C V M` read as a big-endian word.
pub const MAGIC: u32 = 0x4E43_564D;
/// `NXUS_CHEATVM_VERSION`.
pub const VERSION: u32 = 1;

/// Bytes of `NxusCheatProgramHeader`.
pub const HEADER_BYTES: usize = 32;
/// Bytes of `NxusCheatBlockDesc`.
pub const BLOCK_BYTES: usize = 24;
/// Bytes of `NxusCheatInsn`.
pub const INSN_BYTES: usize = 24;

/// `NXUS_CHEATVM_MAX_PROGRAM_BYTES`: header + blocks + instructions.
pub const MAX_PROGRAM_BYTES: usize = 48 * 1024;
/// `NXUS_CHEATVM_MAX_INSNS`.
pub const MAX_INSNS: usize = 512;
/// `NXUS_CHEATVM_MAX_BLOCKS`.
pub const MAX_BLOCKS: usize = 128;
/// `NXUS_CHEATVM_MAX_JOURNAL` (the console journals patched bytes itself).
pub const MAX_JOURNAL: usize = 512;
/// `NXUS_CHEATVM_STEP_LIMIT`: interpreter steps for one block execution.
pub const STEP_LIMIT: u32 = 100_000;

/// `NxusCheatBlockDesc.mode`: run once when enabled.
pub const MODE_PATCH: u32 = 0;
/// `NxusCheatBlockDesc.mode`: run on every tick.
pub const MODE_LOOP: u32 = 1;

// ---------------------------------------------------------------------------
// Opcodes (`NxusCheatOp_*`)
// ---------------------------------------------------------------------------

pub const OP_NOP: u16 = 0;
pub const OP_STORE_STATIC: u16 = 1;
pub const OP_BEGIN_CONDITIONAL: u16 = 2;
pub const OP_ELSE: u16 = 3;
pub const OP_END_CONDITIONAL: u16 = 4;
pub const OP_LOOP_START: u16 = 5;
pub const OP_LOOP_END: u16 = 6;
pub const OP_LOAD_REG_IMM: u16 = 7;
pub const OP_LOAD_REG_MEM: u16 = 8;
pub const OP_STORE_STATIC_TO_REG: u16 = 9;
pub const OP_ARITH_IMM: u16 = 10;
pub const OP_LOAD_REG_MEM_REG: u16 = 11;
pub const OP_LOAD_REG_MEM_REG_REG: u16 = 12;
pub const OP_LOAD_REG_MEM_REG_REGION: u16 = 13;
pub const OP_ARITH_REG: u16 = 14;
pub const OP_STORE_REG: u16 = 15;
pub const OP_REG_CONDITIONAL: u16 = 16;
pub const OP_SAVE_REGS: u16 = 17;
pub const OP_RESTORE_REGS: u16 = 18;
pub const OP_STATIC_REGS: u16 = 19;
pub const OP_PAUSE: u16 = 20;
pub const OP_RESUME: u16 = 21;
pub const OP_KEYPRESS_CONDITIONAL: u16 = 22;

/// `flags` bit for `OP_STORE_STATIC_TO_REG`/`OP_STORE_REG`: the address
/// register is advanced by `width` after the access (Atmosphere 0x6/0xA bit 12).
pub const FLAG_INCREMENT: u8 = 1 << 0;
/// `flags` bit for `OP_BEGIN_CONDITIONAL`/`OP_STORE_STATIC_TO_REG`: `reg_b` is
/// added to the region-relative address.
pub const FLAG_OFFSET_REGISTER: u8 = 1 << 1;
/// `flags` bit for `OP_STATIC_REGS`: the transfer goes general -> static
/// (the Atmosphere 0xC3 convention of a static index at or above `0x80`).
pub const FLAG_STATIC_WRITE: u8 = 1 << 0;

/// `OP_REG_CONDITIONAL` operand form: `[region + address]`.
pub const COND_MEMORY_RELATIVE: u8 = 0;
/// `OP_REG_CONDITIONAL` operand form: `[region + rB]`.
pub const COND_MEMORY_OFFSET: u8 = 1;
/// `OP_REG_CONDITIONAL` operand form: `[rB + address]`.
pub const COND_REGISTER_RELATIVE: u8 = 2;
/// `OP_REG_CONDITIONAL` operand form: `[rB + rValue]` (the offset register is
/// kept in `value`).
pub const COND_REGISTER_OFFSET: u8 = 3;
/// `OP_REG_CONDITIONAL` operand form: compare against the immediate `value`.
pub const COND_IMMEDIATE: u8 = 4;
/// `OP_REG_CONDITIONAL` operand form: compare against `rB`.
pub const COND_REGISTER: u8 = 5;

// ---------------------------------------------------------------------------
// Wire structures
// ---------------------------------------------------------------------------

/// `NxusCheatProgramHeader` - 32 bytes, packed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProgramHeader {
    pub magic: u32,
    pub version: u32,
    pub build_id: u64,
    pub program_id: u64,
    pub block_count: u16,
    pub insn_count: u16,
    /// Header + blocks + instructions.
    pub total_bytes: u16,
    pub reserved: u16,
}

impl ProgramHeader {
    pub fn to_bytes(self) -> [u8; HEADER_BYTES] {
        let mut out = [0u8; HEADER_BYTES];
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4..8].copy_from_slice(&self.version.to_le_bytes());
        out[8..16].copy_from_slice(&self.build_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.program_id.to_le_bytes());
        out[24..26].copy_from_slice(&self.block_count.to_le_bytes());
        out[26..28].copy_from_slice(&self.insn_count.to_le_bytes());
        out[28..30].copy_from_slice(&self.total_bytes.to_le_bytes());
        out[30..32].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != HEADER_BYTES {
            return Err(format!(
                "program header needs {HEADER_BYTES} bytes, got {}",
                bytes.len()
            ));
        }
        Ok(ProgramHeader {
            magic: read_u32(bytes, 0),
            version: read_u32(bytes, 4),
            build_id: read_u64(bytes, 8),
            program_id: read_u64(bytes, 16),
            block_count: read_u16(bytes, 24),
            insn_count: read_u16(bytes, 26),
            total_bytes: read_u16(bytes, 28),
            reserved: read_u16(bytes, 30),
        })
    }
}

/// `NxusCheatBlockDesc` - 24 bytes, packed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockDesc {
    /// Position of the block in the document.
    pub index: u32,
    /// [`MODE_PATCH`] or [`MODE_LOOP`].
    pub mode: u32,
    /// First instruction index.
    pub first: u32,
    /// Instruction count.
    pub count: u32,
    /// Whether the upload asked for this block to start enabled.
    pub enabled: u32,
    pub reserved: u32,
}

impl BlockDesc {
    pub fn to_bytes(self) -> [u8; BLOCK_BYTES] {
        let mut out = [0u8; BLOCK_BYTES];
        out[0..4].copy_from_slice(&self.index.to_le_bytes());
        out[4..8].copy_from_slice(&self.mode.to_le_bytes());
        out[8..12].copy_from_slice(&self.first.to_le_bytes());
        out[12..16].copy_from_slice(&self.count.to_le_bytes());
        out[16..20].copy_from_slice(&self.enabled.to_le_bytes());
        out[20..24].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != BLOCK_BYTES {
            return Err(format!(
                "block descriptor needs {BLOCK_BYTES} bytes, got {}",
                bytes.len()
            ));
        }
        Ok(BlockDesc {
            index: read_u32(bytes, 0),
            mode: read_u32(bytes, 4),
            first: read_u32(bytes, 8),
            count: read_u32(bytes, 12),
            enabled: read_u32(bytes, 16),
            reserved: read_u32(bytes, 20),
        })
    }
}

/// `NxusCheatInsn` - one decoded, linked instruction; 24 bytes, packed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireInsn {
    /// One of the `OP_*` constants.
    pub op: u16,
    /// 1/2/4/8, `0` when the opcode has no access width.
    pub width: u8,
    /// [`MemoryRegion::bits`], `0` when unused.
    pub region: u8,
    /// `NxusCheatCmp` / `NxusCheatArith` numbering, `0` when unused.
    pub cmp: u8,
    pub reg_a: u8,
    pub reg_b: u8,
    /// Opcode specific; see the module documentation.
    pub flags: u8,
    /// Linked branch target (a program-wide instruction index), `0` when none.
    pub target: u32,
    /// Low 32 bits of the relative address, or an immediate.
    pub address: u32,
    /// Immediate, key mask or register mask.
    pub value: u64,
}

impl WireInsn {
    pub fn to_bytes(self) -> [u8; INSN_BYTES] {
        let mut out = [0u8; INSN_BYTES];
        out[0..2].copy_from_slice(&self.op.to_le_bytes());
        out[2] = self.width;
        out[3] = self.region;
        out[4] = self.cmp;
        out[5] = self.reg_a;
        out[6] = self.reg_b;
        out[7] = self.flags;
        out[8..12].copy_from_slice(&self.target.to_le_bytes());
        out[12..16].copy_from_slice(&self.address.to_le_bytes());
        out[16..24].copy_from_slice(&self.value.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != INSN_BYTES {
            return Err(format!(
                "instruction needs {INSN_BYTES} bytes, got {}",
                bytes.len()
            ));
        }
        Ok(WireInsn {
            op: u16::from_le_bytes([bytes[0], bytes[1]]),
            width: bytes[2],
            region: bytes[3],
            cmp: bytes[4],
            reg_a: bytes[5],
            reg_b: bytes[6],
            flags: bytes[7],
            target: read_u32(bytes, 8),
            address: read_u32(bytes, 12),
            value: read_u64(bytes, 16),
        })
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(word)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(word)
}

// ---------------------------------------------------------------------------
// Building a program
// ---------------------------------------------------------------------------

/// Link `document` into one console program.
///
/// Every block of the document becomes one [`BlockDesc`] (in document order),
/// carrying the ON instructions of that block.  `enabled` is the set of cheat
/// keys the caller wants enabled at upload time; it lands in
/// `BlockDesc::enabled`.
///
/// A block whose ON code has parse issues is refused: shipping a partial block
/// would execute something the user never wrote.
pub fn build_program(
    document: &CheatDocument,
    build_id: u64,
    program_id: u64,
    enabled: &BTreeSet<CheatKey>,
) -> Result<Vec<u8>, String> {
    if document.blocks.len() > MAX_BLOCKS {
        return Err(format!(
            "cheat file has {} blocks; the console accepts at most {MAX_BLOCKS}",
            document.blocks.len()
        ));
    }

    let mut blocks: Vec<BlockDesc> = Vec::with_capacity(document.blocks.len());
    let mut insns: Vec<WireInsn> = Vec::new();

    for (index, block) in document.blocks.iter().enumerate() {
        if let Some(issue) = block.on.issues.first() {
            return Err(format!("cheat '{}' cannot be linked: {issue}", block.name));
        }
        let first = insns.len();
        let mut linked = link_block(&block.on, first, &block.name)?;
        let count = linked.len();
        insns.append(&mut linked);
        if insns.len() > MAX_INSNS {
            return Err(format!(
                "cheat program has {} instructions; the console accepts at most {MAX_INSNS}",
                insns.len()
            ));
        }
        blocks.push(BlockDesc {
            index: index as u32,
            mode: match block.mode {
                CheatExecMode::Patch => MODE_PATCH,
                CheatExecMode::Loop => MODE_LOOP,
            },
            first: first as u32,
            count: count as u32,
            enabled: u32::from(enabled.contains(&block.key)),
            reserved: 0,
        });
    }

    let total_bytes = HEADER_BYTES + BLOCK_BYTES * blocks.len() + INSN_BYTES * insns.len();
    if total_bytes > MAX_PROGRAM_BYTES {
        return Err(format!(
            "cheat program is {total_bytes} bytes; the console accepts at most {MAX_PROGRAM_BYTES}"
        ));
    }

    let header = ProgramHeader {
        magic: MAGIC,
        version: VERSION,
        build_id,
        program_id,
        block_count: u16::try_from(blocks.len())
            .map_err(|_| "cheat program has too many blocks for the wire header".to_string())?,
        insn_count: u16::try_from(insns.len()).map_err(|_| {
            "cheat program has too many instructions for the wire header".to_string()
        })?,
        total_bytes: u16::try_from(total_bytes)
            .map_err(|_| "cheat program is too large for the wire header".to_string())?,
        reserved: 0,
    };

    let mut out = Vec::with_capacity(total_bytes);
    out.extend_from_slice(&header.to_bytes());
    for block in &blocks {
        out.extend_from_slice(&block.to_bytes());
    }
    for insn in &insns {
        out.extend_from_slice(&insn.to_bytes());
    }
    debug_assert_eq!(out.len(), total_bytes);
    Ok(out)
}

/// Resolve the control flow of one block and encode its instructions.
///
/// `base` is the program-wide index of the block's first instruction, so the
/// targets written here are already global.
fn link_block(code: &CheatCode, base: usize, name: &str) -> Result<Vec<WireInsn>, String> {
    let count = code.instructions.len();
    let mut local_targets: Vec<Option<usize>> = vec![None; count];
    // (begin index, matching else index)
    let mut conditions: Vec<(usize, Option<usize>)> = Vec::new();
    // (start index, counter register)
    let mut loops: Vec<(usize, u8)> = Vec::new();

    for (index, instruction) in code.instructions.iter().enumerate() {
        match instruction {
            Instruction::BeginConditional { .. }
            | Instruction::KeypressConditional { .. }
            | Instruction::RegisterConditional { .. } => conditions.push((index, None)),
            Instruction::EndConditional { is_else: true } => {
                let Some((_, else_slot)) = conditions.last_mut() else {
                    return Err(format!(
                        "cheat '{name}' instruction {index}: else without a matching conditional"
                    ));
                };
                if else_slot.is_some() {
                    return Err(format!(
                        "cheat '{name}' instruction {index}: conditional has more than one else"
                    ));
                }
                *else_slot = Some(index);
            }
            Instruction::EndConditional { is_else: false } => {
                let Some((begin, else_index)) = conditions.pop() else {
                    return Err(format!(
                        "cheat '{name}' instruction {index}: conditional end without a begin"
                    ));
                };
                let exit = index + 1;
                match else_index {
                    Some(else_index) => {
                        local_targets[else_index] = Some(exit);
                        local_targets[begin] = Some(else_index + 1);
                    }
                    None => local_targets[begin] = Some(exit),
                }
            }
            Instruction::LoopStart { register, .. } => loops.push((index, *register)),
            Instruction::LoopEnd { register } => {
                let Some((start, start_register)) = loops.pop() else {
                    return Err(format!(
                        "cheat '{name}' instruction {index}: loop end without a loop start"
                    ));
                };
                if start_register != *register {
                    return Err(format!(
                        "cheat '{name}' instruction {index}: loop end uses r{register} but the \
                         matching start uses r{start_register}"
                    ));
                }
                local_targets[start] = Some(start + 1);
                local_targets[index] = Some(start);
            }
            _ => {}
        }
    }

    if let Some((index, _)) = conditions.first() {
        return Err(format!(
            "cheat '{name}' instruction {index}: conditional is never closed"
        ));
    }
    if let Some((index, _)) = loops.first() {
        return Err(format!(
            "cheat '{name}' instruction {index}: loop is never closed"
        ));
    }

    // A conditional that runs to the end of the block branches one past the
    // last instruction.  Give that target a real Nop so the console's install
    // check never sees a target outside the instruction array.
    let mut length = count;
    if local_targets.iter().any(|target| *target == Some(count)) {
        length += 1;
    }

    let mut out = Vec::with_capacity(length);
    for (index, instruction) in code.instructions.iter().enumerate() {
        out.push(convert(
            instruction,
            index,
            base,
            local_targets[index],
            name,
        )?);
    }
    if length > count {
        out.push(WireInsn {
            op: OP_NOP,
            ..WireInsn::default()
        });
    }
    Ok(out)
}

/// Encode one model instruction.
fn convert(
    instruction: &Instruction,
    pc: usize,
    base: usize,
    local_target: Option<usize>,
    block: &str,
) -> Result<WireInsn, String> {
    let at = |pc: usize| format!("cheat '{block}' instruction {pc}");
    let resolved = |local: usize| -> Result<u32, String> {
        u32::try_from(base + local)
            .map_err(|_| format!("{}: branch target overflows the instruction index", at(pc)))
    };
    let branch_target = |local_target: Option<usize>| -> Result<u32, String> {
        let local =
            local_target.ok_or_else(|| format!("{}: branch target was not linked", at(pc)))?;
        resolved(local)
    };

    let mut insn = WireInsn::default();
    match instruction {
        Instruction::StoreStatic {
            width,
            region,
            offset_register,
            rel_address,
            value,
        } => {
            insn.op = OP_STORE_STATIC;
            insn.width = *width;
            insn.region = region.bits() as u8;
            insn.reg_b = *offset_register;
            insn.address = address32(*rel_address, &at(pc))?;
            insn.value = *value;
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
            insn.op = OP_BEGIN_CONDITIONAL;
            insn.width = *width;
            insn.region = region.bits() as u8;
            insn.cmp = comparison_code(*comparison);
            insn.reg_b = *offset_register;
            if *include_offset_register {
                insn.flags |= FLAG_OFFSET_REGISTER;
            }
            insn.address = address32(*rel_address, &at(pc))?;
            insn.value = *value;
            insn.target = branch_target(local_target)?;
        }
        Instruction::EndConditional { is_else } => {
            if *is_else {
                insn.op = OP_ELSE;
                insn.target = branch_target(local_target)?;
            } else {
                insn.op = OP_END_CONDITIONAL;
            }
        }
        Instruction::LoopStart { register, count } => {
            insn.op = OP_LOOP_START;
            insn.reg_a = *register;
            insn.value = u64::from(*count);
            insn.target = branch_target(local_target)?;
        }
        Instruction::LoopEnd { register } => {
            insn.op = OP_LOOP_END;
            insn.reg_a = *register;
            insn.target = branch_target(local_target)?;
        }
        Instruction::LoadRegisterImmediate { register, value } => {
            insn.op = OP_LOAD_REG_IMM;
            insn.reg_a = *register;
            insn.value = *value;
        }
        Instruction::LoadRegisterMemory {
            width,
            region,
            register,
            load_from_register,
            offset_register,
            rel_address,
        } => {
            insn.width = *width;
            insn.reg_a = *register;
            insn.address = address32(*rel_address, &at(pc))?;
            match load_from_register {
                0 => {
                    insn.op = OP_LOAD_REG_MEM;
                    insn.region = region.bits() as u8;
                    insn.reg_b = *offset_register;
                }
                1 => insn.op = OP_LOAD_REG_MEM_REG,
                2 => {
                    insn.op = OP_LOAD_REG_MEM_REG_REG;
                    insn.reg_b = *offset_register;
                }
                3 => {
                    insn.op = OP_LOAD_REG_MEM_REG_REGION;
                    insn.region = region.bits() as u8;
                    insn.reg_b = *offset_register;
                }
                other => {
                    return Err(format!(
                        "{}: unsupported load-from-register mode {other}",
                        at(pc)
                    ))
                }
            }
        }
        Instruction::StoreStaticToRegister {
            width,
            register,
            increment,
            add_offset_register,
            offset_register,
            value,
        } => {
            insn.op = OP_STORE_STATIC_TO_REG;
            insn.width = *width;
            insn.reg_a = *register;
            insn.reg_b = *offset_register;
            if *increment {
                insn.flags |= FLAG_INCREMENT;
            }
            if *add_offset_register {
                insn.flags |= FLAG_OFFSET_REGISTER;
            }
            insn.value = *value;
        }
        Instruction::LegacyArithmetic {
            width,
            register,
            operation,
            value,
        } => {
            insn.op = OP_ARITH_IMM;
            insn.width = *width;
            insn.reg_a = *register;
            insn.cmp = arith_code(*operation).ok_or_else(|| {
                format!("{}: arithmetic {operation:?} has no wire encoding", at(pc))
            })?;
            insn.value = u64::from(*value);
        }
        Instruction::KeypressConditional { key_mask } => {
            insn.op = OP_KEYPRESS_CONDITIONAL;
            insn.value = u64::from(*key_mask);
            insn.target = branch_target(local_target)?;
        }
        Instruction::RegisterArithmetic {
            width,
            operation,
            destination_register,
            source_register_1,
            operand,
        } => {
            // The wire arithmetic opcodes are in place (`rA = rA op ...`), so a
            // program that reads one register and writes another cannot be
            // expressed without a move opcode; refuse instead of mis-executing.
            if source_register_1 != destination_register {
                return Err(format!(
                    "{}: register arithmetic r{destination_register} = r{source_register_1} ... \
                     cannot be represented (the wire opcodes are in place)",
                    at(pc)
                ));
            }
            insn.width = *width;
            insn.reg_a = *destination_register;
            insn.cmp = arith_code(*operation).ok_or_else(|| {
                format!("{}: arithmetic {operation:?} has no wire encoding", at(pc))
            })?;
            match operand {
                ArithmeticOperand::Immediate(value) => {
                    insn.op = OP_ARITH_IMM;
                    insn.value = *value;
                }
                ArithmeticOperand::Register(register) => {
                    insn.op = OP_ARITH_REG;
                    insn.reg_b = *register;
                }
            }
        }
        Instruction::StoreRegisterToMemory {
            width,
            source_register,
            address_register,
            increment,
            offset,
        } => {
            insn.op = OP_STORE_REG;
            insn.width = *width;
            insn.reg_a = *address_register;
            insn.reg_b = *source_register;
            if *increment {
                insn.flags |= FLAG_INCREMENT;
            }
            // bits 1..=3: offset form (`StoreOffset::code`)
            insn.flags |= (offset.code() as u8) << 1;
            match offset {
                StoreOffset::None => {}
                StoreOffset::Register(offset_register) => {
                    // bits 4..=7: the offset register
                    insn.flags |= offset_register << 4;
                }
                StoreOffset::Immediate(rel_address) => {
                    insn.address = address32(*rel_address, &at(pc))?;
                }
                StoreOffset::MemoryRegister(region) => {
                    insn.region = region.bits() as u8;
                }
                StoreOffset::MemoryImmediate {
                    region,
                    rel_address,
                } => {
                    insn.region = region.bits() as u8;
                    insn.address = address32(*rel_address, &at(pc))?;
                }
                StoreOffset::MemoryImmediateRegister {
                    region,
                    rel_address,
                } => {
                    insn.region = region.bits() as u8;
                    insn.address = address32(*rel_address, &at(pc))?;
                }
            }
        }
        Instruction::RegisterConditional {
            width,
            comparison,
            value_register,
            operand,
        } => {
            insn.op = OP_REG_CONDITIONAL;
            insn.width = *width;
            insn.cmp = comparison_code(*comparison);
            insn.reg_a = *value_register;
            match operand {
                ConditionalOperand::MemoryRelative {
                    region,
                    rel_address,
                } => {
                    insn.flags = COND_MEMORY_RELATIVE;
                    insn.region = region.bits() as u8;
                    insn.address = address32(*rel_address, &at(pc))?;
                }
                ConditionalOperand::MemoryOffset {
                    region,
                    offset_register,
                } => {
                    insn.flags = COND_MEMORY_OFFSET;
                    insn.region = region.bits() as u8;
                    insn.reg_b = *offset_register;
                }
                ConditionalOperand::RegisterRelative {
                    address_register,
                    rel_address,
                } => {
                    insn.flags = COND_REGISTER_RELATIVE;
                    insn.reg_b = *address_register;
                    insn.address = address32(*rel_address, &at(pc))?;
                }
                ConditionalOperand::RegisterOffset {
                    address_register,
                    offset_register,
                } => {
                    insn.flags = COND_REGISTER_OFFSET;
                    insn.reg_b = *address_register;
                    // `value` is otherwise unused here, so it carries the
                    // second register rather than widening `flags`.
                    insn.value = u64::from(*offset_register);
                }
                ConditionalOperand::Immediate(value) => {
                    insn.flags = COND_IMMEDIATE;
                    insn.value = *value;
                }
                ConditionalOperand::Register(register) => {
                    insn.flags = COND_REGISTER;
                    insn.reg_b = *register;
                }
            }
            insn.target = branch_target(local_target)?;
        }
        Instruction::SaveRestoreRegister { .. } => {
            return Err(format!(
                "{}: single-register save/restore has no wire opcode",
                at(pc)
            ))
        }
        Instruction::SaveRestoreRegisterMask { operation, mask } => match operation {
            SaveRestoreOp::Save => {
                insn.op = OP_SAVE_REGS;
                insn.value = u64::from(*mask);
            }
            SaveRestoreOp::Restore => {
                insn.op = OP_RESTORE_REGS;
                insn.value = u64::from(*mask);
            }
            other => {
                return Err(format!(
                    "{}: save/restore operation {other:?} has no wire opcode",
                    at(pc)
                ))
            }
        },
        Instruction::StaticRegister {
            static_index,
            register,
        } => {
            insn.op = OP_STATIC_REGS;
            insn.reg_a = *register;
            insn.value = u64::from(*static_index);
            if *static_index >= 0x80 {
                insn.flags |= FLAG_STATIC_WRITE;
            }
        }
        Instruction::PauseProcess => insn.op = OP_PAUSE,
        Instruction::ResumeProcess => insn.op = OP_RESUME,
        Instruction::Unsupported { opcode, .. } => {
            return Err(format!("{}: unsupported opcode 0x{opcode:X}", at(pc)))
        }
    }
    Ok(insn)
}

/// The wire format carries 32 bits of relative address.
fn address32(rel_address: u64, at: &str) -> Result<u32, String> {
    u32::try_from(rel_address).map_err(|_| {
        format!(
            "{at}: address 0x{rel_address:X} does not fit the 32-bit wire address \
             (relative addresses above 0xFFFFFFFF cannot be linked)"
        )
    })
}

/// `NxusCheatCmp` numbering (0..=5, `Comparison::bits` uses 1..=6).
fn comparison_code(comparison: Comparison) -> u8 {
    match comparison {
        Comparison::Greater => 0,
        Comparison::GreaterEqual => 1,
        Comparison::Less => 2,
        Comparison::LessEqual => 3,
        Comparison::Equal => 4,
        Comparison::NotEqual => 5,
    }
}

/// `NxusCheatArith` numbering; the wire enum stops at the right shift.
fn arith_code(operation: ArithmeticOp) -> Option<u8> {
    match operation {
        ArithmeticOp::Add => Some(0),
        ArithmeticOp::Sub => Some(1),
        ArithmeticOp::Multiply => Some(2),
        ArithmeticOp::LeftShift => Some(3),
        ArithmeticOp::RightShift => Some(4),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::model::{CheatBlock, CheatKind, ParseIssue};
    use super::*;

    fn build_document(entries: &[(&str, &[&str])]) -> CheatDocument {
        let mut document = CheatDocument::new("9D4C86E6EF74504A");
        for (name, lines) in entries {
            let lines: Vec<String> = lines.iter().map(|line| line.to_string()).collect();
            document.add_cheat(name, &lines, None);
        }
        document
    }

    fn all_blocks(document: &CheatDocument) -> BTreeSet<CheatKey> {
        document.blocks.iter().map(|block| block.key).collect()
    }

    fn program(document: &CheatDocument) -> Vec<u8> {
        build_program(document, 0x0000_0000_9D4C_86E6, 7, &all_blocks(document)).unwrap()
    }

    fn decode(bytes: &[u8]) -> (ProgramHeader, Vec<BlockDesc>, Vec<WireInsn>) {
        let header = ProgramHeader::from_bytes(&bytes[..HEADER_BYTES]).unwrap();
        let mut offset = HEADER_BYTES;
        let mut blocks = Vec::new();
        for _ in 0..header.block_count {
            blocks.push(BlockDesc::from_bytes(&bytes[offset..offset + BLOCK_BYTES]).unwrap());
            offset += BLOCK_BYTES;
        }
        let mut insns = Vec::new();
        for _ in 0..header.insn_count {
            insns.push(WireInsn::from_bytes(&bytes[offset..offset + INSN_BYTES]).unwrap());
            offset += INSN_BYTES;
        }
        assert_eq!(
            offset,
            bytes.len(),
            "the program must be exactly total_bytes long"
        );
        (header, blocks, insns)
    }

    #[test]
    fn header_fields_and_wire_sizes_are_pinned() {
        assert_eq!(HEADER_BYTES, 32);
        assert_eq!(BLOCK_BYTES, 24);
        assert_eq!(INSN_BYTES, 24);
        assert_eq!(MAX_PROGRAM_BYTES, 48 * 1024);
        assert_eq!(MAX_INSNS, 512);
        assert_eq!(MAX_BLOCKS, 128);

        let document = build_document(&[("Money", &["04000000 42CA1DC4 0098967F"])]);
        let bytes = build_program(
            &document,
            0x1122_3344_5566_7788,
            0x99AA_BBCC_DDEE_FF00,
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(bytes.len(), HEADER_BYTES + BLOCK_BYTES + INSN_BYTES);
        // Little endian: 'NCVM' as a big-endian word is 4D 56 43 4E on the wire.
        assert_eq!(&bytes[0..4], &[0x4D, 0x56, 0x43, 0x4E]);

        let header = ProgramHeader::from_bytes(&bytes[..HEADER_BYTES]).unwrap();
        assert_eq!(header.magic, MAGIC);
        assert_eq!(header.magic, 0x4E43_564D);
        assert_eq!(header.version, VERSION);
        assert_eq!(header.version, 1);
        assert_eq!(header.build_id, 0x1122_3344_5566_7788);
        assert_eq!(header.program_id, 0x99AA_BBCC_DDEE_FF00);
        assert_eq!(header.block_count, 1);
        assert_eq!(header.insn_count, 1);
        assert_eq!(header.total_bytes as usize, bytes.len());
        assert_eq!(header.reserved, 0);
    }

    #[test]
    fn store_static_maps_to_one_instruction() {
        let document = build_document(&[("Money", &["04000000 42CA1DC4 0098967F"])]);
        let (header, blocks, insns) = decode(&program(&document));
        assert_eq!(header.block_count, 1);
        assert_eq!(header.insn_count, 1);
        assert_eq!(blocks[0].index, 0);
        assert_eq!(blocks[0].mode, MODE_PATCH);
        assert_eq!(blocks[0].first, 0);
        assert_eq!(blocks[0].count, 1);
        assert_eq!(blocks[0].reserved, 0);

        let insn = insns[0];
        assert_eq!(insn.op, OP_STORE_STATIC);
        assert_eq!(insn.width, 4);
        assert_eq!(insn.region, 0);
        assert_eq!(insn.cmp, 0);
        assert_eq!(insn.reg_a, 0);
        assert_eq!(insn.reg_b, 0);
        assert_eq!(insn.flags, 0);
        assert_eq!(insn.target, 0);
        assert_eq!(insn.address, 0x42CA_1DC4);
        assert_eq!(insn.value, 0x0098_967F);
    }

    #[test]
    fn conditional_links_false_and_else_targets() {
        let document = build_document(&[(
            "If",
            &[
                "14050000 00000010 00000001",
                "04000000 00000020 000000AA",
                "21000000",
                "04000000 00000020 000000BB",
                "20000000",
            ],
        )]);
        let (header, blocks, insns) = decode(&program(&document));
        // Five instructions plus the exit Nop that gives the else a real target.
        assert_eq!(header.insn_count, 6);
        assert_eq!(blocks[0].count, 6);

        let begin = insns[0];
        assert_eq!(begin.op, OP_BEGIN_CONDITIONAL);
        assert_eq!(begin.width, 4);
        assert_eq!(begin.region, 0);
        assert_eq!(begin.cmp, 4); // NxusCheatCmp_Equal
        assert_eq!(begin.address, 0x10);
        assert_eq!(begin.value, 1);
        assert_eq!(begin.flags, 0);
        assert_eq!(begin.target, 3); // first instruction of the else body

        assert_eq!(insns[2].op, OP_ELSE);
        assert_eq!(insns[2].target, 5); // first instruction after the matching end
        assert_eq!(insns[4].op, OP_END_CONDITIONAL);
        assert_eq!(insns[4].target, 0);
        assert_eq!(insns[5].op, OP_NOP);
    }

    #[test]
    fn loop_start_and_loop_end_link_to_each_other() {
        let document = build_document(&[(
            "Loop",
            &["30000000 00000003", "74010000 00000001", "31000000"],
        )]);
        let (header, blocks, insns) = decode(&program(&document));
        assert_eq!(header.insn_count, 3);
        assert_eq!(blocks[0].count, 3);

        assert_eq!(insns[0].op, OP_LOOP_START);
        assert_eq!(insns[0].reg_a, 0);
        assert_eq!(insns[0].value, 3);
        assert_eq!(insns[0].target, 1); // first body instruction

        assert_eq!(insns[2].op, OP_LOOP_END);
        assert_eq!(insns[2].reg_a, 0);
        assert_eq!(insns[2].target, 0); // the matching loop start
    }

    #[test]
    fn keypress_conditional_jumps_past_its_end() {
        let document = build_document(&[(
            "Keys",
            &[
                "80000001",
                "04000000 00000020 000000AA",
                "20000000",
                "04000000 00000024 000000BB",
            ],
        )]);
        let (_, blocks, insns) = decode(&program(&document));
        // A keypad trigger makes the block a loop block.
        assert_eq!(blocks[0].mode, MODE_LOOP);
        assert_eq!(insns[0].op, OP_KEYPRESS_CONDITIONAL);
        assert_eq!(insns[0].value, 1);
        assert_eq!(insns[0].target, 3);
        assert_eq!(insns[2].op, OP_END_CONDITIONAL);
        assert_eq!(insns[3].op, OP_STORE_STATIC);
    }

    #[test]
    fn register_opcodes_keep_their_operands() {
        let document = build_document(&[(
            "Regs",
            &[
                "40010000 00000000 00007000",
                "74010000 00000010",
                "64011100 00000000 0000002A",
            ],
        )]);
        let (_, _, insns) = decode(&program(&document));

        assert_eq!(insns[0].op, OP_LOAD_REG_IMM);
        assert_eq!(insns[0].reg_a, 1);
        assert_eq!(insns[0].value, 0x7000);
        assert_eq!(insns[0].width, 0);

        assert_eq!(insns[1].op, OP_ARITH_IMM);
        assert_eq!(insns[1].width, 4);
        assert_eq!(insns[1].reg_a, 1);
        assert_eq!(insns[1].cmp, 0); // NxusCheatArith_Add
        assert_eq!(insns[1].value, 0x10);

        assert_eq!(insns[2].op, OP_STORE_STATIC_TO_REG);
        assert_eq!(insns[2].width, 4);
        assert_eq!(insns[2].reg_a, 1);
        assert_eq!(insns[2].reg_b, 0);
        assert_eq!(
            insns[2].flags,
            FLAG_INCREMENT | FLAG_OFFSET_REGISTER,
            "the increment and offset-register bits must survive"
        );
        assert_eq!(insns[2].value, 0x2A);
    }

    #[test]
    fn enabled_set_lands_in_block_enabled() {
        let document = build_document(&[
            ("A", &["04000000 00000000 00000001"]),
            ("B", &["04000000 00000004 00000002"]),
        ]);
        let key_b = document.blocks[1].key;
        let enabled: BTreeSet<CheatKey> = [key_b].into_iter().collect();
        let bytes = build_program(&document, 1, 2, &enabled).unwrap();
        let (_, blocks, insns) = decode(&bytes);

        assert_eq!(blocks[0].enabled, 0);
        assert_eq!(blocks[1].enabled, 1);
        assert_eq!(blocks[0].index, 0);
        assert_eq!(blocks[1].index, 1);
        assert_eq!(blocks[0].first, 0);
        assert_eq!(blocks[1].first, 1);
        assert_eq!(insns.len(), 2);
    }

    #[test]
    fn block_modes_come_from_the_document() {
        let document = build_document(&[
            ("Plain", &["04000000 00000000 00000001"]),
            (
                "Keyed",
                &["80000001", "04000000 00000020 000000AA", "20000000"],
            ),
        ]);
        let (header, blocks, _) = decode(&program(&document));
        assert_eq!(blocks[0].mode, MODE_PATCH);
        assert_eq!(blocks[1].mode, MODE_LOOP);
        // The keypress block ends with the conditional, so it carries the Nop.
        assert_eq!(blocks[1].count, 4);
        assert_eq!(header.insn_count, 1 + 4);
    }

    #[test]
    fn branch_targets_are_program_wide() {
        let document = build_document(&[
            ("First", &["04000000 00000000 00000001"]),
            (
                "Second",
                &[
                    "80000001",
                    "04000000 00000020 000000AA",
                    "20000000",
                    "04000000 00000024 000000BB",
                ],
            ),
        ]);
        let (_, blocks, insns) = decode(&program(&document));
        assert_eq!(blocks[1].first, 1);
        assert_eq!(insns[1].op, OP_KEYPRESS_CONDITIONAL);
        assert_eq!(
            insns[1].target, 4,
            "targets count from the first instruction"
        );
        assert_eq!(insns[4].op, OP_STORE_STATIC);
    }

    #[test]
    fn too_many_instructions_is_an_error() {
        let lines: Vec<String> = vec!["04000000 00000000 00000001".to_string(); MAX_INSNS + 1];
        let mut document = CheatDocument::new("LIMIT");
        document.add_cheat("Too Many", &lines, None);

        let error = build_program(&document, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("512"), "{error}");
        assert!(error.contains("instructions"), "{error}");
    }

    #[test]
    fn too_many_blocks_is_an_error() {
        let mut document = CheatDocument::new("LIMIT");
        for index in 0..=MAX_BLOCKS {
            document.add_cheat(
                &format!("Cheat {index}"),
                &["04000000 00000000 00000001".to_string()],
                None,
            );
        }

        let error = build_program(&document, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("128"), "{error}");
        assert!(error.contains("blocks"), "{error}");
    }

    #[test]
    fn unsupported_instructions_are_refused_instead_of_dropped() {
        // A parsed line the PC cannot decode leaves an `Unsupported`
        // instruction behind; the linker must refuse it, not ship a fragment.
        let parsed = build_document(&[("Broken", &["B0000000"])]);
        let error = build_program(&parsed, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.to_lowercase().contains("unsupported"), "{error}");

        // The same must hold for a hand-built block without parse issues.
        let mut document = CheatDocument::new("TEST");
        let mut block = CheatBlock::new(CheatKey(1), "Raw", CheatKind::Regular);
        block.on.instructions.push(Instruction::Unsupported {
            opcode: 0xB,
            words: vec![0x0B00_0000],
        });
        document.blocks.push(block);

        let error = build_program(&document, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("0xB"), "{error}");
    }

    #[test]
    fn blocks_with_parse_issues_are_refused() {
        let mut document = CheatDocument::new("TEST");
        let mut block = CheatBlock::new(CheatKey(1), "Half", CheatKind::Regular);
        block.on.issues.push(ParseIssue::new(3, "undecodable line"));
        document.blocks.push(block);

        let error = build_program(&document, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("Half"), "{error}");
        assert!(error.contains("undecodable line"), "{error}");
    }

    #[test]
    fn save_restore_masks_map_to_the_wire_opcodes() {
        let document = build_document(&[("Saves", &["C2110002", "C2010002"])]);
        let (_, _, insns) = decode(&program(&document));
        assert_eq!(insns[0].op, OP_SAVE_REGS);
        assert_eq!(insns[0].value, 2);
        assert_eq!(insns[1].op, OP_RESTORE_REGS);
        assert_eq!(insns[1].value, 2);
    }

    #[test]
    fn single_register_save_restore_is_refused() {
        let mut document = CheatDocument::new("TEST");
        let mut block = CheatBlock::new(CheatKey(1), "C1", CheatKind::Regular);
        block
            .on
            .instructions
            .push(Instruction::SaveRestoreRegister {
                destination: 1,
                source: 2,
                operation: SaveRestoreOp::Save,
            });
        document.blocks.push(block);

        let error = build_program(&document, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("save/restore"), "{error}");
    }

    #[test]
    fn relative_addresses_wider_than_32_bits_are_refused() {
        let mut document = CheatDocument::new("TEST");
        let mut block = CheatBlock::new(CheatKey(1), "Wide", CheatKind::Regular);
        block.on.instructions.push(Instruction::StoreStatic {
            width: 4,
            region: MemoryRegion::Absolute,
            offset_register: 0,
            rel_address: 0x1_0000_0000,
            value: 1,
        });
        document.blocks.push(block);

        let error = build_program(&document, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("32-bit"), "{error}");
    }

    #[test]
    fn store_register_offset_forms_are_kept_in_flags() {
        let document = build_document(&[(
            "Store",
            &[
                "40010000 00000000 0000002A",
                "40020000 00000000 00007000",
                "A4120000",
                "A4120130",
                "A4120200 00000010",
                "A4120300",
            ],
        )]);
        let (_, _, insns) = decode(&program(&document));

        assert_eq!(insns[2].op, OP_STORE_REG);
        assert_eq!(insns[2].width, 4);
        assert_eq!(insns[2].reg_a, 2); // address register
        assert_eq!(insns[2].reg_b, 1); // source register
        assert_eq!(insns[2].flags, 0);
        assert_eq!(insns[2].address, 0);

        // Offset register r3, form 1.
        assert_eq!(insns[3].flags, (1 << 1) | (3 << 4));
        // Immediate 0x10 captured in `address`, form 2.
        assert_eq!(insns[4].flags, 2 << 1);
        assert_eq!(insns[4].address, 0x10);
        // `[region + rA]`, form 3.
        assert_eq!(insns[5].flags, 3 << 1);
        assert_eq!(insns[5].region, 0);
    }

    #[test]
    fn load_register_memory_modes_map_to_their_opcodes() {
        let document = build_document(&[(
            "Load",
            &[
                "58010000 00000010",
                "54011000 00000000",
                "54022100 00000004",
                "54033100 00000000",
            ],
        )]);
        let (_, _, insns) = decode(&program(&document));

        assert_eq!(insns[0].op, OP_LOAD_REG_MEM);
        assert_eq!(insns[0].reg_a, 1);
        assert_eq!(insns[0].address, 0x10);

        assert_eq!(insns[1].op, OP_LOAD_REG_MEM_REG);
        assert_eq!(insns[1].reg_a, 1);

        assert_eq!(insns[2].op, OP_LOAD_REG_MEM_REG_REG);
        assert_eq!(insns[2].reg_a, 2);
        assert_eq!(insns[2].reg_b, 1);
        assert_eq!(insns[2].address, 4);

        assert_eq!(insns[3].op, OP_LOAD_REG_MEM_REG_REGION);
        assert_eq!(insns[3].reg_a, 3);
        assert_eq!(insns[3].reg_b, 1);
    }

    #[test]
    fn unmatched_control_flow_is_an_error() {
        let mut document = CheatDocument::new("TEST");
        let mut block = CheatBlock::new(CheatKey(1), "Else", CheatKind::Regular);
        block
            .on
            .instructions
            .push(Instruction::EndConditional { is_else: true });
        document.blocks.push(block);

        let error = build_program(&document, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("else"), "{error}");
    }
}
