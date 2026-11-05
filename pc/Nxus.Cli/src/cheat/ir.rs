//! Linked cheat programs for the on-console interpreter.
//!
//! `core/nxus_cheatvm.h` is the contract.  The PC parses an Atmosphere
//! `<BUILDID>.txt` into a [`CheatDocument`]; this module turns that document
//! into the **wire program** the console executes (`nxusCheatInstall`), with
//! every branch target already resolved to an instruction index, so the console
//! never needs an assembler or a linker.
//!
//! ## Layout (little endian, packed - no padding)
//!
//! ```text
//! NxusCheatProgramHeader (40 bytes, one per program)
//!   u32 magic, u32 version, u64 build_id, u64 program_id,
//!   u32 block_count, u32 insn_count, u32 total_bytes, u32 reserved
//! NxusCheatBlockDesc (24 bytes, block_count of them)
//!   u32 index, u32 mode, u32 first, u32 count, u32 enabled, u32 reserved
//! NxusCheatInsn (24 bytes, insn_count of them)
//!   u16 op, u8 width, u8 region, u8 cmp, u8 reg_a, u8 reg_b, u8 flags,
//!   u32 target, u32 address, u64 value
//! ```
//!
//! The blocks and then the instructions follow the header back to back;
//! `total_bytes` covers all three.
//!
//! ## Address contract
//!
//! The header says the PC resolves `region + offset` to the **final absolute
//! address** before uploading and that the console adds no base.
//! [`build_program`] keeps the region-relative address (plus the region) as
//! parsed, which is what the PC-side VM consumes; [`build_program_resolved`]
//! applies [`MemoryRegions`] first and is what an upload has to use.  `address`
//! is 32 bits wide, so an absolute address above `0xFFFF_FFFF` cannot be linked
//! and is an error.
//!
//! ## Instruction mapping
//!
//! `target` is a program-wide instruction index and is `0` for instructions
//! that never branch.  `address` holds the (resolved or relative) address;
//! `value` holds an immediate, a key mask or a register mask.
//!
//! | `Instruction` (model.rs) | `op` | fields |
//! |---|---|---|
//! | `StoreStatic` | 1 | `width`, `region`, `address`, `value`, `reg_b` = offset register, [`FLAG_OFFSET_REGISTER`] |
//! | `BeginConditional` | 2 | `width`, `region`, `cmp`, `address`, `value`, `reg_b`, [`FLAG_OFFSET_REGISTER`], `target` |
//! | `EndConditional { is_else: true }` | 3 | `target` = first instruction after the matching end |
//! | `EndConditional { is_else: false }` | 4 | falls through, `target` = 0 |
//! | `LoopStart` | 5 | `reg_a` = counter, `value` = count, `target` = first body instruction |
//! | `LoopEnd` | 6 | `reg_a` = counter, `target` = the matching `LoopStart` |
//! | `LoadRegisterImmediate` | 7 | `reg_a`, `value` |
//! | `LoadRegisterMemory` mode 0 | 8 | `width`, `region`, `address`, `reg_a` = destination, `reg_b` = unused offset register |
//! | `LoadRegisterMemory` mode 1 | 11 | `width`, `reg_a` = destination (and base), `address` = offset |
//! | `LoadRegisterMemory` mode 2 | 8 | `width`, `region` = absolute, `reg_a` = destination, `reg_b` = base register, [`FLAG_OFFSET_REGISTER`], `address` = offset |
//! | `LoadRegisterMemory` mode 3 | 8 | `width`, `region`, `reg_a` = destination, `reg_b` = base register, [`FLAG_OFFSET_REGISTER`], `address` = offset |
//! | `StoreStaticToRegister` | 9 | `width`, `reg_a`, `value`, `reg_b` = offset register, [`FLAG_OFFSET_REGISTER`] / [`FLAG_INCREMENT`] |
//! | `LegacyArithmetic` | 10 | `width`, `reg_a`, `cmp` = arithmetic, `value` |
//! | `RegisterArithmetic` (immediate, in place) | 10 | `width`, `reg_a`, `cmp` = arithmetic, `value` |
//! | `RegisterArithmetic` (register, in place) | 14 | `width`, `reg_a`, `cmp` = arithmetic, `reg_b` = operand |
//! | `StoreRegisterToMemory` (no offset, no increment) | 15 | `width`, `reg_a` = address register, `reg_b` = source register |
//! | `RegisterConditional` (immediate) | 16 | `width`, `cmp`, `reg_a` = value register, `value` = immediate, `target` |
//! | `RegisterConditional` (register) | 16 | `width`, `cmp`, `reg_a`, `reg_b` = operand register, [`FLAG_REGISTER_OPERAND`], `target` |
//! | `SaveRestoreRegisterMask` (save / restore) | 17, 18 | `value` = mask |
//! | `PauseProcess` / `ResumeProcess` | 20, 21 | — |
//! | `KeypressConditional` | 22 | `value` = key mask, `target` = false branch |
//!
//! ## What cannot be linked (an error, never a silent drop)
//!
//! * `Unsupported` opcodes and blocks whose ON code has parse issues.
//! * `SaveRestoreRegister` (`0xC1`) and the "clear" mask operations: the wire
//!   only has mask save/restore.
//! * `StaticRegister` (`0xC3`): the wire opcode is reserved and executes as a
//!   `Nop`, so linking it would silently drop the transfer.
//! * `StoreRegisterToMemory` with an offset or an increment: wire `StoreReg` is
//!   only `[rA] = rB`.
//! * `RegisterConditional` with a memory operand: wire `RegConditional`
//!   compares a register with an immediate or another register.
//! * Register arithmetic whose destination differs from its first source, and
//!   arithmetic other than `+ - * << >>`: the wire opcodes are in place and the
//!   arithmetic enum stops at the right shift.
//! * Addresses that do not fit 32 bits, and any program over
//!   [`MAX_PROGRAM_BYTES`] / [`MAX_INSNS`] / [`MAX_BLOCKS`].
//!
//! A conditional whose false (or else) branch leaves the block at its very end
//! would point one past the last instruction, which `nxusCheatInstall` rejects
//! (`-4`).  Such a block gets a trailing [`OP_NOP`] so every target names an
//! instruction inside the block; the interpreter stops at the end either way.
//!
//! The OFF half of a block is deliberately not part of the program: the console
//! journals the original bytes and restores them when a block is disabled.

use std::collections::BTreeSet;

use super::model::{
    ArithmeticOp, ArithmeticOperand, CheatCode, CheatDocument, CheatExecMode, CheatKey, Comparison,
    ConditionalOperand, Instruction, MemoryRegion, SaveRestoreOp, StoreOffset,
};
use super::vm::MemoryRegions;

// ---------------------------------------------------------------------------
// Limits and format constants (mirror of `core/nxus_cheatvm.h`)
// ---------------------------------------------------------------------------

/// `NXUS_CHEATVM_MAGIC` - the bytes `N C V M` read as a big-endian word.
pub const MAGIC: u32 = 0x4E43_564D;
/// `NXUS_CHEATVM_VERSION`.
pub const VERSION: u32 = 1;

/// Bytes of `NxusCheatProgramHeader`.
pub const HEADER_BYTES: usize = 40;
/// Bytes of `NxusCheatBlockDesc`.
pub const BLOCK_BYTES: usize = 24;
/// Bytes of `NxusCheatInsn`.
pub const INSN_BYTES: usize = 24;

/// `NXUS_CHEATVM_MAX_PROGRAM_BYTES`: header + blocks + instructions.
pub const MAX_PROGRAM_BYTES: usize = 64 * 1024;
/// `NXUS_CHEATVM_MAX_INSNS`.
pub const MAX_INSNS: usize = 2048;
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

/// `flags` bit for `OP_STORE_STATIC`/`OP_BEGIN_CONDITIONAL`/`OP_LOAD_REG_MEM`:
/// `reg_b` is added to the region-relative address.  Also bit 0 of
/// `OP_STORE_STATIC_TO_REG` (the `nxus_cheatvm.c` convention).
pub const FLAG_OFFSET_REGISTER: u8 = 1 << 0;
/// `flags` bit for `OP_STORE_STATIC_TO_REG`: advance the address register by
/// `width` after the store (Atmosphere 0x6 `I` bit).
pub const FLAG_INCREMENT: u8 = 1 << 1;
/// `flags` bit for `OP_REG_CONDITIONAL`: compare with `reg_b` instead of the
/// immediate `value`.
pub const FLAG_REGISTER_OPERAND: u8 = 1 << 0;

// ---------------------------------------------------------------------------
// Wire structures
// ---------------------------------------------------------------------------

/// `NxusCheatProgramHeader` - 40 bytes, packed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProgramHeader {
    pub magic: u32,
    pub version: u32,
    pub build_id: u64,
    pub program_id: u64,
    pub block_count: u32,
    pub insn_count: u32,
    /// Header + blocks + instructions.
    pub total_bytes: u32,
    pub reserved: u32,
}

impl ProgramHeader {
    pub fn to_bytes(self) -> [u8; HEADER_BYTES] {
        let mut out = [0u8; HEADER_BYTES];
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4..8].copy_from_slice(&self.version.to_le_bytes());
        out[8..16].copy_from_slice(&self.build_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.program_id.to_le_bytes());
        out[24..28].copy_from_slice(&self.block_count.to_le_bytes());
        out[28..32].copy_from_slice(&self.insn_count.to_le_bytes());
        out[32..36].copy_from_slice(&self.total_bytes.to_le_bytes());
        out[36..40].copy_from_slice(&self.reserved.to_le_bytes());
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
            block_count: read_u32(bytes, 24),
            insn_count: read_u32(bytes, 28),
            total_bytes: read_u32(bytes, 32),
            reserved: read_u32(bytes, 36),
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
    /// Address (32 bits), or an immediate.
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

/// Link `document` into one console program, keeping region-relative addresses.
///
/// Every block of the document becomes one [`BlockDesc`] (in document order)
/// carrying the ON instructions of that block.  `enabled` is the set of cheat
/// keys the caller wants enabled at upload time; it lands in
/// `BlockDesc::enabled`.
///
/// The addresses stay relative to `region`.  The console's interpreter adds no
/// region base (see the header's address contract), so an upload normally wants
/// [`build_program_resolved`] instead.
///
/// A block whose ON code has parse issues is refused: shipping a partial block
/// would execute something the user never wrote.
pub fn build_program(
    document: &CheatDocument,
    build_id: u64,
    program_id: u64,
    enabled: &BTreeSet<CheatKey>,
) -> Result<Vec<u8>, String> {
    build(document, build_id, program_id, enabled, None)
}

/// Link `document` into one console program with every address resolved.
///
/// `regions` are the target's main/heap/alias/aslr bases (the same values the
/// PC-side VM uses).  Each region-relative address becomes the final absolute
/// address the console executes against, exactly as the header's address
/// contract requires.  [`MemoryRegion::Absolute`] addresses are left alone.
pub fn build_program_resolved(
    document: &CheatDocument,
    build_id: u64,
    program_id: u64,
    enabled: &BTreeSet<CheatKey>,
    regions: &MemoryRegions,
) -> Result<Vec<u8>, String> {
    build(document, build_id, program_id, enabled, Some(regions))
}

fn build(
    document: &CheatDocument,
    build_id: u64,
    program_id: u64,
    enabled: &BTreeSet<CheatKey>,
    regions: Option<&MemoryRegions>,
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
        let mut linked = link_block(&block.on, first, &block.name, regions)?;
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
        block_count: blocks.len() as u32,
        insn_count: insns.len() as u32,
        total_bytes: total_bytes as u32,
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
fn link_block(
    code: &CheatCode,
    base: usize,
    name: &str,
    regions: Option<&MemoryRegions>,
) -> Result<Vec<WireInsn>, String> {
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
    // last instruction.  `nxusCheatInstall` rejects such a target, so give it a
    // real Nop and let the interpreter stop after it.
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
            regions,
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
    regions: Option<&MemoryRegions>,
) -> Result<WireInsn, String> {
    let at = |pc: usize| format!("cheat '{block}' instruction {pc}");
    let branch_target = |local_target: Option<usize>| -> Result<u32, String> {
        let local =
            local_target.ok_or_else(|| format!("{}: branch target was not linked", at(pc)))?;
        u32::try_from(base + local)
            .map_err(|_| format!("{}: branch target overflows the instruction index", at(pc)))
    };
    let address = |rel_address: u64, region: MemoryRegion| {
        wire_address(rel_address, region, regions, &at(pc))
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
            // Atmosphere 0x0 - and the PC VM - always add the offset register,
            // so the flag is always set (for the usual r0 this is a zero add).
            insn.op = OP_STORE_STATIC;
            insn.width = *width;
            insn.region = region.bits() as u8;
            insn.reg_b = *offset_register;
            insn.flags |= FLAG_OFFSET_REGISTER;
            insn.address = address(*rel_address, *region)?;
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
            insn.address = address(*rel_address, *region)?;
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
            match load_from_register {
                // `[region + address]`; Atmosphere mode 0 ignores the offset
                // register, so it is kept for the record but not added.
                0 => {
                    insn.op = OP_LOAD_REG_MEM;
                    insn.region = region.bits() as u8;
                    insn.reg_b = *offset_register;
                    insn.address = address(*rel_address, *region)?;
                }
                // `[rA + address]`.
                1 => {
                    insn.op = OP_LOAD_REG_MEM_REG;
                    insn.address = raw_address(*rel_address, &at(pc))?;
                }
                // `[rS + address]`: the wire `[region + address + rB]` form is
                // the exact shape (`region = absolute` adds no base), while
                // op 12's `[rA + rB]` would also add the destination register.
                2 => {
                    insn.op = OP_LOAD_REG_MEM;
                    insn.region = MemoryRegion::Absolute.bits() as u8;
                    insn.reg_b = *offset_register;
                    insn.flags |= FLAG_OFFSET_REGISTER;
                    insn.address = address(*rel_address, MemoryRegion::Absolute)?;
                }
                // `[region + rS + address]`, same decomposition.
                3 => {
                    insn.op = OP_LOAD_REG_MEM;
                    insn.region = region.bits() as u8;
                    insn.reg_b = *offset_register;
                    insn.flags |= FLAG_OFFSET_REGISTER;
                    insn.address = address(*rel_address, *region)?;
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
            if *add_offset_register {
                insn.flags |= FLAG_OFFSET_REGISTER;
            }
            if *increment {
                insn.flags |= FLAG_INCREMENT;
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
            // Wire `StoreReg` is only `[rA] = rB`; neither an offset nor an
            // increment has a field, so refuse rather than write the wrong
            // address or leave the register unadvanced.
            if *increment {
                return Err(format!(
                    "{}: StoreRegisterToMemory with an increment cannot be linked (the wire \
                     StoreReg has no increment form)",
                    at(pc)
                ));
            }
            if !matches!(offset, StoreOffset::None) {
                return Err(format!(
                    "{}: StoreRegisterToMemory offset form {} cannot be linked (the wire StoreReg \
                     only writes [rA])",
                    at(pc),
                    offset.code()
                ));
            }
            insn.op = OP_STORE_REG;
            insn.width = *width;
            insn.reg_a = *address_register;
            insn.reg_b = *source_register;
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
                // The wire instruction compares a register with an immediate
                // or another register; a memory operand has no field.
                ConditionalOperand::Immediate(value) => {
                    insn.value = *value;
                }
                ConditionalOperand::Register(register) => {
                    insn.flags |= FLAG_REGISTER_OPERAND;
                    insn.reg_b = *register;
                }
                other => {
                    return Err(format!(
                        "{}: register conditional against {other:?} cannot be linked (the wire \
                         RegConditional compares an immediate or a register)",
                        at(pc)
                    ))
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
        Instruction::StaticRegister { .. } => {
            // NxusCheatOp_StaticRegs is reserved and the interpreter treats it
            // as a Nop; linking would silently drop the transfer.
            return Err(format!(
                "{}: static-register opcode is reserved on the console and cannot be linked",
                at(pc)
            ));
        }
        Instruction::PauseProcess => insn.op = OP_PAUSE,
        Instruction::ResumeProcess => insn.op = OP_RESUME,
        Instruction::Unsupported { opcode, .. } => {
            return Err(format!("{}: unsupported opcode 0x{opcode:X}", at(pc)))
        }
    }
    Ok(insn)
}

/// The wire address: 32 bits, with the region base applied when a resolver is
/// given (the header's address contract).
fn wire_address(
    rel_address: u64,
    region: MemoryRegion,
    regions: Option<&MemoryRegions>,
    at: &str,
) -> Result<u32, String> {
    let absolute = match regions {
        Some(regions) => regions.resolve(region, rel_address),
        None => rel_address,
    };
    u32::try_from(absolute).map_err(|_| {
        format!(
            "{at}: address 0x{absolute:X} does not fit the 32-bit wire address \
             (absolute addresses above 0xFFFFFFFF cannot be linked)"
        )
    })
}

/// A plain 32-bit offset that is added to a register at run time and never
/// carries a region base.
fn raw_address(rel_address: u64, at: &str) -> Result<u32, String> {
    u32::try_from(rel_address)
        .map_err(|_| format!("{at}: offset 0x{rel_address:X} does not fit the 32-bit wire address"))
}

/// `NxusCheatCmp` numbering (0..=5; `Comparison::bits` uses 1..=6).
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

    /// The checks `nxusCheatInstall` makes, applied to a decoded program.
    fn assert_installable(header: &ProgramHeader, blocks: &[BlockDesc], insns: &[WireInsn]) {
        assert_eq!(
            header.total_bytes as usize,
            HEADER_BYTES + BLOCK_BYTES * blocks.len() + INSN_BYTES * insns.len()
        );
        let total = header.insn_count as usize;
        assert_eq!(total, insns.len());
        for block in blocks {
            assert!(block.mode <= MODE_LOOP);
            let first = block.first as usize;
            let count = block.count as usize;
            assert!(count <= total && first <= total - count);
            for insn in &insns[first..first + count] {
                assert!(insn.op <= OP_KEYPRESS_CONDITIONAL);
                assert!(matches!(insn.width, 0 | 1 | 2 | 4 | 8));
                assert!(insn.region <= MemoryRegion::Absolute.bits() as u8);
                if matches!(
                    insn.op,
                    OP_BEGIN_CONDITIONAL
                        | OP_ELSE
                        | OP_LOOP_END
                        | OP_REG_CONDITIONAL
                        | OP_KEYPRESS_CONDITIONAL
                ) {
                    // nxusCheatInstall rejects a target outside the block.
                    assert!(
                        (insn.target as usize) >= first && (insn.target as usize) < first + count,
                        "target outside its block: {insn:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn header_fields_and_wire_sizes_are_pinned() {
        assert_eq!(HEADER_BYTES, 40);
        assert_eq!(BLOCK_BYTES, 24);
        assert_eq!(INSN_BYTES, 24);
        assert_eq!(MAX_PROGRAM_BYTES, 64 * 1024);
        assert_eq!(MAX_INSNS, 2048);
        assert_eq!(MAX_BLOCKS, 128);
        assert_eq!(MAGIC, 0x4E43_564D);
        assert_eq!(VERSION, 1);

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
        assert_eq!(header.version, VERSION);
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
        // Atmosphere 0x0 always adds the offset register; r0 adds nothing.
        assert_eq!(insn.flags, FLAG_OFFSET_REGISTER);
        assert_eq!(insn.target, 0);
        assert_eq!(insn.address, 0x42CA_1DC4);
        assert_eq!(insn.value, 0x0098_967F);
        assert_installable(&header, &blocks, &insns);
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
        // Five instructions plus the exit Nop that gives the branch a target
        // inside the block.
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
        assert_installable(&header, &blocks, &insns);
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
        assert_installable(&header, &blocks, &insns);
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
        let (header, blocks, insns) = decode(&program(&document));
        // A keypad trigger makes the block a loop block.
        assert_eq!(blocks[0].mode, MODE_LOOP);
        assert_eq!(insns[0].op, OP_KEYPRESS_CONDITIONAL);
        assert_eq!(insns[0].value, 1);
        assert_eq!(insns[0].target, 3);
        assert_eq!(insns[2].op, OP_END_CONDITIONAL);
        assert_eq!(insns[3].op, OP_STORE_STATIC);
        assert_installable(&header, &blocks, &insns);
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
        let (header, blocks, insns) = decode(&program(&document));

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
        // The C interpreter reads bit 0 as "add rB" and bit 1 as "increment".
        assert_eq!(
            insns[2].flags,
            FLAG_OFFSET_REGISTER | FLAG_INCREMENT,
            "the offset-register and increment bits must survive"
        );
        assert_eq!(insns[2].value, 0x2A);
        assert_installable(&header, &blocks, &insns);
    }

    #[test]
    fn store_static_to_register_flag_bits_are_distinct() {
        // 64010000 = width 4, r1, no offset register, no increment.
        let plain = build_document(&[("Plain", &["64010000 00000000 00000001"])]);
        let (_, _, insns) = decode(&program(&plain));
        assert_eq!(insns[0].op, OP_STORE_STATIC_TO_REG);
        assert_eq!(insns[0].flags, 0);

        // 64010100 = offset register r0 added.
        let offset = build_document(&[("Offset", &["64010100 00000000 00000001"])]);
        let (_, _, insns) = decode(&program(&offset));
        assert_eq!(insns[0].flags, FLAG_OFFSET_REGISTER);

        // 64011000 = increment after the store.
        let increment = build_document(&[("Increment", &["64011000 00000000 00000001"])]);
        let (_, _, insns) = decode(&program(&increment));
        assert_eq!(insns[0].flags, FLAG_INCREMENT);
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
        let (header, blocks, insns) = decode(&program(&document));
        assert_eq!(blocks[0].mode, MODE_PATCH);
        assert_eq!(blocks[1].mode, MODE_LOOP);
        // The keypress block ends with the conditional, so it carries the Nop.
        assert_eq!(blocks[1].count, 4);
        assert_eq!(header.insn_count, 1 + 4);
        assert_installable(&header, &blocks, &insns);
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
        // The parser stops at the Atmosphere-compatible 0x400-opcode limit long before
        // the console's 2048-instruction ceiling, so this exercises the first gate that
        // fires.  The console-side ceiling is enforced by `nxusCheatInstall` as well.
        let lines: Vec<String> = vec!["04000000 00000000 00000001".to_string(); MAX_INSNS + 1];
        let mut document = CheatDocument::new("LIMIT");
        document.add_cheat("Too Many", &lines, None);

        let error = build_program(&document, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("opcode limit") || error.contains("instructions"), "{error}");
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

        // The same holds for a hand-built block without parse issues.
        let mut document = CheatDocument::new("TEST");
        let mut block = CheatBlock::new(CheatKey(1), "Raw", CheatKind::Regular);
        block.on.instructions.push(Instruction::Unsupported {
            opcode: 0xB,
            words: vec![0xB000_0000],
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
    fn unrepresentable_instructions_are_refused() {
        // Single-register save/restore (0xC1).
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

        // The reserved static-register opcode (0xC3).
        let mut document = CheatDocument::new("TEST");
        let mut block = CheatBlock::new(CheatKey(1), "C3", CheatKind::Regular);
        block.on.instructions.push(Instruction::StaticRegister {
            static_index: 0x05,
            register: 2,
        });
        document.blocks.push(block);
        let error = build_program(&document, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("static-register"), "{error}");
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
    fn store_register_without_offset_maps_to_store_reg() {
        let document = build_document(&[(
            "Store",
            &[
                "40010000 00000000 0000002A",
                "40020000 00000000 00007000",
                "A4120000",
            ],
        )]);
        let (header, blocks, insns) = decode(&program(&document));
        assert_eq!(insns[2].op, OP_STORE_REG);
        assert_eq!(insns[2].width, 4);
        assert_eq!(insns[2].reg_a, 2); // address register
        assert_eq!(insns[2].reg_b, 1); // source register
        assert_eq!(insns[2].flags, 0);
        assert_installable(&header, &blocks, &insns);
    }

    #[test]
    fn store_register_offsets_and_increments_are_refused() {
        // A4120130: offset register r3.
        let offset = build_document(&[("Offset", &["A4120130"])]);
        let error = build_program(&offset, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("offset"), "{error}");

        // A4121000: increment after the store.
        let increment = build_document(&[("Increment", &["A4121000"])]);
        let error = build_program(&increment, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("increment"), "{error}");
    }

    #[test]
    fn load_register_memory_modes_use_the_matching_wire_forms() {
        let document = build_document(&[(
            "Load",
            &[
                "58010000 00000010",
                "54011000 00000000",
                "54022100 00000004",
                "54033100 00000000",
            ],
        )]);
        let (header, blocks, insns) = decode(&program(&document));

        // Mode 0: [region + address], the offset register is not added.
        assert_eq!(insns[0].op, OP_LOAD_REG_MEM);
        assert_eq!(insns[0].region, 0);
        assert_eq!(insns[0].reg_a, 1);
        assert_eq!(insns[0].reg_b, 0);
        assert_eq!(insns[0].flags, 0);
        assert_eq!(insns[0].address, 0x10);

        // Mode 1: [rA + address].
        assert_eq!(insns[1].op, OP_LOAD_REG_MEM_REG);
        assert_eq!(insns[1].reg_a, 1);
        assert_eq!(insns[1].address, 0);

        // Mode 2: [rB + address] - expressed as the wire's offset-register form.
        assert_eq!(insns[2].op, OP_LOAD_REG_MEM);
        assert_eq!(insns[2].region, MemoryRegion::Absolute.bits() as u8);
        assert_eq!(insns[2].reg_a, 2);
        assert_eq!(insns[2].reg_b, 1);
        assert_eq!(insns[2].flags, FLAG_OFFSET_REGISTER);
        assert_eq!(insns[2].address, 4);

        // Mode 3: [region + rB + address].
        assert_eq!(insns[3].op, OP_LOAD_REG_MEM);
        assert_eq!(insns[3].region, 0);
        assert_eq!(insns[3].reg_a, 3);
        assert_eq!(insns[3].reg_b, 1);
        assert_eq!(insns[3].flags, FLAG_OFFSET_REGISTER);
        assert_installable(&header, &blocks, &insns);
    }

    #[test]
    fn register_conditional_immediate_and_register_forms() {
        // C0451400 00000005: if r1 == 5 (immediate form)
        let immediate = build_document(&[(
            "Imm",
            &[
                "40010000 00000000 00000005",
                "C0451400 00000005",
                "20000000",
            ],
        )]);
        let (header, blocks, insns) = decode(&program(&immediate));
        assert_eq!(insns[1].op, OP_REG_CONDITIONAL);
        assert_eq!(insns[1].cmp, 4); // Equal
        assert_eq!(insns[1].reg_a, 1);
        assert_eq!(insns[1].flags, 0);
        assert_eq!(insns[1].value, 5);
        assert_eq!(insns[1].target, 3); // the exit Nop after the end
        assert_eq!(insns[3].op, OP_NOP);
        assert_installable(&header, &blocks, &insns);

        // C0451520: if r1 == r2 (register form)
        let register = build_document(&[("Reg", &["C0451520", "20000000"])]);
        let (_, _, insns) = decode(&program(&register));
        assert_eq!(insns[0].op, OP_REG_CONDITIONAL);
        assert_eq!(insns[0].flags, FLAG_REGISTER_OPERAND);
        assert_eq!(insns[0].reg_b, 2);
    }

    #[test]
    fn register_conditional_with_a_memory_operand_is_refused() {
        // C0420000 00000010: compare r1 with [main + 0x10].
        let document = build_document(&[("Mem", &["C0420000 00000010", "20000000"])]);
        let error = build_program(&document, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("RegConditional"), "{error}");
    }

    #[test]
    fn three_operand_register_arithmetic_is_refused() {
        // 94021100: r2 = r1 + 0x0F (the wire opcode is in place).
        let document = build_document(&[("Three", &["94021100 0000000F"])]);
        let error = build_program(&document, 0, 0, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("in place"), "{error}");
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

    #[test]
    fn resolved_build_applies_region_bases_to_absolute_addresses() {
        let document = build_document(&[(
            "Regions",
            &[
                "04000000 00000010 0000002A", // main + 0x10
                "04400000 00001000 0000002B", // absolute 0x1000
                "14050000 00000020 00000001", // condition on main + 0x20
                "04000000 00000030 000000AA",
                "20000000",
            ],
        )]);
        let regions = MemoryRegions::new(0x8000_0000, 0x1000, 0x2000, 0x3000);
        let bytes =
            build_program_resolved(&document, 1, 2, &all_blocks(&document), &regions).unwrap();
        let (header, blocks, insns) = decode(&bytes);
        assert_installable(&header, &blocks, &insns);

        assert_eq!(insns[0].region, MemoryRegion::Main.bits() as u8);
        assert_eq!(insns[0].address, 0x8000_0010, "main base is folded in");
        assert_eq!(insns[1].region, MemoryRegion::Absolute.bits() as u8);
        assert_eq!(
            insns[1].address, 0x1000,
            "absolute addresses stay as they are"
        );
        assert_eq!(insns[2].address, 0x8000_0020);
    }

    #[test]
    fn resolved_build_leaves_register_relative_offsets_alone() {
        // 540F1000: rA = [rA + 0] - a register offset, never a region base.
        let document = build_document(&[("Reg", &["540F1000 00000024"])]);
        let regions = MemoryRegions::new(0x8000_0000, 0x1000, 0x2000, 0x3000);
        let bytes =
            build_program_resolved(&document, 1, 2, &all_blocks(&document), &regions).unwrap();
        let (_, _, insns) = decode(&bytes);
        assert_eq!(insns[0].op, OP_LOAD_REG_MEM_REG);
        assert_eq!(insns[0].address, 0x24);
    }
}
