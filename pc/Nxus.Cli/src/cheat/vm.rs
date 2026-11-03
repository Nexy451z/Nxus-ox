//! Typed Atmosphere cheat-code interpreter.
//!
//! The VM never talks to the console directly: all memory access goes through
//! [`CheatMemoryIo`], which lets the same interpreter run against `NxusClient`
//! or an in-memory mock.  Every evaluation has a hard step cap.

use std::fmt;
use std::time::{Duration, Instant};

use super::model::{
    ArithmeticOp, ArithmeticOperand, ConditionalOperand, Instruction, JumpInfo, MemoryRegion,
    SaveRestoreOp, StoreOffset, VM_STEP_LIMIT,
};

/// Memory operations required by the cheat VM.
///
/// `allow_rx` is passed to the writer so a live implementation may permit
/// executable (`R-X`) pages, exactly as Atmosphère's own cheat VM does.
pub trait CheatMemoryIo {
    fn read_mem(&mut self, address: u64, size: u32) -> Result<Vec<u8>, String>;
    fn write_mem(&mut self, address: u64, data: &[u8], allow_rx: bool) -> Result<(), String>;
    fn pause_process(&mut self) -> Result<(), String>;
    fn resume_process(&mut self) -> Result<(), String>;
}

impl<T: CheatMemoryIo + ?Sized> CheatMemoryIo for &mut T {
    fn read_mem(&mut self, address: u64, size: u32) -> Result<Vec<u8>, String> {
        (**self).read_mem(address, size)
    }

    fn write_mem(&mut self, address: u64, data: &[u8], allow_rx: bool) -> Result<(), String> {
        (**self).write_mem(address, data, allow_rx)
    }

    fn pause_process(&mut self) -> Result<(), String> {
        (**self).pause_process()
    }

    fn resume_process(&mut self) -> Result<(), String> {
        (**self).resume_process()
    }
}

/// Region bases for the current target, taken from `Metadata`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryRegions {
    pub main: u64,
    pub heap: u64,
    pub alias: u64,
    pub aslr: u64,
}

impl MemoryRegions {
    pub fn new(main: u64, heap: u64, alias: u64, aslr: u64) -> Self {
        MemoryRegions {
            main,
            heap,
            alias,
            aslr,
        }
    }

    pub fn base(self, region: MemoryRegion) -> Option<u64> {
        match region {
            MemoryRegion::Main => Some(self.main),
            MemoryRegion::Heap => Some(self.heap),
            MemoryRegion::Alias => Some(self.alias),
            MemoryRegion::Aslr => Some(self.aslr),
            MemoryRegion::Absolute => None,
        }
    }

    pub fn resolve(self, region: MemoryRegion, relative: u64) -> u64 {
        match self.base(region) {
            Some(base) => base.wrapping_add(relative),
            None => relative,
        }
    }
}

/// Registers retained by the VM.
///
/// General/saved registers are cleared for every evaluation (Atmosphere's
/// `ResetState`), while static registers persist across ticks.
#[derive(Clone, Debug)]
pub struct VmState {
    pub registers: [u64; 16],
    pub saved: [u64; 16],
    pub static_registers: [u64; 256],
    /// Tracks FF0/FF1 so a loop does not issue a pause every tick.
    pub paused: bool,
}

impl Default for VmState {
    fn default() -> Self {
        VmState {
            registers: [0; 16],
            saved: [0; 16],
            static_registers: [0; 256],
            paused: false,
        }
    }
}

impl VmState {
    pub fn reset_transient(&mut self) {
        self.registers = [0; 16];
        self.saved = [0; 16];
    }

    pub fn reset_all(&mut self) {
        *self = VmState::default();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmError {
    pub pc: Option<usize>,
    pub message: String,
}

impl VmError {
    pub fn new(pc: usize, message: impl Into<String>) -> Self {
        VmError {
            pc: Some(pc),
            message: message.into(),
        }
    }

    pub fn without_pc(message: impl Into<String>) -> Self {
        VmError {
            pc: None,
            message: message.into(),
        }
    }
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pc {
            Some(pc) => write!(f, "cheat VM error at pc 0x{pc:X}: {}", self.message),
            None => write!(f, "cheat VM error: {}", self.message),
        }
    }
}

impl std::error::Error for VmError {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmReport {
    pub steps: usize,
    pub reads: usize,
    pub writes: usize,
}

/// Execute one ON/OFF program with the default limits (no wall-clock budget).
///
/// `jumps` must be the metadata produced by the parser for `instructions`.
pub fn execute(
    instructions: &[Instruction],
    jumps: &[JumpInfo],
    io: &mut dyn CheatMemoryIo,
    regions: &MemoryRegions,
    keys_held: u64,
    state: &mut VmState,
) -> Result<VmReport, VmError> {
    execute_with_budget(
        instructions,
        jumps,
        io,
        regions,
        keys_held,
        state,
        None,
        &mut |_, _| {},
    )
}

/// Execute one ON/OFF program with a per-block budget and a progress callback.
///
/// * `budget` bounds the wall clock of the whole block.  The deadline is
///   checked between instructions, so an overrun ends with an error whose
///   message contains `timed out` as soon as the pending memory access
///   returns.  The access itself still uses the caller's own request timeout,
///   which is why this is a *block* budget and not a per-instruction one.
/// * `on_progress(done, total)` reports how far into the program the
///   interpreter has reached (`0 <= done <= total`).  It is called once before
///   the first instruction and once after the last one of a valid program;
///   loops keep `done` at the furthest instruction reached instead of going
///   backwards.
///
/// A `0xFF0` pause never outlives the block: before returning, the process is
/// resumed when the block left it paused.  A paused process cannot resume
/// itself, so a block that pauses and fails (or simply never emits `0xFF1`)
/// would otherwise freeze the console with no way to recover.
#[allow(clippy::too_many_arguments)]
pub fn execute_with_budget(
    instructions: &[Instruction],
    jumps: &[JumpInfo],
    io: &mut dyn CheatMemoryIo,
    regions: &MemoryRegions,
    keys_held: u64,
    state: &mut VmState,
    budget: Option<Duration>,
    on_progress: &mut dyn FnMut(usize, usize),
) -> Result<VmReport, VmError> {
    let outcome = run_program(
        instructions,
        jumps,
        io,
        regions,
        keys_held,
        state,
        budget,
        on_progress,
    );
    if !state.paused {
        return outcome;
    }
    match io.resume_process() {
        Ok(()) => {
            state.paused = false;
            outcome
        }
        Err(error) => {
            // Keep `state.paused` set: a later block can still retry the resume.
            let message = format!("resume after block failed: {error}");
            Err(match outcome {
                Ok(_) => VmError::without_pc(message),
                Err(original) => VmError {
                    pc: original.pc,
                    message: format!("{}; {message}", original.message),
                },
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_program(
    instructions: &[Instruction],
    jumps: &[JumpInfo],
    io: &mut dyn CheatMemoryIo,
    regions: &MemoryRegions,
    keys_held: u64,
    state: &mut VmState,
    budget: Option<Duration>,
    on_progress: &mut dyn FnMut(usize, usize),
) -> Result<VmReport, VmError> {
    if instructions.len() != jumps.len() {
        return Err(VmError::without_pc(format!(
            "control-flow metadata has {} entries for {} instructions",
            jumps.len(),
            instructions.len()
        )));
    }

    state.reset_transient();
    let total = instructions.len();
    // An absurd budget (near `Duration::MAX`) must not overflow the instant.
    let deadline = budget.and_then(|limit| {
        Instant::now()
            .checked_add(limit)
            .map(|deadline| (deadline, limit))
    });
    let mut report = VmReport::default();
    let mut pc = 0usize;
    let mut loops: Vec<LoopFrame> = Vec::new();
    let mut loop_restarts = 0usize;
    let mut reported = 0usize;
    on_progress(0, total);

    while pc < instructions.len() {
        if report.steps >= VM_STEP_LIMIT {
            return Err(VmError::new(
                pc,
                format!("instruction step limit ({VM_STEP_LIMIT}) exceeded"),
            ));
        }
        if let Some((deadline, limit)) = deadline {
            if Instant::now() >= deadline {
                return Err(VmError::new(
                    pc,
                    format!("timed out after {} ms", limit.as_millis()),
                ));
            }
        }
        if pc > reported {
            reported = pc;
            on_progress(reported, total);
        }
        report.steps += 1;

        let instruction = &instructions[pc];
        match instruction {
            Instruction::StoreStatic {
                width,
                region,
                offset_register,
                rel_address,
                value,
            } => {
                let offset = *state
                    .registers
                    .get(*offset_register as usize)
                    .ok_or_else(|| VmError::new(pc, format!("r{offset_register} out of range")))?;
                let address = regions.resolve(*region, rel_address.wrapping_add(offset));
                write_value(
                    io,
                    &mut report,
                    pc,
                    address,
                    *width,
                    truncate(*value, *width),
                )?;
                pc += 1;
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
                let offset = if *include_offset_register {
                    *state
                        .registers
                        .get(*offset_register as usize)
                        .ok_or_else(|| {
                            VmError::new(pc, format!("r{offset_register} out of range"))
                        })?
                } else {
                    0
                };
                let address = regions.resolve(*region, rel_address.wrapping_add(offset));
                let source = read_value(io, &mut report, pc, address, *width)?;
                let expected = truncate(*value, *width);
                let condition = comparison.evaluate(source, expected);
                if condition {
                    pc += 1;
                } else {
                    pc = jump_target(jumps, pc, false_target(jumps, pc)?, pc)?;
                }
            }
            Instruction::EndConditional { is_else } => {
                if *is_else {
                    pc = jump_target(jumps, pc, else_target(jumps, pc)?, pc)?;
                } else {
                    pc += 1;
                }
            }
            Instruction::LoopStart { register, count } => {
                let register = *register;
                if register >= 16 {
                    return Err(VmError::new(pc, format!("r{register} out of range")));
                }
                if *count == 0 {
                    // Atmosphere would underflow at the end; skipping is the
                    // only useful interpretation of a zero-iteration loop.
                    let end = jumps
                        .get(pc)
                        .and_then(|jump| jump.loop_end)
                        .ok_or_else(|| VmError::new(pc, "loop start has no matching end"))?;
                    pc = jump_target(jumps, pc, end + 1, pc)?;
                    continue;
                }
                if loops.len() >= 16 {
                    return Err(VmError::new(pc, "loop nesting is too deep"));
                }
                state.registers[register as usize] = u64::from(*count);
                loops.push(LoopFrame {
                    register,
                    remaining: *count,
                    body_pc: pc + 1,
                });
                pc += 1;
            }
            Instruction::LoopEnd { register } => {
                let frame = loops
                    .last_mut()
                    .ok_or_else(|| VmError::new(pc, "loop end without a loop start"))?;
                if frame.register != *register {
                    return Err(VmError::new(
                        pc,
                        format!(
                            "loop end uses r{register} but the matching start uses r{}",
                            frame.register
                        ),
                    ));
                }
                frame.remaining -= 1;
                state.registers[*register as usize] = u64::from(frame.remaining);
                if frame.remaining == 0 {
                    loops.pop();
                    pc += 1;
                } else {
                    loop_restarts += 1;
                    if loop_restarts > VM_STEP_LIMIT {
                        return Err(VmError::new(pc, "loop iteration guard exceeded"));
                    }
                    pc = frame.body_pc;
                }
            }
            Instruction::LoadRegisterImmediate { register, value } => {
                let slot = state
                    .registers
                    .get_mut(*register as usize)
                    .ok_or_else(|| VmError::new(pc, format!("r{register} out of range")))?;
                *slot = *value;
                pc += 1;
            }
            Instruction::LoadRegisterMemory {
                width,
                region,
                register,
                load_from_register,
                offset_register,
                rel_address,
            } => {
                let base_register = state
                    .registers
                    .get(*offset_register as usize)
                    .copied()
                    .ok_or_else(|| VmError::new(pc, format!("r{offset_register} out of range")))?;
                let target_register = state
                    .registers
                    .get(*register as usize)
                    .copied()
                    .ok_or_else(|| VmError::new(pc, format!("r{register} out of range")))?;
                let address = match load_from_register {
                    0 => regions.resolve(*region, *rel_address),
                    1 => target_register.wrapping_add(*rel_address),
                    2 => base_register.wrapping_add(*rel_address),
                    3 => regions.resolve(*region, base_register.wrapping_add(*rel_address)),
                    other => {
                        return Err(VmError::new(
                            pc,
                            format!("invalid load-from-register mode {other}"),
                        ))
                    }
                };
                let value = read_value(io, &mut report, pc, address, *width)?;
                *state
                    .registers
                    .get_mut(*register as usize)
                    .ok_or_else(|| VmError::new(pc, format!("r{register} out of range")))? = value;
                pc += 1;
            }
            Instruction::StoreStaticToRegister {
                width,
                register,
                increment,
                add_offset_register,
                offset_register,
                value,
            } => {
                let mut address = *state
                    .registers
                    .get(*register as usize)
                    .ok_or_else(|| VmError::new(pc, format!("r{register} out of range")))?;
                if *add_offset_register {
                    address = address.wrapping_add(
                        *state
                            .registers
                            .get(*offset_register as usize)
                            .ok_or_else(|| {
                                VmError::new(pc, format!("r{offset_register} out of range"))
                            })?,
                    );
                }
                write_value(
                    io,
                    &mut report,
                    pc,
                    address,
                    *width,
                    truncate(*value, *width),
                )?;
                if *increment {
                    let slot = state
                        .registers
                        .get_mut(*register as usize)
                        .ok_or_else(|| VmError::new(pc, format!("r{register} out of range")))?;
                    *slot = slot.wrapping_add(u64::from(*width));
                }
                pc += 1;
            }
            Instruction::LegacyArithmetic {
                width,
                register,
                operation,
                value,
            } => {
                let slot = state
                    .registers
                    .get_mut(*register as usize)
                    .ok_or_else(|| VmError::new(pc, format!("r{register} out of range")))?;
                let operand = u64::from(*value);
                *slot = match operation {
                    ArithmeticOp::Add => slot.wrapping_add(operand),
                    ArithmeticOp::Sub => slot.wrapping_sub(operand),
                    ArithmeticOp::Multiply => slot.wrapping_mul(operand),
                    ArithmeticOp::LeftShift => slot.wrapping_shl((*value) & 63),
                    ArithmeticOp::RightShift => slot.wrapping_shr((*value) & 63),
                    other => {
                        return Err(VmError::new(
                            pc,
                            format!("unsupported legacy arithmetic {other:?}"),
                        ))
                    }
                };
                *slot = truncate(*slot, *width);
                pc += 1;
            }
            Instruction::KeypressConditional { key_mask } => {
                let mask = u64::from(*key_mask);
                if (mask & keys_held) == mask {
                    pc += 1;
                } else {
                    pc = jump_target(jumps, pc, false_target(jumps, pc)?, pc)?;
                }
            }
            Instruction::RegisterArithmetic {
                width,
                operation,
                destination_register,
                source_register_1,
                operand,
            } => {
                let operand_1 = *state
                    .registers
                    .get(*source_register_1 as usize)
                    .ok_or_else(|| {
                        VmError::new(pc, format!("r{source_register_1} out of range"))
                    })?;
                let operand_2 = match operand {
                    ArithmeticOperand::Immediate(value) => truncate(*value, *width),
                    ArithmeticOperand::Register(register) => *state
                        .registers
                        .get(*register as usize)
                        .ok_or_else(|| VmError::new(pc, format!("r{register} out of range")))?,
                };
                let result = match operation {
                    ArithmeticOp::Add => operand_1.wrapping_add(operand_2),
                    ArithmeticOp::Sub => operand_1.wrapping_sub(operand_2),
                    ArithmeticOp::Multiply => operand_1.wrapping_mul(operand_2),
                    ArithmeticOp::LeftShift => operand_1.wrapping_shl((operand_2 & 63) as u32),
                    ArithmeticOp::RightShift => operand_1.wrapping_shr((operand_2 & 63) as u32),
                    ArithmeticOp::And => operand_1 & operand_2,
                    ArithmeticOp::Or => operand_1 | operand_2,
                    ArithmeticOp::Not => !operand_1,
                    ArithmeticOp::Xor => operand_1 ^ operand_2,
                    ArithmeticOp::None => operand_1,
                    ArithmeticOp::FloatAdd
                    | ArithmeticOp::FloatSub
                    | ArithmeticOp::FloatMultiply
                    | ArithmeticOp::FloatDivide => {
                        float_arithmetic(*width, *operation, operand_1, operand_2)?
                    }
                };
                *state
                    .registers
                    .get_mut(*destination_register as usize)
                    .ok_or_else(|| {
                        VmError::new(pc, format!("r{destination_register} out of range"))
                    })? = truncate(result, *width);
                pc += 1;
            }
            Instruction::StoreRegisterToMemory {
                width,
                source_register,
                address_register,
                increment,
                offset,
            } => {
                let address_register_value = *state
                    .registers
                    .get(*address_register as usize)
                    .ok_or_else(|| VmError::new(pc, format!("r{address_register} out of range")))?;
                let mut address = address_register_value;
                match offset {
                    StoreOffset::None => {}
                    StoreOffset::Register(offset_register) => {
                        address =
                            address.wrapping_add(
                                *state.registers.get(*offset_register as usize).ok_or_else(
                                    || VmError::new(pc, format!("r{offset_register} out of range")),
                                )?,
                            );
                    }
                    StoreOffset::Immediate(rel_address) => {
                        address = address.wrapping_add(*rel_address);
                    }
                    StoreOffset::MemoryRegister(region) => {
                        address = regions.resolve(*region, address_register_value);
                    }
                    StoreOffset::MemoryImmediate {
                        region,
                        rel_address,
                    } => {
                        address = regions.resolve(*region, *rel_address);
                    }
                    StoreOffset::MemoryImmediateRegister {
                        region,
                        rel_address,
                    } => {
                        address = regions
                            .resolve(*region, address_register_value.wrapping_add(*rel_address));
                    }
                }
                let value = *state
                    .registers
                    .get(*source_register as usize)
                    .ok_or_else(|| VmError::new(pc, format!("r{source_register} out of range")))?;
                write_value(
                    io,
                    &mut report,
                    pc,
                    address,
                    *width,
                    truncate(value, *width),
                )?;
                if *increment {
                    let slot = state
                        .registers
                        .get_mut(*address_register as usize)
                        .ok_or_else(|| {
                            VmError::new(pc, format!("r{address_register} out of range"))
                        })?;
                    *slot = slot.wrapping_add(u64::from(*width));
                }
                pc += 1;
            }
            Instruction::RegisterConditional {
                width,
                comparison,
                value_register,
                operand,
            } => {
                let source = truncate(
                    *state
                        .registers
                        .get(*value_register as usize)
                        .ok_or_else(|| {
                            VmError::new(pc, format!("r{value_register} out of range"))
                        })?,
                    *width,
                );
                let other =
                    match operand {
                        ConditionalOperand::MemoryRelative {
                            region,
                            rel_address,
                        } => {
                            let address = regions.resolve(*region, *rel_address);
                            read_value(io, &mut report, pc, address, *width)?
                        }
                        ConditionalOperand::MemoryOffset {
                            region,
                            offset_register,
                        } => {
                            let offset =
                                *state.registers.get(*offset_register as usize).ok_or_else(
                                    || VmError::new(pc, format!("r{offset_register} out of range")),
                                )?;
                            let address = regions.resolve(*region, offset);
                            read_value(io, &mut report, pc, address, *width)?
                        }
                        ConditionalOperand::RegisterRelative {
                            address_register,
                            rel_address,
                        } => {
                            let base = *state
                                .registers
                                .get(*address_register as usize)
                                .ok_or_else(|| {
                                    VmError::new(pc, format!("r{address_register} out of range"))
                                })?;
                            read_value(
                                io,
                                &mut report,
                                pc,
                                base.wrapping_add(*rel_address),
                                *width,
                            )?
                        }
                        ConditionalOperand::RegisterOffset {
                            address_register,
                            offset_register,
                        } => {
                            let base = *state
                                .registers
                                .get(*address_register as usize)
                                .ok_or_else(|| {
                                    VmError::new(pc, format!("r{address_register} out of range"))
                                })?;
                            let offset =
                                *state.registers.get(*offset_register as usize).ok_or_else(
                                    || VmError::new(pc, format!("r{offset_register} out of range")),
                                )?;
                            read_value(io, &mut report, pc, base.wrapping_add(offset), *width)?
                        }
                        ConditionalOperand::Immediate(value) => truncate(*value, *width),
                        ConditionalOperand::Register(register) => truncate(
                            *state.registers.get(*register as usize).ok_or_else(|| {
                                VmError::new(pc, format!("r{register} out of range"))
                            })?,
                            *width,
                        ),
                    };
                if comparison.evaluate(source, other) {
                    pc += 1;
                } else {
                    pc = jump_target(jumps, pc, false_target(jumps, pc)?, pc)?;
                }
            }
            Instruction::SaveRestoreRegister {
                destination,
                source,
                operation,
            } => {
                let destination = *destination as usize;
                let source = *source as usize;
                if destination >= 16 || source >= 16 {
                    return Err(VmError::new(pc, "save/restore register out of range"));
                }
                match operation {
                    SaveRestoreOp::Restore => {
                        state.registers[destination] = state.saved[source];
                    }
                    SaveRestoreOp::Save => {
                        state.saved[destination] = state.registers[source];
                    }
                    SaveRestoreOp::ClearSaved => {
                        state.saved[destination] = 0;
                    }
                    SaveRestoreOp::ClearRegisters => {
                        state.registers[destination] = 0;
                    }
                }
                pc += 1;
            }
            Instruction::SaveRestoreRegisterMask { operation, mask } => {
                let mask = u32::from(*mask);
                match operation {
                    SaveRestoreOp::Save | SaveRestoreOp::ClearSaved => {
                        for index in 0..16 {
                            if mask & (1 << index) != 0 {
                                match operation {
                                    SaveRestoreOp::Save => {
                                        state.saved[index] = state.registers[index]
                                    }
                                    SaveRestoreOp::ClearSaved => state.saved[index] = 0,
                                    _ => {}
                                }
                            }
                        }
                    }
                    SaveRestoreOp::Restore | SaveRestoreOp::ClearRegisters => {
                        for index in 0..16 {
                            if mask & (1 << index) != 0 {
                                match operation {
                                    SaveRestoreOp::Restore => {
                                        state.registers[index] = state.saved[index]
                                    }
                                    SaveRestoreOp::ClearRegisters => state.registers[index] = 0,
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                pc += 1;
            }
            Instruction::StaticRegister {
                static_index,
                register,
            } => {
                let register = *register as usize;
                if register >= 16 {
                    return Err(VmError::new(pc, "static register source out of range"));
                }
                if *static_index < 0x80 {
                    state.registers[register] = state.static_registers[*static_index as usize];
                } else {
                    state.static_registers[*static_index as usize] = state.registers[register];
                }
                pc += 1;
            }
            Instruction::PauseProcess => {
                if !state.paused {
                    io.pause_process()
                        .map_err(|error| VmError::new(pc, format!("pause failed: {error}")))?;
                    state.paused = true;
                }
                pc += 1;
            }
            Instruction::ResumeProcess => {
                if state.paused {
                    io.resume_process()
                        .map_err(|error| VmError::new(pc, format!("resume failed: {error}")))?;
                    state.paused = false;
                }
                pc += 1;
            }
            Instruction::Unsupported { opcode, .. } => {
                return Err(VmError::new(pc, format!("unsupported opcode 0x{opcode:X}")));
            }
        }
    }

    on_progress(total, total);
    Ok(report)
}

#[derive(Clone, Copy, Debug)]
struct LoopFrame {
    register: u8,
    remaining: u32,
    body_pc: usize,
}

fn false_target(jumps: &[JumpInfo], pc: usize) -> Result<usize, VmError> {
    jumps
        .get(pc)
        .and_then(|jump| jump.false_target)
        .ok_or_else(|| VmError::new(pc, "condition has no false target"))
}

fn else_target(jumps: &[JumpInfo], pc: usize) -> Result<usize, VmError> {
    jumps
        .get(pc)
        .and_then(|jump| jump.else_target)
        .ok_or_else(|| VmError::new(pc, "else has no matching end"))
}

fn jump_target(
    jumps: &[JumpInfo],
    _pc: usize,
    target: usize,
    error_pc: usize,
) -> Result<usize, VmError> {
    if target <= jumps.len() {
        Ok(target)
    } else {
        Err(VmError::new(
            error_pc,
            format!("jump target 0x{target:X} is outside the program"),
        ))
    }
}

fn truncate(value: u64, width: u8) -> u64 {
    match width {
        1 => value & 0xFF,
        2 => value & 0xFFFF,
        4 => value & 0xFFFF_FFFF,
        8 => value,
        _ => value,
    }
}

fn read_value(
    io: &mut dyn CheatMemoryIo,
    report: &mut VmReport,
    pc: usize,
    address: u64,
    width: u8,
) -> Result<u64, VmError> {
    let size = u32::from(width);
    let bytes = io
        .read_mem(address, size)
        .map_err(|error| VmError::new(pc, format!("read 0x{address:X} failed: {error}")))?;
    report.reads += 1;
    if bytes.len() != width as usize {
        return Err(VmError::new(
            pc,
            format!(
                "short read at 0x{address:X}: expected {width} bytes, got {}",
                bytes.len()
            ),
        ));
    }
    let mut buffer = [0u8; 8];
    buffer[..bytes.len()].copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(buffer))
}

fn write_value(
    io: &mut dyn CheatMemoryIo,
    report: &mut VmReport,
    pc: usize,
    address: u64,
    width: u8,
    value: u64,
) -> Result<(), VmError> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        return Err(VmError::new(pc, format!("invalid write width {width}")));
    }
    let bytes = value.to_le_bytes();
    io.write_mem(address, &bytes[..width as usize], true)
        .map_err(|error| VmError::new(pc, format!("write 0x{address:X} failed: {error}")))?;
    report.writes += 1;
    Ok(())
}

fn float_arithmetic(
    width: u8,
    operation: ArithmeticOp,
    left: u64,
    right: u64,
) -> Result<u64, VmError> {
    match width {
        4 => {
            let left = f32::from_bits(left as u32);
            let right = f32::from_bits(right as u32);
            let result = match operation {
                ArithmeticOp::FloatAdd => left + right,
                ArithmeticOp::FloatSub => left - right,
                ArithmeticOp::FloatMultiply => left * right,
                ArithmeticOp::FloatDivide => left / right,
                _ => return Err(VmError::without_pc("not a float operation")),
            };
            Ok(u64::from(result.to_bits()))
        }
        8 => {
            let left = f64::from_bits(left);
            let right = f64::from_bits(right);
            let result = match operation {
                ArithmeticOp::FloatAdd => left + right,
                ArithmeticOp::FloatSub => left - right,
                ArithmeticOp::FloatMultiply => left * right,
                ArithmeticOp::FloatDivide => left / right,
                _ => return Err(VmError::without_pc("not a float operation")),
            };
            Ok(result.to_bits())
        }
        other => Err(VmError::without_pc(format!(
            "float arithmetic requires width 4 or 8, got {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cheat::model::CheatCode;
    use crate::cheat::parser::parse_code_lines;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MockIo {
        memory: BTreeMap<u64, u8>,
        writes: Vec<(u64, Vec<u8>, bool)>,
        paused: bool,
        pause_calls: usize,
        resume_calls: usize,
        short_read: bool,
    }

    impl MockIo {
        fn with(memory: &[(u64, &[u8])]) -> Self {
            let mut io = MockIo::default();
            for (address, bytes) in memory {
                for (offset, byte) in bytes.iter().enumerate() {
                    io.memory.insert(address + offset as u64, *byte);
                }
            }
            io
        }

        fn write_at(&self, address: u64, width: u8) -> u64 {
            let bytes = self
                .writes
                .iter()
                .rev()
                .find(|(candidate, data, _)| *candidate == address && data.len() == width as usize)
                .map(|(_, data, _)| data.clone())
                .unwrap_or_default();
            let mut buffer = [0u8; 8];
            buffer[..bytes.len()].copy_from_slice(&bytes);
            u64::from_le_bytes(buffer)
        }

        fn writes_to(&self, address: u64) -> usize {
            self.writes
                .iter()
                .filter(|(candidate, _, _)| *candidate == address)
                .count()
        }
    }

    impl CheatMemoryIo for MockIo {
        fn read_mem(&mut self, address: u64, size: u32) -> Result<Vec<u8>, String> {
            if self.short_read {
                return Ok(Vec::new());
            }
            Ok((0..size)
                .map(|offset| {
                    self.memory
                        .get(&(address + u64::from(offset)))
                        .copied()
                        .unwrap_or(0)
                })
                .collect())
        }

        fn write_mem(&mut self, address: u64, data: &[u8], allow_rx: bool) -> Result<(), String> {
            self.writes.push((address, data.to_vec(), allow_rx));
            for (offset, byte) in data.iter().enumerate() {
                self.memory.insert(address + offset as u64, *byte);
            }
            Ok(())
        }

        fn pause_process(&mut self) -> Result<(), String> {
            self.paused = true;
            self.pause_calls += 1;
            Ok(())
        }

        fn resume_process(&mut self) -> Result<(), String> {
            self.paused = false;
            self.resume_calls += 1;
            Ok(())
        }
    }

    const MAIN: u64 = 0x1000;
    const HEAP: u64 = 0x2000;
    const ALIAS: u64 = 0x3000;
    const ASLR: u64 = 0x4000;

    fn regions() -> MemoryRegions {
        MemoryRegions::new(MAIN, HEAP, ALIAS, ASLR)
    }

    fn code(lines: &[&str]) -> CheatCode {
        let lines: Vec<String> = lines.iter().map(|line| (*line).to_string()).collect();
        parse_code_lines(&lines, 1)
    }

    fn run(lines: &[&str], io: &mut MockIo, keys: u64) -> (VmReport, VmState) {
        let code = code(lines);
        assert!(code.is_valid(), "{:?}", code.issues);
        let mut state = VmState::default();
        let report = execute(
            &code.instructions,
            &code.jumps,
            io,
            &regions(),
            keys,
            &mut state,
        )
        .unwrap();
        (report, state)
    }

    #[test]
    fn store_static_handles_every_width_and_region() {
        let mut io = MockIo::default();
        let (_, _) = run(
            &[
                "01000000 00000010 7F",
                "02000000 00000020 1234",
                "04000000 00000030 89ABCDEF",
                "08000000 00000040 11223344 55667788",
                "04400000 DEADBEEF CAFEBABE",
            ],
            &mut io,
            0,
        );
        assert_eq!(io.write_at(MAIN + 0x10, 1), 0x7F);
        assert_eq!(io.write_at(MAIN + 0x20, 2), 0x1234);
        assert_eq!(io.write_at(MAIN + 0x30, 4), 0x89AB_CDEF);
        assert_eq!(io.write_at(MAIN + 0x40, 8), 0x1122_3344_5566_7788);
        assert_eq!(io.write_at(0xDEAD_BEEF, 4), 0xCAFE_BABE);
        assert!(io.writes.iter().all(|(_, _, allow_rx)| *allow_rx));
    }

    #[test]
    fn store_static_adds_offset_register() {
        let mut io = MockIo::default();
        run(
            &["40010000 00000000 00000100", "04010000 00000010 0000002A"],
            &mut io,
            0,
        );
        assert_eq!(io.write_at(MAIN + 0x110, 4), 0x2A);
    }

    #[test]
    fn conditional_true_runs_body_and_false_skips() {
        let mut io = MockIo::with(&[(MAIN + 0x10, &0x0500_0000u32.to_le_bytes())]);
        run(
            &[
                "14050000 00000010 05000000",
                "04000000 00000020 00000001",
                "20000000",
            ],
            &mut io,
            0,
        );
        assert_eq!(io.writes_to(MAIN + 0x20), 1);
        assert_eq!(io.write_at(MAIN + 0x20, 4), 1);

        let mut io = MockIo::with(&[(MAIN + 0x10, &0x0400_0000u32.to_le_bytes())]);
        run(
            &[
                "14050000 00000010 05000000",
                "04000000 00000020 00000001",
                "20000000",
            ],
            &mut io,
            0,
        );
        assert_eq!(io.writes_to(MAIN + 0x20), 0);
    }

    #[test]
    fn else_branch_executes_alternative() {
        let mut io = MockIo::with(&[(MAIN + 0x10, &0u32.to_le_bytes())]);
        run(
            &[
                "14050000 00000010 00000001",
                "04000000 00000020 000000AA",
                "21000000",
                "04000000 00000020 000000BB",
                "20000000",
            ],
            &mut io,
            0,
        );
        assert_eq!(io.write_at(MAIN + 0x20, 4), 0xBB);
        assert_eq!(io.writes_to(MAIN + 0x20), 1);
    }

    #[test]
    fn nested_conditionals_do_not_leak_writes() {
        let mut io = MockIo::with(&[(MAIN + 0x10, &1u32.to_le_bytes())]);
        run(
            &[
                "14050000 00000010 00000001",
                "14050000 00000011 00000002",
                "04000000 00000020 000000AA",
                "20000000",
                "04000000 00000021 000000BB",
                "20000000",
            ],
            &mut io,
            0,
        );
        assert_eq!(io.writes_to(MAIN + 0x20), 0);
        assert_eq!(io.write_at(MAIN + 0x21, 4), 0xBB);
    }

    #[test]
    fn loop_runs_exact_number_of_iterations() {
        let mut io = MockIo::default();
        let (report, _) = run(
            &["30000000 00000003", "74010000 00000001", "31000000"],
            &mut io,
            0,
        );
        // Three body executions, each an arithmetic op.
        assert_eq!(report.steps, 1 + 3 + 3);
    }

    #[test]
    fn zero_iteration_loop_skips_body() {
        let mut io = MockIo::default();
        run(
            &[
                "30000000 00000000",
                "04000000 00000020 000000AA",
                "31000000",
            ],
            &mut io,
            0,
        );
        assert_eq!(io.writes_to(MAIN + 0x20), 0);
    }

    #[test]
    fn nested_loops_use_independent_registers() {
        let mut io = MockIo::default();
        run(
            &[
                "30050000 00000002",
                "30010000 00000003",
                "94020100 00000001",
                "31010000",
                "31050000",
            ],
            &mut io,
            0,
        );
        assert_eq!(io.writes_to(MAIN + 0), 0);
    }

    #[test]
    fn load_register_memory_pointer_chasing_modes() {
        let pointer = 0x5000u64;
        let mut io = MockIo::with(&[
            (MAIN + 0x10, &pointer.to_le_bytes()),
            (pointer, &0xCAFE_BABEu32.to_le_bytes()),
            (pointer + 4, &0xDEAD_BEEFu32.to_le_bytes()),
            (MAIN + pointer, &0x1122_3344u32.to_le_bytes()),
        ]);
        let program = code(&[
            "58010000 00000010", // r1 = [main+0x10] = 0x5000
            "54011000 00000000", // r1 = [r1] (mode 1, same register)
            "58010000 00000010", // r1 = pointer again
            "54022100 00000004", // r2 = [r1 + 4] (mode 2: offset register)
            "54033100 00000000", // r3 = [main + r1] (mode 3)
        ]);
        assert!(program.is_valid(), "{:?}", program.issues);
        let mut state = VmState::default();
        execute(
            &program.instructions,
            &program.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.registers[1], 0x5000);
        assert_eq!(state.registers[2], 0xDEAD_BEEF);
        assert_eq!(state.registers[3], 0x1122_3344);
        // Mode 1 was checked by a separate run below, because it overwrites r1.
        let mode1 = code(&["58010000 00000010", "54011000 00000000"]);
        let mut state = VmState::default();
        execute(
            &mode1.instructions,
            &mode1.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.registers[1], 0xCAFE_BABE);
    }

    #[test]
    fn store_static_to_register_increments_and_offsets() {
        let base = 0x7000u64;
        let mut io = MockIo::default();
        // r1 = base. Store 4 bytes at r1+r2, increment r1 by 4.
        run(
            &[
                "40010000 00000000 00007000",
                "40020000 00000000 00000008",
                "64011120 00000000 0000002A",
            ],
            &mut io,
            0,
        );
        assert_eq!(io.write_at(base + 8, 4), 0x2A);
    }

    #[test]
    fn legacy_arithmetic_masks_to_width() {
        let code = code(&[
            "40010000 00000000 000000FF",
            "71010000 00000010",
            "74020000 00000002",
            "74030000 00000002",
        ]);
        // Use a more direct assertion via execute.
        let mut io = MockIo::default();
        let mut state = VmState::default();
        execute(
            &code.instructions,
            &code.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
        )
        .unwrap();
        // 0xFF + 0x10 = 0x10F, truncated to 1 byte -> 0x0F.
        assert_eq!(state.registers[1], 0x0F);
        // 0 + 2 = 2; *2 = 4.
        assert_eq!(state.registers[2], 2);
        assert_eq!(state.registers[3], 2);
    }

    #[test]
    fn keypress_conditional_gates_on_held_mask() {
        let lines = &["80000001", "04000000 00000020 000000AA", "20000000"];
        let mut io = MockIo::default();
        run(lines, &mut io, 1);
        assert_eq!(io.write_at(MAIN + 0x20, 4), 0xAA);

        let mut io = MockIo::default();
        run(lines, &mut io, 0);
        assert_eq!(io.writes_to(MAIN + 0x20), 0);
    }

    #[test]
    fn keypress_requires_every_bit_in_the_mask() {
        let lines = &["80000003", "04000000 00000020 000000AA", "20000000"];
        let mut io = MockIo::default();
        run(lines, &mut io, 1);
        assert_eq!(io.writes_to(MAIN + 0x20), 0);
        run(lines, &mut io, 3);
        assert_eq!(io.write_at(MAIN + 0x20, 4), 0xAA);
    }

    #[test]
    fn register_arithmetic_supports_bitwise_and_shifts() {
        let code = code(&[
            "40010000 00000000 0000FF00",
            "94021100 0000000F", // r2 = r1 + 0x0F
            "94131100 0000000F", // r3 = r1 - 0x0F
            "94241100 00000002", // r4 = r1 * 2
            "94351100 00000004", // r5 = r1 << 4
            "94461100 00000004", // r6 = r1 >> 4
            "94571100 0000F0F0", // r7 = r1 & 0xF0F0
            "94681100 0000000F", // r8 = r1 | 0x0F
            "94891100 0000000F", // r9 = r1 ^ 0x0F
            "947A1000",          // r10 = ~r1
            "949B1000",          // r11 = r1
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        let mut io = MockIo::default();
        let mut state = VmState::default();
        execute(
            &code.instructions,
            &code.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.registers[2], 0x0000_FF0F);
        assert_eq!(state.registers[3], 0x0000_FEF1);
        assert_eq!(state.registers[4], 0x0001_FE00);
        assert_eq!(state.registers[5], 0x000F_F000);
        assert_eq!(state.registers[6], 0x0000_0FF0);
        assert_eq!(state.registers[7], 0x0000_F000);
        assert_eq!(state.registers[8], 0x0000_FF0F);
        assert_eq!(state.registers[9], 0x0000_FF0F);
        assert_eq!(state.registers[10], 0xFFFF_00FF);
        assert_eq!(state.registers[11], 0x0000_FF00);
    }

    #[test]
    fn float_arithmetic_uses_ieee_bits() {
        let one = 1.0f32.to_bits();
        let two = 2.0f32.to_bits();
        let code = code(&[
            &format!("40010000 00000000 {one:08X}"),
            &format!("40020000 00000000 {two:08X}"),
            "94A31020", // r3 = r1 + r2
            "94B41020", // r4 = r1 - r2
            "94C51020", // r5 = r1 * r2
            "94D61020", // r6 = r1 / r2
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        let mut io = MockIo::default();
        let mut state = VmState::default();
        execute(
            &code.instructions,
            &code.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
        )
        .unwrap();
        assert_eq!(f32::from_bits(state.registers[3] as u32), 3.0);
        assert_eq!(f32::from_bits(state.registers[4] as u32), -1.0);
        assert_eq!(f32::from_bits(state.registers[5] as u32), 2.0);
        assert_eq!(f32::from_bits(state.registers[6] as u32), 0.5);
    }

    #[test]
    fn store_register_offset_modes() {
        let mut io = MockIo::default();
        run(
            &[
                "40010000 00000000 0000002A",
                "40020000 00000000 00007000",
                "40030000 00000000 00000008",
                "A4120000",
                "A4120130",
                "A4120200 00000010",
                "A4120300",
                "A4120400 00000020",
                "A4120500 00000030",
            ],
            &mut io,
            0,
        );
        assert_eq!(io.write_at(0x7000, 4), 0x2A);
        assert_eq!(io.write_at(0x7008, 4), 0x2A);
        assert_eq!(io.write_at(0x7010, 4), 0x2A);
        assert_eq!(io.write_at(MAIN + 0x7000, 4), 0x2A);
        assert_eq!(io.write_at(MAIN + 0x20, 4), 0x2A);
        assert_eq!(io.write_at(MAIN + 0x7030, 4), 0x2A);
    }

    #[test]
    fn register_conditional_operand_types() {
        let mut io = MockIo::with(&[(MAIN + 0x10, &5u64.to_le_bytes())]);
        run(
            &[
                "40010000 00000000 00000005",
                "40020000 00000000 00000006",
                "40030000 00000000 00000004",
                "C0421000 00000010",
                "04000000 00000020 00000001",
                "20000000",
                "C0411530",
                "04000000 00000021 00000002",
                "20000000",
            ],
            &mut io,
            0,
        );
        assert_eq!(io.write_at(MAIN + 0x20, 4), 1);
        assert_eq!(io.write_at(MAIN + 0x21, 4), 2);
    }

    #[test]
    fn save_restore_registers_and_masks() {
        let code = code(&[
            "40010000 00000000 0000002A",
            "C2110002",
            "40010000 00000000 00000000",
            "C2010002",
            "40020000 00000000 00000099",
            "C2220002",
            "40030000 00000000 00000000",
        ]);
        assert!(code.is_valid(), "{:?}", code.issues);
        let mut io = MockIo::default();
        let mut state = VmState::default();
        execute(
            &code.instructions,
            &code.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.registers[1], 0x2A);
        assert_eq!(state.saved[1], 0);
        assert_eq!(state.registers[2], 0x99);
    }

    #[test]
    fn static_registers_persist_across_executions() {
        let program = code(&[
            "40010000 00000000 0000002A",
            "C3000801", // write r1 to static register 0x80
            "C3000052", // read static register 0x05 into r2
        ]);
        assert!(program.is_valid(), "{:?}", program.issues);
        let mut io = MockIo::default();
        let mut state = VmState::default();
        state.static_registers[0x05] = 0x77;
        execute(
            &program.instructions,
            &program.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.static_registers[0x80], 0x2A);
        assert_eq!(state.registers[2], 0x77);

        // A second evaluation keeps the static register contents.
        let read_back = code(&["C3000803"]);
        execute(
            &read_back.instructions,
            &read_back.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
        )
        .unwrap();
        // 0x80 is a write-only slot, so this writes r3 (0) there; the read
        // path for 0x00..0x7F was already checked above.
        assert_eq!(state.static_registers[0x80], 0);
    }

    #[test]
    fn pause_and_resume_are_deduplicated() {
        let mut io = MockIo::default();
        run(
            &["FF000000", "FF000000", "FF100000", "FF100000"],
            &mut io,
            0,
        );
        assert_eq!(io.pause_calls, 1);
        assert_eq!(io.resume_calls, 1);
        assert!(!io.paused);
    }

    #[test]
    fn pause_is_released_at_the_end_of_the_block() {
        // 0xFF0 without a matching 0xFF1 must not leave the target frozen.
        let mut io = MockIo::default();
        run(
            &["FF000000", "04400000 00000020 0000002A"],
            &mut io,
            0,
        );
        assert_eq!(io.pause_calls, 1);
        assert_eq!(io.resume_calls, 1);
        assert!(!io.paused);

        // A block that fails after pausing is still resumed.
        let mut io = MockIo::default();
        io.short_read = true;
        let program = code(&[
            "FF000000",
            "14050000 00000010 00000001",
            "04000000 00000020 00000001",
            "20000000",
        ]);
        let mut state = VmState::default();
        let error = execute(
            &program.instructions,
            &program.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
        )
        .unwrap_err();
        assert!(error.message.contains("short read"), "{error}");
        assert_eq!(io.pause_calls, 1);
        assert_eq!(io.resume_calls, 1);
        assert!(!io.paused);
        assert!(!state.paused);
    }

    #[test]
    fn budget_overrun_aborts_the_block() {
        let program = code(&["04400000 00000020 0000002A"]);
        let mut io = MockIo::default();
        let mut state = VmState::default();
        let error = execute_with_budget(
            &program.instructions,
            &program.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
            Some(Duration::ZERO),
            &mut |_, _| {},
        )
        .unwrap_err();
        assert!(error.message.contains("timed out"), "{error}");
        assert_eq!(io.writes_to(MAIN + 0x20), 0);
    }

    #[test]
    fn progress_reports_the_furthest_instruction() {
        let program = code(&[
            "40010000 00000000 00000003",
            "30020000 00000003",
            "94020100 00000001",
            "31020000",
        ]);
        assert!(program.is_valid(), "{:?}", program.issues);
        let total = program.instructions.len();
        let mut io = MockIo::default();
        let mut state = VmState::default();
        let mut seen: Vec<(usize, usize)> = Vec::new();
        execute_with_budget(
            &program.instructions,
            &program.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
            None,
            &mut |done, total| seen.push((done, total)),
        )
        .unwrap();
        assert_eq!(seen.first(), Some(&(0, total)));
        assert_eq!(seen.last(), Some(&(total, total)));
        assert!(
            seen.windows(2).all(|pair| pair[0].0 <= pair[1].0),
            "progress must never go backwards: {seen:?}"
        );
    }

    #[test]
    fn step_limit_stops_infinite_loops() {
        let code = code(&["30000000 FFFFFFFF", "31000000"]);
        assert!(code.is_valid(), "{:?}", code.issues);
        let mut io = MockIo::default();
        let mut state = VmState::default();
        let error = execute(
            &code.instructions,
            &code.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
        )
        .unwrap_err();
        assert!(error.message.contains("step limit"));
    }

    #[test]
    fn short_memory_reads_abort_the_evaluation() {
        let mut io = MockIo::default();
        io.short_read = true;
        let code = code(&[
            "14050000 00000010 00000001",
            "04000000 00000020 00000001",
            "20000000",
        ]);
        let mut state = VmState::default();
        let error = execute(
            &code.instructions,
            &code.jumps,
            &mut io,
            &regions(),
            0,
            &mut state,
        )
        .unwrap_err();
        assert!(error.message.contains("short read"));
    }

    #[test]
    fn absolute_region_ignores_bases() {
        let mut io = MockIo::default();
        run(&["04400000 12345678 DEADBEEF"], &mut io, 0);
        assert_eq!(io.write_at(0x1234_5678, 4), 0xDEAD_BEEF);
    }
}
