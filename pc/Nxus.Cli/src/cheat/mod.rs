//! PC-side Atmosphere cheat engine.
//!
//! This module is fully self-contained (standard library only):
//!
//! * [`model`] — documents, blocks, decoded instructions and the writer.
//! * [`parser`] — `<BuildID>.txt` parsing and opcode decoding.
//! * [`vm`] — typed interpreter behind the [`vm::CheatMemoryIo`] trait.
//! * [`manager`] — patch/loop lifecycle, backups and the sidecar journal.
//!
//! Typical integration:
//!
//! ```no_run
//! # use nxus::cheat::{CheatManager, CheatMemoryIo, MemoryRegions, TargetIdentity};
//! # fn demo(identity: TargetIdentity, regions: MemoryRegions, io: &mut dyn CheatMemoryIo)
//! #     -> Result<(), String> {
//! let mut manager = CheatManager::open_for_target(identity, regions)?;
//! let key = manager
//!     .blocks()
//!     .first()
//!     .map(|block| block.key)
//!     .ok_or("no cheats in the file")?;
//! manager.enable(key, io)?;
//! manager.tick(io, 0);
//! manager.restore_all_backups(io);
//! # Ok(())
//! # }
//! ```

pub mod ir;
pub mod manager;
pub mod model;
pub mod parser;
pub mod vm;

pub use ir::{
    build_program, BlockDesc, ProgramHeader, WireInsn, BLOCK_BYTES, HEADER_BYTES, INSN_BYTES,
    MAGIC, MAX_BLOCKS, MAX_INSNS, MAX_JOURNAL, MAX_PROGRAM_BYTES, STEP_LIMIT, VERSION,
};
pub use manager::{
    cheats_dir_for, cheats_directory, exe_dir, normalize_build_id, resolve_backup_path_in,
    resolve_cheat_path, resolve_cheat_path_in, resolve_existing_cheat_path_in, BackupEntry,
    BackupState, CheatManager, CheatSnapshot, RestoreReport, TargetChange, TargetIdentity,
    TickReport, JOURNAL_MAGIC,
};
pub use model::{
    instructions_to_lines, save_text_atomic, ArithmeticOp, ArithmeticOperand, CheatBlock,
    CheatCode, CheatDocument, CheatExecMode, CheatKey, CheatKind, CodeLine, Comparison,
    ConditionalOperand, Instruction, JumpInfo, MemoryRegion, ModeSource, OffStyle, ParseIssue,
    SaveRestoreOp, StoreOffset, MAX_CHEAT_FILE_BYTES, MAX_PROGRAM_OPCODES, MAX_WORDS_PER_CODE_LINE,
    VM_STEP_LIMIT,
};
pub use parser::{parse_code, parse_code_lines, parse_document, parse_file};
pub use vm::{execute, CheatMemoryIo, FailureKind, MemoryRegions, VmError, VmReport, VmState};
