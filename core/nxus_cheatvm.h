/**
 * @file nxus_cheatvm.h
 * @brief On-console cheat interpreter (the Atmosphere cheat VM, running inside nxus).
 *
 * Why this exists
 * ---------------
 * The PC client used to run the cheat VM and write through dmnt every 250 ms.  That
 * is not what Atmosphere does: dmnt runs the VM inside the game's own process, every
 * frame, so key-conditional codes react immediately and loops are frame-accurate.
 * A PC-driven VM can never match that (Wi-Fi round trip + a timer), so the engine is
 * moved here.
 *
 * Division of labour
 * ------------------
 *  - The **PC** parses the `<BUILDID>.txt` file (that parser is tested to death) and
 *    ships a **linked program**: instructions with branch targets already resolved to
 *    instruction indices, so this side needs no assembler/linker, just an interpreter.
 *  - The **console** stores the program, runs it from a 16 ms worker, keeps the
 *    original bytes of everything it patches (so Panic Restore works with no PC), and
 *    refuses to run against a target it was not uploaded for.
 *
 * Everything here is plain C and libnx-free so it can be tested on the host.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nxus_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- limits (heap budget: the sysmodule has 8 MiB in total) ---------------- */

/** Largest program the console accepts, in bytes (header + blocks + instructions). */
#define NXUS_CHEATVM_MAX_PROGRAM_BYTES (512u * 1024u)
/** Largest instruction count one program may carry.  This is a ceiling on the wire
 *  format, not on resident memory: the instruction array is allocated on the heap
 *  with exactly `insn_count` slots (see NxusCheatProgram.insns), so a one-instruction
 *  patch costs 24 bytes while a 20 000-instruction loop file still fits.  The old
 *  fixed array forced every program, including write-once patches, to reserve the
 *  same 48 KiB. */
#define NXUS_CHEATVM_MAX_INSNS 20000u
/** Blocks in one program. */
#define NXUS_CHEATVM_MAX_BLOCKS 128u
/** Ceiling for patched addresses whose original bytes are kept for Panic Restore.
 *
 *  The table is a HEAP array (see NxusCheatJournal): it starts at whatever
 *  capacity the service asks for (512 slots, 12 KiB) and doubles on demand, so a
 *  cheat file that rewrites a few hundred addresses costs a few KiB, while the
 *  real-world "one block writes 112 addresses, 858 addresses in total" case still
 *  fits.  16384 entries x 24 B = 384 KiB, which is the most this table may ever
 *  take from the sysmodule's 8 MiB heap.  A fixed 512-entry array used to make
 *  every write after the 512th address fail until the console was rebooted. */
#define NXUS_CHEATVM_MAX_JOURNAL 16384u
/** Interpreter steps for one block execution (a runaway loop must not wedge us). */
#define NXUS_CHEATVM_STEP_LIMIT 100000u

#define NXUS_CHEATVM_MAGIC 0x4E43564Du /* 'NCVM' */
#define NXUS_CHEATVM_VERSION 1u

/* ---- memory regions (same numbering as Atmosphere and the wire protocol) --- */

typedef enum {
    NxusCheatRegion_Main = 0,
    NxusCheatRegion_Heap = 1,
    NxusCheatRegion_Alias = 2,
    NxusCheatRegion_Aslr = 3,
    NxusCheatRegion_Absolute = 4,
} NxusCheatRegion;

/** Comparison used by conditionals (Atmosphere numbering). */
typedef enum {
    NxusCheatCmp_Greater = 0,
    NxusCheatCmp_GreaterEqual = 1,
    NxusCheatCmp_Less = 2,
    NxusCheatCmp_LessEqual = 3,
    NxusCheatCmp_Equal = 4,
    NxusCheatCmp_NotEqual = 5,
} NxusCheatCmp;

/** Arithmetic used by the register opcodes (Atmosphere numbering). */
typedef enum {
    NxusCheatArith_Add = 0,
    NxusCheatArith_Sub = 1,
    NxusCheatArith_Mul = 2,
    NxusCheatArith_Lsh = 3,
    NxusCheatArith_Rsh = 4,
} NxusCheatArith;

/** One decoded, linked instruction.  24 bytes, packed on the wire. */
typedef enum {
    NxusCheatOp_Nop = 0,
    /** `[region + address (+ rB)] = value`, `width` bytes. */
    NxusCheatOp_StoreStatic = 1,
    /** Compare memory with `value`; when false jump to `target`. */
    NxusCheatOp_BeginConditional = 2,
    /** Unconditional jump to `target` (the `else` of a conditional). */
    NxusCheatOp_Else = 3,
    /** End of a conditional; falls through. */
    NxusCheatOp_EndConditional = 4,
    /** `rA = loop counter for `value` iterations`; `target` = first body insn. */
    NxusCheatOp_LoopStart = 5,
    /** Jump back to `target` (the matching LoopStart) while the counter lasts. */
    NxusCheatOp_LoopEnd = 6,
    /** `rA = value`. */
    NxusCheatOp_LoadRegImm = 7,
    /** `rA = [region + address (+ rB according to flags)]`, `width` bytes. */
    NxusCheatOp_LoadRegMem = 8,
    /** Store the immediate `value` at `[rA (+ rB)]`, `width` bytes. */
    NxusCheatOp_StoreStaticToReg = 9,
    /** `rA = rA op value` (arith, immediate). */
    NxusCheatOp_ArithImm = 10,
    /** `rA = [rA + address]` style register load (Atmosphere 0x5 mode 1). */
    NxusCheatOp_LoadRegMemReg = 11,
    /** `rA = [rA + rB]` style register load (Atmosphere 0x5 mode 2). */
    NxusCheatOp_LoadRegMemRegReg = 12,
    /** `rA = [region + rA + address]` (Atmosphere 0x5 mode 3). */
    NxusCheatOp_LoadRegMemRegRegion = 13,
    /** `rA = rA op rB`. */
    NxusCheatOp_ArithReg = 14,
    /** `[rA] = rB`, `width` bytes (Atmosphere 0xA). */
    NxusCheatOp_StoreReg = 15,
    /** Register-to-register conditional; false jumps to `target`. */
    NxusCheatOp_RegConditional = 16,
    /** Save r0..r15 according to the mask in `value`. */
    NxusCheatOp_SaveRegs = 17,
    /** Restore the saved registers selected by the mask in `value`. */
    NxusCheatOp_RestoreRegs = 18,
    /** Load the static registers from the program's static block (unused, reserved). */
    NxusCheatOp_StaticRegs = 19,
    /** Skip the rest of the block for this tick. */
    NxusCheatOp_Pause = 20,
    /** Resume after a Pause. */
    NxusCheatOp_Resume = 21,
    /** `(value & keys_held) == value` else jump to `target`. */
    NxusCheatOp_KeypressConditional = 22,
} NxusCheatOp;

/**
 * Address contract
 * ----------------
 * The PC resolves `region + offset` to a **final absolute address** before uploading
 * (it knows main/heap/alias/aslr from `nxus metadata`).  `region` travels along so the
 * console can still validate it, but the interpreter adds no base.  Safety comes from
 * identity instead: the program carries `build_id`/`program_id`, the server refuses to
 * run it for any other target, and a restart bumps the dmnt incarnation and stops it.
 *
 * Instructions are **linked**: every branch target is an instruction index, so the
 * console never needs an assembler or a linker.
 */
typedef struct NXUS_PACKED {
    u16 op;      /**< NxusCheatOp */
    u8 width;    /**< 1/2/4/8, 0 when unused */
    u8 region;   /**< NxusCheatRegion */
    u8 cmp;      /**< NxusCheatCmp / NxusCheatArith */
    u8 reg_a;
    u8 reg_b;
    u8 flags;    /**< opcode specific (Atmosphere bit for increment/offset register) */
    u32 target;  /**< linked branch target (instruction index) */
    u32 address; /**< low 32 bits of the address (see the contract below) */
    u64 value;   /**< immediate / mask / high part of the address */
} NxusCheatInsn;

typedef struct NXUS_PACKED {
    u32 index;
    u32 mode;    /**< 0 = patch (run once on enable), 1 = loop (every tick) */
    u32 first;   /**< first instruction index */
    u32 count;   /**< instruction count */
    u32 enabled; /**< upload-time enable request */
    u32 reserved;
} NxusCheatBlockDesc;

typedef struct NXUS_PACKED {
    u32 magic;   /**< NXUS_CHEATVM_MAGIC */
    u32 version; /**< NXUS_CHEATVM_VERSION */
    u64 build_id;
    u64 program_id;
    u32 block_count;
    u32 insn_count;
    u32 total_bytes; /**< header + blocks + instructions */
    u32 reserved;
} NxusCheatProgramHeader;

NXUS_STATIC_ASSERT(sizeof(NxusCheatInsn) == 24, "NxusCheatInsn must be 24 bytes");
NXUS_STATIC_ASSERT(sizeof(NxusCheatBlockDesc) == 24, "NxusCheatBlockDesc must be 24 bytes");
NXUS_STATIC_ASSERT(sizeof(NxusCheatProgramHeader) == 40, "NxusCheatProgramHeader must be 40 bytes");

/* ---- memory access ------------------------------------------------------- */

/**
 * The console side of the interpreter.  `read` and `write` return 0 on success and a
 * negative value on failure; `allow_rx` is set when the program patches code, exactly
 * like the PC writer's `NXUS_WRITE_FLAG_ALLOW_RX`.
 */
typedef struct NxusCheatIo {
    void *user;
    int (*read)(void *user, u64 address, void *out, u32 size);
    int (*write)(void *user, u64 address, const void *data, u32 size, bool allow_rx);
} NxusCheatIo;

/* ---- journal (declared here so the interpreter API can take one) -------- */

typedef struct NxusCheatJournal NxusCheatJournal;

/* ---- program storage ----------------------------------------------------- */

/**
 * Allocator hook for the instruction array.
 *
 * nxusCheatInstall allocates `insn_count * sizeof(NxusCheatInsn)` bytes and
 * nxusCheatProgramRelease frees them again.  The default is malloc/free; the hook
 * exists so host tests can inject an allocation failure (and count calls) without
 * touching the shipped behaviour.  A program remembers the free function that
 * matches the allocator that produced its buffer, so restoring the default while a
 * program is still installed cannot mismatch them.
 *
 * Passing NULL for either function restores the default.  Do not change the hooks
 * concurrently with an install or release.
 */
typedef void *(*NxusCheatAllocFn)(size_t size, void *user);
typedef void (*NxusCheatFreeFn)(void *ptr, void *user);

void nxusCheatSetAllocator(NxusCheatAllocFn alloc, NxusCheatFreeFn release, void *user);

typedef struct NxusCheatBlockState {
    bool enabled;
    bool ran_once;   /**< a patch block has been applied for the current enable */
    u32 execs;
    u32 last_error;  /**< 0, or the result of the last failure */
    u32 error_pc;
} NxusCheatBlockState;

/**
 * Program storage.
 *
 * The instruction array lives on the heap, sized exactly to the installed
 * program, so a write-once patch does not reserve room for a 20 000-instruction
 * loop.  `blocks` and `state` are only 24 B + 16 B per entry, so they stay inline.
 *
 * Ownership: `nxusCheatInstall` (re)allocates `insns`; `nxusCheatReset` empties the
 * program but DOES NOT free it; `nxusCheatProgramRelease` is the only function that
 * frees it.  Every successful install must be paired with a release when the
 * program is dropped, and a program must be initialised with nxusCheatProgramInit
 * (or static zero-initialisation) before its first install/reset.
 */
typedef struct NxusCheatProgram {
    NxusCheatProgramHeader header;
    NxusCheatBlockDesc blocks[NXUS_CHEATVM_MAX_BLOCKS];
    NxusCheatInsn *insns;        /**< heap array of `insn_capacity` instructions, or NULL */
    u32 insn_capacity;           /**< instruction slots actually allocated at `insns` */
    NxusCheatFreeFn insns_free;  /**< free() matching the allocator that produced `insns` */
    void *insns_free_user;       /**< user pointer captured with `insns_free` */
    NxusCheatBlockState state[NXUS_CHEATVM_MAX_BLOCKS];
    u32 registers[16];
    u32 saved_registers[16];
    u64 keys_held;
    bool paused;
    u32 tick_count;
} NxusCheatProgram;

/**
 * Initialise fresh (uninitialised) program storage to the empty, releasable state.
 *
 * This zeroes the struct; it does not free anything, so calling it on a program
 * that still owns an instruction buffer leaks that buffer - call
 * nxusCheatProgramRelease first in that case.
 */
void nxusCheatProgramInit(NxusCheatProgram *program);

/**
 * Free the heap instruction array and return the program to the empty state.
 *
 * Idempotent and safe on a zero-initialised / already-released program (`insns`
 * NULL is a no-op), so it may be called on every teardown path.  This is the only
 * function that releases the instruction storage.
 */
void nxusCheatProgramRelease(NxusCheatProgram *program);

/**
 * Reset a program to "empty, nothing enabled".
 *
 * The heap instruction array (if any) is kept for reuse: this function deliberately
 * does not free it.  Releasing it is nxusCheatProgramRelease's job.
 */
void nxusCheatReset(NxusCheatProgram *program);

/**
 * Validate and install a wire program.
 *
 * Checks the magic/version/size, that every block's instruction range is inside the
 * program, and that every branch target points at a valid instruction.  Once the
 * checks pass it allocates `insn_count * sizeof(NxusCheatInsn)` bytes, copies the
 * instructions there and swaps the new buffer in (the previous buffer, if any, is
 * freed only after the allocation succeeded, so a re-install never leaks and a
 * failed allocation leaves the installed program untouched).
 *
 * Returns 0 on success, a negative value otherwise (`-1` bad magic, `-2` bad size,
 * `-3` bad block, `-4` bad branch target, `-5` too many instructions, `-9` no
 * memory for the instruction array).
 */
int nxusCheatInstall(NxusCheatProgram *program, const void *wire, size_t length);

/** Enable or disable one block.  Enabling a patch block makes it run on the next tick. */
int nxusCheatSetEnabled(NxusCheatProgram *program, u32 index, bool enabled);

/**
 * Run every enabled block once.
 *
 * `keys_held` is the live HID mask (already ORed across pads).  Patch blocks run only
 * once per enable; loop blocks run every call.  Returns the number of blocks that ran.
 */
u32 nxusCheatTick(NxusCheatProgram *program, const NxusCheatIo *io, u64 keys_held,
                  NxusCheatJournal *journal);

/**
 * Run one block (exposed for tests and for the "run now" button).
 * Returns 0 on success, or the interpreter error (`NXUS_CHEATVM_ERR_*`).
 */
int nxusCheatRunBlock(NxusCheatProgram *program, u32 index, const NxusCheatIo *io, u64 keys_held,
                      NxusCheatJournal *journal);

/* ---- interpreter errors -------------------------------------------------- */

#define NXUS_CHEATVM_OK 0
#define NXUS_CHEATVM_ERR_BAD_PROGRAM (-1)
#define NXUS_CHEATVM_ERR_BAD_BLOCK (-2)
#define NXUS_CHEATVM_ERR_BAD_TARGET (-3)
#define NXUS_CHEATVM_ERR_STEP_LIMIT (-4)
#define NXUS_CHEATVM_ERR_READ (-5)
#define NXUS_CHEATVM_ERR_WRITE (-6)
#define NXUS_CHEATVM_ERR_BAD_REGISTER (-7)
#define NXUS_CHEATVM_ERR_BAD_OPCODE (-8)
#define NXUS_CHEATVM_ERR_NO_MEMORY (-9)
/** The restore journal is at NXUS_CHEATVM_MAX_JOURNAL and could not grow.
 *
 *  Separate from ERR_WRITE on purpose: "the program is wrong / the target refused
 *  the store" and "the console ran out of journal" need different reactions (fix
 *  the code vs. free the journal / restart), and the server turns this one into
 *  NXUS_REASON_JOURNAL_FULL instead of the generic "argument outside range". */
#define NXUS_CHEATVM_ERR_JOURNAL_FULL (-10)

/* ---- journal (original bytes, for Panic Restore without a PC) ------------ */

typedef struct NxusCheatJournalEntry {
    u64 address;
    u8 original[8];
    u8 width;
    u8 owners; /**< number of blocks that patched this address; 0 = dead slot */
    u8 reserved[2];
} NxusCheatJournalEntry;

/**
 * Restore journal: the original bytes of every address the engine patched.
 *
 * The entry array is a HEAP array, exactly like NxusCheatProgram.insns: the old
 * fixed `entries[512]` made the 513th distinct address fail to write, and because
 * a failed restore kept the journal, the console stayed unable to apply ANY cheat
 * until it was rebooted.  The array therefore starts at the capacity the service
 * asks for and doubles on demand, up to NXUS_CHEATVM_MAX_JOURNAL.
 *
 * Ownership: nxusCheatJournalInit allocates; nxusCheatJournalReset empties the
 * journal but KEEPS the array for reuse; nxusCheatJournalRelease is the only
 * function that frees it.  A zero-initialised journal (entries NULL, capacity 0)
 * is valid and grows on its first write, so no caller can forget an init and then
 * silently refuse every write.
 */
typedef struct NxusCheatJournal {
    NxusCheatJournalEntry *entries; /**< heap array of `capacity` entries, or NULL */
    u32 count;                      /**< live entries at the front of `entries` */
    u32 capacity;                   /**< slots actually allocated at `entries` */
} NxusCheatJournal;

/**
 * Initialise a journal with `capacity` entry slots (clamped to
 * NXUS_CHEATVM_MAX_JOURNAL).
 *
 * Call it on zero-initialised or released storage: it does NOT free a previous
 * array (that is nxusCheatJournalRelease's job).  Returns NXUS_CHEATVM_OK, or
 * NXUS_CHEATVM_ERR_NO_MEMORY when the initial allocation failed - the journal is
 * still usable in that case, because the first successful remember grows it.
 */
int nxusCheatJournalInit(NxusCheatJournal *journal, u32 capacity);

/**
 * Free the heap entry array and return the journal to the empty state.
 *
 * Idempotent and safe on a zero-initialised / already-released journal, so it may
 * be called on every teardown path.
 */
void nxusCheatJournalRelease(NxusCheatJournal *journal);

/** Empty the journal (count = 0) but KEEP the allocated array for reuse. */
void nxusCheatJournalReset(NxusCheatJournal *journal);

/**
 * Remember the original bytes at `address` before the first write.
 *
 * Returns 0 when the address is (already) journalled and a write may proceed, or a
 * negative value when the block must NOT write:
 *   - NXUS_CHEATVM_ERR_JOURNAL_FULL: the journal is at NXUS_CHEATVM_MAX_JOURNAL
 *     and could not grow (or the allocation failed),
 *   - -1: invalid argument, or the original bytes could not be read.
 *
 * When the journal is full it first compacts entries whose `owners` reached 0
 * (already restored) and only then doubles the capacity, so a single partially
 * failed restore cannot wedge the engine.
 */
int nxusCheatJournalRemember(NxusCheatJournal *journal, const NxusCheatIo *io, u64 address,
                             u32 width, u8 owner);

/**
 * Write every journalled original byte back.
 *
 * Each entry whose write-back SUCCEEDED is removed (owners = 0, then compacted),
 * so the journal only ever keeps addresses that still need restoring and a retry
 * does not rewrite what is already correct.  The array itself is kept for reuse.
 * Returns the number restored, or a negative value when at least one write failed
 * (the failed entries stay journalled so a later call can retry them).
 */
int nxusCheatJournalRestore(NxusCheatJournal *journal, const NxusCheatIo *io, bool allow_rx);

#ifdef __cplusplus
}
#endif
