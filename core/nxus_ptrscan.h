/*
 * Nxus pointer scan + Atmosphère cheat code generation (portable core).
 *
 * Why this exists
 * ---------------
 * A heap address like MHXX's 0x42CA1DC4 moves between sessions, so a cheat that
 * writes it directly cannot be permanent.  What survives is a *chain* of
 * pointers that starts in the module's static data (.data/.bss) and ends at the
 * value.  This module finds such chains and turns them into Atmosphère cheat
 * codes.
 *
 * Encoding reference (Atmosphere docs/features/cheats.md, verified):
 *   0x5: 5TMR00AA AAAAAAAA          load from region base + offset   (T = width)
 *        5T0R10AA AAAAAAAA          load from register + offset
 *   0x7: 7T0RC000 VVVVVVVV          arithmetic (C = 0 add)
 *   0x6: 6T0RIor0 VVVVVVVV VVVVVVVV store immediate to [register]
 *
 * For a 32-bit title the loads must use T=4 (540F...), otherwise the 8-byte read
 * pulls in the neighbouring field.
 */
#pragma once

#include "nxus_scan.h"

#define NXUS_PTRSCAN_MAX_DEPTH 8

/* Region kinds. */
#define NXUS_PTRREGION_STATIC       0u   /* module .data/.bss - where chains may root */
#define NXUS_PTRREGION_TRAVERSABLE  1u   /* heap / other memory a chain may walk through */

typedef struct {
    u64 base;
    u64 size;
    u32 kind;        /* NXUS_PTRREGION_* */
    u32 reserved;
} NxusPtrRegion;

/*
 * The target process's own bitness, as far as the caller can tell.  This is the
 * ground truth the pointer-width inference prefers over any address-space
 * evidence: the address space of a 64-bit title is not a property of *this*
 * launch (AArch64 ASLR routinely places the main module - and sometimes the whole
 * low heap - below 4 GiB, e.g. main 0x00700000 / heap 0x36000000), while a 32-bit
 * title can never hold a pointer above 4 GiB.
 *
 * UNKNOWN is not a synonym for AArch32: it means "nobody told us", which must fall
 * back to the mappings instead of forcing 4-byte loads.
 */
typedef enum {
    NXUS_PTRSCAN_ARCH_UNKNOWN = 0,   /* no debug session / no metadata answer */
    NXUS_PTRSCAN_ARCH_AARCH32 = 1,   /* 32-bit process: 4-byte pointers */
    NXUS_PTRSCAN_ARCH_AARCH64 = 2,   /* 64-bit process: 8-byte pointers */
} NxusPtrScanArch;

/* Reason strings the width came from, for logging ("width auto = 8 (process is
   64-bit)").  Static storage: never freed, safe to log without copying. */
#define NXUS_PTRSCAN_WIDTH_REASON_PROCESS64 "process is 64-bit"
#define NXUS_PTRSCAN_WIDTH_REASON_PROCESS32 "process is AArch32"
#define NXUS_PTRSCAN_WIDTH_REASON_MAPPINGS  "mapping ends"

/* Derive the process architecture from the size of its address space (dmnt's
   CheatProcessMetadata aslr_base/aslr_size, or the equivalent from another
   metadata source).  This is the second-best evidence after an explicit flag: the
   kernel gives AArch32 processes 0x200000 + 0xFFE00000 (ending exactly at 4 GiB)
   and AArch64 processes 0x8000000 + 0x7FF8000000 (512 GiB), so the address-space
   size answers the question even though the metadata carries no architecture bit.
   Anything inconsistent (zero size, or a region that straddles the 4 GiB boundary)
   yields NXUS_PTRSCAN_ARCH_UNKNOWN, never a guess. */
NxusPtrScanArch nxusPtrScanArchFromAddressSpace(u64 aslr_base, u64 aslr_size);

/*
 * Pointer width to walk with when the caller does not know it (value_width == 0).
 *
 * A 32-bit title (MHXX and friends) must be walked with 4-byte loads: an 8-byte
 * load folds the neighbouring field into the pointer, so no chain is found at
 * all.  A 64-bit title needs 8-byte loads for the opposite reason.
 *
 * Priority, highest first:
 *
 *   1. process_arch != UNKNOWN -> 8 for AARCH64, 4 for AARCH32.  The process's
 *      own architecture outranks every address-space observation: a 64-bit title
 *      whose main module and heap both sit below 4 GiB (a real AArch64 ASLR
 *      outcome, and the mock fixture the old rule failed on) still walks with
 *      8-byte loads, and a 32-bit title is never guessed wide.
 *      On the console the caller supplies this from the process metadata: the
 *      debug session's CreateProcess flag (nxusDebugTargetIs64Bit()/Known()) when
 *      attached, otherwise dmnt's CheatProcessMetadata, whose ASLR region size is
 *      the process's address space size (> 4 GiB can only be AArch64, a region
 *      inside 4 GiB can only be AArch32).  A caller that has no metadata passes
 *      UNKNOWN and gets the mapping rule below.
 *   2. No answer from the process -> the mappings the walk is about to traverse:
 *        any mapping ends above 4 GiB   -> 8
 *        every mapping ends below 4 GiB -> 4
 *        no mapping at all              -> main_base >= 4 GiB ? 8 : 4
 *        neither known                  -> 8 (AArch64 default: guessing wide on a
 *                                          32-bit title finds nothing, guessing
 *                                          narrow on a 64-bit one also finds
 *                                          nothing, but 8 is the common case and
 *                                          never over-reads)
 *
 * main_base is only the auxiliary hint for an empty table; 0 means "unknown" and is
 * ignored (it never forces 4 on its own, which is what the old server-side rule
 * did).  out_max_end is optional and receives the highest mapping end examined;
 * out_reason is optional and receives one of the NXUS_PTRSCAN_WIDTH_REASON_*
 * strings (never NULL when set).  The return value is always 4 or 8.
 */
u32 nxusPtrScanAutoWidthFor(const NxusPtrRegion *regions, u32 region_count,
                            u64 main_base, NxusPtrScanArch process_arch,
                            u64 *out_max_end, const char **out_reason);

/* Same, with no process-architecture evidence (the historical rule).  Kept for
   callers that genuinely know nothing about the process. */
u32 nxusPtrScanAutoWidth(const NxusPtrRegion *regions, u32 region_count,
                         u64 main_base, u64 *out_max_end);

typedef struct {
    u64 root_address;                      /* static address holding the first pointer */
    u32 root_offset;                       /* root_address - module base */
    u32 steps[NXUS_PTRSCAN_MAX_DEPTH];     /* intermediate dereference offsets */
    u32 step_count;
    u32 final_offset;                      /* added after the last dereference */
} NxusPtrChain;

typedef struct {
    u32 max_depth;      /* 1..NXUS_PTRSCAN_MAX_DEPTH (1 = static -> value directly) */
    u32 max_offset;     /* how far a pointer value may be from its target */
    u32 max_results;
    u32 value_width;    /* 4 for 32-bit titles, 8 for 64-bit titles, 0 = infer it
                           with nxusPtrScanAutoWidthFor() from the region table
                           (and process_arch below) */
    u32 window_size;    /* bytes read per dereference step (e.g. 0x400) */
    u32 max_reads;      /* hard budget so a scan cannot hang the console */
    /* NxusPtrScanArch: the target process's own bitness when the caller knows it
       (0 = unknown).  Only consulted when value_width == 0, where it outranks the
       mapping ends - see nxusPtrScanAutoWidthFor().  A struct tail field, so an
       existing caller that zero-initialises keeps the historical behaviour. */
    u32 process_arch;
} NxusPtrScanOptions;

typedef struct {
    u64 reads;
    u64 bytes_read;
    u64 roots_examined;
    /* Dereferences skipped because max_reads was reached.  Exposed so callers
       (and tests) can tell "budget exhausted, tried again, still skipped" apart
       from "the address is genuinely unmapped": a skipped read is never
       memoized as a dead end. */
    u64 reads_blocked;
    /* Set when the chain list is not exhaustive:
       - max_results was hit (chains were found but could not be stored), or
       - max_reads ran out (some subtrees were skipped unread, so chains behind
         them may exist and were not found).
       Chains that were stored are always valid; `truncated` only says that more
       may exist.  It is the flag the server forwards to the PC
       (nxus_server.c: NxusPtrChainListHeader.truncated), so a client must not
       present an empty list as a definite answer when it is set. */
    u32 truncated;
} NxusPtrScanStats;

/*
 * Find pointer chains that reach target_address.  Reads go through the same
 * callback the scan engine uses, so this runs on the host (tests) and on the
 * Switch (dmnt:cht) unchanged.
 *
 * Contract for the read budget (options->max_reads): when the budget runs out
 * the scan keeps going but skips the unread subtrees as if they were unmapped,
 * returns every chain it already found, and reports stats->truncated = 1.  A
 * budget-starved dereference is never memoized as a dead end, so a later scan
 * (or a later visit in the same scan) can still read that address.
 */
int nxusPtrScan(const NxusPtrRegion *regions, u32 region_count,
                u64 target_address, u64 module_base,
                const NxusPtrScanOptions *options,
                NxusPtrChain *out, u32 max_out, u32 *out_count,
                NxusReadFn read, void *read_ctx,
                u8 *scratch, u32 scratch_size,
                NxusPtrScanStats *stats, int *cancel);

/*
 * Render an Atmosphère cheat code block for a chain.
 *   is_32bit: use 4-byte loads (required for 32-bit titles)
 *   value:    the value to write on every frame
 * Returns the number of bytes written (excluding the NUL).
 */
int nxusCheatGenerate(const NxusPtrChain *chain, int is_32bit,
                      u64 value, u32 value_width,
                      const char *label, char *out, size_t out_size);

/* Render just the pointer chain part (no final write) - useful for 780F-style
   address exports and for pasting into other tools. */
int nxusCheatGeneratePointer(const NxusPtrChain *chain, int is_32bit,
                             const char *label, char *out, size_t out_size);

/* Direct (non-pointer) write code: 0TMR00AA AAAAAAAA VVVVVVVV */
int nxusCheatGenerateAbsoluteWrite(u64 address, u32 region, u64 value, u32 value_width,
                                   const char *label, char *out, size_t out_size);
