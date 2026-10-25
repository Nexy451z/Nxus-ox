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
 * Pointer width to walk with when the caller does not know it (value_width == 0).
 *
 * A 32-bit title (MHXX and friends) maps everything below 4 GiB and MUST be walked
 * with 4-byte loads: an 8-byte load folds the neighbouring field into the pointer,
 * so no chain is found at all.  A 64-bit title needs 8-byte loads for the opposite
 * reason.  Deciding from the module base alone was wrong on AArch64: ASLR puts the
 * main module below 4 GiB for roughly 1.6% of launches while the heap is randomised
 * independently, so a 64-bit title was walked with 4-byte loads and silently
 * produced zero chains.  The mappings the walk is about to traverse are the real
 * evidence, so:
 *
 *   any mapping ends above 4 GiB   -> 8
 *   every mapping ends below 4 GiB -> 4
 *   no mapping at all              -> main_base >= 4 GiB ? 8 : 4
 *   neither known                  -> 8 (the AArch64 default: guessing wide on a
 *                                     32-bit title finds nothing, guessing narrow
 *                                     on a 64-bit one also finds nothing, but 8 is
 *                                     the common case and never over-reads)
 *
 * main_base is only the auxiliary hint for an empty table; 0 means "unknown" and is
 * ignored (it never forces 4 on its own, which is what the old server-side rule
 * did).  out_max_end is optional and receives the highest mapping end examined, so
 * the caller can log the evidence.  The return value is always 4 or 8.
 */
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
                           with nxusPtrScanAutoWidth() from the region table */
    u32 window_size;    /* bytes read per dereference step (e.g. 0x400) */
    u32 max_reads;      /* hard budget so a scan cannot hang the console */
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
