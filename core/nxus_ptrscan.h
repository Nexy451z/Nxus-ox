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
    u32 value_width;    /* 4 for 32-bit titles, 8 for 64-bit titles */
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
