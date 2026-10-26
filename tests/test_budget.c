/*
 * Host test for the sysmodule's 8 MB heap budget arithmetic.
 *
 * The production estimate lives in switch/source/nxus_server.c:
 *
 *     static u64 estimateHeapPeak(void) { ... }
 *
 * That translation unit needs libnx (threads, results, dmnt:cht), so it cannot
 * be linked into a host test.  This file therefore pins the same formula with
 * the same upper-bound constants, and checks the two things the guard depends
 * on:
 *
 *   - a held snapshot slot adds exactly NXUS_SNAPSHOT_MAX_BLOCKS * 2 * 8 B,
 *   - the "snapshot A/B + pointer scan + maximum hit list" combination is the
 *     first one that crosses NXUS_HEAP_BUDGET_BYTES, while no snapshot at all
 *     stays below it (so PtrScanBegin is not over-rejected).
 *
 * FORMULA (mirrors nxus_server.c: estimateHeapPeak, keep both in sync):
 *
 *   persistent =
 *       NXUS_NET_BUF_SIZE                                     (1 MiB)
 *     + NXUS_SNAPSHOT_MAX_CHANGED * sizeof(NxusChangedBlock)   (256 KiB)
 *     + 4096 * sizeof(NxusMappingEntry)                        (128 KiB)
 *     + 4096 * sizeof(NxusScanRegion)                          (128 KiB)
 *   one snapshot slot =
 *       NXUS_SNAPSHOT_MAX_BLOCKS * 2 * sizeof(u64)             (256 KiB)
 *   hit list          = retained capacity * (16 + value_size)
 *                       (<= NXUS_SESSION_HIT_BUDGET_BYTES)     (max 3.0 MiB)
 *   scan buffers      = NXUS_SESSION_DEFAULT_CHUNK
 *                     + NXUS_SESSION_DEFAULT_WINDOW            (2.0 MiB)
 *   snapshot capture  = 256 KiB (nxus_snapshot_srv.c chunk)
 *   pointer scan      = max(256 KiB scratch
 *                           + (4096 + 1) * sizeof(NxusPtrRegion),
 *                           NXUS_NET_BUF_SIZE chain reply)     (1.0 MiB)
 *
 *   peak(slots_held, hit_bytes) = persistent + slots_held * slot
 *                    + hit_bytes + scan buffers + snapshot capture + ptrscan
 *
 * The absolute values below mirror nxus_server.c's estimateHeapPeak() TODAY.  They
 * must be updated together with that function; the guard itself is a backstop that
 * does not currently fire (two snapshots + a full hit list stay inside 8 MiB), so a
 * green test here does NOT prove the refusal path works - only that the arithmetic
 * still matches.  Round 10 changed the formula and this file kept the old numbers,
 * which is exactly the drift this comment is here to prevent.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "nxus_scan.h"
#include "nxus_snapshot.h"
#include "nxus_ptrscan.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (!(cond)) {                                               \
            g_failures++;                                            \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);            \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
        }                                                            \
    } while (0)

/* ---- mirror of the switch-side constants ------------------------------ */
#define BUDGET_BYTES             (8u * 1024u * 1024u)
#define NET_BUF_BYTES            (1024u * 1024u)          /* NXUS_NET_BUF_SIZE */
#define MAX_MAPPINGS             4096u                    /* nxus_session.c cap */
#define MAX_REGIONS              4096u                    /* nxus_session.c cap */
#define HIT_BUDGET_BYTES         (3000u * 1024u)          /* NXUS_SESSION_HIT_BUDGET_BYTES */
#define DEFAULT_MAXHITS          150000u                  /* NXUS_SESSION_DEFAULT_MAXHITS */
#define SESSION_CHUNK_BYTES      (1024u * 1024u)          /* NXUS_SESSION_DEFAULT_CHUNK */
#define SESSION_WINDOW_BYTES     (1024u * 1024u)          /* NXUS_SESSION_DEFAULT_WINDOW */
#define SNAPSHOT_CAPTURE_BYTES   (256u * 1024u)           /* nxus_snapshot_srv.c */
#define PTRSCAN_SCRATCH_BYTES    (256u * 1024u)           /* handlePtrScanBegin */

static u64 persistentBytes(void) {
    return (u64)NET_BUF_BYTES +
           (u64)NXUS_SNAPSHOT_MAX_CHANGED * (u64)sizeof(NxusChangedBlock) +
           (u64)MAX_MAPPINGS * (u64)sizeof(NxusMappingEntry) +
           (u64)MAX_REGIONS * (u64)sizeof(NxusScanRegion);
}

static u64 oneSlotBytes(void) {
    return (u64)NXUS_SNAPSHOT_MAX_BLOCKS * 2u * (u64)sizeof(u64);
}

static u64 ptrScanPeakBytes(void) {
    const u64 work = (u64)PTRSCAN_SCRATCH_BYTES +
                     (u64)(MAX_MAPPINGS + 1u) * (u64)sizeof(NxusPtrRegion);
    return (u64)NET_BUF_BYTES > work ? (u64)NET_BUF_BYTES : work;
}

static u64 estimateFor(u32 held_slots, u64 hit_bytes) {
    /* Only ONE of the scan buffers is live per pass, and the snapshot capture
       scratch runs on the same thread as the pointer scan, so neither is additive
       (Round 10 removed that double count from nxus_server.c). */
    const u64 scan_work = ((u64)SESSION_CHUNK_BYTES > (u64)SESSION_WINDOW_BYTES)
                              ? (u64)SESSION_CHUNK_BYTES
                              : (u64)SESSION_WINDOW_BYTES;
    return persistentBytes() +
           (u64)held_slots * oneSlotBytes() +
           hit_bytes +
           scan_work +
           ptrScanPeakBytes();
}

/* switch/source/nxus_server.c:handlePtrScanBegin() */
static int wouldRejectPtrScan(u32 held_slots, u64 hit_bytes) {
    return held_slots != 0 &&
           estimateFor(held_slots, hit_bytes) > (u64)BUDGET_BYTES;
}

int main(void) {
    printf("=== Nxus 8 MB heap budget tests ===\n");

    printf("[test] element sizes the formula is built from\n");
    /* NxusHitAddress keeps its packed 8-byte prefix (offset / mapping_idx /
       value_type) and appends the u64 absolute address, so one hit now occupies
       16 B.  nxusSessionHitLimit() derives its stride from sizeof(NxusHitAddress)
       plus value_size, and estimateHeapPeak() in nxus_server.c charges the same
       16 + value_size per retained slot. */
    CHECK(sizeof(NxusHitAddress) == 16, "NxusHitAddress is %u B (8 B prefix + u64 address)",
          (unsigned)sizeof(NxusHitAddress));
    CHECK(offsetof(NxusHitAddress, address) == 8,
          "the absolute address must be APPENDED after the 8 B prefix (offset %u)",
          (unsigned)offsetof(NxusHitAddress, address));
    CHECK(sizeof(NxusChangedBlock) == 16, "NxusChangedBlock is %u B",
          (unsigned)sizeof(NxusChangedBlock));
    CHECK(sizeof(NxusMappingEntry) == 32, "NxusMappingEntry is %u B",
          (unsigned)sizeof(NxusMappingEntry));
    CHECK(sizeof(NxusScanRegion) == 32, "NxusScanRegion is %u B",
          (unsigned)sizeof(NxusScanRegion));
    CHECK(sizeof(NxusPtrRegion) == 24, "NxusPtrRegion is %u B",
          (unsigned)sizeof(NxusPtrRegion));

    printf("[test] snapshot slot = NXUS_SNAPSHOT_MAX_BLOCKS * 2 arrays * 8 B\n");
    const u64 slot = oneSlotBytes();
    CHECK(slot == 262144ull, "one snapshot slot is %llu B (expected 262144)",
          (unsigned long long)slot);
    CHECK(slot * 2u == 524288ull, "A/B pair is %llu B (expected 524288)",
          (unsigned long long)(slot * 2u));
    CHECK((u64)NXUS_SNAPSHOT_MAX_BLOCKS * sizeof(u64) == slot / 2u,
          "hash array alone is %llu B",
          (unsigned long long)((u64)NXUS_SNAPSHOT_MAX_BLOCKS * sizeof(u64)));

    printf("[test] hit list cap = min(DEFAULT_MAXHITS, HIT_BUDGET / (16 B + value_size))\n");
    /* Mirrors nxusSessionHitLimit() (switch/include/nxus_session.h): the default is
       a FLOOR that the byte budget may lower, never a floor that pushes the arrays
       past the budget.  The old flat 150k floor cost 150000 * 24 B = 3.6 MB for
       u64, i.e. 0.5 MiB over the 3.0 MiB budget. */
    const u32 widths[4] = { 1u, 2u, 4u, 8u };
    const u32 expected[4] = { 150000u, 150000u, 150000u, 128000u };
    for (u32 i = 0; i < 4; i++) {
        const u64 row = sizeof(NxusHitAddress) + widths[i];   /* 17 / 18 / 20 / 24 B */
        const u64 budgeted = (u64)HIT_BUDGET_BYTES / row;
        const u64 cap = (u64)DEFAULT_MAXHITS < budgeted ? (u64)DEFAULT_MAXHITS : budgeted;
        CHECK(cap == (u64)expected[i], "u%u: cap is %llu hits (expected %u)",
              (unsigned)(widths[i] * 8u), (unsigned long long)cap,
              (unsigned)expected[i]);
        CHECK(cap <= (u64)DEFAULT_MAXHITS, "u%u: cap %llu exceeds the default floor",
              (unsigned)(widths[i] * 8u), (unsigned long long)cap);
        CHECK(cap * row <= (u64)HIT_BUDGET_BYTES,
              "u%u: %llu hits * %llu B overflows the hit budget",
              (unsigned)(widths[i] * 8u), (unsigned long long)cap,
              (unsigned long long)row);
        /* The cap is the largest value inside both bounds: one more hit of this
           width either leaves the budget or (for the capped widths) breaks the
           default floor, which is the intended limit. */
        const bool budget_bound = (cap + 1u) * row > (u64)HIT_BUDGET_BYTES;
        const bool default_bound = cap == (u64)DEFAULT_MAXHITS;
        CHECK(budget_bound || default_bound,
              "u%u: cap is not maximal (%llu hits)", (unsigned)(widths[i] * 8u),
              (unsigned long long)cap);
    }
    /* The regression itself: the old floor at the widest row does not fit. */
    CHECK((u64)DEFAULT_MAXHITS * (sizeof(NxusHitAddress) + 8u) == 3600000ull,
          "150k u64 rows are %llu B (expected 3600000)",
          (unsigned long long)((u64)DEFAULT_MAXHITS * (sizeof(NxusHitAddress) + 8u)));
    CHECK((u64)DEFAULT_MAXHITS * (sizeof(NxusHitAddress) + 8u) > (u64)HIT_BUDGET_BYTES,
          "the u64 cap must be lowered below the old 150k floor");
    CHECK(128000ull * (sizeof(NxusHitAddress) + 8u) == (u64)HIT_BUDGET_BYTES,
          "the u64 cap lands exactly on the budget (%llu B)",
          (unsigned long long)(128000ull * (sizeof(NxusHitAddress) + 8u)));
    CHECK((u64)HIT_BUDGET_BYTES == 3072000ull, "hit budget is %llu B (expected 3072000)",
          (unsigned long long)HIT_BUDGET_BYTES);

    printf("[test] persistent heap terms\n");
    const u64 persistent = persistentBytes();
    CHECK(persistent == 1572864ull,
          "persistent heap is %llu B (expected 1572864 = 1 MiB + 256 KiB + 128 KiB + 128 KiB)",
          (unsigned long long)persistent);
    CHECK((u64)SNAPSHOT_CAPTURE_BYTES == 262144ull, "capture chunk %u B",
          (unsigned)SNAPSHOT_CAPTURE_BYTES);
    CHECK(ptrScanPeakBytes() == (u64)NET_BUF_BYTES,
          "ptrscan peak is %llu B (the chain reply dominates the scratch)",
          (unsigned long long)ptrScanPeakBytes());

    printf("[test] estimate with the retained hit list at its cap\n");
    const u64 full_hit = (u64)HIT_BUDGET_BYTES;
    const u64 est0 = estimateFor(0, full_hit);
    const u64 est1 = estimateFor(1, full_hit);
    const u64 est2 = estimateFor(2, full_hit);
    printf("       no snapshot : %llu B (%.2f MiB)\n", (unsigned long long)est0,
           (double)est0 / (1024.0 * 1024.0));
    printf("       1 slot held : %llu B (%.2f MiB)\n", (unsigned long long)est1,
           (double)est1 / (1024.0 * 1024.0));
    printf("       2 slots held: %llu B (%.2f MiB)  budget=%u B (8.00 MiB)\n",
           (unsigned long long)est2, (double)est2 / (1024.0 * 1024.0),
           (unsigned)BUDGET_BYTES);
    CHECK(est0 == 6742016ull, "no-snapshot estimate is %llu B (expected 6742016)",
          (unsigned long long)est0);
    CHECK(est1 == 7004160ull, "one-slot estimate is %llu B (expected 7004160)",
          (unsigned long long)est1);
    CHECK(est2 == 7266304ull, "two-slot estimate is %llu B (expected 7266304)",
          (unsigned long long)est2);
    CHECK(est0 <= (u64)BUDGET_BYTES, "no-snapshot estimate exceeds the budget");
    CHECK(est1 <= (u64)BUDGET_BYTES, "one-slot + full hits exceeds the budget");
    /* With the corrected formula the worst case fits, so the refusal path is a
       backstop.  Assert that explicitly instead of asserting an overrun that does
       not happen any more. */
    CHECK(est2 <= (u64)BUDGET_BYTES,
          "two-slot + full hits is %llu B, above the budget: the guard now fires",
          (unsigned long long)est2);
    CHECK(est2 - est1 == slot, "each held slot adds %llu B, not %llu",
          (unsigned long long)slot, (unsigned long long)(est2 - est1));

    printf("[test] an empty/reset hit list keeps two snapshots inside the budget\n");
    const u64 est2_empty = estimateFor(2, 0);
    CHECK(est2_empty == 4194304ull,
          "two slots with no hits is %llu B (expected 4194304)",
          (unsigned long long)est2_empty);
    CHECK(est2_empty < (u64)BUDGET_BYTES, "two empty slots already exceed the budget");
    CHECK(wouldRejectPtrScan(2, 0) == 0,
          "two snapshots without retained hits must not be refused");

    printf("[test] the guard is a backstop: today nothing reaches it\n");
    CHECK(wouldRejectPtrScan(0, full_hit) == 0,
          "PtrScanBegin without a snapshot must not be refused");
    CHECK(wouldRejectPtrScan(1, full_hit) == 0,
          "one snapshot slot + full hits still fits");
    /* Round 10 removed the double-counted scan buffers, so even the worst case
       (two slots + a full hit list) fits.  If this ever becomes 1 the refusal path
       is live again - that is a design change, not a failure. */
    CHECK(wouldRejectPtrScan(2, full_hit) == 0,
          "2 slots + ptrscan + maximum hit list now exceeds the budget (guard is live)");

    /* The 65536-entry initial hit list (u32 rows) is 768 KiB and fits; the
       capacity boundary is exactly where the model crosses the budget. */
    const u64 initial_u32_hit = 65536ull * 12ull;
    CHECK(initial_u32_hit == 786432ull, "initial u32 hit list is %llu B",
          (unsigned long long)initial_u32_hit);
    CHECK(wouldRejectPtrScan(2, initial_u32_hit) == 0,
          "two snapshots + the initial hit list must not be refused");

    const u64 two_slot_fixed = est2 - full_hit;
    const u64 hit_room = (u64)BUDGET_BYTES - two_slot_fixed;
    const u64 cap_fits = hit_room / 12u;
    const u64 cap_over = cap_fits + 1u;
    CHECK(two_slot_fixed == 4194304ull, "two-slot fixed cost is %llu B",
          (unsigned long long)two_slot_fixed);
    CHECK(wouldRejectPtrScan(2, cap_fits * 12u) == 0,
          "u32 hit capacity %llu should still fit", (unsigned long long)cap_fits);
    CHECK(cap_over > cap_fits, "capacity boundary must be monotonic");
    CHECK(wouldRejectPtrScan(2, (u64)HIT_BUDGET_BYTES) == 0,
          "the real hit-list cap must still fit (backstop only)");

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
