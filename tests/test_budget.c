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
 *   hit list          = retained capacity * (8 + value_size)
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
 * Expected with the hit list at its cap:
 *   0 slots = 8,052,736 B (7.68 MiB) -> guard is skipped entirely
 *   1 slot  = 8,314,880 B (7.93 MiB) -> allowed
 *   2 slots = 8,577,024 B (8.18 MiB) -> rejected (BUSY)
 * With an empty/reset hit list the same 2 slots are 5,505,024 B (5.25 MiB),
 * so only "two snapshots + a (nearly) full hit list" is refused.
 */
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
    return persistentBytes() +
           (u64)held_slots * oneSlotBytes() +
           hit_bytes +
           (u64)SESSION_CHUNK_BYTES +
           (u64)SESSION_WINDOW_BYTES +
           (u64)SNAPSHOT_CAPTURE_BYTES +
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
    CHECK(sizeof(NxusHitAddress) == 8, "NxusHitAddress is %u B (formula assumes 8)",
          (unsigned)sizeof(NxusHitAddress));
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

    printf("[test] hit list cap = HIT_BUDGET / (8 B address + value_size)\n");
    const u32 widths[4] = { 1u, 2u, 4u, 8u };
    for (u32 i = 0; i < 4; i++) {
        const u64 row = 8u + widths[i];
        const u64 cap = (u64)HIT_BUDGET_BYTES / row;
        CHECK(cap * row <= (u64)HIT_BUDGET_BYTES,
              "u%u: %llu hits * %llu B overflows the hit budget",
              (unsigned)(widths[i] * 8u), (unsigned long long)cap,
              (unsigned long long)row);
        CHECK((cap + 1u) * row > (u64)HIT_BUDGET_BYTES,
              "u%u: cap is not maximal", (unsigned)(widths[i] * 8u));
    }
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
    CHECK(est0 == 8052736ull, "no-snapshot estimate is %llu B (expected 8052736)",
          (unsigned long long)est0);
    CHECK(est1 == 8314880ull, "one-slot estimate is %llu B (expected 8314880)",
          (unsigned long long)est1);
    CHECK(est2 == 8577024ull, "two-slot estimate is %llu B (expected 8577024)",
          (unsigned long long)est2);
    CHECK(est0 <= (u64)BUDGET_BYTES, "no-snapshot estimate exceeds the budget");
    CHECK(est1 <= (u64)BUDGET_BYTES, "one-slot + full hits exceeds the budget");
    CHECK(est2 > (u64)BUDGET_BYTES, "two-slot + full hits did not exceed the budget");
    CHECK(est2 - (u64)BUDGET_BYTES == 188416ull,
          "two-slot overrun is %llu B (expected 188416)",
          (unsigned long long)(est2 - (u64)BUDGET_BYTES));
    CHECK(est2 - est1 == slot, "each held slot adds %llu B, not %llu",
          (unsigned long long)slot, (unsigned long long)(est2 - est1));

    printf("[test] an empty/reset hit list keeps two snapshots inside the budget\n");
    const u64 est2_empty = estimateFor(2, 0);
    CHECK(est2_empty == 5505024ull,
          "two slots with no hits is %llu B (expected 5505024)",
          (unsigned long long)est2_empty);
    CHECK(est2_empty < (u64)BUDGET_BYTES, "two empty slots already exceed the budget");
    CHECK(wouldRejectPtrScan(2, 0) == 0,
          "two snapshots without retained hits must not be refused");

    printf("[test] the guard only fires on the over-budget combination\n");
    CHECK(wouldRejectPtrScan(0, full_hit) == 0,
          "PtrScanBegin without a snapshot must not be refused");
    CHECK(wouldRejectPtrScan(1, full_hit) == 0,
          "one snapshot slot + full hits still fits (7.93 MiB)");
    CHECK(wouldRejectPtrScan(2, full_hit) == 1,
          "2 slots + ptrscan + maximum hit list must be refused");

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
    CHECK(two_slot_fixed == 5505024ull, "two-slot fixed cost is %llu B",
          (unsigned long long)two_slot_fixed);
    CHECK(wouldRejectPtrScan(2, cap_fits * 12u) == 0,
          "u32 hit capacity %llu should still fit", (unsigned long long)cap_fits);
    CHECK(wouldRejectPtrScan(2, cap_over * 12u) == 1,
          "u32 hit capacity %llu should be refused", (unsigned long long)cap_over);

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
