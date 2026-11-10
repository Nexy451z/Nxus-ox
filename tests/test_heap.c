/*
 * Host tests for the sysmodule heap accounting and the resident-size constants it
 * is built on.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The 8 MiB inner heap is shared by the client connections, the scan engine and the
 * Unknown-scan baseline store, so the per-connection sizes and the RAM budget are
 * load-bearing numbers: one of them drifting back up reintroduces "heap exhausted at
 * boot" without breaking any functional test.  The shipped headers/helpers are
 * included directly (not copied) so a change to the constants or to the budget
 * formula is a test failure here.
 *
 * Covered:
 *   (a) transport sizes: a connection is 24 KiB stack + 32 KiB idle rx (with the
 *       historic 32 KiB 4 KiB-aligned stack retry), the 1 MiB frame ceiling and the
 *       4 MiB total rx ceiling are unchanged, and both stack sizes stay page aligned;
 *   (b) the RAM baseline budget: min(4 MiB, free/3) - shrinks with the free heap,
 *       never exceeds the historic ceiling, is 0 when nothing is measurable, and a
 *       0-free heap therefore sends the store to the SD card;
 *   (c) the boot warning threshold (512 KiB);
 *   (d) the host fallback: no sysmodule heap -> free/used/used-KiB read 0 (which is
 *       what makes the policy in (b) take its documented "no RAM budget" path),
 *       and the logging helpers are link-free no-ops so a Switch .c that calls them
 *       still builds on the host.
 */
#include <stdint.h>
#include <stdio.h>

#include "../shared/nxus_heap.h"
#include "../shared/nxus_net.h"

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond, ...) do {                                            \
        g_checks++;                                                      \
        if (!(cond)) {                                                   \
            g_failures++;                                                \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                \
            printf(__VA_ARGS__);                                         \
            printf("\n");                                                \
        }                                                                \
    } while (0)

/* ====================================================================== */
/* (a) transport sizes                                                     */
/* ====================================================================== */

static void testTransportSizes(void) {
    printf("- transport: per-connection stack and idle rx buffer\n");

    /* The resident cost of an idle connection is these two allocations.  The old
       numbers (32 KiB stack + 128 KiB rx) are pinned as an upper bound: growing
       either back to them must fail here instead of silently eating the heap. */
    CHECK(NXUS_NET_CLIENT_STACK_SIZE == 24u * 1024u,
          "the connection stack is 24 KiB (%u)", (unsigned)NXUS_NET_CLIENT_STACK_SIZE);
    CHECK(NXUS_NET_CLIENT_STACK_FALLBACK_SIZE == 32u * 1024u,
          "the stack retry is the historic 32 KiB (%u)",
          (unsigned)NXUS_NET_CLIENT_STACK_FALLBACK_SIZE);
    CHECK(NXUS_NET_RX_IDLE_SIZE == 32u * 1024u,
          "the idle receive buffer is 32 KiB (%u)", (unsigned)NXUS_NET_RX_IDLE_SIZE);

    /* threadCreate() requires page-aligned memory; both stack sizes are 4 KiB
       multiples, which is what makes aligned_alloc(0x1000, size) legal. */
    CHECK((NXUS_NET_CLIENT_STACK_SIZE % 0x1000u) == 0,
          "the 24 KiB stack is 4 KiB aligned");
    CHECK((NXUS_NET_CLIENT_STACK_FALLBACK_SIZE % 0x1000u) == 0,
          "the 32 KiB retry is 4 KiB aligned");
    CHECK(NXUS_NET_CLIENT_STACK_SIZE <= NXUS_NET_CLIENT_STACK_FALLBACK_SIZE,
          "the retry stack is not smaller than the ship stack");

    /* The idle buffer must stay well below the 1 MiB frame ceiling, and a big frame
       must still be able to grow to it. */
    CHECK(NXUS_NET_RX_IDLE_SIZE < NXUS_NET_BUF_SIZE,
          "the idle rx buffer (%u) stays below the frame ceiling (%u)",
          (unsigned)NXUS_NET_RX_IDLE_SIZE, (unsigned)NXUS_NET_BUF_SIZE);
    CHECK(NXUS_NET_BUF_SIZE == 1024u * 1024u,
          "the frame/receive ceiling is still 1 MiB (%u)", (unsigned)NXUS_NET_BUF_SIZE);

    /* Four idle clients: 128 KiB of buffers + 96 KiB of stacks.  The previous
       numbers were 512 KiB + 128 KiB, so this is the reduction the change is for. */
    CHECK((uint64_t)NXUS_NET_MAX_CLIENTS * NXUS_NET_RX_IDLE_SIZE == 128u * 1024u,
          "four idle clients hold 128 KiB of rx buffers");
    CHECK((uint64_t)NXUS_NET_MAX_CLIENTS * NXUS_NET_CLIENT_STACK_SIZE == 96u * 1024u,
          "four connection stacks hold 96 KiB");

    /* The worst case (every client at a 1 MiB frame) must stay inside the 8 MiB
       heap, exactly as the header documents. */
    CHECK((uint64_t)NXUS_NET_MAX_CLIENTS * NXUS_NET_BUF_SIZE == 4u * 1024u * 1024u,
          "the rx ceiling is still 4 MiB for four clients");
}

/* ====================================================================== */
/* (b) RAM baseline budget                                                 */
/* ====================================================================== */

static void testBaselineBudget(void) {
    printf("- baseline store: RAM budget = min(4 MiB, free / 3)\n");

    /* Nothing measurable (host build, or a heap that is completely used up): no RAM
       budget at all, which is exactly the "stream to the SD card" decision. */
    CHECK(nxusHeapBaselineRamLimit(0) == 0,
          "a 0-free heap has no RAM budget (%llu)",
          (unsigned long long)nxusHeapBaselineRamLimit(0));

    /* A third of what is free while that is below the ceiling. */
    CHECK(nxusHeapBaselineRamLimit(3u * 1024u) == 1u * 1024u,
          "3 KiB free -> a 1 KiB budget");
    CHECK(nxusHeapBaselineRamLimit(3u * 1024u * 1024u) == 1u * 1024u * 1024u,
          "3 MiB free -> a 1 MiB budget");
    CHECK(nxusHeapBaselineRamLimit(8u * 1024u * 1024u) == (8u * 1024u * 1024u) / 3u,
          "8 MiB free -> an 8/3 MiB budget");

    /* The historic 4 MiB ceiling still caps a large heap. */
    CHECK(nxusHeapBaselineRamLimit(12u * 1024u * 1024u) == NXUS_HEAP_BASELINE_RAM_MAX,
          "12 MiB free -> the 4 MiB ceiling");
    CHECK(nxusHeapBaselineRamLimit(NXUS_HEAP_BASELINE_RAM_MAX * 3u) ==
              NXUS_HEAP_BASELINE_RAM_MAX,
          "the ceiling is reached at exactly 3x NXUS_HEAP_BASELINE_RAM_MAX");
    CHECK(NXUS_HEAP_BASELINE_RAM_MAX == 4u * 1024u * 1024u,
          "the ceiling is 4 MiB (%llu)",
          (unsigned long long)NXUS_HEAP_BASELINE_RAM_MAX);
    CHECK(nxusHeapBaselineRamLimit(64u * 1024u * 1024u) == NXUS_HEAP_BASELINE_RAM_MAX,
          "a bigger heap does not raise the ceiling");

    /* The budget never takes more than the free heap: a third of it, in fact, so the
       hit list / scan buffers / connections keep two thirds. */
    {
        static const uint64_t frees[] = {
            0u, 1u, 1024u, 100u * 1024u, 1024u * 1024u, 6u * 1024u * 1024u,
            8u * 1024u * 1024u, 100u * 1024u * 1024u,
        };
        uint64_t previous = 0;
        for (unsigned i = 0; i < (unsigned)(sizeof(frees) / sizeof(frees[0])); i++) {
            const uint64_t free_bytes = frees[i];
            const uint64_t limit = nxusHeapBaselineRamLimit(free_bytes);
            CHECK(limit <= free_bytes,
                  "the budget (%llu) never exceeds the free heap (%llu)",
                  (unsigned long long)limit, (unsigned long long)free_bytes);
            CHECK(limit <= free_bytes / 3u || limit == NXUS_HEAP_BASELINE_RAM_MAX,
                  "the budget respects the free/3 share (%llu of %llu)",
                  (unsigned long long)limit, (unsigned long long)free_bytes);
            CHECK(limit >= previous,
                  "the budget does not shrink as the heap grows (%llu -> %llu)",
                  (unsigned long long)previous, (unsigned long long)limit);
            previous = limit;
        }
    }

    /* The decision helper: 0 free never fits anything (SD path), a 4 MiB scope only
       fits once 12 MiB are free, and an empty scope never opens a store. */
    CHECK(!nxusHeapBaselineFitsRam(0, 4u * 1024u * 1024u),
          "no free heap -> a 4 MiB scope does not fit (SD card)");
    CHECK(!nxusHeapBaselineFitsRam(0, 1u),
          "no free heap -> nothing fits");
    CHECK(!nxusHeapBaselineFitsRam(6u * 1024u, 4u * 1024u * 1024u),
          "a 2 MiB budget does not fit a 4 MiB scope");
    CHECK(nxusHeapBaselineFitsRam(12u * 1024u * 1024u, 4u * 1024u * 1024u),
          "a 12 MiB free heap fits the 4 MiB ceiling");
    CHECK(nxusHeapBaselineFitsRam(96u * 1024u, 32u * 1024u),
          "a 96 KiB free heap fits a 32 KiB scope");
    CHECK(!nxusHeapBaselineFitsRam(12u * 1024u * 1024u, 0),
          "an empty scope never opens a store");
}

/* ====================================================================== */
/* (c) boot warning threshold                                              */
/* ====================================================================== */

static void testBootThreshold(void) {
    printf("- boot: the warning threshold is 512 KiB\n");
    CHECK(NXUS_HEAP_BOOT_WARN_FREE == 512u * 1024u,
          "the boot warning fires below 512 KiB (%llu)",
          (unsigned long long)NXUS_HEAP_BOOT_WARN_FREE);
    /* The threshold must leave room for the connection this module refuses work at:
       one stack + one idle rx buffer. */
    CHECK(NXUS_HEAP_BOOT_WARN_FREE >
              (uint64_t)NXUS_NET_CLIENT_STACK_SIZE + NXUS_NET_RX_IDLE_SIZE,
          "the warning threshold leaves room for one connection");
}

/* ====================================================================== */
/* (d) host fallback                                                       */
/* ====================================================================== */

static void testHostFallback(void) {
    printf("- host build: no sysmodule heap -> 0, and the log helpers are no-ops\n");
    CHECK(nxusHeapFreeBytes() == 0,
          "the host has no heap measurement (%llu)",
          (unsigned long long)nxusHeapFreeBytes());
    CHECK(nxusHeapUsedBytes() == 0,
          "the host has no used-bytes measurement (%llu)",
          (unsigned long long)nxusHeapUsedBytes());
    CHECK(nxusHeapFreeKiB() == 0,
          "the host free KiB is 0 (%u)", (unsigned)nxusHeapFreeKiB());

    /* A Switch translation unit compiled on the host calls these; they must link
       and stay silent without nxus_heap.c. */
    nxusHeapLog("test");
    nxusHeapLogDebug("test");
    nxusHeapBootReport();
    CHECK(1, "the host logging helpers are callable");
}

int main(void) {
    printf("== Nxus heap accounting / resident sizes ==\n");
    testTransportSizes();
    testBaselineBudget();
    testBootThreshold();
    testHostFallback();

    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    if (g_failures == 0) printf("ALL HEAP TESTS PASSED\n");
    return (g_failures == 0) ? 0 : 1;
}
