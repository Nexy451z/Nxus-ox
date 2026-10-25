/*
 * Host tests for the published-view lifetime contract of nxus_session.c.
 *
 * nxusSessionMappings() / nxusSessionRegions() publish a pointer+count pair behind
 * a seqlock.  A consistent sample is not enough: the block it points at used to be
 * freed by the very next publish/drop, so any reader that outlived that publish
 * (the snapshot service keeps the region list for a whole capture) walked freed
 * memory.  The session now pins the block on a successful sample (g_ViewReaders)
 * and retires replaced blocks instead of freeing them while a pin is outstanding;
 * nxusSessionViewRelease() drops the pin and frees the ring once it is the last
 * one.
 *
 * The unit is a Switch translation unit (libnx headers, Mutex/Thread, system tick),
 * so this test compiles the SHIPPED source directly: tests/stubs/switch.h provides
 * the libnx surface and the definitions at the bottom of this file replace the
 * dmnt/debug/log services it would otherwise link from the console.  That keeps the
 * pin/retire logic under test identical to what runs on hardware, and lets the test
 * inspect the static retire ring (the "no free() while pinned" invariant is not
 * observable from the outside otherwise).
 */
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../switch/source/nxus_session.c"

static int g_checks = 0;
static int g_failures = 0;

/* Captured by the nxusLogWrite() stand-in at the bottom: the retire-ring overflow
   is only allowed to be a logged leak, so the tests read the message back. */
static bool g_Verbose;
static char g_LastLog[256];

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (!(cond)) {                                               \
            g_failures++;                                            \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);            \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
        }                                                            \
    } while (0)

/* ---- fake target mappings ---------------------------------------------- */

#define FAKE_MAP_CAP 4096u

static NxusMemoryInfo g_FakeMaps[FAKE_MAP_CAP];
static u64 g_FakeMapCount;

/* Every fake mapping carries its generation in the base address, so a block that
   was reused/reallocated behind a reader's back is detectable: the entries no
   longer match the generation that was published. */
static u64 fakeBase(u32 gen, u32 index) {
    return 0x10000000ull + (u64)gen * 0x00100000ull + (u64)index * 0x1000ull;
}

static void fakeMappings(u32 gen, u32 count) {
    if (count > FAKE_MAP_CAP) count = FAKE_MAP_CAP;
    for (u32 i = 0; i < count; i++) {
        memset(&g_FakeMaps[i], 0, sizeof(g_FakeMaps[i]));
        g_FakeMaps[i].base_addr = fakeBase(gen, i);
        g_FakeMaps[i].size = 0x1000;
        g_FakeMaps[i].memory_type = 3;                       /* MemType_Normal */
        g_FakeMaps[i].perm = NXUS_PERM_R | NXUS_PERM_W;
    }
    g_FakeMapCount = count;
}

static u32 readers(void) {
    return atomic_load_explicit(&g_ViewReaders, memory_order_acquire);
}

static int findRetired(const void *block) {
    for (u32 i = 0; i < g_ViewRetiredCount; i++) {
        if (g_ViewRetired[i].block == block) return (int)i;
    }
    return -1;
}

/* A session with no published views and no pins.  Exit() is a no-op the first
   time, and tears the previous test's session down afterwards. */
static void freshSession(void) {
    nxusSessionExit();
    nxusSessionInit(64 * 1024, 4096);
    fakeMappings(0, 0);
}

/* ---- tests -------------------------------------------------------------- */

/* A successful sample takes exactly one pin; NULL takes none; release is
   idempotent and never wraps the counter. */
static void testPinBookkeeping(void) {
    printf("- pin bookkeeping around a sample\n");
    freshSession();

    CHECK(nxusSessionMappings() == NULL, "no snapshot yet: NULL view");
    CHECK(readers() == 0u, "a NULL view takes no pin (%u)", readers());

    fakeMappings(1, 3);
    Result rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "snapshot rc=0x%08X", (unsigned)rc);

    const NxusMappingTable *table = nxusSessionMappings();
    CHECK(table != NULL, "published table is readable");
    if (table == NULL) return;
    CHECK(table->count == 3u, "snapshot count=%u", (unsigned)table->count);
    CHECK(readers() == 1u, "a successful sample pins the view (%u)", readers());

    nxusSessionViewRelease();
    CHECK(readers() == 0u, "release drops the pin (%u)", readers());

    /* Stray extra releases must not underflow (that would disable retirement for
       the rest of the session). */
    nxusSessionViewRelease();
    nxusSessionViewRelease();
    CHECK(readers() == 0u, "extra releases do not wrap the pin count (%u)", readers());

    /* Region view: empty view -> NULL + count 0, and no pin either. */
    u32 count = 12345;
    CHECK(nxusSessionRegions(&count) == NULL, "no region list yet: NULL view");
    CHECK(count == 0u, "empty region list reports count 0 (%u)", count);
    CHECK(readers() == 0u, "NULL region view takes no pin (%u)", readers());
}

/* The regression this whole change is about: a publish that happens while a reader
   is pinned must park the old block, not free it. */
static void testPublishRetainsPinnedBlock(void) {
    printf("- publish keeps the block a reader still holds\n");
    freshSession();

    fakeMappings(1, 3);
    Result rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "first snapshot rc=0x%08X", (unsigned)rc);

    const NxusMappingTable *table = nxusSessionMappings();
    CHECK(table != NULL, "first table readable");
    if (table == NULL) return;
    NxusMappingEntry *pinned = table->entries;
    NxusMappingEntry before[3];
    memcpy(before, pinned, sizeof(before));

    /* Second publish while the reader is still pinned. */
    fakeMappings(2, 3);
    rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "second snapshot rc=0x%08X", (unsigned)rc);

    CHECK(g_ViewRetiredCount == 1u, "replaced block is retired, not freed (%u parked)",
          (unsigned)g_ViewRetiredCount);
    CHECK(findRetired(pinned) >= 0, "the parked block is the one the reader sampled");
    CHECK(memcmp(pinned, before, sizeof(before)) == 0,
          "the parked block still holds its contents (no use-after-free)");
    CHECK(pinned[0].base == fakeBase(1, 0) && pinned[0].valid == 1u,
          "the parked block still describes generation 1");

    /* Stronger than a content check: while the block is pinned the allocator must
       not be able to hand that memory out again.  With the old immediate free()
       this probe reuses the exact block the reader is walking. */
    void *probe = malloc(sizeof(NxusMappingEntry) * 3);
    CHECK(probe != (void *)pinned, "the pinned block was not returned to the allocator");
    free(probe);

    nxusSessionViewRelease();
    CHECK(readers() == 0u, "release clears the pin (%u)", readers());
    CHECK(g_ViewRetiredCount == 0u, "the last release drains the ring (%u)",
          (unsigned)g_ViewRetiredCount);
}

/* No reader: a replaced block is freed immediately, so repeated publishing does
   not accumulate anything. */
static void testUnpinnedPublishDrains(void) {
    printf("- without readers a replaced block is freed immediately\n");
    freshSession();

    for (u32 gen = 0; gen < 8; gen++) {
        fakeMappings(gen, 4);
        Result rc = nxusSessionRefreshMappings();
        CHECK(R_SUCCEEDED(rc), "publish %u rc=0x%08X", gen, (unsigned)rc);
        CHECK(readers() == 0u, "publish %u leaves no pin (%u)", gen, readers());
        CHECK(g_ViewRetiredCount == 0u, "publish %u leaves nothing parked (%u)",
              gen, (unsigned)g_ViewRetiredCount);
    }
    CHECK(g_ViewLeaked == 0u, "no block was leaked (%llu)",
          (unsigned long long)g_ViewLeaked);
}

/* The compatibility requirement: existing callers that never call
   nxusSessionViewRelease() must stay memory-safe.  Their pin is never dropped, so
   the ring fills and later blocks are kept (leak, logged) instead of freed - but
   every pointer handed out earlier stays readable and unchanged. */
static void testLegacyCallerNeverReleases(void) {
    printf("- a caller that never releases stays memory-safe (leak is logged)\n");
#define LEGACY_GENS 8u
    NxusMappingEntry *blocks[LEGACY_GENS];
    u32 counts[LEGACY_GENS];
    freshSession();

    for (u32 gen = 0; gen < LEGACY_GENS; gen++) {
        fakeMappings(gen, 3u + gen);
        Result rc = nxusSessionRefreshMappings();
        CHECK(R_SUCCEEDED(rc), "publish %u rc=0x%08X", gen, (unsigned)rc);
        const NxusMappingTable *table = nxusSessionMappings();
        CHECK(table != NULL, "publish %u table readable", gen);
        if (table == NULL) return;
        /* Deliberately no nxusSessionViewRelease(): this mimics an existing caller
           that was written against the old "the pointer stays valid" contract. */
        blocks[gen] = table->entries;
        counts[gen] = table->count;
        CHECK(counts[gen] == 3u + gen, "publish %u count=%u", gen, (unsigned)counts[gen]);
    }

    CHECK(readers() == LEGACY_GENS, "un-released pins accumulate (%u)", readers());
    CHECK(g_ViewRetiredCount == NXUS_VIEW_RETIRE_MAX,
          "the ring stops at %u generations (%u)", (unsigned)NXUS_VIEW_RETIRE_MAX,
          (unsigned)g_ViewRetiredCount);
    /* 8 publishes, 7 replaced blocks: 4 parked, the rest kept alive (leaked). */
    CHECK(g_ViewLeaked == LEGACY_GENS - 1u - NXUS_VIEW_RETIRE_MAX,
          "ring overflow keeps %llu block(s) instead of freeing them",
          (unsigned long long)g_ViewLeaked);
    CHECK(strstr(g_LastLog, "retire ring full") != NULL,
          "the overflow is reported: \"%s\"", g_LastLog);

    /* Everything handed out is still intact: no use-after-free for a caller that
       never releases, even after the ring overflowed. */
    for (u32 gen = 0; gen < LEGACY_GENS; gen++) {
        int intact = 1;
        for (u32 i = 0; i < counts[gen]; i++) {
            if (blocks[gen][i].base != fakeBase(gen, i) || blocks[gen][i].valid != 1u ||
                blocks[gen][i].reserved != (NXUS_PERM_R | NXUS_PERM_W)) {
                intact = 0;
                break;
            }
        }
        CHECK(intact, "generation %u is still readable and unchanged", gen);
    }
}

/* The snapshot service pattern: the region list is sampled once and used for a
   whole capture, so a rebuild in between must not free it. */
static void testRegionsHoldAcrossRebuild(void) {
    printf("- a pinned region list survives a rebuild\n");
    freshSession();

    fakeMappings(1, 4);
    Result rc = nxusSessionPrepareRegions(NxusScope_All, 0, 0);
    CHECK(R_SUCCEEDED(rc), "prepare regions rc=0x%08X", (unsigned)rc);

    u32 count = 0;
    const NxusScanRegion *regions = nxusSessionRegions(&count);
    CHECK(regions != NULL, "region list published");
    if (regions == NULL) return;
    CHECK(count == 4u, "one region per readable mapping (%u)", (unsigned)count);
    CHECK(readers() == 1u, "the region sample is pinned (%u)", readers());
    NxusScanRegion copy[4];
    memcpy(copy, regions, sizeof(copy));

    /* A new mapping snapshot and a new region list while the capture "runs". */
    fakeMappings(2, 4);
    rc = nxusSessionPrepareRegions(NxusScope_All, 0, 0);
    CHECK(R_SUCCEEDED(rc), "second prepare regions rc=0x%08X", (unsigned)rc);

    CHECK(findRetired(regions) >= 0, "the pinned region list is parked, not freed");
    CHECK(memcmp(regions, copy, sizeof(copy)) == 0, "the pinned region list is unchanged");
    CHECK(regions[0].base == fakeBase(1, 0), "the parked list still describes generation 1");

    nxusSessionViewRelease();
    CHECK(readers() == 0u, "release clears the region pin (%u)", readers());
    CHECK(g_ViewRetiredCount == 0u, "the last release drains mappings and regions (%u)",
          (unsigned)g_ViewRetiredCount);
}

/* Exit() is terminal for views: it frees the ring even with an outstanding pin,
   unpublishes both views, and Init() starts from a clean pin count. */
static void testExitIsTerminal(void) {
    printf("- Exit frees the ring and unpublishes the views\n");
    freshSession();

    fakeMappings(1, 4);
    Result rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "snapshot rc=0x%08X", (unsigned)rc);
    const NxusMappingTable *table = nxusSessionMappings();
    CHECK(table != NULL, "table readable");
    if (table == NULL) return;

    fakeMappings(2, 4);
    rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "second snapshot rc=0x%08X", (unsigned)rc);
    CHECK(g_ViewRetiredCount == 1u, "the replaced block waits for the pin (%u)",
          (unsigned)g_ViewRetiredCount);

    nxusSessionExit();
    CHECK(g_ViewRetiredCount == 0u, "Exit frees the retire ring (%u)",
          (unsigned)g_ViewRetiredCount);
    CHECK(nxusSessionMappings() == NULL, "Exit unpublishes the mapping view");
    CHECK(readers() == 1u, "Exit does not invent a release (pins: %u)", readers());

    nxusSessionInit(64 * 1024, 4096);
    CHECK(readers() == 0u, "Init starts from a clean pin count (%u)", readers());
    CHECK(nxusSessionMappings() == NULL, "a fresh session has no view");
    nxusSessionExit();
}

/* Concurrent readers against a publisher: every sampled block must stay valid and
   consistent until its own release, and every pin must be dropped. */
#define STRESS_PUBLISHES  600u
#define STRESS_READERS    2
#define STRESS_MAP_COUNT  8u

static atomic_int  g_StressStop;
static atomic_uint g_StressWalks;
static atomic_uint g_StressBad;
static atomic_uint g_StressNulls;

static void *stressReader(void *arg) {
    (void)arg;
    while (atomic_load_explicit(&g_StressStop, memory_order_acquire) == 0) {
        const NxusMappingTable *table = nxusSessionMappings();
        if (table == NULL) {                     /* lost the race: no pin taken */
            atomic_fetch_add_explicit(&g_StressNulls, 1u, memory_order_relaxed);
            continue;
        }
        /* Capture the pair the caller means to walk, like the real callers do. */
        const NxusMappingEntry *entries = table->entries;
        const u32 count = table->count;
        u32 bad = 0;
        for (u32 i = 0; i < count; i++) {
            /* Every published generation is fully written before it is published:
               valid == 1, size == 0x1000 and a 4K-aligned base from fakeBase().
               Freed-and-reused memory (the old immediate free) breaks this. */
            if (entries[i].valid != 1u || entries[i].size != 0x1000u ||
                (entries[i].base & 0xFFFu) != 0u) {
                bad++;
            }
        }
        if (bad != 0) atomic_fetch_add_explicit(&g_StressBad, bad, memory_order_relaxed);
        nxusSessionViewRelease();
        atomic_fetch_add_explicit(&g_StressWalks, 1u, memory_order_relaxed);
    }
    return NULL;
}

static void testConcurrentReaders(void) {
    printf("- concurrent readers vs. publisher\n");
    freshSession();

    fakeMappings(0, STRESS_MAP_COUNT);
    Result rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "initial snapshot rc=0x%08X", (unsigned)rc);

    atomic_store(&g_StressStop, 0);
    atomic_store(&g_StressWalks, 0);
    atomic_store(&g_StressBad, 0);
    atomic_store(&g_StressNulls, 0);

    pthread_t threads[STRESS_READERS];
    int started = 0;
    for (int i = 0; i < STRESS_READERS; i++) {
        if (pthread_create(&threads[i], NULL, stressReader, NULL) != 0) break;
        started++;
    }
    CHECK(started == STRESS_READERS, "started %d/%d reader threads", started, STRESS_READERS);

    /* Every generation keeps the same entry count, so a reader that captures a new
       pointer with a stale count still stays inside the block (no test-side OOB). */
    for (u32 gen = 0; gen < STRESS_PUBLISHES; gen++) {
        fakeMappings(gen % 64u, STRESS_MAP_COUNT);
        rc = nxusSessionRefreshMappings();
        if (R_FAILED(rc)) {
            CHECK(0, "publish %u rc=0x%08X", gen, (unsigned)rc);
            break;
        }
    }

    atomic_store(&g_StressStop, 1);
    for (int i = 0; i < started; i++) pthread_join(threads[i], NULL);

    CHECK(atomic_load(&g_StressBad) == 0u,
          "%u entry observation(s) saw a corrupt/reused block",
          atomic_load(&g_StressBad));
    CHECK(atomic_load(&g_StressWalks) > 0u, "readers actually sampled the view (%u walks)",
          atomic_load(&g_StressWalks));
    CHECK(readers() == 0u, "every successful sample was released (%u pins left)",
          readers());
}

/* ---- libnx / service stand-ins (only what nxus_session.c calls) --------- */

void nxusLogWrite(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_LastLog, sizeof(g_LastLog), fmt, ap);
    va_end(ap);
    if (g_Verbose) printf("    [log] %s\n", g_LastLog);
}

/* No debug session in the tests: dmnt:cht is the "real" backend, faked below. */
bool nxusDebugIsAttached(void) { return false; }
bool nxusDebugIsHandoff(void) { return false; }

Result nxusDebugReadMemory(u64 address, void *buffer, u32 size) {
    (void)address; (void)buffer; (void)size;
    return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
}

Result nxusDebugQueryMemory(u64 address, NxusMemoryInfo *out) {
    (void)address; (void)out;
    return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
}

Result nxusDmntRead(u64 address, void *buffer, size_t size) {
    (void)address; (void)buffer; (void)size;
    return 0;
}

Result nxusDmntGetMappingCount(u64 *out_count) {
    if (out_count == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    *out_count = g_FakeMapCount;
    return 0;
}

Result nxusDmntGetMappings(NxusMemoryInfo *buffer, size_t max_count, size_t offset,
                           size_t *out_count) {
    if (buffer == NULL || out_count == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    *out_count = 0;
    if ((u64)offset >= g_FakeMapCount) return 0;
    size_t n = (size_t)g_FakeMapCount - offset;
    if (n > max_count) n = max_count;
    memcpy(buffer, &g_FakeMaps[offset], n * sizeof(NxusMemoryInfo));
    *out_count = n;
    return 0;
}

/* No target metadata: the identity stays zero, which nothing here depends on. */
Result nxusDmntGetMetadata(NxusProcessMetadata *out) {
    if (out != NULL) memset(out, 0, sizeof(*out));
    return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
}

/* ---- main --------------------------------------------------------------- */

int main(void) {
    g_Verbose = getenv("NXUS_TEST_VERBOSE") != NULL;
    printf("=== session view lifetime (pin / retire) ===\n");

    testPinBookkeeping();
    testPublishRetainsPinnedBlock();
    testUnpinnedPublishDrains();
    testLegacyCallerNeverReleases();
    testRegionsHoldAcrossRebuild();
    testExitIsTerminal();
    testConcurrentReaders();

    /* Leave the module in the state the console leaves it in at shutdown. */
    nxusSessionExit();

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    if (g_failures == 0) printf("ALL SESSION-VIEW TESTS PASSED\n");
    else printf("SESSION-VIEW TESTS FAILED\n");
    return g_failures == 0 ? 0 : 1;
}
