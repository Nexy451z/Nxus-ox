/*
 * Host tests for the published-view lifetime contract of nxus_session.c.
 *
 * nxusSessionMappings() / nxusSessionRegions() publish a pointer+count pair behind
 * a seqlock.  A consistent sample is not enough: the block it points at used to be
 * freed by the very next publish/drop, so any reader that outlived that publish
 * (the snapshot service keeps the region list for a whole capture) walked freed
 * memory.  The session now pins the block a successful sample returns and retires
 * replaced blocks instead of freeing them while a pin is outstanding; the last
 * unpin/release frees the ring.
 *
 * PIN OWNERSHIP is the second half of the contract: pins are tokens
 * (nxusSessionViewPinCurrent / nxusSessionViewUnpin), so a pin can only be dropped
 * by the caller that took it.  The old single counter had no owner, which meant an
 * extra release silently consumed somebody else's pin and a forgotten release
 * looked exactly like a clean session - a leak the tests could not distinguish
 * from correctness.  The tests below cover:
 *
 *   - a token unpin drops exactly its own pin (a double/foreign unpin is a no-op),
 *   - a forgotten unpin is COUNTABLE: nxusSessionViewPinnedCount() stays non-zero
 *     until it is unpinned, and the block it protects stays alive,
 *   - the compat API (internal anonymous pin + nxusSessionViewRelease) is still
 *     memory-safe for callers that never release.
 *
 * The unit is a Switch translation unit (libnx headers, Mutex/Thread, system tick),
 * so this test compiles the SHIPPED source directly: tests/stubs/switch.h provides
 * the libnx surface and the definitions at the bottom of this file replace the
 * dmnt/debug/log services it would otherwise link from the console.  That keeps the
 * pin/retire logic under test identical to what runs on hardware, and lets the test
 * inspect the static retire ring and token table (the "no free() while pinned" /
 * "who owns this pin" invariants are not observable from the outside otherwise).
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

/* An arbitrary table: the hit-rescue tests need layouts fakeMappings() cannot express
   (a mapping inserted in the middle, a reused base with a smaller size, a mapping
   turned read-only).  Entries are appended in the order the caller gives them, which
   is how dmnt hands them back: ascending by base. */
static void fakeClearMappings(void) {
    g_FakeMapCount = 0;
}

static void fakeAddMapping(u64 base, u64 size, u32 perm) {
    if (g_FakeMapCount >= FAKE_MAP_CAP) return;
    NxusMemoryInfo *m = &g_FakeMaps[g_FakeMapCount++];
    memset(m, 0, sizeof(*m));
    m->base_addr = base;
    m->size = size;
    m->memory_type = 3;
    m->perm = perm;
}

/* Outstanding view pins, exactly as the session reports them (identified tokens
   plus the compat pins).  This is the "did somebody forget to unpin?" signal. */
static u32 readers(void) {
    return nxusSessionViewPinnedCount();
}

/* Index of a live token slot with this id, or -1.  Used by the ownership tests to
   prove that a stray unpin did not free a slot it does not own. */
static int findPinId(u32 id) {
    if (id == 0) return -1;           /* 0 is "no pin", never a live slot */
    for (u32 i = 0; i < NXUS_VIEW_PIN_MAX; i++) {
        if (g_ViewPins[i].id == id) return (int)i;
    }
    return -1;
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

/* The regression this whole change is about: a publish that happens while a reader
   is pinned must park the old block, not free it.  Uses the token API, which is
   what every shipped call site uses now. */
static void testPublishRetainsPinnedBlock(void) {
    printf("- publish keeps the block a reader still holds\n");
    freshSession();

    fakeMappings(1, 3);
    Result rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "first snapshot rc=0x%08X", (unsigned)rc);

    NxusViewPin pin;
    CHECK(nxusSessionViewPinCurrent(&pin), "view pin acquired (id=%u gen=%u)",
          (unsigned)pin.id, (unsigned)pin.generation);
    CHECK(pin.id != 0, "a pin carries an id (%u)", (unsigned)pin.id);
    const NxusMappingTable *table = nxusSessionMappingsPinned(&pin);
    CHECK(table != NULL, "first table readable behind the token");
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

    nxusSessionViewUnpin(&pin);
    CHECK(pin.id == 0u, "unpin consumes the token (%u)", (unsigned)pin.id);
    CHECK(readers() == 0u, "unpin clears the pin (%u)", readers());
    CHECK(g_ViewRetiredCount == 0u, "the last unpin drains the ring (%u)",
          (unsigned)g_ViewRetiredCount);
}

/* Ownership: a pin belongs to its token.  An extra unpin, a double unpin, or a
   token nobody issued must change nothing - that is exactly the bug the old
   single counter had (an extra release ate a live pin, so the other caller's
   block could be freed under it). */
static void testTokenPinOwnership(void) {
    printf("- token pins are owned: extra/foreign unpins take nothing\n");
    freshSession();

    fakeMappings(1, 3);
    Result rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "snapshot rc=0x%08X", (unsigned)rc);

    NxusViewPin a, b;
    CHECK(nxusSessionViewPinCurrent(&a), "caller A pins");
    CHECK(nxusSessionViewPinCurrent(&b), "caller B pins");
    CHECK(a.id != 0u && b.id != 0u && a.id != b.id,
          "each pin gets a distinct id (%u / %u)", (unsigned)a.id, (unsigned)b.id);
    CHECK(readers() == 2u, "both pins are counted (%u)", readers());
    CHECK(nxusSessionMappingsPinned(&a) != NULL, "A's view is readable");
    CHECK(nxusSessionMappingsPinned(&b) != NULL, "B's view is readable");

    /* A unpins twice: the second call must not reach B's pin. */
    const u32 a_id = a.id;
    const u32 a_gen = a.generation;
    nxusSessionViewUnpin(&a);
    CHECK(readers() == 1u, "A's unpin drops exactly one pin (%u)", readers());
    CHECK(findPinId(a_id) < 0, "A's token is gone from the table");
    CHECK(a.id == 0u, "unpin consumes A's token (%u)", (unsigned)a.id);
    g_LastLog[0] = '\0';
    nxusSessionViewUnpin(&a);                   /* same variable, second time */
    CHECK(readers() == 1u, "A's double unpin is a no-op (%u)", readers());
    CHECK(strstr(g_LastLog, "double unpin") != NULL,
          "the double unpin is logged: \"%s\"", g_LastLog);
    CHECK(nxusSessionMappingsPinned(&b) != NULL,
          "B still owns a live pin and can still walk its view");

    /* A stale COPY of A's token (same id/generation, slot already free) is not the
       token: the table lookup rejects it, so it cannot consume B's pin. */
    NxusViewPin stale;
    stale.id = a_id;
    stale.generation = a_gen;
    g_LastLog[0] = '\0';
    nxusSessionViewUnpin(&stale);
    CHECK(readers() == 1u, "a stale copy changes nothing (%u)", readers());
    CHECK(strstr(g_LastLog, "foreign/stale") != NULL,
          "the stale unpin is logged: \"%s\"", g_LastLog);

    /* A forged token (right id, wrong generation) is not a live pin either. */
    NxusViewPin forged;
    forged.id = b.id;
    forged.generation = b.generation + 1u;
    g_LastLog[0] = '\0';
    nxusSessionViewUnpin(&forged);
    CHECK(readers() == 1u, "a forged token changes nothing (%u)", readers());
    CHECK(strstr(g_LastLog, "foreign/stale") != NULL,
          "the foreign unpin is logged: \"%s\"", g_LastLog);

    /* An unpin with no token at all is also inert (and logged). */
    NxusViewPin empty;
    empty.id = 0;
    empty.generation = 0;
    g_LastLog[0] = '\0';
    nxusSessionViewUnpin(&empty);
    CHECK(readers() == 1u, "an empty token changes nothing (%u)", readers());
    CHECK(strstr(g_LastLog, "empty token") != NULL,
          "the empty unpin is logged: \"%s\"", g_LastLog);

    const u32 b_id = b.id;
    nxusSessionViewUnpin(&b);
    CHECK(readers() == 0u, "the owner's unpin returns the count to 0 (%u)", readers());
    CHECK(findPinId(b_id) < 0, "B's slot is free again");
}

/* The detection story: a forgotten unpin is not "safely leaked", it is visible.
   The count stays non-zero (the old single counter looked exactly like a clean
   session), the block the pin protects stays alive, and one unpin recovers. */
static void testForgottenPinIsDetected(void) {
    printf("- a forgotten unpin is counted, not silently safe\n");
    freshSession();

    fakeMappings(1, 3);
    Result rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "snapshot rc=0x%08X", (unsigned)rc);

    NxusViewPin pin;
    CHECK(nxusSessionViewPinCurrent(&pin), "pin acquired");
    const NxusMappingTable *table = nxusSessionMappingsPinned(&pin);
    CHECK(table != NULL, "view sampled behind the token");
    if (table == NULL) return;
    NxusMappingEntry *block = table->entries;
    /* Deliberately no unpin: this is the regression the token API has to expose. */

    CHECK(readers() == 1u, "the unpinned view is reported as 1 outstanding pin (%u)",
          readers());

    fakeMappings(2, 3);
    rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "publish while the pin is leaked rc=0x%08X", (unsigned)rc);
    CHECK(findRetired(block) >= 0, "the leaked pin still protects its block");
    CHECK(readers() == 1u, "a publish does not hide the leaked pin (%u)", readers());

    nxusSessionViewUnpin(&pin);
    CHECK(readers() == 0u, "unpinning the leaked token returns the count to 0 (%u)",
          readers());
    CHECK(g_ViewRetiredCount == 0u, "and the retire ring drains (%u)",
          (unsigned)g_ViewRetiredCount);
}

/* The token table is bounded; exhaustion is a bug report, not a silent success. */
static void testPinTableLimit(void) {
    printf("- the token table is bounded and reports exhaustion\n");
    freshSession();

    fakeMappings(1, 2);
    Result rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "snapshot rc=0x%08X", (unsigned)rc);

    NxusViewPin pins[NXUS_VIEW_PIN_MAX];
    u32 taken = 0;
    for (u32 i = 0; i < NXUS_VIEW_PIN_MAX; i++) {
        memset(&pins[i], 0, sizeof(pins[i]));
        if (nxusSessionViewPinCurrent(&pins[i])) taken++;
    }
    CHECK(taken == NXUS_VIEW_PIN_MAX, "all %u slots can be handed out (%u)",
          (unsigned)NXUS_VIEW_PIN_MAX, taken);
    CHECK(readers() == NXUS_VIEW_PIN_MAX, "every slot is counted (%u)", readers());

    NxusViewPin extra;
    g_LastLog[0] = '\0';
    CHECK(!nxusSessionViewPinCurrent(&extra), "the next pin is refused");
    CHECK(extra.id == 0u, "a refused pin is not a token (%u)", (unsigned)extra.id);
    CHECK(strstr(g_LastLog, "pin table full") != NULL,
          "the exhaustion is logged: \"%s\"", g_LastLog);

    /* Sampling needs a live pin: a refused token must not read the view. */
    g_LastLog[0] = '\0';
    CHECK(nxusSessionMappingsPinned(&extra) == NULL,
          "sampling without a live pin is refused");
    CHECK(strstr(g_LastLog, "without a live pin") != NULL,
          "the unpinned sample is logged: \"%s\"", g_LastLog);
    u32 count = 99;
    CHECK(nxusSessionRegionsPinned(&extra, &count) == NULL,
          "region sampling without a live pin is refused");
    CHECK(count == 0u, "and reports count 0 (%u)", (unsigned)count);

    for (u32 i = 0; i < NXUS_VIEW_PIN_MAX; i++) nxusSessionViewUnpin(&pins[i]);
    CHECK(readers() == 0u, "all pins released (%u)", readers());

    CHECK(nxusSessionViewPinCurrent(&extra), "a slot is reusable after unpin");
    nxusSessionViewUnpin(&extra);
    CHECK(readers() == 0u, "and released again (%u)", readers());
}

/* Compat API bookkeeping: one pin per successful sample, NULL takes none, and an
   extra release is clamped (and logged) instead of stealing a live pin.  Kept
   because existing callers still use this pair. */
static void testCompatPinBookkeeping(void) {
    printf("- compat pin bookkeeping around a sample\n");
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

    /* A stray extra release must not underflow (that would disable retirement for
       the rest of the session) and must not eat a token pin either. */
    g_LastLog[0] = '\0';
    nxusSessionViewRelease();
    CHECK(readers() == 0u, "an extra release does not wrap the count (%u)", readers());
    CHECK(strstr(g_LastLog, "no compat pin outstanding") != NULL,
          "the stray release is logged: \"%s\"", g_LastLog);

    NxusViewPin pin;
    CHECK(nxusSessionViewPinCurrent(&pin), "a token pin is taken");
    nxusSessionViewRelease();            /* compat release with only a token live */
    CHECK(readers() == 1u, "a compat release cannot eat a token pin (%u)", readers());
    CHECK(nxusSessionMappingsPinned(&pin) != NULL, "the token pin is still live");
    nxusSessionViewUnpin(&pin);
    CHECK(readers() == 0u, "the token unpin clears it (%u)", readers());

    /* Region view: empty view -> NULL + count 0, and no pin either. */
    u32 count = 12345;
    CHECK(nxusSessionRegions(&count) == NULL, "no region list yet: NULL view");
    CHECK(count == 0u, "empty region list reports count 0 (%u)", count);
    CHECK(readers() == 0u, "NULL region view takes no pin (%u)", readers());
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

/* The compatibility requirement (COMPAT API only - the shipped call sites are all
   tokens now): callers that never call nxusSessionViewRelease() must stay
   memory-safe.  Their pin is never dropped, so the ring fills and later blocks are
   kept (leak, logged) instead of freed - but every pointer handed out earlier stays
   readable and unchanged, and the leak is at least counted by readers(). */
static void testLegacyCallerNeverReleases(void) {
    printf("- a compat caller that never releases stays memory-safe (leak is logged)\n");
#define LEGACY_GENS 8u
    NxusMappingEntry *blocks[LEGACY_GENS];
    u32 counts[LEGACY_GENS];
    freshSession();
    g_LastLog[0] = '\0';       /* only the overflow of this loop may be asserted */

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

/* The snapshot service pattern, migrated: the region list is sampled once behind a
   token and used for a whole capture, so a rebuild in between must not free it. */
static void testRegionsHoldAcrossRebuild(void) {
    printf("- a pinned region list survives a rebuild\n");
    freshSession();

    fakeMappings(1, 4);
    Result rc = nxusSessionPrepareRegions(NxusScope_All, 0, 0);
    CHECK(R_SUCCEEDED(rc), "prepare regions rc=0x%08X", (unsigned)rc);

    NxusViewPin pin;
    CHECK(nxusSessionViewPinCurrent(&pin), "capture pins the view");
    u32 count = 0;
    const NxusScanRegion *regions = nxusSessionRegionsPinned(&pin, &count);
    CHECK(regions != NULL, "region list published");
    if (regions == NULL) { nxusSessionViewUnpin(&pin); return; }
    CHECK(count == 4u, "one region per readable mapping (%u)", (unsigned)count);
    CHECK(readers() == 1u, "the region sample is pinned by the token (%u)", readers());
    NxusScanRegion copy[4];
    memcpy(copy, regions, sizeof(copy));

    /* A new mapping snapshot and a new region list while the capture "runs". */
    fakeMappings(2, 4);
    rc = nxusSessionPrepareRegions(NxusScope_All, 0, 0);
    CHECK(R_SUCCEEDED(rc), "second prepare regions rc=0x%08X", (unsigned)rc);

    CHECK(findRetired(regions) >= 0, "the pinned region list is parked, not freed");
    CHECK(memcmp(regions, copy, sizeof(copy)) == 0, "the pinned region list is unchanged");
    CHECK(regions[0].base == fakeBase(1, 0), "the parked list still describes generation 1");

    nxusSessionViewUnpin(&pin);
    CHECK(readers() == 0u, "unpin clears the region pin (%u)", readers());
    CHECK(g_ViewRetiredCount == 0u, "the last unpin drains mappings and regions (%u)",
          (unsigned)g_ViewRetiredCount);
}

/* ---- hit rescue across a mapping rebuild --------------------------------
 *
 * nxusSessionHitsRevalidate() used to verify "mapping_base[same idx] + offset ==
 * address", which cannot rescue the case the rescue exists for: a mapping inserted or
 * removed BEFORE the recorded ones shifts every later ordinal, so the stored index
 * names another (readable, plausible) region and the check fails.  The list is now
 * repaired from the ABSOLUTE ADDRESS recorded with each hit, and only hits whose
 * address is no longer inside a readable mapping are dropped.
 *
 * The list is filled the way the engine fills it (absolute address next to the
 * ordinal + offset) but without running a scan, so the rebuild is the only variable. */

#define HIT_VALUE_SIZE 4u

/* Append one hit as the engine would: (mapping_idx, offset) plus the ABSOLUTE address
   it was found at, and its value in the SoA value array. */
static void hitAppend(u32 mapping_idx, u32 offset, u64 address, u8 value) {
    CHECK(g_Session.hits.count < g_Session.hits.capacity, "the test hit list has room");
    if (g_Session.hits.count >= g_Session.hits.capacity) return;
    const u32 i = g_Session.hits.count++;
    NxusHitAddress *hit = &g_Session.hits.addresses[i];
    hit->offset = offset;
    hit->mapping_idx = (u16)mapping_idx;
    hit->reserved = 0;
    hit->address = address;
    memset(g_Session.hits.values + (size_t)i * g_Session.hits.value_size, 0,
           g_Session.hits.value_size);
    g_Session.hits.values[(size_t)i * g_Session.hits.value_size] = value;
}

static u8 hitValue(u32 index) {
    return g_Session.hits.values[(size_t)index * g_Session.hits.value_size];
}

/* Arm a hit list exactly like ScanBegin(): the owner stamp (which also records the
   mapping bases) followed by the list itself.  The caller published its table first. */
static bool armHitList(u32 capacity) {
    hitsOwnerStamp();
    atomic_store_explicit(&g_HitsStale, 0, memory_order_release);
    sessionStateStore(NxusScanState_Done);
    return nxusHitListInit(&g_Session.hits, capacity, capacity, HIT_VALUE_SIZE) ==
           NXUS_SCAN_OK;
}

/* Three readable mappings: 0x30000000 / 0x30010000 / 0x30020000. */
#define RESCUE_B0 0x30000000ull
#define RESCUE_B1 0x30010000ull
#define RESCUE_B2 0x30020000ull
#define RESCUE_RW (NXUS_PERM_R | NXUS_PERM_W)

/* Target incarnation the dmnt stub below reports.  Tests set it to drive
   hitsOwnerStamp()/the ownership checks; 0 is the boot value. */
static u32 g_FakeIncarnation;

static void rescuePublishThree(void) {
    fakeClearMappings();
    fakeAddMapping(RESCUE_B0, 0x1000, RESCUE_RW);
    fakeAddMapping(RESCUE_B1, 0x1000, RESCUE_RW);
    fakeAddMapping(RESCUE_B2, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "rescue base table published");
}

/* The regression: a rebuild that INSERTS a mapping in front of the recorded ones. */
static void testHitsRescueShiftedRebuild(void) {
    printf("- a rebuilt table that shifted the indices keeps its hits\n");
    freshSession();
    rescuePublishThree();
    CHECK(armHitList(8), "hit list armed against the first table");
    hitAppend(1, 0x40, RESCUE_B1 + 0x40, 0x11);
    hitAppend(2, 0x80, RESCUE_B2 + 0x80, 0x22);
    CHECK(nxusSessionHitsMatchTarget(), "a fresh list matches its own table");
    const u32 gen_before = nxusSessionMappingGeneration();

    /* The newcomer is not related to either hit, but it shifts both ordinals by one. */
    fakeClearMappings();
    fakeAddMapping(RESCUE_B0, 0x1000, RESCUE_RW);
    fakeAddMapping(0x30008000ull, 0x1000, RESCUE_RW);        /* inserted */
    fakeAddMapping(RESCUE_B1, 0x1000, RESCUE_RW);
    fakeAddMapping(RESCUE_B2, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "shifted table published");
    CHECK(nxusSessionMappingGeneration() != gen_before,
          "the rebuild is a new generation (%u/%u)", gen_before,
          nxusSessionMappingGeneration());

    g_LastLog[0] = '\0';
    CHECK(nxusSessionHitsMatchTarget(), "the list is rescued, not discarded (log: \"%s\")",
          g_LastLog);
    CHECK(strstr(g_LastLog, "revalidated 2 hit(s)") != NULL,
          "the rescue is logged: \"%s\"", g_LastLog);
    CHECK(g_Session.hits.count == 2u, "both hits survive (%u)", (unsigned)g_Session.hits.count);
    CHECK(g_Session.hits.addresses[0].mapping_idx == 2u &&
          g_Session.hits.addresses[0].offset == 0x40u,
          "hit 0 was re-pointed at the shifted mapping (%u/%u)",
          (unsigned)g_Session.hits.addresses[0].mapping_idx,
          (unsigned)g_Session.hits.addresses[0].offset);
    CHECK(g_Session.hits.addresses[1].mapping_idx == 3u &&
          g_Session.hits.addresses[1].offset == 0x80u,
          "hit 1 was re-pointed at the shifted mapping (%u/%u)",
          (unsigned)g_Session.hits.addresses[1].mapping_idx,
          (unsigned)g_Session.hits.addresses[1].offset);
    CHECK(g_Session.hits.addresses[0].address == RESCUE_B1 + 0x40 &&
          g_Session.hits.addresses[1].address == RESCUE_B2 + 0x80,
          "the recorded addresses are unchanged");
    CHECK(hitValue(0) == 0x11 && hitValue(1) == 0x22,
          "the recorded values travelled with their hits (%u/%u)",
          (unsigned)hitValue(0), (unsigned)hitValue(1));

    /* The rewritten indices must resolve through the CURRENT table to the very same
       addresses - that is what sendHits()/the PC do with mapping_idx + offset. */
    const NxusMappingTable *table = nxusSessionMappings();
    CHECK(table != NULL, "rescue table readable");
    if (table != NULL) {
        u64 a0 = 0;
        u64 a1 = 0;
        CHECK(nxusHitResolve(&g_Session.hits, table, 0, &a0) && a0 == RESCUE_B1 + 0x40,
              "hit 0 resolves to its recorded address (0x%llX)",
              (unsigned long long)a0);
        CHECK(nxusHitResolve(&g_Session.hits, table, 1, &a1) && a1 == RESCUE_B2 + 0x80,
              "hit 1 resolves to its recorded address (0x%llX)",
              (unsigned long long)a1);
        nxusSessionViewRelease();
    }
}

/* Only the hits the current table can no longer resolve are dropped; when none is
   left the list is refused as a whole (the caller answers BAD_STATE). */
static void testHitsRescueDropsOnlyUnresolvable(void) {
    printf("- a shift costs only the hits that really vanished\n");
    freshSession();
    rescuePublishThree();
    CHECK(armHitList(8), "hit list armed");
    hitAppend(1, 0x40, RESCUE_B1 + 0x40, 0x11);
    hitAppend(2, 0x80, RESCUE_B2 + 0x80, 0x22);
    /* A previous refine pass would have left its count here; Undo rewinds to it, so a
       rescue that drops entries must clamp it or Undo would resurrect empty slots. */
    g_Session.hits.prev_count = 2;

    /* B1 is gone: the hit recorded inside it can never resolve again, the other one
       moved to index 1. */
    fakeClearMappings();
    fakeAddMapping(RESCUE_B0, 0x1000, RESCUE_RW);
    fakeAddMapping(RESCUE_B2, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "table without B1 published");

    g_LastLog[0] = '\0';
    CHECK(nxusSessionHitsMatchTarget(), "one hit is enough to keep the list");
    CHECK(g_Session.hits.count == 1u, "only the resolvable hit survives (%u)",
          (unsigned)g_Session.hits.count);
    CHECK(g_Session.hits.addresses[0].address == RESCUE_B2 + 0x80 &&
          g_Session.hits.addresses[0].mapping_idx == 1u &&
          g_Session.hits.addresses[0].offset == 0x80u,
          "the surviving hit was compacted and re-pointed (%u/%u)",
          (unsigned)g_Session.hits.addresses[0].mapping_idx,
          (unsigned)g_Session.hits.addresses[0].offset);
    CHECK(hitValue(0) == 0x22, "its value moved with it (%u)", (unsigned)hitValue(0));
    CHECK(strstr(g_LastLog, "1 hit(s) can no longer be resolved - dropped") != NULL,
          "the dropped hit is named: \"%s\"", g_LastLog);
    CHECK(g_Session.hits.prev_count == 1u,
          "Undo cannot resurrect the dropped slot (prev_count=%u)",
          (unsigned)g_Session.hits.prev_count);

    /* Now the recorded mapping is gone too: nothing is left to refine. */
    fakeClearMappings();
    fakeAddMapping(RESCUE_B0, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "table without B2 published");
    g_LastLog[0] = '\0';
    CHECK(!nxusSessionHitsMatchTarget(), "no resolvable hit -> the list is refused");
    CHECK(g_Session.hits.count == 0u, "and the list is emptied (%u)",
          (unsigned)g_Session.hits.count);
    CHECK(g_Session.hits.prev_count == 0u, "and Undo has nothing to rewind to (%u)",
          (unsigned)g_Session.hits.prev_count);
    CHECK(strstr(g_LastLog, "can no longer be resolved") != NULL,
          "the refusal names the cause: \"%s\"", g_LastLog);
}

/* A reused base is not a valid hit address: the check is base <= address < base+size
   WITH read permission, not "the base matches".  The base array being unchanged also
   exercises the stamp fast path (no search, per-hit arithmetic only). */
static void testHitsRescueSameBaseReuse(void) {
    printf("- same base, smaller size / lost read perm: the hit is unresolvable\n");
    freshSession();
    rescuePublishThree();
    CHECK(armHitList(8), "hit list armed");
    hitAppend(1, 0x40, RESCUE_B1 + 0x40, 0x33);

    /* Unrelated mapping grew: the base ORDER is unchanged (fast path), the fingerprint
       (base/size) changed, so the generation - and thus the rescue - runs. */
    fakeClearMappings();
    fakeAddMapping(RESCUE_B0, 0x2000, RESCUE_RW);
    fakeAddMapping(RESCUE_B1, 0x1000, RESCUE_RW);
    fakeAddMapping(RESCUE_B2, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "grown table published");
    CHECK(nxusSessionHitsMatchTarget(), "an unchanged base order keeps the list");
    CHECK(g_Session.hits.count == 1u && g_Session.hits.addresses[0].mapping_idx == 1u &&
          g_Session.hits.addresses[0].offset == 0x40u,
          "the hit keeps its index and offset (%u/%u)",
          (unsigned)g_Session.hits.addresses[0].mapping_idx,
          (unsigned)g_Session.hits.addresses[0].offset);

    /* The SAME base is reused with a size that no longer covers the offset. */
    fakeClearMappings();
    fakeAddMapping(RESCUE_B0, 0x2000, RESCUE_RW);
    fakeAddMapping(RESCUE_B1, 0x20, RESCUE_RW);
    fakeAddMapping(RESCUE_B2, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "shrunken table published");
    g_LastLog[0] = '\0';
    CHECK(!nxusSessionHitsMatchTarget(), "a shrunken mapping drops the hit");
    CHECK(g_Session.hits.count == 0u, "the list is emptied (%u)",
          (unsigned)g_Session.hits.count);
    CHECK(strstr(g_LastLog, "can no longer be resolved") != NULL,
          "the drop is logged: \"%s\"", g_LastLog);

    /* Read permission is required as well: the mapping is there, at the right place,
       but a hit cannot be refined through a write-only mapping. */
    freshSession();
    rescuePublishThree();
    CHECK(armHitList(8), "hit list armed (perm case)");
    hitAppend(1, 0x40, RESCUE_B1 + 0x40, 0x33);
    fakeClearMappings();
    fakeAddMapping(RESCUE_B0, 0x2000, RESCUE_RW);            /* forces a new generation */
    fakeAddMapping(RESCUE_B1, 0x1000, NXUS_PERM_W);          /* read access lost */
    fakeAddMapping(RESCUE_B2, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "read-only table published");
    g_LastLog[0] = '\0';
    CHECK(!nxusSessionHitsMatchTarget(), "a mapping without read permission drops the hit");
    CHECK(g_Session.hits.count == 0u, "the list is emptied (%u)",
          (unsigned)g_Session.hits.count);
    CHECK(strstr(g_LastLog, "can no longer be resolved") != NULL,
          "the drop is logged: \"%s\"", g_LastLog);
}

/* A table that does not come back in base order must still be searched correctly: the
   resolver builds and sorts its own base index instead of binary-searching a table it
   wrongly assumes is ordered. */
static void testHitsRescueUnsortedTable(void) {
    printf("- a table that is not base-ascending is indexed, not assumed sorted\n");
    freshSession();
    rescuePublishThree();
    CHECK(armHitList(8), "hit list armed");
    hitAppend(1, 0x40, RESCUE_B1 + 0x40, 0x44);
    hitAppend(2, 0x80, RESCUE_B2 + 0x80, 0x55);

    /* Same mappings, reversed order: B2 -> index 0, B0 -> 1, B1 -> 2. */
    fakeClearMappings();
    fakeAddMapping(RESCUE_B2, 0x1000, RESCUE_RW);
    fakeAddMapping(RESCUE_B0, 0x1000, RESCUE_RW);
    fakeAddMapping(RESCUE_B1, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "reversed table published");

    g_LastLog[0] = '\0';
    CHECK(nxusSessionHitsMatchTarget(), "the list is rescued through the sorted index");
    CHECK(g_Session.hits.count == 2u, "both hits survive (%u)",
          (unsigned)g_Session.hits.count);
    CHECK(g_Session.hits.addresses[0].mapping_idx == 2u &&
          g_Session.hits.addresses[0].offset == 0x40u,
          "hit 0 found its mapping at the new ordinal (%u/%u)",
          (unsigned)g_Session.hits.addresses[0].mapping_idx,
          (unsigned)g_Session.hits.addresses[0].offset);
    CHECK(g_Session.hits.addresses[1].mapping_idx == 0u &&
          g_Session.hits.addresses[1].offset == 0x80u,
          "hit 1 found its mapping at the new ordinal (%u/%u)",
          (unsigned)g_Session.hits.addresses[1].mapping_idx,
          (unsigned)g_Session.hits.addresses[1].offset);
    CHECK(strstr(g_LastLog, "revalidated 2 hit(s)") != NULL,
          "the rescue is logged: \"%s\"", g_LastLog);

    const NxusMappingTable *table = nxusSessionMappings();
    CHECK(table != NULL, "reversed table readable");
    if (table != NULL) {
        u64 a0 = 0;
        u64 a1 = 0;
        CHECK(nxusHitResolve(&g_Session.hits, table, 0, &a0) && a0 == RESCUE_B1 + 0x40,
              "hit 0 resolves to its recorded address (0x%llX)",
              (unsigned long long)a0);
        CHECK(nxusHitResolve(&g_Session.hits, table, 1, &a1) && a1 == RESCUE_B2 + 0x80,
              "hit 1 resolves to its recorded address (0x%llX)",
              (unsigned long long)a1);
        nxusSessionViewRelease();
    }
}

/* ---- target incarnation -------------------------------------------------
 *
 * pid + program id + mapping generation all survive a relaunch in a FIXED layout:
 * the title comes back under the same pid and dmnt walks the same mappings, so every
 * recorded address still resolves - against a different process.  With the
 * absolute-address rescue in place that is no longer detectable by "the check fails",
 * so the list is stamped with dmnt's target incarnation and refused when it moved.
 * g_FakeIncarnation drives the stub at the bottom of this file.
 */

static void testHitsIncarnationMismatch(void) {
    printf("- a hit list from an earlier target incarnation is refused\n");
    freshSession();
    g_FakeIncarnation = 3;
    rescuePublishThree();
    CHECK(armHitList(8), "hit list armed in incarnation 3");
    hitAppend(1, 0x40, RESCUE_B1 + 0x40, 0x11);
    CHECK(g_Session.hits_owner_incarnation == 3u,
          "the list carries the incarnation it was armed in (%u)",
          (unsigned)g_Session.hits_owner_incarnation);
    CHECK(nxusSessionHitsMatchTarget(), "a fresh list matches its own incarnation");

    /* dmnt reopened the process.  pid, title and the mapping table are unchanged -
       this is exactly the fixed-layout restart - only the incarnation moved. */
    g_FakeIncarnation = 4;
    g_LastLog[0] = '\0';
    CHECK(!nxusSessionHitsMatchTarget(),
          "the same pid in a new incarnation is a different target");
    CHECK(strstr(g_LastLog, "earlier incarnation (was 3, now 4)") != NULL,
          "the mismatch names both incarnations: \"%s\"", g_LastLog);
    CHECK(g_Session.hits.count == 1u,
          "refusing the list does not mutate it here (%u)",
          (unsigned)g_Session.hits.count);
    CHECK(!nxusSessionHitsMatchTargetIdentity(),
          "the identity-only check (the 1 Hz tick) refuses it as well");

    fakeClearMappings();
    g_FakeIncarnation = 0;
}

/* The rescue repairs ORDINALS, so it must not be reachable across an incarnation:
 * a restarted title resolves every address perfectly and is still the wrong target. */
static void testHitsRevalidateOnlySameIncarnation(void) {
    printf("- the address rescue never crosses an incarnation\n");
    freshSession();
    g_FakeIncarnation = 5;
    rescuePublishThree();
    CHECK(armHitList(8), "hit list armed in incarnation 5");
    hitAppend(1, 0x40, RESCUE_B1 + 0x40, 0x11);

    /* Positive control: a rebuilt table WITHIN the same incarnation is rescued. */
    fakeClearMappings();
    fakeAddMapping(RESCUE_B0, 0x2000, RESCUE_RW);
    fakeAddMapping(RESCUE_B1, 0x1000, RESCUE_RW);
    fakeAddMapping(RESCUE_B2, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "rebuilt table published");
    g_LastLog[0] = '\0';
    CHECK(nxusSessionHitsMatchTarget(), "same incarnation: the list is rescued");
    CHECK(strstr(g_LastLog, "revalidated 1 hit(s)") != NULL,
          "the rescue ran: \"%s\"", g_LastLog);

    /* A rebuild that the rescue WOULD repair, plus a reopened process. */
    fakeClearMappings();
    fakeAddMapping(RESCUE_B0, 0x1000, RESCUE_RW);
    fakeAddMapping(0x30008000ull, 0x1000, RESCUE_RW);      /* shifts both ordinals */
    fakeAddMapping(RESCUE_B1, 0x1000, RESCUE_RW);
    fakeAddMapping(RESCUE_B2, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "shifted table published");
    const u32 stamped_generation = g_Session.hits_owner_mapping_generation;
    g_FakeIncarnation = 6;

    g_LastLog[0] = '\0';
    CHECK(!nxusSessionHitsRevalidate(),
          "revalidate refuses across incarnations: nothing is repaired");
    CHECK(strstr(g_LastLog, "earlier incarnation (was 5, now 6)") != NULL,
          "the refusal names both incarnations: \"%s\"", g_LastLog);
    CHECK(g_Session.hits.count == 1u,
          "the refused list keeps its entries (%u)", (unsigned)g_Session.hits.count);
    CHECK(g_Session.hits.addresses[0].mapping_idx == 1u &&
          g_Session.hits.addresses[0].offset == 0x40u,
          "the stored index was NOT rewritten (%u/%u)",
          (unsigned)g_Session.hits.addresses[0].mapping_idx,
          (unsigned)g_Session.hits.addresses[0].offset);
    CHECK(g_Session.hits_owner_mapping_generation == stamped_generation,
          "the stamp still names the old table (%u/%u)",
          (unsigned)g_Session.hits_owner_mapping_generation, (unsigned)stamped_generation);
    CHECK(!nxusSessionHitsMatchTarget(),
          "and the full check does not serve it either");

    /* Servable again only once a scan stamps the new incarnation. */
    CHECK(armHitList(8), "a new scan arms a list in the new incarnation");
    CHECK(g_Session.hits_owner_incarnation == 6u, "stamped with the current one (%u)",
          (unsigned)g_Session.hits_owner_incarnation);
    CHECK(nxusSessionHitsMatchTarget(), "and that list matches");

    fakeClearMappings();
    g_FakeIncarnation = 0;
}

/* A hit is only resolvable when its whole VALUE fits inside the mapping: offset <
   size proves the first byte is mapped, not that reading value_size bytes from there
   stays inside the region the refine would read. */
static void testHitsRescueValueMustFitMapping(void) {
    printf("- a hit whose value straddles the mapping end is dropped\n");
    freshSession();
    g_FakeIncarnation = 0;
    rescuePublishThree();
    CHECK(armHitList(8), "hit list armed");
    hitAppend(1, 0xFFE, RESCUE_B1 + 0xFFE, 0x66);   /* 2 bytes left, value is 4 */
    hitAppend(2, 0x80, RESCUE_B2 + 0x80, 0x77);

    /* Same base order (the fast path), B1 shrank so the straddling hit no longer fits
       while its address is still mapped. */
    fakeClearMappings();
    fakeAddMapping(RESCUE_B0, 0x1000, RESCUE_RW);
    fakeAddMapping(RESCUE_B1, 0xFFF, RESCUE_RW);
    fakeAddMapping(RESCUE_B2, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "shrunken table published");

    g_LastLog[0] = '\0';
    CHECK(nxusSessionHitsMatchTarget(), "the fully-inside hit keeps the list alive");
    CHECK(g_Session.hits.count == 1u, "the straddling hit is gone (%u)",
          (unsigned)g_Session.hits.count);
    CHECK(g_Session.hits.addresses[0].address == RESCUE_B2 + 0x80,
          "the survivor is the one that fully fits (0x%llX)",
          (unsigned long long)g_Session.hits.addresses[0].address);
    CHECK(strstr(g_LastLog, "1 hit(s) can no longer be resolved - dropped") != NULL,
          "the drop is logged: \"%s\"", g_LastLog);

    /* Same rule through the address resolver (a shifted table). */
    freshSession();
    g_FakeIncarnation = 0;
    rescuePublishThree();
    CHECK(armHitList(8), "hit list armed (shifted case)");
    hitAppend(1, 0xFFE, RESCUE_B1 + 0xFFE, 0x66);
    fakeClearMappings();
    fakeAddMapping(RESCUE_B0, 0x1000, RESCUE_RW);
    fakeAddMapping(0x30008000ull, 0x1000, RESCUE_RW);      /* shifts both ordinals */
    fakeAddMapping(RESCUE_B1, 0x1000, RESCUE_RW);
    fakeAddMapping(RESCUE_B2, 0x1000, RESCUE_RW);
    CHECK(R_SUCCEEDED(nxusSessionRefreshMappings()), "shifted table published");
    g_LastLog[0] = '\0';
    CHECK(!nxusSessionHitsMatchTarget(),
          "the only hit cannot be rescued when its value would cross the end");
    CHECK(g_Session.hits.count == 0u, "the list is emptied (%u)",
          (unsigned)g_Session.hits.count);
    CHECK(strstr(g_LastLog, "can no longer be resolved") != NULL,
          "the refusal names the cause: \"%s\"", g_LastLog);

    fakeClearMappings();
}

/* Exit() is terminal for views: it frees the ring even with an outstanding pin,
   unpublishes both views, and INVALIDATES the tokens handed out before it - a
   stale unpin afterwards is a logged no-op that cannot touch the next session. */
static void testExitIsTerminal(void) {
    printf("- Exit frees the ring, unpublishes the views and invalidates tokens\n");
    freshSession();

    fakeMappings(1, 4);
    Result rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "snapshot rc=0x%08X", (unsigned)rc);
    NxusViewPin stale;
    CHECK(nxusSessionViewPinCurrent(&stale), "token pin taken");
    const NxusMappingTable *table = nxusSessionMappingsPinned(&stale);
    CHECK(table != NULL, "table readable");
    if (table == NULL) return;

    fakeMappings(2, 4);
    rc = nxusSessionRefreshMappings();
    CHECK(R_SUCCEEDED(rc), "second snapshot rc=0x%08X", (unsigned)rc);
    CHECK(g_ViewRetiredCount == 1u, "the replaced block waits for the pin (%u)",
          (unsigned)g_ViewRetiredCount);

    g_LastLog[0] = '\0';
    nxusSessionExit();
    CHECK(strstr(g_LastLog, "exit with 1 unreleased pin") != NULL,
          "the unreleased pin is reported at Exit: \"%s\"", g_LastLog);
    CHECK(g_ViewRetiredCount == 0u, "Exit frees the retire ring (%u)",
          (unsigned)g_ViewRetiredCount);
    CHECK(nxusSessionMappings() == NULL, "Exit unpublishes the mapping view");
    CHECK(readers() == 0u, "Exit invalidates the outstanding pin instead of carrying it (%u)",
          readers());

    nxusSessionInit(64 * 1024, 4096);
    CHECK(readers() == 0u, "Init starts from a clean pin count (%u)", readers());
    CHECK(nxusSessionMappings() == NULL, "a fresh session has no view");

    /* A pin of the next session must survive an unpin of the stale token. */
    NxusViewPin live;
    CHECK(nxusSessionViewPinCurrent(&live), "pin in the new session");
    g_LastLog[0] = '\0';
    nxusSessionViewUnpin(&stale);
    CHECK(readers() == 1u, "a stale token cannot unpin the new session's pin (%u)",
          readers());
    CHECK(strstr(g_LastLog, "foreign/stale") != NULL,
          "the stale unpin is logged: \"%s\"", g_LastLog);
    nxusSessionViewUnpin(&live);
    CHECK(readers() == 0u, "the live token still unpins (%u)", readers());
    nxusSessionExit();
}

/* Concurrent readers against a publisher, using the shipped token API: every
   sampled block must stay valid and consistent until its own unpin, every pin must
   be dropped, and two threads must be able to hold pins at the same time (the old
   single counter could not tell them apart). */
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
        NxusViewPin pin;
        if (!nxusSessionViewPinCurrent(&pin)) {   /* table exhausted: count and retry */
            atomic_fetch_add_explicit(&g_StressNulls, 1u, memory_order_relaxed);
            continue;
        }
        const NxusMappingTable *table = nxusSessionMappingsPinned(&pin);
        if (table == NULL) {                     /* lost the race: no view right now */
            nxusSessionViewUnpin(&pin);
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
        nxusSessionViewUnpin(&pin);
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
    CHECK(readers() == 0u, "every successful sample was unpinned (%u pins left)",
          readers());
}

/* ---- mixed-view sampling ------------------------------------------------
 *
 * Both published views are a pointer+count pair behind the g_ViewSeq seqlock.  A
 * sampler that omits the ACQUIRE FENCE between the copy and the re-check can accept
 * a pair whose count came from a newer publication than the block it points at
 * (arm64 may move the plain loads past the check), so the caller walks `count`
 * entries over a block that only holds the older (smaller) publication.
 *
 * The stress makes the pair self-describing instead of relying on a crash:
 *   - every block is allocated with MIX_VIEW_CAP entries, so even a stale count
 *     stays inside the allocation (the test must not read OOB when the bug it
 *     hunts is present),
 *   - the published COUNT is written into every entry, so a count from another
 *     publication disagrees with every entry of the block it was paired with,
 *   - the publication count alternates between a small value and the full
 *     capacity, so an old/new mix cannot pass by coincidence.
 *
 * The region accessors hand the verified pair back BY VALUE, so the sample itself
 * is what gets validated.  The mapping accessor returns NxusMappingTable by
 * address and re-publishes its fields in place (nxus_session.h: "the pin protects
 * the block, not the struct fields"), so the capture is done twice there and only
 * a pair that stayed put is validated - a publish landing between the sample and
 * the capture is that documented re-publication, not a seqlock failure.
 *
 * x86 does not reorder the two plain loads, so on the host this is a protocol
 * regression guard (it fails if the writer barriers are dropped or the samplers
 * start returning a torn pair as if it were a copy), not a reproduction of the
 * arm64 reorder.
 */
#define MIX_VIEW_CAP    64u
#define MIX_SMALL_COUNT 4u
#define MIX_PUBLISHES   240u
#define MIX_READERS     2

static atomic_int  g_MixStop;
static atomic_uint g_MixWalks;
static atomic_uint g_MixMixed;
static atomic_uint g_MixSkipped;

static void mixFillMappings(NxusMappingEntry *entries, u32 gen, u32 count) {
    for (u32 i = 0; i < MIX_VIEW_CAP; i++) {
        entries[i].base = 0x40000000ull + (u64)gen * 0x00100000ull + (u64)i * 0x1000ull;
        entries[i].size = (u64)count;
        entries[i].valid = 1;
        entries[i].reserved = NXUS_PERM_R;
        entries[i].type = 3;
    }
}

static void mixFillRegions(NxusScanRegion *regions, u32 gen, u32 count) {
    for (u32 i = 0; i < MIX_VIEW_CAP; i++) {
        regions[i].base = 0x40000000ull + (u64)gen * 0x00100000ull + (u64)i * 0x1000ull;
        regions[i].addr_base = regions[i].base;
        regions[i].size = (u64)count;
        regions[i].perm = NXUS_PERM_R;
        regions[i].mapping_idx = i;
    }
}

/* One pass over the mapping pair.  table->entries/count are the LIVE fields, so a
   publish between the sample and this capture is skipped rather than blamed on the
   seqlock (see the block comment). */
static u32 mixCheckMappings(const NxusMappingTable *table, u32 *skipped) {
    if (table == NULL) return 0;
    const NxusMappingEntry *e1 = table->entries;
    const u32 c1 = table->count;
    atomic_thread_fence(memory_order_acquire);
    const NxusMappingEntry *e2 = table->entries;
    const u32 c2 = table->count;
    if (e1 != e2 || c1 != c2) {
        (*skipped)++;
        return 0;
    }
    if (e1 == NULL || c1 == 0 || c1 > MIX_VIEW_CAP) return 1;
    for (u32 i = 0; i < c1; i++) {
        if (e1[i].valid != 1u || e1[i].size != (u64)c1 || (e1[i].base & 0xFFFu) != 0u) {
            return 1;
        }
    }
    return 0;
}

/* One pass over the region pair.  regions/count are the sampler's own verified
   copies (returned by value), so a mismatch here is a mixed sample. */
static u32 mixCheckRegions(const NxusScanRegion *regions, u32 count) {
    if (regions == NULL) return 0;
    if (count == 0 || count > MIX_VIEW_CAP) return 1;
    for (u32 i = 0; i < count; i++) {
        if (regions[i].perm != NXUS_PERM_R || regions[i].size != (u64)count ||
            regions[i].mapping_idx != i) {
            return 1;
        }
    }
    return 0;
}

static void *mixReader(void *arg) {
    (void)arg;
    while (atomic_load_explicit(&g_MixStop, memory_order_acquire) == 0) {
        NxusViewPin pin;
        if (!nxusSessionViewPinCurrent(&pin)) continue;   /* table exhausted: retry */

        const NxusMappingTable *table = nxusSessionMappingsPinned(&pin);
        u32 region_count = 0;
        const NxusScanRegion *regions = nxusSessionRegionsPinned(&pin, &region_count);

        u32 skipped = 0;
        u32 mixed = mixCheckMappings(table, &skipped);
        mixed += mixCheckRegions(regions, region_count);

        if (mixed != 0) atomic_fetch_add_explicit(&g_MixMixed, mixed, memory_order_relaxed);
        if (skipped != 0) atomic_fetch_add_explicit(&g_MixSkipped, skipped, memory_order_relaxed);
        nxusSessionViewUnpin(&pin);
        atomic_fetch_add_explicit(&g_MixWalks, 1u, memory_order_relaxed);
    }
    return NULL;
}

static void testNoMixedViewSample(void) {
    printf("- a sampled view pair never mixes two publications\n");
    freshSession();

    /* A block to sample from before the writer starts (readers tolerate NULL, but
       this keeps the first iterations on the validated path). */
    NxusMappingEntry *first = (NxusMappingEntry *)calloc(MIX_VIEW_CAP, sizeof(*first));
    NxusScanRegion *first_regions = (NxusScanRegion *)calloc(MIX_VIEW_CAP, sizeof(*first_regions));
    if (first == NULL || first_regions == NULL) {
        free(first);
        free(first_regions);
        CHECK(0, "could not allocate the initial mixed-view blocks");
        return;
    }
    mixFillMappings(first, 0, MIX_SMALL_COUNT);
    mixFillRegions(first_regions, 0, MIX_SMALL_COUNT);
    mappingSnapshotPublish(first, MIX_SMALL_COUNT);
    regionListPublish(first_regions, MIX_SMALL_COUNT);

    atomic_store(&g_MixStop, 0);
    atomic_store(&g_MixWalks, 0);
    atomic_store(&g_MixMixed, 0);
    atomic_store(&g_MixSkipped, 0);

    pthread_t threads[MIX_READERS];
    int started = 0;
    for (int i = 0; i < MIX_READERS; i++) {
        if (pthread_create(&threads[i], NULL, mixReader, NULL) != 0) break;
        started++;
    }
    CHECK(started == MIX_READERS, "started %d/%d mixed-read readers", started, MIX_READERS);

    for (u32 gen = 1; gen <= MIX_PUBLISHES; gen++) {
        const u32 count = (gen & 1u) ? MIX_SMALL_COUNT : MIX_VIEW_CAP;
        NxusMappingEntry *entries =
            (NxusMappingEntry *)calloc(MIX_VIEW_CAP, sizeof(*entries));
        NxusScanRegion *regions =
            (NxusScanRegion *)calloc(MIX_VIEW_CAP, sizeof(*regions));
        if (entries == NULL || regions == NULL) {
            free(entries);
            free(regions);
            CHECK(0, "could not allocate publication %u", gen);
            break;
        }
        mixFillMappings(entries, gen, count);
        mixFillRegions(regions, gen, count);
        mappingSnapshotPublish(entries, count);
        regionListPublish(regions, count);
    }

    atomic_store(&g_MixStop, 1);
    for (int i = 0; i < started; i++) pthread_join(threads[i], NULL);

    CHECK(atomic_load(&g_MixMixed) == 0u,
          "%u view sample(s) paired a count with a block from another publication",
          atomic_load(&g_MixMixed));
    CHECK(atomic_load(&g_MixWalks) > 0u, "readers actually sampled both views (%u walks)",
          atomic_load(&g_MixWalks));
    /* The captures that raced a publish are the documented in-place re-publication;
       they only skip a validation, they are not counted as a mixed sample. */
    CHECK(atomic_load(&g_MixSkipped) <= atomic_load(&g_MixWalks),
          "skipped captures (%u) cannot exceed the walks (%u)",
          atomic_load(&g_MixSkipped), atomic_load(&g_MixWalks));
    CHECK(readers() == 0u, "every mixed-view sample was unpinned (%u pins left)", readers());
}

/* ---- hit cap ------------------------------------------------------------
 *
 * The hit arrays are charged against NXUS_SESSION_HIT_BUDGET_BYTES, so the cap has
 * to be derived per width and the 150k default must never raise it: a u64 row is
 * 24 B and the old flat floor made a full list 3.6 MB (0.5 MiB over budget).
 * test_budget.c mirrors the formula against its own constants; this test calls the
 * shipped inline function so the two cannot drift apart silently. */
static void testHitLimitBudget(void) {
    printf("- the hit cap follows the row width and stays inside the budget\n");
    const u32 widths[4] = { 1u, 2u, 4u, 8u };
    const u32 expected[4] = { 150000u, 150000u, 150000u, 128000u };

    for (u32 i = 0; i < 4; i++) {
        const u32 row = (u32)sizeof(NxusHitAddress) + widths[i];
        const u32 cap = nxusSessionHitLimit(widths[i]);
        CHECK(cap == expected[i], "u%u: cap is %u hits (expected %u)",
              (unsigned)(widths[i] * 8u), (unsigned)cap, (unsigned)expected[i]);
        CHECK((u64)cap * row <= (u64)NXUS_SESSION_HIT_BUDGET_BYTES,
              "u%u: %u hits * %u B exceeds the %u B budget",
              (unsigned)(widths[i] * 8u), (unsigned)cap, (unsigned)row,
              (unsigned)NXUS_SESSION_HIT_BUDGET_BYTES);
        CHECK(cap <= NXUS_SESSION_DEFAULT_MAXHITS,
              "u%u: the default is clamped by the budget, not raised (%u > %u)",
              (unsigned)(widths[i] * 8u), (unsigned)cap,
              (unsigned)NXUS_SESSION_DEFAULT_MAXHITS);
    }
    CHECK((u64)NXUS_SESSION_DEFAULT_MAXHITS * 24ull == 3600000ull,
          "150k u64 rows are %llu B - 0.5 MiB over the 3.0 MiB budget",
          (unsigned long long)((u64)NXUS_SESSION_DEFAULT_MAXHITS * 24ull));
    CHECK((u64)nxusSessionHitLimit(8u) * 24ull ==
              (u64)NXUS_SESSION_HIT_BUDGET_BYTES,
          "the u64 cap lands exactly on the budget (%u hits * 24 B)",
          (unsigned)nxusSessionHitLimit(8u));
    CHECK(nxusSessionHitLimit(0u) == nxusSessionHitLimit(1u),
          "value_size 0 is treated as a 1-byte value (%u/%u)",
          (unsigned)nxusSessionHitLimit(0u), (unsigned)nxusSessionHitLimit(1u));
}

/* The identity is ONE snapshot since the four fields are written through a seqlock.
   The regression was a reader pairing "new pid" with "old main range" (or the title
   of one write with the pid of the next); the flip stress below detects exactly that
   by tying the fields of every publication to the generation it was published with:
   odd generation => target A, even generation => target B.  A reader that copies two
   different publications therefore sees a tuple that matches neither. */
#define ID_PID_A    0x1000ull
#define ID_PROG_A   0xA000ull
#define ID_BASE_A   0x00100000ull
#define ID_SIZE_A   0x00200000ull
#define ID_PID_B    0x2000ull
#define ID_PROG_B   0xB000ull
#define ID_BASE_B   0x00300000ull
#define ID_SIZE_B   0x00400000ull

static void testTargetIdentitySnapshot(void) {
    printf("- target identity is one consistent snapshot\n");
    freshSession();

    NxusTargetIdentity id;
    CHECK(nxusSessionTargetIdentity(&id), "an empty session still samples an identity");
    CHECK(id.pid == 0 && id.program_id == 0 && id.main_base == 0 && id.main_size == 0 &&
          id.generation == 0u,
          "fresh session publishes the empty identity (gen=%u, pid=0x%llX)",
          (unsigned)id.generation, (unsigned long long)id.pid);
    CHECK(nxusSessionTargetIdentity(NULL), "out=NULL only asks whether a sample succeeded");

    nxusSessionSetProcessIdentityEx(ID_PID_A, ID_PROG_A, ID_BASE_A, ID_SIZE_A);
    CHECK(nxusSessionTargetIdentity(&id), "identity sampled after the first write");
    CHECK(id.pid == ID_PID_A && id.program_id == ID_PROG_A &&
          id.main_base == ID_BASE_A && id.main_size == ID_SIZE_A,
          "all four fields describe the same write (pid=0x%llX base=0x%llX)",
          (unsigned long long)id.pid, (unsigned long long)id.main_base);
    CHECK(id.generation == 1u, "the write bumps the generation (%u)", (unsigned)id.generation);

    /* The compat accessors sample the same snapshot. */
    CHECK(nxusSessionProcessId() == ID_PID_A, "ProcessId() agrees with the snapshot");
    CHECK(nxusSessionProgramId() == ID_PROG_A, "ProgramId() agrees with the snapshot");
    CHECK(nxusSessionMainBase() == ID_BASE_A, "MainBase() agrees with the snapshot");
    CHECK(nxusSessionMainSize() == ID_SIZE_A, "MainSize() agrees with the snapshot");

    /* A copy the caller already holds keeps its values: it is a snapshot, not a
       view onto the live fields. */
    const NxusTargetIdentity held = id;
    nxusSessionSetProcessIdentityEx(ID_PID_B, ID_PROG_B, ID_BASE_B, ID_SIZE_B);
    CHECK(held.pid == ID_PID_A && held.main_base == ID_BASE_A,
          "a held snapshot is not rewritten by a later publication");

    CHECK(nxusSessionTargetIdentity(&id), "identity sampled after the second write");
    CHECK(id.pid == ID_PID_B && id.program_id == ID_PROG_B &&
          id.main_base == ID_BASE_B && id.main_size == ID_SIZE_B,
          "the second write is published as one unit too");
    CHECK(id.generation == 2u, "the generation counts publications (%u)", (unsigned)id.generation);

    /* SetProcessIdentity() carries no program id: it must publish 0 for it, in the
       same write as the new pid / main range (not leave the old title behind). */
    nxusSessionSetProcessIdentity(ID_PID_A, ID_BASE_A, ID_SIZE_A);
    CHECK(nxusSessionTargetIdentity(&id), "identity sampled after a SetProcessIdentity()");
    CHECK(id.pid == ID_PID_A && id.program_id == 0 &&
          id.main_base == ID_BASE_A && id.main_size == ID_SIZE_A,
          "the pid-only write replaces the title with 0 atomically");
    CHECK(id.generation == 3u, "every write bumps the generation once (%u)",
          (unsigned)id.generation);

    nxusSessionExit();
}

/* Concurrent reader/writer: no sample may blend two publications. */
#define ID_FLIP_WRITES  5000u
#define ID_FLIP_READERS 2

static atomic_int  g_IdStop;
static atomic_uint g_IdWrites;
static atomic_uint g_IdSamples;
static atomic_uint g_IdMixed;
static atomic_uint g_IdNoSample;

static void *identityFlipWriter(void *arg) {
    (void)arg;
    while (atomic_load_explicit(&g_IdStop, memory_order_acquire) == 0) {
        const u32 n = atomic_fetch_add_explicit(&g_IdWrites, 1u, memory_order_relaxed) + 1u;
        if ((n & 1u) != 0u) {
            nxusSessionSetProcessIdentityEx(ID_PID_A, ID_PROG_A, ID_BASE_A, ID_SIZE_A);
        } else {
            nxusSessionSetProcessIdentityEx(ID_PID_B, ID_PROG_B, ID_BASE_B, ID_SIZE_B);
        }
    }
    return NULL;
}

static void *identityFlipReader(void *arg) {
    (void)arg;
    while (atomic_load_explicit(&g_IdStop, memory_order_acquire) == 0) {
        NxusTargetIdentity id;
        if (!nxusSessionTargetIdentity(&id)) {
            /* Allowed by the contract ("writer kept the seqlock busy"); no torn value
               is returned, so counting it separately keeps the test meaningful. */
            atomic_fetch_add_explicit(&g_IdNoSample, 1u, memory_order_relaxed);
            continue;
        }
        atomic_fetch_add_explicit(&g_IdSamples, 1u, memory_order_relaxed);

        bool mixed;
        if (id.generation == 0u) {
            /* Before the writer's first publication. */
            mixed = id.pid != 0 || id.program_id != 0 || id.main_base != 0 || id.main_size != 0;
        } else if ((id.generation & 1u) != 0u) {
            mixed = id.pid != ID_PID_A || id.program_id != ID_PROG_A ||
                    id.main_base != ID_BASE_A || id.main_size != ID_SIZE_A;
        } else {
            mixed = id.pid != ID_PID_B || id.program_id != ID_PROG_B ||
                    id.main_base != ID_BASE_B || id.main_size != ID_SIZE_B;
        }
        if (mixed) atomic_fetch_add_explicit(&g_IdMixed, 1u, memory_order_relaxed);
    }
    return NULL;
}

static void testTargetIdentityNoTornRead(void) {
    printf("- identity writes are atomic for concurrent readers\n");
    freshSession();

    atomic_store(&g_IdStop, 0);
    atomic_store(&g_IdWrites, 0);
    atomic_store(&g_IdSamples, 0);
    atomic_store(&g_IdMixed, 0);
    atomic_store(&g_IdNoSample, 0);

    pthread_t readers[ID_FLIP_READERS];
    int started = 0;
    for (int i = 0; i < ID_FLIP_READERS; i++) {
        if (pthread_create(&readers[i], NULL, identityFlipReader, NULL) != 0) break;
        started++;
    }
    CHECK(started == ID_FLIP_READERS, "started %d/%d identity readers", started,
          ID_FLIP_READERS);

    pthread_t writer;
    const bool writer_started = pthread_create(&writer, NULL, identityFlipWriter, NULL) == 0;
    CHECK(writer_started, "started the identity writer");

    if (writer_started) {
        /* Let the writer run; readers sample concurrently.  Yielding keeps the
           writer (and the readers) scheduled without a fixed wall-clock sleep. */
        while (atomic_load_explicit(&g_IdWrites, memory_order_acquire) < ID_FLIP_WRITES) {
            svcSleepThread(0);
        }
    }
    atomic_store(&g_IdStop, 1);
    if (writer_started) pthread_join(writer, NULL);
    for (int i = 0; i < started; i++) pthread_join(readers[i], NULL);

    CHECK(atomic_load(&g_IdMixed) == 0u,
          "%u identity sample(s) mixed two publications (new pid + old main range)",
          atomic_load(&g_IdMixed));
    CHECK(atomic_load(&g_IdSamples) > 0u, "readers actually sampled the identity (%u)",
          atomic_load(&g_IdSamples));

    /* Everything settled: the last publication is visible as one target, and the
       generation counts exactly the writes performed. */
    NxusTargetIdentity id;
    CHECK(nxusSessionTargetIdentity(&id), "identity sampled after the writer stopped");
    CHECK(id.generation == atomic_load(&g_IdWrites),
          "generation counts every publication (%u/%u)", (unsigned)id.generation,
          atomic_load(&g_IdWrites));
    const bool is_a = (id.generation & 1u) != 0u;
    CHECK(is_a ? (id.pid == ID_PID_A && id.program_id == ID_PROG_A &&
                  id.main_base == ID_BASE_A && id.main_size == ID_SIZE_A)
               : (id.pid == ID_PID_B && id.program_id == ID_PROG_B &&
                  id.main_base == ID_BASE_B && id.main_size == ID_SIZE_B),
          "the final identity is one complete publication (gen=%u pid=0x%llX)",
          (unsigned)id.generation, (unsigned long long)id.pid);
    CHECK(nxusSessionProcessId() == id.pid &&
          nxusSessionProgramId() == id.program_id &&
          nxusSessionMainBase() == id.main_base &&
          nxusSessionMainSize() == id.main_size,
          "the compat accessors report the same final target");

    nxusSessionExit();
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

/* dmnt's cheat-process incarnation (nxusDmntTargetIncarnation).  The real counter
   lives in shared/nxus_dmntcht.c and only moves when dmnt opens a process; here the
   tests drive it directly so "the same pid in a restarted process" is expressible. */
u32 nxusDmntTargetIncarnation(void) {
    return g_FakeIncarnation;
}

/* ---- main --------------------------------------------------------------- */

int main(void) {
    g_Verbose = getenv("NXUS_TEST_VERBOSE") != NULL;
    printf("=== session view lifetime (pin / retire) ===\n");

    testPublishRetainsPinnedBlock();
    testTokenPinOwnership();
    testForgottenPinIsDetected();
    testPinTableLimit();
    testCompatPinBookkeeping();
    testUnpinnedPublishDrains();
    testLegacyCallerNeverReleases();
    testRegionsHoldAcrossRebuild();
    testHitsRescueShiftedRebuild();
    testHitsRescueDropsOnlyUnresolvable();
    testHitsRescueSameBaseReuse();
    testHitsRescueUnsortedTable();
    testHitsIncarnationMismatch();
    testHitsRevalidateOnlySameIncarnation();
    testHitsRescueValueMustFitMapping();
    testExitIsTerminal();
    testConcurrentReaders();
    testNoMixedViewSample();
    testHitLimitBudget();
    testTargetIdentitySnapshot();
    testTargetIdentityNoTornRead();

    /* Leave the module in the state the console leaves it in at shutdown. */
    nxusSessionExit();

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    if (g_failures == 0) printf("ALL SESSION-VIEW TESTS PASSED\n");
    else printf("SESSION-VIEW TESTS FAILED\n");
    return g_failures == 0 ? 0 : 1;
}
