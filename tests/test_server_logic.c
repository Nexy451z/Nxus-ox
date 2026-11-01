/*
 * Host tests for the server/session algorithms that have no regression coverage.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * `switch/source/nxus_server.c` is a 4,520-line libnx translation unit with 103
 * external Nxus/Nintendo dependencies, so it is not host-linkable (yet).  This
 * file therefore keeps the *algorithms* under test in a self-contained white-box
 * harness: each block mirrors the production code at the line range named in its
 * comment, and the assertions pin the contract that code must keep.  Keeping the
 * harness independent of `nxus_server.c` means the server test can run while the
 * server translation unit itself is being edited.
 *
 * Covered:
 *   (a) the 4 KiB pointer-scan page cache: page-end clamping, zero-fill of an
 *       unmapped suffix, cross-page single-IPC fallback, failed fills, the
 *       non-page-aligned mapping safety net, and overflow-safe bounds checks;
 *   (b) the frozen-ownership table: 128 entries, re-owning, removal, dropping an
 *       earlier target, and release-all returning the TRUE total (128) while the
 *       event payload stays capped at 32;
 *   (c) the tick's watchdog evaluation: while a scan job is RUNNING BOTH the scan
 *       progress/abandon check AND the 120 s synchronous-command stall check are
 *       evaluated (the old early return skipped the latter);
 *   (d) result classification: a libnx MAKERESULT(345, n) has no bit 31, native
 *       errors do, and NXUS' own `0x8003C8xx` codes put 484 in the libnx
 *       DESCRIPTION field - the trap that made resultIsNxusError() always false.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nxus_protocol.h"
#include "nxus_ptrscan.h"

static int g_checks;
static int g_failures;

#define CHECK(cond, ...) do {                                            \
        g_checks++;                                                      \
        if (!(cond)) {                                                   \
            g_failures++;                                                \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                \
            printf(__VA_ARGS__);                                         \
            printf("\n");                                                \
        }                                                                \
    } while (0)

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* ====================================================================== */
/* (a) 4 KiB pointer-scan page cache                                      */
/* ====================================================================== */

#define PAGE_SHIFT 12u
#define PAGE_SIZE  (1u << PAGE_SHIFT)
#define PAGE_MASK  ((u64)PAGE_SIZE - 1u)
#define PAGE_SLOTS 8u

typedef struct {
    u64 tag;
    u32 valid;
    u32 reserved;
    u8  data[PAGE_SIZE];
} TestPage;

static TestPage g_Pages[PAGE_SLOTS];
static u32      g_PageNext;
static u32      g_RegionHint;

static const NxusPtrRegion *g_Regions;
static u32                  g_RegionCount;

/* Mock target-side read: records every IPC and refuses any read that is not
   fully inside one mapping, so a missing page-end clamp is caught instead of
   being silently served. */
#define MAX_READ_LOG 16
static u32 g_ReadCalls;
static u64 g_ReadAddr[MAX_READ_LOG];
static u32 g_ReadSize[MAX_READ_LOG];
static int g_FailNextRead;

static u8 mockByte(u64 address) {
    /* Never zero: a zero-filled tail must not look like target data. */
    return (u8)(0x80u | (u8)((address >> 1) & 0x7Fu));
}

static bool mockRangeMapped(u64 address, u32 size) {
    if (size == 0) return false;
    for (u32 i = 0; i < g_RegionCount; i++) {
        const NxusPtrRegion *r = &g_Regions[i];
        if (r->size == 0 || r->base > address) continue;
        const u64 offset = address - r->base;
        if (offset >= r->size) continue;
        if ((u64)size <= r->size - offset) return true;
    }
    return false;
}

static int mockRead(u64 address, void *buffer, u32 size) {
    if (g_ReadCalls < MAX_READ_LOG) {
        g_ReadAddr[g_ReadCalls] = address;
        g_ReadSize[g_ReadCalls] = size;
    }
    g_ReadCalls++;
    if (g_FailNextRead > 0) {
        g_FailNextRead--;
        return -1;
    }
    if (!mockRangeMapped(address, size)) return -1;
    for (u32 i = 0; i < size; i++) ((u8 *)buffer)[i] = mockByte(address + i);
    return 0;
}

/* mirrors nxus_server.c:ptrScanRegionHolds() */
static bool regionHolds(const NxusPtrRegion *r, u64 address) {
    if (r->size == 0) return false;
    if (r->base > UINT64_MAX - (u64)r->size) return false;
    if (address < r->base) return false;
    return address - r->base < (u64)r->size;
}

/* mirrors nxus_server.c:ptrScanMappingFor() */
static bool mappingFor(u64 address, u64 *out_start, u64 *out_end) {
    if (g_Regions == NULL || g_RegionCount == 0) return false;

    u32 hint = g_RegionHint;
    if (hint >= g_RegionCount) hint = 0;
    if (regionHolds(&g_Regions[hint], address)) {
        *out_start = g_Regions[hint].base;
        *out_end = g_Regions[hint].base + (u64)g_Regions[hint].size;
        return true;
    }
    for (u32 i = 0; i < g_RegionCount; i++) {
        if (!regionHolds(&g_Regions[i], address)) continue;
        g_RegionHint = i;
        *out_start = g_Regions[i].base;
        *out_end = g_Regions[i].base + (u64)g_Regions[i].size;
        return true;
    }
    return false;
}

/* mirrors nxus_server.c:ptrScanPageCacheArm() */
static void cacheArm(const NxusPtrRegion *regions, u32 region_count) {
    for (u32 i = 0; i < PAGE_SLOTS; i++) {
        g_Pages[i].valid = 0;
        g_Pages[i].tag = 0;
    }
    g_PageNext = 0;
    g_Regions = regions;
    g_RegionCount = regions != NULL ? region_count : 0;
    g_RegionHint = 0;
}

static void testReset(void) {
    memset(g_Pages, 0, sizeof(g_Pages));
    memset(g_ReadAddr, 0, sizeof(g_ReadAddr));
    memset(g_ReadSize, 0, sizeof(g_ReadSize));
    g_PageNext = 0;
    g_RegionHint = 0;
    g_Regions = NULL;
    g_RegionCount = 0;
    g_ReadCalls = 0;
    g_FailNextRead = 0;
}

/* mirrors nxus_server.c:ptrScanPageFind() */
static TestPage *pageFind(u64 page) {
    for (u32 i = 0; i < PAGE_SLOTS; i++) {
        if (g_Pages[i].valid != 0 && g_Pages[i].tag == page) return &g_Pages[i];
    }
    return NULL;
}

/* mirrors nxus_server.c:ptrScanReadPaged() */
static int testReadPaged(u64 address, void *buffer, u32 size) {
    u8 *out = (u8 *)buffer;
    u32 done = 0;
    if (address > UINT64_MAX - (u64)size) return -1;

    if (size > 1u && size <= PAGE_SIZE) {
        const u64 first = address & ~PAGE_MASK;
        const u64 last = (address + (u64)size - 1u) & ~PAGE_MASK;
        if (last != first && pageFind(first) == NULL && pageFind(last) == NULL) {
            u64 map_start = 0;
            u64 map_end = 0;
            if (mappingFor(address, &map_start, &map_end) &&
                address < map_end && (u64)size <= map_end - address) {
                return mockRead(address, buffer, size) == 0 ? 0 : -1;
            }
        }
    }

    while (done < size) {
        const u64 addr = address + (u64)done;
        const u64 page = addr & ~PAGE_MASK;
        const u32 in_page = (u32)(addr - page);
        u32 chunk = PAGE_SIZE - in_page;
        if (chunk > size - done) chunk = size - done;

        u64 map_start = 0;
        u64 map_end = 0;
        if (!mappingFor(addr, &map_start, &map_end)) {
            if (done == 0) return -1;
            memset(out + done, 0, size - (size_t)done);
            return 0;
        }

        u32 mapped = chunk;
        if ((u64)chunk > map_end - addr) mapped = (u32)(map_end - addr);

        TestPage *slot = pageFind(page);
        if (slot != NULL && in_page + mapped <= slot->valid) {
            memcpy(out + done, slot->data + in_page, mapped);
            done += mapped;
            continue;
        }

        if (page < map_start) {
            if (mockRead(addr, out + done, mapped) != 0) return -1;
            done += mapped;
            continue;
        }

        u64 want64 = map_end - page;
        u32 want = PAGE_SIZE;
        if (want64 < (u64)want) want = (u32)want64;

        const u32 victim = g_PageNext;
        g_PageNext = (g_PageNext + 1u) % PAGE_SLOTS;
        TestPage *fill = &g_Pages[victim];
        fill->valid = 0;
        fill->tag = 0;
        if (mockRead(page, fill->data, want) != 0) return -1;
        fill->tag = page;
        fill->valid = want;

        memcpy(out + done, fill->data + in_page, mapped);
        done += mapped;
    }
    return 0;
}

/* mirrors nxus_server.c:ptrScanReadTarget() */
static int testReadTarget(u64 address, void *buffer, u32 size) {
    if (size > PAGE_SIZE) {
        u64 map_start = 0;
        u64 map_end = 0;
        if (mappingFor(address, &map_start, &map_end) &&
            address < map_end && size <= map_end - address) {
            return mockRead(address, buffer, size) == 0 ? 0 : -1;
        }
    }
    return testReadPaged(address, buffer, size);
}

static bool bytesMatch(u64 address, const u8 *buffer, u32 size) {
    for (u32 i = 0; i < size; i++) {
        if (buffer[i] != mockByte(address + i)) return false;
    }
    return true;
}

static bool bytesZero(const u8 *buffer, u32 size) {
    for (u32 i = 0; i < size; i++) {
        if (buffer[i] != 0) return false;
    }
    return true;
}

static void testPageCacheRegions(void) {
    printf("[test] page cache: overflow-safe region and request bounds\n");
    testReset();

    const NxusPtrRegion normal = { 0x1000u, 0x3000u, NXUS_PTRREGION_TRAVERSABLE, 0 };
    CHECK(regionHolds(&normal, 0x1000u), "region must contain its base");
    CHECK(regionHolds(&normal, 0x3FFFu), "region must contain its last byte");
    CHECK(!regionHolds(&normal, 0x4000u), "region must not contain its exclusive end");
    CHECK(!regionHolds(&normal, 0x0FFFu), "region must not contain the byte before its base");

    const NxusPtrRegion empty = { 0x1000u, 0, NXUS_PTRREGION_TRAVERSABLE, 0 };
    const NxusPtrRegion wrapped = { UINT64_MAX - 0x100u, 0x200u,
                                    NXUS_PTRREGION_TRAVERSABLE, 0 };
    CHECK(!regionHolds(&empty, 0x1000u), "a zero-sized region holds nothing");
    CHECK(!regionHolds(&wrapped, UINT64_MAX - 0x80u),
          "a region whose end wraps the address space holds nothing");

    const NxusPtrRegion regions[] = { normal, wrapped };
    cacheArm(regions, (u32)ARRAY_LEN(regions));
    u64 start = 0, end = 0;
    CHECK(!mappingFor(UINT64_MAX - 0x80u, &start, &end),
          "the wrapping region must not be selected as a mapping");
    CHECK(mappingFor(0x2000u, &start, &end) && start == 0x1000u && end == 0x4000u,
          "the normal region must still be found after the wrapping one");

    u8 out[8];
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(UINT64_MAX - 1u, out, 4u) == -1,
          "a request whose end wraps must fail");
    CHECK(g_ReadCalls == 0, "a wrapping request must not issue an IPC (got %u)",
          (unsigned)g_ReadCalls);
}

static void testPageCacheClampAndZeroFill(void) {
    printf("[test] page cache: mapping-end clamp and zero-filled suffix\n");
    testReset();
    const NxusPtrRegion regions[] = {
        { 0x1000u, 0x1800u, NXUS_PTRREGION_TRAVERSABLE, 0 },   /* ends 0x2800 */
    };
    cacheArm(regions, (u32)ARRAY_LEN(regions));

    u8 out[8];
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(0x27FCu, out, 8u) == 0,
          "a window that starts in the mapping and runs past its end must succeed");
    CHECK(g_ReadCalls == 1u, "the page must be fetched once (got %u IPCs)",
          (unsigned)g_ReadCalls);
    CHECK(g_ReadAddr[0] == 0x2000u && g_ReadSize[0] == 0x800u,
          "the page read must be clamped to map_end-page: got %llX/%u",
          (unsigned long long)g_ReadAddr[0], (unsigned)g_ReadSize[0]);
    CHECK(bytesMatch(0x27FCu, out, 4u), "the mapped 4 bytes must be target data");
    CHECK(bytesZero(out + 4, 4u), "the 4 bytes past the mapping must be zero-filled");

    TestPage *page = pageFind(0x2000u);
    CHECK(page != NULL, "the clamped page must be cached");
    CHECK(page != NULL && page->valid == 0x800u,
          "the cache must record exactly the clamped byte count, not a full page");
    CHECK(page != NULL && page->data[0] == mockByte(0x2000u),
          "the cached page must start at the page base");

    /* A later window in the cached page must be served without an IPC. */
    const u32 before = g_ReadCalls;
    u8 cached[16];
    memset(cached, 0xCC, sizeof(cached));
    CHECK(testReadPaged(0x2500u, cached, 16u) == 0 && g_ReadCalls == before,
          "a cached page must not issue another read");
    CHECK(bytesMatch(0x2500u, cached, 16u), "cached bytes must match the target");

    /* A request that starts outside every mapping is a fault, not a zero read. */
    const u32 after = g_ReadCalls;
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(0x2800u, out, 4u) == -1,
          "a request that starts unmapped must fail, not zero-fill");
    CHECK(g_ReadCalls == after, "an unmapped first byte must not issue an IPC");
}

static void testPageCacheFullPageEnd(void) {
    printf("[test] page cache: full final page then an unmapped tail\n");
    testReset();
    const NxusPtrRegion regions[] = {
        { 0x1000u, 0x3000u, NXUS_PTRREGION_TRAVERSABLE, 0 },   /* ends 0x4000 */
    };
    cacheArm(regions, (u32)ARRAY_LEN(regions));

    u8 out[4];
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(0x3FFEu, out, 4u) == 0, "a window over the last page must succeed");
    CHECK(g_ReadCalls == 1u && g_ReadAddr[0] == 0x3000u && g_ReadSize[0] == PAGE_SIZE,
          "the final page is page-aligned, so the full 4 KiB is read");
    CHECK(bytesMatch(0x3FFEu, out, 2u), "the last mapped 2 bytes must be target data");
    CHECK(bytesZero(out + 2, 2u), "the 2 bytes after the mapping must be zero");
}

static void testPageCacheGapAndContiguousMapping(void) {
    printf("[test] page cache: unmapped gap zero-fill and contiguous next mapping\n");
    testReset();
    const NxusPtrRegion gapped[] = {
        { 0x1000u, 0x1000u, NXUS_PTRREGION_TRAVERSABLE, 0 },   /* ends 0x2000 */
        { 0x3000u, 0x1000u, NXUS_PTRREGION_TRAVERSABLE, 0 },   /* gap 0x2000..0x3000 */
    };
    cacheArm(gapped, (u32)ARRAY_LEN(gapped));

    u8 out[8];
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(0x1FFCu, out, 8u) == 0,
          "a window ending in a gap must succeed with a zero-filled tail");
    CHECK(bytesMatch(0x1FFCu, out, 4u), "the bytes before the gap must be target data");
    CHECK(bytesZero(out + 4, 4u), "the bytes in the gap must be zero");
    CHECK(testReadPaged(0x2000u, out, 4u) == -1,
          "a request starting in the gap must still fail");

    testReset();
    const NxusPtrRegion contiguous[] = {
        { 0x1000u, 0x1000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { 0x2000u, 0x1000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
    };
    cacheArm(contiguous, (u32)ARRAY_LEN(contiguous));
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(0x1FFCu, out, 8u) == 0,
          "a window crossing into the next contiguous mapping must succeed");
    CHECK(g_ReadCalls == 2u, "both pages must be fetched for the contiguous case");
    CHECK(bytesMatch(0x1FFCu, out, 8u),
          "no byte may be zeroed when the next mapping starts at the boundary");
}

static void testPageCacheCrossPageFallback(void) {
    printf("[test] page cache: cross-page single-IPC fallback\n");
    testReset();
    const NxusPtrRegion regions[] = {
        { 0x1000u, 0x2000u, NXUS_PTRREGION_TRAVERSABLE, 0 },   /* ends 0x3000 */
    };
    cacheArm(regions, (u32)ARRAY_LEN(regions));

    u8 out[4];
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(0x1FFEu, out, 4u) == 0, "a cross-page window must succeed");
    CHECK(g_ReadCalls == 1u, "both-uncached cross-page reads must use ONE IPC (got %u)",
          (unsigned)g_ReadCalls);
    CHECK(g_ReadAddr[0] == 0x1FFEu && g_ReadSize[0] == 4u,
          "the fallback must read exactly the window: got %llX/%u",
          (unsigned long long)g_ReadAddr[0], (unsigned)g_ReadSize[0]);
    CHECK(bytesMatch(0x1FFEu, out, 4u), "the fallback bytes must match the target");
    CHECK(pageFind(0x1000u) == NULL && pageFind(0x2000u) == NULL,
          "a fallback read must not populate either page slot");

    /* With the FIRST page cached the fallback is skipped and only the second
       page is fetched: still one IPC, and the cached half comes from RAM. */
    cacheArm(regions, (u32)ARRAY_LEN(regions));
    u8 prime[4];
    CHECK(testReadPaged(0x1000u, prime, sizeof(prime)) == 0, "prime the first page");
    const u32 first_ipcs = g_ReadCalls;
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(0x1FFEu, out, 4u) == 0, "cross-page with the first page cached");
    CHECK(g_ReadCalls == first_ipcs + 1u,
          "only the missing page is fetched when one page is cached");
    CHECK(g_ReadAddr[first_ipcs] == 0x2000u && g_ReadSize[first_ipcs] == PAGE_SIZE,
          "the missing page is fetched from its page base");
    CHECK(bytesMatch(0x1FFEu, out, 4u), "both halves must be correct");

    /* Same with the SECOND page cached. */
    cacheArm(regions, (u32)ARRAY_LEN(regions));
    CHECK(testReadPaged(0x2000u, prime, sizeof(prime)) == 0, "prime the second page");
    const u32 second_ipcs = g_ReadCalls;
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(0x1FFEu, out, 4u) == 0, "cross-page with the second page cached");
    CHECK(g_ReadCalls == second_ipcs + 1u,
          "only the missing first page is fetched when the second is cached");
    CHECK(g_ReadAddr[second_ipcs] == 0x1000u && g_ReadSize[second_ipcs] == PAGE_SIZE,
          "the missing first page is fetched from its page base");
    CHECK(bytesMatch(0x1FFEu, out, 4u), "both halves must be correct");
}

static void testPageCacheUnalignedMapping(void) {
    printf("[test] page cache: non-page-aligned mapping safety net\n");
    testReset();
    const NxusPtrRegion regions[] = {
        { 0x1800u, 0x2000u, NXUS_PTRREGION_TRAVERSABLE, 0 },   /* ends 0x3800 */
    };
    cacheArm(regions, (u32)ARRAY_LEN(regions));

    u8 out[16];
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(0x1800u, out, sizeof(out)) == 0,
          "a request in a non-page-aligned mapping must succeed");
    CHECK(g_ReadCalls == 1u && g_ReadAddr[0] == 0x1800u &&
          g_ReadSize[0] == (u32)sizeof(out),
          "a mapping that starts mid-page must be read directly, not cached");
    CHECK(bytesMatch(0x1800u, out, (u32)sizeof(out)), "the direct read must match the target");
    for (u32 i = 0; i < PAGE_SLOTS; i++) {
        CHECK(g_Pages[i].valid == 0,
              "no page may be cached from a non-page-aligned mapping (slot %u)", i);
    }

    CHECK(testReadPaged(0x17F0u, out, 4u) == -1,
          "a request before the unaligned mapping must fail");
}

static void testPageCacheFailedFill(void) {
    printf("[test] page cache: a failed fill must invalidate its victim slot\n");
    testReset();
    const NxusPtrRegion regions[] = {
        { 0x1000u, 0x3000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
    };
    cacheArm(regions, (u32)ARRAY_LEN(regions));

    /* Poison slot 0 with a DIFFERENT page's tag and plausible bytes.  The victim
       is about to be reused for 0x2000, and the production code clears valid/tag
       BEFORE the read, so a failed fill must leave the slot dead - never serving
       the old page's bytes under the new tag. */
    g_Pages[0].tag = 0x1000u;
    g_Pages[0].valid = PAGE_SIZE;
    memset(g_Pages[0].data, 0xEE, PAGE_SIZE);
    g_PageNext = 0;
    g_FailNextRead = 1;

    u8 out[4];
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(0x2000u, out, sizeof(out)) == -1, "the injected read must fail");
    CHECK(g_Pages[0].valid == 0 && g_Pages[0].tag == 0,
          "a failed fill must clear the victim's valid/tag");
    CHECK(pageFind(0x2000u) == NULL, "the failed page must not be findable");

    const u32 after_fail = g_ReadCalls;
    memset(out, 0xCC, sizeof(out));
    CHECK(testReadPaged(0x2000u, out, sizeof(out)) == 0,
          "the next attempt must retry the read");
    CHECK(g_ReadCalls == after_fail + 1u, "the retry must issue exactly one IPC");
    CHECK(bytesMatch(0x2000u, out, sizeof(out)),
          "the retry must serve target data, never the poisoned bytes");
}

static void testPageCacheChunkPath(void) {
    printf("[test] page cache: >4 KiB chunk path and a chunk crossing map end\n");
    testReset();
    const NxusPtrRegion regions[] = {
        { 0x1000u, 0x3000u, NXUS_PTRREGION_TRAVERSABLE, 0 },   /* ends 0x4000 */
    };
    cacheArm(regions, (u32)ARRAY_LEN(regions));

    static u8 chunk[0x2000];
    memset(chunk, 0xCC, sizeof(chunk));
    CHECK(testReadTarget(0x1800u, chunk, (u32)sizeof(chunk)) == 0,
          "a >4 KiB chunk inside one mapping must succeed");
    CHECK(g_ReadCalls == 1u && g_ReadAddr[0] == 0x1800u &&
          g_ReadSize[0] == (u32)sizeof(chunk),
          "a chunk inside one mapping must be one IPC, not per-page reads");
    CHECK(bytesMatch(0x1800u, chunk, (u32)sizeof(chunk)), "the chunk must match the target");
    CHECK(pageFind(0x1000u) == NULL && pageFind(0x2000u) == NULL,
          "a direct chunk must not populate the page cache");

    /* A >4 KiB chunk that runs off the mapping end falls through to the page
       path: it serves the mapped bytes and zero-fills the tail. */
    testReset();
    const NxusPtrRegion short_region[] = {
        { 0x1000u, 0x1800u, NXUS_PTRREGION_TRAVERSABLE, 0 },   /* ends 0x2800 */
    };
    cacheArm(short_region, (u32)ARRAY_LEN(short_region));
    static u8 big[0x1000];
    memset(big, 0xCC, sizeof(big));
    CHECK(testReadTarget(0x2000u, big, (u32)sizeof(big)) == 0,
          "a chunk crossing the mapping end must still succeed");
    CHECK(g_ReadCalls == 1u && g_ReadAddr[0] == 0x2000u && g_ReadSize[0] == 0x800u,
          "the final page of the mapping must be read clamped to 0x800 B");
    CHECK(bytesMatch(0x2000u, big, 0x800u), "the mapped half must be target data");
    CHECK(bytesZero(big + 0x800u, 0x800u), "the unmapped half must be zero-filled");
}

/* ====================================================================== */
/* (b) frozen ownership table                                             */
/* ====================================================================== */

#define FROZEN_OWNED_MAX 128
#define FROZEN_EVENT_MAX 32

typedef struct {
    u64 address;
    u64 pid;
    u64 program_id;
    u32 incarnation;
} TestFrozenOwner;

typedef struct {
    TestFrozenOwner owned[FROZEN_OWNED_MAX];
    u32 count;

    /* target the session is on now */
    u64 pid;
    u64 program_id;
    u32 incarnation;

    bool debug_attached;

    /* released / queued state (mirrors g_FrozenReleased*) */
    u64 released[FROZEN_OWNED_MAX];
    u32 released_count;
    u64 pending[FROZEN_EVENT_MAX];
    u32 pending_count;
    u32 released_total;

    /* captured event */
    u32 event_sends;
    u32 event_count;
    u64 event_addresses[FROZEN_EVENT_MAX];
    u32 event_sent;
} TestFrozen;

static void frozenReset(TestFrozen *f, u64 pid, u64 program_id, u32 incarnation) {
    memset(f, 0, sizeof(*f));
    f->pid = pid;
    f->program_id = program_id;
    f->incarnation = incarnation;
}

/* mirrors nxus_server.c:frozenOwnerIsCurrent() */
static bool frozenOwnerIsCurrent(const TestFrozenOwner *o, u64 pid, u64 program_id,
                                 u32 incarnation) {
    if (o->incarnation != incarnation) return false;
    if (o->pid != pid) return false;
    return o->program_id == 0 || program_id == 0 || o->program_id == program_id;
}

/* mirrors nxus_server.c:frozenOwnedAdd() */
static void frozenAdd(TestFrozen *f, u64 address) {
    for (u32 i = 0; i < f->count; i++) {
        if (f->owned[i].address == address) {
            if (!frozenOwnerIsCurrent(&f->owned[i], f->pid, f->program_id,
                                      f->incarnation)) {
                f->owned[i].pid = f->pid;
                f->owned[i].program_id = f->program_id;
                f->owned[i].incarnation = f->incarnation;
            }
            return;
        }
    }
    if (f->count >= FROZEN_OWNED_MAX) return;   /* logged in production */
    f->owned[f->count].address = address;
    f->owned[f->count].pid = f->pid;
    f->owned[f->count].program_id = f->program_id;
    f->owned[f->count].incarnation = f->incarnation;
    f->count++;
}

/* mirrors nxus_server.c:frozenOwnedRemove() */
static void frozenRemove(TestFrozen *f, u64 address) {
    for (u32 i = 0; i < f->count; i++) {
        if (f->owned[i].address == address) {
            f->owned[i] = f->owned[--f->count];
            return;
        }
    }
}

static bool frozenContains(const TestFrozen *f, u64 address) {
    for (u32 i = 0; i < f->count; i++) {
        if (f->owned[i].address == address) return true;
    }
    return false;
}

/* mirrors nxus_server.c:frozenOwnedDropEarlierTarget() */
static u32 frozenDropEarlier(TestFrozen *f) {
    u32 dropped = 0;
    for (u32 i = 0; i < f->count; ) {
        if (frozenOwnerIsCurrent(&f->owned[i], f->pid, f->program_id,
                                 f->incarnation)) {
            i++;
            continue;
        }
        f->owned[i] = f->owned[--f->count];
        dropped++;
    }
    return dropped;
}

/* mirrors nxus_server.c:sendFrozenReleasedEvent() */
static void frozenSendEvent(TestFrozen *f, u32 total, const u64 *addresses) {
    const u32 sent = total < FROZEN_EVENT_MAX ? total : FROZEN_EVENT_MAX;
    f->event_sends++;
    f->event_count = total;
    f->event_sent = sent;
    for (u32 i = 0; i < sent; i++) f->event_addresses[i] = addresses[i];
}

/* mirrors nxus_server.c:releaseOwnedFrozen(), but returns the released total so
   the test can assert the "true total" contract directly (production tracks it
   in g_FrozenReleasedTotal). */
static u32 frozenReleaseAll(TestFrozen *f) {
    u64 release_all[FROZEN_OWNED_MAX];
    u32 release_all_count = 0;
    u64 released_addresses[FROZEN_EVENT_MAX];
    u32 released = 0;
    u32 snapshot = 0;

    if (f->count == 0) return 0;
    if (f->debug_attached) return 0;

    for (u32 i = 0; i < f->count; i++) {
        if (!frozenOwnerIsCurrent(&f->owned[i], f->pid, f->program_id,
                                  f->incarnation)) {
            continue;
        }
        if (released < FROZEN_EVENT_MAX) {
            released_addresses[released] = f->owned[i].address;
        }
        if (release_all_count < FROZEN_OWNED_MAX) {
            release_all[release_all_count++] = f->owned[i].address;
        }
        released++;
    }
    snapshot = released < FROZEN_EVENT_MAX ? released : FROZEN_EVENT_MAX;
    f->count = 0;

    if (released == 0) return 0;

    for (u32 i = 0; i < release_all_count; i++) {
        f->released[f->released_count++] = release_all[i];
    }
    f->released_total += released;
    for (u32 i = 0; i < snapshot && f->pending_count < FROZEN_EVENT_MAX; i++) {
        f->pending[f->pending_count++] = released_addresses[i];
    }
    return released;
}

/* mirrors nxus_server.c:flushFrozenReleased() */
static void frozenFlush(TestFrozen *f) {
    u64 addresses[FROZEN_EVENT_MAX];
    const u32 total = f->released_total;
    const u32 count = f->pending_count;
    for (u32 i = 0; i < count; i++) addresses[i] = f->pending[i];
    f->released_total = 0;
    f->pending_count = 0;
    if (total != 0) frozenSendEvent(f, total, addresses);
}

static void testFrozenCapacityAndReown(void) {
    printf("[test] frozen table: 128-entry cap and re-owning an address\n");
    TestFrozen f;
    frozenReset(&f, 10u, 0xAAu, 1u);

    for (u32 i = 0; i < FROZEN_OWNED_MAX; i++) frozenAdd(&f, 0x10000u + i);
    CHECK(f.count == FROZEN_OWNED_MAX, "the table must hold %u entries (got %u)",
          FROZEN_OWNED_MAX, f.count);
    CHECK(frozenContains(&f, 0x10000u) && frozenContains(&f, 0x1007Fu),
          "the first and last tracked addresses must be present");

    frozenAdd(&f, 0x20000u);
    CHECK(f.count == FROZEN_OWNED_MAX,
          "a 129th address must be refused, not evict a tracked one");
    CHECK(!frozenContains(&f, 0x20000u), "the refused address must not be tracked");

    /* Same address under a new target: re-owned in place, never duplicated. */
    frozenReset(&f, 20u, 0xBBu, 2u);
    frozenAdd(&f, 0x5000u);
    frozenAdd(&f, 0x6000u);
    CHECK(f.count == 2u, "two distinct addresses must occupy two entries");
    f.pid = 30u;
    f.program_id = 0xCCu;
    f.incarnation = 3u;
    frozenAdd(&f, 0x5000u);
    CHECK(f.count == 2u, "re-adding an address must not grow the table");
    CHECK(f.owned[0].pid == 30u && f.owned[0].program_id == 0xCCu &&
          f.owned[0].incarnation == 3u,
          "the existing entry must be re-stamped for the current target");
}

static void testFrozenRemoveAndDrop(void) {
    printf("[test] frozen table: swap-remove and dropping an earlier target\n");
    TestFrozen f;
    frozenReset(&f, 10u, 0xAAu, 1u);
    frozenAdd(&f, 0x100u);
    frozenAdd(&f, 0x200u);
    frozenAdd(&f, 0x300u);
    frozenRemove(&f, 0x200u);
    CHECK(f.count == 2u && frozenContains(&f, 0x100u) && frozenContains(&f, 0x300u),
          "removing one address must keep the other two");
    frozenRemove(&f, 0x999u);
    CHECK(f.count == 2u, "removing an unknown address must not change the table");

    frozenReset(&f, 10u, 0xAAu, 1u);
    for (u32 i = 0; i < 5u; i++) frozenAdd(&f, 0x1000u + i);
    f.pid = 20u;
    f.program_id = 0xBBu;
    f.incarnation = 2u;
    for (u32 i = 0; i < 2u; i++) frozenAdd(&f, 0x2000u + i);
    CHECK(frozenDropEarlier(&f) == 5u, "all five entries of the earlier target must drop");
    CHECK(f.count == 2u && frozenContains(&f, 0x2000u) && frozenContains(&f, 0x2001u),
          "only the current target's entries may remain");
    CHECK(f.released_count == 0u, "dropping an earlier target must not release anything");
}

static void testFrozenReleaseAll(void) {
    printf("[test] frozen release-all: 128 releases, event capped at 32, true total\n");
    TestFrozen f;
    frozenReset(&f, 10u, 0xAAu, 1u);
    for (u32 i = 0; i < FROZEN_OWNED_MAX; i++) frozenAdd(&f, 0x30000u + i);

    CHECK(frozenReleaseAll(&f) == FROZEN_OWNED_MAX,
          "release-all must report the true total (%u), not the 32-entry event cap",
          FROZEN_OWNED_MAX);
    CHECK(f.count == 0u, "release-all must clear the ownership table");
    CHECK(f.released_count == FROZEN_OWNED_MAX,
          "all %u addresses must be disabled through dmnt (got %u)",
          FROZEN_OWNED_MAX, f.released_count);
    CHECK(f.released[0] == 0x30000u && f.released[FROZEN_OWNED_MAX - 1u] == 0x3007Fu,
          "the release loop must cover the first and last address");
    CHECK(f.released_total == FROZEN_OWNED_MAX,
          "the queued total must be the true released count");
    CHECK(f.pending_count == FROZEN_EVENT_MAX,
          "only %u addresses may be queued for the event (got %u)",
          FROZEN_EVENT_MAX, f.pending_count);

    frozenFlush(&f);
    CHECK(f.event_sends == 1u, "exactly one FrozenReleased event must be sent");
    CHECK(f.event_count == FROZEN_OWNED_MAX,
          "the event count must be the true total (%u), got %u",
          FROZEN_OWNED_MAX, f.event_count);
    CHECK(f.event_sent == FROZEN_EVENT_MAX,
          "the event array must carry exactly %u addresses", FROZEN_EVENT_MAX);
    CHECK(f.event_addresses[0] == 0x30000u &&
          f.event_addresses[FROZEN_EVENT_MAX - 1u] == 0x3001Fu,
          "the event must carry the first 32 released addresses in order");
}

static void testFrozenReleaseMixedAndGuards(void) {
    printf("[test] frozen release-all: earlier-target drop, attached and empty guards\n");
    TestFrozen f;
    frozenReset(&f, 10u, 0xAAu, 1u);
    for (u32 i = 0; i < 10u; i++) frozenAdd(&f, 0x40000u + i);
    f.pid = 20u;
    f.program_id = 0xBBu;
    f.incarnation = 2u;
    for (u32 i = 0; i < 40u; i++) frozenAdd(&f, 0x50000u + i);

    CHECK(frozenReleaseAll(&f) == 40u,
          "only current-target entries may be released (got wrong total)");
    CHECK(f.count == 0u, "the table must be cleared of both current and earlier entries");
    CHECK(f.released_count == 40u, "the earlier-target entries must not be disabled");
    CHECK(f.pending_count == FROZEN_EVENT_MAX,
          "the event payload must still be capped at 32");
    frozenFlush(&f);
    CHECK(f.event_count == 40u && f.event_sent == 32u,
          "the event must say 40 total but carry 32 addresses");

    /* Debug-attached is a hard gate: nothing is released, the table survives. */
    frozenReset(&f, 10u, 0xAAu, 1u);
    frozenAdd(&f, 0x7000u);
    frozenAdd(&f, 0x7008u);
    f.debug_attached = true;
    CHECK(frozenReleaseAll(&f) == 0u, "release-all must do nothing while a debug session is attached");
    CHECK(f.count == 2u && f.released_count == 0u,
          "the attached guard must keep the bookkeeping and issue no dmnt write");

    /* Only an earlier target: the table is dropped, but nothing is released. */
    frozenReset(&f, 10u, 0xAAu, 1u);
    frozenAdd(&f, 0x8000u);
    f.pid = 20u;
    f.program_id = 0xBBu;
    f.incarnation = 2u;
    CHECK(frozenReleaseAll(&f) == 0u,
          "an earlier target's entries must not be released");
    CHECK(f.count == 0u && f.released_count == 0u && f.pending_count == 0u,
          "the stale bookkeeping must be dropped without an event");

    frozenReset(&f, 10u, 0xAAu, 1u);
    CHECK(frozenReleaseAll(&f) == 0u, "an empty table must release nothing");
}

/* ====================================================================== */
/* (c) tick watchdog evaluation                                           */
/* ====================================================================== */

#define COMMAND_GRACE_MS        120000u
#define PTRSCAN_BUDGET_MS        90000u
#define PTRSCAN_SLACK_MS         30000u
#define SCAN_ABANDON_MS          60000u

typedef struct {
    bool server_exited;
    bool command_active;
    bool scan_running;       /* nxusSessionScanState() == Running */
    bool ptr_job_running;    /* asynchronous pointer scan worker */
    bool client_connected;
    u64  command_started_ms;
    u64  ptr_job_started_ms;
    u64  last_client_ms;

    bool scan_cancel_requested;
    bool ptr_cancel_requested;
    bool watchdog_re_enabled;

    int scan_progress_checks;
    int command_stall_checks;
    int reaper_runs;
} TestTick;

/* This is the CONTRACT the tick must implement, not a copy of the current early
   return.  The order is the fix: the scan progress/deadman block is evaluated
   first, and the 120 s synchronous-command guard is evaluated next even when the
   scan is Running.  Only the grace period itself may defer the reapers. */
static void testTick(TestTick *t, u64 now_ms) {
    if (t->server_exited) return;

    if (t->scan_running) {
        t->scan_progress_checks++;
        if (!t->client_connected && t->last_client_ms != 0 &&
            now_ms >= t->last_client_ms &&
            now_ms - t->last_client_ms >= SCAN_ABANDON_MS) {
            t->scan_cancel_requested = true;
        }
    }
    if (t->ptr_job_running) {
        t->scan_progress_checks++;
        const u64 limit_ms = PTRSCAN_BUDGET_MS + PTRSCAN_SLACK_MS;
        if (t->ptr_job_started_ms != 0 && now_ms > t->ptr_job_started_ms &&
            now_ms - t->ptr_job_started_ms > limit_ms) {
            t->ptr_cancel_requested = true;
        } else if (!t->client_connected && t->last_client_ms != 0 &&
                   now_ms >= t->last_client_ms &&
                   now_ms - t->last_client_ms >= SCAN_ABANDON_MS) {
            t->ptr_cancel_requested = true;
        }
    }

    if (t->command_active) {
        t->command_stall_checks++;
        const u64 started = t->command_started_ms;
        if (started != 0 && now_ms >= started &&
            now_ms - started < COMMAND_GRACE_MS) {
            return;   /* a legitimate long handler: keep the reapers off */
        }
        t->watchdog_re_enabled = true;
        t->command_active = false;
    }

    t->reaper_runs++;
}

static void tickReset(TestTick *t) {
    memset(t, 0, sizeof(*t));
    t->client_connected = true;
    t->last_client_ms = 1000u;
}

static void testWatchdogRunningScan(void) {
    printf("[test] tick: a RUNNING scan must not skip the 120 s command-stall check\n");
    TestTick t;

    /* Just inside the grace period: both checks run, but the command holds. */
    tickReset(&t);
    t.scan_running = true;
    t.command_active = true;
    t.command_started_ms = 1000u;
    testTick(&t, 1000u + COMMAND_GRACE_MS - 1u);
    CHECK(t.scan_progress_checks == 1,
          "the scan progress check must run while a command is active (got %d)",
          t.scan_progress_checks);
    CHECK(t.command_stall_checks == 1,
          "the 120 s command-stall check must also run during a Running scan");
    CHECK(!t.watchdog_re_enabled && t.command_active,
          "inside the grace period the command must stay active");
    CHECK(t.reaper_runs == 0, "the reapers must stay off inside the grace period");

    /* At exactly 120 s the stall MUST be detected even though the scan is
       Running - this is the path the old unconditional early return skipped. */
    tickReset(&t);
    t.scan_running = true;
    t.command_active = true;
    t.command_started_ms = 1000u;
    testTick(&t, 1000u + COMMAND_GRACE_MS);
    CHECK(t.scan_progress_checks == 1,
          "the scan progress check must still run at the grace boundary");
    CHECK(t.command_stall_checks == 1,
          "the command-stall check must run at the grace boundary");
    CHECK(t.watchdog_re_enabled,
          "a 120 s synchronous command must re-enable the watchdog while a scan runs");
    CHECK(!t.command_active, "the stalled command must be cleared");
    CHECK(t.reaper_runs == 1,
          "the reapers must run once the stalled command has been cleared");
}

static void testWatchdogScanProgress(void) {
    printf("[test] tick: scan progress/abandon and pointer-scan deadman are evaluated\n");
    TestTick t;

    tickReset(&t);
    t.scan_running = true;
    t.client_connected = false;
    t.last_client_ms = 1000u;
    testTick(&t, 1000u + SCAN_ABANDON_MS);
    CHECK(t.scan_progress_checks == 1, "the abandoned-scan check must run");
    CHECK(t.scan_cancel_requested,
          "a scan with no client for 60 s must be cancelled");
    CHECK(t.command_stall_checks == 0,
          "no command is active, so the stall check must not run");
    CHECK(t.reaper_runs == 1, "the reapers still run when no command is active");

    tickReset(&t);
    t.ptr_job_running = true;
    t.ptr_job_started_ms = 1000u;
    testTick(&t, 1000u + PTRSCAN_BUDGET_MS + PTRSCAN_SLACK_MS);
    CHECK(t.scan_progress_checks == 1,
          "the pointer-scan deadman check must run at budget + slack");
    CHECK(!t.ptr_cancel_requested,
          "budget + slack exactly is not yet over the deadman limit");
    testTick(&t, 1001u + PTRSCAN_BUDGET_MS + PTRSCAN_SLACK_MS);
    CHECK(t.ptr_cancel_requested,
          "one millisecond past budget + slack must cancel the wedged walk");

    tickReset(&t);
    t.ptr_job_running = true;
    t.ptr_job_started_ms = 1000u;
    t.client_connected = false;
    t.last_client_ms = 1000u;
    testTick(&t, 1000u + SCAN_ABANDON_MS);
    CHECK(t.ptr_cancel_requested,
          "a pointer scan whose client has been gone for 60 s must be cancelled");
}

static void testWatchdogOtherStates(void) {
    printf("[test] tick: scan without command, command without scan, terminal gate\n");
    TestTick t;

    tickReset(&t);
    t.scan_running = true;
    testTick(&t, 5000u);
    CHECK(t.scan_progress_checks == 1 && t.command_stall_checks == 0,
          "a Running scan alone runs only the scan progress check");
    CHECK(t.reaper_runs == 1, "the reapers run when no command is active");

    tickReset(&t);
    t.command_active = true;
    t.command_started_ms = 1000u;
    testTick(&t, 1000u + COMMAND_GRACE_MS);
    CHECK(t.scan_progress_checks == 0 && t.command_stall_checks == 1,
          "a synchronous command without a scan runs only the stall check");
    CHECK(t.watchdog_re_enabled && !t.command_active && t.reaper_runs == 1,
          "the 120 s bound must clear the command and run the reapers");

    tickReset(&t);
    t.server_exited = true;
    t.scan_running = true;
    t.command_active = true;
    t.command_started_ms = 1u;
    testTick(&t, 1000u + COMMAND_GRACE_MS);
    CHECK(t.scan_progress_checks == 0 && t.command_stall_checks == 0,
          "the terminal gate must short-circuit both checks");
    CHECK(t.reaper_runs == 0, "the tick after Exit must not run the reapers");
}

/* ====================================================================== */
/* (d) result classification                                              */
/* ====================================================================== */

/* The two macros libnx uses (switch/result.h).  Reproduced here so the test can
   host-compile without libnx; the field widths are the point. */
#define R_MODULE(res)      ((u32)(res) & 0x1FFu)
#define R_DESCRIPTION(res) (((u32)(res) >> 9) & 0x1FFFu)
#define LIBNX_MAKERESULT(module, desc) \
    ((u32)(((u32)(module) & 0x1FFu) | (((u32)(desc) & 0x1FFFu) << 9)))

/* The buggy production helper at nxus_server.c:1047: it feeds NXUS' custom
   layout into the libnx field macros, so it can never match. */
static bool resultIsNxusErrorLibnxMacros(u32 rc, u32 desc) {
    return R_MODULE(rc) == NXUS_RESULT_MODULE && R_DESCRIPTION(rc) == desc;
}

/* The wire-compatible decoder: bit 31, module 484 in bits 17..9, descriptor in
   bits 8..0 (which is what NXUS_MAKE_RESULT actually writes). */
static bool resultIsNxusErrorWire(u32 rc, u32 desc) {
    return (rc & 0x80000000u) != 0 &&
           (((rc >> 9) & 0x1FFu) == NXUS_RESULT_MODULE) &&
           ((rc & 0x1FFu) == (desc & 0x1FFu));
}

typedef enum {
    TEST_RC_SUCCESS = 0,
    TEST_RC_LIBNX_ERROR,     /* bit 31 clear, non-zero: HOS/libnx failure */
    TEST_RC_NXUS_ERROR,      /* bit 31 set, NXUS custom encoding */
    TEST_RC_NATIVE_ERROR,    /* bit 31 set, anything else */
} TestResultClass;

static TestResultClass classifyResult(u32 rc) {
    if (rc == 0) return TEST_RC_SUCCESS;
    if (resultIsNxusErrorWire(rc, rc & 0x1FFu)) return TEST_RC_NXUS_ERROR;
    if ((rc & 0x80000000u) != 0) return TEST_RC_NATIVE_ERROR;
    return TEST_RC_LIBNX_ERROR;
}

static void testResultClassification(void) {
    printf("[test] result codes: libnx MAKERESULT(345,n), NXUS 0x8003C8xx, native\n");

    /* libnx/HOS errors do NOT set bit 31. */
    const u32 libnx_bad_input = LIBNX_MAKERESULT(345u, 11u);
    CHECK(libnx_bad_input == 0x00001759u,
          "MAKERESULT(345, 11) must be 0x00001759 (got 0x%08X)", libnx_bad_input);
    CHECK((libnx_bad_input & 0x80000000u) == 0,
          "a libnx result must leave bit 31 clear");
    CHECK(R_MODULE(libnx_bad_input) == 345u && R_DESCRIPTION(libnx_bad_input) == 11u,
          "the libnx field macros must decode module 345 / description 11");
    CHECK(libnx_bad_input != 0 && classifyResult(libnx_bad_input) == TEST_RC_LIBNX_ERROR,
          "a bit-31-clear non-zero result is a libnx failure");
    CHECK(!resultIsNxusErrorWire(libnx_bad_input, NXUS_ERR_BUSY),
          "a libnx error must never be mistaken for an NXUS BUSY");

    /* NXUS' own encoding: bit 31 + 484 in the HOS DESCRIPTION field + desc in
       the low 9 bits.  This is deliberately NOT libnx MAKERESULT layout. */
    const u32 nxus_busy = NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    const u32 nxus_bad_state = NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    CHECK(nxus_busy == 0x8003C803u,
          "NXUS_MAKE_RESULT(BUSY) must be 0x8003C803 (got 0x%08X)", nxus_busy);
    CHECK(nxus_bad_state == 0x8003C806u,
          "NXUS_MAKE_RESULT(BAD_STATE) must be 0x8003C806 (got 0x%08X)", nxus_bad_state);
    CHECK((nxus_busy >> 31) != 0, "an NXUS result must set bit 31");
    CHECK(R_MODULE(nxus_busy) == NXUS_ERR_BUSY,
          "libnx R_MODULE() reads the NXUS *description* (%u), not module 484",
          R_MODULE(nxus_busy));
    CHECK(R_DESCRIPTION(nxus_busy) == NXUS_RESULT_MODULE,
          "libnx R_DESCRIPTION() reads the NXUS *module* (%u)",
          R_DESCRIPTION(nxus_busy));

    /* The exact production bug: the libnx-macro helper never matches. */
    CHECK(!resultIsNxusErrorLibnxMacros(nxus_busy, NXUS_ERR_BUSY),
          "the old R_MODULE()/R_DESCRIPTION() helper must be false for NXUS codes");
    CHECK(!resultIsNxusErrorLibnxMacros(nxus_bad_state, NXUS_ERR_BAD_STATE),
          "the old helper must also miss BAD_STATE");
    CHECK(resultIsNxusErrorWire(nxus_busy, NXUS_ERR_BUSY),
          "the wire-layout decoder must recognise NXUS BUSY");
    CHECK(resultIsNxusErrorWire(nxus_bad_state, NXUS_ERR_BAD_STATE),
          "the wire-layout decoder must recognise NXUS BAD_STATE");
    CHECK(!resultIsNxusErrorWire(nxus_busy, NXUS_ERR_BAD_STATE),
          "the descriptor must still be compared, not just the module");
    CHECK(classifyResult(nxus_busy) == TEST_RC_NXUS_ERROR,
          "NXUS BUSY must classify as an NXUS error");
    CHECK(classifyResult(nxus_bad_state) == TEST_RC_NXUS_ERROR,
          "NXUS BAD_STATE must classify as an NXUS error");

    /* A native bit-31 error from another module must not become NXUS. */
    const u32 native_error = LIBNX_MAKERESULT(2u, 5u) | 0x80000000u;
    CHECK((native_error & 0x80000000u) != 0, "the native fixture must set bit 31");
    CHECK(classifyResult(native_error) == TEST_RC_NATIVE_ERROR,
          "a bit-31 result that is not NXUS must classify as a native error");
    CHECK(!resultIsNxusErrorWire(native_error, NXUS_ERR_BUSY),
          "a native error must not be decoded as NXUS BUSY");
    CHECK(classifyResult(0) == TEST_RC_SUCCESS, "result 0 is success");
}

/* ====================================================================== */
/* (e) status tail layout + code-patch write policy                       */
/* ====================================================================== */

/* Mirrors nxus_session.c:sessionRangePermits().  A normal write requires R+W;
   NXUS_WRITE_FLAG_ALLOW_RX accepts R + (W or X), which is how a PC cheat
   patches RX .text without giving every write RX permission.  The range must
   also fit inside ONE mapping: a straddling patch would be applied with one
   region's attributes. */
typedef struct {
    u64 base;
    u64 size;
    u32 perm;
} TestMapping;

static bool testRangePermits(const TestMapping *m, u64 address, u64 size, bool allow_rx) {
    if (m == NULL || size == 0) return false;
    if (address > UINT64_MAX - size) return false;
    if (m->size == 0 || m->base > address) return false;
    const u64 offset = address - m->base;
    if (offset >= m->size) return false;
    if (size > m->size - offset) return false;

    const u32 perm = m->perm & (NXUS_PERM_R | NXUS_PERM_W | NXUS_PERM_X);
    if ((perm & NXUS_PERM_R) == 0) return false;
    if (allow_rx) return (perm & (NXUS_PERM_W | NXUS_PERM_X)) != 0;
    return (perm & NXUS_PERM_W) != 0;
}

static void testStatusLayoutAndCodePatchPolicy(void) {
    printf("[test] NxusStatus tail, write flags, RX/RW code-patch gate\n");

    /* Chapter 7 rule: fields are appended, so the old 76-byte prefix keeps its
       layout and only the total grows to 84. */
    CHECK(sizeof(NxusStatus) == 84u, "NxusStatus must be 84 bytes (got %u)",
          (unsigned)sizeof(NxusStatus));
    CHECK(offsetof(NxusStatus, keys_held) == 76u,
          "keys_held must start at the old status end (got %u)",
          (unsigned)offsetof(NxusStatus, keys_held));
    CHECK(NXUS_STATUS_MIN_SIZE == 76u, "the legacy status prefix stays 76 bytes");
    CHECK(offsetof(NxusStatus, max_read) + sizeof(u32) == NXUS_STATUS_MIN_SIZE,
          "the 76-byte prefix must end after max_read");

    NxusStatus st;
    memset(&st, 0, sizeof(st));
    st.max_read = 0xAABBCCDDu;
    st.keys_held = 0x0123456789ABCDEFull;
    CHECK(st.max_read == 0xAABBCCDDu, "max_read sits before the appended tail");
    u64 raw_keys = 0;
    memcpy(&raw_keys, ((const u8 *)&st) + 76u, sizeof(raw_keys));
    CHECK(raw_keys == 0x0123456789ABCDEFull,
          "keys_held is the u64 at byte 76 (read 0x%016llX)",
          (unsigned long long)raw_keys);

    CHECK(sizeof(NxusWriteHeader) == 16u, "NxusWriteHeader stays 16 bytes");
    CHECK(NXUS_WRITE_FLAG_ALLOW_RX == 0x01u,
          "NXUS_WRITE_FLAG_ALLOW_RX must be bit 0 (got 0x%X)",
          (unsigned)NXUS_WRITE_FLAG_ALLOW_RX);

    TestMapping rx = {0x7100000000ull, 0x4000ull, NXUS_PERM_R | NXUS_PERM_X};
    TestMapping ro = {0x7200000000ull, 0x2000ull, NXUS_PERM_R};
    TestMapping rw = {0x7300000000ull, 0x3000ull, NXUS_PERM_R | NXUS_PERM_W};

    CHECK(testRangePermits(&rx, rx.base, rx.size, true),
          "an RX .text range passes the ALLOW_RX check");
    CHECK(!testRangePermits(&rx, rx.base, rx.size, false),
          "the same RX .text range fails a normal writable check");
    CHECK(testRangePermits(&rw, rw.base + 0x40, 0x10, true),
          "RW .data passes the ALLOW_RX check");
    CHECK(testRangePermits(&rw, rw.base, rw.size, false),
          "RW .data passes the normal writable check");
    CHECK(!testRangePermits(&ro, ro.base, ro.size, true),
          "RO .rodata is never patchable");
    CHECK(!testRangePermits(&rx, rx.base + rx.size - 0x10, 0x20, true),
          "a patch crossing the mapping end is refused");
    CHECK(!testRangePermits(&rx, rx.base, 0, true), "a zero-length patch is refused");
    CHECK(!testRangePermits(&rx, UINT64_MAX, 2, true),
          "an address+size overflow is refused");
    CHECK(!testRangePermits(NULL, 0x1000u, 1u, true),
          "an unmapped range is refused (no containing mapping)");
}

/* ====================================================================== */

int main(void) {
    printf("=== Nxus server/session algorithm tests ===\n");

    testPageCacheRegions();
    testPageCacheClampAndZeroFill();
    testPageCacheFullPageEnd();
    testPageCacheGapAndContiguousMapping();
    testPageCacheCrossPageFallback();
    testPageCacheUnalignedMapping();
    testPageCacheFailedFill();
    testPageCacheChunkPath();

    testFrozenCapacityAndReown();
    testFrozenRemoveAndDrop();
    testFrozenReleaseAll();
    testFrozenReleaseMixedAndGuards();

    testWatchdogRunningScan();
    testWatchdogScanProgress();
    testWatchdogOtherStates();

    testResultClassification();
    testStatusLayoutAndCodePatchPolicy();

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
