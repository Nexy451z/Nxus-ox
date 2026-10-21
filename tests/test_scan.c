/*
 * Host-side tests for the Nxus portable scan engine.
 *
 * These run on Windows/Linux with a plain C compiler - no Switch, no emulator,
 * no hardware.  They are the main "proof" that the scan core behaves before the
 * console arrives.
 *
 *   gcc -std=c11 -O2 -Wall -I../core -o test_scan test_scan.c ../core/nxus_scan.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nxus_scan.h"

/* ------------------------------------------------------------------ */
/* tiny test framework                                                 */
/* ------------------------------------------------------------------ */

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (!(cond)) {                                               \
            g_failures++;                                            \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);            \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
        }                                                            \
    } while (0)

/* ------------------------------------------------------------------ */
/* fake target process                                                 */
/* ------------------------------------------------------------------ */

#define MAP0_BASE   0x10000000ull
#define MAP0_SIZE   (2u * 1024 * 1024)
#define MAP1_BASE   0x30000000ull
#define MAP1_SIZE   (2u * 1024 * 1024)
#define FAKE_SIZE   (MAP0_SIZE + MAP1_SIZE)

/* an unreadable hole inside mapping 0, to exercise failure handling */
#define HOLE_OFF    0x100000u
#define HOLE_BASE   (MAP0_BASE + HOLE_OFF)
#define HOLE_SIZE   (64u * 1024)

typedef struct {
    u8  *mem;          /* MAP0 bytes followed by MAP1 bytes */
    u64  reads;
    u64  bytes_read;
    int  fail_hole;    /* when non-zero, reads overlapping the hole fail */
    int *cancel_ptr;   /* optional: set to 1 after cancel_after reads */
    u32  cancel_after;
    u32  cancel_reads;
} FakeTarget;

static NxusMappingTable g_maps;

/* guest address -> index into t->mem; fails for unmapped/gap addresses */
static int translate(FakeTarget *t, u64 address, u32 size, u64 *out_index) {
    (void)t;
    if (address >= MAP0_BASE && address + size <= MAP0_BASE + MAP0_SIZE) {
        *out_index = address - MAP0_BASE;
        return 1;
    }
    if (address >= MAP1_BASE && address + size <= MAP1_BASE + MAP1_SIZE) {
        *out_index = MAP0_SIZE + (address - MAP1_BASE);
        return 1;
    }
    return 0;
}

static int fakeRead(void *ctx, u64 address, void *buffer, u32 size) {
    FakeTarget *t = (FakeTarget *)ctx;
    u64 index = 0;

    t->reads++;
    t->bytes_read += size;

    if (t->cancel_ptr != NULL && ++t->cancel_reads >= t->cancel_after) {
        *t->cancel_ptr = 1;   /* simulate the PC asking to cancel mid-scan */
    }

    if (t->fail_hole && address < HOLE_BASE + HOLE_SIZE && address + size > HOLE_BASE) {
        return -1;
    }
    if (!translate(t, address, size, &index)) return -1;

    memcpy(buffer, t->mem + index, size);
    return 0;
}

/* A reader that refuses anything larger than 4096 bytes, like dmnt may do. */
static int fakeReadLimited(void *ctx, u64 address, void *buffer, u32 size) {
    if (size > 4096u) return -1;
    return fakeRead(ctx, address, buffer, size);
}

static void writeU32(FakeTarget *t, u64 address, u32 value) {
    u64 index = 0;
    if (!translate(t, address, 4, &index)) { printf("  BUG: write outside fake target at %llx\n", (unsigned long long)address); exit(2); }
    memcpy(t->mem + index, &value, 4);
}

static u32 readU32(FakeTarget *t, u64 address) {
    u64 index = 0;
    if (!translate(t, address, 4, &index)) return 0xFFFFFFFFu;
    u32 v;
    memcpy(&v, t->mem + index, 4);
    return v;
}

static void writeBytes(FakeTarget *t, u64 address, const void *src, u32 size) {
    u64 index = 0;
    if (!translate(t, address, size, &index)) {
        printf("  BUG: write outside fake target at %llx\n", (unsigned long long)address);
        exit(2);
    }
    memcpy(t->mem + index, src, size);
}

static void setupTarget(FakeTarget *t) {
    t->mem = (u8 *)calloc(1, FAKE_SIZE);
    t->reads = 0;
    t->bytes_read = 0;
    t->fail_hole = 1;
    t->cancel_ptr = NULL;
    t->cancel_after = 0;
    t->cancel_reads = 0;

    g_maps.count = 2;
    g_maps.entries = (NxusMappingEntry *)calloc(2, sizeof(NxusMappingEntry));
    g_maps.entries[0].base = MAP0_BASE; g_maps.entries[0].size = MAP0_SIZE; g_maps.entries[0].valid = 1;
    g_maps.entries[1].base = MAP1_BASE; g_maps.entries[1].size = MAP1_SIZE; g_maps.entries[1].valid = 1;
}

static void teardownTarget(FakeTarget *t) {
    free(t->mem);
    free(g_maps.entries);
    g_maps.entries = NULL;
    g_maps.count = 0;
}

/* ------------------------------------------------------------------ */
/* naive reference implementation (independent of the engine)          */
/* ------------------------------------------------------------------ */

#define REF_MAX 65536
typedef struct { u64 addr; u32 value; } RefHit;

static int refFirstU32(FakeTarget *t, const NxusScanRegion *regions, u32 region_count,
                       u32 target, NxusHitList *hits, RefHit *out) {
    int n = 0;
    for (u32 r = 0; r < region_count; r++) {
        u64 a = (regions[r].base + 3) & ~3ull;
        for (; a + 4 <= regions[r].base + regions[r].size; a += 4) {
            u64 off = a - regions[r].base;
            if (off > 0xFFFFFFFFull) continue;
            u32 v;
            if (fakeRead(t, a, &v, 4) != 0) continue;
            if (v == target) {
                if (n < REF_MAX) { out[n].addr = a; out[n].value = v; }
                n++;
            }
        }
    }
    (void)hits;
    return n;
}

/* verify engine hits against the reference list (order-insensitive, no dupes) */
static void compareHitSets(NxusHitList *hits, const NxusMappingTable *maps,
                           const RefHit *ref, int ref_count, const char *label) {
    CHECK((int)hits->count == ref_count, "%s: hit count %u != reference %d", label, hits->count, ref_count);
    int matched = 0;
    for (u32 i = 0; i < hits->count; i++) {
        u64 addr = 0;
        CHECK(nxusHitResolve(hits, maps, i, &addr) == 1, "%s: hit %u not resolvable", label, i);
        int found = 0;
        for (int j = 0; j < ref_count && j < REF_MAX; j++) {
            if (ref[j].addr == addr) { found = 1; break; }
        }
        if (found) matched++;
    }
    CHECK(matched == ref_count, "%s: %d/%d reference hits present in engine output", label, matched, ref_count);
}

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

static void testFirstScanExact(void) {
    printf("[test] first scan: exact u32 match\n");
    FakeTarget t; setupTarget(&t);

    const u64 planted[] = { MAP0_BASE + 0x1000, MAP0_BASE + 0x12344, MAP1_BASE + 0x2000 };
    for (unsigned i = 0; i < sizeof(planted) / sizeof(planted[0]); i++) writeU32(&t, planted[i], 0xDEADBEEF);

    NxusScanRegion regions[2] = {
        { MAP0_BASE, MAP0_SIZE, NXUS_PERM_R, 0, 0 },
        { MAP1_BASE, MAP1_SIZE, NXUS_PERM_R, 1, 0 },
    };
    NxusScanRequest req; memset(&req, 0, sizeof(req));
    req.kind = NxusScanKind_First; req.value_size = 4;
    req.cmp_mode = NxusCmp_Equal; req.target = 0xDEADBEEF;

    NxusHitList hits;
    CHECK(nxusHitListInit(&hits, 16, 1u << 20, 4) == NXUS_SCAN_OK, "hit list init");
    u8 *chunk = (u8 *)malloc(256 * 1024u);
    NxusScanStats st;

    int rc = nxusScanFirst(regions, 2, &req, &hits, fakeRead, &t, chunk, 256 * 1024u, &st, NULL);
    CHECK(rc == NXUS_SCAN_OK, "scan rc=%d", rc);
    CHECK(hits.count == 3, "expected 3 hits, got %u", hits.count);

    for (unsigned i = 0; i < 3; i++) {
        u64 addr = 0;
        CHECK(nxusHitResolve(&hits, &g_maps, i, &addr) == 1, "resolve %u", i);
        CHECK(addr == planted[i], "hit %u address %llx != %llx", i,
              (unsigned long long)addr, (unsigned long long)planted[i]);
    }

    /* values must be captured for the refine pass */
    u32 v0; memcpy(&v0, hits.values, 4);
    CHECK(v0 == 0xDEADBEEF, "stored value %x", v0);

    /* queries stats */
    CHECK(st.bytes_scanned == MAP0_SIZE + MAP1_SIZE, "scanned %llu bytes", (unsigned long long)st.bytes_scanned);
    CHECK(st.permille == 1000, "permille %u", st.permille);

    free(chunk);
    nxusHitListFree(&hits);
    teardownTarget(&t);
}

static void testRefineAndCoalescing(void) {
    printf("[test] refine pass: sparse coalescing + in-place compaction\n");
    FakeTarget t; setupTarget(&t);

    const int n = 64;
    u64 addrs[64];
    for (int i = 0; i < n; i++) {
        addrs[i] = MAP0_BASE + 0x4000 + (u64)i * 0x1000;   /* 4KB apart -> needs coalescing */
        writeU32(&t, addrs[i], 100);
    }
    /* one extra far away to force a second window */
    u64 far = MAP1_BASE + 0x8000;
    writeU32(&t, far, 100);

    NxusScanRegion regions[2] = {
        { MAP0_BASE, MAP0_SIZE, NXUS_PERM_R, 0, 0 },
        { MAP1_BASE, MAP1_SIZE, NXUS_PERM_R, 1, 0 },
    };
    NxusScanRequest req; memset(&req, 0, sizeof(req));
    req.value_size = 4; req.cmp_mode = NxusCmp_Equal; req.target = 100;

    NxusHitList hits;
    nxusHitListInit(&hits, 8, 1u << 20, 4);
    u8 *chunk = (u8 *)malloc(128 * 1024u);
    int rc = nxusScanFirst(regions, 2, &req, &hits, fakeRead, &t, chunk, 128 * 1024u, NULL, NULL);
    CHECK(rc == NXUS_SCAN_OK && hits.count == 65, "first scan hits=%u rc=%d", hits.count, rc);

    /* mutate: half increase, half stay */
    for (int i = 0; i < n; i++) if (i % 2 == 0) writeU32(&t, addrs[i], 250);
    writeU32(&t, far, 250);

    NxusScanRequest next; memset(&next, 0, sizeof(next));
    next.value_size = 4; next.cmp_mode = NxusCmp_Increased;

    u8 *window = (u8 *)malloc(64 * 1024u);
    t.reads = 0; t.bytes_read = 0;
    NxusScanStats st;
    rc = nxusScanNext(&hits, &next, &g_maps, fakeRead, &t, window, 32 * 1024u, 16 * 1024u, &st, NULL);
    CHECK(rc == NXUS_SCAN_OK, "refine rc=%d", rc);
    CHECK(hits.count == 33, "increased hits %u (expected 33)", hits.count);

    /* in-place compaction must keep the list ordered and self-consistent */
    int ordered = 1;
    for (u32 i = 1; i < hits.count; i++) {
        if (hits.addresses[i - 1].mapping_idx > hits.addresses[i].mapping_idx) ordered = 0;
        else if (hits.addresses[i - 1].mapping_idx == hits.addresses[i].mapping_idx &&
                 hits.addresses[i - 1].offset >= hits.addresses[i].offset) ordered = 0;
    }
    CHECK(ordered, "hit list not ordered after in-place compaction");

    /* values must have been refreshed to the *current* value */
    for (u32 i = 0; i < hits.count; i++) {
        u64 addr = 0; nxusHitResolve(&hits, &g_maps, i, &addr);
        u32 stored; memcpy(&stored, hits.values + (size_t)i * 4, 4);
        CHECK(stored == readU32(&t, addr), "stored value stale at %llx", (unsigned long long)addr);
        CHECK(stored == 250, "expected 250 at %llx", (unsigned long long)addr);
    }

    /* coalescing: window_max (32KB) caps a window's span, so 65 hits spread over
       256KB of mapping 0 plus one hit in mapping 1 must cost ~9 reads, not 33. */
    const u64 naive_reads = hits.count;
    CHECK(t.reads <= 10, "coalescing ineffective: %llu reads for %u hits", (unsigned long long)t.reads, hits.count);
    CHECK(t.reads * 3 <= naive_reads, "expected >=3x fewer reads: %llu vs %llu",
          (unsigned long long)t.reads, (unsigned long long)naive_reads);
    printf("       coalescing: %u hits -> %llu reads (%llux), %llu bytes read\n",
           hits.count, (unsigned long long)t.reads, (unsigned long long)(naive_reads / t.reads),
           (unsigned long long)t.bytes_read);

    free(window); free(chunk);
    nxusHitListFree(&hits);
    teardownTarget(&t);
}

static void testCancelConsistency(void) {
    printf("[test] mid-scan cancellation keeps the hit list consistent and reusable\n");
    FakeTarget t; setupTarget(&t);

    const u32 total = 4096;
    for (u32 i = 0; i < total; i++) writeU32(&t, MAP0_BASE + 0x1000 + (u64)i * 4, 7);

    NxusScanRegion regions[1] = { { MAP0_BASE, MAP0_SIZE, NXUS_PERM_R, 0, 0 } };
    NxusScanRequest req; memset(&req, 0, sizeof(req));
    req.value_size = 4; req.cmp_mode = NxusCmp_Equal; req.target = 7;

    NxusHitList hits;
    nxusHitListInit(&hits, 16, 1u << 20, 4);
    u8 *chunk = (u8 *)malloc(64 * 1024u);

    /* --- phase 1: cancel before the first chunk even completes --- */
    int cancel = 1;
    int rc = nxusScanFirst(regions, 1, &req, &hits, fakeRead, &t, chunk, 64 * 1024u, NULL, &cancel);
    CHECK(rc == NXUS_SCAN_ERR_CANCELLED, "expected cancel, got %d", rc);
    CHECK(hits.count == 0, "a cancel before the first chunk must keep 0 hits, got %u", hits.count);

    /* --- phase 2: a full first pass, then cancel a refine pass mid-way --- */
    cancel = 0;
    rc = nxusScanFirst(regions, 1, &req, &hits, fakeRead, &t, chunk, 64 * 1024u, NULL, NULL);
    CHECK(rc == NXUS_SCAN_OK && hits.count == total, "first pass hits=%u rc=%d", hits.count, rc);

    /* every 4th value stops matching: 1024 of 4096, spread across both windows */
    for (u32 i = 0; i < total; i += 4) writeU32(&t, MAP0_BASE + 0x1000 + (u64)i * 4, 9);

    NxusScanRequest next; memset(&next, 0, sizeof(next));
    next.value_size = 4; next.cmp_mode = NxusCmp_Equal; next.target = 7;

    u8 *window = (u8 *)malloc(16 * 1024u);
    int cancel2 = 0;
    /* hits are 4 bytes apart over 16KB and window_max is 8KB, so the pass needs
       two reads; cancelling after the first read must commit window 1 only. */
    t.cancel_ptr = &cancel2; t.cancel_after = 1; t.cancel_reads = 0;
    int rc2 = nxusScanNext(&hits, &next, &g_maps, fakeRead, &t, window, 8 * 1024u, 4096u, NULL, &cancel2);
    CHECK(rc2 == NXUS_SCAN_ERR_CANCELLED, "expected mid-refine cancel, got %d", rc2);

    /* the partial result must be committed and self-consistent */
    CHECK(cancel2 == 1, "cancel flag not observed");
    CHECK(hits.count <= total, "post-cancel count %u exceeds %u", hits.count, total);
    int bad = 0;
    u32 prev_map = 0, prev_off = 0;
    for (u32 i = 0; i < hits.count; i++) {
        u64 addr = 0;
        if (!nxusHitResolve(&hits, &g_maps, i, &addr)) { bad++; continue; }
        if (i > 0 && (hits.addresses[i].mapping_idx < prev_map ||
                      (hits.addresses[i].mapping_idx == prev_map && hits.addresses[i].offset <= prev_off))) bad++;
        prev_map = hits.addresses[i].mapping_idx;
        prev_off = hits.addresses[i].offset;
        /* the refined prefix (window 1) is verified; the tail is explicitly
           unverified and may still hold the pre-refine value */
        if (i < 1536 && readU32(&t, addr) != 7) bad++;
    }
    u32 tail_matches = 0;
    for (u32 i = 1536; i < hits.count; i++) {
        u64 addr = 0; nxusHitResolve(&hits, &g_maps, i, &addr);
        if (readU32(&t, addr) == 7) tail_matches++;
    }
    CHECK(tail_matches == 1536, "unrefined tail: %u/2048 still match (expected 1536)", tail_matches);
    CHECK(bad == 0, "%d corrupted entries after mid-refine cancel (count=%u)", bad, hits.count);
    /* 2048 hits in window 1 minus the 512 that changed = 1536 refined + 2048 untouched tail */
    CHECK(hits.count == 3584, "post-cancel count %u (expected 1536 refined + 2048 tail)", hits.count);
    printf("       partial refine: %u hits kept (1536 verified + 2048 pending)\n", hits.count);

    /* --- phase 3: the list must still be usable for a clean refine --- */
    t.cancel_ptr = NULL;
    int rc3 = nxusScanNext(&hits, &next, &g_maps, fakeRead, &t, window, 8 * 1024u, 4096u, NULL, NULL);
    CHECK(rc3 == NXUS_SCAN_OK, "resumed refine rc=%d", rc3);
    CHECK(hits.count == total - 1024, "final refine hits=%u (expected %u)", hits.count, total - 1024);

    u32 wrong = 0;
    for (u32 i = 0; i < hits.count; i++) {
        u64 addr = 0; nxusHitResolve(&hits, &g_maps, i, &addr);
        if (readU32(&t, addr) != 7) wrong++;
    }
    CHECK(wrong == 0, "%u final survivors do not match", wrong);

    free(window); free(chunk);
    nxusHitListFree(&hits);
    teardownTarget(&t);
}

static void testUnreadableRegion(void) {
    printf("[test] unreadable regions are skipped, not fatal\n");
    FakeTarget t; setupTarget(&t);

    /* plant hits either side of the unreadable hole (both inside mapping 0) */
    writeU32(&t, HOLE_BASE - 0x800, 0x11112222);
    writeU32(&t, HOLE_BASE + HOLE_SIZE + 0x800, 0x11112222);

    NxusScanRegion regions[1] = { { MAP0_BASE, MAP0_SIZE, NXUS_PERM_R, 0, 0 } };
    NxusScanRequest req; memset(&req, 0, sizeof(req));
    req.value_size = 4; req.cmp_mode = NxusCmp_Equal; req.target = 0x11112222;

    NxusHitList hits;
    nxusHitListInit(&hits, 8, 4096, 4);
    u8 *chunk = (u8 *)malloc(32 * 1024u);
    NxusScanStats st;
    int rc = nxusScanFirst(regions, 1, &req, &hits, fakeRead, &t, chunk, 32 * 1024u, &st, NULL);
    CHECK(rc == NXUS_SCAN_OK, "rc=%d", rc);
    CHECK(hits.count >= 1, "expected the hit before the hole, got %u", hits.count);
    CHECK(st.dropped >= 1, "expected dropped>0 (hole), got %u", st.dropped);

    free(chunk);
    nxusHitListFree(&hits);
    teardownTarget(&t);
}

static void testPageBoundaryAlignment(void) {
    printf("[test] hit values cross chunk boundaries correctly\n");
    FakeTarget t; setupTarget(&t);

    /* place hits exactly at the last 4 bytes of a 4096-byte chunk */
    for (int c = 0; c < 8; c++) {
        u64 a = MAP0_BASE + (u64)(c + 1) * 4096 - 4;
        writeU32(&t, a, 0xABCDEF01);
    }

    NxusScanRegion regions[1] = { { MAP0_BASE, 16 * 4096, NXUS_PERM_R, 0, 0 } };
    NxusScanRequest req; memset(&req, 0, sizeof(req));
    req.value_size = 4; req.cmp_mode = NxusCmp_Equal; req.target = 0xABCDEF01;

    NxusHitList hits;
    nxusHitListInit(&hits, 8, 4096, 4);
    u8 *chunk = (u8 *)malloc(4096);
    int rc = nxusScanFirst(regions, 1, &req, &hits, fakeRead, &t, chunk, 4096, NULL, NULL);
    CHECK(rc == NXUS_SCAN_OK, "rc=%d", rc);
    CHECK(hits.count == 8, "boundary hits %u (expected 8)", hits.count);

    free(chunk);
    nxusHitListFree(&hits);
    teardownTarget(&t);
}

static void testFirstScanDifferential(void) {
    printf("[test] differential: engine vs naive reference over random memory\n");
    FakeTarget t; setupTarget(&t);

    NxusScanRegion regions[2] = {
        { MAP0_BASE, 256 * 1024, NXUS_PERM_R, 0, 0 },
        { MAP1_BASE, 256 * 1024, NXUS_PERM_R, 1, 0 },
    };

    unsigned seed = 12345;
    int rounds = 0;
    for (int round = 0; round < 20; round++) {
        /* random content with a tunable density of the target value */
        u32 target = 0x1000 + (u32)round;
        int planted = 0;
        for (u64 off = 0; off < 256 * 1024; off += 4) {
            seed = seed * 1103515245u + 12345u;
            u32 v = (seed >> 8) & 0xFFF;
            if (v == (target & 0xFFF)) {
                writeU32(&t, MAP0_BASE + off, target);
                writeU32(&t, MAP1_BASE + off, target);
                planted += 2;
            } else {
                writeU32(&t, MAP0_BASE + off, v);
                writeU32(&t, MAP1_BASE + off, v);
            }
        }

        NxusScanRequest req; memset(&req, 0, sizeof(req));
        req.value_size = 4; req.cmp_mode = NxusCmp_Equal; req.target = target;

        NxusHitList hits;
        nxusHitListInit(&hits, 64, 1u << 20, 4);
        u8 *chunk = (u8 *)malloc(48 * 1024u);
        int rc = nxusScanFirst(regions, 2, &req, &hits, fakeRead, &t, chunk, 48 * 1024u, NULL, NULL);
        CHECK(rc == NXUS_SCAN_OK, "round %d rc=%d", round, rc);

        RefHit ref[REF_MAX];
        int refn = refFirstU32(&t, regions, 2, target, &hits, ref);
        if (refn < REF_MAX) {
            compareHitSets(&hits, &g_maps, ref, refn, "differential");
            rounds++;
        }
        free(chunk);
        nxusHitListFree(&hits);
    }
    CHECK(rounds == 20, "differential rounds executed: %d", rounds);

    teardownTarget(&t);
}

static void testRefineDifferential(void) {
    printf("[test] differential: refine pass vs naive per-address re-read\n");
    FakeTarget t; setupTarget(&t);

    const u32 base_val = 500;
    for (u64 i = 0; i < 2048; i++) writeU32(&t, MAP0_BASE + 0x2000 + i * 8, base_val);

    NxusScanRegion regions[1] = { { MAP0_BASE, MAP0_SIZE, NXUS_PERM_R, 0, 0 } };
    NxusScanRequest req; memset(&req, 0, sizeof(req));
    req.value_size = 4; req.cmp_mode = NxusCmp_Equal; req.target = base_val;

    NxusHitList hits;
    nxusHitListInit(&hits, 32, 1u << 20, 4);
    u8 *chunk = (u8 *)malloc(64 * 1024u);
    nxusScanFirst(regions, 1, &req, &hits, fakeRead, &t, chunk, 64 * 1024u, NULL, NULL);
    CHECK(hits.count == 2048, "setup hits %u", hits.count);

    /* every 3rd value increases, every 5th decreases, rest unchanged */
    for (u64 i = 0; i < 2048; i++) {
        u64 a = MAP0_BASE + 0x2000 + i * 8;
        if (i % 3 == 0) writeU32(&t, a, base_val + 10);
        else if (i % 5 == 0) writeU32(&t, a, base_val - 10);
    }

    /* expected survivors computed naively */
    u32 expected = 0;
    for (u64 i = 0; i < 2048; i++) if (i % 3 == 0) expected++;

    NxusScanRequest next; memset(&next, 0, sizeof(next));
    next.value_size = 4; next.cmp_mode = NxusCmp_Increased;
    u8 *window = (u8 *)malloc(16 * 1024u);
    int rc = nxusScanNext(&hits, &next, &g_maps, fakeRead, &t, window, 8 * 1024u, 4096u, NULL, NULL);
    CHECK(rc == NXUS_SCAN_OK, "rc=%d", rc);
    CHECK(hits.count == expected, "increased survivors %u != expected %u", hits.count, expected);

    /* each survivor must genuinely have increased */
    int bad = 0;
    for (u32 i = 0; i < hits.count; i++) {
        u64 addr = 0; nxusHitResolve(&hits, &g_maps, i, &addr);
        if (readU32(&t, addr) != base_val + 10) bad++;
    }
    CHECK(bad == 0, "%d survivors are wrong", bad);

    free(window); free(chunk);
    nxusHitListFree(&hits);
    teardownTarget(&t);
}

static void testHitListFull(void) {
    printf("[test] hit list limit is reported instead of overflowing\n");
    FakeTarget t; setupTarget(&t);
    for (u64 i = 0; i < 1024; i++) writeU32(&t, MAP0_BASE + i * 4, 42);

    NxusScanRegion regions[1] = { { MAP0_BASE, MAP0_SIZE, NXUS_PERM_R, 0, 0 } };
    NxusScanRequest req; memset(&req, 0, sizeof(req));
    req.value_size = 4; req.cmp_mode = NxusCmp_Equal; req.target = 42;

    NxusHitList hits;
    nxusHitListInit(&hits, 16, 16, 4);   /* hard cap of 16 */
    u8 *chunk = (u8 *)malloc(64 * 1024u);
    int rc = nxusScanFirst(regions, 1, &req, &hits, fakeRead, &t, chunk, 64 * 1024u, NULL, NULL);
    CHECK(rc == NXUS_SCAN_ERR_FULL, "expected FULL, got %d", rc);
    CHECK(hits.count == 16, "count %u should stop at capacity", hits.count);

    free(chunk);
    nxusHitListFree(&hits);
    teardownTarget(&t);
}

/* B1: an All scan records a 1-byte hit with reserved == NxusValueType_U8 (0).
   The refine pass used a "vtype ? vtype : plain_type" fallback, so that hit was
   compared as an 8-byte value and silently dropped on the next pass. */
static void testAllU8Refine(void) {
    printf("[test] All scan: a U8 hit survives the refine pass (B1)\n");
    FakeTarget t; setupTarget(&t);
    t.fail_hole = 0;

    /* Only the 1-byte candidate matches: 0x44 followed by 0x01, so the u16/u32/u64
       values at the same (aligned) address differ from the target 0x44. */
    const u8 bytes[4] = { 0x44, 0x01, 0x00, 0x00 };
    const u64 at = MAP0_BASE + 0x4000;
    writeBytes(&t, at, bytes, 4);

    NxusScanRegion regions[1] = { { MAP0_BASE, MAP0_SIZE, NXUS_PERM_R, 0, 0 } };
    NxusScanRequest req; memset(&req, 0, sizeof(req));
    req.value_size = 1; req.cmp_mode = NxusCmp_Equal; req.target = 0x44;
    NxusScanPattern pattern; memset(&pattern, 0, sizeof(pattern));
    pattern.value_type = NxusValueType_All;

    NxusHitList hits;
    CHECK(nxusHitListInit(&hits, 8, 1u << 20, 8) == NXUS_SCAN_OK, "hit list init");
    u8 *chunk = (u8 *)malloc(64 * 1024u);
    int rc = nxusScanFirstEx(regions, 1, &req, &pattern, &hits, fakeRead, &t,
                             chunk, 64 * 1024u, NULL, NULL);
    CHECK(rc == NXUS_SCAN_OK, "All first pass rc=%d", rc);
    CHECK(hits.count == 1, "exactly one U8 hit, got %u", hits.count);
    if (hits.count == 1) {
        CHECK(hits.addresses[0].reserved == NxusValueType_U8,
              "hit tagged as U8 (got %u)", hits.addresses[0].reserved);
        CHECK(hits.addresses[0].offset == 0x4000, "hit at offset 0x4000");
    }

    /* Unchanged: the single byte did not change, so the hit must stay.  With the
       bug the compare used an 8-byte window and saw the trailing 0x01. */
    NxusScanRequest next; memset(&next, 0, sizeof(next));
    next.value_size = 1; next.cmp_mode = NxusCmp_Unchanged;
    u8 *window = (u8 *)malloc(4096);
    NxusScanStats st;
    rc = nxusScanNextEx(&hits, &next, &pattern, &g_maps, fakeRead, &t,
                        window, 4096, 256, &st, NULL);
    CHECK(rc == NXUS_SCAN_OK, "All refine rc=%d", rc);
    CHECK(hits.count == 1, "U8 hit kept by the refine pass, got %u", hits.count);
    if (hits.count == 1) {
        CHECK(hits.addresses[0].reserved == NxusValueType_U8, "still tagged as U8");
        CHECK(hits.addresses[0].offset == 0x4000, "still at offset 0x4000");
    }

    free(window); free(chunk);
    nxusHitListFree(&hits);
    teardownTarget(&t);
}

/* B2: a window far above the reader's accepted size must be halved repeatedly
   down to 4 KB, not once: a single halving leaves the whole batch unrefined. */
static void testRefineHalvingRetry(void) {
    printf("[test] refine halves a refused window down to 4 KB (B2)\n");
    FakeTarget t; setupTarget(&t);
    t.fail_hole = 0;

    const u32 n = 16;
    u64 addrs[16];
    for (u32 i = 0; i < n; i++) {
        addrs[i] = MAP0_BASE + 0x2000 + (u64)i * 0x10000u;   /* ~1 MB span */
        writeU32(&t, addrs[i], 100);
    }

    NxusScanRegion regions[1] = { { MAP0_BASE, MAP0_SIZE, NXUS_PERM_R, 0, 0 } };
    NxusScanRequest req; memset(&req, 0, sizeof(req));
    req.value_size = 4; req.cmp_mode = NxusCmp_Equal; req.target = 100;

    NxusHitList hits;
    CHECK(nxusHitListInit(&hits, 8, 1u << 20, 4) == NXUS_SCAN_OK, "hit list init");
    u8 *chunk = (u8 *)malloc(64 * 1024u);
    int rc = nxusScanFirst(regions, 1, &req, &hits, fakeRead, &t, chunk, 64 * 1024u, NULL, NULL);
    CHECK(rc == NXUS_SCAN_OK && hits.count == n, "first pass hits=%u rc=%d", hits.count, rc);

    /* the batch window spans the whole run; only the first hit is inside the
       first 4 KB of it, so only that one may be judged (and it no longer matches) */
    writeU32(&t, addrs[0], 200);

    NxusScanRequest next; memset(&next, 0, sizeof(next));
    next.value_size = 4; next.cmp_mode = NxusCmp_Equal; next.target = 100;

    const u32 window_max = 1u << 20;
    u8 *window = (u8 *)malloc(window_max);
    NxusScanStats st;
    rc = nxusScanNext(&hits, &next, &g_maps, fakeReadLimited, &t,
                      window, window_max, 1u << 20, &st, NULL);
    CHECK(rc == NXUS_SCAN_OK, "refine rc=%d", rc);
    CHECK(st.retries >= 2, "the engine halved several times (retries=%u)", st.retries);
    CHECK(hits.count == n - 1, "the changed hit was dropped, rest kept (count=%u)", hits.count);
    if (hits.count == n - 1) {
        CHECK(hits.addresses[0].offset == (u32)(addrs[1] - MAP0_BASE),
              "survivors start at the second planted address");
    }

    free(window); free(chunk);
    nxusHitListFree(&hits);
    teardownTarget(&t);
}

/* B3: a pattern / All value that starts 4 bytes before a chunk boundary spans
   into the next chunk.  The first pass used to jump to pos + todo and never
   inspect those start positions. */
static void testChunkBoundaryStraddle(void) {
    printf("[test] pattern / All hits straddling a chunk boundary (B3)\n");

    /* --- byte pattern (step 1, window 8) --- */
    {
        FakeTarget t; setupTarget(&t);
        t.fail_hole = 0;

        static const u8 needle[8] = { 'N', 'X', 'U', 'S', 'B', '3', 'B', 'D' };
        writeBytes(&t, MAP0_BASE + 4092, needle, 8);   /* crosses 4096 */
        writeBytes(&t, MAP0_BASE + 8188, needle, 8);   /* crosses 8192 */

        NxusScanRegion regions[1] = { { MAP0_BASE, 4 * 4096, NXUS_PERM_R, 0, 0 } };
        NxusScanRequest req; memset(&req, 0, sizeof(req));
        req.value_size = 4; req.cmp_mode = NxusCmp_Equal;
        NxusScanPattern pattern; memset(&pattern, 0, sizeof(pattern));
        pattern.value_type = NxusValueType_Bytes;
        pattern.pattern = needle;
        pattern.pattern_len = 8;

        NxusHitList hits;
        CHECK(nxusHitListInit(&hits, 8, 1u << 20, 8) == NXUS_SCAN_OK, "pattern hit list init");
        u8 *chunk = (u8 *)malloc(4096);
        NxusScanStats st;
        int rc = nxusScanFirstEx(regions, 1, &req, &pattern, &hits, fakeRead, &t,
                                 chunk, 4096, &st, NULL);
        CHECK(rc == NXUS_SCAN_OK, "boundary pattern scan rc=%d", rc);
        CHECK(hits.count == 2, "both boundary patterns found, got %u", hits.count);
        if (hits.count == 2) {
            CHECK(hits.addresses[0].offset == 4092, "first pattern offset %u", hits.addresses[0].offset);
            CHECK(hits.addresses[1].offset == 8188, "second pattern offset %u", hits.addresses[1].offset);
        }
        /* the resumed overlap must not be counted twice */
        CHECK(st.bytes_scanned == 4 * 4096, "bytes_scanned %llu (expected %u)",
              (unsigned long long)st.bytes_scanned, 4 * 4096);

        free(chunk);
        nxusHitListFree(&hits);
        teardownTarget(&t);
    }

    /* --- All (step 4, window 8): an 8-byte value at an aligned but boundary
       straddling address was invisible to the first pass --- */
    {
        FakeTarget t; setupTarget(&t);
        t.fail_hole = 0;

        const u64 value = 0x1122334455667788ull;
        writeBytes(&t, MAP0_BASE + 4092, &value, 8);

        NxusScanRegion regions[1] = { { MAP0_BASE, 2 * 4096, NXUS_PERM_R, 0, 0 } };
        NxusScanRequest req; memset(&req, 0, sizeof(req));
        req.value_size = 8; req.cmp_mode = NxusCmp_Equal; req.target = value;
        NxusScanPattern pattern; memset(&pattern, 0, sizeof(pattern));
        pattern.value_type = NxusValueType_All;

        NxusHitList hits;
        CHECK(nxusHitListInit(&hits, 16, 1u << 20, 8) == NXUS_SCAN_OK, "All hit list init");
        u8 *chunk = (u8 *)malloc(4096);
        NxusScanStats st;
        int rc = nxusScanFirstEx(regions, 1, &req, &pattern, &hits, fakeRead, &t,
                                 chunk, 4096, &st, NULL);
        CHECK(rc == NXUS_SCAN_OK, "boundary All scan rc=%d", rc);
        int saw_u64 = 0;
        for (u32 i = 0; i < hits.count; i++) {
            if (hits.addresses[i].offset == 4092 && hits.addresses[i].reserved == NxusValueType_U64) {
                saw_u64 = 1;
            }
        }
        CHECK(saw_u64, "the 8-byte value at offset 4092 is found (%u hits)", hits.count);

        free(chunk);
        nxusHitListFree(&hits);
        teardownTarget(&t);
    }
}

/* M2: the initial allocation is clamped to the caller's hard cap. */
static void testHitListCapacityClamp(void) {
    printf("[test] hit list capacity clamped to max_capacity (M2)\n");

    NxusHitList hits;
    CHECK(nxusHitListInit(&hits, 1u << 16, 4096, 4) == NXUS_SCAN_OK, "init clamped list");
    CHECK(hits.capacity == 4096, "capacity %u clamped to 4096", hits.capacity);
    CHECK(hits.max_capacity == 4096, "max_capacity kept");
    nxusHitListFree(&hits);

    /* and the clamped list still reports FULL at the cap, not at the request */
    FakeTarget t; setupTarget(&t);
    t.fail_hole = 0;
    for (u64 i = 0; i < 100; i++) writeU32(&t, MAP0_BASE + 0x1000 + i * 4, 0x5A5A5A5Au);

    NxusScanRegion regions[1] = { { MAP0_BASE, 0x4000, NXUS_PERM_R, 0, 0 } };
    NxusScanRequest req; memset(&req, 0, sizeof(req));
    req.value_size = 4; req.cmp_mode = NxusCmp_Equal; req.target = 0x5A5A5A5Au;

    CHECK(nxusHitListInit(&hits, 1u << 12, 16, 4) == NXUS_SCAN_OK, "init tiny cap list");
    CHECK(hits.capacity == 16, "capacity %u clamped to 16", hits.capacity);
    u8 *chunk = (u8 *)malloc(16 * 1024u);
    int rc = nxusScanFirst(regions, 1, &req, &hits, fakeRead, &t, chunk, 16 * 1024u, NULL, NULL);
    CHECK(rc == NXUS_SCAN_ERR_FULL, "expected FULL once the cap is hit, got %d", rc);
    CHECK(hits.count == 16, "count stops at the clamped capacity (%u)", hits.count);

    free(chunk);
    nxusHitListFree(&hits);
    teardownTarget(&t);
}

int main(void) {
    printf("=== Nxus scan engine host tests ===\n");
    printf("sizeof(NxusPacketHeader)=%u NxusScanRequest=%u NxusHit=%u NxusStatus=%u NxusModuleInfo=%u\n",
           (unsigned)sizeof(NxusPacketHeader), (unsigned)sizeof(NxusScanRequest),
           (unsigned)sizeof(NxusHit), (unsigned)sizeof(NxusStatus),
           (unsigned)sizeof(NxusModuleInfo));

    testFirstScanExact();
    testRefineAndCoalescing();
    testCancelConsistency();
    testUnreadableRegion();
    testPageBoundaryAlignment();
    testFirstScanDifferential();
    testRefineDifferential();
    testHitListFull();
    testAllU8Refine();
    testRefineHalvingRetry();
    testChunkBoundaryStraddle();
    testHitListCapacityClamp();

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}