/*
 * Host tests for the Nxus snapshot/diff engine.
 * This is the piece that replaces "dump 520MB and diff it on the PC".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nxus_snapshot.h"

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

#define REG_A_BASE 0x36000000ull
#define REG_A_SIZE (1024u * 1024u)
#define REG_B_BASE 0x42CA0000ull
#define REG_B_SIZE (512u * 1024u)
#define BLOCK_SIZE 4096u

typedef struct {
    u8 *a;
    u8 *b;
    u64 reads;
    int fail_after;      /* fail every read after this many (0 = never) */
} Fake;

static int fakeRead(void *ctx, u64 address, void *buffer, u32 size) {
    Fake *f = (Fake *)ctx;
    f->reads++;
    if (f->fail_after > 0 && f->reads > (u64)f->fail_after) return -1;
    if (address >= REG_A_BASE && address + size <= REG_A_BASE + REG_A_SIZE) {
        memcpy(buffer, f->a + (address - REG_A_BASE), size);
        return 0;
    }
    if (address >= REG_B_BASE && address + size <= REG_B_BASE + REG_B_SIZE) {
        memcpy(buffer, f->b + (address - REG_B_BASE), size);
        return 0;
    }
    return -1;
}

static const NxusScanRegion g_Regions[] = {
    { REG_A_BASE, REG_A_SIZE, NXUS_PERM_R, 0, 0 },
    { REG_B_BASE, REG_B_SIZE, NXUS_PERM_R, 1, 0 },
};

static NxusSnapshot makeSnapshot(Fake *f, u64 *hashes, u64 *addresses, u32 capacity) {
    NxusSnapshot snap;
    nxusSnapshotInit(&snap, hashes, addresses, capacity, BLOCK_SIZE);
    u8 *chunk = (u8 *)malloc(16 * 1024);
    int rc = nxusSnapshotCapture(&snap, g_Regions, 2, fakeRead, f, chunk, 16 * 1024, NULL, NULL);
    CHECK(rc == NXUS_SNAPSHOT_OK, "capture rc=%d", rc);
    free(chunk);
    return snap;
}

static int hasChange(const NxusChangedBlock *blocks, u32 count, u64 address) {
    for (u32 i = 0; i < count; i++) if (blocks[i].address == address) return 1;
    return 0;
}

/* ---- coalesced (16 blocks per read) path ----------------------------- */

#define COV_ENTRIES 1024u
/* The gate in nxus_snapshot.c: a chunk of this many blocks enables coalescing. */
#define COALESCE_CHUNK_BLOCKS 16u

static u64 g_ch1[COV_ENTRIES], g_ca1[COV_ENTRIES];
static u64 g_ch2[COV_ENTRIES], g_ca2[COV_ENTRIES];

/* Capture with an explicit chunk size (in blocks), so the same data can be read
   through the coalesced (chunk >= 16 blocks) and the one-block-per-read path.
   The output arrays are pre-filled with a sentinel: any entry the capture did
   not write shows up as a difference instead of a stale match. */
static int captureWithRead(NxusReadFn read, void *read_ctx,
                           const NxusScanRegion *regions, u32 region_count,
                           u32 chunk_blocks, u32 capacity,
                           u64 *hashes, u64 *addresses,
                           NxusSnapshot *snapshot, NxusScanStats *stats) {
    memset(hashes, 0xEE, (size_t)capacity * sizeof(u64));
    memset(addresses, 0xEE, (size_t)capacity * sizeof(u64));
    memset(stats, 0, sizeof(*stats));
    nxusSnapshotInit(snapshot, hashes, addresses, capacity, BLOCK_SIZE);

    u8 *chunk = (u8 *)malloc((size_t)chunk_blocks * BLOCK_SIZE);
    int rc = nxusSnapshotCapture(snapshot, regions, region_count, read, read_ctx,
                                 chunk, chunk_blocks * BLOCK_SIZE, stats, NULL);
    free(chunk);
    return rc;
}

static int sameEntries(const NxusSnapshot *a, const u64 *ha, const u64 *aa,
                       const NxusSnapshot *b, const u64 *hb, const u64 *ab, u32 n) {
    if (a->count != b->count) return 0;
    if (n > a->count) n = a->count;
    for (u32 i = 0; i < n; i++) {
        if (ha[i] != hb[i]) return 0;
        if (aa[i] != ab[i]) return 0;
    }
    return 1;
}

/* A target with an unmapped hole in the middle: [HOLE_BASE, +0x4000) and
   [HOLE_BASE + 0x8000, +0x4000) are readable, the 0x4000 bytes between them are
   not.  A coalesced read that crosses the hole must be refused and fall back to
   the per-block sequence. */
#define HOLE_BASE 0x51000000ull
#define HOLE_READ 0x4000u
#define HOLE_SIZE 0xC000u

typedef struct {
    u8 *low;       /* HOLE_READ bytes at HOLE_BASE */
    u8 *high;      /* HOLE_READ bytes at HOLE_BASE + 0x8000 */
} HoleFake;

static int holeRead(void *ctx, u64 address, void *buffer, u32 size) {
    HoleFake *h = (HoleFake *)ctx;
    if (address >= HOLE_BASE && address + size <= HOLE_BASE + HOLE_READ) {
        memcpy(buffer, h->low + (address - HOLE_BASE), size);
        return 0;
    }
    if (address >= HOLE_BASE + 0x8000u &&
        address + size <= HOLE_BASE + 0x8000u + HOLE_READ) {
        memcpy(buffer, h->high + (address - (HOLE_BASE + 0x8000u)), size);
        return 0;
    }
    return -1;
}

int main(void) {
    printf("=== Nxus snapshot / diff tests ===\n");

    Fake f;
    f.a = (u8 *)calloc(1, REG_A_SIZE);
    f.b = (u8 *)calloc(1, REG_B_SIZE);
    f.reads = 0;
    f.fail_after = 0;

    const u32 expected_blocks = (REG_A_SIZE + REG_B_SIZE) / BLOCK_SIZE;
    const u32 cap = 1024;

    u64 *h1 = (u64 *)calloc(cap, 8), *a1 = (u64 *)calloc(cap, 8);
    u64 *h2 = (u64 *)calloc(cap, 8), *a2 = (u64 *)calloc(cap, 8);
    NxusChangedBlock *changes = (NxusChangedBlock *)calloc(cap, sizeof(NxusChangedBlock));

    printf("[test] baseline capture\n");
    f.reads = 0;
    NxusSnapshot s1 = makeSnapshot(&f, h1, a1, cap);
    CHECK(s1.count == expected_blocks, "expected %u blocks, got %u", expected_blocks, s1.count);
    CHECK(f.reads == expected_blocks, "expected one read per block, got %llu", (unsigned long long)f.reads);
    CHECK(a1[0] == REG_A_BASE, "first block address %llx", (unsigned long long)a1[0]);
    CHECK(a1[expected_blocks - 1] == REG_B_BASE + REG_B_SIZE - BLOCK_SIZE,
          "last block address %llx", (unsigned long long)a1[expected_blocks - 1]);
    printf("       %u blocks, %llu reads (%.1f MB of target)\n", s1.count,
           (unsigned long long)f.reads, (REG_A_SIZE + REG_B_SIZE) / 1048576.0);

    printf("[test] diff with no changes\n");
    u32 changed = 0;
    NxusSnapshot s2 = makeSnapshot(&f, h2, a2, cap);
    int rc = nxusSnapshotDiff(&s1, &s2, changes, cap, &changed);
    CHECK(rc == NXUS_SNAPSHOT_OK && changed == 0, "expected 0 changes, got %u (rc=%d)", changed, rc);

    printf("[test] three scattered changes\n");
    f.a[0x100] ^= 0xFF;                       /* block 0 */
    f.a[0x8000 + 0x40] ^= 0xFF;               /* block 8 */
    f.b[0x1234] ^= 0xFF;                      /* region B block 1 */
    s2 = makeSnapshot(&f, h2, a2, cap);
    rc = nxusSnapshotDiff(&s1, &s2, changes, cap, &changed);
    CHECK(rc == NXUS_SNAPSHOT_OK, "diff rc=%d", rc);
    CHECK(changed == 3, "expected 3 changed blocks, got %u", changed);
    CHECK(hasChange(changes, changed, REG_A_BASE + 0x0), "block 0 missing");
    CHECK(hasChange(changes, changed, REG_A_BASE + 0x8000), "block 8 missing");
    CHECK(hasChange(changes, changed, REG_B_BASE + 0x1000), "region B block missing");

    printf("[test] several changes inside one block collapse to one\n");
    /* Rebaseline BOTH slots into their own storage: the snapshot struct only
       points at caller buffers, so s1 = s2 would alias them. */
    s1 = makeSnapshot(&f, h1, a1, cap);
    s2 = makeSnapshot(&f, h2, a2, cap);
    for (u32 i = 0; i < 64; i++) f.a[0x20000 + i] ^= 0x5A;
    s2 = makeSnapshot(&f, h2, a2, cap);
    rc = nxusSnapshotDiff(&s1, &s2, changes, cap, &changed);
    CHECK(changed == 1, "expected 1 changed block, got %u", changed);
    CHECK(changes[0].address == REG_A_BASE + 0x20000, "wrong block %llx",
          (unsigned long long)changes[0].address);
    CHECK(changes[0].size == BLOCK_SIZE, "block size %u", changes[0].size);

    printf("[test] hash stability and sensitivity\n");
    u8 buf[BLOCK_SIZE];
    memset(buf, 0xAB, sizeof(buf));
    u64 h_a = nxusHash64(buf, sizeof(buf));
    CHECK(h_a == nxusHash64(buf, sizeof(buf)), "hash is not deterministic");
    buf[BLOCK_SIZE - 1] ^= 0x01;
    CHECK(h_a != nxusHash64(buf, sizeof(buf)), "hash missed a 1-bit change");
    buf[BLOCK_SIZE - 1] ^= 0x01;
    CHECK(h_a == nxusHash64(buf, sizeof(buf)), "hash not reversible");

    printf("[test] unreadable blocks are skipped, not fatal\n");
    f.reads = 0;
    f.fail_after = 10;
    NxusSnapshot s3 = makeSnapshot(&f, h1, a1, cap);
    CHECK(s3.count == 10, "expected 10 captured blocks before the failures, got %u", s3.count);
    f.fail_after = 0;

    printf("[test] capacity limit is reported\n");
    nxusSnapshotInit(&s3, h1, a1, 4, BLOCK_SIZE);
    u8 *chunk = (u8 *)malloc(4096);
    rc = nxusSnapshotCapture(&s3, g_Regions, 2, fakeRead, &f, chunk, 4096, NULL, NULL);
    CHECK(rc == NXUS_SNAPSHOT_ERR_FULL, "expected FULL, got %d", rc);
    /* FULL is a truncated capture, not a failed one: the blocks that were hashed
       stay usable (the service reports it as truncated=1). */
    CHECK(s3.block_size == BLOCK_SIZE, "a FULL capture must keep its block grid (block_size %u)",
          s3.block_size);
    free(chunk);

    printf("[test] cancellation keeps a consistent partial snapshot\n");
    int cancel = 1;
    nxusSnapshotInit(&s3, h1, a1, cap, BLOCK_SIZE);
    chunk = (u8 *)malloc(4096);
    rc = nxusSnapshotCapture(&s3, g_Regions, 2, fakeRead, &f, chunk, 4096, NULL, &cancel);
    CHECK(rc == NXUS_SNAPSHOT_ERR_CANCELLED, "expected CANCELLED, got %d", rc);
    CHECK(s3.count <= expected_blocks, "partial count %u", s3.count);
    /* Cancellation is not a failure either: the partial snapshot keeps its grid. */
    CHECK(s3.block_size == BLOCK_SIZE, "a cancelled capture must keep its block grid (block_size %u)",
          s3.block_size);
    free(chunk);

    printf("[test] regions appearing/vanishing are reported\n");
    NxusSnapshot s4 = makeSnapshot(&f, h1, a1, cap);
    NxusScanRegion only_a[1] = { { REG_A_BASE, REG_A_SIZE, NXUS_PERM_R, 0, 0 } };
    NxusSnapshot s5;
    nxusSnapshotInit(&s5, h2, a2, cap, BLOCK_SIZE);
    chunk = (u8 *)malloc(4096);
    rc = nxusSnapshotCapture(&s5, only_a, 1, fakeRead, &f, chunk, 4096, NULL, NULL);
    CHECK(rc == NXUS_SNAPSHOT_OK, "capture rc=%d", rc);
    free(chunk);
    changed = 0;
    rc = nxusSnapshotDiff(&s4, &s5, changes, cap, &changed);
    CHECK(rc == NXUS_SNAPSHOT_OK, "diff rc=%d", rc);
    CHECK(changed == REG_B_SIZE / BLOCK_SIZE, "expected %u vanished blocks, got %u",
          REG_B_SIZE / BLOCK_SIZE, changed);
    CHECK(changes[0].reserved == 1, "vanished blocks must be flagged (got %u)", changes[0].reserved);

    printf("[test] diff output limit is honoured\n");
    changed = 0;
    rc = nxusSnapshotDiff(&s4, &s5, changes, 4, &changed);
    CHECK(rc == NXUS_SNAPSHOT_ERR_FULL, "expected FULL, got %d", rc);
    CHECK(changed == 4, "expected 4 reported, got %u", changed);

    /*
     * The sysmodule reads with a 256 KB chunk, i.e. 16 blocks per read: that
     * coalesced branch is the path the console always takes, and until now every
     * test used a 4-block chunk and only ever hit the one-read-per-block code.
     */
    printf("[test] coalesced 16-block reads match the one-block path\n");
    NxusScanStats cs1, cs2, cs3;
    NxusSnapshot c1, c2, c3;

    f.reads = 0;
    int crc = captureWithRead(fakeRead, &f, g_Regions, 2, COALESCE_CHUNK_BLOCKS,
                              COV_ENTRIES, g_ch1, g_ca1, &c1, &cs1);
    const u64 coalesced_reads = f.reads;
    CHECK(crc == NXUS_SNAPSHOT_OK, "coalesced capture rc=%d", crc);
    CHECK(c1.count == expected_blocks, "coalesced block count %u (expected %u)",
          c1.count, expected_blocks);
    CHECK(cs1.reads == expected_blocks / COALESCE_CHUNK_BLOCKS,
          "expected %u coalesced reads, got %llu", expected_blocks / COALESCE_CHUNK_BLOCKS,
          (unsigned long long)cs1.reads);
    CHECK(cs1.reads < expected_blocks, "coalescing did not reduce the read count (%llu)",
          (unsigned long long)cs1.reads);
    CHECK(coalesced_reads == cs1.reads, "the reader saw %llu reads, stats say %llu",
          (unsigned long long)coalesced_reads, (unsigned long long)cs1.reads);

    f.reads = 0;
    int src = captureWithRead(fakeRead, &f, g_Regions, 2, 1,
                              COV_ENTRIES, g_ch2, g_ca2, &c2, &cs2);
    CHECK(src == NXUS_SNAPSHOT_OK, "one-block capture rc=%d", src);
    CHECK(cs2.reads == expected_blocks, "expected one read per block, got %llu",
          (unsigned long long)cs2.reads);
    CHECK(sameEntries(&c1, g_ch1, g_ca1, &c2, g_ch2, g_ca2, COV_ENTRIES),
          "coalesced hashes/addresses differ from the one-block path");

    /* A 32-block chunk is still clamped to 16 blocks per read. */
    f.reads = 0;
    int brc = captureWithRead(fakeRead, &f, g_Regions, 2, 2 * COALESCE_CHUNK_BLOCKS,
                              COV_ENTRIES, g_ch1, g_ca1, &c3, &cs3);
    CHECK(brc == NXUS_SNAPSHOT_OK, "32-block chunk capture rc=%d", brc);
    CHECK(cs3.reads == expected_blocks / COALESCE_CHUNK_BLOCKS,
          "a 32-block chunk must still coalesce 16 blocks per read, got %llu",
          (unsigned long long)cs3.reads);
    CHECK(sameEntries(&c3, g_ch1, g_ca1, &c2, g_ch2, g_ca2, COV_ENTRIES),
          "a 32-block chunk changes the hashes/addresses");

    /* Region starts at +0x800 (inside block 0) and ends at -0x400 (inside the
       last block): the partial edge blocks must not be coalesced, and the full
       blocks between them must hash exactly like the one-block path. */
    printf("[test] coalesced reads with an unaligned start and a ragged end\n");
    NxusScanRegion ragged[1];
    memset(ragged, 0, sizeof(ragged));
    ragged[0].base = REG_A_BASE + 0x800;
    ragged[0].size = REG_A_SIZE - 0x800 - 0x400;
    ragged[0].perm = NXUS_PERM_R;

    int rrc1 = captureWithRead(fakeRead, &f, ragged, 1, COALESCE_CHUNK_BLOCKS,
                               COV_ENTRIES, g_ch1, g_ca1, &c1, &cs1);
    CHECK(rrc1 == NXUS_SNAPSHOT_OK, "unaligned coalesced capture rc=%d", rrc1);
    int rrc2 = captureWithRead(fakeRead, &f, ragged, 1, 1,
                               COV_ENTRIES, g_ch2, g_ca2, &c2, &cs2);
    CHECK(rrc2 == NXUS_SNAPSHOT_OK, "unaligned one-block capture rc=%d", rrc2);
    CHECK(c1.count == 256u, "expected 256 blocks for the ragged region, got %u", c1.count);
    CHECK(c1.addresses[0] == REG_A_BASE, "first address %llx (rounded down to the block grid)",
          (unsigned long long)c1.addresses[0]);
    CHECK(c1.count > 0 && c1.addresses[c1.count - 1] == REG_A_BASE + 0xFF000ull,
          "last address %llx", (unsigned long long)c1.addresses[c1.count - 1]);
    CHECK(cs1.reads < cs2.reads, "coalescing was not used for the ragged region (%llu vs %llu)",
          (unsigned long long)cs1.reads, (unsigned long long)cs2.reads);
    CHECK(sameEntries(&c1, g_ch1, g_ca1, &c2, g_ch2, g_ca2, COV_ENTRIES),
          "the partial first/last blocks differ between the two paths");

    printf("[test] coalesced capture reports FULL and keeps the leading blocks\n");
    const u32 small_cap = 20u;
    int frc1 = captureWithRead(fakeRead, &f, g_Regions, 2, COALESCE_CHUNK_BLOCKS,
                               small_cap, g_ch1, g_ca1, &c1, &cs1);
    CHECK(frc1 == NXUS_SNAPSHOT_ERR_FULL, "expected FULL, got %d", frc1);
    CHECK(c1.count == small_cap, "expected %u captured blocks, got %u", small_cap, c1.count);
    int frc2 = captureWithRead(fakeRead, &f, g_Regions, 2, 1,
                               small_cap, g_ch2, g_ca2, &c2, &cs2);
    CHECK(frc2 == NXUS_SNAPSHOT_ERR_FULL, "one-block capture expected FULL, got %d", frc2);
    CHECK(c2.count == small_cap, "one-block count %u", c2.count);
    CHECK(sameEntries(&c1, g_ch1, g_ca1, &c2, g_ch2, g_ca2, small_cap),
          "the blocks kept before FULL differ between the two paths");

    /* A hole between two readable spans: the coalesced read is refused, the
       fallback drops exactly the same blocks as the one-block path. */
    printf("[test] an unmapped hole drops the same blocks in both paths\n");
    HoleFake hf;
    hf.low  = (u8 *)calloc(1, HOLE_READ);
    hf.high = (u8 *)calloc(1, HOLE_READ);
    for (u32 i = 0; i < HOLE_READ; i++) {
        hf.low[i]  = (u8)(i * 3u + 1u);
        hf.high[i] = (u8)(i * 5u + 7u);
    }

    NxusScanRegion hole_region[1];
    memset(hole_region, 0, sizeof(hole_region));
    hole_region[0].base = HOLE_BASE;
    hole_region[0].size = HOLE_SIZE;
    hole_region[0].perm = NXUS_PERM_R;

    int hrc1 = captureWithRead(holeRead, &hf, hole_region, 1, COALESCE_CHUNK_BLOCKS,
                               COV_ENTRIES, g_ch1, g_ca1, &c1, &cs1);
    CHECK(hrc1 == NXUS_SNAPSHOT_OK, "hole capture rc=%d", hrc1);
    int hrc2 = captureWithRead(holeRead, &hf, hole_region, 1, 1,
                               COV_ENTRIES, g_ch2, g_ca2, &c2, &cs2);
    CHECK(hrc2 == NXUS_SNAPSHOT_OK, "hole one-block capture rc=%d", hrc2);
    CHECK(c1.count == 8u && c2.count == 8u, "captured %u / %u blocks around the hole",
          c1.count, c2.count);
    CHECK(cs1.dropped == 4u && cs2.dropped == 4u, "dropped %u / %u blocks",
          cs1.dropped, cs2.dropped);
    CHECK(cs1.reads < cs2.reads, "the readable spans still coalesced (%llu vs %llu reads)",
          (unsigned long long)cs1.reads, (unsigned long long)cs2.reads);
    CHECK(sameEntries(&c1, g_ch1, g_ca1, &c2, g_ch2, g_ca2, COV_ENTRIES),
          "hashes/addresses around the hole differ between the two paths");
    free(hf.low); free(hf.high);

    /*
     * A capture that fails must not leave "0 blocks, but valid" behind: the diff
     * then reports every block of the other side as vanished, which the client
     * shows as a confident "N changed" for a comparison that never happened.
     * The service layer relies on this to hand the client BAD_STATE instead.
     */
    printf("[test] a failed capture leaves no usable snapshot\n");
    u64 fh[16], fa[16];
    NxusSnapshot bad;
    nxusSnapshotInit(&bad, fh, fa, 16, BLOCK_SIZE);
    chunk = (u8 *)malloc(1024);
    /* chunk_size < 16 cannot hash even one block: the capture never starts. */
    rc = nxusSnapshotCapture(&bad, g_Regions, 2, fakeRead, &f, chunk, 15, NULL, NULL);
    CHECK(rc == NXUS_SNAPSHOT_ERR_PARAM, "small-chunk capture rc=%d", rc);
    CHECK(bad.count == 0 && bad.block_size == 0,
          "a failed capture must not look valid (count=%u block_size=%u)",
          bad.count, bad.block_size);
    changed = 0;
    rc = nxusSnapshotDiff(&s1, &bad, changes, cap, &changed);
    CHECK(rc == NXUS_SNAPSHOT_ERR_PARAM,
          "diff against a failed capture must fail, got rc=%d", rc);

    /* Two uncaptured slots are not "nothing changed" either. */
    NxusSnapshot bad2;
    nxusSnapshotInit(&bad2, fh, fa, 16, BLOCK_SIZE);
    rc = nxusSnapshotCapture(&bad2, g_Regions, 2, NULL, &f, chunk, 16 * BLOCK_SIZE, NULL, NULL);
    CHECK(rc == NXUS_SNAPSHOT_ERR_PARAM, "missing reader rc=%d", rc);
    CHECK(bad2.count == 0 && bad2.block_size == 0, "the second failed slot stayed valid");
    changed = 0;
    rc = nxusSnapshotDiff(&bad, &bad2, changes, cap, &changed);
    CHECK(rc == NXUS_SNAPSHOT_ERR_PARAM, "diff of two failed captures rc=%d", rc);
    free(chunk);

    printf("[test] a re-initialised slot captures normally again\n");
    nxusSnapshotInit(&bad, h2, a2, cap, BLOCK_SIZE);
    chunk = (u8 *)malloc(16 * 1024);
    rc = nxusSnapshotCapture(&bad, g_Regions, 2, fakeRead, &f, chunk, 16 * 1024, NULL, NULL);
    CHECK(rc == NXUS_SNAPSHOT_OK, "recovery capture rc=%d", rc);
    CHECK(bad.count == expected_blocks && bad.block_size == BLOCK_SIZE,
          "recovered slot: %u blocks, block_size %u", bad.count, bad.block_size);
    NxusSnapshot fresh = makeSnapshot(&f, g_ch1, g_ca1, COV_ENTRIES);
    changed = 0;
    rc = nxusSnapshotDiff(&bad, &fresh, changes, cap, &changed);
    CHECK(rc == NXUS_SNAPSHOT_OK && changed == 0,
          "recovered slot vs a fresh capture: rc=%d, %u changed", rc, changed);

    free(h1); free(a1); free(h2); free(a2); free(changes);
    free(f.a); free(f.b);

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
