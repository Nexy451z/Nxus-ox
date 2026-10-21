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
    free(chunk);

    printf("[test] cancellation keeps a consistent partial snapshot\n");
    int cancel = 1;
    nxusSnapshotInit(&s3, h1, a1, cap, BLOCK_SIZE);
    chunk = (u8 *)malloc(4096);
    rc = nxusSnapshotCapture(&s3, g_Regions, 2, fakeRead, &f, chunk, 4096, NULL, &cancel);
    CHECK(rc == NXUS_SNAPSHOT_ERR_CANCELLED, "expected CANCELLED, got %d", rc);
    CHECK(s3.count <= expected_blocks, "partial count %u", s3.count);
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

    free(h1); free(a1); free(h2); free(a2); free(changes);
    free(f.a); free(f.b);

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
