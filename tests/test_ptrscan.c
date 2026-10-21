/*
 * Host tests for the Nxus pointer scan + Atmosphère cheat code generator.
 *
 * The layout mirrors the MHXX problem: a static .data pointer leads (through a
 * heap structure) to the money record whose address moves between sessions.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* ---- fake 32-bit target ------------------------------------------------ */

#define MODULE_BASE  0x00700000ull
#define STATIC_BASE  0x00750000ull
#define STATIC_SIZE  0x00010000ull
#define HEAP_BASE    0x36000000ull
#define HEAP_SIZE    0x00010000ull
#define REC_BASE     0x42CA0000ull
#define REC_SIZE     0x00010000ull

#define TARGET_MONEY 0x42CA1DC4ull
#define MONEY_VALUE  6440u

typedef struct {
    u8 *static_mem;
    u8 *heap;
    u8 *rec;
    u64 reads;
} Fake;

static int fakeRead(void *ctx, u64 address, void *buffer, u32 size) {
    Fake *f = (Fake *)ctx;
    f->reads++;

    if (address >= STATIC_BASE && address + size <= STATIC_BASE + STATIC_SIZE) {
        memcpy(buffer, f->static_mem + (address - STATIC_BASE), size);
        return 0;
    }
    if (address >= HEAP_BASE && address + size <= HEAP_BASE + HEAP_SIZE) {
        memcpy(buffer, f->heap + (address - HEAP_BASE), size);
        return 0;
    }
    if (address >= REC_BASE && address + size <= REC_BASE + REC_SIZE) {
        memcpy(buffer, f->rec + (address - REC_BASE), size);
        return 0;
    }
    return -1;
}

static void pokeU32(u8 *base, u64 offset, u32 value) {
    memcpy(base + offset, &value, 4);
}

static void setup(Fake *f) {
    f->static_mem = (u8 *)calloc(1, STATIC_SIZE);
    f->heap = (u8 *)calloc(1, HEAP_SIZE);
    f->rec = (u8 *)calloc(1, REC_SIZE);
    f->reads = 0;

    /* the money record: {u32 id, s32 money, u32 zero, u32 other} */
    pokeU32(f->rec, 0x1DC0, 0x64);
    pokeU32(f->rec, 0x1DC4, MONEY_VALUE);
    pokeU32(f->rec, 0x1DC8, 0);
    pokeU32(f->rec, 0x1DCC, 5000);

    /* chain A: static+0x40 -> heap+0x1234 -> (+0x10) -> record+0x1DA0, then +0x24 */
    pokeU32(f->static_mem, 0x40, (u32)(HEAP_BASE + 0x1234));
    pokeU32(f->heap, 0x1234 + 0x10, (u32)(REC_BASE + 0x1DA0));

    /* chain B: a static pointer straight at the record start (final offset 4) */
    pokeU32(f->static_mem, 0x200, (u32)(REC_BASE + 0x1DC0));

    /* chain C: static -> heap -> record+0x1DB0 (final offset 0x14) */
    pokeU32(f->static_mem, 0x300, (u32)(HEAP_BASE + 0x2000));
    pokeU32(f->heap, 0x2000 + 0x8, (u32)(REC_BASE + 0x1DB0));

    /* decoys */
    pokeU32(f->static_mem, 0x100, 0x41414141);      /* not mapped -> pruned */
    pokeU32(f->static_mem, 0x104, 0);               /* null -> skipped */
    pokeU32(f->static_mem, 0x400, (u32)(HEAP_BASE + 0x3000));  /* points at zeroed heap */
}

static void teardown(Fake *f) {
    free(f->static_mem);
    free(f->heap);
    free(f->rec);
}

static const NxusPtrRegion g_Regions[] = {
    { STATIC_BASE, STATIC_SIZE, NXUS_PTRREGION_STATIC, 0 },
    { HEAP_BASE, HEAP_SIZE, NXUS_PTRREGION_TRAVERSABLE, 0 },
    { REC_BASE, REC_SIZE, NXUS_PTRREGION_TRAVERSABLE, 0 },
};

static int findChain(const NxusPtrChain *chains, u32 count, u32 root_offset,
                     const u32 *steps, u32 step_count, u32 final_offset) {
    for (u32 i = 0; i < count; i++) {
        if (chains[i].root_offset != root_offset) continue;
        if (chains[i].step_count != step_count) continue;
        if (chains[i].final_offset != final_offset) continue;
        int match = 1;
        for (u32 s = 0; s < step_count; s++) if (chains[i].steps[s] != steps[s]) match = 0;
        if (match) return 1;
    }
    return 0;
}

/* ---- dead-end memoisation / window cache -------------------------------- */

/*
 * A diamond graph: many static roots point at the *same* heap structure.
 *
 *   root[0..99]  (static) --> A --> C     both dead ends (no chain below)
 *   root[100]    (static) --> B           B holds target-4  (a live chain)
 *   root[101]    (static) --> B           the same B, shared
 *
 * Without memoisation A is dereferenced 100 times and B twice; with the
 * dead-end set plus the direct-mapped window cache each structure must be read
 * exactly once, while both live chains are still found.
 */
#define G_MODULE_BASE  0x00700000ull
#define G_STATIC_BASE  0x00750000ull
#define G_STATIC_SIZE  0x00001000ull
#define G_A            0x30000000ull
#define G_C            0x30010000ull
#define G_B            0x31000000ull
#define G_TBASE        0x32000000ull
#define G_TARGET       (G_TBASE + 0x100ull)
#define G_STRUCT_SIZE  0x00001000ull
#define G_BLOCKS       10u

typedef struct {
    u64 base;
    u32 size;
    u8 *mem;
} GBlock;

typedef struct {
    GBlock blocks[G_BLOCKS];
    u32 count;
    u64 reads;
    u64 watch[4];
    u64 seen[4];
} GMem;

static void gAdd(GMem *m, u64 base, u32 size) {
    GBlock *b = &m->blocks[m->count++];
    b->base = base;
    b->size = size;
    b->mem = (u8 *)calloc(1, size);
}

static void gPoke(GMem *m, u64 address, u32 value) {
    for (u32 i = 0; i < m->count; i++) {
        GBlock *b = &m->blocks[i];
        if (address >= b->base && address + 4 <= b->base + b->size) {
            memcpy(b->mem + (address - b->base), &value, 4);
            return;
        }
    }
    printf("  (test bug) gPoke outside all blocks: 0x%llX\n", (unsigned long long)address);
}

static void gWatch(GMem *m, u32 slot, u64 address) {
    m->watch[slot] = address;
    m->seen[slot] = 0;
}

static void gFree(GMem *m) {
    for (u32 i = 0; i < m->count; i++) free(m->blocks[i].mem);
    memset(m, 0, sizeof(*m));
}

static int gRead(void *ctx, u64 address, void *buffer, u32 size) {
    GMem *m = (GMem *)ctx;
    m->reads++;
    for (u32 i = 0; i < m->count; i++) {
        const GBlock *b = &m->blocks[i];
        if (address >= b->base && address + size <= b->base + b->size) {
            memcpy(buffer, b->mem + (address - b->base), size);
            for (u32 w = 0; w < 4; w++)
                if (m->watch[w] != 0 && address == m->watch[w]) m->seen[w]++;
            return 0;
        }
    }
    return -1;
}

static void testDeadEndMemo(void) {
    printf("[test] dead-end memoisation + window cache (100 duplicate roots)\n");
    GMem m;
    memset(&m, 0, sizeof(m));
    gAdd(&m, G_STATIC_BASE, G_STATIC_SIZE);
    gAdd(&m, G_A, G_STRUCT_SIZE);
    gAdd(&m, G_C, G_STRUCT_SIZE);
    gAdd(&m, G_B, G_STRUCT_SIZE);
    gAdd(&m, G_TBASE, 0x00001000u);

    for (u32 i = 0; i < 100; i++) gPoke(&m, G_STATIC_BASE + i * 4u, (u32)G_A);
    gPoke(&m, G_STATIC_BASE + 0x200, (u32)G_B);
    gPoke(&m, G_STATIC_BASE + 0x204, (u32)G_B);

    gPoke(&m, G_A + 0x40, (u32)G_C);              /* A dead-ends one level down */
    gPoke(&m, G_B + 0x00, (u32)(G_TARGET - 4));   /* B holds a live chain */

    gWatch(&m, 0, G_A);
    gWatch(&m, 1, G_B);
    gWatch(&m, 2, G_C);

    const NxusPtrRegion regions[] = {
        { G_STATIC_BASE, G_STATIC_SIZE, NXUS_PTRREGION_STATIC, 0 },
        { G_A, G_STRUCT_SIZE, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { G_C, G_STRUCT_SIZE, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { G_B, G_STRUCT_SIZE, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { G_TBASE, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
    };

    NxusPtrScanOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.max_depth = 3;
    opts.max_offset = 0x1000;
    opts.max_results = 64;
    opts.value_width = 4;
    opts.window_size = 0x400;
    opts.max_reads = 10000;

    NxusPtrChain chains[64];
    NxusPtrScanStats st;
    u32 count = 0;
    u8 *scratch = (u8 *)malloc(64 * 1024);
    int rc = nxusPtrScan(regions, 5, G_TARGET, G_MODULE_BASE, &opts,
                         chains, 64, &count, gRead, &m, scratch, 64 * 1024, &st, NULL);

    CHECK(rc == NXUS_SCAN_OK, "dead-end scan rc=%d", rc);
    CHECK(count == 2, "expected exactly 2 chains, got %u", count);

    const u32 in_module = (u32)(G_STATIC_BASE - G_MODULE_BASE);
    {
        const u32 steps[] = { 0x0 };
        CHECK(findChain(chains, count, in_module + 0x200, steps, 1, 4),
              "live chain via root+0x200 not found");
        CHECK(findChain(chains, count, in_module + 0x204, steps, 1, 4),
              "live chain via root+0x204 not found");
    }

    printf("       reads=%llu  A=%llu B=%llu C=%llu\n",
           (unsigned long long)st.reads,
           (unsigned long long)m.seen[0], (unsigned long long)m.seen[1],
           (unsigned long long)m.seen[2]);

    /* The whole point: 100 identical roots must not re-read A, and the shared
       live node B must not be re-read by its second root.  The read budget also
       proves the walk stays tiny: 1 static chunk + A + C + B = 4 reads. */
    CHECK(st.reads == 4, "expected exactly 4 reads (1 chunk + A + C + B), got %llu",
          (unsigned long long)st.reads);
    CHECK(m.seen[0] == 1, "dead-end A was read %llu times (memoisation missed)",
          (unsigned long long)m.seen[0]);
    CHECK(m.seen[1] == 1, "shared live node B was read %llu times (window cache missed)",
          (unsigned long long)m.seen[1]);
    CHECK(m.seen[2] == 1, "dead-end C was read %llu times (subtree not memoised)",
          (unsigned long long)m.seen[2]);

    free(scratch);
    gFree(&m);
}

/*
 * Depth-class regression: the memo key masks the depth to two bits, so a proof
 * made at depth 5 shares a key with depth 1.  Depth 5 has less depth budget, so
 * it must never be reused to skip a depth-1 walk.  Here X is dead at depth 5
 * (four hops are needed and only three remain) but alive at depth 1.
 */
static void testDeadDepthClass(void) {
    printf("[test] dead-end memo must not leak proofs across depth classes\n");
    GMem m;
    memset(&m, 0, sizeof(m));

    const u64 mod_base = 0x00800000ull;
    const u64 static_base = 0x00850000ull;
    const u64 h1 = 0x34000000ull, h2 = 0x34001000ull, h3 = 0x34002000ull;
    const u64 h4 = 0x34003000ull, x = 0x34004000ull, y = 0x34005000ull;
    const u64 z = 0x34006000ull, w = 0x34007000ull;
    const u64 tbase = 0x35000000ull, target = tbase + 0x100ull;

    gAdd(&m, static_base, 0x00001000u);
    gAdd(&m, h1, 0x00001000u);
    gAdd(&m, h2, 0x00001000u);
    gAdd(&m, h3, 0x00001000u);
    gAdd(&m, h4, 0x00001000u);
    gAdd(&m, x, 0x00001000u);
    gAdd(&m, y, 0x00001000u);
    gAdd(&m, z, 0x00001000u);
    gAdd(&m, w, 0x00001000u);
    gAdd(&m, tbase, 0x00001000u);

    /* root+0x300 reaches X at depth 5 (too late to walk the 4 hops to target) */
    gPoke(&m, static_base + 0x300, (u32)h1);
    gPoke(&m, h1, (u32)h2);
    gPoke(&m, h2, (u32)h3);
    gPoke(&m, h3, (u32)h4);
    gPoke(&m, h4, (u32)x);
    /* root+0x400 reaches X at depth 1, where the chain still fits */
    gPoke(&m, static_base + 0x400, (u32)x);
    gPoke(&m, x, (u32)y);
    gPoke(&m, y, (u32)z);
    gPoke(&m, z, (u32)w);
    gPoke(&m, w, (u32)(target - 4));

    const NxusPtrRegion regions[] = {
        { static_base, 0x00001000u, NXUS_PTRREGION_STATIC, 0 },
        { h1, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { h2, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { h3, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { h4, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { x, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { y, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { z, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { w, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { tbase, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
    };

    NxusPtrScanOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.max_depth = 8;
    opts.max_offset = 0x1000;
    opts.max_results = 64;
    opts.value_width = 4;
    opts.window_size = 0x400;
    opts.max_reads = 10000;

    NxusPtrChain chains[64];
    NxusPtrScanStats st;
    u32 count = 0;
    u8 *scratch = (u8 *)malloc(64 * 1024);
    int rc = nxusPtrScan(regions, 10, target, mod_base, &opts,
                         chains, 64, &count, gRead, &m, scratch, 64 * 1024, &st, NULL);

    CHECK(rc == NXUS_SCAN_OK, "depth-class scan rc=%d", rc);
    CHECK(count == 1, "expected exactly 1 chain, got %u", count);
    {
        const u32 steps[] = { 0x0, 0x0, 0x0, 0x0 };
        CHECK(findChain(chains, count, (u32)(static_base - mod_base) + 0x400,
                        steps, 4, 4),
              "depth-1 chain through X was lost to a depth-5 dead-end proof");
    }

    free(scratch);
    gFree(&m);
}

/*
 * Window isolation: the walk recurses *inside* the window loop, so each depth
 * must own its window.  With one shared buffer the walk into the zeroed child
 * C1 overwrites the parent's window and every pointer after offset 0 (here
 * C2 at +0x40) is silently lost.
 *
 *   root+0 -> P -> [ +0x00 = C1 (zeroed), +0x40 = C2 ] -> C2+0x10 -> target-4
 */
static void testWindowIsolation(void) {
    printf("[test] per-depth windows: a child walk must not erase the parent window\n");
    GMem m;
    memset(&m, 0, sizeof(m));

    const u64 static_base = 0x00950000ull;
    const u64 p = 0x33000000ull, c1 = 0x33100000ull, c2 = 0x33200000ull;
    const u64 tbase = 0x33300000ull, target = tbase + 0x100ull;

    gAdd(&m, static_base, 0x00001000u);
    gAdd(&m, p, 0x00001000u);
    gAdd(&m, c1, 0x00001000u);
    gAdd(&m, c2, 0x00001000u);
    gAdd(&m, tbase, 0x00001000u);

    gPoke(&m, static_base + 0x80, (u32)p);
    gPoke(&m, p + 0x00, (u32)c1);
    gPoke(&m, p + 0x40, (u32)c2);
    gPoke(&m, c2 + 0x10, (u32)(target - 4));

    const NxusPtrRegion regions[] = {
        { static_base, 0x00001000u, NXUS_PTRREGION_STATIC, 0 },
        { p, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { c1, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { c2, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
        { tbase, 0x00001000u, NXUS_PTRREGION_TRAVERSABLE, 0 },
    };

    NxusPtrScanOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.max_depth = 3;
    opts.max_offset = 0x1000;
    opts.max_results = 16;
    opts.value_width = 4;
    opts.window_size = 0x400;
    opts.max_reads = 1000;

    NxusPtrChain chains[16];
    NxusPtrScanStats st;
    u32 count = 0;
    u8 *scratch = (u8 *)malloc(64 * 1024);
    int rc = nxusPtrScan(regions, 5, target, 0x00900000ull, &opts,
                         chains, 16, &count, gRead, &m, scratch, 64 * 1024, &st, NULL);

    CHECK(rc == NXUS_SCAN_OK, "window isolation scan rc=%d", rc);
    CHECK(count == 1, "expected exactly 1 chain, got %u", count);
    {
        const u32 steps[] = { 0x40, 0x10 };
        CHECK(findChain(chains, count, (u32)(static_base - 0x00900000ull) + 0x80,
                        steps, 2, 4),
              "chain behind P+0x40 was lost (shared window buffer)");
    }

    free(scratch);
    gFree(&m);
}

int main(void) {
    printf("=== Nxus pointer scan / cheat generator tests ===\n");
    Fake f;
    setup(&f);

    NxusPtrScanOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.max_depth = 3;
    opts.max_offset = 0x1000;
    opts.max_results = 64;
    opts.value_width = 4;          /* 32-bit title */
    opts.window_size = 0x400;
    opts.max_reads = 100000;

    NxusPtrChain chains[64];
    u32 count = 0;
    NxusPtrScanStats stats;
    u8 *scratch = (u8 *)malloc(64 * 1024);

    printf("[test] finding chains to 0x%llX\n", (unsigned long long)TARGET_MONEY);
    int rc = nxusPtrScan(g_Regions, 3, TARGET_MONEY, MODULE_BASE, &opts,
                         chains, 64, &count, fakeRead, &f, scratch, 64 * 1024, &stats, NULL);
    CHECK(rc == NXUS_SCAN_OK, "scan rc=%d", rc);
    CHECK(count >= 3, "expected at least 3 chains, got %u", count);
    printf("       chains=%u roots=%llu reads=%llu\n", count,
           (unsigned long long)stats.roots_examined, (unsigned long long)stats.reads);

    /* root_offset is relative to the MODULE base, because that is what a cheat
       code with M=0 (Main NSO) needs.  The static region starts at module+0x50000. */
    const u32 STATIC_IN_MODULE = (u32)(STATIC_BASE - MODULE_BASE);

    {   /* chain A: heap structure + 0x10, then +0x24 */
        const u32 steps[] = { 0x10 };
        CHECK(findChain(chains, count, STATIC_IN_MODULE + 0x40, steps, 1, 0x24),
              "chain A (static+0x40 -> +0x10 -> +0x24) not found");
    }
    {   /* chain B: direct */
        CHECK(findChain(chains, count, STATIC_IN_MODULE + 0x200, NULL, 0, 4), "chain B (direct +4) not found");
    }
    {   /* chain C */
        const u32 steps[] = { 0x8 };
        CHECK(findChain(chains, count, STATIC_IN_MODULE + 0x300, steps, 1, 0x14), "chain C not found");
    }
    {   /* decoys must not appear */
        CHECK(!findChain(chains, count, STATIC_IN_MODULE + 0x100, NULL, 0, 0), "unmapped decoy produced a chain");
        CHECK(!findChain(chains, count, STATIC_IN_MODULE + 0x104, NULL, 0, 0), "null decoy produced a chain");
        CHECK(!findChain(chains, count, STATIC_IN_MODULE + 0x400, NULL, 0, 0), "zero-heap decoy produced a chain");
    }

    for (u32 i = 0; i < count && i < 6; i++) {
        printf("       chain %u: root=main+0x%X steps=%u", i, chains[i].root_offset, chains[i].step_count);
        for (u32 s = 0; s < chains[i].step_count; s++) printf(" +0x%X", chains[i].steps[s]);
        printf(" final=+0x%X\n", chains[i].final_offset);
    }

    /* ---- cheat code generation ---- */
    printf("[test] Atmosphère cheat code generation\n");
    char code[512];
    const NxusPtrChain *chainA = NULL;
    const u32 stepsA[] = { 0x10 };
    for (u32 i = 0; i < count; i++) {
        if (findChain(&chains[i], 1, STATIC_IN_MODULE + 0x40, stepsA, 1, 0x24)) { chainA = &chains[i]; break; }
    }
    CHECK(chainA != NULL, "chain A missing for code generation");

    if (chainA != NULL) {
        int n = nxusCheatGenerate(chainA, 1, 9999999, 4, "MHXX money (Nxus)", code, sizeof(code));
        CHECK(n > 0, "generate returned %d", n);
        char expected[256];
        snprintf(expected, sizeof(expected),
            "[MHXX money (Nxus)]\n"
            "540F0000 %08X\n"
            "540F1000 00000010\n"
            "780F0000 00000024\n"
            "640F0000 00000000 0098967F\n", STATIC_IN_MODULE + 0x40);
        if (strcmp(code, expected) != 0) {
            printf("  --- generated ---\n%s  -----------------\n", code);
        }
        CHECK(strcmp(code, expected) == 0, "cheat code text mismatch");

        /* 64-bit titles must use 8-byte loads */
        n = nxusCheatGenerate(chainA, 0, 9999999, 4, "t", code, sizeof(code));
        char want64[64];
        snprintf(want64, sizeof(want64), "580F0000 %08X", STATIC_IN_MODULE + 0x40);
        CHECK(strstr(code, want64) != NULL, "64-bit load prefix missing: %s", code);
    }

    {   /* absolute write code (region 4 = non-relative) */
        int n = nxusCheatGenerateAbsoluteWrite(TARGET_MONEY, 4, 9999999, 4, "money abs", code, sizeof(code));
        CHECK(n > 0, "absolute write returned %d", n);
        CHECK(strcmp(code, "[money abs]\n04400000 42CA1DC4 0098967F\n") == 0,
              "absolute write text mismatch: %s", code);
    }
    {   /* main-relative write code (what the old MHXX cheat accidentally was) */
        nxusCheatGenerateAbsoluteWrite(0x42CA1DC4ull, 0, 9999999, 4, "money main-rel", code, sizeof(code));
        CHECK(strcmp(code, "[money main-rel]\n04000000 42CA1DC4 0098967F\n") == 0,
              "main-relative text mismatch: %s", code);
    }

    /* ---- cancellation and budget ---- */
    printf("[test] cancellation / read budget\n");
    int cancel = 1;
    count = 0;
    rc = nxusPtrScan(g_Regions, 3, TARGET_MONEY, MODULE_BASE, &opts,
                     chains, 64, &count, fakeRead, &f, scratch, 64 * 1024, &stats, &cancel);
    CHECK(rc == NXUS_SCAN_ERR_CANCELLED, "expected cancelled, got %d", rc);

    opts.max_reads = 4;
    cancel = 0;
    count = 0;
    rc = nxusPtrScan(g_Regions, 3, TARGET_MONEY, MODULE_BASE, &opts,
                     chains, 64, &count, fakeRead, &f, scratch, 64 * 1024, &stats, NULL);
    CHECK(rc == NXUS_SCAN_OK, "budget run rc=%d", rc);
    CHECK(stats.reads <= 8, "read budget not honoured: %llu", (unsigned long long)stats.reads);

    free(scratch);

    /* ---- dead-end memoisation / window cache ---- */
    testDeadEndMemo();
    testDeadDepthClass();
    testWindowIsolation();

    teardown(&f);
    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
