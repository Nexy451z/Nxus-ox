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
    teardown(&f);
    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
