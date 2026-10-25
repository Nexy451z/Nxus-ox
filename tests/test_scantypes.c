/*
 * Host tests for the Cheat-Engine-style value types and scan types:
 * byte / 2 / 4 / 8 bytes, float, double, string, array of byte (with
 * wildcards), All, plus Between and Unknown-initial scans.
 */
#include <stdio.h>
#include <string.h>

#include "nxus_scan.h"

static int checks = 0;
static int failures = 0;

static void check(int condition, const char *what) {
    checks++;
    if (!condition) {
        failures++;
        printf("  FAIL  %s\n", what);
    }
}

/* ---- fake target ---------------------------------------------------- */

#define FAKE_SIZE (64u * 1024u)
static u8 g_memory[FAKE_SIZE];
static u64 g_base = 0x10000000ull;

static int fakeRead(void *ctx, u64 address, void *buffer, u32 size) {
    (void)ctx;
    if (address < g_base) return -1;
    u64 offset = address - g_base;
    if (offset + size > FAKE_SIZE) return -1;
    memcpy(buffer, g_memory + offset, size);
    return 0;
}

static void put(u64 offset, const void *data, u32 size) {
    memcpy(g_memory + offset, data, size);
}

static void putU64(u64 offset, u64 value, u32 size) {
    nxusStoreLE(g_memory + offset, value, size);
}

static NxusScanRegion g_region;
static NxusMappingEntry g_map_entry;
static NxusMappingTable g_maps;

static void setup(void) {
    memset(g_memory, 0, sizeof(g_memory));
    g_region.base = g_base;
    g_region.size = FAKE_SIZE;
    g_region.perm = 0;
    g_region.mapping_idx = 0;

    /* the refine pass resolves hits through the mapping table */
    g_map_entry.base = g_base;
    g_map_entry.size = FAKE_SIZE;
    g_map_entry.valid = 1;
    g_maps.entries = &g_map_entry;
    g_maps.count = 1;
}

static NxusScanRequest baseRequest(u32 compare, u64 target, u64 target2) {
    NxusScanRequest req;
    memset(&req, 0, sizeof(req));
    req.kind = 0;
    req.value_size = 4;
    req.cmp_mode = compare;
    req.scope = NxusScope_All;
    req.target = target;
    req.target2 = target2;
    req.chunk_size = 4096;
    return req;
}

static NxusHitList g_hits;
/* One chunk covering the whole fake region: with a small chunk the gaps between
   chunks break dense runs and would hide the window-overflow bug. */
static u8 g_chunk[64 * 1024];
static u8 g_window[8192];

static void hitListInit(u32 value_size) {
    nxusHitListFree(&g_hits);
    if (nxusHitListInit(&g_hits, 64, 100000, value_size) != NXUS_SCAN_OK) {
        printf("hit list init failed\n");
        failures++;
    }
}

static int runFirst(const NxusScanRequest *req, const NxusScanPattern *pattern) {
    NxusScanStats stats;
    return nxusScanFirstEx(&g_region, 1, req, pattern, &g_hits, fakeRead, NULL,
                           g_chunk, sizeof(g_chunk), &stats, NULL);
}

static int runNext(const NxusScanRequest *req, const NxusScanPattern *pattern) {
    NxusScanStats stats;
    return nxusScanNextEx(&g_hits, req, pattern, &g_maps, fakeRead, NULL,
                          g_window, sizeof(g_window), 256, &stats, NULL);
}

/* ---- tests ---------------------------------------------------------- */

static void testFloat(void) {
    printf("- float / double\n");
    setup();
    const float values[3] = { 1.5f, 100.25f, -4.75f };
    put(0x100, &values[0], 4);
    put(0x200, &values[1], 4);
    put(0x300, &values[2], 4);

    NxusScanRequest req = baseRequest(NxusCmp_Equal, 0, 0);
    float target = 100.25f;
    u32 bits;
    memcpy(&bits, &target, 4);
    req.target = bits;
    req.flags = NXUS_SCAN_F_FLOAT;
    req.value_size = 4;

    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));
    pattern.value_type = NxusValueType_F32;
    pattern.flags = NXUS_SCAN_F_FLOAT;

    hitListInit(4);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "float scan completes");
    check(g_hits.count == 1, "exactly one float hit");
    check(nxusLoadLE(g_hits.values, 4) == bits, "float bits round-trip");

    /* fuzzy: 100.25 vs 100.3 with 1 decimal */
    float target2 = 100.3f;
    u32 bits2;
    memcpy(&bits2, &target2, 4);
    req.target = bits2;
    float eps = 0.1f;
    u32 eps_bits;
    memcpy(&eps_bits, &eps, 4);
    req.target2 = eps_bits;
    req.cmp_mode = NxusCmp_FuzzyEqual;
    hitListInit(4);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "fuzzy float scan completes");
    check(g_hits.count == 1, "fuzzy float matches within epsilon");

    /* fuzzy via epsilon_decimals when target2 == 0 (GUI / CLI NxusScanExt path) */
    req.target2 = 0;
    pattern.epsilon_decimals = 1;
    hitListInit(4);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "fuzzy float via epsilon_decimals completes");
    check(g_hits.count == 1, "fuzzy float via epsilon_decimals matches within 10^-1");

    /* double */
    double d = 1234.5678;
    u64 dbits;
    memcpy(&dbits, &d, 8);
    put(0x400, &d, 8);
    NxusScanRequest dreq = baseRequest(NxusCmp_Equal, dbits, 0);
    dreq.value_size = 8;
    dreq.flags = NXUS_SCAN_F_FLOAT;
    NxusScanPattern dpat;
    memset(&dpat, 0, sizeof(dpat));
    dpat.value_type = NxusValueType_F64;
    dpat.flags = NXUS_SCAN_F_FLOAT;
    hitListInit(8);
    check(runFirst(&dreq, &dpat) == NXUS_SCAN_OK, "double scan completes");
    check(g_hits.count == 1, "exactly one double hit");
}

static void testBetween(void) {
    printf("- value between\n");
    setup();
    putU64(0x40, 10, 4);
    putU64(0x80, 50, 4);
    putU64(0xc0, 90, 4);
    putU64(0x100, 150, 4);

    NxusScanRequest req = baseRequest(NxusCmp_Between, 40, 100);
    req.value_size = 4;
    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));
    pattern.value_type = NxusValueType_U32;

    hitListInit(4);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "between scan completes");
    check(g_hits.count == 2, "between keeps only the two in-range values");
    check(nxusLoadLE(g_hits.values, 4) == 50, "first in-range value");
    check(nxusLoadLE(g_hits.values + 4, 4) == 90, "second in-range value");
}

static void testString(void) {
    printf("- string\n");
    setup();
    const char *needle = "MASTER BALL";
    memcpy(g_memory + 0x1000, needle, strlen(needle));
    memcpy(g_memory + 0x2000, "master ball", 11);
    memcpy(g_memory + 0x3000, "POTION", 6);

    NxusScanRequest req = baseRequest(NxusCmp_Equal, 0, 0);
    req.value_size = 4;
    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));
    pattern.value_type = NxusValueType_String;
    pattern.pattern = (const u8 *)needle;
    pattern.pattern_len = (u32)strlen(needle);

    hitListInit(8);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "string scan completes");
    check(g_hits.count == 1, "only the exact-case string matches");
    check(g_hits.addresses[0].offset == 0x1000, "string found at the right offset");

    /* case insensitive */
    pattern.flags = NXUS_SCAN_F_CASE_INSENS;
    req.flags = NXUS_SCAN_F_CASE_INSENS;
    hitListInit(8);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "case-insensitive scan completes");
    check(g_hits.count == 2, "case-insensitive finds both spellings");

    /* UTF-16LE */
    setup();
    for (u32 i = 0; i < 4; i++) {
        g_memory[0x800 + i * 2] = (u8)"GOLD"[i];
        g_memory[0x801 + i * 2] = 0;
    }
    pattern.flags = NXUS_SCAN_F_UTF16;
    req.flags = NXUS_SCAN_F_UTF16;
    pattern.pattern = (const u8 *)"GOLD";
    pattern.pattern_len = 4;
    hitListInit(8);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "utf16 scan completes");
    check(g_hits.count == 1, "utf16 string found");
    check(g_hits.addresses[0].offset == 0x800, "utf16 string offset");
}

static void testByteArray(void) {
    printf("- array of byte (wildcards)\n");
    setup();
    const u8 want[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11 };
    const u8 other[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x99, 0x11 };
    put(0x2000, want, 6);
    put(0x2400, other, 6);

    NxusScanRequest req = baseRequest(NxusCmp_Equal, 0, 0);
    req.value_size = 4;
    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));
    pattern.value_type = NxusValueType_Bytes;
    pattern.pattern = want;
    pattern.pattern_len = 6;

    hitListInit(8);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "byte array scan completes");
    check(g_hits.count == 1, "exact byte array matches once");

    /* wildcard on the 5th byte: both should match */
    const u8 mask[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF };
    pattern.mask = mask;
    pattern.flags = NXUS_SCAN_F_WILDCARD;
    req.flags = NXUS_SCAN_F_WILDCARD;
    hitListInit(8);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "wildcard scan completes");
    check(g_hits.count == 2, "wildcard matches both candidates");

    /* refine with the same pattern keeps them */
    check(runNext(&req, &pattern) == NXUS_SCAN_OK, "wildcard refine completes");
    check(g_hits.count == 2, "wildcard refine keeps both");
}

static void testAllTypes(void) {
    printf("- All (every numeric width)\n");
    setup();
    putU64(0x4000, 0x11223344u, 4);

    NxusScanRequest req = baseRequest(NxusCmp_Equal, 0x11223344u, 0);
    req.value_size = 4;
    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));
    pattern.value_type = NxusValueType_All;

    hitListInit(8);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "All scan completes");
    check(g_hits.count >= 1, "All finds the value");
    int saw_u32 = 0;
    for (u32 i = 0; i < g_hits.count; i++) {
        if (g_hits.addresses[i].reserved == NxusValueType_U32) saw_u32 = 1;
    }
    check(saw_u32, "All tags the hit as a 4-byte value");

    /* refine by "changed": modify memory, the same value must drop out */
    putU64(0x4000, 0x55667788u, 4);
    req.cmp_mode = NxusCmp_Unchanged;
    check(runNext(&req, &pattern) == NXUS_SCAN_OK, "All refine completes");
    check(g_hits.count == 0, "unchanged refine drops the modified value");
}

static void testDenseRunRefine(void) {
    printf("- dense run survives a refine\n");
    setup();
    /* 16 KB of a repeating byte: a 'AA AA' byte-pattern scan hits at every
       offset, so every window overlaps the next one. */
    memset(g_memory + 0x2000, 0xAA, 16 * 1024);

    const u8 pattern[2] = { 0xAA, 0xAA };
    NxusScanRequest req = baseRequest(NxusCmp_Equal, 0, 0);
    req.value_size = 4;
    NxusScanPattern pat;
    memset(&pat, 0, sizeof(pat));
    pat.value_type = NxusValueType_Bytes;
    pat.pattern = pattern;
    pat.pattern_len = 2;

    hitListInit(8);
    check(runFirst(&req, &pat) == NXUS_SCAN_OK, "dense byte-pattern scan completes");
    const u32 found = g_hits.count;
    check(found > 8000, "dense scan finds a hit at (almost) every offset");

    /* Window in runNext() is 8 KB: the run must be split, not dropped. */
    check(runNext(&req, &pat) == NXUS_SCAN_OK, "dense refine completes");
    check(g_hits.count == found, "dense refine keeps every hit (no silent drop)");
}

/* A reader that refuses anything larger than 4096 bytes, like dmnt may. */
static int fakeReadLimited(void *ctx, u64 address, void *buffer, u32 size) {
    if (size > 4096u) return -1;
    return fakeRead(ctx, address, buffer, size);
}

static void testRefusedWindowRead(void) {
    printf("- refine survives a refused window read\n");
    setup();
    memset(g_memory + 0x4000, 0x5A, 8 * 1024);

    const u8 pattern[2] = { 0x5A, 0x5A };
    NxusScanRequest req = baseRequest(NxusCmp_Equal, 0, 0);
    req.value_size = 4;
    NxusScanPattern pat;
    memset(&pat, 0, sizeof(pat));
    pat.value_type = NxusValueType_Bytes;
    pat.pattern = pattern;
    pat.pattern_len = 2;

    hitListInit(8);
    check(runFirst(&req, &pat) == NXUS_SCAN_OK, "limited-read scan completes");
    const u32 found = g_hits.count;
    check(found > 8000, "dense scan found hits");

    /* window_max 8192 makes one big window; the read is refused and the
       half-size retry succeeds, so the upper half must be KEPT unrefined
       instead of being compared against uninitialised memory. */
    NxusScanStats stats;
    int rc = nxusScanNextEx(&g_hits, &req, &pat, &g_maps, fakeReadLimited, NULL,
                            g_window, 8192, 256, &stats, NULL);
    check(rc == NXUS_SCAN_OK, "refine with a refused window completes");
    check(stats.retries >= 1, "the engine retried the read smaller");
    check(g_hits.count == found, "every still-matching hit kept (no bogus compare)");
}

/* A hit below the window start (an out-of-order / corrupt hit list) made
   'offset - win_start' wrap to 0xFFFFFFFF.  For a 1-byte value 'rel + vlen'
   then wrapped to 0, so the bounds check passed and the compare read
   window + 0xFFFFFFFF - 4 GiB past the buffer (it crashed when this test was
   added).  The guard must skip the entry instead of letting the wrapped
   subtraction decide the read address. */
static void testRefineOffsetUnderflow(void) {
    printf("- refine rejects an offset below the window start\n");
    setup();
    g_memory[1] = 0x11;

    hitListInit(1);                          /* value_size 1: rel + vlen wraps */
    NxusScanPattern pat;
    memset(&pat, 0, sizeof(pat));
    pat.value_type = NxusValueType_U8;

    NxusScanRequest req = baseRequest(NxusCmp_Equal, 0x11, 0);
    req.value_size = 1;

    /* Deliberately out of order: the window starts at 1, the second hit is 0. */
    g_hits.addresses[0].offset = 1;
    g_hits.addresses[0].mapping_idx = 0;
    g_hits.addresses[0].reserved = NxusValueType_U8;
    g_hits.values[0] = 0x11;
    g_hits.addresses[1].offset = 0;
    g_hits.addresses[1].mapping_idx = 0;
    g_hits.addresses[1].reserved = NxusValueType_U8;
    g_hits.values[1] = 0x22;
    g_hits.count = 2;

    NxusScanStats stats;
    int rc = nxusScanNextEx(&g_hits, &req, &pat, &g_maps, fakeRead, NULL,
                            g_window + 1, 8192, 256, &stats, NULL);
    check(rc == NXUS_SCAN_OK, "refine with an out-of-order hit completes");
    check(g_hits.count == 1, "the in-window hit survives, the below-window one is skipped");
}

/* S1: the specialized equal-compare loops for the four integer widths must find
   exactly the same hits as the generic compare (the width switch is hoisted and
   each loop uses a constant-size load). */
static void testEqualFastPaths(void) {
    printf("- equal fast paths for u8 / u16 / u32 / u64\n");
    setup();

    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));

    /* u8: window 1, step 1 */
    g_memory[0x100] = 0x7E;
    g_memory[0x101] = 0x7E;
    pattern.value_type = NxusValueType_U8;
    NxusScanRequest req = baseRequest(NxusCmp_Equal, 0x7E, 0);
    req.value_size = 1;
    hitListInit(1);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "u8 equal scan completes");
    check(g_hits.count == 2, "u8 equal finds both bytes");
    if (g_hits.count == 2) {
        check(g_hits.addresses[0].offset == 0x100 && g_hits.addresses[1].offset == 0x101,
              "u8 equal hit offsets");
    }

    /* u16 */
    putU64(0x200, 0xBEEF, 2);
    pattern.value_type = NxusValueType_U16;
    req = baseRequest(NxusCmp_Equal, 0xBEEF, 0);
    req.value_size = 2;
    hitListInit(2);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "u16 equal scan completes");
    check(g_hits.count == 1, "u16 equal finds the value");
    check(g_hits.count == 1 && g_hits.addresses[0].offset == 0x200, "u16 equal offset");
    check(g_hits.count == 1 && nxusLoadLE(g_hits.values, 2) == 0xBEEF, "u16 stored value");

    /* u32 */
    putU64(0x300, 0xCAFEBABEull, 4);
    pattern.value_type = NxusValueType_U32;
    req = baseRequest(NxusCmp_Equal, 0xCAFEBABEull, 0);
    req.value_size = 4;
    hitListInit(4);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "u32 equal scan completes");
    check(g_hits.count == 1 && g_hits.addresses[0].offset == 0x300, "u32 equal hit");

    /* u64, then refine it through the u64 fast compare */
    putU64(0x400, 5000, 8);
    pattern.value_type = NxusValueType_U64;
    req = baseRequest(NxusCmp_Equal, 5000, 0);
    req.value_size = 8;
    hitListInit(8);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "u64 equal scan completes");
    check(g_hits.count == 1 && g_hits.addresses[0].offset == 0x400, "u64 equal hit");

    putU64(0x400, 4000, 8);                     /* decreased */
    NxusScanRequest next = baseRequest(NxusCmp_Decreased, 0, 0);
    next.value_size = 8;
    check(runNext(&next, &pattern) == NXUS_SCAN_OK, "u64 decreased refine completes");
    check(g_hits.count == 1, "u64 decreased keeps the hit");

    putU64(0x400, 3999, 8);                     /* changed again */
    next.cmp_mode = NxusCmp_Unchanged;
    check(runNext(&next, &pattern) == NXUS_SCAN_OK, "u64 unchanged refine completes");
    check(g_hits.count == 0, "u64 unchanged drops the changed hit");
}

/* B4: a UTF-16 window spans two bytes per pattern byte, so a 40 character string
   needs an 80 byte window - twice NXUS_SCAN_MAX_PATTERN.  The refine pass used to
   reject it as a parameter error and lose the whole result. */
static void testUtf16LongRefine(void) {
    printf("- long UTF-16 string refines (B4)\n");
    setup();

    char text[41];
    for (u32 i = 0; i < 40; i++) text[i] = (char)('A' + (i % 26));
    text[40] = '\0';
    for (u32 i = 0; i < 40; i++) {
        g_memory[0x1000 + i * 2]     = (u8)text[i];
        g_memory[0x1000 + i * 2 + 1] = 0;
    }

    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));
    pattern.value_type = NxusValueType_String;
    pattern.pattern = (const u8 *)text;
    pattern.pattern_len = 40;                 /* window = 80 > NXUS_SCAN_MAX_PATTERN */
    pattern.flags = NXUS_SCAN_F_UTF16;

    NxusScanRequest req = baseRequest(NxusCmp_Equal, 0, 0);
    req.value_size = 4;
    req.flags = NXUS_SCAN_F_UTF16;

    hitListInit(8);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "40 char utf16 scan completes");
    check(g_hits.count == 1, "40 char utf16 found once");
    check(g_hits.count == 1 && g_hits.addresses[0].offset == 0x1000, "40 char utf16 offset");

    check(runNext(&req, &pattern) == NXUS_SCAN_OK, "40 char utf16 refine completes");
    check(g_hits.count == 1, "40 char utf16 hit survives the refine");
}

/* B9: an infinity never equals itself under |c-t| <= eps because c-t is NaN, so
   the float compare must test c == t first - otherwise neither the first pass nor
   the refine can match an Is-Infinity value. */
static void testFloatInfinity(void) {
    printf("- float / double infinity (B9)\n");
    setup();
    putU64(0x100, 0x7F800000ull, 4);    /* +Inf  (float)  */
    putU64(0x200, 0xFF800000ull, 4);    /* -Inf  (float)  */
    putU64(0x300, 0x7FF0000000000000ull, 8);  /* +Inf (double) */

    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));
    pattern.value_type = NxusValueType_F32;
    pattern.flags = NXUS_SCAN_F_FLOAT;

    NxusScanRequest req = baseRequest(NxusCmp_Equal, 0x7F800000ull, 0);
    req.value_size = 4;
    req.flags = NXUS_SCAN_F_FLOAT;

    hitListInit(4);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "float +Inf scan completes");
    check(g_hits.count == 1, "float +Inf matches itself (not -Inf)");
    check(g_hits.count == 1 && g_hits.addresses[0].offset == 0x100, "float +Inf offset");

    check(runNext(&req, &pattern) == NXUS_SCAN_OK, "float +Inf refine completes");
    check(g_hits.count == 1, "float +Inf survives the refine");

    /* fuzzy compare must accept the same infinite value as well */
    req.target2 = 0x3DCCCCCDu;                 /* 0.1f */
    req.cmp_mode = NxusCmp_FuzzyEqual;
    hitListInit(4);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "fuzzy float +Inf scan completes");
    check(g_hits.count == 1, "fuzzy float +Inf matches itself");

    /* double */
    pattern.value_type = NxusValueType_F64;
    NxusScanRequest dreq = baseRequest(NxusCmp_Equal, 0x7FF0000000000000ull, 0);
    dreq.value_size = 8;
    dreq.flags = NXUS_SCAN_F_FLOAT;
    hitListInit(8);
    check(runFirst(&dreq, &pattern) == NXUS_SCAN_OK, "double +Inf scan completes");
    check(g_hits.count == 1, "double +Inf matches itself");
    check(g_hits.count == 1 && g_hits.addresses[0].offset == 0x300, "double +Inf offset");
}

/* A clipped region (custom range / main) reads from 'base' but must report
   offsets relative to the MAPPING base, because the PC resolves each hit as
   mapping_base + offset. */
static void testClippedRegionOffsets(void) {
    printf("- clipped region reports mapping-relative offsets\n");
    setup();

    const u32 marker = 0x12345678;
    memcpy(g_memory + 0x1000, &marker, sizeof(marker));

    NxusScanRegion region;
    memset(&region, 0, sizeof(region));
    region.base = g_base + 0x800;        /* where the read starts (clipped)   */
    region.addr_base = g_base;           /* where the mapping starts          */
    region.size = 0x2000;
    region.perm = NXUS_PERM_R | NXUS_PERM_W;
    region.mapping_idx = 0;

    NxusScanRequest req = baseRequest(NxusCmp_Equal, marker, 0);
    req.value_size = 4;

    hitListInit(8);
    NxusScanStats stats;
    int rc = nxusScanFirstEx(&region, 1, &req, NULL, &g_hits, fakeRead, NULL,
                             g_chunk, (u32)sizeof(g_chunk), &stats, NULL);
    check(rc == NXUS_SCAN_OK, "clipped-region scan completes");
    check(g_hits.count == 1, "exactly one hit");
    if (g_hits.count > 0) {
        check(g_hits.addresses[0].offset == 0x1000,
              "offset measured from the mapping base, not the clipped start");
    }
}

/* The first pass must survive a dmnt that refuses large reads: it halves the
   chunk (4 KB floor) and still finds everything, instead of reporting 0 hits. */
static void testRefusedChunkRead(void) {
    printf("- first pass retries a refused chunk read\n");
    setup();

    const u32 marker = 0xCAFEBABE;
    memcpy(g_memory + 0x100, &marker, sizeof(marker));
    memset(g_memory + 0x2000, 0x11, 0x1000);

    NxusScanRequest req = baseRequest(NxusCmp_Equal, marker, 0);
    req.value_size = 4;

    hitListInit(8);
    NxusScanStats stats;
    int rc = nxusScanFirstEx(&g_region, 1, &req, NULL, &g_hits, fakeReadLimited, NULL,
                             g_chunk, (u32)sizeof(g_chunk), &stats, NULL);
    check(rc == NXUS_SCAN_OK, "scan completes although every big read is refused");
    check(g_hits.count == 1, "the value is still found");
    check(stats.retries > 0, "the engine halved the chunk instead of giving up");
}

/* The region builder is the producer of every hit offset: if a scope clips a
   mapping but the offset is measured from the clipped start, the PC resolves the
   hit to a different address and the refine reads the wrong bytes. */
static void testRegionBuilding(void) {
    printf("- region building: clip rules and mapping-relative base\n");

    NxusMappingEntry maps[4];
    memset(maps, 0, sizeof(maps));
    maps[0].base = 0x1000; maps[0].size = 0x3000; maps[0].reserved = NXUS_PERM_R | NXUS_PERM_W;
    maps[1].base = 0x5000; maps[1].size = 0x1000; maps[1].reserved = NXUS_PERM_R;
    maps[2].base = 0x8000; maps[2].size = 0;      maps[2].reserved = NXUS_PERM_R | NXUS_PERM_W;
    maps[3].base = 0x9000; maps[3].size = 0x1000; maps[3].reserved = 0;

    NxusScanRegion out[8];
    memset(out, 0, sizeof(out));

    u32 n = nxusBuildRegions(maps, 4, 0, 0, NxusScope_All, 0, 0, out, 8);
    check(n == 2, "All keeps readable, non-empty mappings");
    check(out[0].base == 0x1000 && out[0].size == 0x3000 && out[0].addr_base == 0x1000,
          "All: whole mapping, addr_base = mapping base");
    check(out[1].base == 0x5000 && out[1].mapping_idx == 1, "All: mapping index preserved");

    n = nxusBuildRegions(maps, 4, 0, 0, NxusScope_Custom, 0x2000, 0x6000, out, 8);
    check(n == 2, "Custom keeps the overlapping mappings");
    check(out[0].base == 0x2000 && out[0].size == 0x2000 && out[0].addr_base == 0x1000,
          "Custom clips the read range but keeps the mapping base");
    check(out[1].base == 0x5000 && out[1].size == 0x1000, "Custom: range end clips the second mapping");

    n = nxusBuildRegions(maps, 4, 0x1800, 0x1000, NxusScope_Main, 0, 0, out, 8);
    check(n == 1 && out[0].base == 0x1800 && out[0].size == 0x1000 && out[0].addr_base == 0x1000,
          "Main clips to the main range, addr_base stays the mapping base");
    n = nxusBuildRegions(maps, 4, 0, 0, NxusScope_Main, 0, 0, out, 8);
    check(n == 0, "Main without a main range yields nothing");

    n = nxusBuildRegions(maps, 4, 0, 0, NxusScope_Writable, 0, 0, out, 8);
    check(n == 1 && out[0].base == 0x1000, "Writable keeps write mappings only");

    n = nxusBuildRegions(maps, 4, 0, 0, NxusScope_All, 0, 0, out, 1);
    check(n == 1, "capacity bounds the result");
}

/* Documented behaviour: numeric scans walk absolute multiples of the value size,
   so an unaligned region base is scanned from the next aligned address (and an
   unaligned numeric value is not found - use a byte pattern for those). */
static void testAlignedFlag(void) {
    printf("- aligned flag restricts hits to absolute alignment\n");
    setup();

    const u32 marker = 0x11223344;
    memcpy(g_memory + 0x100, &marker, sizeof(marker));

    NxusScanRegion region;
    memset(&region, 0, sizeof(region));
    /* unaligned base: the first candidate is rounded UP to an absolute multiple of 4 */
    region.base = g_base + 1;
    region.addr_base = g_base + 1;
    region.size = 0x2000;
    region.perm = NXUS_PERM_R | NXUS_PERM_W;
    region.mapping_idx = 0;

    NxusScanRequest req = baseRequest(NxusCmp_Equal, marker, 0);
    req.value_size = 4;

    hitListInit(8);
    NxusScanStats stats;
    int rc = nxusScanFirstEx(&region, 1, &req, NULL, &g_hits, fakeRead, NULL,
                             g_chunk, (u32)sizeof(g_chunk), &stats, NULL);
    check(rc == NXUS_SCAN_OK, "unaligned-base scan completes");
    check(g_hits.count == 1, "values on aligned addresses are found from an unaligned base");
    if (g_hits.count > 0) {
        check((g_hits.addresses[0].offset & 3u) == 3u,
              "the hit sits 3 bytes into the region (base+1 rounded up to base+4)");
    }

    /* the flag cannot change this - it only documents the behaviour */
    req.flags = NXUS_SCAN_F_ALIGNED;
    hitListInit(8);
    rc = nxusScanFirstEx(&region, 1, &req, NULL, &g_hits, fakeRead, NULL,
                         g_chunk, (u32)sizeof(g_chunk), &stats, NULL);
    check(rc == NXUS_SCAN_OK, "aligned scan completes");
    check(g_hits.count == 1, "the flag does not change the numeric scan result");
}

/* NxusScope_Heap must mean the process heap: without the type filter it was
   byte-identical to NxusScope_Writable, which drags the stack and .data in. */
static void testHeapScope(void) {
    printf("- heap scope filters by memory type\n");

    NxusMappingEntry maps[4];
    memset(maps, 0, sizeof(maps));
    /* 0: heap  1: thread-local  2: code data  3: unknown type */
    maps[0].base = 0x100000; maps[0].size = 0x1000; maps[0].valid = 1;
    maps[0].reserved = NXUS_PERM_R | NXUS_PERM_W; maps[0].type = NXUS_MEMTYPE_HEAP;
    maps[1].base = 0x200000; maps[1].size = 0x1000; maps[1].valid = 1;
    maps[1].reserved = NXUS_PERM_R | NXUS_PERM_W; maps[1].type = 0x0Cu;   /* MemType_ThreadLocal */
    maps[2].base = 0x300000; maps[2].size = 0x1000; maps[2].valid = 1;
    maps[2].reserved = NXUS_PERM_R | NXUS_PERM_W; maps[2].type = 0x04u;   /* MemType_CodeData */
    maps[3].base = 0x400000; maps[3].size = 0x1000; maps[3].valid = 1;
    maps[3].reserved = NXUS_PERM_R | NXUS_PERM_W; maps[3].type = 0;       /* unknown */

    NxusScanRegion regions[8];
    u32 n = nxusBuildRegions(maps, 4, 0, 0, NxusScope_Heap, 0, 0, regions, 8);
    check(n == 2, "heap scope keeps only heap + unknown-type writable mappings");
    if (n == 2) {
        check(regions[0].base == maps[0].base, "the heap mapping is included");
        check(regions[1].base == maps[3].base, "an unknown type falls back to writable");
    }

    n = nxusBuildRegions(maps, 4, 0, 0, NxusScope_Writable, 0, 0, regions, 8);
    check(n == 4, "writable scope still takes every writable mapping");

    n = nxusBuildRegions(maps, 4, 0, 0, NxusScope_Tls, 0, 0, regions, 8);
    check(n == 1, "tls scope keeps only MemType_ThreadLocal (0x0C)");
    if (n == 1) {
        check(regions[0].base == maps[1].base, "the tls mapping is included");
    }
}

/* NxusScope_Ranges: the union of a list, one region per (mapping, range) pair. */
static void testRangeList(void) {
    printf("- multi-range scan regions\n");

    NxusMappingEntry maps[2];
    memset(maps, 0, sizeof(maps));
    maps[0].base = 0x100000; maps[0].size = 0x10000; maps[0].valid = 1;
    maps[0].reserved = NXUS_PERM_R | NXUS_PERM_W;
    maps[1].base = 0x500000; maps[1].size = 0x1000; maps[1].valid = 1;
    maps[1].reserved = NXUS_PERM_R | NXUS_PERM_W;

    NxusRangeEntry ranges[3];
    memset(ranges, 0, sizeof(ranges));
    /* two ranges land in the SAME mapping, one in the second (and is clipped) */
    ranges[0].begin = 0x101000; ranges[0].end = 0x102000;
    ranges[1].begin = 0x104000; ranges[1].end = 0x108000;
    ranges[2].begin = 0x4FF000; ranges[2].end = 0x500800;

    NxusScanRegion regions[8];
    u32 n = nxusBuildRegionsMulti(maps, 2, 0, 0, ranges, 3, regions, 8);
    check(n == 3, "three regions (two in one mapping, one clipped)");
    if (n == 3) {
        check(regions[0].base == 0x101000 && regions[0].size == 0x1000, "first range exact");
        check(regions[1].base == 0x104000 && regions[1].size == 0x4000, "second range exact");
        check(regions[0].mapping_idx == 0 && regions[1].mapping_idx == 0, "both keep mapping 0");
        check(regions[2].base == 0x500000 && regions[2].size == 0x800,
              "the third range is clipped to the mapping it meets");
        check(regions[2].addr_base == 0x500000, "offsets stay mapping-relative");
    }

    NxusRangeEntry none[1];
    none[0].begin = 0x900000; none[0].end = 0x901000;
    check(nxusBuildRegionsMulti(maps, 2, 0, 0, none, 1, regions, 8) == 0,
          "a range outside every mapping yields no regions");
    check(nxusBuildRegionsMulti(maps, 2, 0, 0, ranges, 0, regions, 8) == 0,
          "an empty range list yields no regions");

    /* overlapping / duplicated entries must collapse into one region */
    NxusRangeEntry dup[3];
    dup[0].begin = 0x101000; dup[0].end = 0x102000;
    dup[1].begin = 0x101000; dup[1].end = 0x102000;      /* exact duplicate */
    dup[2].begin = 0x101800; dup[2].end = 0x103000;      /* overlaps the first */
    n = nxusBuildRegionsMulti(maps, 2, 0, 0, dup, 3, regions, 8);
    check(n == 1, "duplicate and overlapping ranges merge into one region");
    if (n == 1) {
        check(regions[0].base == 0x101000 && regions[0].size == 0x2000, "merged span is the union");
    }

    /* addr_base must stay the MAPPING base even when the range starts later */
    NxusRangeEntry mid[1];
    mid[0].begin = 0x102000; mid[0].end = 0x103000;
    n = nxusBuildRegionsMulti(maps, 2, 0, 0, mid, 1, regions, 8);
    check(n == 1, "a range inside a mapping yields one region");
    if (n == 1) {
        check(regions[0].base == 0x102000, "the region starts at the range");
        check(regions[0].addr_base == 0x100000,
              "addr_base is the mapping base, not the clipped start");
    }
}

/* The console parses the range list out of the scan payload; that arithmetic used to
   live only in switch/ (never compiled for the host), so it is pinned here. */
static void testRangeListParsing(void) {
    printf("- range list payload parsing\n");

    u8 payload[256];
    memset(payload, 0, sizeof(payload));
    NxusRangeEntry entries[4];

    /* one entry, followed by 16 bytes of "ext" */
    NxusRangeListHeader head = { 1, 0 };
    memcpy(payload + sizeof(NxusScanRequest), &head, sizeof(head));
    NxusRangeEntry e0 = { 0x1000, 0x2000 };
    memcpy(payload + sizeof(NxusScanRequest) + sizeof(head), &e0, sizeof(e0));
    u32 offset = 0;
    int count = nxusParseRangeList(payload, sizeof(NxusScanRequest) + sizeof(head) + sizeof(e0) + 16,
                                   &offset, entries, 4);
    check(count == 1, "one entry is parsed");
    check(offset == sizeof(NxusScanRequest) + sizeof(head) + sizeof(e0),
          "the follow-up offset points past the entry");
    check(entries[0].begin == 0x1000 && entries[0].end == 0x2000, "the entry survives");

    /* truncated payload */
    check(nxusParseRangeList(payload, sizeof(NxusScanRequest) + sizeof(head) + 8, &offset,
                             entries, 4) == -1,
          "a truncated entry list is rejected");
    check(nxusParseRangeList(payload, sizeof(NxusScanRequest) + 4, &offset, entries, 4) == -1,
          "a missing header is rejected");

    /* more entries than the protocol allows: rejected, never clamped (clamping would
       leave the following ext/pattern at the wrong offset) */
    NxusRangeListHeader too_many = { NXUS_MAX_SCAN_RANGES + 1, 0 };
    memcpy(payload + sizeof(NxusScanRequest), &too_many, sizeof(too_many));
    check(nxusParseRangeList(payload, sizeof(payload), &offset, entries, 4) == -2,
          "more entries than the maximum are rejected");

    /* zero entries is a valid (but useless) list */
    NxusRangeListHeader empty = { 0, 0 };
    memcpy(payload + sizeof(NxusScanRequest), &empty, sizeof(empty));
    check(nxusParseRangeList(payload, sizeof(payload), &offset, entries, 4) == 0,
          "an empty list parses as zero entries");
    check(offset == sizeof(NxusScanRequest) + sizeof(head), "the offset skips only the header");
}

static void testUnknownInitial(void) {
    printf("- unknown initial value\n");
    setup();
    putU64(0x10, 111, 4);
    putU64(0x20, 222, 4);
    putU64(0x30, 333, 4);

    NxusScanRequest req = baseRequest(NxusCmp_Unknown, 0, 0);
    req.value_size = 4;
    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));
    pattern.value_type = NxusValueType_U32;

    hitListInit(4);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "unknown scan completes");
    check(g_hits.count == FAKE_SIZE / 4, "unknown records every aligned position");

    /* now the classic workflow: something decreased -> refine */
    putU64(0x20, 100, 4);
    req.cmp_mode = NxusCmp_Decreased;
    check(runNext(&req, &pattern) == NXUS_SCAN_OK, "decreased refine completes");
    check(g_hits.count == 1, "decreased keeps exactly one");
    check(g_hits.addresses[0].offset == 0x20, "and it is the one that changed");
}

static void testAlignmentAndSizes(void) {
    printf("- value sizes and alignment\n");
    setup();
    putU64(0x5000, 0x1234, 2);
    putU64(0x5004, 0x1234, 4);
    putU64(0x5008, 0x1234, 8);

    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));
    pattern.value_type = NxusValueType_U16;
    NxusScanRequest req = baseRequest(NxusCmp_Equal, 0x1234, 0);
    req.value_size = 2;
    hitListInit(2);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "u16 scan completes");
    check(g_hits.count >= 1, "u16 finds the value");

    pattern.value_type = NxusValueType_U64;
    req.value_size = 8;
    hitListInit(8);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "u64 scan completes");
    check(g_hits.count == 1, "u64 finds exactly one");
    check(g_hits.addresses[0].offset == 0x5008, "u64 alignment");

    check(nxusValueTypeSize(NxusValueType_U8) == 1, "type size u8");
    check(nxusValueTypeSize(NxusValueType_U16) == 2, "type size u16");
    check(nxusValueTypeSize(NxusValueType_F32) == 4, "type size f32");
    check(nxusValueTypeSize(NxusValueType_F64) == 8, "type size f64");
    check(nxusValueTypeSize(NxusValueType_String) == 0, "type size string = 0");
    check(nxusHitListValueSize(NxusValueType_String, 4) == 8, "hit size for strings = 8");
    check(nxusHitListValueSize(NxusValueType_U64, 4) == 8, "hit size for u64 = 8");
}

static void testGeLeAndDifferent(void) {
    printf("- greater/less-or-equal and different (delta)\n");
    setup();
    putU64(0x100, 100, 4);
    putU64(0x200, 200, 4);
    putU64(0x300, 300, 4);

    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));
    pattern.value_type = NxusValueType_U32;

    NxusScanRequest req = baseRequest(NxusCmp_GreaterOrEqual, 200, 0);
    hitListInit(4);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "ge scan completes");
    check(g_hits.count == 2, "ge 200 matches 200 and 300");

    /* Refine with <= 200 -> keeps only 200 */
    req.cmp_mode = NxusCmp_LessOrEqual;
    req.target = 200;
    check(runNext(&req, &pattern) == NXUS_SCAN_OK, "le refine completes");
    check(g_hits.count == 1, "le 200 keeps only 200");
    check(g_hits.addresses[0].offset == 0x200, "le 200 hit at 0x200");

    /* Now test Different (|cur - prev| == target):
     * First pass unknown or >= 100 (matches 0x100=100, 0x200=200, 0x300=300),
     * then mutate 0x100 -> 125 (+25), 0x200 -> 175 (-25), 0x300 -> 310 (+10). */
    req = baseRequest(NxusCmp_GreaterOrEqual, 100, 0);
    hitListInit(4);
    check(runFirst(&req, &pattern) == NXUS_SCAN_OK, "ge 100 setup completes");
    check(g_hits.count == 3, "ge 100 finds 3 hits");

    putU64(0x100, 125, 4);
    putU64(0x200, 175, 4);
    putU64(0x300, 310, 4);

    req.cmp_mode = NxusCmp_Different;
    req.target = 25;
    check(runNext(&req, &pattern) == NXUS_SCAN_OK, "different refine completes");
    check(g_hits.count == 2, "different 25 matches both +25 and -25");
    check(g_hits.addresses[0].offset == 0x100 && g_hits.addresses[1].offset == 0x200,
          "different 25 keeps 0x100 and 0x200");

    /* Undo the refine: all 3 original hits (0x100, 0x200, 0x300) come back in order */
    check(nxusHitListUndo(&g_hits) == NXUS_SCAN_OK, "undo restores previous pass");
    check(g_hits.count == 3, "undo restores 3 hits");
    check(g_hits.addresses[0].offset == 0x100 &&
          g_hits.addresses[1].offset == 0x200 &&
          g_hits.addresses[2].offset == 0x300,
          "undo restores ascending offset order");
    check(nxusHitListUndo(&g_hits) == NXUS_SCAN_ERR_PARAM, "second undo without refine is rejected");
}

/* ---- dense baseline -------------------------------------------------- */

/* A memory "store" (an SD file on the console): the first pass writes every
   non-zero block here once, and the refine pass reads a block back only when it
   actually changed. */
static u8  g_store[FAKE_SIZE];
static u32 g_store_used;
static u32 g_store_writes;
static u32 g_store_reads;

static int storeWrite(void *ctx, u64 offset, const void *buf, u32 len) {
    (void)ctx;
    if (offset + len > (u64)sizeof(g_store)) return -1;
    memcpy(g_store + offset, buf, len);
    g_store_writes++;
    if (offset + len > (u64)g_store_used) g_store_used = (u32)(offset + len);
    return 0;
}

static int storeRead(void *ctx, u64 offset, void *buf, u32 len) {
    (void)ctx;
    if (offset + len > (u64)g_store_used) return -1;
    memcpy(buf, g_store + offset, len);
    g_store_reads++;
    return 0;
}

static const NxusBaselineIo g_store_io = { storeWrite, storeRead };

/* The baseline allocates its own region / block tables; the data buffers below
   must be at least one block (NXUS_BASELINE_BLOCK_MIN) wide. */
static NxusBaseline  g_bl;
static u8 g_blk_cur[NXUS_BASELINE_BLOCK_MIN];
static u8 g_blk_prev[NXUS_BASELINE_BLOCK_MIN];
static u8 g_blk_big[FAKE_SIZE];   /* for the coarse-grid case: one 64 KB block */

static void baselineInit(u32 value_size, u32 value_type) {
    nxusBaselineFree(&g_bl);
    memset(g_store, 0, sizeof(g_store));
    g_store_used   = 0;
    g_store_writes = 0;
    g_store_reads  = 0;
    if (nxusBaselineInit(&g_bl, 4, 64, value_size, value_type) != NXUS_SCAN_OK) {
        printf("baseline init failed\n");
        failures++;
    }
}

/* A hit list whose hard cap is far below the candidate count: the whole point of
   the baseline is that this no longer truncates the scan. */
static void baselineHits(u32 max_capacity) {
    nxusHitListFree(&g_hits);
    if (nxusHitListInit(&g_hits, 16, max_capacity, 4) != NXUS_SCAN_OK) {
        printf("baseline hit list init failed\n");
        failures++;
    }
}

static int baselineFirst(const NxusScanRequest *req, NxusScanStats *stats) {
    return nxusScanFirstBaseline(&g_bl, &g_region, 1, req, fakeRead, NULL, &g_store_io, NULL,
                                 g_chunk, (u32)sizeof(g_chunk), stats, NULL);
}

static int baselineNext(const NxusScanRequest *req, NxusScanStats *stats) {
    return nxusScanNextFromBaseline(&g_bl, &g_hits, req, &g_maps, fakeRead, NULL,
                                    &g_store_io, NULL,
                                    g_blk_cur, (u32)sizeof(g_blk_cur),
                                    g_blk_prev, (u32)sizeof(g_blk_prev),
                                    stats, NULL);
}

/* The core problem this feature exists for: an Unknown scan over 64 KB has
   16,384 candidates - 160x the 100 hit slots the caller allows - and used to be
   truncated.  The baseline records block fingerprints instead, so the candidate
   count is complete and the refine pass materialises only what changed. */
static void testDenseBaseline(void) {
    printf("- dense baseline: 16,384 candidates with a 100 hit list\n");
    setup();
    memset(g_memory, 0x11, FAKE_SIZE);      /* non-zero: each block must be stored */

    NxusScanRequest req = baseRequest(NxusCmp_Unknown, 0, 0);
    req.value_size = 4;

    baselineInit(4, NxusValueType_U32);
    baselineHits(100);

    NxusScanStats stats;
    check(baselineFirst(&req, &stats) == NXUS_SCAN_OK, "unknown baseline capture completes");
    check(g_hits.count == 0, "the first pass pushes no hits at all");
    check(g_bl.candidate_count == FAKE_SIZE / 4, "all 16,384 candidates are counted");
    check(g_bl.block_size == NXUS_BASELINE_BLOCK_MIN, "the block grid is 16 KB");
    check(g_bl.block_count == 4, "64 KB is four blocks");
    check(g_bl.stored_bytes == FAKE_SIZE, "every non-zero block is stored once");
    check(g_store_writes == 4, "four store writes, not 16,384");
    check(g_bl.active == 1, "the baseline stays active for the refine pass");

    /* five values change; they sit in two of the four blocks, so the other two
       blocks must be rejected by their hash alone */
    const u64 changed[5] = { 0x4010, 0x4100, 0x7FF0, 0xC000, 0xCFFC };
    for (u32 i = 0; i < 5; i++) putU64(changed[i], 0x22222222u, 4);

    g_store_reads = 0;
    req.cmp_mode = NxusCmp_Changed;
    check(baselineNext(&req, &stats) == NXUS_SCAN_OK, "changed refine completes");
    check(g_hits.count == 5, "exactly the five modified candidates are materialised");
    check(g_store_reads == 2, "only the two changed blocks read the store (O(1) skip)");
    check(g_bl.active == 0, "the baseline is consumed");

    int hits_ok = (g_hits.count == 5);
    for (u32 i = 0; i < g_hits.count; i++) {
        if (g_hits.addresses[i].offset != (u32)changed[i]) hits_ok = 0;
        if (nxusLoadLE(g_hits.values + (size_t)i * g_hits.value_size, 4) != 0x22222222u) hits_ok = 0;
    }
    check(hits_ok, "the hits carry the changed offsets and their fresh values");

    /* same procedure with Increased */
    setup();
    memset(g_memory, 0x11, FAKE_SIZE);
    baselineInit(4, NxusValueType_U32);
    baselineHits(100);
    check(baselineFirst(&req, &stats) == NXUS_SCAN_OK, "second baseline capture completes");
    check(g_hits.count == 0, "still no hits after the capture");

    for (u32 i = 0; i < 5; i++) putU64(changed[i], 0x11111112u, 4);   /* +1 each */

    g_store_reads = 0;
    req.cmp_mode = NxusCmp_Increased;
    check(baselineNext(&req, &stats) == NXUS_SCAN_OK, "increased refine completes");
    check(g_hits.count == 5, "increased materialises exactly the five raised values");
    check(g_store_reads == 2, "increased also reads only the changed blocks");

    int inc_ok = (g_hits.count == 5);
    for (u32 i = 0; i < g_hits.count; i++) {
        if (g_hits.addresses[i].offset != (u32)changed[i]) inc_ok = 0;
    }
    check(inc_ok, "the increased hits are at the five changed offsets");
}

/* A zeroed heap is the common case for an Unknown scan: the block is all zero,
   so there is nothing to store - the flag alone is the previous value. */
static void testBaselineZeroBlocks(void) {
    printf("- dense baseline: zero blocks cost no store space\n");
    setup();                                 /* g_memory is all zero */

    NxusScanRequest req = baseRequest(NxusCmp_Unknown, 0, 0);
    req.value_size = 4;

    baselineInit(4, NxusValueType_U32);
    baselineHits(100);

    NxusScanStats stats;
    check(baselineFirst(&req, &stats) == NXUS_SCAN_OK, "all-zero baseline capture completes");
    check(g_bl.stored_bytes == 0, "nothing is written for an all-zero range");
    check(g_store_writes == 0, "zero store writes");
    check(g_bl.candidate_count == FAKE_SIZE / 4, "candidates are still counted");
    check(g_bl.block_count == 4, "blocks are still tracked");

    putU64(0x8000, 0x1234, 4);               /* a value appears out of zero */

    g_store_reads = 0;
    req.cmp_mode = NxusCmp_Changed;
    check(baselineNext(&req, &stats) == NXUS_SCAN_OK, "changed refine against zero blocks completes");
    check(g_hits.count == 1, "only the value that left zero matches");
    check(g_hits.count == 1 && g_hits.addresses[0].offset == 0x8000, "the changed offset is found");
    check(g_store_reads == 0, "the previous value came from the zero flag, not the store");

    /* a target whose large reads are refused must still be hashed in full */
    setup();
    memset(g_memory, 0x11, FAKE_SIZE);
    baselineInit(4, NxusValueType_U32);
    req.cmp_mode = NxusCmp_Unknown;
    check(nxusScanFirstBaseline(&g_bl, &g_region, 1, &req, fakeReadLimited, NULL, &g_store_io,
                                NULL, g_chunk, (u32)sizeof(g_chunk), &stats, NULL) == NXUS_SCAN_OK,
          "capture survives a 4 KB read limit");
    check(stats.retries > 0, "the refused block read was split into accepted pieces");
    check(g_bl.block_size == NXUS_BASELINE_BLOCK_MIN, "block size is unchanged");
    check(g_bl.candidate_count == FAKE_SIZE / 4, "all candidates found despite the read limit");
}

/* A small block budget makes the grid coarser instead of losing the range. */
static void testBaselineBlockSizing(void) {
    printf("- dense baseline: the block grid grows to fit the block budget\n");
    setup();
    memset(g_memory, 0x11, FAKE_SIZE);

    NxusScanRequest req = baseRequest(NxusCmp_Unknown, 0, 0);
    req.value_size = 4;

    /* a two-block budget cannot hold 16 KB blocks for 64 KB */
    nxusBaselineFree(&g_bl);
    memset(g_store, 0, sizeof(g_store));
    g_store_used = g_store_writes = g_store_reads = 0;
    check(nxusBaselineInit(&g_bl, 2, 2, 4, NxusValueType_U32) == NXUS_SCAN_OK,
          "baseline init with a two block budget");

    NxusScanStats stats;
    check(baselineFirst(&req, &stats) == NXUS_SCAN_OK, "coarse-grid capture completes");
    check(g_bl.block_size == FAKE_SIZE, "the grid grew to 64 KB to stay inside the budget");
    check(g_bl.block_count == 1, "one block covers the range");
    check(g_bl.candidate_count == FAKE_SIZE / 4, "the candidate count is unaffected");

    putU64(0x1234, 0x22222222u, 4);

    baselineHits(100);
    req.cmp_mode = NxusCmp_Changed;
    check(nxusScanNextFromBaseline(&g_bl, &g_hits, &req, &g_maps, fakeRead, NULL,
                                   &g_store_io, NULL, g_chunk, (u32)sizeof(g_chunk),
                                   g_blk_big, (u32)sizeof(g_blk_big), &stats, NULL) == NXUS_SCAN_OK,
          "coarse-grid refine completes");
    check(g_hits.count == 1 && g_hits.addresses[0].offset == 0x1234,
          "the changed value is found on the coarse grid");

    /* a mapping that vanished must contribute nothing */
    baselineInit(4, NxusValueType_U32);
    req.cmp_mode = NxusCmp_Unknown;
    check(baselineFirst(&req, &stats) == NXUS_SCAN_OK, "capture before the mapping test");
    baselineHits(100);
    g_map_entry.valid = 0;
    check(baselineNext(&req, &stats) == NXUS_SCAN_OK, "refine with a vanished mapping completes");
    check(g_hits.count == 0, "a vanished mapping yields no hits");
    g_map_entry.valid = 1;
}

/* A full hit list must stop the materialisation, not the scan. */
static void testBaselineHitCap(void) {
    printf("- dense baseline: a full hit list keeps the hits found so far\n");
    setup();
    memset(g_memory, 0x11, FAKE_SIZE);

    NxusScanRequest req = baseRequest(NxusCmp_Unknown, 0, 0);
    req.value_size = 4;

    baselineInit(4, NxusValueType_U32);
    NxusScanStats stats;
    check(baselineFirst(&req, &stats) == NXUS_SCAN_OK, "capture for the cap test completes");

    /* 200 changed candidates, 100 slots */
    for (u32 i = 0; i < 200; i++) putU64(0x4000 + (u64)i * 4u, 0x33333333u, 4);

    baselineHits(100);
    req.cmp_mode = NxusCmp_Changed;
    int rc = baselineNext(&req, &stats);
    check(rc == NXUS_SCAN_OK, "a full hit list is not reported as an error");
    check(g_hits.count == 100, "exactly max_capacity hits are returned");
    check(g_hits.count == 100 && g_hits.addresses[0].offset == 0x4000,
          "the hits start at the first changed candidate");
    check(g_hits.count == 100 && g_hits.addresses[99].offset == 0x4000 + 99u * 4u,
          "the hits are the ascending prefix of the changed candidates");
    check(g_bl.active == 0, "the baseline is consumed even when it stops early");
}

/* The baseline replaces the classic "one hit per candidate" first pass, so it
   must enumerate exactly the same addresses.  Checked on an unaligned region
   base, where the absolute alignment (align_skip) decides the first candidate. */
static NxusHitList g_ref_hits;

static void testBaselineMatchesFirstPass(void) {
    printf("- dense baseline: same candidates as the classic first pass\n");
    setup();
    for (u32 i = 0; i < FAKE_SIZE; i++) g_memory[i] = (u8)(i * 7u + 3u);

    NxusScanRegion region;
    memset(&region, 0, sizeof(region));
    region.base = g_base + 3;             /* unaligned: align_skip must be applied */
    region.addr_base = g_base;
    region.size = 0x4000;
    region.perm = NXUS_PERM_R | NXUS_PERM_W;
    region.mapping_idx = 0;

    NxusScanRequest req = baseRequest(NxusCmp_Unknown, 0, 0);
    req.value_size = 2;

    nxusHitListFree(&g_ref_hits);
    check(nxusHitListInit(&g_ref_hits, 1024, 20000, 2) == NXUS_SCAN_OK,
          "reference hit list init");

    NxusScanStats stats;
    check(nxusScanFirstEx(&region, 1, &req, NULL, &g_ref_hits, fakeRead, NULL,
                          g_chunk, (u32)sizeof(g_chunk), &stats, NULL) == NXUS_SCAN_OK,
          "classic unknown first pass completes");
    const u32 ref_count = g_ref_hits.count;
    check(ref_count > 8000, "the classic pass records every candidate");

    nxusBaselineFree(&g_bl);
    memset(g_store, 0, sizeof(g_store));
    g_store_used = g_store_writes = g_store_reads = 0;
    check(nxusBaselineInit(&g_bl, 4, 64, 2, NxusValueType_U16) == NXUS_SCAN_OK,
          "baseline init for u16");
    check(nxusScanFirstBaseline(&g_bl, &region, 1, &req, fakeRead, NULL, &g_store_io, NULL,
                                g_chunk, (u32)sizeof(g_chunk), &stats, NULL) == NXUS_SCAN_OK,
          "baseline capture completes");
    check(g_bl.candidate_count == ref_count, "the baseline counts the same candidates");
    check(g_bl.candidate_count == 8191, "unaligned base starts at the first even address");

    nxusHitListFree(&g_hits);
    check(nxusHitListInit(&g_hits, 1024, 20000, 2) == NXUS_SCAN_OK, "baseline hit list init");

    check(nxusScanNextFromBaseline(&g_bl, &g_hits, &req, &g_maps, fakeRead, NULL,
                                   &g_store_io, NULL, g_blk_cur, (u32)sizeof(g_blk_cur),
                                   g_blk_prev, (u32)sizeof(g_blk_prev), &stats, NULL) == NXUS_SCAN_OK,
          "baseline unknown refine completes");
    check(g_hits.count == ref_count, "the baseline materialises the same number of candidates");

    int same = (g_hits.count == ref_count);
    for (u32 i = 0; i < g_hits.count && same; i++) {
        if (g_hits.addresses[i].offset != g_ref_hits.addresses[i].offset) same = 0;
        if (memcmp(g_hits.values + (size_t)i * g_hits.value_size,
                   g_ref_hits.values + (size_t)i * g_ref_hits.value_size, 2) != 0) same = 0;
    }
    check(same, "candidate offsets and values match the classic pass exactly");

    nxusHitListFree(&g_ref_hits);
}

/* The baseline's store offsets and hit offsets are u32: a range set whose total
   size does not fit 32 bits must be refused instead of wrapping (the sum used to
   wrap silently and the blocks were then stored at colliding offsets). */
static void testBaselineRejectsHugeRegion(void) {
    printf("- dense baseline rejects a range set larger than the u32 store\n");
    setup();
    memset(g_memory, 0x11, FAKE_SIZE);

    NxusScanRequest req = baseRequest(NxusCmp_Unknown, 0, 0);
    req.value_size = 4;
    baselineInit(4, NxusValueType_U32);

    NxusScanStats stats;

    NxusScanRegion single;
    memset(&single, 0, sizeof(single));
    single.base = g_base;
    single.addr_base = g_base;
    single.size = 0x100000000ull;             /* 4 GiB */
    single.mapping_idx = 0;
    check(nxusScanFirstBaseline(&g_bl, &single, 1, &req, fakeRead, NULL, &g_store_io, NULL,
                                g_chunk, (u32)sizeof(g_chunk), &stats, NULL) == NXUS_SCAN_ERR_PARAM,
          "a single 4 GiB region is rejected");
    check(g_bl.active == 0, "the rejected baseline is not left active");
    check(g_store_writes == 0, "nothing was written to the store");

    /* Two 2 GiB regions are each fine, but their SUM overflows the u32 store. */
    NxusScanRegion big[2];
    memset(big, 0, sizeof(big));
    big[0].base = g_base;                 big[0].addr_base = g_base;
    big[0].size = 0x80000000ull;          big[0].mapping_idx = 0;
    big[1].base = g_base + 0x80000000ull; big[1].addr_base = g_base;
    big[1].size = 0x80000000ull;          big[1].mapping_idx = 0;
    check(nxusScanFirstBaseline(&g_bl, big, 2, &req, fakeRead, NULL, &g_store_io, NULL,
                                g_chunk, (u32)sizeof(g_chunk), &stats, NULL) == NXUS_SCAN_ERR_PARAM,
          "the summed range size is checked, not just one region");
    check(g_bl.active == 0, "the summed case is not left active either");
    check(g_store_writes == 0, "the summed case stores nothing either");
}

int main(void) {
    printf("Nxus scan-type tests\n");
    testFloat();
    testFloatInfinity();
    testBetween();
    testString();
    testUtf16LongRefine();
    testByteArray();
    testAllTypes();
    testEqualFastPaths();
    testDenseRunRefine();
    testRefusedWindowRead();
    testRefineOffsetUnderflow();
    testClippedRegionOffsets();
    testRefusedChunkRead();
    testRegionBuilding();
    testAlignedFlag();
    testHeapScope();
    testRangeList();
    testRangeListParsing();
    testUnknownInitial();
    testAlignmentAndSizes();
    testGeLeAndDifferent();
    testDenseBaseline();
    testBaselineZeroBlocks();
    testBaselineBlockSizing();
    testBaselineHitCap();
    testBaselineMatchesFirstPass();
    testBaselineRejectsHugeRegion();

    printf("\n%d checks, %d failure(s)\n", checks, failures);
    if (failures == 0) printf("ALL SCAN-TYPE TESTS PASSED\n");
    return failures == 0 ? 0 : 1;
}
