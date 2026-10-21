#include "nxus_ptrscan.h"

#include <stdio.h>
#include <string.h>

/* ---- helpers ----------------------------------------------------------- */

typedef struct {
    const NxusPtrRegion *regions;
    u32 region_count;
    u64 min_mapped;
    u64 max_mapped;
    int sorted;
    u64 target;
    u64 module_base;
    const NxusPtrScanOptions *opts;
    NxusReadFn read;
    void *read_ctx;
    u8 *chunk_buf;      /* static region chunk being scanned for roots */
    u32 chunk_size;
    u8 *window_buf;     /* per-dereference window; must NOT overlap chunk_buf */
    u32 window_cap;

    NxusPtrChain *out;
    u32 max_out;
    u32 count;
    NxusPtrScanStats stats;
    int *cancel;

    u64 current_root;                     /* root the current walk started from */
    u32 stack[NXUS_PTRSCAN_MAX_DEPTH];
    u32 stack_depth;
} PtrScan;

static int regionContaining(const NxusPtrRegion *regions, u32 count, u64 address, u32 width) {
    for (u32 i = 0; i < count; i++) {
        if (address >= regions[i].base && address + width <= regions[i].base + regions[i].size)
            return (int)i;
    }
    return -1;
}

/* regions sorted by base: find the last region starting at or below `address`
   and verify containment. */
static int regionContainingSorted(const NxusPtrRegion *regions, u32 count, u64 address, u32 width) {
    u32 lo = 0, hi = count;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (regions[mid].base <= address) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return -1;
    const NxusPtrRegion *r = &regions[lo - 1];
    if (address >= r->base && address + width <= r->base + r->size) return (int)(lo - 1);
    return -1;
}

static int isMapped(const PtrScan *scan, u64 address, u32 width) {
    if (address < scan->min_mapped || address + width > scan->max_mapped) return 0;
    if (scan->sorted)
        return regionContainingSorted(scan->regions, scan->region_count, address, width) >= 0;
    return regionContaining(scan->regions, scan->region_count, address, width) >= 0;
}

static u64 loadValue(const u8 *p, u32 width) {
    if (width == 4) { u32 v; memcpy(&v, p, 4); return (u64)v; }
    if (width == 8) { u64 v; memcpy(&v, p, 8); return v; }
    u64 v = 0;
    for (u32 i = 0; i < width && i < 8; i++) v |= ((u64)p[i]) << (8 * i);
    return v;
}

static int readTarget(PtrScan *scan, u64 address, void *buffer, u32 size) {
    if (scan->opts->max_reads != 0 && scan->stats.reads >= scan->opts->max_reads) return -1;
    int rc = scan->read(scan->read_ctx, address, buffer, size);
    scan->stats.reads++;
    if (rc == 0) scan->stats.bytes_read += size;
    return rc;
}

static void emitChain(PtrScan *scan, u64 root_address, u32 final_offset) {
    if (scan->count >= scan->max_out) { scan->stats.truncated = 1; return; }
    NxusPtrChain *chain = &scan->out[scan->count++];
    memset(chain, 0, sizeof(*chain));
    chain->root_address = root_address;
    chain->root_offset = (u32)(root_address - scan->module_base);
    chain->step_count = scan->stack_depth;
    for (u32 i = 0; i < scan->stack_depth; i++) chain->steps[i] = scan->stack[i];
    chain->final_offset = final_offset;
}

static void walkFrom(PtrScan *scan, u64 reg, u32 depth) {
    if (scan->cancel != NULL && *scan->cancel) return;
    if (scan->stats.truncated) return;
    if (scan->count >= scan->max_out) { scan->stats.truncated = 1; return; }

    if (reg <= scan->target && scan->target - reg <= scan->opts->max_offset) {
        emitChain(scan, scan->current_root, (u32)(scan->target - reg));
        return;
    }
    if (depth >= scan->opts->max_depth) return;

    u32 window = scan->opts->window_size;
    if (window == 0) window = 0x400;
    if (window > scan->window_cap) window = scan->window_cap;

    /* read the window starting at reg so a hit's offset is its position */
    if (readTarget(scan, reg, scan->window_buf, window) != 0) return;

    const u32 width = scan->opts->value_width;
    for (u32 off = 0; off + width <= window; off += width) {
        u64 w = loadValue(scan->window_buf + off, width);
        if (w == 0) continue;
        if (!isMapped(scan, w, width)) continue;
        if (w == reg) continue;                 /* self loop */
        if (scan->stack_depth >= NXUS_PTRSCAN_MAX_DEPTH) continue;

        scan->stack[scan->stack_depth++] = off;
        walkFrom(scan, w, depth + 1);
        scan->stack_depth--;
        if (scan->stats.truncated) return;
    }
}

/* ---- main entry -------------------------------------------------------- */

int nxusPtrScan(const NxusPtrRegion *regions, u32 region_count,
                u64 target_address, u64 module_base,
                const NxusPtrScanOptions *options,
                NxusPtrChain *out, u32 max_out, u32 *out_count,
                NxusReadFn read, void *read_ctx,
                u8 *scratch, u32 scratch_size,
                NxusPtrScanStats *stats, int *cancel) {
    if (regions == NULL || options == NULL || read == NULL || scratch == NULL ||
        out == NULL || out_count == NULL || scratch_size < 0x1000) {
        return NXUS_SCAN_ERR_PARAM;
    }
    if (options->value_width != 4 && options->value_width != 8) return NXUS_SCAN_ERR_PARAM;
    if (options->max_depth == 0 || options->max_depth > NXUS_PTRSCAN_MAX_DEPTH) return NXUS_SCAN_ERR_PARAM;

    PtrScan scan;
    memset(&scan, 0, sizeof(scan));
    scan.regions = regions;
    scan.region_count = region_count;
    scan.target = target_address;
    scan.module_base = module_base;
    scan.opts = options;
    scan.read = read;
    scan.read_ctx = read_ctx;
    /* split the caller's scratch: first half for static chunks, second half for
       the dereference windows (they are used at the same time) */
    scan.chunk_buf = scratch;
    scan.chunk_size = scratch_size / 2;
    scan.window_buf = scratch + scratch_size / 2;
    scan.window_cap = scratch_size - scratch_size / 2;
    scan.out = out;
    scan.max_out = max_out;
    scan.cancel = cancel;

    /* Precompute the mapped bounds for O(1) rejection and whether the region
       table is sorted so lookups can use a binary search. */
    scan.min_mapped = 0;
    scan.max_mapped = 0;
    scan.sorted = 1;
    for (u32 i = 0; i < region_count; i++) {
        const NxusPtrRegion *r = &regions[i];
        if (i == 0) {
            scan.min_mapped = r->base;
            scan.max_mapped = r->base + r->size;
        } else {
            if (r->base < scan.min_mapped) scan.min_mapped = r->base;
            if (r->base + r->size > scan.max_mapped) scan.max_mapped = r->base + r->size;
            if (r->base < regions[i - 1].base) scan.sorted = 0;
        }
    }

    /* The static regions are read in chunks; every aligned word is a root
       candidate.  Pointers that cannot possibly lead anywhere are pruned before
       any dereference happens. */
    const u32 width = options->value_width;
    const u32 chunk = scan.chunk_size;

    for (u32 r = 0; r < region_count && !scan.stats.truncated; r++) {
        if (regions[r].kind != NXUS_PTRREGION_STATIC) continue;
        u64 pos = regions[r].base;
        const u64 end = regions[r].base + regions[r].size;

        while (pos < end && !scan.stats.truncated) {
            if (cancel != NULL && *cancel) break;
            u64 remaining = end - pos;
            u32 todo = (remaining > (u64)chunk) ? chunk : (u32)remaining;
            if (readTarget(&scan, pos, scan.chunk_buf, todo) != 0) { pos += todo; continue; }

            for (u32 off = 0; off + width <= todo; off += width) {
                u64 value = loadValue(scan.chunk_buf + off, width);
                if (value == 0) continue;
                if (!isMapped(&scan, value, width)) continue;

                u64 root_address = pos + off;
                scan.stats.roots_examined++;
                scan.current_root = root_address;
                scan.stack_depth = 0;
                walkFrom(&scan, value, 1);
                if (scan.stats.truncated) break;
            }
            pos += todo;
        }
    }

    *out_count = scan.count;
    if (stats != NULL) *stats = scan.stats;
    if (cancel != NULL && *cancel) return NXUS_SCAN_ERR_CANCELLED;
    return NXUS_SCAN_OK;
}

/* ---- cheat code generation --------------------------------------------- */

static u32 nibbleWidth(u32 value_width) {
    switch (value_width) {
        case 1: return 1;
        case 2: return 2;
        case 4: return 4;
        default: return 8;
    }
}

int nxusCheatGeneratePointer(const NxusPtrChain *chain, int is_32bit,
                             const char *label, char *out, size_t out_size) {
    if (chain == NULL || out == NULL) return -1;
    /* 32-bit titles must load 4 bytes, otherwise the neighbouring field is
       pulled into the upper half of the register. */
    const char *load = is_32bit ? "540F" : "580F";
    int written = snprintf(out, out_size, "[%s]\n", label ? label : "Nxus pointer chain");
    if (written < 0 || (size_t)written >= out_size) return -1;

    written += snprintf(out + written, out_size - written, "%s0000 %08X\n", load, chain->root_offset);
    if (written < 0 || (size_t)written >= out_size) return -1;

    for (u32 i = 0; i < chain->step_count && i < NXUS_PTRSCAN_MAX_DEPTH; i++) {
        written += snprintf(out + written, out_size - written, "%s1000 %08X\n", load, chain->steps[i]);
        if (written < 0 || (size_t)written >= out_size) return -1;
    }
    if (chain->final_offset != 0) {
        written += snprintf(out + written, out_size - written, "780F0000 %08X\n", chain->final_offset);
        if (written < 0 || (size_t)written >= out_size) return -1;
    }
    return written;
}

int nxusCheatGenerate(const NxusPtrChain *chain, int is_32bit,
                      u64 value, u32 value_width,
                      const char *label, char *out, size_t out_size) {
    int written = nxusCheatGeneratePointer(chain, is_32bit, label, out, out_size);
    if (written < 0) return -1;

    const u32 width = nibbleWidth(value_width);
    /* 6T0RIor0 : T = width, R = 0xF (the register the chain codes use) */
    written += snprintf(out + written, out_size - written,
                        "6%X0F0000 %08X %08X\n", width,
                        (unsigned)((value >> 32) & 0xFFFFFFFFu), (unsigned)(value & 0xFFFFFFFFu));
    if (written < 0 || (size_t)written >= out_size) return -1;
    return written;
}

int nxusCheatGenerateAbsoluteWrite(u64 address, u32 region, u64 value, u32 value_width,
                                   const char *label, char *out, size_t out_size) {
    if (out == NULL) return -1;
    const u32 width = nibbleWidth(value_width);
    /* 0TMR00AA AAAAAAAA VVVVVVVV (VVVVVVVV)
       M = region (0 main, 1 heap, 2 alias, 3 aslr, 4 non-relative/absolute).
       The address field is a single 32-bit dword, which is all a 32-bit title
       can address; 8-byte values carry a second (high) dword. */
    int written;
    if (width == 8) {
        written = snprintf(out, out_size,
                           "[%s]\n0%X%X00000 %08X %08X %08X\n",
                           label ? label : "Nxus write",
                           width, (unsigned)(region & 0xF),
                           (unsigned)(address & 0xFFFFFFFFu),
                           (unsigned)((value >> 32) & 0xFFFFFFFFu),
                           (unsigned)(value & 0xFFFFFFFFu));
    } else {
        /* 0TMR00AA: T = width, M = region, R = register used as offset (0 here) */
        written = snprintf(out, out_size,
                           "[%s]\n0%X%X00000 %08X %08X\n",
                           label ? label : "Nxus write",
                           width, (unsigned)(region & 0xF),
                           (unsigned)(address & 0xFFFFFFFFu),
                           (unsigned)(value & 0xFFFFFFFFu));
    }
    if (written < 0 || (size_t)written >= out_size) return -1;
    return written;
}
