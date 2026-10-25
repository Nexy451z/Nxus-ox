#include "nxus_ptrscan.h"

#include <stdio.h>
#include <string.h>

/* ---- helpers ----------------------------------------------------------- */

/* Dead-end memoization table: every entry proves that "(reg, depth) and
   everything below it" contains zero chains.  512 sets x 8 ways (4096 u64
   slots), no allocation: the table lives in the (stack) scan state. */
#define NXUS_DEAD_SET_SIZE   4096u
#define NXUS_DEAD_WAYS       8u
#define NXUS_DEAD_SETS       (NXUS_DEAD_SET_SIZE / NXUS_DEAD_WAYS)
#define NXUS_DEAD_SET_MASK_S (NXUS_DEAD_SETS - 1u)
#define NXUS_DEAD_SET_SHIFT  (64u - 9u)   /* 512 sets -> 9 index bits */

/* Direct-mapped dereference-window cache: up to 64 slots x window bytes, carved
   out of the caller's scratch (the second half, behind the per-depth windows).
   Enabled only when the caller handed us enough scratch to pay for it. */
#define NXUS_WINDOW_CACHE_MAX_SLOTS  64u
#define NXUS_WINDOW_CACHE_MIN_SCRATCH 65536u

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
    u8 *window_buf;     /* one window per depth: window[depth - 1]; must NOT overlap chunk_buf */
    u32 window;         /* effective window size used for every dereference */

    /* -- dead-end memoization (O(1) rejection of subtrees that yielded nothing) */
    u64 dead_set[NXUS_DEAD_SET_SIZE];    /* key = (reg & ~3) | (depth & 3), 0 = empty */
    u8  dead_depth[NXUS_DEAD_SET_SIZE];  /* exact depth that proved the subtree dead */
    u8  dead_next[NXUS_DEAD_SETS];       /* round-robin victim hint per set */

    /* -- direct-mapped window cache (no IPC when the same reg is re-visited) */
    u8 *wcache_data;                     /* slots * window bytes inside scratch */
    u64 wcache_tag[NXUS_WINDOW_CACHE_MAX_SLOTS];   /* full reg, exact tag */
    u8  wcache_ok[NXUS_WINDOW_CACHE_MAX_SLOTS];    /* 0 = the read for this reg failed */
    u32 wcache_slots;                    /* power of two, 0 = cache disabled */

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

/* ---- dead-end memoization ---------------------------------------------- */

/* The key packs the (4-byte aligned) register and the depth class into one u64.
   0 is reserved for "empty slot", which is safe because a dereferenceable
   register is never 0 and the low two bits are only set by the depth class.
   The depth class keeps the table tiny; the *exact* depth is remembered in
   dead_depth[] so a proof made deep in the tree can never be reused at a
   shallower depth (less budget cannot rescue a subtree that more budget could
   not reach).  See deadContains(). */
static u64 deadKey(u64 reg, u32 depth) {
    return (reg & ~3ull) | (u64)(depth & 3u);
}

static u32 deadHome(u64 key) {
    /* Fibonacci hashing: the high bits of the product mix the address well. */
    return (u32)((key * 0x9E3779B97F4A7C15ull) >> NXUS_DEAD_SET_SHIFT) & NXUS_DEAD_SET_MASK_S;
}

/* Has (reg, depth) already been proven to lead to no chain at all?  O(1), no
   IPC.  Only sound when the stored proof was made at a depth <= depth: a walk
   from a shallower node has strictly more depth budget, so anything that is
   unreachable from up there is also unreachable from down here. */
static int deadContains(const PtrScan *scan, u64 key, u32 depth) {
    const u32 base = deadHome(key) * NXUS_DEAD_WAYS;
    for (u32 way = 0; way < NXUS_DEAD_WAYS; way++) {
        const u32 slot = base + way;
        const u64 stored = scan->dead_set[slot];
        if (stored == 0) return 0;                 /* ways fill from the front */
        if (stored == key && scan->dead_depth[slot] != 0 && scan->dead_depth[slot] <= depth)
            return 1;
    }
    return 0;
}

/* Record "nothing below (reg, depth) reaches the target".  A set keeps its
   shallowest proofs: shallower proofs are reusable by more queries, so they are
   the ones worth holding when a scan touches more nodes than the table has
   slots.  Ties are broken round-robin so no way is starved.  Losing a proof
   only costs speed, never a chain. */
static void deadInsert(PtrScan *scan, u64 key, u32 depth) {
    if (key == 0) return;
    const u32 set = deadHome(key);
    const u32 base = set * NXUS_DEAD_WAYS;
    const u32 start = (u32)scan->dead_next[set] & (NXUS_DEAD_WAYS - 1u);
    u32 victim = base + start;
    u32 victim_depth = 0;
    for (u32 i = 0; i < NXUS_DEAD_WAYS; i++) {
        const u32 way = (start + i) & (NXUS_DEAD_WAYS - 1u);
        const u32 slot = base + way;
        if (scan->dead_set[slot] == 0) {
            scan->dead_set[slot] = key;
            scan->dead_depth[slot] = (u8)depth;
            return;
        }
        if (scan->dead_set[slot] == key) {
            if (scan->dead_depth[slot] == 0 || depth < scan->dead_depth[slot])
                scan->dead_depth[slot] = (u8)depth;
            return;
        }
        if (i == 0 || scan->dead_depth[slot] > victim_depth) {
            victim = slot;
            victim_depth = scan->dead_depth[slot];
        }
    }
    /* Set full: drop its deepest proof (valid for the fewest queries) unless the
       new proof is deeper than every stored one, in which case it is the least
       valuable of the set and is simply discarded. */
    if (depth <= victim_depth) {
        scan->dead_set[victim] = key;
        scan->dead_depth[victim] = (u8)depth;
        scan->dead_next[set] = (u8)(((victim - base) + 1u) & (NXUS_DEAD_WAYS - 1u));
    }
}

/* ---- direct-mapped window cache ---------------------------------------- */

static u32 wcacheIndex(const PtrScan *scan, u64 reg) {
    return (u32)((reg >> 2) ^ (reg >> 12)) & (scan->wcache_slots - 1u);
}

/* Window buffer owned by one depth level.  Every level needs its own: the walk
   recurses *inside* the window loop, so a single shared buffer would let the
   child overwrite the window the parent is still iterating (which silently
   loses pointers of the parent -- and would also break the dead-end memo, since
   a subtree must be a pure function of (reg, depth)). */
static u8 *windowFor(const PtrScan *scan, u32 depth) {
    u32 slot = (depth > 0) ? depth - 1u : 0u;
    if (slot >= scan->opts->max_depth) slot = scan->opts->max_depth - 1u;
    return scan->window_buf + (size_t)slot * scan->window;
}

/* Window at `reg`: served from the cache when it is already there, otherwise
   read once and stored.  The tag is the full register value, so a hit is always
   the same address.  A hit is copied into this depth's buffer (cheap) instead of
   handing out the cache slot, which a deeper level could evict mid-loop.
   Returns NULL when the read failed (negative results are cached too, because
   re-reading a dead address just burns IPC budget). */
static const u8 *fetchWindow(PtrScan *scan, u64 reg, u32 depth) {
    u8 *dst = windowFor(scan, depth);
    if (scan->wcache_slots != 0) {
        const u32 idx = wcacheIndex(scan, reg);
        if (scan->wcache_tag[idx] == reg) {
            if (!scan->wcache_ok[idx]) return NULL;
            memcpy(dst, scan->wcache_data + (size_t)idx * scan->window, scan->window);
            return dst;
        }
    }

    if (readTarget(scan, reg, dst, scan->window) != 0) {
        if (scan->wcache_slots != 0) {
            const u32 idx = wcacheIndex(scan, reg);
            scan->wcache_tag[idx] = reg;
            scan->wcache_ok[idx] = 0;
        }
        return NULL;
    }

    if (scan->wcache_slots != 0) {
        const u32 idx = wcacheIndex(scan, reg);
        memcpy(scan->wcache_data + (size_t)idx * scan->window, dst, scan->window);
        scan->wcache_tag[idx] = reg;
        scan->wcache_ok[idx] = 1;
    }
    return dst;
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

    /* O(1) dead-end test: (reg, depth) was already explored and produced not a
       single chain, so there is no reason to spend a single IPC read on it
       again.  Registers are only memoized when they are 4-byte aligned, which
       is what deadKey() assumes (the low two bits hold the depth class). */
    const int memo = (reg & 3u) == 0;
    const u64 key = memo ? deadKey(reg, depth) : 0;
    if (memo && deadContains(scan, key, depth)) return;

    const u32 count_before = scan->count;
    const u8 *window_data = fetchWindow(scan, reg, depth);
    if (window_data == NULL) {
        /* Unreadable: nothing can hang off this node, now or later. */
        if (memo) deadInsert(scan, key, depth);
        return;
    }

    const u32 window = scan->window;
    const u32 width = scan->opts->value_width;
    for (u32 off = 0; off + width <= window; off += width) {
        u64 w = loadValue(window_data + off, width);
        if (w == 0) continue;
        if (!isMapped(scan, w, width)) continue;
        if (w == reg) continue;                 /* self loop */
        if (scan->stack_depth >= NXUS_PTRSCAN_MAX_DEPTH) continue;

        scan->stack[scan->stack_depth++] = off;
        walkFrom(scan, w, depth + 1);
        scan->stack_depth--;
        if (scan->stats.truncated) return;
    }

    /* This whole subtree was fully explored and produced no chain: remember it
       so the next root that reaches the same node stops here in O(1).  The
       check is strict so that a truncated or cancelled walk is never memoized. */
    if (memo && scan->count == count_before && !scan->stats.truncated &&
        (scan->cancel == NULL || !*scan->cancel))
        deadInsert(scan, key, depth);
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

    /* ~38 KB (dead_set/dead_depth/window-cache tables): far too large for the
       32 KB server-thread stack this is called from, where it silently
       overflowed into .bss.  nxusPtrScan is non-reentrant (one ptrscan per
       connection, the server serialises commands), so a static instance is
       the cheapest way to keep it off the stack. */
    static PtrScan scan;
    memset(&scan, 0, sizeof(scan));
    scan.regions = regions;
    scan.region_count = region_count;
    scan.target = target_address;
    scan.module_base = module_base;
    scan.opts = options;
    scan.read = read;
    scan.read_ctx = read_ctx;
    /* Split the caller's scratch:
        [ chunk_buf | window per depth (max_depth of them) | window cache ... ]
       The chunk buffer and the windows are alive at the same time, and every
       depth level gets its own window because the walk recurses inside the
       window loop.  Whatever is left over becomes a direct-mapped cache of whole
       windows, so a node shared by many roots costs one IPC read instead of one
       per root. */
    const u32 second_size = scratch_size - scratch_size / 2;
    scan.chunk_buf = scratch;
    scan.chunk_size = scratch_size / 2;
    scan.window_buf = scratch + scratch_size / 2;

    /* Shrink the window rather than share a buffer, but never below one value:
       the shipped layouts (64 KB in tests, 256 KB on the console) keep the full
       requested window because it is only max_depth * window bytes. */
    u32 window = options->window_size ? options->window_size : 0x400;
    const u32 per_depth = second_size / options->max_depth;
    if (window > per_depth) window = per_depth;
    window -= window % options->value_width;
    if (window < options->value_width) {
        *out_count = 0;
        if (stats != NULL) memset(stats, 0, sizeof(*stats));
        return NXUS_SCAN_ERR_PARAM;
    }
    scan.window = window;
    const u32 windows_bytes = window * options->max_depth;

    scan.wcache_slots = 0;
    scan.wcache_data = NULL;
    if (scratch_size >= NXUS_WINDOW_CACHE_MIN_SCRATCH && windows_bytes < second_size) {
        const u32 avail = second_size - windows_bytes;
        u32 slots = 1;
        while (slots < NXUS_WINDOW_CACHE_MAX_SLOTS &&
               (u64)(slots * 2u) * (u64)window <= (u64)avail) slots *= 2u;
        if (slots >= 4) {
            scan.wcache_slots = slots;
            scan.wcache_data = scan.window_buf + windows_bytes;  /* right after the windows */
        }
    }
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
