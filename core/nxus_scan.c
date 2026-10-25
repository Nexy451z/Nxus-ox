#include "nxus_scan.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* little-endian value helpers                                         */
/* ------------------------------------------------------------------ */

void nxusStoreLE(u8 *dst, u64 value, u32 size) {
    for (u32 i = 0; i < size; i++) {
        dst[i] = (u8)(value >> (8 * i));
    }
}

u64 nxusLoadLE(const u8 *src, u32 size) {
    u64 v = 0;
    for (u32 i = 0; i < size && i < 8; i++) {
        v |= ((u64)src[i]) << (8 * i);
    }
    return v;
}

static s64 loadSignedLE(const u8 *src, u32 size) {
    switch (size) {
        case 1: return (s64)(s8)src[0];
        case 2: return (s64)(s16)nxusLoadLE(src, 2);
        case 4: return (s64)(s32)nxusLoadLE(src, 4);
        default: return (s64)nxusLoadLE(src, 8);
    }
}

static double bitsToF64(u64 bits) {
    double d;
    memcpy(&d, &bits, sizeof(d));
    return d;
}

static double bitsToF32(u64 bits) {
    u32 b = (u32)bits;
    float f;
    memcpy(&f, &b, sizeof(f));
    return (double)f;
}

/* ------------------------------------------------------------------ */
/* comparison                                                          */
/* ------------------------------------------------------------------ */

int nxusCompareBytes(const u8 *cur, const u8 *prev, const u8 *target, u32 size,
                     u32 cmp_mode, u64 target2, u32 flags) {
    if (cur == NULL || size == 0 || size > 8) return 0;

    if (flags & NXUS_SCAN_F_FLOAT) {
        double c, t, eps, p = 0.0;
        if (size == 8) {
            c   = bitsToF64(nxusLoadLE(cur, 8));
            t   = bitsToF64(nxusLoadLE(target, 8));
            eps = bitsToF64(target2);
            if (prev) p = bitsToF64(nxusLoadLE(prev, 8));
        } else {
            c   = bitsToF32(nxusLoadLE(cur, 4));
            t   = bitsToF32(nxusLoadLE(target, 4));
            eps = bitsToF32(target2);
            if (prev) p = bitsToF32(nxusLoadLE(prev, 4));
        }
        /* epsilon comparison without libm: |c - t| <= eps  <=>  both deltas <= eps.
           c == t is tested first: (Inf - Inf) is NaN, so the epsilon form alone
           rejects an Is-Infinity match / refine (the value never equals itself). */
        switch (cmp_mode) {
            case NxusCmp_Equal:
            case NxusCmp_FuzzyEqual:     return (c == t) || ((c - t) <= eps && (t - c) <= eps);
            case NxusCmp_NotEqual:       return !((c == t) || ((c - t) <= eps && (t - c) <= eps));
            case NxusCmp_Greater:        return c > t;
            case NxusCmp_Less:           return c < t;
            case NxusCmp_GreaterOrEqual: return c >= t;
            case NxusCmp_LessOrEqual:    return c <= t;
            case NxusCmp_Increased:      return prev != NULL && c > p;
            case NxusCmp_Decreased:      return prev != NULL && c < p;
            case NxusCmp_Unchanged:      return prev != NULL && c == p;
            case NxusCmp_Changed:        return prev != NULL && c != p;
            case NxusCmp_Different: {
                if (prev == NULL) return 0;
                double diff = (c >= p) ? (c - p) : (p - c);
                return (diff - t) <= eps && (t - diff) <= eps;
            }
            case NxusCmp_Between: {
                double hi = (size == 8) ? bitsToF64(target2) : bitsToF32(target2);
                return c >= t && c <= hi;
            }
            case NxusCmp_Unknown:        return 1;
            default:                     return 0;
        }
    }

    if (flags & NXUS_SCAN_F_SIGNED) {
        s64 c = loadSignedLE(cur, size);
        s64 t = loadSignedLE(target, size);
        s64 p = prev ? loadSignedLE(prev, size) : 0;
        switch (cmp_mode) {
            case NxusCmp_Equal:          return c == t;
            case NxusCmp_NotEqual:       return c != t;
            case NxusCmp_Greater:        return c > t;
            case NxusCmp_Less:           return c < t;
            case NxusCmp_GreaterOrEqual: return c >= t;
            case NxusCmp_LessOrEqual:    return c <= t;
            case NxusCmp_Increased:      return prev != NULL && c > p;
            case NxusCmp_Decreased:      return prev != NULL && c < p;
            case NxusCmp_Unchanged:      return prev != NULL && c == p;
            case NxusCmp_Changed:        return prev != NULL && c != p;
            case NxusCmp_Different: {
                if (prev == NULL) return 0;
                u64 diff = (c >= p) ? ((u64)c - (u64)p) : ((u64)p - (u64)c);
                u64 want = (t >= 0) ? (u64)t : (0ull - (u64)t);
                return diff == want;
            }
            case NxusCmp_Between:        return c >= t && c <= (s64)target2;
            case NxusCmp_Unknown:        return 1;
            default:                     return 0;
        }
    }

    {
        u64 c = nxusLoadLE(cur, size);
        u64 t = nxusLoadLE(target, size);
        u64 p = prev ? nxusLoadLE(prev, size) : 0;
        switch (cmp_mode) {
            case NxusCmp_Equal:          return c == t;
            case NxusCmp_NotEqual:       return c != t;
            case NxusCmp_Greater:        return c > t;
            case NxusCmp_Less:           return c < t;
            case NxusCmp_GreaterOrEqual: return c >= t;
            case NxusCmp_LessOrEqual:    return c <= t;
            case NxusCmp_Increased:      return prev != NULL && c > p;
            case NxusCmp_Decreased:      return prev != NULL && c < p;
            case NxusCmp_Unchanged:      return prev != NULL && c == p;
            case NxusCmp_Changed:        return prev != NULL && c != p;
            case NxusCmp_Different: {
                if (prev == NULL) return 0;
                u64 diff = (c >= p) ? (c - p) : (p - c);
                return diff == t;
            }
            case NxusCmp_Between:        return c >= t && c <= target2;
            case NxusCmp_Unknown:        return 1;
            default:                     return 0;
        }
    }
}

/* ------------------------------------------------------------------ */
/* refine fast compares (unsigned, fixed 4 / 8 byte width)             */
/* ------------------------------------------------------------------ */

/* Those two are the hot inner loop of a refine pass over an integer hit list:
   the mode switch is hoisted by the caller (only the six modes below get here)
   and the width is a compile-time constant, so the compare is one load per
   operand instead of the type-flag + byte-walk path of nxusCompareBytes. */

static int compareU32Fast(const u8 *cur, const u8 *prev, const u8 *target, u32 cmp_mode) {
    u32 c = 0, t = 0, p = 0;
    memcpy(&c, cur, 4);
    memcpy(&t, target, 4);
    memcpy(&p, prev, 4);
    switch (cmp_mode) {
        case NxusCmp_Equal:     return c == t;
        case NxusCmp_NotEqual:  return c != t;
        case NxusCmp_Increased: return c > p;
        case NxusCmp_Decreased: return c < p;
        case NxusCmp_Unchanged: return c == p;
        case NxusCmp_Changed:   return c != p;
        default:                return 0;
    }
}

static int compareU64Fast(const u8 *cur, const u8 *prev, const u8 *target, u32 cmp_mode) {
    u64 c = 0, t = 0, p = 0;
    memcpy(&c, cur, 8);
    memcpy(&t, target, 8);
    memcpy(&p, prev, 8);
    switch (cmp_mode) {
        case NxusCmp_Equal:     return c == t;
        case NxusCmp_NotEqual:  return c != t;
        case NxusCmp_Increased: return c > p;
        case NxusCmp_Decreased: return c < p;
        case NxusCmp_Unchanged: return c == p;
        case NxusCmp_Changed:   return c != p;
        default:                return 0;
    }
}

/* ------------------------------------------------------------------ */
/* value types / patterns                                              */
/* ------------------------------------------------------------------ */

u32 nxusValueTypeSize(u32 value_type) {
    switch (value_type) {
        case NxusValueType_U8:  return 1;
        case NxusValueType_U16: return 2;
        case NxusValueType_U32:
        case NxusValueType_F32: return 4;
        case NxusValueType_U64:
        case NxusValueType_F64: return 8;
        default: return 0;      /* String / Bytes / Binary / All */
    }
}

u32 nxusHitListValueSize(u32 value_type, u32 fallback_size) {
    u32 size = nxusValueTypeSize(value_type);
    if (size != 0) return size;
    if (value_type == NxusValueType_String || value_type == NxusValueType_Bytes ||
        value_type == NxusValueType_Binary || value_type == NxusValueType_All) {
        return 8;               /* hash, or the widest numeric value */
    }
    return fallback_size ? fallback_size : 4;
}

u64 nxusHashBytes(const u8 *data, u32 len) {
    u64 hash = 0xCBF29CE484222325ull;
    for (u32 i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x100000001B3ull;
    }
    return hash;
}

/* Bytes a single match occupies for this pattern. */
static u32 patternWindow(const NxusScanPattern *pattern) {
    if (pattern == NULL || pattern->pattern == NULL) return 0;
    if (pattern->value_type == NxusValueType_String && (pattern->flags & NXUS_SCAN_F_UTF16)) {
        return pattern->pattern_len * 2;
    }
    return pattern->pattern_len;
}

static int isPatternType(u32 value_type) {
    return value_type == NxusValueType_String || value_type == NxusValueType_Bytes ||
           value_type == NxusValueType_Binary;
}

/* A wildcard byte pattern is applied as mask[i] at pattern[i], and the caller
   locates that mask at pattern + pattern_len (nxus_server.c builds the pointer
   that way after reading ext.pattern_len).  If the declared length is not the
   length actually sent - the console rounds it down to NXUS_SCAN_MAX_PATTERN -
   mask[] is read from the wrong offset and every "??" compares the wrong bytes,
   silently producing wrong hits.  The wire format caps a byte array at
   NXUS_SCAN_MAX_PATTERN and always carries a mask with the WILDCARD flag, so
   anything else is rejected here instead of scanning with a bogus mask. */
static int patternLengthValid(const NxusScanPattern *pattern) {
    if (pattern == NULL || pattern->pattern == NULL || pattern->pattern_len == 0) return 0;

    if (pattern->value_type == NxusValueType_Bytes ||
        pattern->value_type == NxusValueType_Binary) {
        /* A rounded / truncated length (the console clamps at 64) cannot match
           the bytes that follow it, and the mask position depends on it. */
        if (pattern->pattern_len > NXUS_SCAN_MAX_PATTERN) return 0;
        if ((pattern->flags & NXUS_SCAN_F_WILDCARD) && pattern->mask == NULL) return 0;
    }
    return 1;
}

static u8 foldCase(u8 c) {
    return (c >= 'A' && c <= 'Z') ? (u8)(c + 32) : c;
}

/* Match pattern_len bytes at cur.  Handles strings (ASCII / UTF-16LE, optional
   case folding), byte arrays with ?? wildcards and bit patterns. */
static int matchPatternAt(const u8 *cur, const NxusScanPattern *pattern) {
    if (pattern == NULL || pattern->pattern == NULL || pattern->pattern_len == 0) return 0;

    if (pattern->value_type == NxusValueType_String) {
        const int utf16 = (pattern->flags & NXUS_SCAN_F_UTF16) != 0;
        const int fold  = (pattern->flags & NXUS_SCAN_F_CASE_INSENS) != 0;
        for (u32 i = 0; i < pattern->pattern_len; i++) {
            u8 want = pattern->pattern[i];
            u8 got  = cur[utf16 ? i * 2 : i];
            if (utf16 && cur[i * 2 + 1] != 0) return 0;   /* ASCII only */
            if (fold) { want = foldCase(want); got = foldCase(got); }
            if (want != got) return 0;
        }
        return 1;
    }

    for (u32 i = 0; i < pattern->pattern_len; i++) {
        const u8 mask = (pattern->mask != NULL) ? pattern->mask[i] : 0xFF;
        if (((cur[i] ^ pattern->pattern[i]) & mask) != 0) return 0;
    }
    return 1;
}

/* Compare one candidate value of the given type against the target. */
static int compareTyped(const u8 *cur, u32 value_type, const NxusScanRequest *req, const u8 *target) {
    u32 size = nxusValueTypeSize(value_type);
    if (size == 0) return 0;
    u32 flags = req->flags;
    if (value_type == NxusValueType_F32 || value_type == NxusValueType_F64) {
        flags |= NXUS_SCAN_F_FLOAT;
    } else {
        flags &= ~NXUS_SCAN_F_FLOAT;
    }
    return nxusCompareBytes(cur, NULL, target, size, req->cmp_mode, req->target2, flags);
}

/* Legacy callers pass no pattern: derive the type from the old request fields. */
static NxusScanPattern patternFromRequest(const NxusScanRequest *req) {
    NxusScanPattern pattern;
    memset(&pattern, 0, sizeof(pattern));
    pattern.flags = req->flags;
    if (req->flags & NXUS_SCAN_F_FLOAT) {
        pattern.value_type = (req->value_size == 8) ? NxusValueType_F64 : NxusValueType_F32;
    } else {
        switch (req->value_size) {
            case 1: pattern.value_type = NxusValueType_U8;  break;
            case 2: pattern.value_type = NxusValueType_U16; break;
            case 8: pattern.value_type = NxusValueType_U64; break;
            default: pattern.value_type = NxusValueType_U32; break;
        }
    }
    return pattern;
}

/* ------------------------------------------------------------------ */
/* hit list                                                            */
/* ------------------------------------------------------------------ */

int nxusHitListInit(NxusHitList *list, u32 capacity, u32 max_capacity, u32 value_size) {
    if (list == NULL || value_size == 0 || value_size > 8) return NXUS_SCAN_ERR_PARAM;
    memset(list, 0, sizeof(*list));
    list->value_size   = value_size;
    list->max_capacity = max_capacity ? max_capacity : capacity;
    /* Never allocate (or advertise) more than the caller's hard cap: growing is
       capped later by hitListGrow, but the initial malloc used to ignore it. */
    if (capacity > list->max_capacity) capacity = list->max_capacity;
    if (capacity > 0) {
        list->addresses = (NxusHitAddress *)malloc((size_t)capacity * sizeof(NxusHitAddress));
        list->values    = (u8 *)malloc((size_t)capacity * value_size);
        if (list->addresses == NULL || list->values == NULL) {
            nxusHitListFree(list);
            return NXUS_SCAN_ERR_PARAM;
        }
        list->capacity = capacity;
    }
    return NXUS_SCAN_OK;
}

void nxusHitListFree(NxusHitList *list) {
    if (list == NULL) return;
    free(list->addresses);
    free(list->values);
    memset(list, 0, sizeof(*list));
}

void nxusHitListReset(NxusHitList *list) {
    if (list != NULL) {
        list->count = 0;
        list->prev_count = 0;
    }
}

static u64 hitSortKey(NxusHitAddress a) {
    return ((u64)a.mapping_idx << 32) | (u64)a.offset;
}

int nxusHitListUndo(NxusHitList *list) {
    if (list == NULL || list->prev_count == 0 || list->prev_count < list->count ||
        list->prev_count > list->capacity) {
        return NXUS_SCAN_ERR_PARAM;
    }
    u32 n = list->prev_count;
    u32 stored = list->value_size;
    list->count = n;
    list->prev_count = 0;

    /* Restore ascending (mapping_idx, offset) order in-place via Shellsort (0 heap allocs). */
    u32 gap = 1;
    while (gap < n / 3) gap = gap * 3 + 1;
    while (gap >= 1) {
        for (u32 i = gap; i < n; i++) {
            NxusHitAddress tmp_addr = list->addresses[i];
            u64 tmp_key = hitSortKey(tmp_addr);
            u8 tmp_val[8];
            memcpy(tmp_val, list->values + (size_t)i * stored, stored);
            u32 j = i;
            while (j >= gap && hitSortKey(list->addresses[j - gap]) > tmp_key) {
                list->addresses[j] = list->addresses[j - gap];
                memcpy(list->values + (size_t)j * stored,
                       list->values + (size_t)(j - gap) * stored, stored);
                j -= gap;
            }
            list->addresses[j] = tmp_addr;
            memcpy(list->values + (size_t)j * stored, tmp_val, stored);
        }
        gap /= 3;
    }
    return NXUS_SCAN_OK;
}

static int hitListGrow(NxusHitList *list) {
    u32 new_capacity = list->capacity ? list->capacity * 2 : 4096;
    if (new_capacity > list->max_capacity) new_capacity = list->max_capacity;
    if (new_capacity <= list->capacity) return NXUS_SCAN_ERR_FULL;

    /* Grow the value array FIRST.  Growing addresses first and then failing on
       values used to leave capacity at the new size while values still had the
       old size: every later push then wrote past the values allocation or, with
       the old ordering, the list advertised room it could not use (permanent
       FULL).  Capacity is only updated once BOTH arrays are the new size. */
    u8 *nv = (u8 *)realloc(list->values, (size_t)new_capacity * list->value_size);
    if (nv == NULL) return NXUS_SCAN_ERR_FULL;
    list->values = nv;

    NxusHitAddress *na = (NxusHitAddress *)realloc(list->addresses,
                                                   (size_t)new_capacity * sizeof(NxusHitAddress));
    if (na == NULL) {
        /* Undo the value growth so no unused tail is left behind and capacity
           keeps describing the real allocation exactly.  A shrinking realloc
           never moves into a smaller block, so this normally succeeds; if it
           does not, the block is merely larger than the advertised capacity and
           the next grow simply retries (entries past capacity are never
           touched). */
        if (list->capacity == 0) {
            free(list->values);
            list->values = NULL;
        } else {
            u8 *shrunk = (u8 *)realloc(list->values,
                                       (size_t)list->capacity * list->value_size);
            if (shrunk != NULL) list->values = shrunk;
        }
        return NXUS_SCAN_ERR_FULL;
    }
    list->addresses = na;

    list->capacity = new_capacity;
    return NXUS_SCAN_OK;
}

static int hitListPush(NxusHitList *list, u32 mapping_idx, u32 offset,
                       const u8 *value, u32 value_type) {
    if (list->count >= list->capacity) {
        int rc = hitListGrow(list);
        if (rc != NXUS_SCAN_OK) return rc;
    }
    NxusHitAddress *slot = &list->addresses[list->count];
    slot->offset      = offset;
    slot->mapping_idx = (u16)mapping_idx;
    slot->reserved    = (u16)value_type;
    memset(list->values + (size_t)list->count * list->value_size, 0, list->value_size);
    memcpy(list->values + (size_t)list->count * list->value_size, value, list->value_size);
    list->count++;
    return NXUS_SCAN_OK;
}

int nxusHitResolve(const NxusHitList *list, const NxusMappingTable *maps, u32 index, u64 *out_address) {
    if (list == NULL || maps == NULL || out_address == NULL || index >= list->count) return 0;
    u16 mi = list->addresses[index].mapping_idx;
    if (mi >= maps->count) return 0;
    if (!maps->entries[mi].valid) return 0;
    *out_address = maps->entries[mi].base + list->addresses[index].offset;
    return 1;
}

/* ------------------------------------------------------------------ */
/* first pass                                                          */
/* ------------------------------------------------------------------ */

u32 nxusBuildRegions(const NxusMappingEntry *maps, u32 map_count,
                     u64 main_base, u64 main_size,
                     u32 scope, u64 range_begin, u64 range_end,
                     NxusScanRegion *out, u32 capacity) {
    if (out == NULL || capacity == 0) return 0;

    u32 n = 0;
    for (u32 i = 0; i < map_count && n < capacity; i++) {
        const NxusMappingEntry *m = &maps[i];
        const u32 perm = m->reserved;
        if (!(perm & NXUS_PERM_R) || m->size == 0) continue;

        u64 begin = m->base;
        u64 end = m->base + m->size;

        switch (scope) {
            case NxusScope_Main:
                if (main_size == 0) continue;
                if (end <= main_base || begin >= main_base + main_size) continue;
                if (begin < main_base) begin = main_base;
                if (end > main_base + main_size) end = main_base + main_size;
                break;
            case NxusScope_Heap:
                /* Heap means the process heap, not "everything writable": stack and
                   .data would only add noise (jnoexs filters by MemoryType.HEAP too).
                   When the mapping snapshot has no type (0), keep the old, wider
                   behaviour instead of returning nothing. */
                if (!(perm & NXUS_PERM_W)) continue;
                if (m->type != 0 && m->type != NXUS_MEMTYPE_HEAP) continue;
                break;
            case NxusScope_Writable:
                if (!(perm & NXUS_PERM_W)) continue;
                break;
            case NxusScope_Tls:
                if (m->type != NXUS_MEMTYPE_TLS) continue;
                break;
            case NxusScope_Custom:
                if (range_end <= range_begin) continue;
                if (end <= range_begin || begin >= range_end) continue;
                if (begin < range_begin) begin = range_begin;
                if (end > range_end) end = range_end;
                break;
            case NxusScope_All:
            default:
                break;
        }

        if (end <= begin) continue;
        out[n].base = begin;
        out[n].addr_base = m->base;      /* hits stay mapping-relative */
        out[n].size = end - begin;
        out[n].perm = perm;
        out[n].mapping_idx = i;
        n++;
    }
    return n;
}

int nxusParseRangeList(const u8 *payload, u32 length, u32 *out_offset,
                       NxusRangeEntry *out, u32 capacity) {
    if (payload == NULL || out_offset == NULL) return -1;
    const u32 base = (u32)sizeof(NxusScanRequest);
    if (length < base + (u32)sizeof(NxusRangeListHeader)) return -1;

    NxusRangeListHeader head;
    memcpy(&head, payload + base, sizeof(head));
    if (head.count > NXUS_MAX_SCAN_RANGES) return -2;
    if (head.count > capacity) return -2;

    const u32 entries = head.count;
    if (length < base + (u32)sizeof(NxusRangeListHeader) + entries * (u32)sizeof(NxusRangeEntry)) {
        return -1;
    }
    if (entries > 0) {
        memcpy(out, payload + base + sizeof(NxusRangeListHeader),
               (size_t)entries * sizeof(NxusRangeEntry));
    }
    *out_offset = base + (u32)sizeof(NxusRangeListHeader) + entries * (u32)sizeof(NxusRangeEntry);
    return (int)entries;
}

/* Intersections of one mapping with the list, sorted and merged: overlapping or
   duplicate ranges must not report the same address twice. */
static u32 clipRangesToMapping(u64 map_begin, u64 map_end,
                               const NxusRangeEntry *ranges, u32 range_count,
                               u64 *begin_out, u64 *end_out, u32 capacity) {
    u64 begins[NXUS_MAX_SCAN_RANGES];
    u64 ends[NXUS_MAX_SCAN_RANGES];
    u32 n = 0;
    for (u32 r = 0; r < range_count; r++) {
        if (ranges[r].end <= ranges[r].begin) continue;
        u64 b = ranges[r].begin > map_begin ? ranges[r].begin : map_begin;
        u64 e = ranges[r].end < map_end ? ranges[r].end : map_end;
        if (e <= b) continue;
        if (n < capacity) { begins[n] = b; ends[n] = e; n++; }
    }
    if (n < 2) {
        if (n == 1) { begin_out[0] = begins[0]; end_out[0] = ends[0]; }
        return n;
    }
    /* insertion sort (n <= 16) then merge overlaps and adjacency */
    for (u32 i = 1; i < n; i++) {
        u64 b = begins[i], e = ends[i];
        u32 j = i;
        while (j > 0 && begins[j - 1] > b) { begins[j] = begins[j - 1]; ends[j] = ends[j - 1]; j--; }
        begins[j] = b; ends[j] = e;
    }
    u32 m = 0;
    begin_out[0] = begins[0];
    end_out[0] = ends[0];
    for (u32 i = 1; i < n; i++) {
        if (begins[i] <= end_out[m]) {
            if (ends[i] > end_out[m]) end_out[m] = ends[i];
        } else {
            m++;
            begin_out[m] = begins[i];
            end_out[m] = ends[i];
        }
    }
    return m + 1;
}

u32 nxusBuildRegionsMulti(const NxusMappingEntry *maps, u32 map_count,
                          u64 main_base, u64 main_size,
                          const NxusRangeEntry *ranges, u32 range_count,
                          NxusScanRegion *out, u32 capacity) {
    (void)main_base; (void)main_size;
    if (maps == NULL || ranges == NULL || out == NULL || capacity == 0) return 0;

    u32 n = 0;
    for (u32 i = 0; i < map_count; i++) {
        const NxusMappingEntry *m = &maps[i];
        const u32 perm = m->reserved;
        if (!(perm & NXUS_PERM_R) || m->size == 0) continue;

        const u64 map_begin = m->base;
        const u64 map_end = m->base + m->size;

        /* The intersections are sorted and merged first: overlapping or duplicated
           entries must not report the same address twice (a duplicate would also
           waste hit-list slots and inflate the count the user reads). */
        u64 begins[NXUS_MAX_SCAN_RANGES];
        u64 ends[NXUS_MAX_SCAN_RANGES];
        u32 pieces = clipRangesToMapping(map_begin, map_end, ranges, range_count,
                                         begins, ends, NXUS_MAX_SCAN_RANGES);
        for (u32 p = 0; p < pieces && n < capacity; p++) {
            out[n].base = begins[p];
            out[n].addr_base = m->base;   /* hits stay mapping-relative */
            out[n].size = ends[p] - begins[p];
            out[n].perm = perm;
            out[n].mapping_idx = i;
            n++;
        }
        if (n >= capacity) break;
    }
    return n;
}

/* Derive the target2 epsilon bits from epsilon_decimals when FuzzyEqual is
   requested with target2 == 0 (what the GUI/CLI send in NxusScanExt). */
static u64 fuzzyEpsilonBits(u32 value_type, u32 value_size, u32 epsilon_decimals) {
    u32 decimals = (epsilon_decimals > 0) ? epsilon_decimals : 2u;
    if (decimals > 9u) decimals = 9u;
    double eps = 1.0;
    for (u32 i = 0; i < decimals; i++) eps /= 10.0;
    if (value_type == NxusValueType_F64 || (value_type == 0 && value_size == 8)) {
        u64 bits = 0;
        memcpy(&bits, &eps, sizeof(bits));
        return bits;
    } else {
        float e = (float)eps;
        u32 bits = 0;
        memcpy(&bits, &e, sizeof(bits));
        return (u64)bits;
    }
}

/* Specialized inner loop for the most common first-pass scan (unsigned integer,
   compare Equal).  The width switch and the target load are hoisted out of the
   loop, and the memcpy size is a compile-time constant, so one candidate costs a
   single load + compare + branch instead of the type-flag / mode / byte-walk
   path of compareTyped (measured ~94% of the scan CPU). */
#define NXUS_SCAN_EQ_LOOP(T, W)                                                \
    do {                                                                       \
        T want_v;                                                              \
        memcpy(&want_v, target, (W));                                          \
        for (; addr <= last_start; addr += step) {                             \
            T cand;                                                            \
            memcpy(&cand, chunk + (addr - pos), (W));                          \
            if (cand != want_v) continue;                                      \
            u8 stored[8];                                                      \
            memset(stored, 0, sizeof(stored));                                 \
            memcpy(stored, &cand, (W));                                        \
            int push_rc = hitListPush(hits, region->mapping_idx,               \
                                      (u32)(addr - region_addr_base),          \
                                      stored, value_type);                     \
            if (push_rc != NXUS_SCAN_OK) return push_rc;                       \
        }                                                                      \
    } while (0)

int nxusScanFirstEx(const NxusScanRegion *regions, u32 region_count,
                    const NxusScanRequest *req, const NxusScanPattern *pattern_in,
                    NxusHitList *hits,
                    NxusReadFn read, void *read_ctx,
                    u8 *chunk, u32 chunk_size,
                    NxusScanStats *stats, int *cancel) {
    if (regions == NULL || req == NULL || hits == NULL || read == NULL ||
        chunk == NULL || chunk_size == 0) {
        return NXUS_SCAN_ERR_PARAM;
    }

    NxusScanPattern derived;
    const NxusScanPattern *pattern = pattern_in;
    if (pattern == NULL) {
        derived = patternFromRequest(req);
        pattern = &derived;
    }

    NxusScanRequest effective_req = *req;
    if (effective_req.cmp_mode == NxusCmp_FuzzyEqual && effective_req.target2 == 0) {
        effective_req.target2 = fuzzyEpsilonBits(pattern->value_type, effective_req.value_size,
                                                 pattern->epsilon_decimals);
    }
    req = &effective_req;

    const u32 value_type = pattern->value_type;
    const int  all_types = (value_type == NxusValueType_All);
    const int  patterned = isPatternType(value_type);

    /* Refuse a pattern whose length the mask offset cannot be trusted for. */
    if (patterned && !patternLengthValid(pattern)) return NXUS_SCAN_ERR_PARAM;

    u32 window, step;
    if (patterned) {
        window = patternWindow(pattern);
        step   = 1;                                  /* strings can sit anywhere */
    } else if (all_types) {
        window = 8;                                  /* widest numeric value */
        step   = 4;
    } else {
        window = nxusValueTypeSize(value_type);
        step   = window ? window : req->value_size;
    }
    /* A UTF-16 window spans two bytes per pattern byte, so the window may be up
       to twice the pattern limit. */
    if (window == 0 || window > NXUS_SCAN_MAX_PATTERN * 2 || step == 0) return NXUS_SCAN_ERR_PARAM;
    /* Note on NXUS_SCAN_F_ALIGNED: numeric scans walk absolute multiples of the
       value size (addr = align_up(pos, step)), so every hit is already aligned and
       the flag cannot change the result.  Unaligned numeric values are therefore
       not found by design; string / byte patterns walk byte by byte and do find
       them.  The GUI checkbox is labelled accordingly. */


    if (patterned) {
        switch (req->cmp_mode) {
            case NxusCmp_Equal:
            case NxusCmp_NotEqual:
            case NxusCmp_Changed:
            case NxusCmp_Unchanged:
                break;
            default:
                /* Greater/Between/Unknown make no sense for a byte pattern and
                   would record hits the refine pass then throws away. */
                return NXUS_SCAN_ERR_PARAM;
        }
    }
    if (hits->value_size == 0 || hits->value_size > 8) return NXUS_SCAN_ERR_PARAM;

    /* target bytes, sized for the type being compared */
    u8 target[8];
    memset(target, 0, sizeof(target));
    {
        u32 target_size = nxusValueTypeSize(value_type);
        if (target_size == 0) target_size = req->value_size ? req->value_size : 8;
        nxusStoreLE(target, req->target, target_size);
    }

    u64 total_bytes = 0;
    for (u32 r = 0; r < region_count; r++) total_bytes += regions[r].size;

    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
        stats->regions_total = region_count;
    }

    for (u32 r = 0; r < region_count; r++) {
        const NxusScanRegion *region = &regions[r];
        u64 pos = region->base;
        const u64 end = region->base + region->size;
        const u64 region_addr_base = region->addr_base ? region->addr_base : region->base;
        /* Highest address whose mapping-relative offset still fits the u32
           offset field of NxusHitAddress. */
        const u64 off_limit = region_addr_base + 0xFFFFFFFFull;

        while (pos < end) {
            if (cancel != NULL && *cancel) {
                if (stats != NULL) stats->regions_done = r;
                return NXUS_SCAN_ERR_CANCELLED;
            }

            u64 remaining = end - pos;
            u32 todo = (remaining > (u64)chunk_size) ? chunk_size : (u32)remaining;

            if (read(read_ctx, pos, chunk, todo) != 0) {
                /* dmnt may refuse a large read (the accepted size is not
                   documented).  Halving down to 4 KB before giving up keeps a
                   size limit from silently producing an empty scan. */
                u32 retry = todo / 2;
                while (retry >= 4096u && read(read_ctx, pos, chunk, retry) != 0) {
                    retry /= 2;
                }
                if (retry >= 4096u) {
                    todo = retry;
                    if (stats != NULL) stats->retries++;
                } else {
                    /* genuinely unreadable: skip, never abort the whole scan.
                       Progress still advances so the PC-side bar cannot stall. */
                    if (stats != NULL) {
                        stats->regions_done = r;
                        stats->dropped++;
                        stats->bytes_scanned += todo;
                        if (total_bytes) stats->permille = (u32)((stats->bytes_scanned * 1000ull) / total_bytes);
                    }
                    pos += todo;
                    continue;
                }
            }

            if (stats != NULL) {
                stats->reads++;
                stats->bytes_read += todo;
            }

            const u64 chunk_end = pos + todo;
            u64 addr = (pos + step - 1) & ~((u64)step - 1);

            /* Last start position whose whole window still lies in this chunk,
               clamped so the hit offset cannot overflow u32. */
            u64 last_start = 0;
            int have_last = 0;
            if ((chunk_end - pos) >= (u64)window) {
                last_start = chunk_end - (u64)window;
                if (last_start > off_limit) last_start = off_limit;
                have_last = (addr <= last_start);
            }

            int chunk_done = 0;

            if (have_last && !patterned && !all_types &&
                req->cmp_mode == NxusCmp_Equal &&
                window <= 8 && value_type <= NxusValueType_U64) {
                switch (window) {
                    case 1: NXUS_SCAN_EQ_LOOP(u8,  1); chunk_done = 1; break;
                    case 2: NXUS_SCAN_EQ_LOOP(u16, 2); chunk_done = 1; break;
                    case 4: NXUS_SCAN_EQ_LOOP(u32, 4); chunk_done = 1; break;
                    case 8: NXUS_SCAN_EQ_LOOP(u64, 8); chunk_done = 1; break;
                    default: break;
                }
            }

            if (!chunk_done) {
                for (; addr + window <= chunk_end; addr += step) {
                    const u8 *cur = chunk + (addr - pos);
                    u64 offset = addr - region_addr_base;
                    if (offset > 0xFFFFFFFFull) continue;   /* u32 offset limit */

                    int rc = NXUS_SCAN_OK;

                    if (patterned) {
                        if (!matchPatternAt(cur, pattern)) continue;
                        u8 stored[8];
                        nxusStoreLE(stored, nxusHashBytes(cur, window), 8);
                        rc = hitListPush(hits, region->mapping_idx, (u32)offset, stored, value_type);
                    } else if (all_types) {
                        static const u32 order[6] = {
                            NxusValueType_U8,  NxusValueType_U16, NxusValueType_U32,
                            NxusValueType_U64, NxusValueType_F32, NxusValueType_F64,
                        };
                        for (u32 t = 0; t < 6 && rc == NXUS_SCAN_OK; t++) {
                            u32 size = nxusValueTypeSize(order[t]);
                            if ((addr - pos) + size > todo) continue;
                            if (!compareTyped(cur, order[t], req, target)) continue;
                            u8 stored[8];
                            memset(stored, 0, sizeof(stored));
                            memcpy(stored, cur, size);
                            rc = hitListPush(hits, region->mapping_idx, (u32)offset, stored, order[t]);
                        }
                    } else {
                        if (!compareTyped(cur, value_type, req, target)) continue;
                        u8 stored[8];
                        memset(stored, 0, sizeof(stored));
                        memcpy(stored, cur, window);
                        rc = hitListPush(hits, region->mapping_idx, (u32)offset, stored, value_type);
                    }

                    if (rc != NXUS_SCAN_OK) return rc;      /* hit list full */
                }
            }

            /* B3: when the window is wider than the step (patterns, All), the
               tail of this chunk holds start positions whose window reaches into
               the next chunk.  'addr' is exactly the first start position this
               chunk could not inspect, so restart the next chunk there instead of
               at pos + todo: a value / pattern straddling the boundary is then
               found instead of being silently lost.  bytes_scanned follows the
               real advance, so the overlap is not counted twice. */
            u64 advance = (u64)todo;
            if (window > step && chunk_end < end && addr > pos && addr <= chunk_end) {
                advance = addr - pos;
            }
            pos += advance;
            if (stats != NULL) {
                stats->bytes_scanned += advance;
                if (total_bytes) stats->permille = (u32)((stats->bytes_scanned * 1000ull) / total_bytes);
            }
        }
        if (stats != NULL) stats->regions_done = r + 1;
    }

    return NXUS_SCAN_OK;
}

#undef NXUS_SCAN_EQ_LOOP

int nxusScanFirst(const NxusScanRegion *regions, u32 region_count,
                  const NxusScanRequest *req, NxusHitList *hits,
                  NxusReadFn read, void *read_ctx,
                  u8 *chunk, u32 chunk_size,
                  NxusScanStats *stats, int *cancel) {
    return nxusScanFirstEx(regions, region_count, req, NULL, hits, read, read_ctx,
                           chunk, chunk_size, stats, cancel);
}

/* ------------------------------------------------------------------ */
/* refine pass (sparse coalescing + in-place compaction)                */
/* ------------------------------------------------------------------ */

int nxusScanNextEx(NxusHitList *hits, const NxusScanRequest *req, const NxusScanPattern *pattern_in,
                   const NxusMappingTable *maps,
                   NxusReadFn read, void *read_ctx,
                   u8 *window, u32 window_max, u32 gap_threshold,
                   NxusScanStats *stats, int *cancel) {
    if (hits == NULL || req == NULL || maps == NULL || read == NULL || window == NULL) {
        return NXUS_SCAN_ERR_PARAM;
    }

    const u32 stored = hits->value_size;
    if (stored == 0 || stored > 8) return NXUS_SCAN_ERR_PARAM;

    NxusScanPattern derived;
    const NxusScanPattern *pattern = pattern_in;
    if (pattern == NULL) {
        derived = patternFromRequest(req);
        pattern = &derived;
    }

    NxusScanRequest effective_req = *req;
    if (effective_req.cmp_mode == NxusCmp_FuzzyEqual && effective_req.target2 == 0) {
        effective_req.target2 = fuzzyEpsilonBits(pattern->value_type, effective_req.value_size,
                                                 pattern->epsilon_decimals);
    }
    req = &effective_req;

    const u32 plain_type = pattern->value_type;
    const int patterned = isPatternType(plain_type);
    const int all_types = (plain_type == NxusValueType_All);

    /* Same guard as the first pass: a pattern_len that no longer matches the
       sent bytes (a rounded length) makes matchPatternAt() read the wildcard
       mask from pattern + pattern_len, i.e. from the wrong bytes. */
    if (patterned && !patternLengthValid(pattern)) return NXUS_SCAN_ERR_PARAM;

    /* How many bytes a single hit needs, and the target bytes for plain types. */
    u32 hit_window;
    if (patterned)      hit_window = patternWindow(pattern);
    else if (all_types) hit_window = 8;
    else                hit_window = nxusValueTypeSize(plain_type);
    if (hit_window == 0 || hit_window > NXUS_SCAN_MAX_PATTERN * 2) return NXUS_SCAN_ERR_PARAM;
    if (window_max < hit_window) return NXUS_SCAN_ERR_PARAM;
    /* The stored (previous) value must be at least as wide as what we compare,
       otherwise reading it would run past the end of the value array.  Pattern
       scans compare an 8-byte hash, so their window is unrelated to the slot. */
    if (!patterned && hit_window > stored) return NXUS_SCAN_ERR_PARAM;

    /* S2: plain unsigned integer hits whose stored slot is exactly 4 or 8 bytes
       wide and whose mode needs no target2 / float / signed semantics can be
       verified with a single constant-width compare instead of walking
       nxusCompareBytes for every hit. */
    u32 fast_compare_width = 0;
    if (!patterned && !all_types && hit_window == stored &&
        (hit_window == 4 || hit_window == 8) &&
        plain_type != NxusValueType_F32 && plain_type != NxusValueType_F64 &&
        !(req->flags & (NXUS_SCAN_F_FLOAT | NXUS_SCAN_F_SIGNED))) {
        switch (req->cmp_mode) {
            case NxusCmp_Equal:
            case NxusCmp_NotEqual:
            case NxusCmp_Increased:
            case NxusCmp_Decreased:
            case NxusCmp_Changed:
            case NxusCmp_Unchanged:
                fast_compare_width = hit_window;
                break;
            default:
                break;
        }
    }

    u8 target[8];
    memset(target, 0, sizeof(target));
    {
        u32 target_size = nxusValueTypeSize(plain_type);
        if (target_size == 0) target_size = req->value_size ? req->value_size : 8;
        nxusStoreLE(target, req->target, target_size);
    }

    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
        stats->regions_total = hits->count;
    }

    const u32 initial_count = hits->count;
    u32 keep = 0;
    u32 dropped = 0;
    u32 i = 0;

    while (i < hits->count) {
        if (cancel != NULL && *cancel) {
            /* Commit the refined prefix and keep the not-yet-refined tail so the
               caller's hit list is never silently truncated.  Tail entries keep
               their previous (now possibly stale) values; the next refine pass
               re-verifies them.  keep <= i, so the in-place move is safe. */
            const u32 tail = hits->count - i;
            if (tail > 0) {
                memmove(hits->addresses + keep, hits->addresses + i,
                        (size_t)tail * sizeof(NxusHitAddress));
                memmove(hits->values + (size_t)keep * stored,
                        hits->values + (size_t)i * stored,
                        (size_t)tail * stored);
            }
            hits->count = keep + tail;
            hits->prev_count = 0;
            if (stats != NULL) { stats->permille = 1000; stats->dropped += dropped; }
            return NXUS_SCAN_ERR_CANCELLED;
        }

        u16 map_idx = hits->addresses[i].mapping_idx;

        if (map_idx >= maps->count || !maps->entries[map_idx].valid) {
            while (i < hits->count && hits->addresses[i].mapping_idx == map_idx) {
                dropped++;
                i++;
            }
            continue;
        }

        const u64 map_base = maps->entries[map_idx].base;
        const u64 map_size = maps->entries[map_idx].size;

        /* ---- build a greedy read window over this mapping ---- */
        const u32 batch_start = i;
        u32 win_start = hits->addresses[i].offset;
        u32 win_end   = win_start + hit_window;
        i++;

        while (i < hits->count && hits->addresses[i].mapping_idx == map_idx) {
            u32 next_off = hits->addresses[i].offset;
            u32 next_end = next_off + hit_window;

            if (next_off < win_end) {
                /* Overlapping/duplicate addresses: extend the window - but never
                   past one read's worth.  A dense run (byte patterns run at step
                   1, so consecutive hits always overlap) must be SPLIT across
                   several windows; growing past window_max would make the whole
                   batch unreadable and silently drop every hit in it. */
                if (next_end > win_end) {
                    if ((u64)(next_end - win_start) > (u64)window_max) break;
                    win_end = next_end;
                }
                i++;
                continue;
            }
            if ((u64)(next_end - win_start) <= (u64)window_max &&
                (next_off - win_end) <= gap_threshold) {
                win_end = next_end;
                i++;
            } else {
                break;
            }
        }

        const u32 batch_end = i;
        if ((u64)win_end > map_size) win_end = (u32)map_size;
        if (win_end <= win_start) {
            dropped += (batch_end - batch_start);
            continue;
        }

        u32 win_size = win_end - win_start;
        if (win_size > window_max) {
            dropped += (batch_end - batch_start);
            continue;
        }

        /* Read the window; if the size is refused, keep halving down to 4 KB (or
           the hit width, when that is wider) before giving up.  One halving is
           not enough for a reader whose limit sits far below the window (a 1 MB
           window against a 4 KB limit needs several steps); only the bytes
           actually read may be judged, because falling through with the full
           win_size would compare the unread upper half against stale memory. */
        const u32 read_floor = (hit_window > 4096u) ? hit_window : 4096u;
        int read_ok = (read(read_ctx, map_base + win_start, window, win_size) == 0);
        u32 read_size = win_size;
        while (!read_ok && read_size > read_floor) {
            u32 next_size = read_size / 2;
            if (next_size < read_floor) next_size = read_floor;
            read_size = next_size;
            read_ok = (read(read_ctx, map_base + win_start, window, read_size) == 0);
            if (stats != NULL) stats->retries++;
        }

        if (!read_ok) {
            /* A transient read failure must not look like "no longer matches":
               keep the batch (its stored values stay from the previous pass, so
               the next pass re-verifies it) and count the failure. */
            for (u32 j = batch_start; j < batch_end; j++) {
                if (keep != j) {
                    NxusHitAddress j_addr = hits->addresses[j];
                    u8 j_val[8];
                    memcpy(j_val, hits->values + (size_t)j * stored, stored);
                    hits->addresses[j] = hits->addresses[keep];
                    memcpy(hits->values + (size_t)j * stored,
                           hits->values + (size_t)keep * stored, stored);
                    hits->addresses[keep] = j_addr;
                    memcpy(hits->values + (size_t)keep * stored, j_val, stored);
                }
                keep++;
            }
            if (stats != NULL) {
                stats->regions_done = keep;
                stats->dropped_reads++;
            }
            continue;
        }

        if (stats != NULL) {
            stats->reads++;
            stats->bytes_read += read_size;
        }

        for (u32 j = batch_start; j < batch_end; j++) {
            const u32 hit_type = hits->addresses[j].reserved;
            const u32 vtype = (all_types || patterned) ? hit_type : plain_type;
            /* vtype is used as-is: NxusValueType_U8 is 0, so a "vtype ? vtype :
               plain_type" fallback silently promoted every U8 hit of an All scan
               to the plain type and dropped it in refine. */
            u32 vlen = patterned ? hit_window : nxusValueTypeSize(vtype);
            if (vlen == 0) vlen = hit_window;

            /* The batch window starts at the first offset of the group.  A hit
               below it (only possible with an out-of-order / corrupt list) would
               make the subtraction wrap to 0xFFFFFFxx and read window[-1]: never
               compare it against bytes outside the window. */
            const u32 offset = hits->addresses[j].offset;
            if (offset < win_start) continue;
            const u32 rel = offset - win_start;
            if (rel > read_size || vlen > read_size - rel) {
                /* outside what we could read (short window): keep it for the
                   next pass rather than judging it from missing bytes */
                if (keep != j) {
                    NxusHitAddress j_addr = hits->addresses[j];
                    u8 j_val[8];
                    memcpy(j_val, hits->values + (size_t)j * stored, stored);
                    hits->addresses[j] = hits->addresses[keep];
                    memcpy(hits->values + (size_t)j * stored,
                           hits->values + (size_t)keep * stored, stored);
                    hits->addresses[keep] = j_addr;
                    memcpy(hits->values + (size_t)keep * stored, j_val, stored);
                }
                keep++;
                continue;
            }

            const u8 *cur  = window + rel;
            u8       *prev = hits->values + (size_t)j * stored;

            int match = 0;
            u8 fresh[8];
            memset(fresh, 0, sizeof(fresh));

            if (patterned) {
                const u64 hash = nxusHashBytes(cur, vlen);
                switch (req->cmp_mode) {
                    case NxusCmp_Equal:     match = matchPatternAt(cur, pattern); break;
                    case NxusCmp_NotEqual:  match = !matchPatternAt(cur, pattern); break;
                    case NxusCmp_Changed:   match = (hash != nxusLoadLE(prev, 8)); break;
                    case NxusCmp_Unchanged: match = (hash == nxusLoadLE(prev, 8)); break;
                    default:                match = 0; break;
                }
                nxusStoreLE(fresh, hash, 8);
            } else if (fast_compare_width == 4) {
                match = compareU32Fast(cur, prev, target, req->cmp_mode);
                memcpy(fresh, cur, 4);
            } else if (fast_compare_width == 8) {
                match = compareU64Fast(cur, prev, target, req->cmp_mode);
                memcpy(fresh, cur, 8);
            } else {
                u32 flags = req->flags;
                if (vtype == NxusValueType_F32 || vtype == NxusValueType_F64) flags |= NXUS_SCAN_F_FLOAT;
                else flags &= ~NXUS_SCAN_F_FLOAT;
                match = nxusCompareBytes(cur, prev, target, vlen, req->cmp_mode, req->target2, flags);
                memcpy(fresh, cur, vlen < 8 ? vlen : 8);
            }

            if (match) {
                if (keep != j) {
                    NxusHitAddress j_addr = hits->addresses[j];
                    hits->addresses[j] = hits->addresses[keep];
                    memcpy(hits->values + (size_t)j * stored,
                           hits->values + (size_t)keep * stored, stored);
                    hits->addresses[keep] = j_addr;
                    memcpy(hits->values + (size_t)keep * stored, fresh, stored);
                } else {
                    /* already in place: just refresh the stored value */
                    memcpy(prev, fresh, stored);
                }
                keep++;
            } else {
                dropped++;
            }
        }

        if (stats != NULL) {
            stats->regions_done = keep;
            stats->permille = 1000;
        }
    }

    hits->prev_count = initial_count;
    hits->count = keep;
    if (stats != NULL) {
        stats->permille = 1000;
        stats->dropped += dropped;
    }
    return NXUS_SCAN_OK;
}

int nxusScanNext(NxusHitList *hits, const NxusScanRequest *req,
                 const NxusMappingTable *maps,
                 NxusReadFn read, void *read_ctx,
                 u8 *window, u32 window_max, u32 gap_threshold,
                 NxusScanStats *stats, int *cancel) {
    return nxusScanNextEx(hits, req, NULL, maps, read, read_ctx, window, window_max,
                          gap_threshold, stats, cancel);
}

/* ------------------------------------------------------------------ */
/* dense baseline                                                      */
/* ------------------------------------------------------------------ */

/* A 16 KB grid already gives an O(1) skip for 4 GB of address space in 256k
   entries; the budget (block_cap) decides how much coarser it has to get. */
#define NXUS_BASELINE_BLOCK_MAX (1u << 24)
#define NXUS_BASELINE_READ_FLOOR 4096u

/* FNV-1a over the block plus the OR of every byte, in one pass: the bytes are
   folded in address order (so the result matches nxusHashBytes() exactly) while
   a 64-bit load per eight bytes feeds or_acc.  or_acc == 0 means every byte is
   zero, which is what lets the first pass skip the store entirely. */
static void blockFingerprint(const u8 *buf, u32 len, u64 *out_hash, int *out_zero) {
    u64 hash = 0xCBF29CE484222325ull;
    u64 or_acc = 0;
    u32 i = 0;

    for (; i + 8u <= len; i += 8u) {
        u64 word;
        memcpy(&word, buf + i, sizeof(word));
        or_acc |= word;
        for (u32 k = 0; k < 8u; k++) {
            hash ^= (u64)buf[i + k];
            hash *= 0x100000001B3ull;
        }
    }
    for (; i < len; i++) {
        or_acc |= (u64)buf[i];
        hash ^= (u64)buf[i];
        hash *= 0x100000001B3ull;
    }

    if (out_hash != NULL) *out_hash = hash;
    if (out_zero != NULL) *out_zero = (or_acc == 0) ? 1 : 0;
}

/* Candidates of one block: the first one sits at 'align_skip' (the offset that
   makes the address an absolute multiple of the width) and every following one
   'step' bytes later, as long as the whole value stays inside the block.  Both
   passes derive the candidate positions from this one function, so the count the
   first pass reports is exactly what the refine pass can produce. */
static u32 blockCandidates(u32 align_skip, u32 step, u32 blk_len, u32 window) {
    if (step == 0 || blk_len < window) return 0;
    if (align_skip + window > blk_len) return 0;
    return (blk_len - window - align_skip) / step + 1u;
}

/*
 * Read [address, address+len) into dst.  dmnt may refuse a large request (the
 * accepted size is not documented), so a refused read is retried with half the
 * size - but never below the 4 KB floor - and the accepted pieces are
 * concatenated.  Returns how many bytes could be read: a short result means the
 * tail is genuinely unreadable and the caller must not judge it.
 */
static u32 readWithSplit(NxusReadFn read, void *read_ctx, u64 address, u8 *dst, u32 len,
                         NxusScanStats *stats) {
    u32 got = 0;

    while (got < len) {
        const u32 want = len - got;
        if (read(read_ctx, address + got, dst + got, want) == 0) {
            got += want;
            continue;
        }

        u32 retry = want / 2u;
        int ok = 0;
        for (;;) {
            if (retry < NXUS_BASELINE_READ_FLOOR) retry = NXUS_BASELINE_READ_FLOOR;
            if (retry > want) break;              /* the floor does not even fit */
            if (stats != NULL) stats->retries++;
            if (read(read_ctx, address + got, dst + got, retry) == 0) { ok = 1; break; }
            if (retry <= NXUS_BASELINE_READ_FLOOR) break;
            retry /= 2u;
        }
        if (!ok) break;
        got += retry;
    }
    return got;
}

/* The baseline only deals in fixed-width numeric values: with step < window a
   value can straddle a block boundary and a block-grid enumeration would miss it,
   so patterns / "All" keep using nxusScanFirstEx(). */
static u32 baselineValueType(u32 value_type, u32 value_size, u32 flags) {
    if (value_type == NxusValueType_All || value_type == NxusValueType_String ||
        value_type == NxusValueType_Bytes || value_type == NxusValueType_Binary) {
        return NxusValueType_All;                  /* rejected by the caller */
    }
    if (nxusValueTypeSize(value_type) == value_size) return value_type;

    /* legacy callers pass value_type == 0 (U8) whatever the width; derive it */
    if (flags & NXUS_SCAN_F_FLOAT) {
        return (value_size == 8) ? NxusValueType_F64 : NxusValueType_F32;
    }
    switch (value_size) {
        case 1: return NxusValueType_U8;
        case 2: return NxusValueType_U16;
        case 8: return NxusValueType_U64;
        default: return NxusValueType_U32;
    }
}

int nxusBaselineInit(NxusBaseline *bl, u32 region_cap, u32 block_cap, u32 value_size, u32 value_type) {
    if (bl == NULL || region_cap == 0 || block_cap == 0 || value_size == 0 || value_size > 8) {
        return NXUS_SCAN_ERR_PARAM;
    }
    memset(bl, 0, sizeof(*bl));
    bl->regions = (NxusBaselineRegion *)calloc(region_cap, sizeof(NxusBaselineRegion));
    bl->blocks  = (NxusBaselineBlock *)calloc(block_cap, sizeof(NxusBaselineBlock));
    if (bl->regions == NULL || bl->blocks == NULL) {
        nxusBaselineFree(bl);
        return NXUS_SCAN_ERR_PARAM;
    }
    bl->region_cap = region_cap;
    bl->block_cap  = block_cap;
    bl->value_size = value_size;
    bl->value_type = value_type;
    return NXUS_SCAN_OK;
}

void nxusBaselineReset(NxusBaseline *bl) {
    if (bl == NULL) return;
    bl->region_count    = 0;
    bl->block_count     = 0;
    bl->stored_bytes    = 0;
    bl->candidate_count = 0;
    bl->block_size      = 0;
    bl->active          = 0;
}

void nxusBaselineFree(NxusBaseline *bl) {
    if (bl == NULL) return;
    free(bl->regions);
    free(bl->blocks);
    memset(bl, 0, sizeof(*bl));
}

int nxusScanFirstBaseline(NxusBaseline *bl,
                          const NxusScanRegion *regions, u32 region_count,
                          const NxusScanRequest *req,
                          NxusReadFn read, void *read_ctx,
                          const NxusBaselineIo *io, void *io_ctx,
                          u8 *chunk, u32 chunk_size,
                          NxusScanStats *stats, int *cancel) {
    if (bl == NULL || regions == NULL || req == NULL || read == NULL || io == NULL ||
        bl->regions == NULL || bl->blocks == NULL) {
        return NXUS_SCAN_ERR_PARAM;
    }

    const u32 window = bl->value_size;
    if (window == 0 || window > 8) return NXUS_SCAN_ERR_PARAM;


    const u32 value_type = baselineValueType(bl->value_type, window, req->flags);
    if (value_type == NxusValueType_All) return NXUS_SCAN_ERR_PARAM;

    bl->value_type      = value_type;
    bl->region_count    = 0;
    bl->block_count     = 0;
    bl->stored_bytes    = 0;
    bl->candidate_count = 0;
    bl->active          = 0;

    const u32 step = window;       /* numeric candidates sit on absolute multiples */

    /* store_off and every hit offset are u32.  A range whose total size does not
       fit 32 bits could never be stored/represented and used to wrap silently
       (two 2 GiB regions summed to 0, so the block grid covered nothing). */
    u64 total_bytes = 0;
    for (u32 r = 0; r < region_count; r++) {
        if (regions[r].size > 0xFFFFFFFFull - total_bytes) return NXUS_SCAN_ERR_PARAM;
        total_bytes += regions[r].size;
    }

    /* Smallest grid whose block count still fits the caller's budget. */
    u32 block_size = NXUS_BASELINE_BLOCK_MIN;
    while (block_size < NXUS_BASELINE_BLOCK_MAX &&
           ((total_bytes + block_size - 1u) / block_size) + (u64)region_count > (u64)bl->block_cap) {
        block_size <<= 1;
    }
    bl->block_size = block_size;

    /* A block is hashed in one piece, so the caller's chunk has to hold one. */
    u8 *blk_buf = chunk;
    int own_buf = 0;
    if (blk_buf == NULL || chunk_size < block_size) {
        blk_buf = (u8 *)malloc(block_size);
        if (blk_buf == NULL) return NXUS_SCAN_ERR_PARAM;
        own_buf = 1;
    }

    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
        stats->regions_total = region_count;
    }

    const u32 work_regions = (region_count > bl->region_cap) ? bl->region_cap : region_count;
    u64 scanned = 0;
    int rc = NXUS_SCAN_OK;

    for (u32 r = 0; r < work_regions && rc == NXUS_SCAN_OK; r++) {
        const NxusScanRegion *reg = &regions[r];
        if (reg->size == 0) continue;

        if (cancel != NULL && *cancel) { rc = NXUS_SCAN_ERR_CANCELLED; break; }

        NxusBaselineRegion *br = &bl->regions[bl->region_count];
        br->base        = reg->base;
        br->addr_base   = reg->addr_base ? reg->addr_base : reg->base;
        br->size        = reg->size;
        br->mapping_idx = reg->mapping_idx;
        br->block_first = bl->block_count;
        br->block_count = 0;
        /* First absolute multiple of the width at or after the region start. */
        br->align_skip  = (u32)((step - (reg->base % step)) % step);
        bl->region_count++;

        u64 done = 0;
        while (done < reg->size) {
            if (cancel != NULL && *cancel) { rc = NXUS_SCAN_ERR_CANCELLED; break; }
            if (bl->block_count >= bl->block_cap) {
                /* out of metadata: the rest of the range stays unrepresented
                   (the call is still usable, the count reports the loss) */
                if (stats != NULL) stats->dropped++;
                break;
            }

            const u64 remaining = reg->size - done;
            const u32 blk_len = (remaining > (u64)block_size) ? block_size : (u32)remaining;
            const u64 addr = reg->base + done;

            NxusBaselineBlock *b = &bl->blocks[bl->block_count];
            const u32 got = readWithSplit(read, read_ctx, addr, blk_buf, blk_len, stats);

            if (got < blk_len) {
                /* genuinely unreadable: keep the slot (the refine pass then knows
                   this range has no baseline) and never abort the whole scan */
                b->hash      = 0;
                b->store_off = 0;
                b->flags     = NXUS_BBLOCK_UNREADABLE;
                bl->block_count++;
                br->block_count++;
                if (stats != NULL) stats->dropped++;
                scanned += blk_len;
                done += blk_len;
                continue;
            }

            if (stats != NULL) {
                stats->reads++;
                stats->bytes_read += blk_len;
            }

            u64 hash = 0;
            int zero = 0;
            blockFingerprint(blk_buf, blk_len, &hash, &zero);

            b->hash      = hash;
            b->store_off = 0;
            b->flags     = NXUS_BBLOCK_VALID;

            if (zero) {
                /* All-zero blocks are their own previous value: no store write,
                   no SD space, and the refine pass still knows the baseline. */
                b->flags |= NXUS_BBLOCK_ZERO;
            } else if (io->write == NULL ||
                       (u64)blk_len > 0xFFFFFFFFull - bl->stored_bytes) {
                /* Check the bound BEFORE adding: stored_bytes is the u32 store
                   offset, so the new block must end at or below 2^32 - 1. */
                b->flags = NXUS_BBLOCK_UNREADABLE;
                if (stats != NULL) stats->dropped++;
            } else if (io->write(io_ctx, bl->stored_bytes, blk_buf, blk_len) != 0) {
                b->flags = NXUS_BBLOCK_UNREADABLE;
                if (stats != NULL) stats->dropped++;
            } else {
                b->store_off = (u32)bl->stored_bytes;
                bl->stored_bytes += blk_len;
            }

            /* Only a block that can be read back contributes candidates: an
               unreadable one can never produce a hit in the refine pass. */
            if (b->flags & NXUS_BBLOCK_VALID) {
                bl->candidate_count += blockCandidates(br->align_skip, step, blk_len, window);
            }

            bl->block_count++;
            br->block_count++;
            scanned += blk_len;
            done += blk_len;
        }

        if (stats != NULL) {
            stats->regions_done = r + 1;
            stats->permille = total_bytes ? (u32)((scanned * 1000ull) / total_bytes) : 1000u;
        }
    }

    if (own_buf) free(blk_buf);

    if (stats != NULL) {
        stats->dropped += region_count - work_regions;
        stats->bytes_scanned = scanned;
        stats->permille = total_bytes ? (u32)((scanned * 1000ull) / total_bytes) : 1000u;
    }

    if (rc != NXUS_SCAN_OK) {
        bl->active = 0;
        return rc;
    }

    bl->active = 1;
    return NXUS_SCAN_OK;
}

int nxusScanNextFromBaseline(NxusBaseline *bl,
                             NxusHitList *hits,
                             const NxusScanRequest *req,
                             const NxusMappingTable *maps,
                             NxusReadFn read, void *read_ctx,
                             const NxusBaselineIo *io, void *io_ctx,
                             u8 *cur_buf, u32 cur_buf_size,
                             u8 *prev_buf, u32 prev_buf_size,
                             NxusScanStats *stats, int *cancel) {
    if (bl == NULL || hits == NULL || req == NULL || maps == NULL || read == NULL ||
        io == NULL || cur_buf == NULL || prev_buf == NULL) {
        return NXUS_SCAN_ERR_PARAM;
    }
    if (!bl->active) return NXUS_SCAN_ERR_PARAM;   /* no baseline / already consumed */

    const u32 block_size = bl->block_size;
    const u32 window     = bl->value_size;
    if (block_size == 0 || window == 0 || window > 8) return NXUS_SCAN_ERR_PARAM;
    if (cur_buf_size < block_size || prev_buf_size < block_size) return NXUS_SCAN_ERR_PARAM;
    if (hits->value_size < window || hits->value_size > 8) return NXUS_SCAN_ERR_PARAM;

    u32 value_type = baselineValueType(bl->value_type, window, req->flags);
    if (value_type == NxusValueType_All) return NXUS_SCAN_ERR_PARAM;

    const u32 step = window;

    /* Same epsilon derivation as the other passes (GUI/CLI send target2 == 0). */
    NxusScanRequest effective = *req;
    if (effective.cmp_mode == NxusCmp_FuzzyEqual && effective.target2 == 0) {
        effective.target2 = fuzzyEpsilonBits(value_type, window, 0);
    }
    req = &effective;

    u8 target[8];
    memset(target, 0, sizeof(target));
    nxusStoreLE(target, req->target, window);

    const u32 cmp_mode = req->cmp_mode;
    const int change_mode = (cmp_mode == NxusCmp_Changed || cmp_mode == NxusCmp_Increased ||
                             cmp_mode == NxusCmp_Decreased || cmp_mode == NxusCmp_Different);
    const int needs_prev = change_mode || (cmp_mode == NxusCmp_Unchanged);

    /* Same single-width fast path as the classic refine pass. */
    u32 fast_width = 0;
    if (!(req->flags & (NXUS_SCAN_F_FLOAT | NXUS_SCAN_F_SIGNED)) &&
        (window == 4 || window == 8) && hits->value_size == window &&
        value_type != NxusValueType_F32 && value_type != NxusValueType_F64) {
        switch (cmp_mode) {
            case NxusCmp_Equal:
            case NxusCmp_NotEqual:
            case NxusCmp_Increased:
            case NxusCmp_Decreased:
            case NxusCmp_Changed:
            case NxusCmp_Unchanged:
                fast_width = window;
                break;
            default:
                break;
        }
    }

    u64 total_bytes = 0;
    for (u32 r = 0; r < bl->region_count; r++) total_bytes += bl->regions[r].size;

    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
        stats->regions_total = bl->block_count;
    }

    const u32 initial_count = hits->count;
    u64 scanned = 0;
    u32 done_blocks = 0;
    u32 dropped = 0;
    int rc = NXUS_SCAN_OK;
    int truncated = 0;   /* hit list filled up before the pass ended */
    int stop = 0;

    for (u32 r = 0; r < bl->region_count && !stop && rc == NXUS_SCAN_OK; r++) {
        const NxusBaselineRegion *br = &bl->regions[r];

        /* A mapping that vanished (or was never valid) has no current bytes: its
           blocks are dropped, exactly like a refine pass drops such hits. */
        if (br->mapping_idx >= maps->count || !maps->entries[br->mapping_idx].valid) {
            dropped += br->block_count;
            done_blocks += br->block_count;
            continue;
        }

        for (u32 bi = 0; bi < br->block_count; bi++) {
            if (cancel != NULL && *cancel) { rc = NXUS_SCAN_ERR_CANCELLED; break; }

            NxusBaselineBlock *b = &bl->blocks[br->block_first + bi];
            const u64 block_addr = br->base + (u64)bi * block_size;
            const u64 remain = br->size - (u64)bi * block_size;
            const u32 blk_len = (remain > (u64)block_size) ? block_size : (u32)remain;

            done_blocks++;
            const u32 got = readWithSplit(read, read_ctx, block_addr, cur_buf, blk_len, stats);
            if (got < blk_len) {
                /* keep nothing from a block we could not read: a bogus compare
                   would report changes that are not there */
                dropped++;
                if (stats != NULL) stats->dropped_reads++;
                scanned += blk_len;
                continue;
            }
            if (stats != NULL) {
                stats->reads++;
                stats->bytes_read += blk_len;
            }

            u64 cur_hash = 0;
            int cur_zero = 0;
            blockFingerprint(cur_buf, blk_len, &cur_hash, &cur_zero);

            const int known = (b->flags & NXUS_BBLOCK_VALID) != 0;
            int same_block = 0;
            if (known) {
                if (cur_zero && (b->flags & NXUS_BBLOCK_ZERO)) {
                    same_block = 1;
                } else if (cur_hash == b->hash) {
                    same_block = 1;
                }
            }

            /* O(1) block skip: for a change-only mode an unchanged block cannot
               contain a hit, so neither the store nor a single value is touched. */
            if (change_mode && known && same_block) {
                scanned += blk_len;
                continue;
            }
            if (change_mode && !known) {
                /* nothing was captured for this block (it was unreadable, or the
                   store ran out): a change cannot be proven, so nothing is kept */
                dropped++;
                if (stats != NULL) stats->dropped_reads++;
                scanned += blk_len;
                continue;
            }

            /* "Unchanged" on an unchanged block matches every candidate: a block
               level decision instead of one compare per value. */
            const int materialize_all =
                (!change_mode && same_block && cmp_mode == NxusCmp_Unchanged);

            /* Previous values are read lazily, and only for the blocks that need
               them: a change-only pass touches the store once per changed block,
               never per candidate. */
            const u8 *prev = NULL;
            if (!materialize_all) {
                if (needs_prev) {
                    if (known && (b->flags & NXUS_BBLOCK_ZERO)) {
                        memset(prev_buf, 0, blk_len);
                        prev = prev_buf;
                    } else if (known && io->read != NULL &&
                               io->read(io_ctx, b->store_off, prev_buf, blk_len) == 0) {
                        if (stats != NULL) {
                            stats->reads++;
                            stats->bytes_read += blk_len;
                        }
                        prev = prev_buf;
                    } else {
                        dropped++;
                        if (stats != NULL) stats->dropped_reads++;
                        scanned += blk_len;
                        continue;
                    }
                } else if (fast_width != 0) {
                    /* Equal / NotEqual ignore the previous value, but the fast
                       compares still load it: hand them a defined buffer. */
                    memset(prev_buf, 0, blk_len);
                    prev = prev_buf;
                }
            }

            const u64 base_off = block_addr - br->addr_base;
            u32 s = br->align_skip;
            for (; s + window <= blk_len; s += step) {
                const u8 *cur = cur_buf + s;
                int match;

                if (materialize_all) {
                    match = 1;
                } else if (fast_width == 4) {
                    match = compareU32Fast(cur, prev + s, target, cmp_mode);
                } else if (fast_width == 8) {
                    match = compareU64Fast(cur, prev + s, target, cmp_mode);
                } else {
                    u32 flags = req->flags;
                    if (value_type == NxusValueType_F32 || value_type == NxusValueType_F64) {
                        flags |= NXUS_SCAN_F_FLOAT;
                    } else {
                        flags &= ~NXUS_SCAN_F_FLOAT;
                    }
                    match = nxusCompareBytes(cur, prev, target, window, cmp_mode,
                                             req->target2, flags);
                }
                if (!match) continue;

                /* A full hit list is a limit, not a failure: keep what fits and
                   report success.  Whether the list was truncated is reported out
                   of band (hit count == capacity), see sendHits(). */
                if (hits->count >= hits->max_capacity) { stop = 1; truncated = 1; break; }

                const u64 off = base_off + s;
                if (off > 0xFFFFFFFFull) continue;   /* u32 offset limit */

                u8 stored[8];
                memset(stored, 0, sizeof(stored));
                memcpy(stored, cur, window);
                if (hitListPush(hits, br->mapping_idx, (u32)off, stored, value_type) != NXUS_SCAN_OK) {
                    stop = 1;
                    /* push only fails on FULL (OOM reports NXUS_SCAN_ERR_NOMEM). */
                    if (hits->count >= hits->max_capacity) truncated = 1;
                    break;
                }
            }

            scanned += blk_len;
            if (stop) break;
        }
    }

    if (stats != NULL) {
        stats->regions_done = done_blocks;
        stats->bytes_scanned = scanned;
        stats->dropped += dropped;
        stats->permille = total_bytes ? (u32)((scanned * 1000ull) / total_bytes) : 1000u;
    }

    bl->active = 0;
    hits->prev_count = initial_count;
    /* The pass may end on the hit-list capacity; the hits collected up to that
       point are valid, so this is still success.  sendHits() marks the batch when
       count == max_capacity so a client can tell "complete" from "cut off". */
    (void)truncated;
    return rc;
}
