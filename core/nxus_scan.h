/*
 * Nxus scan engine (portable core).
 *
 * Deliberately free of libnx / Switch dependencies so the exact same code that
 * runs in the sysmodule can be compiled and unit-tested on the host
 * (see tests/test_scan.c).  All target access goes through a read callback.
 */
#pragma once

#include "nxus_protocol.h"

#define NXUS_SCAN_OK              0
#define NXUS_SCAN_ERR_CANCELLED  (-1)
#define NXUS_SCAN_ERR_FULL       (-2)
#define NXUS_SCAN_ERR_READ       (-3)
#define NXUS_SCAN_ERR_PARAM      (-4)

/* A region of the target process that should be scanned. */
typedef struct {
    u64 base;        /* first byte to READ (may be clipped to a range)     */
    u64 size;
    u32 perm;
    u32 mapping_idx;
    u64 addr_base;   /* mapping base used for hit offsets; 0 means "use base".
                        base and addr_base differ when a scope clips a mapping
                        (custom range / main), and the PC resolves hits as
                        mapping_base + offset, so the offset must be measured
                        from the mapping, never from the clipped start. */
} NxusScanRegion;

/* Snapshot of the target's mappings, taken when the session started. */
/* Mirrors libnx MemType_Heap / MemType_ThreadLocal (svc.h).  Kept as plain
   constants so core/ stays free of libnx headers and the host tests can
   exercise the scope rules. */
#define NXUS_MEMTYPE_HEAP 0x05u
#define NXUS_MEMTYPE_TLS  0x0Cu

typedef struct {
    u64 base;
    u64 size;
    u32 valid;       /* re-validated before a refine pass */
    u32 reserved;    /* NXUS_PERM_* bits */
    u32 type;        /* MemType; 0 = unknown, the scope then falls back to perms */
    u32 pad;
} NxusMappingEntry;

/* Build the region list for a scope from a mapping snapshot.  This is the same
   clipping the console applies; it lives in core/ so the host tests can pin it
   (a wrongly clipped region reports offsets the PC resolves to other addresses,
   which poisons every later refine pass).
   Returns the number of regions written (never more than capacity). */
u32 nxusBuildRegions(const NxusMappingEntry *maps, u32 map_count,
                     u64 main_base, u64 main_size,
                     u32 scope, u64 range_begin, u64 range_end,
                     NxusScanRegion *out, u32 capacity);

/* Same, but with a LIST of ranges (NxusScope_Ranges): a mapping that meets several
   entries yields one region per intersection.  range_count == 0 means "no range",
   which produces no regions (the caller reports a parameter error). */
/* Parse the optional range list that NXUS_SCAN_F_RANGES puts right after the fixed
   NxusScanRequest.  On success *out_offset is the offset of whatever follows (the
   NxusScanExt), and the number of entries is returned.  A negative value is an error:
   -1 malformed/short, -2 more entries than NXUS_MAX_SCAN_RANGES (rejected instead of
   silently truncating, which would desynchronise the following ext/pattern).
   This lives in core/ so the host tests can pin the arithmetic the console uses. */
int nxusParseRangeList(const u8 *payload, u32 length, u32 *out_offset,
                       NxusRangeEntry *out, u32 capacity);

u32 nxusBuildRegionsMulti(const NxusMappingEntry *maps, u32 map_count,
                          u64 main_base, u64 main_size,
                          const NxusRangeEntry *ranges, u32 range_count,
                          NxusScanRegion *out, u32 capacity);

typedef struct {
    NxusMappingEntry *entries;
    u32 count;
} NxusMappingTable;

typedef struct NXUS_PACKED {
    u32 offset;        /* offset from the mapping base */
    u16 mapping_idx;
    u16 reserved;
} NxusHitAddress;

typedef struct {
    NxusHitAddress *addresses;  /* capacity * 8 bytes (packed struct) */
    u8             *values;     /* capacity * value_size bytes (SoA) */
    u32             count;
    u32             prev_count; /* count before the last refine pass (for 1-step Undo) */
    u32             capacity;
    u32             max_capacity;
    u32             value_size;
    u32             mapping_count;
} NxusHitList;

/* Returns 0 on success, non-zero on failure (region is then skipped). */
typedef int (*NxusReadFn)(void *ctx, u64 address, void *buffer, u32 size);

typedef struct {
    u64 bytes_scanned;
    u64 reads;
    u64 bytes_read;
    u32 regions_done;
    u32 regions_total;
    u32 permille;
    u32 dropped;
    u32 retries;      /* reads that had to be retried smaller */
    u32 dropped_reads;/* refine windows that could not be read at all */
} NxusScanStats;

int  nxusHitListInit(NxusHitList *list, u32 capacity, u32 max_capacity, u32 value_size);
void nxusHitListFree(NxusHitList *list);
void nxusHitListReset(NxusHitList *list);
int  nxusHitListUndo(NxusHitList *list);

/* Resolve a hit to an absolute address. Returns 0 if the mapping is invalid. */
int  nxusHitResolve(const NxusHitList *list, const NxusMappingTable *maps, u32 index, u64 *out_address);

/* Kept for reference/testing: byte-level comparison used by both passes. */
int  nxusCompareBytes(const u8 *cur, const u8 *prev, const u8 *target, u32 size,
                      u32 cmp_mode, u64 target2, u32 flags);

void nxusStoreLE(u8 *dst, u64 value, u32 size);
u64  nxusLoadLE(const u8 *src, u32 size);

/* ------------------------------------------------------------------ */
/* value types / patterns (Cheat Engine style scanning)                */
/* ------------------------------------------------------------------ */

typedef struct {
    u32 value_type;        /* NxusValueType */
    u32 flags;             /* NXUS_SCAN_F_* */
    const u8 *pattern;     /* pattern_len bytes; NULL for plain numeric scans */
    u32 pattern_len;
    const u8 *mask;        /* 1 = compare this byte; NULL = compare all */
    u32 epsilon_decimals;  /* float compare: 0 = exact bit compare */
} NxusScanPattern;

/* Bytes needed to represent one value of this type (0 for pattern types). */
u32 nxusValueTypeSize(u32 value_type);

/* Bytes to keep per hit for the given request (8 for patterns: a hash). */
u32 nxusHitListValueSize(u32 value_type, u32 fallback_size);

/* FNV-1a - used to remember string / byte-array hits cheaply. */
u64 nxusHashBytes(const u8 *data, u32 len);

/*
 * Pattern-aware first/refine passes.  Passing a NULL pattern (or a numeric
 * value_type) behaves exactly like the classic numeric scan.
 */
int nxusScanFirstEx(const NxusScanRegion *regions, u32 region_count,
                    const NxusScanRequest *req, const NxusScanPattern *pattern,
                    NxusHitList *hits,
                    NxusReadFn read, void *read_ctx,
                    u8 *chunk, u32 chunk_size,
                    NxusScanStats *stats, int *cancel);

int nxusScanNextEx(NxusHitList *hits, const NxusScanRequest *req, const NxusScanPattern *pattern,
                   const NxusMappingTable *maps,
                   NxusReadFn read, void *read_ctx,
                   u8 *window, u32 window_max, u32 gap_threshold,
                   NxusScanStats *stats, int *cancel);

/*
 * First pass: walk the given regions in CHUNK_SIZE steps, keeping only hits.
 * Peak memory is O(chunk_size + hits), never the full dump.
 */
int nxusScanFirst(const NxusScanRegion *regions, u32 region_count,
                  const NxusScanRequest *req, NxusHitList *hits,
                  NxusReadFn read, void *read_ctx,
                  u8 *chunk, u32 chunk_size,
                  NxusScanStats *stats, int *cancel);

/*
 * Refine pass: re-read only the surviving addresses using sparse coalescing
 * (greedy read windows bounded by window_max / gap_threshold) and compact the
 * hit list IN PLACE so that no additional memory is required.
 *
 * The hit list must be ordered by (mapping_idx, offset); the first pass
 * guarantees this by construction.
 *
 * On cancellation the refined prefix is committed and the not-yet-refined tail
 * is preserved - the caller's hit list is never silently truncated.  Note that
 * the tail's stored values are from BEFORE the cancelled pass, so a later
 * Changed/Increased/Decreased compare on those entries spans two intervals; the
 * next completed pass refreshes them.
 */
int nxusScanNext(NxusHitList *hits, const NxusScanRequest *req,
                 const NxusMappingTable *maps,
                 NxusReadFn read, void *read_ctx,
                 u8 *window, u32 window_max, u32 gap_threshold,
                 NxusScanStats *stats, int *cancel);

/* ------------------------------------------------------------------ */
/* dense baseline                                                      */
/* ------------------------------------------------------------------ */

/*
 * An "unknown initial value" scan has to answer "which of the N candidates
 * changed?", but materialising N hits is both O(memory) and capped by the hit
 * list (150k hits is the practical wall).  The dense baseline replaces the hit
 * list with a per-block FINGERPRINT of the first pass:
 *
 *   - the scanned range is cut into 16 KB (or larger) blocks,
 *   - each block is described by a 64-bit FNV-1a hash plus an all-zero flag,
 *   - all-zero blocks are never written to the store at all (a freshly zeroed
 *     heap - the common case - costs nothing but one line of metadata),
 *   - non-zero blocks are written to the caller's store exactly once,
 *   - the first pass pushes ZERO hits; it only counts candidates.
 *
 * The refine pass then re-reads a block, hashes it, and for the change-only
 * compare modes (Changed / Increased / Decreased / Different) an unchanged block
 * is rejected in O(1) - no store read, no per-value compare.  Only blocks that
 * really changed have their previous values read back (lazily, per block) and
 * only their matching candidates are materialised into the hit list.
 *
 * The candidate geometry is fixed by value_size: numeric scans walk the
 * absolute multiples of the width, exactly like nxusScanFirstEx(), so the
 * candidate count and the addresses a hit would have are identical.
 * Pattern / "All" scans keep using nxusScanFirstEx(): their window is wider
 * than their stride, so a value can straddle a block boundary and a block-grid
 * candidate enumeration would miss it.
 */

#define NXUS_BASELINE_BLOCK_MIN     16384u
#define NXUS_BASELINE_MAX_BLOCKS    16384u   /* default block budget for nxusBaselineInit */

#define NXUS_BBLOCK_VALID           0x01u
#define NXUS_BBLOCK_ZERO            0x02u
#define NXUS_BBLOCK_UNREADABLE      0x04u

/* Where the previous values are kept (SD card, heap, ...).  The baseline never
   keeps the data itself, so a 4 GB scan does not need 4 GB of RAM. */
typedef struct {
    int (*write)(void *ctx, u64 offset, const void *buf, u32 len);
    int (*read)(void *ctx, u64 offset, void *buf, u32 len);
} NxusBaselineIo;

typedef struct {
    u64 hash;       /* FNV-1a of the whole block, 0 when never hashed       */
    u32 store_off;  /* offset in the store (only valid for non-zero blocks) */
    u32 flags;      /* NXUS_BBLOCK_*                                       */
} NxusBaselineBlock;

typedef struct {
    u64 base;       /* first byte read from the target                    */
    u64 addr_base;  /* mapping base used for the hit offsets              */
    u64 size;
    u32 mapping_idx;
    u32 block_first;/* first entry in NxusBaseline.blocks                 */
    u32 block_count;
    u32 align_skip; /* first candidate inside each block (0..value_size-1)*/
} NxusBaselineRegion;

typedef struct {
    NxusBaselineRegion *regions;
    u32 region_cap;
    u32 region_count;
    NxusBaselineBlock *blocks;
    u32 block_cap;
    u32 block_count;
    u64 stored_bytes;      /* how much of the store is used          */
    u64 candidate_count;   /* candidates covered by the first pass    */
    u32 block_size;        /* chosen by nxusScanFirstBaseline         */
    u32 value_size;
    u32 value_type;
    u32 active;            /* 1 until the baseline has been consumed */
} NxusBaseline;

/* Value type / size are fixed for the lifetime of the baseline: the caller
   initialises them once and every pass compares the same width. */
int  nxusBaselineInit(NxusBaseline *bl, u32 region_cap, u32 block_cap, u32 value_size, u32 value_type);
void nxusBaselineReset(NxusBaseline *bl);
void nxusBaselineFree(NxusBaseline *bl);

/*
 * First pass.  Reads every region through 'read' (a refused read is halved down
 * to 4 KB and the block is assembled from the accepted pieces), stores the
 * fingerprint of each block and pushes NO hits.  bl->candidate_count receives
 * the number of aligned candidates the range holds, so the GUI can show
 * "N candidates" instead of "N hits".
 *
 * 'chunk' is a scratch buffer of chunk_size bytes; when it is smaller than the
 * chosen block size the function allocates one temporary block itself.
 * A block that cannot be read is recorded as NXUS_BBLOCK_UNREADABLE (never
 * fatal: the rest of the range still gets scanned).
 */
int  nxusScanFirstBaseline(NxusBaseline *bl,
                           const NxusScanRegion *regions, u32 region_count,
                           const NxusScanRequest *req,
                           NxusReadFn read, void *read_ctx,
                           const NxusBaselineIo *io, void *io_ctx,
                           u8 *chunk, u32 chunk_size,
                           NxusScanStats *stats, int *cancel);

/*
 * Refine pass against the baseline.  cur_buf / prev_buf must each hold at least
 * bl->block_size bytes (cur_buf_size / prev_buf_size are checked).
 *
 * Only matches are pushed into 'hits', in ascending address order, so the
 * resulting list is directly usable by nxusScanNextEx().  If the hit list fills
 * up (hits->count >= hits->max_capacity) materialising stops, the hits found so
 * far stay valid and NXUS_SCAN_OK is returned - a small hit list is a limit,
 * never a failed scan.  bl->active is cleared on every exit path.
 */
int  nxusScanNextFromBaseline(NxusBaseline *bl,
                              NxusHitList *hits,
                              const NxusScanRequest *req,
                              const NxusMappingTable *maps,
                              NxusReadFn read, void *read_ctx,
                              const NxusBaselineIo *io, void *io_ctx,
                              u8 *cur_buf, u32 cur_buf_size,
                              u8 *prev_buf, u32 prev_buf_size,
                              NxusScanStats *stats, int *cancel);
