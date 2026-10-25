#include "nxus_session.h"
#include "nxus_debug.h"
#include "nxus_dmntcht.h"
#include "nxus_log.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    /* Scan state.  Atomic on purpose: the server thread stores Running while the
       worker stores Done/Error/Cancelled, and status pollers plus the server's
       BUSY gates read it without holding g_SessionMutex.  Every store is a
       release store and every load an acquire load (sessionStateStore /
       sessionStateLoad), so observing a settled state also means observing the
       results (hit list, regions, progress, last_result) it describes. */
    atomic_int state;          /* NxusScanState */
    u32 session_id;
    u32 progress;
    s32 last_result;
    u32 chunk_size;
    u32 max_hits;
    u32 window_size;
    u32 gap_threshold;

    NxusHitList hits;
    /* Unknown scans keep their first pass here instead of in the hit list: the
       dense block fingerprints make a multi-GB "initial value" scan possible
       without materialising every candidate.  active == 0 for every other mode,
       where 'hits' is the only state. */
    NxusBaseline baseline;
    NxusMappingEntry *map_entries;
    NxusMappingTable maps;
    NxusScanRegion *regions;
    u32 region_count;

    /* NxusScope_Ranges: the list the current request asked for.  Kept in the session
       so ScanNext (refine) works against the same regions as the first pass. */
    NxusRangeEntry ranges[NXUS_MAX_SCAN_RANGES];
    u32 range_count;

    /* Cancellation flag.  The engine reads it through a plain int pointer (the
       atomic is a plain int on both GCC targets), writers use atomics so the
       store cannot be optimised away and is visible across cores. */
    atomic_int cancel;

    Thread thread;
    bool thread_live;          /* a scan may still be running */
    bool job_first_pass;
    NxusScanRequest job_req;
    NxusScanPattern job_pattern;
    u8 job_pattern_bytes[NXUS_SCAN_MAX_PATTERN];
    u8 job_pattern_mask[NXUS_SCAN_MAX_PATTERN];

    bool paused;
    u64 last_heartbeat_ms;
    u32 watchdog_timeout_ms;

    u64 process_id, program_id, main_base, main_size;
} Session;

static Session g_Session;
static Mutex   g_SessionMutex;

static void cacheProcessInfo(void);
static Result snapshotMappings(void);
static void buildRegions(const NxusScanRequest *req);

static u64 nowMs(void) { return armTicksToNs(armGetSystemTick()) / 1000000ull; }

/* ---- state publication ------------------------------------------------- */

/*
 * g_Session.state is the session's publication barrier:
 *
 *   - the server thread prepares the job (job_req, pattern, regions, hit list)
 *     and only then stores Running with release,
 *   - the worker files its results (final progress, last_result) and only then
 *     stores Done/Error/Cancelled with release,
 *   - readers use acquire, so "state != Running" also means "the results are
 *     final and visible".
 *
 * Ordering matters beyond the worker itself: the server's BUSY gates decide from
 * this value whether the hit list / mapping / region arrays may be walked, so a
 * plain u32 store here would let those arrays be read while they are rebuilt.
 */
static NxusScanState sessionStateLoad(void) {
    return (NxusScanState)atomic_load_explicit(&g_Session.state, memory_order_acquire);
}

static void sessionStateStore(NxusScanState state) {
    atomic_store_explicit(&g_Session.state, (int)state, memory_order_release);
}

/* ---- published views --------------------------------------------------- */

/*
 * g_Session.maps.entries / maps.count and g_Session.regions / region_count are
 * read by other threads (nxusSessionMappings / nxusSessionRegions) with no lock
 * held, yet each pair is two plain fields: a reader could load the pointer from
 * one publication and the count from the next.  Publishing them through a
 * seqlock makes the pair observable as one unit:
 *
 *   g_ViewSeq is even while both pairs are stable, odd while an update is in
 *   flight.  A writer bumps it to odd (release), stores the pair, and bumps it
 *   back to even (release).  A reader samples it (acquire), rejects odd values,
 *   copies the pair, and samples again: an unchanged value means the pair it
 *   copied was one consistent publication; otherwise it retries.
 *
 * The old atomic_thread_fence()s were useless here: a fence only orders atomic
 * operations, so the plain pointer/count stores stayed free to be observed torn
 * apart.  The "clear before free" rule stays - the published pair is emptied
 * before free(), so a reader that loses the race anywhere still sees either the
 * old live block or an explicitly empty view, never a pointer into freed memory.
 *
 * Writers are all on the server thread (publish / drop / buildRegions), so the
 * two views can share a single counter without a lock of their own.
 */
#define NXUS_VIEW_RETRY 8u

static atomic_uint g_ViewSeq;

static void viewUpdateBegin(void) {
    atomic_fetch_add_explicit(&g_ViewSeq, 1u, memory_order_release);   /* odd */
}

static void viewUpdateEnd(void) {
    atomic_fetch_add_explicit(&g_ViewSeq, 1u, memory_order_release);   /* even */
}

static void mappingSnapshotDrop(void) {
    NxusMappingEntry *old = g_Session.map_entries;
    viewUpdateBegin();
    g_Session.maps.entries = NULL;
    g_Session.maps.count = 0;
    g_Session.map_entries = NULL;
    viewUpdateEnd();
    free(old);
}

static void mappingSnapshotPublish(NxusMappingEntry *entries, u32 count) {
    NxusMappingEntry *old = g_Session.map_entries;
    viewUpdateBegin();
    g_Session.map_entries = entries;
    g_Session.maps.entries = entries;
    g_Session.maps.count = count;
    viewUpdateEnd();
    free(old);
}

static void regionListDrop(void) {
    NxusScanRegion *old = g_Session.regions;
    viewUpdateBegin();
    g_Session.regions = NULL;
    g_Session.region_count = 0;
    viewUpdateEnd();
    free(old);
}

/* Publish a freshly built list (buildRegions) as one pair, never as a pointer
   without its count. */
static void regionListPublish(NxusScanRegion *regions, u32 count) {
    NxusScanRegion *old = g_Session.regions;
    viewUpdateBegin();
    g_Session.regions = regions;
    g_Session.region_count = count;
    viewUpdateEnd();
    free(old);
}

/* ---- baseline store (SD card, RAM fallback) ---------------------------- */

/*
 * The dense baseline never holds the scanned bytes in RAM; it only keeps a
 * per-block fingerprint and streams the non-zero blocks to this store.  Two
 * backends share one interface so the engine does not care which is in use:
 *
 *   - SD card: "sdmc:/nxus/scan_base.bin", opened "wb+" with one static 64 KB
 *     stdio buffer (no per-block malloc, writes coalesce into the card's
 *     cluster size),
 *   - RAM: a single malloc of the scoped byte count, used when the card cannot
 *     be opened (no SD inserted, read-only card, ...) or when the scoped range is
 *     small enough that writing a file would cost more than the memory
 *     (<= 512 KB).
 *
 * Offsets are absolute positions in the store; the engine hands each block the
 * offset it was assigned, so a plain fseek covers the sparse layout.
 */
#define NXUS_BASELINE_RAM_MAX   (512u * 1024u)
#define NXUS_BASELINE_FILE_BUF  (64u * 1024u)
/* Refine buffers: at least one whole block, and never below 64 KB so a future
   smaller block size still gets a decent read size. */
#define NXUS_BASELINE_BUF_MIN   (64u * 1024u)

static FILE *g_BaseFile = NULL;
static u8   *g_BaseRam = NULL;
static u64   g_BaseRamSize = 0;
static u8    g_BaseFileBuf[NXUS_BASELINE_FILE_BUF] __attribute__((aligned(0x10)));

static int baselineStoreWrite(void *ctx, u64 offset, const void *buf, u32 len) {
    (void)ctx;
    if (len == 0) return 0;
    if (g_BaseFile != NULL) {
        if (fseek(g_BaseFile, (long)offset, SEEK_SET) != 0) return -1;
        return fwrite(buf, 1, len, g_BaseFile) == len ? 0 : -1;
    }
    if (g_BaseRam == NULL || offset > g_BaseRamSize || (u64)len > g_BaseRamSize - offset) return -1;
    memcpy(g_BaseRam + offset, buf, len);
    return 0;
}

static int baselineStoreRead(void *ctx, u64 offset, void *buf, u32 len) {
    (void)ctx;
    if (len == 0) return 0;
    if (g_BaseFile != NULL) {
        if (fseek(g_BaseFile, (long)offset, SEEK_SET) != 0) return -1;
        return fread(buf, 1, len, g_BaseFile) == len ? 0 : -1;
    }
    if (g_BaseRam == NULL || offset > g_BaseRamSize || (u64)len > g_BaseRamSize - offset) return -1;
    memcpy(buf, g_BaseRam + offset, len);
    return 0;
}

static const NxusBaselineIo g_BaselineIo = {
    .write = baselineStoreWrite,
    .read  = baselineStoreRead,
};

static u64 baselineRegionBytes(void) {
    u64 total = 0;
    for (u32 i = 0; i < g_Session.region_count; i++) {
        if (g_Session.regions[i].size > 0xFFFFFFFFFFFFFFFFull - total) return 0xFFFFFFFFFFFFFFFFull;
        total += g_Session.regions[i].size;
    }
    return total;
}

static void baselineStoreClose(void) {
    if (g_BaseFile != NULL) {
        fclose(g_BaseFile);       /* also flushes the setvbuf() buffer */
        g_BaseFile = NULL;
    }
    free(g_BaseRam);
    g_BaseRam = NULL;
    g_BaseRamSize = 0;
}

/* Open a store able to hold every non-zero block of the current region list. */
static bool baselineStoreOpen(void) {
    baselineStoreClose();
    remove(NXUS_SESSION_BASELINE_PATH);

    const u64 region_bytes = baselineRegionBytes();
    if (region_bytes == 0) return false;

    if (region_bytes > NXUS_BASELINE_RAM_MAX) {
        FILE *f = fopen(NXUS_SESSION_BASELINE_PATH, "wb+");
        if (f != NULL) {
            /* A full buffered stream keeps the write path off the heap and turns
               the engine's per-block writes into card-sized bursts. */
            setvbuf(f, (char *)g_BaseFileBuf, _IOFBF, sizeof(g_BaseFileBuf));
            g_BaseFile = f;
            NXUS_LOG("baseline: SD store open (%llu region bytes)", (unsigned long long)region_bytes);
            return true;
        }
        NXUS_LOG("baseline: SD store unavailable, using RAM");
    }

    /* The whole scoped range is the worst case: only blocks that are not all-zero
       are ever written, so this is an upper bound. */
    g_BaseRam = (u8 *)malloc((size_t)region_bytes);
    if (g_BaseRam == NULL) {
        NXUS_LOG("baseline: %llu-byte RAM store allocation failed",
                 (unsigned long long)region_bytes);
        return false;
    }
    g_BaseRamSize = region_bytes;
    NXUS_LOG("baseline: RAM store open (%llu bytes)", (unsigned long long)region_bytes);
    return true;
}

/* Forget the baseline completely: heap block metadata, open handle and the SD
   dump.  Safe to call when no baseline exists. */
static void baselineDiscard(void) {
    nxusBaselineFree(&g_Session.baseline);
    baselineStoreClose();
    remove(NXUS_SESSION_BASELINE_PATH);
}

/* ---- target memory access --------------------------------------------- */

static int sessionRead(void *ctx, u64 address, void *buffer, u32 size) {
    (void)ctx;
    if (size == 0) return 0;
    /* A whole-region scan issues thousands of reads back to back on one core.
       Yielding every 64 reads keeps the game / system threads scheduled during a
       multi-second scan instead of letting this worker starve them. */
    /* Atomic: both the scan worker and the connection thread (sessions reads,
       snapshots, hex view) run through here, so a plain counter is a data race. */
    static atomic_uint read_tick;
    if ((atomic_fetch_add_explicit(&read_tick, 1u, memory_order_relaxed) & 63u) == 0) {
        svcSleepThread(0);
    }
    /* dmnt rejects oversized single reads; the engine never asks for more than
       one window (<= 32KB) or one chunk, both well within limits.
       In debug mode dmnt is detached, so the debug session serves the reads. */
    /* Sample the attach state exactly ONCE for this read and branch on that
       value: a detach that lands right after the check is nxus_debug's problem
       (it retries / fails the read), and re-testing here would only move the
       window, not close it.  One decision per read also keeps a mid-scan detach
       from mixing the two backends inside a single read. */
    const bool debug_attached = nxusDebugIsAttached();
    Result rc = debug_attached ? nxusDebugReadMemory(address, buffer, size)
                               : nxusDmntRead(address, buffer, size);
    return R_SUCCEEDED(rc) ? 0 : -1;
}

/* ---- lifecycle --------------------------------------------------------- */

/* Guards double initialisation.  A second nxusSessionInit() must not memset a
   live session: that would leak the mapping snapshot, the region list, the hit
   list and the baseline block, and every caller still holding one of those
   pointers would then read freed memory.  Exit() clears the flag, so an
   Exit -> Init sequence reinitialises with new limits. */
static bool g_Inited;

void nxusSessionInit(u32 chunk_size, u32 max_hits) {
    if (g_Inited) return;      /* already initialised: keep the live session */
    mutexInit(&g_SessionMutex);
    memset(&g_Session, 0, sizeof(g_Session));
    atomic_init(&g_Session.state, NxusScanState_Idle);
    atomic_init(&g_Session.cancel, 0);
    atomic_init(&g_ViewSeq, 0);   /* both published views start empty/stable */
    g_Session.chunk_size = chunk_size ? chunk_size : NXUS_SESSION_DEFAULT_CHUNK;
    g_Session.max_hits = max_hits ? max_hits : NXUS_SESSION_DEFAULT_MAXHITS;
    g_Session.window_size = NXUS_SESSION_DEFAULT_WINDOW;
    g_Session.gap_threshold = NXUS_SESSION_DEFAULT_GAP;
    g_Session.watchdog_timeout_ms = 15000;
    g_Session.last_heartbeat_ms = nowMs();
    g_Inited = true;
}

void nxusSessionExit(void) {
    if (!g_Inited) return;     /* nothing initialised (or already exited) */
    nxusSessionScanCancel();
    if (g_Session.thread_live) {
        threadWaitForExit(&g_Session.thread);
        threadClose(&g_Session.thread);
        g_Session.thread_live = false;
    }
    nxusHitListFree(&g_Session.hits);
    baselineDiscard();
    /* Unpublish through the seqlock before releasing: nxusSessionMappings() /
       nxusSessionRegions() must never hand out a view whose backing block is
       already gone, and must never pair the old pointer with the new count. */
    mappingSnapshotDrop();
    regionListDrop();
    sessionStateStore(NxusScanState_Idle);
    g_Inited = false;
}

u32  nxusSessionId(void)            { return g_Session.session_id; }
u32  nxusSessionScanState(void)     { return (u32)sessionStateLoad(); }
u32  nxusSessionProgress(void)      { return g_Session.progress; }
s32  nxusSessionLastResult(void)    { return g_Session.last_result; }
/* While a baseline is live the hit list is intentionally empty (the first pass
   only fingerprints), so report the candidate count the baseline covered: the
   status then reads "N candidates" instead of "0 hits". */
u32  nxusSessionHitCount(void)      {
    if (g_Session.baseline.active) {
        return (g_Session.baseline.candidate_count > 0xFFFFFFFFull)
                   ? 0xFFFFFFFFu : (u32)g_Session.baseline.candidate_count;
    }
    return g_Session.hits.count;
}
u32  nxusSessionMappingCount(void)  { return g_Session.maps.count; }
u64  nxusSessionProcessId(void)     { return g_Session.process_id; }

/* Range list for NxusScope_Ranges; copied, truncated to the protocol maximum. */
void nxusSessionSetScanRanges(const NxusRangeEntry *ranges, u32 count) {
    u32 n = (count > NXUS_MAX_SCAN_RANGES) ? NXUS_MAX_SCAN_RANGES : count;
    if (ranges != NULL && n > 0) {
        memcpy(g_Session.ranges, ranges, (size_t)n * sizeof(NxusRangeEntry));
    }
    g_Session.range_count = (ranges == NULL) ? 0 : n;
}

/* Attaching to another process invalidates the identity cached from dmnt: keeping the
   old main base would make every main-relative scan read the wrong process. */
void nxusSessionSetProcessIdentityEx(u64 pid, u64 program_id, u64 main_base, u64 main_size) {
    g_Session.process_id = pid;
    g_Session.program_id = program_id;
    g_Session.main_base = main_base;
    g_Session.main_size = main_size;
}

void nxusSessionSetProcessIdentity(u64 pid, u64 main_base, u64 main_size) {
    nxusSessionSetProcessIdentityEx(pid, 0, main_base, main_size);
}
u64  nxusSessionProgramId(void)     { return g_Session.program_id; }
u64  nxusSessionMainBase(void)      { return g_Session.main_base; }
u64  nxusSessionMainSize(void)      { return g_Session.main_size; }
/* The hit list is embedded in the session, so the address itself never dangles -
   but its arrays are realloc'd by the worker while a scan runs.  Callers must
   therefore only walk it BEHIND THE BUSY GATE (the server rejects ScanGetHits
   while Running) and must treat the count read from the list as the only
   consistent sample.  While Running there is no consistent view at all, so it is
   not exposed: the acquire load below pairs with the worker's release store. */
const NxusHitList *nxusSessionHits(void) {
    if (sessionStateLoad() == NxusScanState_Running) return NULL;
    return &g_Session.hits;
}

/* Never returns a dangling table: the pair is only readable while g_ViewSeq is
   stable, mappingSnapshotDrop() clears it before free(), and the retry loop
   rejects a sample that raced with an update - so the caller sees either one
   consistent snapshot or an empty view.  Callers must tolerate NULL (= no
   snapshot / after Exit) and must run behind the BUSY gate (the pointer scan and
   the module walk read the array the worker is using); the returned table is the
   live one, not a copy. */
const NxusMappingTable *nxusSessionMappings(void) {
    for (u32 attempt = 0; attempt < NXUS_VIEW_RETRY; attempt++) {
        const u32 seq = atomic_load_explicit(&g_ViewSeq, memory_order_acquire);
        if ((seq & 1u) != 0) continue;              /* update in progress */
        NxusMappingEntry *const entries = g_Session.maps.entries;
        const u32 count = g_Session.maps.count;
        if (atomic_load_explicit(&g_ViewSeq, memory_order_acquire) != seq) continue;
        if (count == 0 || entries == NULL) return NULL;
        return &g_Session.maps;
    }
    return NULL;   /* kept losing the race: report "no table" instead of a torn pair */
}

void nxusSessionSetPaused(bool paused) {
    mutexLock(&g_SessionMutex);
    g_Session.paused = paused;
    g_Session.last_heartbeat_ms = nowMs();
    mutexUnlock(&g_SessionMutex);
}

bool nxusSessionIsPaused(void) {
    mutexLock(&g_SessionMutex);
    bool paused = g_Session.paused;
    mutexUnlock(&g_SessionMutex);
    return paused;
}

/* True when no command has arrived for this long, regardless of pause state.
   (The pause watchdog below only fires while paused; a stale debug session can
   also happen with the target running.) */
void nxusSessionSetChunkSize(u32 chunk_size) {
    if (chunk_size == 0) return;
    /* The worker reads this to size its buffer; changing it mid-scan would let
       the engine read more bytes than the buffer holds. */
    if (sessionStateLoad() == NxusScanState_Running) return;
    /* The scan chunk is a single blocking allocation inside an 8 MB heap shared
       with the rx buffer, the hit list and the snapshot slots, so the ceiling is
       the default rather than the theoretical maximum. */
    if (chunk_size > NXUS_SESSION_DEFAULT_CHUNK) chunk_size = NXUS_SESSION_DEFAULT_CHUNK;
    g_Session.chunk_size = chunk_size;
    NXUS_LOG("scan chunk size set to %u bytes", (unsigned)chunk_size);
}

bool nxusSessionIdleExpired(u32 timeout_ms) {
    return (nowMs() - g_Session.last_heartbeat_ms) > timeout_ms;
}

void nxusSessionHeartbeat(void) {
    mutexLock(&g_SessionMutex);
    g_Session.last_heartbeat_ms = nowMs();
    mutexUnlock(&g_SessionMutex);
}

u32 nxusSessionWatchdogTimeout(void) { return g_Session.watchdog_timeout_ms; }
void nxusSessionSetWatchdogTimeout(u32 timeout_ms) {
    g_Session.watchdog_timeout_ms = timeout_ms ? timeout_ms : 15000;
}

bool nxusSessionWatchdogExpired(u32 timeout_ms) {
    mutexLock(&g_SessionMutex);
    bool expired = g_Session.paused && (nowMs() - g_Session.last_heartbeat_ms) > (u64)timeout_ms;
    mutexUnlock(&g_SessionMutex);
    return expired;
}

/* ---- mapping snapshot -------------------------------------------------- */

/* Walk the address space through the debug session (dmnt is detached). */
static Result snapshotMappingsDebug(void) {
    const u32 cap = 4096;
    NxusMappingEntry *entries = (NxusMappingEntry *)calloc(cap, sizeof(NxusMappingEntry));
    if (entries == NULL) return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);

    u32 n = 0;
    u64 address = 0;
    for (u32 guard = 0; guard < 8192 && n < cap; guard++) {
        NxusMemoryInfo info;
        memset(&info, 0, sizeof(info));
        if (R_FAILED(nxusDebugQueryMemory(address, &info))) break;
        if (info.size == 0 || info.memory_type == 0 || info.perm == 0) {
            /* svcQueryDebugProcessMemory reports unmapped gaps with a NON-zero size
               covering the hole, so skip them by type/permission as well - adding
               them would hand the PC bogus regions that read as garbage. */
            u64 skip = info.size ? info.size : 0x1000ull;
            if (address > 0x7FFFFFFFFFFFull - skip) break;
            address += skip;
            continue;
        }
        entries[n].base = info.base_addr;
        entries[n].size = info.size;
        entries[n].valid = 1;
        entries[n].reserved = info.perm;
        entries[n].type = info.memory_type;      /* Heap scope filters on this */
        n++;

        u64 next = info.base_addr + info.size;
        if (next <= address) break;
        address = next;
    }

    /* Publish first, release the old block after: a concurrent reader then sees
       either the previous snapshot or the new one, never the freed one. */
    mappingSnapshotPublish(entries, n);
    NXUS_LOG("debug snapshot: %u mappings", (unsigned)n);
    return n ? 0 : MAKERESULT(Module_Libnx, LibnxError_BadInput);
}

static Result snapshotMappings(void) {
    if (nxusDebugIsAttached()) return snapshotMappingsDebug();

    u64 count = 0;
    Result rc = nxusDmntGetMappingCount(&count);
    if (R_FAILED(rc)) return rc;
    if (count == 0) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (count > 4096) count = 4096;

    NxusMemoryInfo *raw = (NxusMemoryInfo *)calloc((size_t)count, sizeof(NxusMemoryInfo));
    if (raw == NULL) return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);

    size_t got = 0;
    rc = nxusDmntGetMappings(raw, (size_t)count, 0, &got);
    if (R_FAILED(rc)) { free(raw); return rc; }

    /* dmnt reported mappings but handed none back: publishing an empty table
       would make nxusSessionMappings() return NULL for a call that "succeeded",
       and every caller would then have to defend against a table that is not
       there.  Report the inconsistency instead (and drop the stale table, since
       the process may have changed underneath us). */
    if (got == 0) {
        NXUS_LOG("mappings: dmnt reported %llu entries but returned 0 - dropping the table",
                 (unsigned long long)count);
        mappingSnapshotDrop();
        free(raw);
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }

    NxusMappingEntry *entries = (NxusMappingEntry *)calloc(got, sizeof(NxusMappingEntry));
    if (entries == NULL) { free(raw); return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory); }

    for (size_t i = 0; i < got; i++) {
        entries[i].base = raw[i].base_addr;
        entries[i].size = raw[i].size;
        entries[i].valid = 1;
        entries[i].reserved = raw[i].perm;
        entries[i].type = raw[i].memory_type;
    }
    /* Same publish-then-release rule as the debug path above. */
    mappingSnapshotPublish(entries, (u32)got);
    free(raw);
    return 0;
}

int nxusSessionReadCallback(void *ctx, u64 address, void *buffer, u32 size) {
    return sessionRead(ctx, address, buffer, size);
}

int nxusSessionReadMemory(u64 address, void *buffer, u32 size) {
    return sessionRead(NULL, address, buffer, size);
}

Result nxusSessionPrepareRegions(u32 scope, u64 range_begin, u64 range_end) {
    /* NxusScope_Ranges has no list of its own here: the request that carried one is
       gone, and reusing the previous scan's list would capture the wrong memory. */
    if (scope == NxusScope_Ranges) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    NxusScanRequest req;
    memset(&req, 0, sizeof(req));
    req.scope = scope;
    req.range_begin = range_begin;
    req.range_end = range_end;

    Result rc = nxusSessionRefreshMappings();
    if (R_FAILED(rc)) return rc;
    if (g_Session.maps.count == 0) return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    buildRegions(&req);
    return g_Session.region_count ? 0 : MAKERESULT(Module_Libnx, LibnxError_BadInput);
}

/* Same contract as nxusSessionHits(): consumers (the snapshot service) run
   behind the server's BUSY gate, because preparing a new scan rebuilds this list
   under the running engine.  The pair is sampled behind the seqlock, so a clear
   or a rebuild is reported as one consistent (NULL, 0) / (list, count) instead of
   a pointer from one publication paired with the count of another. */
const NxusScanRegion *nxusSessionRegions(u32 *out_count) {
    for (u32 attempt = 0; attempt < NXUS_VIEW_RETRY; attempt++) {
        const u32 seq = atomic_load_explicit(&g_ViewSeq, memory_order_acquire);
        if ((seq & 1u) != 0) continue;              /* update in progress */
        const NxusScanRegion *regions = g_Session.regions;
        const u32 count = g_Session.region_count;
        if (atomic_load_explicit(&g_ViewSeq, memory_order_acquire) != seq) continue;
        if (regions == NULL || count == 0) {
            if (out_count != NULL) *out_count = 0;
            return NULL;
        }
        if (out_count != NULL) *out_count = count;
        return regions;
    }
    if (out_count != NULL) *out_count = 0;
    return NULL;   /* kept losing the race: report "no list" instead of a torn pair */
}

Result nxusSessionRefreshMappings(void) {
    cacheProcessInfo();
    return snapshotMappings();
}

/* Re-validate the snapshot before a refine pass: the target may have been
   running (heap reshuffles) since the first pass. */
static void revalidateMappings(void) {
    if (nxusDebugIsAttached()) {
        /* dmnt is closed, and hits store indices into g_Session.map_entries from
           ScanBegin: re-query each entry in place via the debug handle so a new or
           split mapping never shifts mapping_idx for surviving hits. */
        for (u32 i = 0; i < g_Session.maps.count; i++) {
            NxusMappingEntry *m = &g_Session.map_entries[i];
            NxusMemoryInfo info;
            memset(&info, 0, sizeof(info));
            if (R_SUCCEEDED(nxusDebugQueryMemory(m->base, &info)) &&
                info.base_addr == m->base && info.size == m->size &&
                info.memory_type != 0 && (info.perm & NXUS_PERM_R)) {
                m->valid = 1;
                m->reserved = info.perm;
                m->type = info.memory_type;
            } else {
                m->valid = 0;
            }
        }
        return;
    }

    u64 count = 0;
    if (R_FAILED(nxusDmntGetMappingCount(&count)) || count == 0) return;

    u64 fetch = count > 512 ? 512 : count;
    NxusMemoryInfo *raw = (NxusMemoryInfo *)calloc((size_t)fetch, sizeof(NxusMemoryInfo));
    if (raw == NULL) return;

    for (u32 i = 0; i < g_Session.maps.count; i++) g_Session.map_entries[i].valid = 0;

    u64 offset = 0;
    u32 snap = 0;
    while (offset < count && snap < g_Session.maps.count) {
        size_t page = 0;
        if (R_FAILED(nxusDmntGetMappings(raw, (size_t)fetch, (size_t)offset, &page)) || page == 0) break;
        for (size_t i = 0; i < page && snap < g_Session.maps.count; i++) {
            while (snap < g_Session.maps.count && g_Session.map_entries[snap].base < raw[i].base_addr) snap++;
            if (snap < g_Session.maps.count &&
                g_Session.map_entries[snap].base == raw[i].base_addr &&
                g_Session.map_entries[snap].size == raw[i].size) {
                g_Session.map_entries[snap].valid = (raw[i].perm & NXUS_PERM_R) ? 1 : 0;
                g_Session.map_entries[snap].reserved = raw[i].perm;
                snap++;
            }
        }
        offset += page;
    }

    /* A refine can follow a game restart, so refresh all four identity fields, not
       just the main NSO range (the mapping revalidation above tolerated this). */
    (void)nxusSessionRefreshIdentity();
    free(raw);
}

/* Refresh the cached target identity from dmnt:cht.  Every main-relative scope,
   hit address and cheat export is derived from these four fields, so they must
   follow a ForceOpen / game restart even when no scan runs in between. */
Result nxusSessionRefreshIdentity(void) {
    /* While attached, dmnt is closed and svcQueryDebugProcessMemory cannot produce
       the metadata struct, so the values cached from the last dmnt session (or the
       attach hand-off) are kept.  Do not even call nxusDmntGetMetadata() here: it
       auto-reopens dmnt after a failure, which would fight with the debug session
       that owns the process. */
    if (nxusDebugIsAttached() || nxusDebugIsHandoff()) return 0;
    NxusProcessMetadata md;
    memset(&md, 0, sizeof(md));
    Result rc = nxusDmntGetMetadata(&md);
    if (R_FAILED(rc)) return rc;   /* no target / dmnt gone: keep the last known */
    nxusSessionSetProcessIdentityEx(md.process_id, md.program_id,
                                    md.main_nso_base, md.main_nso_size);
    return 0;
}

static void cacheProcessInfo(void) {
    /* A missing target is normal (boot, game closed), so the result is ignored here. */
    (void)nxusSessionRefreshIdentity();
}

/* ---- regions ----------------------------------------------------------- */

static void buildRegions(const NxusScanRequest *req) {
    /* Unpublish the old list before releasing it (clear-before-free, see
       regionListDrop): every scan rebuilds this list, and a reader must never
       chase the block that the free below reused. */
    regionListDrop();

    /* One region per mapping, and one per (mapping, range) pair in list mode.
       4096 entries bound this list to ~128 KB (NxusScanRegion is 32 bytes);
       the old 65536 cap could reserve 2 MB and, together with the chunk buffer,
       the mappings and the hit list, squeeze the 8 MB heap. */
    u32 capacity = g_Session.maps.count * (g_Session.range_count ? g_Session.range_count : 1) + 1;
    if (capacity > 4096u) capacity = 4096u;
    NxusScanRegion *regions = (NxusScanRegion *)calloc(capacity, sizeof(NxusScanRegion));
    if (regions == NULL) return;

    /* Fill the block privately and publish pointer+count together at the end:
       the new list is not reachable from another thread until it is complete. */
    u32 count;
    if (req->scope == NxusScope_Ranges) {
        count = nxusBuildRegionsMulti(g_Session.map_entries, g_Session.maps.count,
                                      g_Session.main_base, g_Session.main_size,
                                      g_Session.ranges, g_Session.range_count,
                                      regions, capacity);
    } else {
        count = nxusBuildRegions(g_Session.map_entries, g_Session.maps.count,
                                 g_Session.main_base, g_Session.main_size,
                                 req->scope, req->range_begin, req->range_end,
                                 regions, capacity);
    }
    regionListPublish(regions, count);
}

/* ---- worker ------------------------------------------------------------ */

static void scanThread(void *arg) {
    (void)arg;
    const bool first_pass = g_Session.job_first_pass;
    NxusScanStats stats;
    memset(&stats, 0, sizeof(stats));

    u8 *chunk = NULL;
    u8 *window = NULL;
    u8 *cur_buf = NULL;
    u8 *prev_buf = NULL;
    u64 candidates = 0;
    int rc = NXUS_SCAN_ERR_PARAM;

    if (first_pass) {
        /* Read the size once: the buffer and the engine must agree even if a
           config change arrives while this scan is being set up. */
        const u32 chunk_size = g_Session.chunk_size;
        chunk = (u8 *)malloc(chunk_size);
        if (chunk == NULL) {
            /* The worker cannot scan without its buffer.  Report a real OOM
               (not BadInput) so the client can shrink the chunk or free memory
               instead of blaming the request.  Result first, state last: a reader
               that observes a settled state must also observe the error code
               (release store). */
            g_Session.last_result = (s32)MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
            sessionStateStore(NxusScanState_Error);
            NXUS_LOG("scan abort: %u-byte chunk allocation failed (out of memory)",
                     (unsigned)chunk_size);
            return;
        }
        if (g_Session.baseline.active) {
            /* Unknown scan: fingerprint every block and stream the non-zero ones
               to the baseline store.  No hits are pushed here - the candidate
               count is what the status reports. */
            rc = nxusScanFirstBaseline(&g_Session.baseline,
                                       g_Session.regions, g_Session.region_count,
                                       &g_Session.job_req,
                                       sessionRead, NULL,
                                       &g_BaselineIo, NULL,
                                       chunk, chunk_size, &stats,
                                       (int *)&g_Session.cancel);
            candidates = g_Session.baseline.candidate_count;
            if (rc != NXUS_SCAN_OK) {
                /* A partial baseline cannot be refined safely: blocks that were
                   never hashed would compare against garbage.  Drop it so
                   ScanNext reports BadInput instead of silently scanning a
                   subset of the range. */
                baselineDiscard();
            }
        } else {
            rc = nxusScanFirstEx(g_Session.regions, g_Session.region_count, &g_Session.job_req,
                                 &g_Session.job_pattern,
                                 &g_Session.hits, sessionRead, NULL,
                                 chunk, chunk_size, &stats,
                                 (int *)&g_Session.cancel);
        }
    } else if (g_Session.baseline.active) {
        /* Second pass of an Unknown scan: only blocks whose fingerprint changed
           are re-read, and only their matching candidates become hits.  The
           buffers must hold one baseline block each. */
        u32 buf_size = g_Session.baseline.block_size;
        if (buf_size < NXUS_BASELINE_BUF_MIN) buf_size = NXUS_BASELINE_BUF_MIN;
        cur_buf = (u8 *)malloc(buf_size);
        prev_buf = (u8 *)malloc(buf_size);
        if (cur_buf == NULL || prev_buf == NULL) {
            baselineDiscard();
            g_Session.last_result = (s32)MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
            sessionStateStore(NxusScanState_Error);
            NXUS_LOG("scan abort: %u-byte baseline buffers failed (out of memory)",
                     (unsigned)buf_size);
            free(chunk);
            free(cur_buf);
            free(prev_buf);
            return;
        }
        rc = nxusScanNextFromBaseline(&g_Session.baseline,
                                      &g_Session.hits,
                                      &g_Session.job_req,
                                      &g_Session.maps,
                                      sessionRead, NULL,
                                      &g_BaselineIo, NULL,
                                      cur_buf, buf_size,
                                      prev_buf, buf_size,
                                      &stats, (int *)&g_Session.cancel);
        candidates = g_Session.baseline.candidate_count;
        /* The fingerprints are consumed (active is cleared on every exit path),
           so release the SD dump and the block metadata right away instead of
           holding ~1 MB through every later refine pass. */
        baselineStoreClose();
        remove(NXUS_SESSION_BASELINE_PATH);
        nxusBaselineFree(&g_Session.baseline);
    } else {
        window = (u8 *)malloc(g_Session.window_size);
        if (window == NULL) {
            g_Session.last_result = (s32)MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
            sessionStateStore(NxusScanState_Error);
            NXUS_LOG("scan abort: %u-byte window allocation failed (out of memory)",
                     (unsigned)g_Session.window_size);
            return;
        }
        rc = nxusScanNextEx(&g_Session.hits, &g_Session.job_req, &g_Session.job_pattern,
                            &g_Session.maps,
                            sessionRead, NULL, window, g_Session.window_size,
                            g_Session.gap_threshold, &stats,
                            (int *)&g_Session.cancel);
    }

    g_Session.progress = stats.permille;

    NxusScanState final_state;
    switch (rc) {
        case NXUS_SCAN_OK:
            final_state = NxusScanState_Done;
            g_Session.last_result = 0;
            break;
        case NXUS_SCAN_ERR_CANCELLED:
            final_state = NxusScanState_Cancelled;
            g_Session.last_result = 0;
            break;
        case NXUS_SCAN_ERR_FULL:
            final_state = NxusScanState_Error;
            g_Session.last_result = (s32)MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
            break;
        default:
            final_state = NxusScanState_Error;
            g_Session.last_result = (s32)MAKERESULT(Module_Libnx, LibnxError_BadInput);
            break;
    }

    /* Single release store as the very last publication step: the hit list is
       complete, the baseline is gone, progress and last_result are in place, so
       any reader that now sees "not Running" also sees the final results. */
    sessionStateStore(final_state);

    NXUS_LOG("scan done: state=%u hits=%u candidates=%llu reads=%llu bytes=%llu dropped=%u",
             (unsigned)final_state, (unsigned)g_Session.hits.count,
             (unsigned long long)candidates,
             (unsigned long long)stats.reads, (unsigned long long)stats.bytes_read,
             (unsigned)stats.dropped);

    free(chunk);
    free(window);
    free(cur_buf);
    free(prev_buf);
}

static Result startJob(bool first_pass) {
    if (sessionStateLoad() == NxusScanState_Running) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);

    if (g_Session.thread_live) {
        threadWaitForExit(&g_Session.thread);
        threadClose(&g_Session.thread);
        g_Session.thread_live = false;
    }

    g_Session.job_first_pass = first_pass;
    g_Session.last_result = 0;
    g_Session.progress = 0;
    atomic_store_explicit(&g_Session.cancel, 0, memory_order_relaxed);

    /* The worker gained a deeper call path (Unknown first pass and the baseline
       refine) and the old 32 KB stack had little margin; 64 KB keeps the engine's
       per-block locals off the edge. */
    alignas(0x1000) static u8 scanStack[0x10000];
    Result rc = threadCreate(&g_Session.thread, scanThread, NULL, scanStack, sizeof(scanStack), 0x2C, -2);
    if (R_FAILED(rc)) return rc;

    /* Publish Running only AFTER every worker input is in place (regions, mapping
       snapshot, hit list, job request, thread_live): the release store pairs with
       the acquire loads of the worker and of the server's BUSY gates. */
    g_Session.thread_live = true;
    sessionStateStore(NxusScanState_Running);
    threadStart(&g_Session.thread);
    return 0;
}

/* Copy the pattern (if any) into the session so the worker thread owns it.
   Must be called AFTER g_Session.job_req = *req so FuzzyEqual can populate
   job_req.target2 without startJob() clobbering it. */
static void setPattern(u32 value_type, u32 epsilon_decimals,
                       const u8 *pattern, u32 pattern_len, const u8 *mask) {
    memset(&g_Session.job_pattern, 0, sizeof(g_Session.job_pattern));
    g_Session.job_pattern.value_type = value_type;
    g_Session.job_pattern.epsilon_decimals = epsilon_decimals;

    /* FuzzyEqual compares |current - target| <= epsilon, and the engine reads that
       epsilon from target2 (as float bits).  An ext that only carries
       epsilon_decimals (or a CLI --cmp fuzzy with epsilon_decimals == 0) used to
       leave target2 == 0, turning a fuzzy scan into an exact one silently. */
    if (g_Session.job_req.cmp_mode == NxusCmp_FuzzyEqual && g_Session.job_req.target2 == 0) {
        u32 dec = (epsilon_decimals > 0) ? epsilon_decimals : 2u;
        double eps = 1.0;
        for (u32 i = 0; i < dec && i < 9; i++) eps /= 10.0;   /* no libm here */
        if (value_type == NxusValueType_F32) {
            const float e = (float)eps;
            u32 bits = 0;
            memcpy(&bits, &e, sizeof(bits));
            g_Session.job_req.target2 = bits;
        } else if (value_type == NxusValueType_F64) {
            u64 bits = 0;
            memcpy(&bits, &eps, sizeof(bits));
            g_Session.job_req.target2 = bits;
        }
    }
    g_Session.job_pattern.pattern_len = 0;
    g_Session.job_pattern.pattern = NULL;
    g_Session.job_pattern.mask = NULL;
    if (pattern != NULL && pattern_len > 0) {
        if (pattern_len > NXUS_SCAN_MAX_PATTERN) pattern_len = NXUS_SCAN_MAX_PATTERN;
        memcpy(g_Session.job_pattern_bytes, pattern, pattern_len);
        g_Session.job_pattern.pattern = g_Session.job_pattern_bytes;
        g_Session.job_pattern.pattern_len = pattern_len;
        if (mask != NULL) {
            memcpy(g_Session.job_pattern_mask, mask, pattern_len);
            g_Session.job_pattern.mask = g_Session.job_pattern_mask;
        }
    }
}

/* Value size that the hit list must store for this scan. */
static u32 listValueSize(const NxusScanRequest *req, u32 value_type) {
    return nxusHitListValueSize(value_type, req->value_size ? req->value_size : 4);
}

/* A dense baseline only fits a numeric "unknown initial value" scan.  Pattern
   types (String/Bytes/Binary) and "All" have a match window wider than their
   stride, so a value can straddle a block boundary and a block-grid candidate
   enumeration would miss it - they keep the classic hit-list first pass. */
static bool baselineApplies(const NxusScanRequest *req, u32 value_type, bool patterned) {
    if (req->cmp_mode != NxusCmp_Unknown) return false;
    if (patterned) return false;
    if (value_type == NxusValueType_All) return false;
    if (value_type == NxusValueType_String || value_type == NxusValueType_Bytes ||
        value_type == NxusValueType_Binary) return false;
    return true;
}

Result nxusSessionScanBegin(const NxusScanRequest *req, u32 value_type, u32 epsilon_decimals,
                            const u8 *pattern, u32 pattern_len, const u8 *mask) {
    if (req == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    /* Refuse BEFORE touching anything while the worker is alive: it owns the
       regions, mappings and hit list, and freeing them under it corrupts the
       session.  A finished thread is NOT busy - startJob() joins it before
       reusing the slot, so only the Running state gates here. */
    if (sessionStateLoad() == NxusScanState_Running) {
        return NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    if (req->value_size != 1 && req->value_size != 2 && req->value_size != 4 && req->value_size != 8)
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (pattern_len > NXUS_SCAN_MAX_PATTERN) return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    g_Session.job_req = *req;
    setPattern(value_type, epsilon_decimals, pattern, pattern_len, mask);
    g_Session.job_pattern.flags = req->flags;

    /* A new scan always starts from a clean baseline: the fingerprints describe
       the previous request's width and byte range, so reusing them would compare
       values from two different scans.  Doing it before the snapshot also covers
       a scan that then fails (no target, empty scope): its stale dump must not
       stay on the SD card. */
    baselineDiscard();

    cacheProcessInfo();
    Result rc = snapshotMappings();
    if (R_FAILED(rc)) return rc;

    buildRegions(req);
    if (g_Session.region_count == 0) return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    const u32 hit_value_size = listValueSize(req, value_type);
    if (baselineApplies(req, value_type, g_Session.job_pattern.pattern != NULL)) {
        bool ready = nxusBaselineInit(&g_Session.baseline, g_Session.region_count + 1,
                                      NXUS_BASELINE_MAX_BLOCKS,
                                      hit_value_size, value_type) == NXUS_SCAN_OK;
        if (ready) ready = baselineStoreOpen();
        if (ready) {
            NXUS_LOG("unknown scan: dense baseline armed (%u regions, %u-byte values)",
                     (unsigned)g_Session.region_count, (unsigned)hit_value_size);
        } else {
            /* No store (card refused / out of memory) or no block arrays: keep the
               classic all-hits first pass so the scan still works up to max_hits. */
            baselineDiscard();
            NXUS_LOG("unknown scan: baseline unavailable, using the classic first pass");
        }
    }

    nxusHitListFree(&g_Session.hits);
    /* Dynamic ceiling: NXUS_SESSION_HIT_BUDGET_BYTES split into
       8 B address + value_size B value, so a narrower type buys more hits
       (u8 ~341k, u16 ~307k, u32 ~256k, u64 ~192k) for the same ~3 MB. */
    u32 max_hits = nxusSessionHitLimit(hit_value_size);
    if (max_hits < g_Session.max_hits) max_hits = g_Session.max_hits;
    u32 initial = 65536;
    if (initial > max_hits) initial = max_hits;
    rc = nxusHitListInit(&g_Session.hits, initial, max_hits, hit_value_size);
    if (R_FAILED(rc)) {
        baselineDiscard();
        return rc;
    }

    g_Session.session_id++;
    sessionStateStore(NxusScanState_Idle);
    Result jr = startJob(true);
    if (R_FAILED(jr)) baselineDiscard();   /* no worker: the dump is dead weight */
    return jr;
}

Result nxusSessionScanNext(const NxusScanRequest *req, u32 value_type, u32 epsilon_decimals,
                           const u8 *pattern, u32 pattern_len, const u8 *mask) {
    if (req == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (sessionStateLoad() == NxusScanState_Running) {
        return NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    /* An Unknown scan's first pass deliberately pushes no hits: everything lives
       in the baseline until the refine pass materialises the matches.  So an
       empty hit list is only an error when there is no baseline to refine. */
    if (g_Session.hits.count == 0 && !g_Session.baseline.active) {
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }
    /* A refine must not widen the values it compares against the stored ones:
       that would read past every slot in the hit list. */
    if (nxusHitListValueSize(value_type, req->value_size ? req->value_size : 4) > g_Session.hits.value_size) {
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }

    g_Session.job_req = *req;
    setPattern(value_type, epsilon_decimals, pattern, pattern_len, mask);
    g_Session.job_pattern.flags = req->flags;

    revalidateMappings();
    return startJob(false);
}

Result nxusSessionScanCancel(void) {
    if (sessionStateLoad() != NxusScanState_Running) return 0;
    atomic_store_explicit(&g_Session.cancel, 1, memory_order_relaxed);
    return 0;
}

Result nxusSessionScanUndo(void) {
    if (sessionStateLoad() == NxusScanState_Running) {
        return NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    if (nxusHitListUndo(&g_Session.hits) != NXUS_SCAN_OK) {
        return NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }
    g_Session.progress = 1000;
    sessionStateStore(NxusScanState_Done);
    return 0;
}

void nxusSessionReset(void) {
    nxusSessionScanCancel();
    if (g_Session.thread_live) {
        threadWaitForExit(&g_Session.thread);
        threadClose(&g_Session.thread);
        g_Session.thread_live = false;
    }
    nxusHitListFree(&g_Session.hits);
    baselineDiscard();
    /* Results and identifiers are reset under the release store: a reader that
       sees Idle must not see the previous scan's progress/result. */
    g_Session.session_id++;
    g_Session.progress = 0;
    g_Session.last_result = 0;
    sessionStateStore(NxusScanState_Idle);
}
