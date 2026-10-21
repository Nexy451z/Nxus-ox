#include "nxus_session.h"
#include "nxus_debug.h"
#include "nxus_dmntcht.h"
#include "nxus_log.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    u32 state;                 /* NxusScanState */
    u32 session_id;
    u32 progress;
    s32 last_result;
    u32 chunk_size;
    u32 max_hits;
    u32 window_size;
    u32 gap_threshold;

    NxusHitList hits;
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

/* ---- target memory access --------------------------------------------- */

static int sessionRead(void *ctx, u64 address, void *buffer, u32 size) {
    (void)ctx;
    if (size == 0) return 0;
    /* A whole-region scan issues thousands of reads back to back on one core.
       Yielding every 64 reads keeps the game / system threads scheduled during a
       multi-second scan instead of letting this worker starve them. */
    static u32 read_tick = 0;
    if ((++read_tick & 63u) == 0) svcSleepThread(0);
    /* dmnt rejects oversized single reads; the engine never asks for more than
       one window (<= 32KB) or one chunk, both well within limits.
       In debug mode dmnt is detached, so the debug session serves the reads. */
    Result rc = nxusDebugIsAttached() ? nxusDebugReadMemory(address, buffer, size)
                                      : nxusDmntRead(address, buffer, size);
    return R_SUCCEEDED(rc) ? 0 : -1;
}

/* ---- lifecycle --------------------------------------------------------- */

void nxusSessionInit(u32 chunk_size, u32 max_hits) {
    mutexInit(&g_SessionMutex);
    memset(&g_Session, 0, sizeof(g_Session));
    g_Session.state = NxusScanState_Idle;
    g_Session.chunk_size = chunk_size ? chunk_size : NXUS_SESSION_DEFAULT_CHUNK;
    g_Session.max_hits = max_hits ? max_hits : NXUS_SESSION_DEFAULT_MAXHITS;
    g_Session.window_size = NXUS_SESSION_DEFAULT_WINDOW;
    g_Session.gap_threshold = NXUS_SESSION_DEFAULT_GAP;
    g_Session.watchdog_timeout_ms = 15000;
    g_Session.last_heartbeat_ms = nowMs();
    atomic_init(&g_Session.cancel, 0);
}

void nxusSessionExit(void) {
    nxusSessionScanCancel();
    if (g_Session.thread_live) {
        threadWaitForExit(&g_Session.thread);
        threadClose(&g_Session.thread);
        g_Session.thread_live = false;
    }
    nxusHitListFree(&g_Session.hits);
    free(g_Session.map_entries);
    free(g_Session.regions);
    g_Session.map_entries = NULL;
    g_Session.regions = NULL;
}

u32  nxusSessionId(void)            { return g_Session.session_id; }
u32  nxusSessionScanState(void)     { return g_Session.state; }
u32  nxusSessionProgress(void)      { return g_Session.progress; }
s32  nxusSessionLastResult(void)    { return g_Session.last_result; }
u32  nxusSessionHitCount(void)      { return g_Session.hits.count; }
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
void nxusSessionSetProcessIdentity(u64 pid, u64 main_base, u64 main_size) {
    g_Session.process_id = pid;
    g_Session.program_id = 0;
    g_Session.main_base = main_base;
    g_Session.main_size = main_size;
}
u64  nxusSessionProgramId(void)     { return g_Session.program_id; }
u64  nxusSessionMainBase(void)      { return g_Session.main_base; }
u64  nxusSessionMainSize(void)      { return g_Session.main_size; }
const NxusHitList *nxusSessionHits(void) { return &g_Session.hits; }
const NxusMappingTable *nxusSessionMappings(void) { return &g_Session.maps; }

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
    if (g_Session.state == NxusScanState_Running) return;
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

    free(g_Session.map_entries);
    g_Session.map_entries = entries;
    g_Session.maps.entries = entries;
    g_Session.maps.count = n;
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

    NxusMappingEntry *entries = (NxusMappingEntry *)calloc(got ? got : 1, sizeof(NxusMappingEntry));
    if (entries == NULL) { free(raw); return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory); }

    for (size_t i = 0; i < got; i++) {
        entries[i].base = raw[i].base_addr;
        entries[i].size = raw[i].size;
        entries[i].valid = 1;
        entries[i].reserved = raw[i].perm;
        entries[i].type = raw[i].memory_type;
    }
    free(g_Session.map_entries);
    g_Session.map_entries = entries;
    g_Session.maps.entries = entries;
    g_Session.maps.count = (u32)got;
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

const NxusScanRegion *nxusSessionRegions(u32 *out_count) {
    if (out_count != NULL) *out_count = g_Session.region_count;
    return g_Session.regions;
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

    NxusProcessMetadata md;
    if (R_SUCCEEDED(nxusDmntGetMetadata(&md))) {
        g_Session.main_base = md.main_nso_base;
        g_Session.main_size = md.main_nso_size;
    }
    free(raw);
}

static void cacheProcessInfo(void) {
    /* While attached, dmnt is closed and svcQueryDebugProcessMemory cannot produce
       the metadata struct, so the values cached from the last dmnt session (or the
       first scan) are kept - the client is told to scan before attaching. */
    NxusProcessMetadata md;
    memset(&md, 0, sizeof(md));
    if (R_SUCCEEDED(nxusDmntGetMetadata(&md))) {
        g_Session.process_id = md.process_id;
        g_Session.program_id = md.program_id;
        g_Session.main_base = md.main_nso_base;
        g_Session.main_size = md.main_nso_size;
    }
}

/* ---- regions ----------------------------------------------------------- */

static void buildRegions(const NxusScanRequest *req) {
    free(g_Session.regions);
    g_Session.regions = NULL;
    g_Session.region_count = 0;

    /* One region per mapping, and one per (mapping, range) pair in list mode.
       4096 entries bound this list to ~128 KB (NxusScanRegion is 32 bytes);
       the old 65536 cap could reserve 2 MB and, together with the chunk buffer,
       the mappings and the hit list, squeeze the 8 MB heap. */
    u32 capacity = g_Session.maps.count * (g_Session.range_count ? g_Session.range_count : 1) + 1;
    if (capacity > 4096u) capacity = 4096u;
    g_Session.regions = (NxusScanRegion *)calloc(capacity, sizeof(NxusScanRegion));
    if (g_Session.regions == NULL) return;

    if (req->scope == NxusScope_Ranges) {
        g_Session.region_count = nxusBuildRegionsMulti(g_Session.map_entries, g_Session.maps.count,
                                                       g_Session.main_base, g_Session.main_size,
                                                       g_Session.ranges, g_Session.range_count,
                                                       g_Session.regions, capacity);
        return;
    }

    g_Session.region_count = nxusBuildRegions(g_Session.map_entries, g_Session.maps.count,
                                              g_Session.main_base, g_Session.main_size,
                                              req->scope, req->range_begin, req->range_end,
                                              g_Session.regions, capacity);
}

/* ---- worker ------------------------------------------------------------ */

static void scanThread(void *arg) {
    (void)arg;
    const bool first_pass = g_Session.job_first_pass;
    NxusScanStats stats;
    memset(&stats, 0, sizeof(stats));

    u8 *chunk = NULL;
    u8 *window = NULL;
    int rc = NXUS_SCAN_ERR_PARAM;

    if (first_pass) {
        /* Read the size once: the buffer and the engine must agree even if a
           config change arrives while this scan is being set up. */
        const u32 chunk_size = g_Session.chunk_size;
        chunk = (u8 *)malloc(chunk_size);
        if (chunk == NULL) {
            /* The worker cannot scan without its buffer.  Report a real OOM
               (not BadInput) so the client can shrink the chunk or free memory
               instead of blaming the request. */
            g_Session.state = NxusScanState_Error;
            g_Session.last_result = (s32)MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
            NXUS_LOG("scan abort: %u-byte chunk allocation failed (out of memory)",
                     (unsigned)chunk_size);
            return;
        }
        rc = nxusScanFirstEx(g_Session.regions, g_Session.region_count, &g_Session.job_req,
                             &g_Session.job_pattern,
                             &g_Session.hits, sessionRead, NULL,
                             chunk, chunk_size, &stats,
                             (int *)&g_Session.cancel);
    } else {
        window = (u8 *)malloc(g_Session.window_size);
        if (window == NULL) {
            g_Session.state = NxusScanState_Error;
            g_Session.last_result = (s32)MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
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

    switch (rc) {
        case NXUS_SCAN_OK:
            g_Session.state = NxusScanState_Done;
            g_Session.last_result = 0;
            break;
        case NXUS_SCAN_ERR_CANCELLED:
            g_Session.state = NxusScanState_Cancelled;
            g_Session.last_result = 0;
            break;
        case NXUS_SCAN_ERR_FULL:
            g_Session.state = NxusScanState_Error;
            g_Session.last_result = (s32)MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
            break;
        default:
            g_Session.state = NxusScanState_Error;
            g_Session.last_result = (s32)MAKERESULT(Module_Libnx, LibnxError_BadInput);
            break;
    }

    g_Session.progress = stats.permille;
    NXUS_LOG("scan done: state=%u hits=%u reads=%llu bytes=%llu dropped=%u",
             (unsigned)g_Session.state, (unsigned)g_Session.hits.count,
             (unsigned long long)stats.reads, (unsigned long long)stats.bytes_read,
             (unsigned)stats.dropped);

    free(chunk);
    free(window);
}

static Result startJob(bool first_pass) {
    if (g_Session.state == NxusScanState_Running) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);

    if (g_Session.thread_live) {
        threadWaitForExit(&g_Session.thread);
        threadClose(&g_Session.thread);
        g_Session.thread_live = false;
    }

    g_Session.job_first_pass = first_pass;
    g_Session.last_result = 0;
    g_Session.progress = 0;
    atomic_store_explicit(&g_Session.cancel, 0, memory_order_relaxed);

    alignas(0x1000) static u8 scanStack[0x8000];
    Result rc = threadCreate(&g_Session.thread, scanThread, NULL, scanStack, sizeof(scanStack), 0x2C, -2);
    if (R_FAILED(rc)) return rc;

    g_Session.state = NxusScanState_Running;
    g_Session.thread_live = true;
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

Result nxusSessionScanBegin(const NxusScanRequest *req, u32 value_type, u32 epsilon_decimals,
                            const u8 *pattern, u32 pattern_len, const u8 *mask) {
    if (req == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    /* Refuse BEFORE touching anything while the worker is alive: it owns the
       regions, mappings and hit list, and freeing them under it corrupts the
       session.  A finished thread is NOT busy - startJob() joins it before
       reusing the slot, so only the Running state gates here. */
    if (g_Session.state == NxusScanState_Running) {
        return NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    if (req->value_size != 1 && req->value_size != 2 && req->value_size != 4 && req->value_size != 8)
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (pattern_len > NXUS_SCAN_MAX_PATTERN) return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    g_Session.job_req = *req;
    setPattern(value_type, epsilon_decimals, pattern, pattern_len, mask);
    g_Session.job_pattern.flags = req->flags;

    cacheProcessInfo();
    Result rc = snapshotMappings();
    if (R_FAILED(rc)) return rc;

    buildRegions(req);
    if (g_Session.region_count == 0) return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    nxusHitListFree(&g_Session.hits);
    u32 initial = 65536;
    if (initial > g_Session.max_hits) initial = g_Session.max_hits;
    rc = nxusHitListInit(&g_Session.hits, initial, g_Session.max_hits, listValueSize(req, value_type));
    if (R_FAILED(rc)) return rc;

    g_Session.session_id++;
    g_Session.state = NxusScanState_Idle;
    return startJob(true);
}

Result nxusSessionScanNext(const NxusScanRequest *req, u32 value_type, u32 epsilon_decimals,
                           const u8 *pattern, u32 pattern_len, const u8 *mask) {
    if (req == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (g_Session.state == NxusScanState_Running) {
        return NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    if (g_Session.hits.count == 0) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
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
    if (g_Session.state != NxusScanState_Running) return 0;
    atomic_store_explicit(&g_Session.cancel, 1, memory_order_relaxed);
    return 0;
}

Result nxusSessionScanUndo(void) {
    if (g_Session.state == NxusScanState_Running) {
        return NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    if (nxusHitListUndo(&g_Session.hits) != NXUS_SCAN_OK) {
        return NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }
    g_Session.state = NxusScanState_Done;
    g_Session.progress = 1000;
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
    g_Session.state = NxusScanState_Idle;
    g_Session.session_id++;
    g_Session.progress = 0;
    g_Session.last_result = 0;
}
