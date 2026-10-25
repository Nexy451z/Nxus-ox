#include "nxus_session.h"
#include "nxus_debug.h"
#include "nxus_dmntcht.h"
#include "nxus_log.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>

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
    /* Baseline store health.  The store lives in this file, not in the engine, so
       the write callback is the only place that sees a failing card; the counters
       are published through nxusSessionBaselineWriteFailed() /
       nxusSessionBaselineDegraded() and folded into stats.write_failed by the
       worker.  Reset whenever a baseline is (re)armed or dropped. */
    u32  baseline_write_failed;
    bool baseline_write_logged;   /* the first failure has already been logged */
    bool baseline_degraded;       /* RAM fallback or a failed store write      */
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

    /* pid / program_id / main_base / main_size live in the published
       NxusTargetIdentity above, NOT here: they are one snapshot and must never be
       read or written as four independent fields (see the target-identity block). */

    /* Which target the stored results belong to (see the ownership block below):
       stamped by ScanBegin from the identity its mapping snapshot was taken with,
       so serving the previous title's hits after a switch is detectable. */
    u64 hits_owner_pid, hits_owner_program_id;
    u32 hits_owner_session_id;
    /* Generation of the mapping snapshot the hit indices belong to (see the
       mapping-generation block below).  A hit stores mapping_idx, an ORDINAL into
       the published table, so it is only meaningful while that exact table is the
       one being served - not just while the target identity matches. */
    u32 hits_owner_mapping_generation;
    bool hits_owner_valid;
} Session;

static Session g_Session;
static Mutex   g_SessionMutex;

/* ---- scan worker Thread slot -------------------------------------------
 *
 * g_Session.thread / g_Session.thread_live are touched by three callers on two
 * threads: startJob() (the connection thread) reaps the previous worker and
 * creates the next one, nxusSessionExit() (shutdown) joins the worker, and
 * nxusSessionReset() joins it.  The worker publishes Done/Error BEFORE its last
 * frees, so a shutdown can land while the connection thread is between "the scan
 * finished" and startJob()'s join - previously both sides called
 * threadWaitForExit()/threadClose() on the same Thread: the second wait ran on
 * freed thread state and the second close freed it again.
 *
 * The right to touch the slot is therefore claimed atomically, exactly like
 * nxusServer's ptrScanClaimSlot()/ptrScanJoinSlotLocked():
 *
 *   - startJob() claims it for reap -> threadCreate() -> threadStart(),
 *   - Exit() / Reset() claim it for cancel -> join -> close,
 *   - the loser never touches the Thread (startJob() answers BUSY, Exit()/Reset()
 *     log it and leave the slot to the claim holder),
 *   - g_Session.thread_live is only read or written by the claim holder.
 *
 * g_SessionExited is the shutdown half of the protocol (same shape as
 * g_ServerExited): it is set BEFORE Exit() claims the slot, and startJob()
 * re-checks it UNDER the claim, so a ScanBegin that passed its Running check
 * just before the shutdown cannot create a worker behind Exit()'s join.
 *
 * The claim also serialises the OBJECTS that outlive the Thread: the hit list, the
 * baseline store and the published mapping/region views.  ScanBegin()'s destructive
 * phase (baselineDiscard, hit-list free/re-init, view republish), Reset()'s free and
 * Exit()'s teardown all free or replace them, so each of them holds the claim across
 * that work - not only around the join:
 *
 *   - only the claim holder frees/replaces those objects, so no second caller can
 *     free the same block again (the double free this section used to allow),
 *   - a caller that cannot take the claim LOGS AND LEAVES THE OBJECTS ALONE:
 *     Exit() releases nothing, ScanBegin() answers BUSY, Reset() is skipped.  That
 *     is a leak at shutdown, never a free under a live owner - the same trade-off
 *     ptrScanClaimSlot() makes at server exit.
 *
 * Init() resets both, because Exit() may be followed by a fresh Init().
 */
static atomic_bool g_ScanThreadClaim;
static atomic_bool g_SessionExited;

/* ---- target identity ---------------------------------------------------
 *
 * pid / program_id / main_base / main_size describe ONE process: every
 * main-relative scope, hit address and cheat export is derived from them, and
 * "new pid + old main range" is a target that does not exist.  They used to be
 * four plain fields in g_Session, written one after another, so a reader on
 * another thread (Status, the 1 Hz identity tick, an address normaliser) could
 * copy the pid from one write and the main range from the next.  With a reused
 * pid such a blend can even pass an ownership check that should fail.
 *
 * g_IdentitySeq is a dedicated seqlock for these four fields (same shape as
 * g_ViewSeq, but its own counter: the identity is written far more often than the
 * views and must not make a view sample retry):
 *
 *   - even  => g_Identity is a complete, stable publication,
 *   - odd   => a write is in flight; readers retry.
 *
 * The writer bumps the counter (release), stores all four fields + generation,
 * then bumps it again (release).  The reader samples it (acquire), rejects odd
 * values, copies the struct, puts an ACQUIRE FENCE between the copy and the
 * re-check (an acquire load only keeps LATER accesses after itself, so without
 * the fence the copy could be moved past the re-check and a torn snapshot would
 * be accepted), and compares: an unchanged even value means the copy is one
 * publication.
 *
 * Writers serialize on g_IdentityWriting, because nxusSessionRefreshIdentity()
 * runs both on the main-thread tick and on the connection thread (ForceOpen,
 * revalidate).  Two writers inside the odd/even sequence would interleave it back
 * into an apparently stable state in the middle of a write.  It is an
 * atomic_flag (statically initialised, works even before nxusSessionInit) rather
 * than a Mutex, because an identity write is allowed before/without a live
 * session; the holder only ever does a handful of stores, and the waiter yields
 * so it cannot starve a lower-priority holder.
 */
#define NXUS_IDENTITY_RETRY 8u

static NxusTargetIdentity g_Identity;          /* published copy (seqlock) */
static atomic_uint        g_IdentitySeq;       /* even = stable, odd = writing */
static atomic_flag        g_IdentityWriting = ATOMIC_FLAG_INIT;

/* Publish a complete identity as one seqlock write.  The generation inside the
   snapshot is bumped here, so every publication is distinguishable and a reader
   can tell "same target" from "two different targets sharing a field". */
static void identityPublish(u64 pid, u64 program_id, u64 main_base, u64 main_size) {
    while (atomic_flag_test_and_set_explicit(&g_IdentityWriting, memory_order_acquire)) {
        svcSleepThread(0);   /* let the (possibly lower priority) writer finish */
    }
    (void)atomic_fetch_add_explicit(&g_IdentitySeq, 1u, memory_order_release);  /* odd */
    g_Identity.pid = pid;
    g_Identity.program_id = program_id;
    g_Identity.main_base = main_base;
    g_Identity.main_size = main_size;
    g_Identity.generation = g_Identity.generation + 1u;
    (void)atomic_fetch_add_explicit(&g_IdentitySeq, 1u, memory_order_release);  /* even */
    atomic_flag_clear_explicit(&g_IdentityWriting, memory_order_release);
}

bool nxusSessionTargetIdentity(NxusTargetIdentity *out) {
    for (u32 attempt = 0; attempt < NXUS_IDENTITY_RETRY; attempt++) {
        const u32 seq = atomic_load_explicit(&g_IdentitySeq, memory_order_acquire);
        if ((seq & 1u) != 0) continue;              /* write in flight */

        NxusTargetIdentity snap = g_Identity;       /* plain field copies */

        /* Load/load barrier: without it the copy above could be reordered past the
           re-check below and a torn snapshot accepted (see the block above). */
        atomic_thread_fence(memory_order_acquire);
        if (atomic_load_explicit(&g_IdentitySeq, memory_order_acquire) != seq) continue;

        if (out != NULL) *out = snap;
        return true;
    }
    return false;   /* kept losing the race: no torn value, the caller decides */
}

/* Blocking sample for the in-module readers: the ownership checks are boolean and
   must not turn "a writer was mid-publish" into "different target".  The writer
   never waits on a reader and only holds the seqlock for a few stores, so this
   cannot livelock; the yield keeps a preempted writer runnable. */
static NxusTargetIdentity identitySample(void) {
    NxusTargetIdentity id;
    while (!nxusSessionTargetIdentity(&id)) svcSleepThread(0);
    return id;
}

/* ---- result ownership --------------------------------------------------
 *
 * hits and the mapping snapshot are keyed to the process they were taken from.
 * ForceOpen to another title, a relaunch (same title, new pid) or a DebugAttach to
 * a different process leaves every address and mapping_idx in them pointing at a
 * process that is gone - or at the NEW one at the same numeric address, which looks
 * perfectly valid to the PC.  The pointer-scan chain list already refuses to hand
 * out a list from an earlier target (ptrChainOwnerCheck in nxus_server.c); the hit
 * list records its owner here and answers the same question.
 *
 * The owner also carries the mapping-table generation: mapping_idx is an ordinal
 * into the snapshot, so a re-snapshot of the SAME target can move it to another
 * region (see the mapping-generation block below).  Identity and generation are
 * compared together by nxusSessionHitsMatchTarget().
 *
 * g_HitsStale is the "discarded, not replaced yet" latch.  Invalidating must not
 * free the hit arrays (the connection thread may be walking them inside sendHits),
 * so the discarded list stays allocated and every accessor refuses to serve it until
 * ScanBegin stamps a new one.
 */
static atomic_int g_HitsStale;

static bool hitsStale(void) {
    return atomic_load_explicit(&g_HitsStale, memory_order_acquire) != 0;
}

/* ---- mapping-table generation ------------------------------------------
 *
 * A hit does not carry an address: it carries mapping_idx - an ORDINAL into the
 * mapping snapshot - plus an offset inside that mapping, and the PC resolves it as
 * mapping_bases[mapping_idx] + offset.  The snapshot is replaced on every
 * re-snapshot (ScanBegin, nxusSessionRefreshMappings(), a failed dmnt query that
 * drops it), and the new walk is not guaranteed to list mappings in the same order:
 * a mapping that split, merged or disappeared between the two walks shifts every
 * later index.  The SAME title therefore hands back a table in which the stored
 * mapping_idx still "resolves" - just to a different region, i.e. a silently wrong
 * address that no range check on the PC side can catch.
 *
 * The counter below is bumped every time the published table is actually swapped
 * (mappingSnapshotPublish / mappingSnapshotDrop).  ScanBegin stamps the generation
 * of the table its own snapshot just published into the hit owner (hitsOwnerStamp),
 * and nxusSessionHitsMatchTarget() compares it again on every read, so a table from
 * another generation makes the list unservable exactly like a target change does
 * (the server's discard path answers BAD_STATE).
 *
 * It must NOT change when entries are revalidated in place: a refine pass
 * (revalidateMappings) updates validity/type in the same array without touching an
 * index, so the stored mapping_idx stays correct and the refine keeps working.
 *
 * Acquire load pairs with the release bump that follows the seqlock publication, so
 * a reader that observes the new generation also observes the new table (or the
 * empty view).  Only the connection thread and the thread-safe
 * nxusSessionInvalidateHits() bump it, and it wraps harmlessly: a wrapped value can
 * only ever alias a generation 2^32 swaps apart, while the owner stamp is cleared on
 * every discard and re-stamped on every scan.
 */
static atomic_uint g_MappingGeneration;

static u32 mappingGenerationLoad(void) {
    return (u32)atomic_load_explicit(&g_MappingGeneration, memory_order_acquire);
}

static void mappingGenerationBump(void) {
    (void)atomic_fetch_add_explicit(&g_MappingGeneration, 1u, memory_order_release);
}

/* Generation of the mapping snapshot currently published, 0 before the first one. */
u32 nxusSessionMappingGeneration(void) {
    return mappingGenerationLoad();
}

/* Remember the identity a freshly armed hit list belongs to.  Callers pass the
   session's own cached identity: ScanBegin refreshes it (cacheProcessInfo) and takes
   the mapping snapshot immediately before stamping, so all three describe the same
   read of the target.  The mapping generation is read HERE, after ScanBegin's
   snapshotMappings() published the table the worker will scan with and before
   startJob() runs it - i.e. it names that table, not one published mid-scan.
   pid and program_id are taken from ONE identity snapshot: two separate accessor
   calls could stamp the pid of one write with the title of the next. */
static void hitsOwnerStamp(void) {
    const NxusTargetIdentity id = identitySample();
    g_Session.hits_owner_pid = id.pid;
    g_Session.hits_owner_program_id = id.program_id;
    g_Session.hits_owner_session_id = g_Session.session_id;
    g_Session.hits_owner_mapping_generation = mappingGenerationLoad();
    g_Session.hits_owner_valid = true;
}

/* No list is tied to a target any more (Reset): nothing to compare, nothing to
   refuse. */
static void hitsOwnerClear(void) {
    g_Session.hits_owner_valid = false;
}

/* Guards double initialisation.  A second nxusSessionInit() must not memset a
   live session (see the lifecycle section).  Declared up here because the view
   pin API refuses to hand out a token outside a live session. */
static bool g_Inited;

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
 * before the block is released, so a reader that loses the race anywhere still
 * sees either the old view or an explicitly empty one, never a pointer into
 * memory that is already back in the allocator.
 *
 * Writers are the publish / drop / buildRegions calls; they share a single seqlock
 * counter, and g_ViewPublishMutex keeps two writer THREADS out of the pair (see its
 * declaration below).
 *
 * A consistent sample is still only a sample: the block it points at stays the
 * same memory until somebody replaces it.  Callers outside the connection thread
 * (the snapshot service keeps the region list for a whole capture, and any future
 * reader may walk the mapping table) outlive the next publish, so the returned
 * block must not be freed under them.  Two counters make that safe:
 *
 *   - the outstanding view pins (token table + compat counter, see the pin
 *     accounting block below).  A reader pins BEFORE it samples and drops its own
 *     pin when it is done (see the contract in nxus_session.h),
 *   - a writer never frees the block it just replaced: it parks it in
 *     g_ViewRetired[] (4 generations) and frees the ring only when it observes
 *     zero outstanding pins - immediately at retire time or later from the last
 *     unpin/release.
 *
 * A caller that never unpins keeps its pin forever, which is exactly the safe
 * side: the block is retained (never reused by a later publish) and the ring
 * simply fills up, after which further old blocks are kept instead of freed and a
 * log line reports the growing count.  Memory is recoverable at Exit; a
 * use-after-free is not.  The difference from the old single counter is that such
 * a pin is now COUNTABLE (nxusSessionViewPinnedCount) and owned by its token, so
 * the leak is detected and one caller's stray unpin cannot absorb another's pin.
 */
#define NXUS_VIEW_RETRY 8u
/* Retired blocks kept while a pin is outstanding.  A publish happens once per
   scan / snapshot and a reader holds its pin for one request, so four generations
   are never actually needed - the ring is a safety valve, not a queue. */
#define NXUS_VIEW_RETIRE_MAX 4u
/* Identified pins (NxusViewPin) that can be outstanding at once.  One request
   holds one, and at most the connection thread, the snapshot service and a test
   overlap, so eight is a generous ceiling; running out is a bug that
   nxusSessionViewPinnedCount() exposes, not a normal condition. */
#define NXUS_VIEW_PIN_MAX 8u

static atomic_uint g_ViewSeq;

/* ---- pin accounting ----------------------------------------------------
 *
 * A pin is what keeps a retired block alive.  There are two kinds, and the whole
 * point of the token API is that one kind is OWNED:
 *
 *   - identified pins (token table, NXUS_VIEW_PIN_MAX entries): taken by
 *     nxusSessionViewPinCurrent(), dropped by nxusSessionViewUnpin() after its
 *     id/generation matched.  Only the owner can drop one, so a stray unpin can no
 *     longer consume somebody else's pin, and a pin left behind is countable
 *     (nxusSessionViewPinnedCount).
 *   - compat pins: the anonymous pin nxusSessionMappings()/nxusSessionRegions()
 *     still take and nxusSessionViewRelease() still drops, so existing callers
 *     keep working unchanged.  They are counted separately because they are
 *     anonymous by definition: a compat caller that never releases is the old
 *     documented "safe leak", and it must not be able to exhaust the eight token
 *     slots (it would then also lose its own memory safety).
 *
 * A block is handed back to the allocator only while BOTH counts are zero.
 */
static atomic_uint g_ViewLegacyPins;   /* compat pins (anonymous) */

typedef struct {
    u32 id;            /* 0 = free slot; ids are monotonic and never reused */
    u32 generation;    /* view publication this pin was taken in */
} NxusViewPinSlot;

static NxusViewPinSlot g_ViewPins[NXUS_VIEW_PIN_MAX];
static u32 g_ViewPinnedCount;          /* occupied token slots */
static u32 g_ViewPinNextId = 1;        /* 0 is "no pin", so it is skipped */

typedef struct {
    void *block;
    const char *kind;      /* "mappings" / "regions", for diagnostics */
} NxusRetiredView;

static NxusRetiredView g_ViewRetired[NXUS_VIEW_RETIRE_MAX];
static u32  g_ViewRetiredCount;
static u64  g_ViewLeaked;            /* blocks kept alive past the ring (never freed) */
/* Guards the ring, the token table and g_ViewPinnedCount.  The writers live on the
   server thread, but a release/unpin may run on a reader thread and drain it, and
   the pin count it tests must be the same one the table tracks. */
static Mutex g_ViewRetireMutex;
static bool  g_ViewRetireInited;

/* Serialises the two published views across WRITER THREADS.  Every publish used to
   come from the connection thread, but nxusSessionInvalidateHits() can drop them from
   the main thread (the 1 Hz identity tick) while a handler on the connection thread
   publishes a new snapshot; two writers inside viewUpdateBegin/End would interleave
   the odd/even sequence and a reader could then accept a pair that is being written.
   Readers never take this lock (that is what the seqlock is for), and a writer only
   ever holds it across the two plain stores, so it cannot block a scan. */
static Mutex g_ViewPublishMutex;

static void viewUpdateBegin(void) {
    mutexLock(&g_ViewPublishMutex);
    atomic_fetch_add_explicit(&g_ViewSeq, 1u, memory_order_release);   /* odd */
}

static void viewUpdateEnd(void) {
    atomic_fetch_add_explicit(&g_ViewSeq, 1u, memory_order_release);   /* even */
    mutexUnlock(&g_ViewPublishMutex);
}

/* Outstanding pins of both kinds.  Caller holds g_ViewRetireMutex: the token count
   is guarded by it, and testing it together with the atomic compat count is what
   makes "the last pin is gone" a single decision. */
static u32 viewReaderCountLocked(void) {
    return g_ViewPinnedCount +
           atomic_load_explicit(&g_ViewLegacyPins, memory_order_acquire);
}

static u32 viewReaderCount(void) {
    if (!g_ViewRetireInited) return 0;
    mutexLock(&g_ViewRetireMutex);
    const u32 count = viewReaderCountLocked();
    mutexUnlock(&g_ViewRetireMutex);
    return count;
}

/* Publication generation: one increment per publish/drop cycle (g_ViewSeq counts
   the two halves of the seqlock).  A token records it so a pin can never be
   mistaken for one taken in another publication or another session. */
static u32 viewGeneration(void) {
    return atomic_load_explicit(&g_ViewSeq, memory_order_acquire) / 2u;
}

/* Take a compat pin before touching the published pair, so a writer that retires
   the block can never observe zero readers while this one is sampling. */
static void viewPinLegacy(void) {
    atomic_fetch_add_explicit(&g_ViewLegacyPins, 1u, memory_order_acq_rel);
}

/* Drop one compat pin.  An unmatched extra release used to be clamped to zero
   silently - and that clamp is exactly what hid "a stray release silently ate a
   live pin".  It still cannot underflow (that would disable retirement for the
   rest of the session), but it is no longer silent. */
static void viewReleaseLegacy(void) {
    u32 cur = atomic_load_explicit(&g_ViewLegacyPins, memory_order_acquire);
    while (cur > 0) {
        if (atomic_compare_exchange_weak_explicit(&g_ViewLegacyPins, &cur, cur - 1u,
                                                  memory_order_acq_rel,
                                                  memory_order_acquire)) {
            return;
        }
    }
    NXUS_LOG("view: release with no compat pin outstanding - ignored "
             "(an extra release must not eat another caller's pin)");
}

/* Caller holds g_ViewRetireMutex.  Hands out one token slot; ids are monotonic, so
   a token that was dropped (or belongs to an earlier session) never matches a
   live slot again. */
static bool viewPinTokenLocked(NxusViewPin *out) {
    u32 slot = NXUS_VIEW_PIN_MAX;
    for (u32 i = 0; i < NXUS_VIEW_PIN_MAX; i++) {
        if (g_ViewPins[i].id == 0) { slot = i; break; }
    }
    if (slot == NXUS_VIEW_PIN_MAX) return false;

    u32 id = g_ViewPinNextId++;
    if (id == 0) id = g_ViewPinNextId++;      /* 0 is the "no pin" id */
    g_ViewPins[slot].id = id;
    g_ViewPins[slot].generation = viewGeneration();
    g_ViewPinnedCount++;
    out->id = id;
    out->generation = g_ViewPins[slot].generation;
    return true;
}

/* Caller holds g_ViewRetireMutex.  Index of the live slot `pin` names, or -1. */
static int viewPinSlotLocked(const NxusViewPin *pin) {
    if (pin == NULL || pin->id == 0) return -1;
    for (u32 i = 0; i < NXUS_VIEW_PIN_MAX; i++) {
        if (g_ViewPins[i].id == pin->id && g_ViewPins[i].generation == pin->generation) {
            return (int)i;
        }
    }
    return -1;
}

static bool viewPinIsLive(const NxusViewPin *pin) {
    if (!g_ViewRetireInited || pin == NULL || pin->id == 0) return false;
    mutexLock(&g_ViewRetireMutex);
    const bool live = viewPinSlotLocked(pin) >= 0;
    mutexUnlock(&g_ViewRetireMutex);
    return live;
}

/* Caller holds g_ViewRetireMutex.  Re-checks the pin counts under the lock: a
   reader may have pinned between the caller's first observation and the lock, and
   its pin is what keeps the ring blocks reachable. */
static void viewDrainLocked(void) {
    if (viewReaderCountLocked() != 0) return;
    for (u32 i = 0; i < g_ViewRetiredCount; i++) {
        free(g_ViewRetired[i].block);
        g_ViewRetired[i].block = NULL;
        g_ViewRetired[i].kind = NULL;
    }
    g_ViewRetiredCount = 0;
}

static void viewDrainIfUnpinned(void) {
    if (!g_ViewRetireInited) return;
    mutexLock(&g_ViewRetireMutex);
    viewDrainLocked();
    mutexUnlock(&g_ViewRetireMutex);
}

/* Park a block that was just unpublished.  It is freed right away when nobody
   pins a view; otherwise it waits in the ring for the last release. */
static void viewRetire(void *block, const char *kind) {
    if (block == NULL) return;
    if (!g_ViewRetireInited) { free(block); return; }

    /* Store-load barrier: the publication above (new pointer + count, then the
       even g_ViewSeq) is complete, and this makes it visible before the pin count
       is inspected below.  A reader that is not counted as pinned therefore cannot
       still be looking at the block being retired.  (The seqlock still does the
       consistency work; this fence only orders "published" against "freed".) */
    atomic_thread_fence(memory_order_seq_cst);

    mutexLock(&g_ViewRetireMutex);
    if (g_ViewRetiredCount == NXUS_VIEW_RETIRE_MAX) {
        /* Ring full: keep the block instead of freeing it under a live reader, i.e.
           a leak rather than a use-after-free.  Logged at the first overflow and
           then every 64 blocks, so a caller that never releases its pins shows up
           as a growing count instead of a silent heap exhaustion. */
        g_ViewLeaked++;
        const bool log = (g_ViewLeaked == 1u) || ((g_ViewLeaked % 64u) == 0u);
        const u64 leaked = g_ViewLeaked;
        const u32 pins = viewReaderCountLocked();
        mutexUnlock(&g_ViewRetireMutex);
        if (log) {
            NXUS_LOG("view: retire ring full (%u blocks, %u pin(s), %llu kept alive) - "
                     "not freeing the old %s block under a reader",
                     (unsigned)NXUS_VIEW_RETIRE_MAX, (unsigned)pins,
                     (unsigned long long)leaked, kind);
        }
        return;
    }
    g_ViewRetired[g_ViewRetiredCount].block = block;
    g_ViewRetired[g_ViewRetiredCount].kind = kind;
    g_ViewRetiredCount++;
    viewDrainLocked();
    mutexUnlock(&g_ViewRetireMutex);
}

/* ---- token API --------------------------------------------------------- */

/* Exit is terminal for views, so every token (and the compat count) describes a
   publication that no longer exists.  They are dropped here instead of being
   carried into the next session: a caller that unpins afterwards gets a logged
   no-op, and nxusSessionViewPinnedCount() starts from zero again. */
static void viewPinsInvalidate(void) {
    if (!g_ViewRetireInited) return;
    mutexLock(&g_ViewRetireMutex);
    memset(g_ViewPins, 0, sizeof(g_ViewPins));
    g_ViewPinnedCount = 0;
    atomic_store_explicit(&g_ViewLegacyPins, 0u, memory_order_release);
    mutexUnlock(&g_ViewRetireMutex);
}

bool nxusSessionViewPinCurrent(NxusViewPin *out) {
    if (out == NULL) return false;
    out->id = 0;
    out->generation = 0;
    if (!g_ViewRetireInited || !g_Inited) {
        NXUS_LOG("view: pin requested outside a live session - refused");
        return false;
    }

    mutexLock(&g_ViewRetireMutex);
    const bool okay = viewPinTokenLocked(out);
    mutexUnlock(&g_ViewRetireMutex);

    if (!okay) {
        /* Every slot is taken: somebody holds NXUS_VIEW_PIN_MAX pins at once, which
           is a missing unpin somewhere.  Refusing (instead of handing out an
           unowned pin) keeps that detectable. */
        NXUS_LOG("view: pin table full (%u pins outstanding) - pin refused, "
                 "nxusSessionViewPinnedCount() reports the leak",
                 (unsigned)NXUS_VIEW_PIN_MAX);
    }
    return okay;
}

void nxusSessionViewUnpin(NxusViewPin *pin) {
    if (pin == NULL) return;

    /* Consume the token first: whatever this call decides, a second unpin of the
       same variable finds id 0 and cannot touch anything. */
    const u32 id = pin->id;
    const u32 generation = pin->generation;
    pin->id = 0;
    pin->generation = 0;

    if (id == 0) {
        NXUS_LOG("view: unpin of an empty token (double unpin) - ignored");
        return;
    }
    if (!g_ViewRetireInited) {
        NXUS_LOG("view: unpin of id=%u after Exit - ignored", (unsigned)id);
        return;
    }

    NxusViewPin probe;
    probe.id = id;
    probe.generation = generation;

    mutexLock(&g_ViewRetireMutex);
    const int slot = viewPinSlotLocked(&probe);
    if (slot < 0) {
        mutexUnlock(&g_ViewRetireMutex);
        /* Not a live pin: a foreign token, or one from before the last Exit.  Never
           decrement anything - that is how an extra unpin used to eat a live pin. */
        NXUS_LOG("view: unpin of a foreign/stale token (id=%u gen=%u) - ignored",
                 (unsigned)id, (unsigned)generation);
        return;
    }

    g_ViewPins[slot].id = 0;
    g_ViewPins[slot].generation = 0;
    if (g_ViewPinnedCount > 0) g_ViewPinnedCount--;
    viewDrainLocked();          /* this may have been the last pin: free the ring */
    mutexUnlock(&g_ViewRetireMutex);
}

u32 nxusSessionViewPinnedCount(void) {
    return viewReaderCount();
}

/* Release the compat pin taken by a successful nxusSessionMappings()/Regions()
   call and free the ring if this was the last reader. */
void nxusSessionViewRelease(void) {
    viewReleaseLegacy();
    viewDrainIfUnpinned();
}

/* Exit is terminal for views: hand every retained block back even when a caller
   never released its pin, because Exit invalidates every pointer handed out
   before it (nxus_session.h). */
static void viewRetireFlush(void) {
    if (!g_ViewRetireInited) return;
    mutexLock(&g_ViewRetireMutex);
    for (u32 i = 0; i < g_ViewRetiredCount; i++) {
        free(g_ViewRetired[i].block);
        g_ViewRetired[i].block = NULL;
        g_ViewRetired[i].kind = NULL;
    }
    g_ViewRetiredCount = 0;
    mutexUnlock(&g_ViewRetireMutex);
}

static void mappingSnapshotDrop(void) {
    NxusMappingEntry *old;
    viewUpdateBegin();
    /* The block being replaced is captured INSIDE the writer lock.  Reading it
       before viewUpdateBegin() made "which block did this writer replace?" two
       independent samples: e.g. Exit() on the main thread and a disconnect/target
       change dropping the table on the connection thread both saw the same pointer
       and both handed it to viewRetire() - a double free.  Under the lock exactly
       one writer sees (and therefore retires) each publication: the second one
       already observes NULL or the first writer's block. */
    old = g_Session.map_entries;
    g_Session.maps.entries = NULL;
    g_Session.maps.count = 0;
    g_Session.map_entries = NULL;
    viewUpdateEnd();
    /* An empty table is still a different table: no stored mapping_idx can resolve
       through it any more, so the hits stamped against the old one are unservable. */
    mappingGenerationBump();
    /* Retiring stays outside: viewRetire() takes g_ViewRetireMutex, and the publish
       lock is documented to cover only the plain stores.  Release is safe here
       because this writer owns `old` exclusively (captured above). */
    viewRetire(old, "mappings");
}

/* Cheap fingerprint of a mapping table: count plus an order-independent mix of
   every (base, size).  Re-snapshotting an unchanged process (ptrscan and
   SnapshotCapture both refresh the table) must NOT invalidate the hits: their
   mapping_idx still resolves to the very same regions. */
static u64 mappingFingerprint(const NxusMappingEntry *entries, u32 count) {
    u64 mix = 0x9E3779B97F4A7C15ull ^ (u64)count;
    for (u32 i = 0; i < count; i++) {
        const u64 v = entries[i].base ^ (entries[i].size << 1);
        mix ^= v + 0x9E3779B97F4A7C15ull + (mix << 6) + (mix >> 2);
    }
    return mix;
}

static atomic_ullong g_MappingFingerprint;

static void mappingSnapshotPublish(NxusMappingEntry *entries, u32 count) {
    NxusMappingEntry *old;
    const u64 fingerprint = mappingFingerprint(entries, count);
    const u64 previous =
        atomic_load_explicit(&g_MappingFingerprint, memory_order_acquire);
    viewUpdateBegin();
    /* Captured under the writer lock, like mappingSnapshotDrop(): two writers must
       never both sample the same previous block and both retire it. */
    old = g_Session.map_entries;
    g_Session.map_entries = entries;
    g_Session.maps.entries = entries;
    g_Session.maps.count = count;
    viewUpdateEnd();
    /* Only a CONTENT change invalidates stored mapping_idx values.  Bumping on every
       re-snapshot made a plain ptrscan or snapshot capture discard a perfectly good
       hit list (the server answered BAD_STATE for work that had not changed). */
    atomic_store_explicit(&g_MappingFingerprint, fingerprint, memory_order_release);
    if (fingerprint != previous) mappingGenerationBump();
    viewRetire(old, "mappings");
}

static void regionListDrop(void) {
    NxusScanRegion *old;
    viewUpdateBegin();
    /* Same rule as mappingSnapshotDrop(): the replaced block is sampled under the
       writer lock, so two writers (connection-thread drop vs. a concurrent publish)
       can never retire the same region list twice. */
    old = g_Session.regions;
    g_Session.regions = NULL;
    g_Session.region_count = 0;
    viewUpdateEnd();
    viewRetire(old, "regions");
}

/* Publish a freshly built list (buildRegions) as one pair, never as a pointer
   without its count. */
static void regionListPublish(NxusScanRegion *regions, u32 count) {
    NxusScanRegion *old;
    viewUpdateBegin();
    /* Captured under the writer lock (see mappingSnapshotPublish). */
    old = g_Session.regions;
    g_Session.regions = regions;
    g_Session.region_count = count;
    viewUpdateEnd();
    viewRetire(old, "regions");
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
 *     be opened (no SD inserted, read-only card, ...), when the scoped range is
 *     small enough that writing a file would cost more than the memory
 *     (<= 512 KB), or when statvfs proves the card cannot hold the stream with
 *     1.5x headroom (a store that fills up mid-scan loses blocks silently).
 *
 * Offsets are absolute positions in the store; the engine hands each block the
 * offset it was assigned, so a plain fseek covers the sparse layout.
 *
 * Health: a failed write is counted in g_Session.baseline_write_failed, logged
 * once, folded into stats.write_failed and published through
 * nxusSessionBaselineWriteFailed() / nxusSessionBaselineDegraded(), so a short
 * candidate list caused by the store is distinguishable from an empty target.
 */
#define NXUS_BASELINE_RAM_MAX   (512u * 1024u)
#define NXUS_BASELINE_FILE_BUF  (64u * 1024u)
/* Refine buffers: at least one whole block, and never below 64 KB so a future
   smaller block size still gets a decent read size. */
#define NXUS_BASELINE_BUF_MIN   (64u * 1024u)

static FILE *g_BaseFile = NULL;
static u8   *g_BaseRam = NULL;
static u64   g_BaseRamSize = 0;
/* Ordinal of the next store write.  The engine writes exactly one block per
   non-zero, storable block, so this is the block number the failure line names. */
static u32   g_BaseWriteSeq = 0;
static u8    g_BaseFileBuf[NXUS_BASELINE_FILE_BUF] __attribute__((aligned(0x10)));

/* Record one failing store write.  The engine turns that block into
   NXUS_BBLOCK_UNREADABLE and bumps stats->dropped like any unreadable block, so
   without this counter a card that is full / unplugged mid-scan looks exactly
   like "the target had few candidates".  The FIRST failure is logged (a failing
   card would otherwise emit one line per block); every failure is counted. */
static void baselineWriteFailure(u32 block, int err) {
    g_Session.baseline_write_failed++;
    g_Session.baseline_degraded = true;
    if (!g_Session.baseline_write_logged) {
        g_Session.baseline_write_logged = true;
        NXUS_LOG("baseline: write failed at block %u (errno=%d) - SD streaming degraded to RAM/skip",
                 (unsigned)block, err);
    }
}

static int baselineStoreWrite(void *ctx, u64 offset, const void *buf, u32 len) {
    (void)ctx;
    if (len == 0) return 0;
    const u32 block = g_BaseWriteSeq++;
    errno = 0;
    int failed;
    if (g_BaseFile != NULL) {
        if (fseek(g_BaseFile, (long)offset, SEEK_SET) != 0) {
            failed = 1;
        } else {
            failed = (fwrite(buf, 1, len, g_BaseFile) == len) ? 0 : 1;
        }
    } else if (g_BaseRam == NULL || offset > g_BaseRamSize || (u64)len > g_BaseRamSize - offset) {
        failed = 1;
    } else {
        memcpy(g_BaseRam + offset, buf, len);
        failed = 0;
    }
    if (failed) {
        baselineWriteFailure(block, errno ? errno : EIO);
        return -1;
    }
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
        /* A buffered stream can surface a card error only at flush time: the last
           (< 64 KB) writes still sit in the stdio buffer when the stream closes,
           so a card that filled up near the end of the scan would otherwise look
           like a clean run.  Only the FLUSH result is checked, never ferror():
           ferror() also reflects a failed READ from the refine pass, which is not
           a write failure and is reported as dropped_reads instead. */
        errno = 0;
        int flush_err = (fflush(g_BaseFile) != 0) ? (errno ? errno : EIO) : 0;
        if (fclose(g_BaseFile) != 0 && flush_err == 0) {   /* also flushes */
            flush_err = errno ? errno : EIO;
        }
        g_BaseFile = NULL;
        if (flush_err != 0) baselineWriteFailure(g_BaseWriteSeq, flush_err);
    }
    free(g_BaseRam);
    g_BaseRam = NULL;
    g_BaseRamSize = 0;
}

/* Does the card hold the whole stream with room to spare?  `needed` is the upper
   bound of the dump (see baselineStoreOpen).  A failing probe must NOT disable SD
   streaming on its own - only a PROVEN shortage falls back to the RAM buffer.
   Returns false only when statvfs succeeded and reported less than 1.5x `needed`
   free, in which case the caller takes the RAM branch (and its own failure path,
   which ends in the classic first pass when the range does not fit in RAM). */
static bool baselineSdHasRoom(u64 needed) {
    struct statvfs vfs;
    if (statvfs(NXUS_SESSION_BASELINE_DIR, &vfs) != 0) {
        NXUS_LOG("baseline: free-space probe on %s failed (errno=%d) - trying the SD store",
                 NXUS_SESSION_BASELINE_DIR, errno);
        return true;
    }
    const u64 unit  = vfs.f_frsize ? (u64)vfs.f_frsize : (u64)vfs.f_bsize;
    const u64 avail = (u64)vfs.f_bavail * unit;

    /* 1.5x leaves the card usable while the scan runs (log file, snapshots) and
       keeps the stream from failing near the end, where every lost block is a
       silently missing candidate. */
    u64 required = needed + needed / 2u;
    if (required < needed) required = 0xFFFFFFFFFFFFFFFFull;   /* overflow clamp */

    if (avail < required) {
        NXUS_LOG("baseline: only %llu MiB free of %llu MiB needed - using the RAM buffer",
                 (unsigned long long)(avail / (1024ull * 1024ull)),
                 (unsigned long long)(required / (1024ull * 1024ull)));
        return false;
    }
    return true;
}

/* Open a store able to hold every non-zero block of the current region list. */
static bool baselineStoreOpen(void) {
    baselineStoreClose();
    remove(NXUS_SESSION_BASELINE_PATH);
    g_BaseWriteSeq = 0;

    const u64 region_bytes = baselineRegionBytes();
    if (region_bytes == 0) return false;

    if (region_bytes > NXUS_BASELINE_RAM_MAX) {
        /* The dump can only grow to the last byte the u32 store offset can name,
           so a range beyond 4 GiB does not need 1.5x of its full size: the stream
           is capped there (blocks past it are dropped by the engine). */
        u64 needed = region_bytes;
        if (needed > 0xFFFFFFFFull) needed = 0xFFFFFFFFull;
        if (!baselineSdHasRoom(needed)) {
            /* Proven shortage: skip the SD stream entirely instead of filling the
               card / failing write by write.  Mark it so the client can tell this
               scan is running on the reduced (RAM or classic) baseline. */
            g_Session.baseline_degraded = true;
        } else {
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
    /* The health counters describe the baseline that just went away: clearing
       them here keeps a later classic hit-list scan from inheriting an earlier
       Unknown scan's degraded state.  A refine pass that just consumed the
       baseline does NOT go through here, so its report stays readable. */
    g_Session.baseline_write_failed = 0;
    g_Session.baseline_write_logged = false;
    g_Session.baseline_degraded = false;
    g_BaseWriteSeq = 0;
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

/* (g_Inited is declared above: the view pin API has to know whether a session is
   live before it hands out a token.) */

/* Join and close the worker Thread.  The caller must hold g_ScanThreadClaim (see
   the slot block at the top of this file).  Returns true when a worker was
   actually reaped. */
static bool scanThreadJoinLocked(void) {
    if (!g_Session.thread_live) return false;
    threadWaitForExit(&g_Session.thread);
    threadClose(&g_Session.thread);
    g_Session.thread_live = false;
    return true;
}

/* Take the worker Thread slot for one of the sequences listed in the slot block.
   Bounded wait instead of an endless one: the holder only sits in a worker join
   plus threadCreate()/threadStart(), never in an IPC, and a scan that has to wait
   for a shutting-down session is better answered BUSY than blocked. */
static bool scanThreadClaim(u32 spin_ms) {
    for (u32 waited = 0; ; waited += 1u) {
        bool expected = false;
        if (atomic_compare_exchange_strong_explicit(&g_ScanThreadClaim, &expected, true,
                                                    memory_order_acq_rel, memory_order_acquire)) {
            return true;
        }
        if (waited >= spin_ms) return false;
        svcSleepThread(1000000ull);
    }
}

static void scanThreadRelease(void) {
    atomic_store_explicit(&g_ScanThreadClaim, false, memory_order_release);
}

void nxusSessionInit(u32 chunk_size, u32 max_hits) {
    if (g_Inited) return;      /* already initialised: keep the live session */
    mutexInit(&g_SessionMutex);
    mutexInit(&g_ViewRetireMutex);
    /* Before any publish/drop can run (they are all behind a live session). */
    mutexInit(&g_ViewPublishMutex);
    memset(&g_Session, 0, sizeof(g_Session));
    /* No worker exists at boot, and Init() after Exit() starts a new session:
       both halves of the worker-slot protocol start free (see the slot block). */
    atomic_init(&g_ScanThreadClaim, false);
    atomic_init(&g_SessionExited, false);
    atomic_init(&g_Session.state, NxusScanState_Idle);
    atomic_init(&g_Session.cancel, 0);
    atomic_init(&g_ViewSeq, 0);   /* both published views start empty/stable */
    atomic_init(&g_HitsStale, 0); /* no results to discard in a fresh session */
    /* A fresh session has no target: publish the empty identity (generation 0) as one
       seqlock write so no reader can pair "zero pid" with a previous session's main
       range.  Init runs before the server / identity tick exist, so this cannot race
       a writer; g_IdentityWriting is left as-is (it is statically cleared). */
    memset(&g_Identity, 0, sizeof(g_Identity));
    atomic_init(&g_IdentitySeq, 0);
    /* A fresh session starts with no pins and an empty retire ring: Exit() freed
       every block it knew about and invalidated every token, and the published
       views are gone with the memset above (see the view contract in
       nxus_session.h).  g_ViewPinNextId is deliberately NOT reset: ids stay
       monotonic across sessions so a token from an earlier session can never name
       a live pin of this one. */
    atomic_init(&g_ViewLegacyPins, 0);
    memset(g_ViewPins, 0, sizeof(g_ViewPins));
    g_ViewPinnedCount = 0;
    g_ViewRetiredCount = 0;
    g_ViewLeaked = 0;
    g_ViewRetireInited = true;
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

    /* Shutdown gate first: a startJob()/ScanBegin() that is about to take the slot
       re-checks this under the claim instead of creating a worker behind the join
       below. */
    atomic_store_explicit(&g_SessionExited, true, memory_order_release);

    nxusSessionScanCancel();
    /* Everything this function frees - the hit list, the baseline store, both
       published views and the retire ring behind them - is also freed or replaced
       by the claim holder: startJob()'s worker reaps and a concurrent Reset() (its
       free) or ScanBegin() (baselineDiscard / hit-list re-init / view republish) do
       it under this same claim.  Freeing outside it meant Exit() could free the very
       block the owner was already freeing: a double free.  So the whole teardown -
       join -> close -> free -> release - runs under the claim, and there is no
       "join failed, keep freeing anyway" path left.  The wait stays bounded: the
       holder may be inside ScanBegin()'s mapping snapshot (a dmnt IPC), and a
       shutdown that is already gated may not block on it forever. */
    if (!scanThreadClaim(2000)) {
        /* Reset()/ScanBegin() (or a startJob() they called) owns the claim and is
           inside those objects.  No join can prove it is done, and touching the
           Thread/objects here is exactly the double free/close the claim exists to
           prevent.  So: release nothing, log it, and leave the memory to the
           process - the same trade-off ptrScanClaimSlot() makes at server exit.
           g_Inited stays true on purpose: a later Exit() retries the claim instead
           of making the leak permanent, and g_SessionExited (already up) keeps every
           begin/startJob out in the meantime, so nothing can be re-created behind
           this call.  The published views are left in place here (not unpublished);
           the server reaches Exit() only after it drained the handlers and gated new
           ones, so nothing but the claim holder can still touch them. */
        NXUS_LOG("scan: worker slot still claimed at exit - session NOT released "
                 "(its owner may still free/read the hit list, baseline and views; "
                 "the process is exiting)");
        return;
    }

    /* A startJob() that took the slot just before g_SessionExited became visible
       may have started a worker AFTER the cancel above was ignored (startJob()
       clears the flag).  Re-issue it under the claim so the join is bounded by the
       worker's own read loop, not by a whole scan. */
    nxusSessionScanCancel();
    if (scanThreadJoinLocked()) {
        NXUS_LOG("scan: worker joined and closed (session exit)");
    }

    nxusHitListFree(&g_Session.hits);
    baselineDiscard();
    /* Unpublish through the seqlock before releasing: nxusSessionMappings() /
       nxusSessionRegions() must never hand out a view whose backing block is
       already gone, and must never pair the old pointer with the new count. */
    mappingSnapshotDrop();
    regionListDrop();
    sessionStateStore(NxusScanState_Idle);
    /* Exit is terminal for views, so the retire ring is emptied even when a pin
       was never released: after this point no earlier pointer may be used.  The
       count is the leak report - a non-zero value here means a caller forgot its
       unpin. */
    const u32 pinned = viewReaderCount();
    if (pinned != 0) {
        NXUS_LOG("view: exit with %u unreleased pin(s) - freeing the retire ring "
                 "and invalidating every token",
                 (unsigned)pinned);
    }
    viewRetireFlush();
    viewPinsInvalidate();
    /* The view machinery is dead from here on: a pin/unpin request after Exit is
       refused (and logged) instead of silently taking a token that protects
       nothing, and nxusSessionViewPinnedCount() reports 0 until the next Init. */
    g_ViewRetireInited = false;
    g_Inited = false;
    /* Released last: a begin/reset that waited on the claim runs from here, sees
       g_SessionExited under it and refuses, so it cannot touch what was just
       freed. */
    scanThreadRelease();
}

u32  nxusSessionId(void)            { return g_Session.session_id; }
u32  nxusSessionScanState(void)     { return (u32)sessionStateLoad(); }
u32  nxusSessionProgress(void)      { return g_Session.progress; }
s32  nxusSessionLastResult(void)    { return g_Session.last_result; }
/* Baseline store health (see nxus_session.h): a failing card and a RAM fallback
   are reported here because both only ever showed up as "few candidates". */
u32  nxusSessionBaselineWriteFailed(void) { return g_Session.baseline_write_failed; }
bool nxusSessionBaselineDegraded(void)    { return g_Session.baseline_degraded; }
/* While a baseline is live the hit list is intentionally empty (the first pass
   only fingerprints), so report the candidate count the baseline covered: the
   status then reads "N candidates" instead of "0 hits". */
u32  nxusSessionHitCount(void)      {
    /* A discarded list (see nxusSessionInvalidateHits) is reported empty: Status
       must never advertise hits that ScanGetHits refuses to serve, and those
       candidates belong to the previous target's baseline. */
    if (hitsStale()) return 0;
    if (g_Session.baseline.active) {
        return (g_Session.baseline.candidate_count > 0xFFFFFFFFull)
                   ? 0xFFFFFFFFu : (u32)g_Session.baseline.candidate_count;
    }
    return g_Session.hits.count;
}
u32  nxusSessionMappingCount(void)  { return g_Session.maps.count; }

/* Compat accessors: each one samples the published identity snapshot, so it can
   never pair a value from one write with a value from another.  A caller that needs
   more than one field must use nxusSessionTargetIdentity() - four calls are four
   samples and may straddle a write. */
u64  nxusSessionProcessId(void)     { return identitySample().pid; }
u64  nxusSessionProgramId(void)     { return identitySample().program_id; }
u64  nxusSessionMainBase(void)      { return identitySample().main_base; }
u64  nxusSessionMainSize(void)      { return identitySample().main_size; }

/* Range list for NxusScope_Ranges; copied, truncated to the protocol maximum. */
void nxusSessionSetScanRanges(const NxusRangeEntry *ranges, u32 count) {
    u32 n = (count > NXUS_MAX_SCAN_RANGES) ? NXUS_MAX_SCAN_RANGES : count;
    if (ranges != NULL && n > 0) {
        memcpy(g_Session.ranges, ranges, (size_t)n * sizeof(NxusRangeEntry));
    }
    g_Session.range_count = (ranges == NULL) ? 0 : n;
}

/* Attaching to another process invalidates the identity cached from dmnt: keeping the
   old main base would make every main-relative scan read the wrong process.  All four
   fields are published in ONE seqlock write (generation bumped), so a reader either
   sees the old identity or the new one - never a mixture such as the new pid with the
   old main range. */
void nxusSessionSetProcessIdentityEx(u64 pid, u64 program_id, u64 main_base, u64 main_size) {
    identityPublish(pid, program_id, main_base, main_size);
}

void nxusSessionSetProcessIdentity(u64 pid, u64 main_base, u64 main_size) {
    nxusSessionSetProcessIdentityEx(pid, 0, main_base, main_size);
}

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

/* Identity half of the ownership check (pid / program id / scan generation), shared
   by the full match and by the identity-only variant the main-thread tick uses.  The
   caller has already checked hitsStale() and hits_owner_valid. */
static bool hitsOwnerIdentityMatches(void) {
    /* ONE identity snapshot for both compared fields: sampling the pid and the
       program id separately could compare the stamp against the pid of one write
       and the title of the next (the stamp itself is written from one snapshot). */
    const NxusTargetIdentity id = identitySample();
    if (g_Session.hits_owner_pid != 0) {
        /* Both sides know a pid, so that is the identity.  The program id is only
           compared when BOTH sides have one: an explicit DebugAttach can leave it 0
           (dmnt metadata unavailable then), and refusing the session's own list for
           a missing title would break the scan-then-attach flow - the same rule
           ptrChainOwnerCheck() uses for the chain list. */
        if (g_Session.hits_owner_pid != id.pid) return false;
        const u64 saved_title = g_Session.hits_owner_program_id;
        const u64 now_title = id.program_id;
        return saved_title == 0 || now_title == 0 || saved_title == now_title;
    }

    /* No pid when the scan started (dmnt had no metadata): the scan generation is
       the only per-target token the session publishes, because nxusSessionId()
       changes on every ScanBegin/Reset. */
    return g_Session.hits_owner_session_id == g_Session.session_id;
}

/* Can the retained hit list still be served?  Two independent things have to hold:
   the list must belong to the target the session is on, and it must have been
   stamped against the mapping snapshot that is published now (its mapping_idx is an
   ordinal into THAT table).  See the ownership and mapping-generation blocks at the
   top of this file, and the contract in nxus_session.h. */
bool nxusSessionHitsMatchTarget(void) {
    /* A discarded list is not replaced until a new scan arms one, and it must stay
       refused in the meantime (the arrays are still there, see
       nxusSessionInvalidateHits). */
    if (hitsStale()) return false;
    /* Nothing was ever built for a target: nothing can be stale. */
    if (!g_Session.hits_owner_valid) return true;

    /* The mapping snapshot was replaced after this list was stamped.  mapping_idx is
       an ordinal into that table, so even for the SAME target it now names a
       different region - the addresses would look perfectly valid and be wrong.
       Refusing here is what the server's discard path turns into BAD_STATE. */
    if (g_Session.hits_owner_mapping_generation != mappingGenerationLoad()) return false;

    return hitsOwnerIdentityMatches();
}

/* The identity half of nxusSessionHitsMatchTarget(), without the mapping generation.
   The 1 Hz identity tick uses it: a ScanBegin publishes its table BEFORE it stamps the
   owner (and so do the other re-snapshot call sites, which then use that table in the
   same call).  Acting on the intermediate "new table, old stamp" state would drop the
   very table that command is building; the connection-thread readers
   (fillStatus / sendHits / ScanNext) are serialized with those publications and do
   compare the generation, so nothing is served stale. */
bool nxusSessionHitsMatchTargetIdentity(void) {
    if (hitsStale()) return false;
    if (!g_Session.hits_owner_valid) return true;
    return hitsOwnerIdentityMatches();
}

/* Was the stored list refused ONLY because the table was rebuilt under it?  This
   lets the server name the cause (and both generations) in its log line instead of
   reporting every refusal as a target change.  Returns false for a list that was
   never stamped or is already discarded, so a stale latch does not masquerade as a
   rebuild. */
bool nxusSessionHitsMappingGenerationChanged(u32 *owner_generation, u32 *current_generation) {
    const u32 current = mappingGenerationLoad();
    const bool stamped = g_Session.hits_owner_valid;
    const u32 owner = stamped ? g_Session.hits_owner_mapping_generation : 0;
    if (owner_generation != NULL) *owner_generation = owner;
    if (current_generation != NULL) *current_generation = current;
    if (hitsStale() || !stamped) return false;
    return owner != current;
}

void nxusSessionInvalidateHitsEx(bool drop_tables) {
    /* Publish "unservable" first, so any reader that arrives while the rest of this
       runs already sees the discard. */
    atomic_store_explicit(&g_HitsStale, 1, memory_order_release);
    hitsOwnerClear();

    /* A pass that is still reading the old process must not keep scanning it.  Only
       the cancel flag is touched here: this also runs on the main thread (the 1 Hz
       identity tick), which must not block behind an in-flight chunk read waiting
       for the worker to exit. */
    (void)nxusSessionScanCancel();

    /* While the worker is inside a pass it walks the region list and the mapping
       table WITHOUT a pin, so freeing them here would be a use-after-free.  The
       cancel lands within one chunk; the next call (the server calls this from the
       status path and the tick) drops them then.  Nothing stale is served in the
       meantime: the hits are already refused above. */
    if (sessionStateLoad() == NxusScanState_Running) return;
    /* The main-thread tick passes false: it cannot see a scan that is between
       "snapshot published" and "worker started" (the state still reads Idle), so
       only the connection-thread callers may free these tables. */
    if (!drop_tables) return;

    /* Readers of these views are pin-protected (see the view contract in
       nxus_session.h), so dropping them is safe from any thread. */
    mappingSnapshotDrop();
    regionListDrop();

    /* The results described the discarded list: leaving "Done / N hits" in place
       would make Status report the previous title's work as this target's. */
    g_Session.progress = 0;
    g_Session.last_result = 0;
    sessionStateStore(NxusScanState_Idle);
}

void nxusSessionInvalidateHits(void) {
    nxusSessionInvalidateHitsEx(true);
}

/* Never returns a dangling table: the pair is only readable while g_ViewSeq is
   stable, mappingSnapshotDrop() clears it before the block is retired, and the
   retry loop rejects a sample that raced with an update - so the caller sees
   either one consistent snapshot or an empty view.  Callers must tolerate NULL
   (= no snapshot / after Exit) and must run behind the BUSY gate (the pointer
   scan and the module walk read the array the worker is using).
 *
 * The sample itself takes NO pin: every caller already holds one (a token via
 * nxusSessionViewPinCurrent(), or the compat pin taken by nxusSessionMappings()).
 * Taking a second one here is what made a forgotten release invisible, and it
 * would also make the token and the sample disagree about ownership. */
static const NxusMappingTable *mappingsSample(void) {
    for (u32 attempt = 0; attempt < NXUS_VIEW_RETRY; attempt++) {
        const u32 seq = atomic_load_explicit(&g_ViewSeq, memory_order_acquire);
        if ((seq & 1u) != 0) continue;              /* update in progress */
        NxusMappingEntry *const entries = g_Session.maps.entries;
        const u32 count = g_Session.maps.count;
        if (atomic_load_explicit(&g_ViewSeq, memory_order_acquire) != seq) continue;
        if (count == 0 || entries == NULL) return NULL;   /* empty view */
        return &g_Session.maps;
    }
    return NULL;   /* kept losing the race: report "no table" instead of a torn pair */
}

/* Compat sample: takes one anonymous pin, dropped by nxusSessionViewRelease().  A
   caller that never releases stays memory-safe - the block is simply never freed -
   but keeps the retire ring occupied (see the contract in nxus_session.h).  NULL
   takes no pin, so it must not be released. */
const NxusMappingTable *nxusSessionMappings(void) {
    viewPinLegacy();            /* pin BEFORE sampling: retire then sees a reader */
    const NxusMappingTable *table = mappingsSample();
    if (table == NULL) viewReleaseLegacy();
    return table;
}

/* Token sample: the caller's pin already protects the block, so no new pin is
   taken.  A token that is not live (unpinned twice, foreign, from an earlier
   session) yields NULL instead of a walk nobody owns. */
const NxusMappingTable *nxusSessionMappingsPinned(const NxusViewPin *pin) {
    if (!viewPinIsLive(pin)) {
        NXUS_LOG("view: mappings sampled without a live pin - refused");
        return NULL;
    }
    return mappingsSample();
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
   a pointer from one publication paired with the count of another.
 *
 * Like mappingsSample(), the sample itself takes no pin: the caller's pin (token or
 * compat) is what keeps the list alive across the next publish. */
static const NxusScanRegion *regionsSample(u32 *out_count) {
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

/* Compat sample: one anonymous pin, dropped by nxusSessionViewRelease(); NULL
   takes no pin (out_count is then 0). */
const NxusScanRegion *nxusSessionRegions(u32 *out_count) {
    viewPinLegacy();            /* pin BEFORE sampling: retire then sees a reader */
    const NxusScanRegion *regions = regionsSample(out_count);
    if (regions == NULL) viewReleaseLegacy();
    return regions;
}

/* Token sample behind the caller's pin (no extra pin taken). */
const NxusScanRegion *nxusSessionRegionsPinned(const NxusViewPin *pin, u32 *out_count) {
    if (!viewPinIsLive(pin)) {
        NXUS_LOG("view: regions sampled without a live pin - refused");
        if (out_count != NULL) *out_count = 0;
        return NULL;
    }
    return regionsSample(out_count);
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
       the new list is not reachable from another thread until it is complete.
       main_base/main_size come from ONE identity snapshot: reading the two
       accessors separately could build "new base + old size" regions. */
    const NxusTargetIdentity id = identitySample();
    u32 count;
    if (req->scope == NxusScope_Ranges) {
        count = nxusBuildRegionsMulti(g_Session.map_entries, g_Session.maps.count,
                                      id.main_base, id.main_size,
                                      g_Session.ranges, g_Session.range_count,
                                      regions, capacity);
    } else {
        count = nxusBuildRegions(g_Session.map_entries, g_Session.maps.count,
                                 id.main_base, id.main_size,
                                 req->scope, req->range_begin, req->range_end,
                                 regions, capacity);
    }
    regionListPublish(regions, count);
}

/* ---- worker ------------------------------------------------------------ */

/* Release everything a worker pass allocated.  Every abort path goes through
   this, and `discard_baseline` drops the armed baseline store along with it:
   a pass that cannot run can never be refined, so leaving the store open and
   the dump on the card is a leak that only the NEXT ScanBegin's baselineDiscard()
   would hide - and if no scan follows, the FILE* and sdmc:/nxus/scan_base.bin
   stay behind for the rest of the session.  The normal exit passes false because
   a completed first pass keeps its fingerprints for the refine pass. */
static void scanWorkerRelease(bool discard_baseline, u8 *chunk, u8 *window,
                              u8 *cur_buf, u8 *prev_buf) {
    if (discard_baseline && g_Session.baseline.active) {
        /* Closes the FILE* (checking the final flush), frees the RAM store and
           removes the dump - the same path the other error paths already used. */
        baselineDiscard();
    }
    free(chunk);
    free(window);
    free(cur_buf);
    free(prev_buf);
}

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
            /* The worker cannot scan without its buffer.  Drop the baseline armed
               by ScanBegin() FIRST (its store is closed and scan_base.bin removed)
               so an aborted Unknown scan does not keep the FILE* open and the dump
               on the card.  Report a real OOM (not BadInput) so the client can
               shrink the chunk or free memory instead of blaming the request, and
               publish the result before the state: a reader that observes a
               settled state must also observe the error code (release store). */
            scanWorkerRelease(true, chunk, NULL, NULL, NULL);
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
            /* Nothing can be refined without the block buffers: close the store
               and remove the dump (scanWorkerRelease) before publishing the OOM,
               then release whatever of the two buffers did get allocated. */
            scanWorkerRelease(true, chunk, NULL, cur_buf, prev_buf);
            g_Session.last_result = (s32)MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
            sessionStateStore(NxusScanState_Error);
            NXUS_LOG("scan abort: %u-byte baseline buffers failed (out of memory)",
                     (unsigned)buf_size);
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
            /* No baseline is armed on this path (an armed one makes ScanBegin take
               the branch above), but release through the same helper so every abort
               has exactly one cleanup route. */
            scanWorkerRelease(true, chunk, window, NULL, NULL);
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

    /* The store belongs to the session, so the engine could only report a failed
       store write as one more generic drop.  Publish the real count alongside the
       pass that produced it (0 for every scan without a baseline). */
    stats.write_failed = g_Session.baseline_write_failed;
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

    NXUS_LOG("scan done: state=%u hits=%u candidates=%llu reads=%llu bytes=%llu dropped=%u write_failed=%u degraded=%u",
             (unsigned)final_state, (unsigned)g_Session.hits.count,
             (unsigned long long)candidates,
             (unsigned long long)stats.reads, (unsigned long long)stats.bytes_read,
             (unsigned)stats.dropped, (unsigned)stats.write_failed,
             (unsigned)(g_Session.baseline_degraded ? 1u : 0u));

    /* Normal exit: the baseline (if this was a first pass) is deliberately kept,
       so false keeps its fingerprints and dump for the next refine pass. */
    scanWorkerRelease(false, chunk, window, cur_buf, prev_buf);
}

/* Reap the previous worker and create the next one.  The CALLER holds the slot
   claim (see the slot block at the top of this file): ScanBegin() keeps it across
   its destructive phase and must not drop/re-take it between "freed/replaced the
   old objects" and "started the worker", and ScanNext() reaches this through
   startJob().  Re-checks g_SessionExited so a worker cannot be started behind
   Exit()'s join, where the session blocks it is about to read are being freed. */
static Result startJobLocked(bool first_pass) {
    if (atomic_load_explicit(&g_SessionExited, memory_order_acquire)) {
        NXUS_LOG("scan: session is exiting - not starting the worker");
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }
    (void)scanThreadJoinLocked();

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

static Result startJob(bool first_pass) {
    if (sessionStateLoad() == NxusScanState_Running) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);

    /* A begin/refine that loses the claim to Exit()/Reset() is answered BUSY
       instead of racing their join/free. */
    if (!scanThreadClaim(200)) {
        NXUS_LOG("scan: worker slot busy (exit/reset in progress) - not starting the scan");
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    const Result rc = startJobLocked(first_pass);
    /* Released only now: from here on Exit()/Reset() may claim, join and free. */
    scanThreadRelease();
    return rc;
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

    /* Everything below DESTROYS state that a worker, Exit() or Reset() also owns:
       baselineDiscard() closes the store, the mapping/region republishes replace the
       published views, and the hit list is freed and re-initialised.  Exit() and
       Reset() free those very objects under the worker-slot claim, so this whole
       destructive phase takes the same claim - not just startJob() at the end, which
       used to leave "free the old objects" and "take the slot" in two separate
       windows (a concurrent Exit()/Reset() could free the same block in between).
       A begin that cannot take the claim is answered BUSY instead of freeing an
       object the claim holder is freeing too. */
    if (!scanThreadClaim(200)) {
        NXUS_LOG("scan: worker slot busy (exit/reset in progress) - not starting the scan");
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    if (atomic_load_explicit(&g_SessionExited, memory_order_acquire)) {
        scanThreadRelease();
        NXUS_LOG("scan: session is exiting - not starting the worker");
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }
    /* Re-check under the claim: a startJob() that won the slot just after the
       Running test above had already published Running when it released it, and
       joining that worker below would block this begin for a whole scan. */
    if (sessionStateLoad() == NxusScanState_Running) {
        scanThreadRelease();
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    /* Reap the previous worker right away: from here on no worker, Exit() or
       Reset() can touch the hit list, the baseline or the views it replaces
       below. */
    (void)scanThreadJoinLocked();

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
    if (R_FAILED(rc)) {                 /* claim released: Exit()/Reset() may free */
        scanThreadRelease();
        return rc;
    }

    buildRegions(req);
    if (g_Session.region_count == 0) {
        scanThreadRelease();
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }

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
        scanThreadRelease();
        return rc;
    }

    g_Session.session_id++;
    /* Stamp the list with the identity its mapping snapshot was just taken from
       (cacheProcessInfo() at the top of this function refreshed it): a later title
       switch is then detectable by nxusSessionHitsMatchTarget() instead of serving
       these addresses against the new process.  A fresh list also ends the previous
       discard: nothing stale is left in it. */
    hitsOwnerStamp();
    atomic_store_explicit(&g_HitsStale, 0, memory_order_release);
    sessionStateStore(NxusScanState_Idle);
    /* Started under the claim this call still holds: the worker cannot be created
       behind Exit()'s join (startJobLocked() re-checks the exit gate), and Exit()
       cannot free the objects above between the free and the start. */
    Result jr = startJobLocked(true);
    /* No worker: the dump is dead weight.  Unless Exit() owns the session by now:
       it frees the baseline itself, and discarding it here would race that teardown
       on the FILE* / RAM store (startJobLocked() reports BAD_STATE once the exit
       gate is up, the same case this check covers). */
    if (R_FAILED(jr) && !atomic_load_explicit(&g_SessionExited, memory_order_acquire)) {
        baselineDiscard();
    }
    scanThreadRelease();
    return jr;
}

Result nxusSessionScanNext(const NxusScanRequest *req, u32 value_type, u32 epsilon_decimals,
                           const u8 *pattern, u32 pattern_len, const u8 *mask) {
    if (req == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (sessionStateLoad() == NxusScanState_Running) {
        return NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    /* Refining a list that belongs to an earlier target would compare the new
       process's memory against the old one's addresses - the worker reads the wrong
       bytes at the right offsets and reports them as matches.  Discard first, then
       refuse: the client has to rescan.  This also covers a list the server already
       discarded (hitsStale): the arrays are still in memory but must not be refined,
       and a baseline that belongs to the old target must not be either. */
    if (!nxusSessionHitsMatchTarget()) {
        /* Either an earlier target or a rebuilt mapping table: in both cases the
           stored addresses/indices no longer describe what a refine would read. */
        NXUS_LOG("refine: the stored hit list no longer matches the target/mapping table - discarding");
        nxusSessionInvalidateHits();
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
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
    /* An undo re-publishes the previous pass's results, i.e. it rewinds the list
       against the baseline that pass captured - and both were taken from ONE target
       and ONE mapping table (see the ownership block at the top of this file).  After
       a title switch, or after a rebuilt table, that baseline describes the old
       process: undoing would present the NEW title's state as if it had been rewound
       through the OLD title's addresses / mapping_idx - every entry looks plausible
       and is wrong.  Same rule as ScanNext: refuse (a discarded list is included,
       hitsStale() is the first thing nxusSessionHitsMatchTarget() checks), so the
       client rescans instead of seeing a silently wrong list.  The server names the
       cause and drops the stale results once per mismatch on this return path. */
    if (!nxusSessionHitsMatchTarget()) {
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
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
    /* Reset is the third user of the worker Thread slot: it joins and closes it,
       so it must take the same claim as startJob()/Exit() instead of racing their
       join (see the slot block at the top of this file).  When the slot cannot be
       claimed (Exit() is tearing the session down, or a Begin() is between reap
       and start), the reset is a logged no-op: freeing the hit list/baseline under
       a worker this call could not reap is the corruption the claim prevents. */
    if (!scanThreadClaim(2000)) {
        NXUS_LOG("scan: worker slot still claimed at reset - reset skipped");
        return;
    }
    if (atomic_load_explicit(&g_SessionExited, memory_order_acquire)) {
        scanThreadRelease();
        NXUS_LOG("scan: session is exiting - reset skipped (Exit owns the teardown)");
        return;
    }
    (void)scanThreadJoinLocked();

    /* The frees stay UNDER the claim, not after scanThreadRelease(): a begin that
       takes the slot in that gap frees/re-inits the very same hit list and baseline
       (ScanBegin's destructive phase now claims the slot for that reason), so
       releasing first would reopen the double free the join above just closed. */
    nxusHitListFree(&g_Session.hits);
    baselineDiscard();
    /* No list is left that could belong to a target: the next ScanBegin stamps a
       fresh owner, and nothing must be refused as "earlier target" in between. */
    hitsOwnerClear();
    atomic_store_explicit(&g_HitsStale, 0, memory_order_release);
    /* Results and identifiers are reset under the release store: a reader that
       sees Idle must not see the previous scan's progress/result. */
    g_Session.session_id++;
    g_Session.progress = 0;
    g_Session.last_result = 0;
    sessionStateStore(NxusScanState_Idle);
    scanThreadRelease();
}
