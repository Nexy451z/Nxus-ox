/* Nxus scan session: mapping snapshot + background scan worker. */
#pragma once

#include <switch.h>

#include "nxus_protocol.h"
#include "nxus_scan.h"

#define NXUS_SESSION_DEFAULT_CHUNK   (1024u * 1024u)
/* Refine read window. The first pass already reads 1 MB chunks, so this size is
   proven to be accepted; a 150k-hit refine costs ~29 reads instead of ~229 at
   128 KB, reading the same bytes. */
#define NXUS_SESSION_DEFAULT_WINDOW  (1024u * 1024u)
#define NXUS_SESSION_DEFAULT_GAP     (16u * 1024u)
/* Floor for the hit cap (150k hits = ~2.4 MB with 8 B address + 8 B value each).
   The real ceiling is derived per scan from NXUS_SESSION_HIT_BUDGET_BYTES below,
   which raises it to ~192k-341k depending on the value width. */
#define NXUS_SESSION_DEFAULT_MAXHITS 150000u

/* Unknown scans cannot discard anything: the first pass stores a baseline of the
   whole scoped range (SD card, RAM fallback) and every match must survive until
   the second pass.  A flat 150k ceiling therefore truncates real candidates, so
   the cap is derived from a byte budget instead:
       max_hits = BUDGET / (8 B address + value_size B value)
   3.0 MB yields ~256k hits for u32, ~307k for u16, ~341k for u8, ~192k for u64 -
   always more than the old 150k default, and never more memory for wider types. */
#define NXUS_SESSION_HIT_BUDGET_BYTES (3000u * 1024u)

static inline u32 nxusSessionHitLimit(u32 value_size) {
    if (value_size == 0) value_size = 1;
    return (u32)(NXUS_SESSION_HIT_BUDGET_BYTES / (8u + value_size));
}

/* Baseline dump the Unknown scan keeps on the SD card (RAM fallback inside the
   session when the card is unavailable).  main.c creates the directory at boot. */
#define NXUS_SESSION_BASELINE_DIR  "sdmc:/nxus"
#define NXUS_SESSION_BASELINE_PATH "sdmc:/nxus/scan_base.bin"

/* Bring the session up.  Idempotent: a second call while the session is live
   does nothing and keeps the current limits - it must NOT reinitialise, which
   would leak the mapping snapshot / region list / hit list and leave callers
   holding freed pointers.  Call nxusSessionExit() first to reinitialise. */
void nxusSessionInit(u32 chunk_size, u32 max_hits);
/* Tear the session down: stop the worker, free every owned block and unpublish
   the mapping/region views.  Safe to call when not initialised (no-op).  Clears
   the initialised state, so Init() after Exit() starts a fresh session.
   The worker Thread is joined and closed exactly once: the slot is claimed
   atomically in nxus_session.c (the same pattern as the pointer-scan worker), so
   a concurrent ScanBegin/ScanNext/Reset on the connection thread either starts
   the next worker or hands the slot to Exit, never both - two callers could
   otherwise threadWaitForExit()/threadClose() the same Thread and double-close
   it.  A scan that loses the claim is refused (BUSY) or refused after the
   shutdown gate (BAD_STATE) instead of creating a worker behind this teardown.
   Exit is TERMINAL for published views: it frees the blocks behind every pointer
   nxusSessionMappings()/nxusSessionRegions() ever returned, including ones whose
   pin was never released, so no view may be used across Exit.  It also invalidates
   every view pin: an outstanding token is reported in the Exit log line (and by
   nxusSessionViewPinnedCount() before the call), and unpinning it afterwards is a
   logged no-op that cannot touch the next session's pins. */
void nxusSessionExit(void);

/* ---- status ---- */
u32  nxusSessionId(void);
u32  nxusSessionScanState(void);
/* True while the background scan worker is running.  Used by the main loop to
   distinguish a busy console from a real sleep/wake. */
static inline bool nxusSessionIsRunning(void) {
    return nxusSessionScanState() == NxusScanState_Running;
}
u32  nxusSessionProgress(void);
s32  nxusSessionLastResult(void);
/* ---- baseline store health (Unknown scan) -------------------------------
 * The dense baseline streams its fingerprint store to the SD card and used to
 * degrade invisibly: a failed write only turned a block unreadable (one more
 * "dropped" block), which every client shows as "few candidates".  These two
 * accessors are the missing signal; neither changes an existing signature.
 *
 *   nxusSessionBaselineWriteFailed() - blocks the store could not persist for
 *       the current (or last) baseline.  Each one can never yield a hit.
 *   nxusSessionBaselineDegraded()    - true when the scan is running with a
 *       reduced baseline at all: the SD stream was refused up front because the
 *       card had less than 1.5x the estimated need free (RAM buffer fallback),
 *       or at least one store write failed.
 *
 * Both are cleared when a new scan arms or drops a baseline, so a classic
 * hit-list scan reports 0/false.  Read them while not Running: the worker only
 * publishes the counters when its pass returns. */
u32  nxusSessionBaselineWriteFailed(void);
bool nxusSessionBaselineDegraded(void);
/* Reports 0 while the stored list has been discarded as belonging to an earlier
   target (nxusSessionInvalidateHits), so Status never advertises hits that
   ScanGetHits refuses to serve. */
u32  nxusSessionHitCount(void);
u32  nxusSessionMappingCount(void);

/* ---- target identity (published as ONE snapshot) ------------------------
 * pid / program_id / main_base / main_size describe the one process every address
 * in this session is resolved against, so they are not four independent values:
 * "new pid + old main range" is a target that does not exist.  They used to be
 * four plain fields written one after another, which let any reader - Status, the
 * 1 Hz identity tick, an address normaliser - copy part of one write and part of
 * the next.  With a reused pid such a blend can even pass an ownership check
 * against a process the session is no longer on.
 *
 * They are therefore published as a single snapshot behind a dedicated seqlock
 * (see nxus_session.c): a reader observes exactly one write, never a blend.
 *
 * `generation` counts publications.  It is bumped on EVERY identity write and is
 * 0 until the first one (fresh session / no target yet), so two samples with the
 * same generation describe the same target while a changed generation says the
 * identity was rewritten in between - "same target?" can then be answered without
 * comparing fields across two separate reads.
 *
 * Returns false only when a writer kept the seqlock busy for the whole retry
 * budget; no torn value is ever returned.  Callers that must answer anyway (the
 * in-module ownership checks) retry, everybody else can wait for the next tick.
 * `out` may be NULL when only the successful-sample question matters.
 */
typedef struct {
    u64 pid;
    u64 program_id;
    u64 main_base;
    u64 main_size;
    u32 generation;    /* publication counter: bumped on every identity write */
} NxusTargetIdentity;

bool nxusSessionTargetIdentity(NxusTargetIdentity *out);

/* Compat accessors: one field each, sampled from the consistent snapshot above.
   KEEP THEM FOR EXISTING CALLERS ONLY - four separate calls are four samples and
   can still straddle a write, so new code that needs more than one field calls
   nxusSessionTargetIdentity() and reads its local copy. */
u64  nxusSessionProcessId(void);
u64  nxusSessionProgramId(void);
u64  nxusSessionMainBase(void);
u64  nxusSessionMainSize(void);

/* Replace the cached process identity (used when attaching to an explicit pid, where
   dmnt's metadata no longer describes the process we hold).  One seqlock write of
   all four fields, so concurrent readers see either the old or the new target. */
void nxusSessionSetProcessIdentity(u64 pid, u64 main_base, u64 main_size);
/* Same, but carries the program id too: DebugAttach preserves the metadata it
   read from dmnt just before taking the process. */
void nxusSessionSetProcessIdentityEx(u64 pid, u64 program_id, u64 main_base, u64 main_size);

/* Re-read pid / program id / main NSO range from dmnt:cht and cache it.
   Returns 0 when the identity was refreshed, the dmnt failure otherwise.
   No-op returning 0 while a debug session owns the process: dmnt is closed, so
   the values cached at attach time are the only (and correct) ones.  Call it
   after ForceOpen and from the server tick so Status never reports a zeroed
   target just because no scan has snapshotted the metadata yet. */
Result nxusSessionRefreshIdentity(void);

/* Range list for NxusScope_Ranges (copied; truncated to NXUS_MAX_SCAN_RANGES).
   NULL/0 clears it. */
void nxusSessionSetScanRanges(const NxusRangeEntry *ranges, u32 count);

/* ---- control ---- */
/* The pattern (value type + string / byte-array data) is copied by the session,
   so the caller's buffer only has to live for the duration of the call. */
Result nxusSessionScanBegin(const NxusScanRequest *req,
                            u32 value_type, u32 epsilon_decimals,
                            const u8 *pattern, u32 pattern_len, const u8 *mask);
Result nxusSessionScanNext(const NxusScanRequest *req,
                           u32 value_type, u32 epsilon_decimals,
                           const u8 *pattern, u32 pattern_len, const u8 *mask);
Result nxusSessionScanCancel(void);
Result nxusSessionScanUndo(void);
/* Drop the hit list / baseline and leave the session idle.  Takes the same worker
   Thread-slot claim as ScanBegin()/Exit(), so it never joins a worker another
   caller is already reaping; while Exit() owns the teardown the call is a logged
   no-op (the connection thread's ScanReset handler can land during shutdown). */
void   nxusSessionReset(void);

/* (Re)snapshot the target's mappings without starting a scan; used by the
   pointer scan and by clients that want the map before scanning. */
Result nxusSessionRefreshMappings(void);

/* Read callback (NxusReadFn) that goes through dmnt:cht; used by the pointer
   scan so it shares the scan engine's plumbing. */
int nxusSessionReadCallback(void *ctx, u64 address, void *buffer, u32 size);

/* Reads through dmnt:cht, or through the debug session while we hold one (dmnt is
   closed then).  Returns 0 on success.  Every server-side reader uses this so a
   debug session does not silently break reads. */
int nxusSessionReadMemory(u64 address, void *buffer, u32 size);

/* Refresh mappings and rebuild the region list for a scope without starting a
   scan; the snapshot service reuses it. */
Result nxusSessionPrepareRegions(u32 scope, u64 range_begin, u64 range_end);
/* Non-NULL return pins the list (see the lifetime contract below): release it with
   nxusSessionViewRelease() when the walk/capture is done.  COMPAT API kept for
   existing callers - new code pins with nxusSessionViewPinCurrent() and samples
   with nxusSessionRegionsPinned(). */
const NxusScanRegion *nxusSessionRegions(u32 *out_count);

/* ---- results ---- */
/* Both views are published as pointer+count pairs behind a seqlock (see
   nxus_session.c), so a reader observes one consistent snapshot instead of a
   pointer from one publication and the count from the next.  NULL means "no view
   right now" (not yet built, dropped by Exit/Reset, or the reader lost the race
   with an update); callers must always tolerate it.  Walk either view only
   behind the busy gate: the worker rebuilds these blocks while a scan runs.
 *
 * LIFETIME CONTRACT (the block behind a returned pointer is not stable):
 *
 *   - a successful (non-NULL) call PINS the block it sampled.  The session then
 *     keeps that memory alive even if a later publish replaces it: the old block
 *     is retired, not freed, until every pin is gone.  So a reader may keep using
 *     the pointer across a later publish/refresh (the snapshot service holds the
 *     region list for a whole capture) without hitting freed memory.
 *   - OWNERSHIP IS PER TOKEN.  New code takes a named pin with
 *     nxusSessionViewPinCurrent() and drops that exact pin with
 *     nxusSessionViewUnpin().  A pin can only be dropped by the owner of its
 *     token: an extra/repeated unpin, or a token from somebody else, is a logged
 *     no-op, so one caller's stray release can no longer consume another caller's
 *     pin (the old single counter could, and a forgotten release then looked
 *     "safe" forever).  A pin that is never unpinned is reported by
 *     nxusSessionViewPinnedCount(), so a forgotten release is DETECTABLE instead
 *     of silently leaking the retire ring.
 *   - a caller that never releases remains MEMORY-SAFE: the block is simply never
 *     freed (no use-after-free).  The price is that the pin lasts for the life of
 *     the session, so every later publish retains its predecessor: the retire
 *     ring holds 4 generations, and past that the old blocks are kept and only
 *     logged (at the first overflow and then every 64), i.e. a non-releasing
 *     caller turns publish traffic into a slow leak.
 *   - the pin protects the BLOCK, not the struct fields.  NxusMappingTable is
 *     returned by address and its entries/count pair is re-published in place, so
 *     a caller that re-reads table->entries sees the current publication: capture
 *     the pair you intend to walk right after the call returns.
 *   - nxusSessionExit() is terminal for views: it frees every retained block, even
 *     ones whose pin was never released, and invalidates every token (a later
 *     unpin of such a token is a logged no-op).  Do not use a view across Exit.
 */
const NxusHitList      *nxusSessionHits(void);

/* ---- result ownership (does the stored result belong to THIS target?) ----
 * hits and the mapping snapshot are keyed to the process they were taken from.
 * ForceOpen to another title, a relaunch (same title, new pid) or a DebugAttach to
 * a different process leaves every address / mapping_idx in them pointing at a
 * process that is gone - or at the NEW one at the same numeric address, which looks
 * perfectly valid to the PC.  The pointer-scan chain list already refuses to serve a
 * list from an earlier target (ptrChainOwnerCheck in nxus_server.c); the hit list
 * records its owner and is checked the same way:
 *
 *   - nxusSessionScanBegin() stamps {pid, program_id, session_id} when it arms a
 *     list, after refreshing the identity and taking the mapping snapshot, so the
 *     stamp describes the same read of the target.  The stamp also carries the
 *     MAPPING-TABLE GENERATION the scan published (see
 *     nxusSessionMappingGeneration()); a re-snapshot replaces the table, and a
 *     mapping_idx is an ordinal into that table, so the same target can still hand
 *     back indices that now name different regions,
 *   - nxusSessionHitsMatchTarget() compares that stamp with the identity the session
 *     currently holds, and the stamped mapping generation with the published one.  A
 *     value that is 0 on either side is "unknown", not a mismatch (an explicit
 *     DebugAttach can leave the title unknown, and refusing the session's own list
 *     would break scan-then-attach); with no pid at all the scan generation is the
 *     token, exactly like the chain list.  A generation change, however, is ALWAYS a
 *     mismatch: it invalidates every mapping_idx regardless of the target,
 *   - nxusSessionInvalidateHits() discards hits + mapping snapshot.
 *
 * Detection is the server's job: fillStatus() and sendHits(), plus ScanNext() inside
 * the session, call MatchTarget() and InvalidateHits() when it returns false.  The
 * 1 Hz identity tick runs on another thread, so it uses the identity-only partial
 * check below instead.
 */
/* True while the stored hit list may be served to the current target.  Also false
   after nxusSessionInvalidateHits() until a new scan stamps a list, and when the
   mapping table was rebuilt after the list was stamped, so one detection is enough
   for every later reader.  An empty session (no list ever built) matches: there is
   nothing that could be stale. */
bool nxusSessionHitsMatchTarget(void);

/* Identity half of the check above: the same pid / program id / scan-generation
   comparison, WITHOUT the mapping-table generation.  Meant for the 1 Hz identity
   tick, which must not act on a re-snapshot: ScanBegin (and the other re-snapshot
   call sites) publishes the new table before it stamps the hit owner, so for a
   moment the new generation and the old stamp coexist.  Discarding on that
   transient would drop the table the on-going command is building.  Readers that
   can serve a stored mapping_idx - fillStatus / sendHits / ScanNext - run on the
   connection thread that publishes, so they use the full nxusSessionHitsMatchTarget()
   and no stale index is ever served. */
bool nxusSessionHitsMatchTargetIdentity(void);

/* Current generation of the published mapping snapshot.  It is bumped every time
   the table is replaced (a successful snapshot publish, or a drop) - including a
   re-snapshot of the SAME process, because the new list may order the mappings
   differently and every stored mapping_idx then resolves to a different region.
   It does NOT change when a refine pass revalidates the entries in place, so a
   refined hit list keeps working.  0 means no table has been published yet. */
u32  nxusSessionMappingGeneration(void);

/* If the stored list is refused only because the mapping table was rebuilt under it,
   report the generation it was stamped with and the current one.  False for every
   other case (no stamped list, already discarded, or an identity mismatch whose
   generations still match), which lets the server name the actual cause in its log
   line.  Either out pointer may be NULL. */
bool nxusSessionHitsMappingGenerationChanged(u32 *owner_generation, u32 *current_generation);

/* Discard the stored hits and the mapping snapshot because they no longer describe
   what the session would serve - an earlier target, or a mapping table that was
   rebuilt after the hits were stamped (their mapping_idx then resolves to other
   regions) - and ask a pass that is still reading it to cancel.  Idempotent, cheap to
   repeat, and SAFE FROM ANY THREAD (the connection thread's status path and the main
   thread's tick both call it):
 *
 *   - the hit arrays are NOT freed here: the connection thread may be inside
 *     sendHits() walking them.  They become unservable (MatchTarget() is false and
 *     nxusSessionHitCount() reports 0) and are reclaimed by the next
 *     ScanBegin / Reset / Exit,
 *   - the published views are pin-protected, but the worker walks the region list and
 *     the mapping table WITHOUT a pin while it runs, so they are dropped only when no
 *     pass is active; otherwise the drop is left to the next call,
 *   - the worker is only asked to cancel (no join), so this can never stall the tick.
 */
void nxusSessionInvalidateHits(void);
/* false = only refuse the results (safe from the main-thread tick, which cannot
   see a scan preparing its mapping snapshot); true = also free the tables. */
void nxusSessionInvalidateHitsEx(bool drop_tables);

/* Identified view pin: `id` 0 means "no pin" - it is never handed out and unpin
   clears it.  `generation` names the view publication the pin was taken in, so a
   token cannot be confused with a later pin that happens to reuse the same slot. */
typedef struct {
    u32 id;
    u32 generation;
} NxusViewPin;

/* Pin the CURRENT view publication and fill *out.  This is the only pin a new
   caller should take: it names the pin, so only its owner can drop it.  Use it
   exactly like this, and unpin on EVERY path out of the block:

       NxusViewPin pin;
       if (nxusSessionViewPinCurrent(&pin)) {
           const NxusMappingTable *table = nxusSessionMappingsPinned(&pin);
           ... walk table ...
           nxusSessionViewUnpin(&pin);
       }

   Returns false when the session is not live or all 8 token slots are taken
   (an outstanding-pin bug on some other caller; nxusSessionViewPinnedCount()
   shows it).  The pin is view-agnostic: it keeps the publication alive, and
   whether the mapping table or the region list is readable is decided by the
   sampler below. */
bool nxusSessionViewPinCurrent(NxusViewPin *out);
/* Drop `pin` and invalidate it (pin->id becomes 0), so calling it twice is a
   no-op.  An id/generation that does not name a live pin - a double unpin, a
   foreign token, a token from an earlier session - changes nothing and only logs,
   so it can never decrement another caller's pin. */
void nxusSessionViewUnpin(NxusViewPin *pin);
/* Outstanding view pins: the identified tokens above plus the compat pins taken by
   nxusSessionMappings()/nxusSessionRegions().  0 means nothing is pinned and the
   retire ring has been drained.  A value that does not return to 0 once a request
   is finished is the "somebody forgot to unpin" signal. */
u32  nxusSessionViewPinnedCount(void);

/* Sample the published view while `pin` is held.  These take NO additional pin:
   the caller's token is the pin, which is what makes a forgotten unpin visible.
   A token that is not live yields NULL (+ a log line) instead of a walk without a
   pin.  NULL also means "no view right now", exactly like the compat API. */
const NxusMappingTable *nxusSessionMappingsPinned(const NxusViewPin *pin);
const NxusScanRegion   *nxusSessionRegionsPinned(const NxusViewPin *pin, u32 *out_count);

/* ---- compat view API (pins internally; existing callers unchanged) ------ */
/* Both sample the view and take ONE anonymous pin; drop it with
   nxusSessionViewRelease(), exactly once per non-NULL return, as soon as the view
   is no longer used.  NULL takes no pin and must not be released.  These pins are
   anonymous, so an extra release cannot be attributed to a caller: it is clamped
   (and now logged) rather than allowed to eat a live pin.  Migrated callers use
   the token API above, which is why a leaked pin can be detected there. */
const NxusMappingTable *nxusSessionMappings(void);
/* Drop the pin taken by the last successful nxusSessionMappings() /
   nxusSessionRegions() call.  Also frees retained old blocks when this was the
   last outstanding pin.  Safe to call with no pin held (it does not underflow),
   but every successful sample must be released exactly once. */
void nxusSessionViewRelease(void);

/* ---- pause / watchdog bookkeeping ---- */
void nxusSessionSetPaused(bool paused);
bool nxusSessionIsPaused(void);
void nxusSessionHeartbeat(void);
bool nxusSessionWatchdogExpired(u32 timeout_ms);
/* No command for this long, whether or not the target is paused. */
bool nxusSessionIdleExpired(u32 timeout_ms);

/* Size of one read the scan engine asks dmnt for (applied on the next scan). */
void nxusSessionSetChunkSize(u32 chunk_size);
u32  nxusSessionWatchdogTimeout(void);
void nxusSessionSetWatchdogTimeout(u32 timeout_ms);
