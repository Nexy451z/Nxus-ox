#include "nxus_server.h"
#include "nxus_debug.h"
#include "nxus_dmntcht.h"
#include "nxus_hid.h"

#include <malloc.h>
#include "nxus_log.h"
#include "nxus_net.h"
#include "nxus_ptrscan.h"
#include "nxus_session.h"
#include "nxus_snapshot_srv.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static NxusConfig g_Config;
/* Set while the connection thread is inside a handler (see nxusServerTick). */
static volatile bool g_CommandActive;
/* When the current command started, so a handler that never returns (blocked dmnt
   call, stalled send) cannot suppress the watchdog and reaper for the whole boot. */
static volatile u64  g_CommandStartedMs;
#define NXUS_COMMAND_GRACE_MS 120000u

/* Break-list reply size.  The debugger tracks every hardware slot now (ten: six
   instruction + four watch, NXUS_DEBUG_MAX_BREAKS), and nxus_server.h still carries
   the older 8, so the arrays are sized from the larger of the two - a smaller array
   would silently truncate BreakSet/BreakList replies and hide a live breakpoint. */
#define NXUS_DEBUG_SERVER_BREAK_MAX \
    ((NXUS_DEBUG_SERVER_MAX_BREAKS > NXUS_DEBUG_MAX_BREAKS) \
         ? NXUS_DEBUG_SERVER_MAX_BREAKS \
         : NXUS_DEBUG_MAX_BREAKS)

/* ---- pause / resume state ---------------------------------------------- */

/* True while Pause holds the target through Nxus's own debug session
   (nxusDebugAttach + svcBreakDebugProcess).  Only set when dmnt could not stop
   the process itself: the normal pause goes through dmnt's 65004, which keeps
   dmnt as the debugger (and therefore keeps scans/snapshots alive).  While this
   is set dmnt does not own the process, so Resume has to continue and detach
   instead of asking dmnt. */
static bool g_PauseViaDebug = false;
/* Pause/Resume arrive from the connection thread AND from the HID hotkey thread;
   attach/detach is a multi-step hand-off (ForceClose -> svcDebugActiveProcess ->
   event thread) and must not interleave.

   The hand-off is serialised by g_PauseBusy, NOT by a lock: the HID thread has to
   answer the controller immediately, so a second Pause/Resume is refused with
   BUSY instead of queueing behind a 200 ms attach, a thread join or a dmnt IPC.
   g_PauseLock only guards the state fields (g_PauseViaDebug plus the session pause
   flag) and is never held across anything that can block. */
static Mutex g_PauseLock;
static bool   g_PauseLockReady = false;
/* True while one pause/resume hand-off is running (atomic claim, see
   pauseTryEnter/pauseLeave). */
static atomic_bool g_PauseBusy;
/* True while the pause in effect was started by the controller hotkey AND no PC
   was attached at that moment.  The hotkey path is the "freeze the game without
   touching the PC" feature (serverPauseEx(false) never takes the process over),
   so with no client there is nobody to send Resume: the 15 s pause watchdog must
   not thaw a target the user deliberately froze.  nxusServerTick() keeps the
   session's idle clock fresh while this is set and re-arms the normal watchdog
   as soon as a client connects.  Cleared by Resume, by a PC-owned pause/attach,
   by the end of a debug session and on boot (see pauseCommitState). */
static atomic_bool g_PauseFromHotkey;
/* One-shot: the "watchdog suspended" line is worth a log entry, not one per tick
   (the main loop runs this at ~100 Hz).  Atomic for the same reason as the flag
   it annotates: the HID thread clears it while the tick sets it. */
static atomic_bool g_PauseHotkeyLogged;

static Result serverPause(void);
static Result serverPauseEx(bool allow_attach);
static Result serverResume(void);
/* Defined below; forward-declared because fillStatus reports the pause state. */
static void pauseLock(void);
static void pauseUnlock(void);
static bool pauseIsViaDebug(void);
static bool pauseTryEnter(void);
static void pauseLeave(void);
/* Hotkey-pause hold (see g_PauseFromHotkey); used by the pause paths and the tick. */
static bool pauseIsHotkeyHold(void);
static void pauseNoteHotkeyHold(void);
static void pauseClearHotkeyHold(void);
/* Defined with the tick; the pointer-scan chain check refreshes the cached target
   identity through it before comparing (throttled to 1 Hz, a no-op while a debug
   session owns the process), so the check does not rest on a value the tick has
   not updated yet. */
static void refreshTargetIdentityThrottled(void);

/* Frozen addresses Nxus itself enabled.  dmnt keeps writing them forever, so if
   the PC disappears while some are frozen the only way out is a console reboot -
   unless we remember what we froze and release it ourselves.  The dmnt frozen
   table is capped at 0x80 entries, which is what this array mirrors.
 *
 * An entry also carries the target it was frozen in (pid + program id).  The
 * address alone is not an identity: the next title can map something else at the
 * same address, so a table of bare addresses would (a) disable a freeze in the
 * new title because an earlier one froze that address, (b) keep retrying a
 * release for memory that disappeared with the old process, and (c) treat a
 * same-address freeze of the new title as "ours" although this session never
 * asked for it.  The stamp is taken from the session when the freeze is enabled
 * and compared again before anything is released. */
#define NXUS_FROZEN_OWNED_MAX 128
typedef struct {
    u64 address;
    u64 pid;          /* target the freeze was requested in (0 = unknown) */
    u64 program_id;   /* its title id (0 = unknown)                       */
} NxusFrozenOwner;
static NxusFrozenOwner g_FrozenOwned[NXUS_FROZEN_OWNED_MAX];
static u32 g_FrozenOwnedCount;

/* g_FrozenOwned is written by the connection thread (FrozenEnable/Disable) and by
   the tick (releaseOwnedFrozen), so it needs a lock: without one, a release that
   runs concurrently with an enable can drop the just-added address from the table
   and leave it frozen forever - exactly the symptom this bookkeeping exists to fix. */
static Mutex g_FrozenLock;
static bool  g_FrozenLockReady;
static void frozenLock(void)   { if (g_FrozenLockReady) mutexLock(&g_FrozenLock); }
static void frozenUnlock(void) { if (g_FrozenLockReady) mutexUnlock(&g_FrozenLock); }

/* Releases that happened while nobody was connected.  The event can only be sent to
   a live client, and the release itself is triggered by the client being gone, so
   the notification waits for the next connection instead of being dropped. */
static u64 g_FrozenReleasedPending[NXUS_FROZEN_RELEASE_ADDR_MAX];
static u32 g_FrozenReleasedPendingCount;
static u32 g_FrozenReleasedTotal;

/* Does this entry describe a freeze of the target the session is on now?
 *
 * Same rule as hitsOwnerIdentityMatches() / ptrChainOwnerCheck(), so the frozen
 * table cannot disagree with the hit list about what "the same target" means: the
 * pid is the identity, and a program id that is 0 on either side is "unknown"
 * (dmnt metadata unavailable), not a mismatch.  A pid known on only one side is a
 * mismatch: an entry stamped when dmnt had no metadata cannot be proven to belong
 * to the process running now, and releasing on a guess would write into whatever
 * the new title has mapped at that address. */
static bool frozenOwnerIsCurrent(const NxusFrozenOwner *owned, u64 pid, u64 program_id) {
    if (owned->pid != pid) return false;
    return owned->program_id == 0 || program_id == 0 || owned->program_id == program_id;
}

static void frozenOwnedAdd(u64 address) {
    /* Stamp the target the freeze was just applied to.  Both values come from the
       session, i.e. the same identity Status reports and the chain/pointer-scan
       owners use, so the table means "Nxus froze this address in THIS title". */
    const u64 pid = nxusSessionProcessId();
    const u64 program_id = nxusSessionProgramId();
    frozenLock();
    for (u32 i = 0; i < g_FrozenOwnedCount; i++) {
        if (g_FrozenOwned[i].address == address) {
            /* Already tracked, but possibly for an earlier target: dmnt just froze
               the address in the current one, so the entry belongs to it now. */
            if (!frozenOwnerIsCurrent(&g_FrozenOwned[i], pid, program_id)) {
                NXUS_LOG("frozen: %016llX re-owned by pid=%llu title=%016llX "
                         "(was pid=%llu title=%016llX)",
                         (unsigned long long)address,
                         (unsigned long long)pid, (unsigned long long)program_id,
                         (unsigned long long)g_FrozenOwned[i].pid,
                         (unsigned long long)g_FrozenOwned[i].program_id);
                g_FrozenOwned[i].pid = pid;
                g_FrozenOwned[i].program_id = program_id;
            }
            frozenUnlock();
            return;
        }
    }
    if (g_FrozenOwnedCount >= NXUS_FROZEN_OWNED_MAX) {
        NXUS_LOG("frozen: ownership table full - cannot track %016llX for cleanup",
                 (unsigned long long)address);
        frozenUnlock();
        return;
    }
    g_FrozenOwned[g_FrozenOwnedCount].address = address;
    g_FrozenOwned[g_FrozenOwnedCount].pid = pid;
    g_FrozenOwned[g_FrozenOwnedCount].program_id = program_id;
    g_FrozenOwnedCount++;
    frozenUnlock();
}

static void frozenOwnedRemove(u64 address) {
    frozenLock();
    for (u32 i = 0; i < g_FrozenOwnedCount; i++) {
        /* Keyed by address alone: dmnt's frozen table holds at most one freeze per
           address, and FrozenDisable disabled exactly that one - whichever target
           the entry was stamped for.  An entry left behind would make a later
           release act on a freeze that no longer exists. */
        if (g_FrozenOwned[i].address == address) {
            g_FrozenOwned[i] = g_FrozenOwned[--g_FrozenOwnedCount];
            frozenUnlock();
            return;
        }
    }
    frozenUnlock();
}

/* Forget the entries that were stamped for a target other than the current one
   and return how many were dropped.  Only the bookkeeping is dropped: the
   addresses are NOT released here, because an earlier title's memory is gone (or
   has been reused by whatever runs now), so disabling a freeze through dmnt would
   act on memory this session never asked about. */
static u32 frozenOwnedDropEarlierTarget(void) {
    const u64 pid = nxusSessionProcessId();
    const u64 program_id = nxusSessionProgramId();
    u32 dropped = 0;
    u64 dropped_pid = 0;

    frozenLock();
    if (g_FrozenOwnedCount == 0) { frozenUnlock(); return 0; }
    for (u32 i = 0; i < g_FrozenOwnedCount; ) {
        if (frozenOwnerIsCurrent(&g_FrozenOwned[i], pid, program_id)) {
            i++;
            continue;
        }
        /* Swap-remove: the table's order carries no meaning. */
        if (dropped == 0) dropped_pid = g_FrozenOwned[i].pid;
        g_FrozenOwned[i] = g_FrozenOwned[--g_FrozenOwnedCount];
        dropped++;
    }
    frozenUnlock();

    if (dropped != 0) {
        NXUS_LOG("frozen: dropping %u address(es) from an earlier target "
                 "(pid %llu -> %llu)",
                 (unsigned)dropped, (unsigned long long)dropped_pid,
                 (unsigned long long)pid);
    }
    return dropped;
}

/* Frozen addresses released by the switch itself are reported with
   NxusEvent_FrozenReleased, so a client that reconnects does not keep showing
   them as frozen.  The payload only carries the first
   NXUS_FROZEN_RELEASE_ADDR_MAX addresses; anything beyond that is summarised by
   count alone (see NxusFrozenReleased in nxus_protocol.h).  A failed send must
   never turn the release itself into a failure - it is only logged. */
static void sendFrozenReleasedEvent(u32 total, const u64 *addresses) {
    if (nxusNetClientFd() < 0) return;   /* nobody connected: no one to tell */
    const u32 sent = (total < NXUS_FROZEN_RELEASE_ADDR_MAX)
                         ? total : (u32)NXUS_FROZEN_RELEASE_ADDR_MAX;
    u8 payload[sizeof(NxusFrozenReleased) + NXUS_FROZEN_RELEASE_ADDR_MAX * sizeof(u64)];
    NxusFrozenReleased head;
    memset(&head, 0, sizeof(head));
    head.count = total;      /* the full total; the array may be shorter */
    head.reserved = 0;
    memcpy(payload, &head, sizeof(head));
    for (u32 i = 0; i < sent; i++) {
        const u64 address = addresses[i];
        memcpy(payload + sizeof(head) + (size_t)i * sizeof(u64), &address, sizeof(address));
    }
    const u32 length = (u32)(sizeof(head) + (size_t)sent * sizeof(u64));
    Result rc = nxusNetSendEvent(NxusEvent_FrozenReleased, payload, length);
    if (R_FAILED(rc)) {
        NXUS_LOG("frozen: FrozenReleased event (count=%u) failed rc=0x%08X - "
                 "the release itself stands",
                 (unsigned)total, (unsigned)rc);
    }
}

static void releaseOwnedFrozen(void) {
    u64 released_addresses[NXUS_FROZEN_RELEASE_ADDR_MAX];
    u32 released = 0;
    u32 snapshot = 0;
    u32 dropped = 0;
    u64 dropped_pid = 0;
    const u64 pid = nxusSessionProcessId();
    const u64 program_id = nxusSessionProgramId();

    frozenLock();
    if (g_FrozenOwnedCount == 0) { frozenUnlock(); return; }
    if (nxusDebugIsAttached()) { frozenUnlock(); return; }
    /* Only freezes of the current target are ours to undo.  An entry stamped for an
       earlier title is dropped instead of released: its address either belonged to
       a process that no longer exists or was reused by the title that runs now, and
       writing that address through dmnt would touch memory this session never
       froze.  The table is cleared either way - these entries cannot become
       meaningful again. */
    for (u32 i = 0; i < g_FrozenOwnedCount; i++) {
        if (!frozenOwnerIsCurrent(&g_FrozenOwned[i], pid, program_id)) {
            if (dropped == 0) dropped_pid = g_FrozenOwned[i].pid;
            dropped++;
            continue;
        }
        if (released < NXUS_FROZEN_RELEASE_ADDR_MAX) {
            released_addresses[released] = g_FrozenOwned[i].address;
        }
        released++;
    }
    snapshot = (released < NXUS_FROZEN_RELEASE_ADDR_MAX)
                   ? released : (u32)NXUS_FROZEN_RELEASE_ADDR_MAX;
    g_FrozenOwnedCount = 0;
    frozenUnlock();

    if (dropped != 0) {
        /* Same wording as frozenOwnedDropEarlierTarget(): one event, one meaning. */
        NXUS_LOG("frozen: dropping %u address(es) from an earlier target "
                 "(pid %llu -> %llu)",
                 (unsigned)dropped, (unsigned long long)dropped_pid,
                 (unsigned long long)pid);
    }
    if (released == 0) {
        /* Only leftovers of an earlier target were in the table, so there is
           nothing to release and nothing to report to the next client. */
        return;
    }

    NXUS_LOG("frozen: releasing %u address(es) - the client is gone", (unsigned)released);
    for (u32 i = 0; i < snapshot; i++) {
        Result rc = nxusDmntDisableFrozen(released_addresses[i]);
        if (R_FAILED(rc)) {
            NXUS_LOG("frozen: release of %016llX failed rc=0x%08X",
                     (unsigned long long)released_addresses[i], (unsigned)rc);
        }
    }

    /* Nobody is connected (that is why this ran): queue the notification for the
       next client instead of calling nxusNetSendEvent with no peer. */
    frozenLock();
    g_FrozenReleasedTotal += released;
    for (u32 i = 0; i < snapshot && g_FrozenReleasedPendingCount < NXUS_FROZEN_RELEASE_ADDR_MAX; i++) {
        g_FrozenReleasedPending[g_FrozenReleasedPendingCount++] = released_addresses[i];
    }
    frozenUnlock();
}

/* Deliver a queued FrozenReleased notification now that a client is connected. */
static void flushFrozenReleased(void) {
    u64 addresses[NXUS_FROZEN_RELEASE_ADDR_MAX];
    u32 count = 0;
    u32 total = 0;

    frozenLock();
    total = g_FrozenReleasedTotal;
    count = g_FrozenReleasedPendingCount;
    for (u32 i = 0; i < count; i++) addresses[i] = g_FrozenReleasedPending[i];
    g_FrozenReleasedTotal = 0;
    g_FrozenReleasedPendingCount = 0;
    frozenUnlock();

    if (total != 0) sendFrozenReleasedEvent(total, addresses);
}

/* Pointer scan results kept between PtrScanBegin and PtrScanGet/CheatExport. */
#define NXUS_PTRSCAN_MAX_RESULTS 64
static NxusPtrChain     g_Chains[NXUS_PTRSCAN_MAX_RESULTS];
static u32              g_ChainCount;
/* Pointer width the published list was actually walked with (4 or 8), 0 when
   nobody walked one / the list was discarded.  Published with the list (see
   ptrScanPublish) so PtrScanGet can report it in NxusPtrChainListHeader.
   pointer_width and CheatExport can build its codes from the real width instead
   of trusting the client's claim.  Deliberately NOT read from g_PtrJob after the
   walk: the job is only the in-flight request, this is the published result. */
static u32              g_ChainWidth;
static NxusPtrScanStats g_PtrStats;

/* Which target g_Chains was found for.
 *
 * The list outlives the process it describes: Begin is its only writer, and a
 * title change (or a new scan after ForceOpen) does not touch it.  A client that
 * quits game A, starts game B and then exports chain #N would therefore get a
 * cheat code built from A's addresses - and because a chain is a module-relative
 * root plus offsets, the code still looks plausible for B while pointing at
 * whatever now lives there.  Coding a wrong address into a running game is worse
 * than an error, so the list carries this stamp and every reader compares it with
 * the session's current identity first (ptrChainOwnerCheck()).
 *
 * Identity is (strongest first):
 *   pid + program id            - what dmnt reports for the cheat process; both
 *                                 change when another title is launched.
 *   session id + target address - the fallback when dmnt had no metadata (no
 *                                 pid): the scan generation and the address the
 *                                 walk rooted at are then the only tokens that
 *                                 separate one target from the next.
 */
typedef struct {
    bool valid;           /* the fields below were stamped for g_Chains       */
    u64  pid;             /* process the walk ran in (0 = dmnt had no metadata) */
    u64  program_id;      /* title id of that process (0 = unknown)            */
    u32  session_id;      /* nxusSessionId() at Begin (fallback identity)      */
    u64  target_address;  /* the address the walk rooted at (Begin request)   */
} NxusChainOwner;

static NxusChainOwner g_ChainOwner;
/* Set when a reader found that the list belongs to an earlier target and dropped
   it.  PtrScanGet then keeps answering BAD_STATE until a new walk publishes a
   list: an empty list would read as "no chains found (complete)", i.e. the client
   would believe the title simply has none. */
static bool g_ChainsStale;

/* A PtrScanBegin may not run longer than this.  The PC gives up on the reply
   after 120 s, but the console used to keep walking roots, so a scan the client
   had already abandoned could hold the session and its heap for minutes and the
   client never saw the result.  90 s leaves 30 s of headroom: the reply is
   produced before the client's timeout, and what the scan found by then is
   returned as a partial list.  The clock starts at the top of the handler, so
   the mapping refresh counts against the budget too. */
#define NXUS_PTRSCAN_TIME_BUDGET_MS 90000ull

/* Budget state the engine sees through the cancel flag it polls.  nxusPtrScan()
   takes `int *cancel` and only looks at it between roots and inside the walk,
   so the flag is refreshed from the read callback - the one hook that runs
   throughout the scan - rather than from a timer thread. */
typedef struct {
    u64 start_ms;
    int cancel;      /* the flag nxusPtrScan() reads: 1 = stop the walk */
    int budget_hit;  /* set once the time budget produced that stop */
} PtrScanBudget;

/* Reads the one clock the handler owns; 1 once the budget is gone. */
static int ptrScanOverBudget(const PtrScanBudget *budget) {
    const u64 now_ms = armTicksToNs(armGetSystemTick()) / 1000000ull;
    return (now_ms - budget->start_ms) >= NXUS_PTRSCAN_TIME_BUDGET_MS;
}

/* Read callback handed to nxusPtrScan(): re-arms the cancel flag before the
   memory read, so a scan that is burning its budget stops within one read of
   the deadline instead of at the next command.  The context is the budget, not
   the session: nxusSessionReadCallback() ignores it. */
static int ptrScanReadBudgeted(void *ctx, u64 address, void *buffer, u32 size) {
    PtrScanBudget *budget = (PtrScanBudget *)ctx;
    if (!budget->cancel && ptrScanOverBudget(budget)) {
        budget->cancel = 1;
        budget->budget_hit = 1;
    }
    return nxusSessionReadCallback(NULL, address, buffer, size);
}

/* ---- 8 MB heap budget -------------------------------------------------- */

/*
 * The sysmodule's inner heap (main.c: INNER_HEAP_SIZE) is 8 MB shared by the
 * rx buffer, the hit list, the snapshot slots, the scan buffers and every
 * per-command allocation.  The pointer scan is the one command that adds its
 * own working set (scratch, region array and, on success, a chain reply) on
 * top of everything the session still holds, so it is refused up front when
 * the conservative peak estimate no longer fits.
 *
 * estimateHeapPeak() sums the upper bounds of the allocations that can be
 * resident in one session.  Every term is derived from the same constant the
 * allocator uses:
 *
 *   persistent
 *     network rx buffer     NXUS_NET_BUF_SIZE                      1 MiB
 *     changed-block cache   NXUS_SNAPSHOT_MAX_CHANGED * 16 B       256 KiB
 *     mapping table         4096 * sizeof(NxusMappingEntry)        128 KiB
 *     scan region list      4096 * sizeof(NxusScanRegion)          128 KiB
 *   per snapshot slot
 *     hashes + addresses    NXUS_SNAPSHOT_MAX_BLOCKS * 2 * 8 B     256 KiB
 *                           (lazily allocated by nxus_snapshot_srv.c,
 *                            freed again by nxusSnapshotReleaseAll() and
 *                            re-allocated by the next capture)
 *   hit list                retained capacity, <= NXUS_SESSION_HIT_BUDGET_BYTES
 *                           (8 B NxusHitAddress + value_size per hit; the
 *                            estimate reads the live capacity, so an empty or
 *                            reset list costs nothing and only a full list
 *                            reaches the 3.0 MiB bound)
 *   scan working set        NXUS_SESSION_DEFAULT_CHUNK + WINDOW    2.0 MiB
 *                           (one is live per pass; both are counted as a
 *                            conservative reserve)
 *   snapshot capture        chunk_size in nxus_snapshot_srv.c     256 KiB
 *   pointer scan            max(scratch + region array,           1.0 MiB
 *                               1 MiB chain reply)
 *                           = max(256 KiB + 4097*24 B, 1 MiB)
 *
 * With the hit list at its cap and no snapshot slot the estimate is
 * 6,742,016 B (6.43 MiB).  A held slot adds exactly the 256 KiB its two arrays
 * occupy, so the A/B pair brings it to 7,266,304 B (6.93 MiB) - inside the budget,
 * which is why the guard is a backstop today rather than a routine refusal.  A
 * released slot adds nothing at all now that nxusSnapshotReleaseAll() frees the
 * arrays (see its comment), so the charge follows the resident memory exactly.
 * Without a held snapshot the guard never runs, which keeps the previous behaviour
 * of PtrScanBegin unchanged.
 */
#define NXUS_HEAP_BUDGET_BYTES         (8u * 1024u * 1024u)
/* Session hard caps (nxus_session.c: mapping/region lists are clamped to 4096). */
#define NXUS_HEAP_MAX_MAPPINGS         4096u
#define NXUS_HEAP_MAX_REGIONS          4096u
/* nxus_snapshot_srv.c allocates this capture scratch per SnapshotCapture. */
#define NXUS_HEAP_SNAPSHOT_CHUNK_BYTES (256u * 1024u)
/* nxus_server.c: handlePtrScanBegin() allocates this scan scratch. */
#define NXUS_HEAP_PTRSCAN_SCRATCH_BYTES (256u * 1024u)

/* Bit n set: snapshot slot n has its hash/address arrays allocated and is charged
   against the heap budget.  Kept in step with the service - it is refreshed from
   nxusSnapshotResidentSlots() after every capture and release, never guessed - so
   the set of charged slots is exactly the set of resident arrays.  (It used to be
   maintained by the server because a release only dropped the bookkeeping while
   the arrays stayed allocated; nxusSnapshotReleaseAll() now frees them, which makes
   "released" and "not resident" the same thing.) */
static u32 g_HeldSnapshotSlots;

static u64 estimateHeapPeak(void) {
    const u64 persistent =
        (u64)NXUS_NET_BUF_SIZE +
        (u64)NXUS_SNAPSHOT_MAX_CHANGED * (u64)sizeof(NxusChangedBlock) +
        (u64)NXUS_HEAP_MAX_MAPPINGS * (u64)sizeof(NxusMappingEntry) +
        (u64)NXUS_HEAP_MAX_REGIONS * (u64)sizeof(NxusScanRegion);

    /* hashes + addresses of the slots that are actually allocated right now, taken
       from the service that owns them (nxusSnapshotResidentBytes()).  This used to
       be "the slot was ever used", which overstated the heap after a release only
       because the release did not free anything; now it under- or over-states
       nothing: a released slot costs 0 because its arrays are gone. */
    const u64 held = nxusSnapshotResidentBytes();

    /* The chain reply (up to one net buffer) is built after the scratch has
       been freed; taking the larger of the two keeps the estimate independent
       of that ordering. */
    const u64 ptr_work = (u64)NXUS_HEAP_PTRSCAN_SCRATCH_BYTES +
                         (u64)(NXUS_HEAP_MAX_MAPPINGS + 1u) * (u64)sizeof(NxusPtrRegion);
    const u64 ptr_peak = (ptr_work > (u64)NXUS_NET_BUF_SIZE) ? ptr_work
                                                             : (u64)NXUS_NET_BUF_SIZE;

    /* The hit list survives between scans; use its real capacity so an empty
       or reset session is not charged for results it does not hold.  PtrScanBegin
       runs behind the BUSY gate, so no worker can realloc the arrays while this
       is read; nxusSessionHits() returns NULL for a running scan, in which case
       the full budget is the safe bound. */
    u64 hit_bytes = (u64)NXUS_SESSION_HIT_BUDGET_BYTES;
    const NxusHitList *hits = nxusSessionHits();
    if (hits != NULL) {
        hit_bytes = (u64)hits->capacity * (8u + (u64)hits->value_size);
        if (hit_bytes > (u64)NXUS_SESSION_HIT_BUDGET_BYTES)
            hit_bytes = (u64)NXUS_SESSION_HIT_BUDGET_BYTES;
    }

    /* Only ONE of the scan buffers is live per pass, and a scan cannot be running
       here (PtrScanBegin sits behind the scan BUSY gate), so the two are not
       additive.  The snapshot capture scratch is likewise transient and runs on
       this very thread, so it cannot coexist with the pointer scan either.
       Counting all of them (the first version did) rejected legitimate work with
       ~2.3 MiB of memory that can never be resident. */
    const u64 scan_work = ((u64)NXUS_SESSION_DEFAULT_CHUNK > (u64)NXUS_SESSION_DEFAULT_WINDOW)
                              ? (u64)NXUS_SESSION_DEFAULT_CHUNK
                              : (u64)NXUS_SESSION_DEFAULT_WINDOW;

    return persistent + held + hit_bytes + scan_work + ptr_peak;
}

/* ---- releasing the snapshot slots -------------------------------------- */

/*
 * Drop both A/B captures and hand their memory back to the 8 MB inner heap.
 *
 * nxusSnapshotReleaseAll() (nxus_snapshot_srv.c) now really frees the hash/address
 * arrays and leaves each slot in the "never used" state, so this is the release the
 * PC's HEAP_BUDGET advice promises ("release the snapshots (or reset)") and the next
 * capture re-allocates on demand through the existing snapshotSlotEnsure() path.
 * The bookkeeping below is refreshed FROM the service instead of being cleared
 * blindly, so g_HeldSnapshotSlots and estimateHeapPeak() always describe the
 * resident arrays.
 *
 * No capture can be mid-flight here: captures run on the connection thread, and the
 * server serialises commands (SnapshotCapture additionally refuses while the pointer
 * scan worker runs).
 *
 * NxusCmd_ScanReset calls this too.
 */
static void snapshotReleaseSlots(const char *why) {
    /* The service owns the storage and the validity marker: ask it to release both
       slots instead of driving nxusSnapshotTake() with a request that is meant to be
       rejected. */
    const u32 held = g_HeldSnapshotSlots;
    const u64 resident = nxusSnapshotResidentBytes();
    nxusSnapshotReleaseAll();
    g_HeldSnapshotSlots = nxusSnapshotResidentSlots();
    NXUS_LOG("snapshot: released both slots (held=0x%X, %llu B freed, now held=0x%X)",
             (unsigned)held, (unsigned long long)resident,
             (unsigned)g_HeldSnapshotSlots);
    if (why != NULL) NXUS_LOG_DEBUG("snapshot: release reason: %s", why);
}

/* Fired from the HID thread: freeze the target without touching the PC.
   Goes through the same serverPause() as the PC command: dmnt stops the cheat
   process first (65004 is a real svc::BreakDebugProcess and keeps the dmnt
   session usable), with the own-debug-session stop only as a fallback. */
static void onHotkeyFired(void *user) {
    (void)user;
    if (g_CommandActive) {
        NXUS_LOG("hotkey: a command is running - in-flight reads may be dropped by the pause");
    }
    Result rc = serverPauseEx(false);   /* hotkey: never hijack the process */
    if (rc == (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY)) {
        /* Another Pause/Resume owns the hand-off: give up at once instead of
           blocking the controller reader behind it. */
        NXUS_LOG("hotkey: pause/resume already in progress - ignored");
        return;
    }
    NXUS_RESULT("hotkey pause", rc);
    if (R_SUCCEEDED(rc)) {
        nxusNetSendEvent(NxusEvent_HotkeyPaused, NULL, 0);
    }
}

/* Defined with the pointer scan worker, further down. */
static void ptrScanInit(void);

void nxusServerInit(void) {
    memset(&g_Config, 0, sizeof(g_Config));
    g_Config.hotkey_enabled = 0;
    g_Config.chunk_size = NXUS_SESSION_DEFAULT_CHUNK;
    g_Config.watchdog_timeout_ms = 15000;
    g_Config.heartbeat_interval_ms = 5000;
    g_Config.log_level = 1;

    /* Before the HID thread can exist: nxusHidStart() is only called from the
       config handler, long after this. */
    if (!g_PauseLockReady) {
        mutexInit(&g_PauseLock);
        atomic_init(&g_PauseBusy, false);
        atomic_init(&g_PauseFromHotkey, false);
        atomic_init(&g_PauseHotkeyLogged, false);
        g_PauseLockReady = true;
    }

    if (!g_FrozenLockReady) {
        mutexInit(&g_FrozenLock);
        g_FrozenLockReady = true;
    }

    nxusHidInit();
    nxusHidSetCallback(onHotkeyFired, NULL);

    /* Pointer scan worker state (defined with the worker, further down). */
    ptrScanInit();
}

/* ---- helpers ----------------------------------------------------------- */

static void reply(int fd, u16 type, u32 seq, const void *payload, u32 length) {
    Result rc = nxusNetSendFd(fd, type, 0, seq, payload, length);
    if (R_FAILED(rc)) NXUS_RESULT("send reply", rc);
}

static void replyError(int fd, u16 type, u32 seq, Result rc) {
    s32 value = (s32)rc;
    nxusNetSendFd(fd, type, NXUS_FLAG_ERROR, seq, &value, sizeof(value));
}

/* Error reply with a machine-readable reason: the s32 Result followed by one
   u32 NXUS_REASON_* word.  Older clients read only the Result (the first 4
   bytes) and ignore the tail, and older servers send only the Result, so this
   stays compatible in both directions.  Used for the argument-validation
   failures where "result=0x80000186" alone does not tell the user what to fix;
   OOM / dmnt / IPC errors still go through replyError(). */
static void replyErrorReason(int fd, u16 type, u32 seq, Result rc, u32 reason) {
    s32 value[2];
    value[0] = (s32)rc;
    value[1] = (s32)reason;
    nxusNetSendFd(fd, type, NXUS_FLAG_ERROR, seq, value, sizeof(value));
}

/* True when rc is one of Nxus's own NXUS_ERR_* codes.  Used to decide whether a
   BUSY deserves a reason: libnx's own "busy" (LibnxError_Busy) must keep going
   out as a bare Result, because it means something different (a service call). */
static bool resultIsNxusError(Result rc, u32 desc) {
    return (R_MODULE(rc) == NXUS_RESULT_MODULE) && (R_DESCRIPTION(rc) == desc);
}

/* Transient "another operation owns this": retrying later is the fix. */
static bool resultIsBusyRetryable(Result rc) {
    return resultIsNxusError(rc, NXUS_ERR_BUSY);
}

/* Error reply that names a BUSY.  Everything used to be a bare NXUS_ERR_BUSY, so
   a client could not tell "wait for the scan to finish" from "freeze is
   impossible while a debug session holds dmnt".  The reason is appended to the
   Result (wire-compatible, see replyErrorReason). */
static void replyBusyReason(int fd, u16 type, u32 seq, u32 reason) {
    replyErrorReason(fd, type, seq, (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY), reason);
}

/* Drop the stored scan results when they belong to an earlier target, or when the
 * mapping table they were stamped against was rebuilt.
 *
 * hits and the mapping snapshot are keyed to the process that produced them (see
 * the ownership block in nxus_session.h).  Switching titles - ForceOpen to another
 * game, a relaunch with a new pid, a DebugAttach to a different process - left them
 * in place, so sendHits happily answered with the previous title's addresses under
 * the new title's pid: every address and mapping_idx still resolves through the
 * table the PC holds, so the batch looks completely valid.  The chain list already
 * refuses this (ptrChainOwnerCheck); this is the same gate for the scan results.
 *
 * The SAME title is not enough either: a re-snapshot replaces the mapping table, and
 * mapping_idx is an ordinal into it, so hits stamped before the replacement resolve
 * through the new table to a different region.  nxusSessionHitsMatchTarget() compares
 * the stamped generation too; this function then discards and logs which of the two
 * causes fired.
 *
 * Runs on the connection thread (status path) and in the 1 Hz identity tick:
 * nxusSessionInvalidateHitsEx(drop_tables) is safe from both (it never frees the arrays a handler
 * may be walking).  The log line is emitted once per mismatch: a client that keeps
 * polling after the refusal must not flood the log ring.
 *
 * compare_mapping_generation selects which comparison drives the discard.  The
 * connection-thread readers pass true (a rebuilt table must not be served either),
 * the 1 Hz tick passes false: it must only react to a target change.  A re-snapshot
 * publishes the new table before ScanBegin stamps the owner, so the tick could catch
 * that transient, call this, and drop the mapping table the on-going ScanBegin is
 * still building - a sporadic BAD_INPUT for a scan.  A generation-only mismatch is
 * picked up by the next status / hits request on the connection thread instead, which
 * is serialized with the publication. */
static void discardHitsOfEarlierTarget(bool compare_mapping_generation,
                                         bool drop_tables) {
    static atomic_int logged;
    const bool matches = compare_mapping_generation
                             ? nxusSessionHitsMatchTarget()
                             : nxusSessionHitsMatchTargetIdentity();
    if (matches) {
        atomic_store_explicit(&logged, 0, memory_order_relaxed);   /* re-arm */
        return;
    }
    /* Name the cause once: a rebuilt table breaks mapping_idx even on the same
       target, an identity change means the addresses belong to somebody else.  Both
       end in the same discard. */
    u32 owner_gen = 0, now_gen = 0;
    const bool table_rebuilt = compare_mapping_generation &&
                               nxusSessionHitsMappingGenerationChanged(&owner_gen, &now_gen);
    if (atomic_exchange_explicit(&logged, 1, memory_order_relaxed) == 0) {
        if (table_rebuilt) {
            NXUS_LOG("hits: the mapping table was rebuilt (gen %u -> %u) - discarding",
                     (unsigned)owner_gen, (unsigned)now_gen);
        } else {
            NXUS_LOG("hits: the hit list belongs to an earlier target - discarding");
        }
    }
    nxusSessionInvalidateHitsEx(drop_tables);
}

/* Connection-thread entry point: identity AND mapping generation. */
static void discardResultsOfEarlierTarget(void) {
    discardHitsOfEarlierTarget(true, true);
}

/* Same rule for the mapping snapshot: the PC resolves every address it received
 * from a hit batch through these bases, so serving the previous title's table is as
 * wrong as serving its hits.  Only the debug-session path reads the session's
 * snapshot (without a debug session the pages come straight from dmnt and are
 * current by construction).  A failed refresh keeps the cached table, which is what
 * this path did before the ownership check existed. */
static void refreshMappingsAfterTargetChange(void) {
    if (nxusSessionHitsMatchTarget()) return;
    discardResultsOfEarlierTarget();
    /* Never rebuild the table under a running pass: the worker walks it (and the
       region list) without a pin, and this page can be answered from the cache. */
    if (nxusSessionScanState() == NxusScanState_Running) return;
    Result rc = nxusSessionRefreshMappings();
    if (R_FAILED(rc)) {
        NXUS_RESULT("mappings: refresh after the target changed", rc);
    }
}

/* How long the console waits for a command before it assumes the PC is gone. */
#define NXUS_DEBUG_IDLE_TIMEOUT_MS 20000u

static void fillStatus(NxusStatus *st) {
    memset(st, 0, sizeof(*st));
    /* Results are keyed to the target that produced them.  The 1 Hz tick keeps the
       cached identity current, so the first status poll after a title switch sees
       the mismatch here and drops the previous title's list - instead of reporting
       its hit count as if it described the process the client now sees. */
    discardResultsOfEarlierTarget();
    st->proto_version = NXUS_PROTO_VERSION;
    /* Which read path the console is serving, not a build-time constant: while
       Nxus owns the kernel debug handle dmnt:cht is closed and nxusSessionReadMemory()
       answers every read through svc debug memory, so the PC can only tell "dmnt
       read" from "debug handle read" by looking at this field.  Probing the session
       once and reusing the result for the flags below keeps mode and status_flags
       consistent within one reply (a debug-session pause attaches too, which counts
       as DEBUG exactly like an explicit DebugAttach). */
    const bool debug_attached = nxusDebugIsAttached();
    st->mode = debug_attached ? NXUS_MODE_DEBUG : NXUS_MODE_DMNT;
    st->scan_state = nxusSessionScanState();
    /* One snapshot for the whole identity: four separate reads could straddle a
       publication and report a new pid with the previous title's base. */
    NxusTargetIdentity identity;
    if (nxusSessionTargetIdentity(&identity)) {
        st->process_id = identity.pid;
        st->program_id = identity.program_id;
    } else {
        st->process_id = nxusSessionProcessId();
        st->program_id = nxusSessionProgramId();
    }
    /* The client polls Status far more often than the 1 Hz tick, so a title switch
       that already moved the cached identity is caught here on the first poll after
       it: the frozen entries of the title that went away are forgotten (never
       released - see frozenOwnedDropEarlierTarget).  The count check keeps the
       common case at one load instead of a lock; a stale non-zero value only costs
       the locked re-check, and a missed drop is caught by the next call. */
    if (g_FrozenOwnedCount != 0) (void)frozenOwnedDropEarlierTarget();
    st->main_base = nxusSessionMainBase();
    st->main_size = nxusSessionMainSize();
    st->hit_count = nxusSessionHitCount();
    st->progress_permille = nxusSessionProgress();
    st->last_result = nxusSessionLastResult();
    st->uptime_ms = (u32)(armTicksToNs(armGetSystemTick()) / 1000000ull);
    /* The client must not ask for more than one net buffer can carry; saying so
       keeps the PC-side scanner from silently failing on oversized reads. */
    /* One reply carries header + payload, so the largest usable read is the buffer
       minus the header. Advertising the real limit keeps PC-side scans from doing
       four times the necessary round trips. */
    st->max_read = NXUS_NET_BUF_SIZE - (u32)sizeof(NxusPacketHeader);
    {
        struct mallinfo mi = mallinfo();
        st->heap_used = (u32)mi.uordblks;
        st->heap_total = (u32)mi.arena;
    }

    u32 flags = 0;
    if (debug_attached) {
        /* dmnt is closed (has_process would fail), but we do hold the process. */
        flags |= NXUS_ST_HAS_PROCESS | NXUS_ST_DEBUG_MODE | NXUS_ST_DEBUG_ATTACHED;
        /* GDB-style stop: the target is being held at a break/watch stop. */
        if (nxusDebugIsStopped()) flags |= NXUS_ST_DEBUG_STOPPED;
    } else {
        /* The PC polls Status every ~20 ms, which was 50 dmnt IPCs per second, each
           taking g_DmntLock and therefore serialising behind the reader thread.
           Cache the probe for 500 ms: far below the time scale on which a cheat
           process appears or disappears, but 25x fewer IPCs.  The branch above
           already handles the attached case, where dmnt is closed and asking it
           would fail every time. */
        static u64  last_check_ms;
        static bool cached;
        const u64 now_ms = armTicksToNs(armGetSystemTick()) / 1000000ull;
        if (last_check_ms == 0 || now_ms - last_check_ms >= 500ull) {
            bool has_process = false;
            cached = R_SUCCEEDED(nxusDmntHasCheatProcess(&has_process)) && has_process;
            last_check_ms = now_ms;
        }
        if (cached) flags |= NXUS_ST_HAS_PROCESS;
    }
    /* A pause that went through the debug session keeps the target held with dmnt
       closed, so nxusSessionIsPaused() alone would under-report it.  A debugger
       stop (breakpoint/watchpoint/GDB-style hold) is the same thing from the
       client's point of view and must light the same flag, otherwise the GUI shows
       "running" while the title is frozen. */
    if (pauseIsViaDebug() || nxusSessionIsPaused()) flags |= NXUS_ST_PAUSED;
    if (nxusDebugIsStopped()) flags |= NXUS_ST_PAUSED;
    if (nxusSessionScanState() == NxusScanState_Running) flags |= NXUS_ST_SCANNING;
    st->status_flags = flags;
}

/* ---- real pause / resume ----------------------------------------------- */

static void pauseLock(void) {
    if (g_PauseLockReady) mutexLock(&g_PauseLock);
}

static void pauseUnlock(void) {
    if (g_PauseLockReady) mutexUnlock(&g_PauseLock);
}

/* Claim the pause/resume hand-off.  Returns false when another one is already
   running, so the caller can answer BUSY immediately -- blocking here is exactly
   what made the hotkey freeze for seconds while an attach finished. */
static bool pauseTryEnter(void) {
    bool expected = false;
    return atomic_compare_exchange_strong(&g_PauseBusy, &expected, true);
}

static void pauseLeave(void) {
    atomic_store_explicit(&g_PauseBusy, false, memory_order_release);
}

/* Hotkey-pause hold.  Atomic rather than g_PauseLock-guarded because the tick
   reads it on the main thread while the HID thread sets it; it is a single flag,
   so a load/store pair is all the ordering that is needed. */
static bool pauseIsHotkeyHold(void) {
    return atomic_load_explicit(&g_PauseFromHotkey, memory_order_acquire);
}

static void pauseNoteHotkeyHold(void) {
    atomic_store_explicit(&g_PauseFromHotkey, true, memory_order_release);
}

static void pauseClearHotkeyHold(void) {
    atomic_store_explicit(&g_PauseFromHotkey, false, memory_order_release);
    atomic_store_explicit(&g_PauseHotkeyLogged, false, memory_order_relaxed);
}

/* The pause state is only ever read/written in these short sections; every IPC,
   attach/detach and thread join happens outside the lock.  A pause that ends by
   any route also ends the hotkey hold: the target is running again, so there is
   nothing left for the watchdog to spare. */
static void pauseCommitState(bool via_debug, bool paused) {
    pauseLock();
    g_PauseViaDebug = via_debug;
    nxusSessionSetPaused(paused);
    pauseUnlock();
    if (!paused) pauseClearHotkeyHold();
}

static bool pauseIsViaDebug(void) {
    pauseLock();
    const bool via_debug = g_PauseViaDebug;
    pauseUnlock();
    return via_debug;
}

/* Releases a pause that was held through Nxus's own debug session, after the
   session itself is gone.  Kept in one section so Status never observes
   g_PauseViaDebug cleared while the session still reports "paused" (or the
   reverse).  Returns true when such a pause was released. */
static bool pauseReleaseDebugSessionPause(void) {
    pauseLock();
    const bool was = g_PauseViaDebug;
    if (was) {
        g_PauseViaDebug = false;
        nxusSessionSetPaused(false);
    }
    pauseUnlock();
    /* A debug session that ends releases the target, so a hold recorded for the
       pause is stale (the exit/attach paths rely on this clear). */
    if (was) pauseClearHotkeyHold();
    return was;
}

/* Freeze every thread of the target.
 *
 * Preferred path: dmnt's own stop.  dmnt:cht 65004 PauseCheatProcess is
 * svc::BreakDebugProcess on the debug handle dmnt already owns, so the title
 * really stops while dmnt keeps the process - reads, mappings, snapshots and
 * frozen addresses keep working through the same session, and no attach/detach
 * churn is needed.
 *
 * Fallback: when dmnt cannot stop it (no cheat process open, another debugger
 * took the process over, ...), take the process over with Nxus's own debug
 * session and break it there.  That closes dmnt for the duration of the pause,
 * which is why it is only the second choice.
 *
 * Runs with the hand-off claimed but WITHOUT g_PauseLock: the dmnt IPCs, the
 * 200 ms debug attach and the event-thread hand-off all happen lock-free, and the
 * state fields are only touched in pauseCommitState(). */
static Result pauseTarget(bool allow_attach) {
    if (nxusDebugIsAttached()) {
        /* Our session already owns the process (DebugAttach, or a repeated
           Pause): one kernel call is enough. */
        Result rc = nxusDebugBreak();
        if (R_SUCCEEDED(rc)) {
            pauseCommitState(pauseIsViaDebug(), true);
            NXUS_LOG("pause: stopped the owned debug session");
        }
        return rc;
    }

    /* dmnt still owns the cheat process: let it break the process.  The dmnt
       session stays open, so scans/snapshots/frozen addresses keep working while
       the target is held. */
    Result dmnt_rc = nxusDmntPause();
    if (R_SUCCEEDED(dmnt_rc)) {
        pauseCommitState(false, true);
        NXUS_LOG("pause: dmnt stopped the cheat process (65004) - dmnt session kept");
        return 0;
    }

    /* The own-debug-session fallback CLOSES dmnt's cheat process: frozen values,
       toggles and the cheat VM of every tool sharing it go away, and the ten
       hardware BP/WP slots are wiped.  That is acceptable when the user asked for
       it from the PC ("nxus pause"), but not when a controller hotkey did it, so
       only the explicit path may take the process over. */
    if (!allow_attach) {
        NXUS_LOG("pause: dmnt stop failed rc=0x%08X; debug-attach fallback is disabled "
                 "for this path (use `nxus pause` / DebugAttach to force it)",
                 (unsigned)dmnt_rc);
        return dmnt_rc;
    }

    NXUS_LOG("pause: dmnt stop failed rc=0x%08X - falling back to an own debug session",
             (unsigned)dmnt_rc);

    /* The pid must be read BEFORE the attach: svcDebugActiveProcess makes dmnt
       close the cheat process, and after that GetMetadata has nothing to report
       (and auto-reopen would fight the session we just created). */
    NxusProcessMetadata md;
    memset(&md, 0, sizeof(md));
    Result rc = nxusDmntGetMetadata(&md);
    if (R_FAILED(rc) || md.process_id == 0) {
        /* Nothing to attach to either.  Never report success for a no-op: an
           ineffective "pause" is what made the PC continue scanning a live game.
           dmnt_rc is the pause failure itself, so it is what the client needs. */
        NXUS_LOG("pause: no dmnt target (metadata rc=0x%08X pid=%llu); dmnt stop rc=0x%08X",
                 (unsigned)rc, (unsigned long long)md.process_id, (unsigned)dmnt_rc);
        if (R_FAILED(rc)) return dmnt_rc;
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NO_PROCESS);
    }

    /* Stopping the wrong process is worse than not pausing: after the game quits,
       dmnt's metadata can describe whatever still runs (the home menu).  Require a
       real program id and, when the session already knows its target, the same
       pid. */
    {
        const u64 known_pid = nxusSessionProcessId();
        if (md.program_id == 0 || (known_pid != 0 && md.process_id != known_pid)) {
            NXUS_LOG("pause: refusing to stop pid=%llu (title=%016llX, known pid=%llu) - "
                     "not the target this session was using",
                     (unsigned long long)md.process_id,
                     (unsigned long long)md.program_id,
                     (unsigned long long)known_pid);
            return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NO_PROCESS);
        }
    }

    rc = nxusDebugAttach(md.process_id);
    if (R_FAILED(rc)) {
        NXUS_LOG("pause: debug attach to pid=%llu failed rc=0x%08X - target not stopped",
                 (unsigned long long)md.process_id, (unsigned)rc);
        /* Hands the process back to dmnt and re-enables its auto-reopen. */
        nxusDebugDetach();
        return rc;
    }

    /* svcDebugActiveProcess itself continues the title, so the stop has to follow
       the attach; auto_continue would release it again on the next debug event. */
    nxusDebugSetAutoContinue(0);
    rc = nxusDebugBreak();
    if (R_FAILED(rc)) {
        NXUS_LOG("pause: svcBreakDebugProcess failed rc=0x%08X - detaching", (unsigned)rc);
        nxusDebugDetach();
        return rc;
    }

    /* dmnt is closed now, so the metadata read above is the only source for
       pid / title / main NSO base.  It describes exactly the process we just
       attached to, so adopt it wholesale: Status and every main-relative scope
       read the session cache, and a stale value from an earlier run would point
       them at the wrong memory. */
    nxusSessionSetProcessIdentityEx(md.process_id, md.program_id,
                                    md.main_nso_base, md.main_nso_size);

    pauseCommitState(true, true);
    NXUS_LOG("pause: debug session attached to pid=%llu - every thread stopped",
             (unsigned long long)md.process_id);
    return 0;
}

/* Same rules as pauseTarget(): runs with the hand-off claimed, never with
   g_PauseLock held, and commits the state fields once the real work is done. */
static Result resumeTarget(void) {
    if (pauseIsViaDebug()) {
        /* The pause owns the process through the debug session: release the stop,
           then detach, which ForceOpens dmnt again so scans/cheats go back to the
           normal path.  Detaching even when the continue failed matters: closing
           the debug handle resumes the target, so the title must never be left
           frozen because one IPC failed. */
        Result cont_rc = nxusDebugContinueAll();
        Result detach_rc = nxusDebugDetach();
        pauseCommitState(false, false);
        NXUS_LOG("resume: debug pause released (continue rc=0x%08X, detach rc=0x%08X)",
                 (unsigned)cont_rc, (unsigned)detach_rc);
        /* Detaching is what actually releases the target: closing the debug
           handle resumes every thread even when the explicit Continue failed, so
           reporting that failure would tell the PC "still frozen" about a game
           that is running again.  The rcs above keep it visible in the log. */
        return detach_rc;
    }

    if (nxusDebugIsAttached()) {
        /* Debug mode was started explicitly: continue it, keep the session. */
        Result rc = nxusDebugContinueAll();
        if (R_SUCCEEDED(rc)) pauseCommitState(false, false);
        return rc;
    }

    /* The target is held by dmnt's own break (65004): continue it through dmnt.
       That keeps the cheat process open, so the normal scan/read path is ready
       again the moment the title runs. */
    Result rc = nxusDmntResume();
    if (R_SUCCEEDED(rc)) {
        pauseCommitState(false, false);
        return 0;
    }

    NXUS_LOG("resume: dmnt continue failed rc=0x%08X", (unsigned)rc);
    /* dmnt lost the cheat process while it was stopped (the title was closed, or
       another debugger took it over).  If a debug session we own exists, it is
       the only remaining way to release the target. */
    if (nxusDebugIsAttached()) {
        Result debug_rc = nxusDebugContinueAll();
        if (R_SUCCEEDED(debug_rc)) pauseCommitState(false, false);
        return debug_rc;
    }
    return rc;
}

/* allow_attach == true is the explicit PC request ("nxus pause"): it may take the
   process over with an own debug session when dmnt cannot stop it.  The controller
   hotkey must not, because closing dmnt destroys cheat/frozen state shared with
   other tools and wipes the hardware BP slots. */
static Result serverPauseEx(bool allow_attach) {
    /* Never block a caller (the HID hotkey runs here too) behind another
       pause/resume: it would wait for the attach, the thread join or a dmnt IPC. */
    if (!pauseTryEnter()) {
        NXUS_LOG("pause: another pause/resume is in progress - refusing (busy)");
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    Result rc = pauseTarget(allow_attach);
    pauseLeave();
    if (R_SUCCEEDED(rc)) {
        /* Which path owns the pause decides the watchdog: the explicit PC pause is
           serviced by the client's own heartbeats (and a PC pause while the client
           is gone makes no sense), while the hotkey pause may have to outlive the
           client - that is what "freeze without touching the PC" means.  Only
           record the hold when nobody was attached at the time: with a client
           connected the normal watchdog applies and the tick's reconnect branch
           would otherwise log a transition that never happened. */
        if (allow_attach || nxusNetClientFd() >= 0) pauseClearHotkeyHold();
        else pauseNoteHotkeyHold();
    }
    return rc;
}

static Result serverPause(void) {
    return serverPauseEx(true);
}

static Result serverResume(void) {
    if (!pauseTryEnter()) {
        NXUS_LOG("resume: another pause/resume is in progress - refusing (busy)");
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }
    Result rc = resumeTarget();
    pauseLeave();
    /* resumeTarget() already cleared it on success (pauseCommitState); do it here
       too so a failed resume cannot leave the hold set for a pause that is gone. */
    if (R_SUCCEEDED(rc)) pauseClearHotkeyHold();
    return rc;
}

/* ---- module detection -------------------------------------------------- */

static u32 collectModules(NxusModuleInfo *out, u32 max_modules) {
    /* Token pin: the sampled table is only valid while this pin is held, and only
       this call knows the id that can drop it (a stray release elsewhere can no
       longer consume it).  Every early return below therefore unpins. */
    NxusViewPin pin;
    if (!nxusSessionViewPinCurrent(&pin)) return 0;   /* no session / pin table full */
    const NxusMappingTable *maps = nxusSessionMappingsPinned(&pin);
    if (maps == NULL) {                               /* no snapshot: NULL is no view */
        nxusSessionViewUnpin(&pin);
        return 0;
    }

    u32 found = 0;
    u8 page[0x200];
    /* Copy the pair once: nxus_session.h asks callers to read entries+count
       immediately, because a publish can replace the block while we walk it. */
    const u32 map_total = maps->count;
    for (u32 i = 0; i < map_total && found < max_modules; i++) {
        const NxusMappingEntry *m = &maps->entries[i];
        if (!(m->reserved & NXUS_PERM_R) || m->size < sizeof(page)) continue;
        if (nxusSessionReadMemory(m->base, page, sizeof(page)) != 0) continue;

        for (u32 off = 0; off + 0x20 <= sizeof(page); off += 4) {
            if (memcmp(page + off, "MOD0", 4) != 0) continue;
            memset(&out[found], 0, sizeof(out[found]));
            out[found].base = m->base;
            out[found].size = m->size;
            /* The NSO header sits at the mapping base and carries the build id at
               +0x40. */
            memcpy(out[found].build_id, page + 0x40, 0x20);

            /* MOD0 carries no module name (its 0x1C field is RelroStart on
               19.0.0+), so title NSOs get a positional name.  Do not read a name
               offset here: the NSO header's ModuleNameOffset is a different
               struct, and a hostile/garbage offset would escape this 0x200 buffer. */
            snprintf(out[found].name, sizeof(out[found].name), "mod%u", (unsigned)found);
            found++;
            break;
        }
    }
    nxusSessionViewUnpin(&pin);
    return found;
}

/* ---- pointer scan ------------------------------------------------------ */

static u32 buildPtrRegions(NxusPtrRegion *out, u32 max_regions, u64 *out_module_base) {
    NxusViewPin pin;
    if (!nxusSessionViewPinCurrent(&pin)) {   /* no session / pin table full */
        *out_module_base = nxusSessionMainBase();
        return 0;
    }
    const NxusMappingTable *maps = nxusSessionMappingsPinned(&pin);
    if (maps == NULL) {          /* no snapshot; the caller reports NO_MAPPINGS */
        nxusSessionViewUnpin(&pin);
        *out_module_base = nxusSessionMainBase();
        return 0;
    }
    const u64 module_base = nxusSessionMainBase();
    const u64 module_end = module_base + nxusSessionMainSize();
    *out_module_base = module_base;

    u32 n = 0;
    const u32 map_total = maps->count;   /* copied once, see nxus_session.h */
    for (u32 i = 0; i < map_total && n < max_regions; i++) {
        const NxusMappingEntry *m = &maps->entries[i];
        if (!(m->reserved & NXUS_PERM_R) || m->size == 0) continue;

        out[n].base = m->base;
        out[n].size = m->size;
        /* Chains may only root inside the module's own static data (.data/.bss):
           anything else moves between sessions. */
        int is_static = (m->reserved & NXUS_PERM_W) &&
                        module_base != 0 && module_end > module_base &&
                        m->base >= module_base && m->base + m->size <= module_end;
        out[n].kind = is_static ? NXUS_PTRREGION_STATIC : NXUS_PTRREGION_TRAVERSABLE;
        out[n].reserved = m->reserved;
        n++;
    }
    nxusSessionViewUnpin(&pin);
    return n;
}

/* ---- pointer scan worker -----------------------------------------------
 *
 * The walk used to run inside handlePtrScanBegin(), i.e. on the connection
 * thread.  A pointer scan is the one command that may run for the whole
 * NXUS_PTRSCAN_TIME_BUDGET_MS (90 s), and for that long nothing was read: the
 * listen socket was not polled either, so a reconnecting client completed the
 * TCP handshake (backlog 8) and then got no reply at all, and the PC's heartbeats
 * stopped feeding the pause watchdog.  Fixing that in the transport (accept and
 * handler on separate threads) would require every handler to be reachable from
 * two threads plus a lock around all session state; moving the one long walk off
 * the connection thread has the same effect for a fraction of the risk.
 *
 * The walk now runs on its own thread - the pattern the scan worker in
 * nxus_session.c already uses - and PtrScanBegin answers immediately with
 * NXUS_RESULT_PTRSCAN_STARTED (switch/include/nxus_server.h).  The client polls
 * PtrScanGet every few hundred ms; the poll is also what keeps the watchdog
 * alive, and between two polls the connection thread is back in recvExact(),
 * whose listener watch preempts the session for a new connection as usual.
 *
 * Concurrency this introduces, and why it is safe:
 *   - core/nxus_ptrscan.c keeps its ~38 KB engine state in a static (documented
 *     non-reentrant), so exactly ONE worker may run at a time: g_PtrJobState is
 *     that gate and a second PtrScanBegin is refused with BUSY.
 *   - g_Chains / g_PtrStats / g_ChainCount / g_ChainWidth / g_ChainOwner /
 *     g_ChainsStale are written by the worker and read by PtrScanGet.  The worker
 *     publishes them BEFORE its release store that marks the job Done/Failed, and
 *     every reader acquire-loads the state first, so no reader ever sees a
 *     half-written list.
 *   - CheatExport indexes g_Chains and is refused while the worker runs.  Both it
 *     and PtrScanGet first check that the list still belongs to the current target
 *     (ptrChainOwnerCheck) - the chains may be one title old.
 *   - SnapshotCapture and ScanBegin/ScanNext are refused while the worker runs:
 *     their buffers (capture chunk, scan chunk/window) would land on top of the
 *     pointer scan's scratch, region array and chain reply, which estimateHeapPeak
 *     counts but those extra buffers do not.  They already answer BUSY while a
 *     scan runs, so this is the same rule read the other way round.
 */
typedef enum {
    NxusPtrJob_Idle = 0,   /* no worker: PtrScanGet serves the previous list    */
    NxusPtrJob_Running,    /* the worker owns g_Chains and the job buffers      */
    NxusPtrJob_Done,       /* results published; PtrScanGet serves them         */
    NxusPtrJob_Failed,     /* the walk failed; PtrScanGet reports it once       */
} NxusPtrJobState;

/* Filled in on the connection thread before the worker starts, so every failure
   that can be detected up front (bad request, heap budget, OOM, no mappings) is
   still answered synchronously by PtrScanBegin. */
typedef struct {
    NxusPtrScanRequest  req;
    NxusPtrRegion      *regions;
    u8                 *scratch;
    u32                 scratch_size;
    u32                 region_count;
    NxusPtrScanOptions  opts;
    /* The width the walk really loads with: opts.value_width has already been
       resolved (explicit 4/8, or nxusPtrScanAutoWidthFor()'s answer) and the
       engine cannot change it any more, but this field is what the published
       result reports, so it is set where the decision is made and never
       re-derived at reply time. */
    u32                 walk_width;
    u64                 module_base;
    PtrScanBudget       budget;
    /* Target identity captured at Begin (published with the chains, see
       NxusChainOwner): the walk may take up to 90 s, so the stamp has to describe
       the process the request was made against, not whatever runs when it ends. */
    NxusChainOwner      owner;
} PtrScanJob;

static PtrScanJob  g_PtrJob;
static atomic_int  g_PtrJobState;
static Result      g_PtrJobResult;   /* the failure NxusPtrJob_Failed carries */
static Thread      g_PtrThread;
static bool        g_PtrThreadLive;
/* True while one of the two users of the worker Thread slot (handlePtrScanBegin()
   preparing the next walk, or nxusServerExit()) owns it.  The Thread object must be
   joined and closed exactly once - a second threadWaitForExit() on a closed Thread
   waits on freed state, and closing one that threadStart() is about to use is worse -
   and the shutdown runs concurrently with the connection thread, so the right to touch
   the slot is claimed atomically here instead of being decided by g_PtrThreadLive. */
static atomic_bool g_PtrThreadReaping;
/* Set by nxusServerExit() (the claim is also its idempotency guard): no new pointer
   scan may start after that point, or a worker created during the shutdown would
   outlive the session and the debug handle it reads - the very leak the exit path
   exists to close.  Atomic because handlePtrScanBegin() on the connection thread
   re-checks it under the slot claim. */
static atomic_bool g_ServerExited;

static bool ptrScanBusy(void) {
    return atomic_load_explicit(&g_PtrJobState, memory_order_acquire) == NxusPtrJob_Running;
}

/* Join and close the worker Thread.  The caller must hold the slot claim (see
   ptrScanClaimSlot).  Returns true when a worker was actually reaped. */
static bool ptrScanJoinSlotLocked(void) {
    if (!g_PtrThreadLive) return false;
    threadWaitForExit(&g_PtrThread);
    threadClose(&g_PtrThread);
    g_PtrThreadLive = false;
    return true;
}

/* Take the worker Thread slot for "reap the previous worker + create/start the next
   one" (handlePtrScanBegin) or for "cancel + join" (nxusServerExit).  Bounded wait
   instead of an endless one: the holder never sits in an IPC, only in
   threadCreate()/threadStart() and one worker join, and a Begin that has to wait for a
   shutting-down server is better answered BUSY than blocked. */
static bool ptrScanClaimSlot(u32 spin_ms) {
    for (u32 waited = 0; ; waited += 1u) {
        bool expected = false;
        if (atomic_compare_exchange_strong_explicit(&g_PtrThreadReaping, &expected, true,
                                                    memory_order_acq_rel, memory_order_acquire)) {
            return true;
        }
        if (waited >= spin_ms) return false;
        svcSleepThread(1000000ull);
    }
}

static void ptrScanReleaseSlot(void) {
    atomic_store_explicit(&g_PtrThreadReaping, false, memory_order_release);
}

/* When the worker last entered Running: the tick uses it to spot a walk that never
   returns (a wedged IPC read would otherwise keep four BUSY gates closed for the
   rest of the boot). */
static u64 g_PtrJobStartedMs;

/* Ask the running walk to stop at its next read.  The worker publishes its own
   Failed/partial result; this only flips the flag the engine already polls. */
static void ptrScanRequestCancel(const char *why) {
    if (!ptrScanBusy()) return;
    g_PtrJob.budget.cancel = 1;
    NXUS_LOG("ptrscan: cancel requested (%s) - the worker stops at its next read", why);
}

/* The target's own architecture, as far as the console can tell - the highest
 * priority input of the pointer-width inference.  Two sources, both "process
 * metadata", because the process's bitness is a fact about the process while the
 * mapping table only says where its memory happens to sit this run:
 *
 *   1. the debug session's CreateProcess event (DebugEventInfo.flags bit 0), via
 *      nxusDebugTargetIs64Bit()/Known().  Exact, but only exists in debug mode.
 *   2. dmnt's CheatProcessMetadata (65002).  It carries no explicit architecture
 *      flag, but aslr_base/aslr_size describe the process's *address space*, and
 *      the kernel hands out two unmistakably different pairs: AArch32 gets
 *      0x200000 + 0xFFE00000 (sums to exactly 4 GiB - the measured MHXX values in
 *      docs/work/probe.txt), AArch64 gets 0x8000000 + 0x7FF8000000 (512 GiB).  A
 *      region that cannot fit in 4 GiB therefore proves AArch64 and one that ends
 *      inside it proves AArch32.  The rule itself lives in core
 *      (nxusPtrScanArchFromAddressSpace()) so it can be tested on the host; an
 *      inconsistent region answers "unknown".
 *
 * Returns UNKNOWN when neither source has an answer (or a debug session owns the
 * process but has not seen CreateProcess yet: dmnt is closed then, so asking it
 * would only re-open it and steal the process back). */
static NxusPtrScanArch ptrScanProcessArch(void) {
    if (nxusDebugTargetIs64BitKnown()) {
        return nxusDebugTargetIs64Bit() ? NXUS_PTRSCAN_ARCH_AARCH64
                                       : NXUS_PTRSCAN_ARCH_AARCH32;
    }
    /* Mid-handoff / no CreateProcess yet: do NOT touch dmnt here (a failed call
       auto-reopens it, which would take the process away from our debug session). */
    if (nxusDebugIsAttached() || nxusDebugIsHandoff()) return NXUS_PTRSCAN_ARCH_UNKNOWN;

    NxusProcessMetadata md;
    memset(&md, 0, sizeof(md));
    if (R_FAILED(nxusDmntGetMetadata(&md))) return NXUS_PTRSCAN_ARCH_UNKNOWN;
    const NxusPtrScanArch arch = nxusPtrScanArchFromAddressSpace(md.aslr_base, md.aslr_size);
    if (arch == NXUS_PTRSCAN_ARCH_UNKNOWN) {
        NXUS_LOG_DEBUG("ptrscan: dmnt metadata gives no usable architecture "
                       "(aslr=%08llX+%08llX)",
                       (unsigned long long)md.aslr_base, (unsigned long long)md.aslr_size);
    }
    return arch;
}

/* No walk has run yet, and none can be running while init runs (it is part of the
   boot chain, before the listener is up). */
static void ptrScanInit(void) {
    atomic_init(&g_PtrJobState, NxusPtrJob_Idle);
    /* No worker exists at boot, so the Thread-slot claim starts free (see
       ptrScanClaimSlot). */
    atomic_init(&g_PtrThreadReaping, false);
    g_PtrJobResult = 0;
}

/* Publish the walk's outcome and hand the state over to the readers.  Runs on the
   worker thread, or on the connection thread when no thread could be created. */
static void ptrScanPublish(int src, u32 count, u64 elapsed_ms) {
    /* A cancelled walk is a partial result, not a failure: the chains already
       stored are real, so they are published, flagged as incomplete.  Anything
       else keeps the old all-or-nothing rule. */
    if (g_PtrJob.budget.budget_hit || src == NXUS_SCAN_ERR_CANCELLED) g_PtrStats.truncated = 1;
    const bool ok = (src == NXUS_SCAN_OK || src == NXUS_SCAN_ERR_CANCELLED);
    g_ChainCount = ok ? count : 0;
    /* Published with the list, for the same reason as g_ChainOwner: the job's
       width describes the walk that just ended, and a later Begin overwrites the
       job before a client may still be polling for THIS result.  A failed walk
       publishes no list, so its width must not stay behind either (0 = unknown). */
    g_ChainWidth = ok ? g_PtrJob.walk_width : 0;
    /* Stamp the list with the target it was walked in (captured at Begin).  Done
       here, before the release store that publishes Done/Failed, like every other
       field a reader consumes.  A new publication also clears the stale marker of
       an earlier discard - a fresh walk has just replaced what it referred to. */
    g_ChainOwner = g_PtrJob.owner;
    g_ChainOwner.valid = ok;
    g_ChainsStale = false;

    if (g_PtrJob.budget.budget_hit) {
        NXUS_LOG("ptrscan: time budget reached after %llu ms (chains=%u) - "
                 "returning partial results",
                 (unsigned long long)elapsed_ms, (unsigned)g_ChainCount);
    }
    NXUS_LOG("ptrscan: done in %llu ms, chains=%u, reads=%llu",
             (unsigned long long)elapsed_ms, (unsigned)g_ChainCount,
             (unsigned long long)g_PtrStats.reads);

    free(g_PtrJob.regions);
    free(g_PtrJob.scratch);
    g_PtrJob.regions = NULL;
    g_PtrJob.scratch = NULL;

    g_PtrJobResult = ok ? 0 : (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    atomic_store_explicit(&g_PtrJobState, ok ? NxusPtrJob_Done : NxusPtrJob_Failed,
                          memory_order_release);
}

/* The walk itself.  Only touches the job, the engine and the result globals. */
static void ptrScanJobRun(void) {
    const u64 start_ms = g_PtrJob.budget.start_ms;
    u32 count = 0;

    /* Start from a clean slate: a previous run's stats must not be published
       together with a failed/empty result (that reads as "0 chains, complete"). */
    memset(&g_PtrStats, 0, sizeof(g_PtrStats));
    /* Honour the client's --max: the engine stops at max_results and reports
       truncated, which is exactly the advice the CLI gives when it fires. */
    const u32 out_cap = g_PtrJob.opts.max_results ? g_PtrJob.opts.max_results
                                                  : NXUS_PTRSCAN_MAX_RESULTS;
    /* The last argument is the cancel flag the engine polls; ptrScanReadBudgeted
       raises it once the time budget is spent, so the walk always returns. */
    const int src = nxusPtrScan(g_PtrJob.regions, g_PtrJob.region_count,
                                g_PtrJob.req.target_address, g_PtrJob.module_base,
                                &g_PtrJob.opts, g_Chains, out_cap, &count,
                                ptrScanReadBudgeted, &g_PtrJob.budget,
                                g_PtrJob.scratch, g_PtrJob.scratch_size,
                                &g_PtrStats, &g_PtrJob.budget.cancel);

    const u64 elapsed_ms = (armTicksToNs(armGetSystemTick()) / 1000000ull) - start_ms;
    ptrScanPublish(src, count, elapsed_ms);
}

static void ptrScanThread(void *arg) {
    (void)arg;
    /* Acquire load: pairs with the release store that publishes g_PtrJob and the
       Running state before threadStart(), so the job fields are visible here even
       if threadStart() itself is not a synchronisation point the compiler knows. */
    (void)atomic_load_explicit(&g_PtrJobState, memory_order_acquire);
    ptrScanJobRun();
}

static void sendChainList(int fd, u32 seq, u16 type) {
    /* header + one wire record per chain, sized in u64: a wrapped u32 product
       would look small enough to pass the buffer check and then be written past
       the end of the allocation.  (The old `payload ? payload : 1` fallback was
       dead - the header alone makes payload non-zero - and would have written the
       16-byte header into a 1-byte allocation if it ever had been taken.) */
    const u64 payload_u64 = (u64)sizeof(NxusPtrChainListHeader) +
                            (u64)g_ChainCount * (u64)sizeof(NxusPtrChainWire);
    if (payload_u64 > (u64)NXUS_NET_BUF_SIZE) {
        replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_TOO_LARGE));
        return;
    }
    const u32 payload = (u32)payload_u64;
    u8 *buffer = (u8 *)malloc(payload);
    if (buffer == NULL) {
        replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory));
        return;
    }
    NxusPtrChainListHeader header;
    memset(&header, 0, sizeof(header));
    header.count = g_ChainCount;
    header.total = g_ChainCount;
    header.truncated = g_PtrStats.truncated;
    /* The width the walk actually used (0 = unknown).  Appended field: the first
       16 bytes keep their offsets for a reader that predates it, and the chain
       records follow the full 20-byte header. */
    header.pointer_width = g_ChainWidth;
    memcpy(buffer, &header, sizeof(header));

    u32 offset = (u32)sizeof(header);
    for (u32 i = 0; i < g_ChainCount; i++) {
        NxusPtrChainWire wire;
        memset(&wire, 0, sizeof(wire));
        wire.root_offset = g_Chains[i].root_offset;
        wire.final_offset = g_Chains[i].final_offset;
        wire.step_count = g_Chains[i].step_count;
        for (u32 s = 0; s < g_Chains[i].step_count && s < NXUS_PTRSCAN_MAX_DEPTH; s++)
            wire.steps[s] = g_Chains[i].steps[s];
        memcpy(buffer + offset, &wire, sizeof(wire));
        offset += (u32)sizeof(wire);
    }
    reply(fd, type, seq, buffer, offset);
    free(buffer);
}

/* May this chain list be served to the client that is asking now?
 *
 * g_Chains is only written by a walk, so the list survives whatever happens to the
 * process it was found in: the PC can quit game A, start game B and then export
 * chain #N.  That export would code A's addresses - a module-relative root plus
 * offsets, so it looks valid for B - and writing such a code into a running game
 * is worse than refusing it.  Every reader therefore compares the stamp taken at
 * Begin with the session's current identity before handing chains out.
 *
 * Callers run on the connection thread and have already refused BUSY while the
 * worker owns g_Chains (CheatExport checks that at its top, PtrScanGet by state),
 * so the plain reads/writes below cannot race with ptrScanPublish().
 *
 * Returns 0 when the list may be served, NXUS_ERR_BAD_STATE once it has been
 * discarded.  An empty list needs no protection.
 */
static Result ptrChainOwnerCheck(void) {
    /* A list an earlier read already dropped stays refused until the next walk
       publishes a new one: an empty list would read as "no chains (complete)". */
    if (g_ChainsStale) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    if (g_ChainCount == 0 || !g_ChainOwner.valid) return 0;

    /* The tick refreshes the cached identity once a second; asking here makes the
       answer deterministic for a client that exports right after a title change
       instead of waiting for the next tick.  Throttled, and a no-op returning 0
       while a debug session owns the process (dmnt is closed then), so it is cheap
       and cannot fight the debug session. */
    refreshTargetIdentityThrottled();

    const u64 now_pid = nxusSessionProcessId();
    const u64 now_title = nxusSessionProgramId();
    bool same;
    if (g_ChainOwner.pid != 0) {
        /* Both sides know a pid, so that is the identity.  A program id that is 0
           on either side (dmnt metadata unavailable at Begin or at an explicit
           attach) is treated as unknown, not as a mismatch: refusing a list that
           cannot be proven stale would break scan-then-attach flows. */
        same = (g_ChainOwner.pid == now_pid) &&
               (g_ChainOwner.program_id == 0 || now_title == 0 ||
                g_ChainOwner.program_id == now_title);
        if (!same) {
            NXUS_LOG("ptrscan: chain list belongs to an earlier target "
                     "(saved pid=%llu, current pid=%llu) - discarding",
                     (unsigned long long)g_ChainOwner.pid, (unsigned long long)now_pid);
            if (g_ChainOwner.pid == now_pid) {
                /* Same pid, different title: the pid was reused after a restart. */
                NXUS_LOG("ptrscan: chain list title changed (saved title=%016llX, "
                         "current title=%016llX)",
                         (unsigned long long)g_ChainOwner.program_id,
                         (unsigned long long)now_title);
            }
        }
    } else {
        /* No pid when the walk ran, so dmnt had no metadata: the scan generation is
           the only per-target token the session publishes (nxusSessionId() changes
           on every ScanBegin/Reset). */
        same = (g_ChainOwner.session_id == nxusSessionId());
        if (!same) {
            NXUS_LOG("ptrscan: chain list belongs to an earlier scan generation "
                     "(saved session=%u, current session=%u) - discarding",
                     (unsigned)g_ChainOwner.session_id, (unsigned)nxusSessionId());
        }
    }
    if (same) return 0;

    /* Invalidate instead of leaving the bytes around: a later reader must not be
       able to serve them, and the next Begin replaces them anyway. */
    g_ChainCount = 0;
    g_ChainWidth = 0;   /* the width belonged to the list that is now gone */
    g_ChainOwner.valid = false;
    g_ChainsStale = true;
    return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
}

static void handlePtrScanBegin(int fd, u16 type, u32 seq, const u8 *payload, u32 length) {
    /* The server is shutting down (nxusServerExit ran): no new walk may start.  It
       would outlive the session and the debug handle that the exit path is releasing,
       and the worker Thread slot may already have been closed (see
       ptrScanClaimSlot / ptrScanJoinSlotLocked).  Answered as BAD_STATE because
       nothing will clear - the console is going down - but with the BUSY reason so a
       client that reconnects during the teardown reads "retry", not "your request was
       malformed". */
    if (atomic_load_explicit(&g_ServerExited, memory_order_acquire)) {
        replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                         NXUS_REASON_BUSY_STATE);
        return;
    }
    if (length < sizeof(NxusPtrScanRequest)) {
        replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                         NXUS_REASON_BAD_LENGTH);
        return;
    }

    /* One walk at a time: the engine's 38 KB state is a static (see the worker
       comment above), so a second job would overwrite the first.  Refusing here
       also keeps this gate identical for the polled and the synchronous path. */
    if (ptrScanBusy()) {
        NXUS_LOG("ptrscan: a walk is already running - refusing the new request");
        replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BUSY),
                         NXUS_REASON_BUSY_STATE);
        return;
    }

    NxusPtrScanRequest req;
    memcpy(&req, payload, sizeof(req));

    /* Start the clock before the mapping refresh and before the heap check: the
       client times the whole command from its own request, so everything this
       handler does has to fit inside the budget. */
    PtrScanBudget budget;
    budget.start_ms = armTicksToNs(armGetSystemTick()) / 1000000ull;
    budget.cancel = 0;
    budget.budget_hit = 0;

    /* Refuse before the mapping refresh and before allocating anything: the
       pointer scan needs its scratch (256 KiB), region array (~96 KiB) and a
       chain reply (up to 1 MiB) on top of the retained hit list and snapshot
       slots.  The estimate reads the hit list's real capacity, so it only
       exceeds the budget with a (nearly) full list: an empty or reset session
       is allowed, and so is a single snapshot slot.  With the A/B pair and a
       maximum hit list it is 8.18 MiB and a pointer scan would be the
       allocation that pushes the 8 MB heap over.  The client gets BUSY and can
       retry after ScanReset / a narrower scan shrinks the retained list. */
    if (g_HeldSnapshotSlots != 0) {
        const u64 peak = estimateHeapPeak();
        if (peak > (u64)NXUS_HEAP_BUDGET_BYTES) {
            NXUS_LOG("ptrscan: snapshot 保持中の ptrscan はメモリ予算超過 "
                     "(estimate=%llu B > budget=%u B, slots=0x%X) - refusing",
                     (unsigned long long)peak, (unsigned)NXUS_HEAP_BUDGET_BYTES,
                     (unsigned)g_HeldSnapshotSlots);
            replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BUSY),
                             NXUS_REASON_HEAP_BUDGET);   /* not "a scan is running" */
            return;
        }
    }

    Result rc = nxusSessionRefreshMappings();
    if (R_FAILED(rc)) { replyError(fd, type, seq, rc); return; }

    NxusViewPin pin;
    if (!nxusSessionViewPinCurrent(&pin)) {   /* no live session / pin table full */
        /* Nobody holds a view pin we could use: that is a session-level condition,
           not "this process has no mappings".  Retrying does not help until the
           outstanding pin is released, so it is not BUSY_STATE. */
        NXUS_LOG("ptrscan: view pin table exhausted (%u held) - refusing",
                 (unsigned)nxusSessionViewPinnedCount());
        replyBusyReason(fd, type, seq, NXUS_REASON_SLOT_FULL);
        return;
    }
    const NxusMappingTable *maps = nxusSessionMappingsPinned(&pin);
    /* The compat accessor published NULL when there is no table (never
       snapshotted, or already dropped), and so does the token sample. */
    if (maps == NULL) {
        nxusSessionViewUnpin(&pin);
        replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_NO_PROCESS),
                         NXUS_REASON_NO_MAPPINGS);
        return;
    }
    /* The pin is only needed to read the count: drop it as soon as the region
       array is sized, or the retire ring can never drain and every later publish
       leaks its old block (about 40 runs to OOM on a 1000-mapping title). */
    u32 region_cap = maps->count + 1;
    nxusSessionViewUnpin(&pin);

    NxusPtrRegion *regions = (NxusPtrRegion *)calloc(region_cap, sizeof(NxusPtrRegion));
    u8 *scratch = (u8 *)malloc(256 * 1024);
    if (regions == NULL || scratch == NULL) {
        free(regions); free(scratch);
        replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory));
        return;
    }

    u64 module_base = 0;
    u32 region_count = buildPtrRegions(regions, region_cap, &module_base);
    if (req.module_base != 0) module_base = req.module_base;

    NxusPtrScanOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.max_depth = req.max_depth ? req.max_depth : 3;
    if (opts.max_depth > NXUS_PTRSCAN_MAX_DEPTH) opts.max_depth = NXUS_PTRSCAN_MAX_DEPTH;
    opts.max_offset = req.max_offset ? req.max_offset : 0x1000;
    opts.max_results = req.max_results ? req.max_results : NXUS_PTRSCAN_MAX_RESULTS;
    if (opts.max_results > NXUS_PTRSCAN_MAX_RESULTS) opts.max_results = NXUS_PTRSCAN_MAX_RESULTS;
    /* Pointer width.  An explicit 4/8 request always wins.  When the client lets
       the console decide (0 - and for any other value, as this handler has always
       treated "not 4/8" as "infer it"), the width comes from:
         1. the target process's own architecture, as ptrScanProcessArch() reports
            it (the debug session's CreateProcess flag, else dmnt's process
            metadata address-space size).  This outranks everything address based:
            a 64-bit title can have its main module AND heap below 4 GiB (main
            0x00700000 / heap 0x36000000 is a real AArch64 ASLR outcome, and the
            fixture the old "every mapping <= 4 GiB -> 4" rule walked with 4-byte
            loads, silently returning zero chains), while a 32-bit title can never
            hold a pointer above 4 GiB.
         2. the mappings the walk is about to traverse (see nxusPtrScanAutoWidthFor()
            in core/nxus_ptrscan.c), with the module base as the empty-table hint.
       Both paths go through the same function, so the console and a host caller
       cannot drift apart. */
    const NxusPtrScanArch process_arch = ptrScanProcessArch();
    opts.process_arch = (u32)process_arch;
    if (req.value_width == 4 || req.value_width == 8) {
        opts.value_width = req.value_width;
    } else {
        u64 max_mapping_end = 0;
        const char *width_reason = NULL;
        opts.value_width = nxusPtrScanAutoWidthFor(regions, region_count, module_base,
                                                  process_arch, &max_mapping_end,
                                                  &width_reason);
        NXUS_LOG("ptrscan: pointer width auto = %u (%s) "
                 "(main=%08llX, max mapping end=%08llX, process arch=%u)",
                 (unsigned)opts.value_width,
                 width_reason ? width_reason : NXUS_PTRSCAN_WIDTH_REASON_MAPPINGS,
                 (unsigned long long)module_base,
                 (unsigned long long)max_mapping_end, (unsigned)process_arch);
    }
    /* The resolved width the walk will load with - explicit request or the
       auto-inference above, never 0 here.  Captured once so the reply and
       CheatExport report the width that was actually walked, not the client's
       claim (they can differ: the client's inference sees its own, possibly
       stale mapping table). */
    const u32 walk_width = opts.value_width;
    opts.window_size = 0x400;
    opts.max_reads = 20000;      /* bounded so the console cannot be held hostage */

    NXUS_LOG("ptrscan: target=%08llX module=%08llX depth=%u width=%u regions=%u",
             (unsigned long long)req.target_address, (unsigned long long)module_base,
             (unsigned)opts.max_depth, (unsigned)opts.value_width, (unsigned)region_count);

    /* Everything the walk needs is in place, so hand the job to the worker.  The
       start clock was taken at the top of the handler: the client times the whole
       command from its request, and the mapping refresh is part of it. */
    g_PtrJob.req = req;
    g_PtrJob.regions = regions;
    g_PtrJob.scratch = scratch;
    g_PtrJob.scratch_size = 256 * 1024;
    g_PtrJob.region_count = region_count;
    g_PtrJob.opts = opts;
    g_PtrJob.walk_width = walk_width;
    g_PtrJob.module_base = module_base;
    g_PtrJob.budget = budget;

    /* Identity the resulting chains will be stamped with (NxusChainOwner).  Taken
       HERE, not at publish time: the walk may run for 90 s, and if the title is
       closed meanwhile the list must still be attributed to the process it was
       actually walked in.  The mapping refresh above has just re-read dmnt's
       metadata, so pid / title are as current as they can be.  Without a pid the
       scan generation and the rooted address are the only identity available. */
    {
        NxusChainOwner owner;
        memset(&owner, 0, sizeof(owner));
        owner.valid = true;
        owner.pid = nxusSessionProcessId();
        owner.program_id = nxusSessionProgramId();
        owner.session_id = nxusSessionId();
        owner.target_address = req.target_address;
        g_PtrJob.owner = owner;
        NXUS_LOG_DEBUG("ptrscan: stamping the chain list with pid=%llu title=%016llX "
                       "session=%u target=%08llX",
                       (unsigned long long)owner.pid,
                       (unsigned long long)owner.program_id,
                       (unsigned)owner.session_id,
                       (unsigned long long)owner.target_address);
    }

    /* Take the worker Thread slot, re-check the shutdown UNDER the claim (nxusServerExit
       sets that flag before it claims, so a Begin that passed the check at the top of
       this handler can still be refused here instead of creating a worker behind the
       exit path's join) and reap the previous worker before threadCreate() overwrites
       its Thread.  The previous worker has finished, or the BUSY gate above would have
       refused this request; the exit path's cancel is what brings a running walk back
       to ptrScanPublish(). */
    if (!ptrScanClaimSlot(200)) {
        free(regions);
        free(scratch);
        replyBusyReason(fd, type, seq, NXUS_REASON_BUSY_STATE);
        return;
    }
    if (atomic_load_explicit(&g_ServerExited, memory_order_acquire)) {
        ptrScanReleaseSlot();
        free(regions);
        free(scratch);
        replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                         NXUS_REASON_BUSY_STATE);
        return;
    }
    (void)ptrScanJoinSlotLocked();

    /* 16 KB: the engine's ~38 KB state is static and the deepest measured frame in
       this module is under 2 KB (the scan worker keeps an even larger engine on
       64 KB).  The stack lives in .bss next to the server/scan/event/HID stacks. */
    alignas(0x1000) static u8 ptrScanStack[0x4000];
    Result trc = threadCreate(&g_PtrThread, ptrScanThread, NULL, ptrScanStack,
                              sizeof(ptrScanStack), 0x2C, -2);
    if (R_SUCCEEDED(trc)) {
        g_PtrThreadLive = true;
        /* Running BEFORE threadStart(): a PtrScanGet that lands while the worker
           is writing g_Chains must see BUSY, never a half-written list.  The
           release store pairs with the acquire load in the PtrScanGet case. */
        g_PtrJobStartedMs = armTicksToNs(armGetSystemTick()) / 1000000ull;
        atomic_store_explicit(&g_PtrJobState, NxusPtrJob_Running, memory_order_release);
        threadStart(&g_PtrThread);
        /* Released only now: from here on nxusServerExit() may join the worker. */
        ptrScanReleaseSlot();
        NXUS_LOG("ptrscan: started on the worker thread (target=%08llX regions=%u) - "
                 "answering PTRSCAN_STARTED, the client polls PtrScanGet",
                 (unsigned long long)req.target_address, (unsigned)region_count);
        replyError(fd, type, seq, NXUS_RESULT_PTRSCAN_STARTED);
        return;
    }

    /* No thread available (kernel quota, low memory): walk here instead of failing
       a scan the console can still perform.  That is the old behaviour, so the
       reply is the old one - the chain list (or the walk's own error). */
    ptrScanReleaseSlot();
    NXUS_RESULT("threadCreate(ptrscan)", trc);
    NXUS_LOG("ptrscan: no worker thread - walking on the connection thread");
    ptrScanJobRun();
    const int state = atomic_load_explicit(&g_PtrJobState, memory_order_acquire);
    const Result walk_rc = g_PtrJobResult;
    /* Leave the state as Get() knew it (no pending result to report): the reply
       below carries the outcome, exactly as before this change. */
    atomic_store_explicit(&g_PtrJobState, NxusPtrJob_Idle, memory_order_release);
    if (state != NxusPtrJob_Done) {
        replyError(fd, type, seq, walk_rc);
        return;
    }
    sendChainList(fd, seq, type);
}

static void handleCheatExport(int fd, u16 type, u32 seq, const u8 *payload, u32 length) {
    /* g_Chains belongs to the pointer scan worker while it runs: indexing the
       array below would race with the walk rewriting it.  BUSY is also what the
       client's own scan gate reports, so a retry after the poll loop is natural. */
    if (ptrScanBusy()) {
        replyBusyReason(fd, type, seq, NXUS_REASON_BUSY_STATE);
        return;
    }
    if (length < sizeof(NxusCheatExportRequest)) {
        replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                         NXUS_REASON_BAD_LENGTH);
        return;
    }
    NxusCheatExportRequest req;
    memcpy(&req, payload, sizeof(req));

    /* The list may have been found in a title that is no longer running: exporting
       it would code that title's addresses into the game that runs now (see
       ptrChainOwnerCheck).  Checked before the index so a stale list answers
       "wrong target" instead of "no such chain". */
    const Result owner_rc = ptrChainOwnerCheck();
    if (R_FAILED(owner_rc)) {
        replyError(fd, type, seq, owner_rc);
        return;
    }
    if (req.index >= g_ChainCount) {
        replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                         NXUS_REASON_BAD_INDEX);
        return;
    }

    char *text = (char *)malloc(1024);
    if (text == NULL) { replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory)); return; }

    /* Which width the generated code must use.
     *
     * The list was walked with g_ChainWidth, and those chains only make sense
     * with the loads that found them: a 4-byte walk of a 64-bit title (or the
     * reverse) generates a code that walks a different graph.  The request's
     * value_width is the client's own guess, made from a mapping table it may
     * have read minutes ago (or from a dump of another title).  So when the
     * walked width is known it wins, and a disagreement is logged.  When it is
     * unknown (0: a list published by an older server, or none at all) the
     * request is used exactly as it always was - that keeps old clients working.
     *
     * The load form (is_32bit) follows the same width.  Mixing a 4-byte store
     * with 8-byte loads would pull the neighbouring field into the register, so
     * it cannot be inherited from the client flag once the width is known.
     * Exception: a 1/2-byte value_width is a store-size choice, not a claim
     * about the pointer width, so it is left alone while the loads follow the
     * walked width. */
    u32 value_width;
    int is_32bit;
    if (g_ChainWidth == 4 || g_ChainWidth == 8) {
        is_32bit = (g_ChainWidth == 4) ? 1 : 0;
        if (req.value_width == 1 || req.value_width == 2) {
            value_width = req.value_width;
        } else {
            if (req.value_width != 0 && req.value_width != g_ChainWidth) {
                NXUS_LOG("cheat: using the walked width %u (client asked %u)",
                         (unsigned)g_ChainWidth, (unsigned)req.value_width);
            }
            value_width = g_ChainWidth;
        }
    } else {
        value_width = req.value_width ? req.value_width : 4;
        is_32bit = (req.flags & NXUS_CHEAT_F_32BIT) ? 1 : 0;
    }

    int written = nxusCheatGenerate(&g_Chains[req.index], is_32bit,
                                    req.value, value_width,
                                    "Nxus", text, 1024);
    if (written <= 0) replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_UNSUPPORTED));
    else reply(fd, type, seq, text, (u32)written);
    free(text);
}

/* ---- scan results ------------------------------------------------------ */

static void sendHits(int fd, u32 seq, const NxusGetHitsRequest *req) {
    /* The list is tied to the target that produced it, and to the mapping table its
       mapping_idx values were stamped against: after a title switch every address
       belongs to a different process, and after a re-snapshot of the SAME title the
       indices name different regions - in both cases the batch would still look
       valid to the PC (it resolves against the base array it was given).  Refuse and
       discard BEFORE the pin is taken, so this path cannot leak one; the client has
       to rescan.  No dedicated NXUS_REASON_* exists for "the results no longer
       describe this table", and a reason word here would read as an argument
       problem, so the refusal stays a bare NXUS_ERR_BAD_STATE (the log names the
       cause). */
    if (!nxusSessionHitsMatchTarget()) {
        discardResultsOfEarlierTarget();
        replyError(fd, NxusCmd_ScanGetHits, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
        return;
    }
    /* One token pin covers both views for the whole reply: the hit list arrays and
       the mapping table are walked while it is held.  Every early return below
       unpins exactly this token, so no path can leak the pin - and a stray release
       in some other handler can no longer drop it. */
    NxusViewPin pin;
    if (!nxusSessionViewPinCurrent(&pin)) {
        /* Pin table exhausted (an unpin was forgotten somewhere): refusing is
           better than serving mapping bases nobody owns.  Permanent until that
           pin is released, hence SLOT_FULL instead of BUSY_STATE. */
        NXUS_LOG("hits: view pin table exhausted (%u held) - refusing the batch",
                 (unsigned)nxusSessionViewPinnedCount());
        replyBusyReason(fd, NxusCmd_ScanGetHits, seq, NXUS_REASON_SLOT_FULL);
        return;
    }
    const NxusHitList *hits = nxusSessionHits();
    const NxusMappingTable *maps = nxusSessionMappingsPinned(&pin);

    /* Both views are published by nxus_session.c: the hit list is NULL while a
       scan is running, and the mapping table is NULL when nothing has been
       snapshotted (or after Exit).  Answering with an empty batch keeps a stale
       client from crashing the whole sysmodule. */
    if (hits == NULL) {
        replyError(fd, NxusCmd_ScanGetHits, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
        nxusSessionViewUnpin(&pin);
        return;
    }

    u32 count = req->count;
    if (count > NXUS_MAX_HITS_PER_BATCH) count = NXUS_MAX_HITS_PER_BATCH;
    if (req->offset >= hits->count) count = 0;
    else if (req->offset + count > hits->count) count = hits->count - req->offset;

    const u32 map_count = (maps != NULL) ? maps->count : 0;
    /* header + mapping bases + hits.  Sized in u64: map_count comes from the
       target's mapping table and count from the client, so a u32 product could
       wrap, pass the buffer check and then overrun the allocation while filling
       it.  Refuse anything one reply cannot carry. */
    const u64 payload_u64 = (u64)sizeof(NxusHitBatchHeader) +
                            (u64)map_count * (u64)sizeof(u64) +
                            (u64)count * (u64)sizeof(NxusHit);
    if (payload_u64 > (u64)NXUS_NET_BUF_SIZE) {
        replyError(fd, NxusCmd_ScanGetHits, seq, NXUS_MAKE_RESULT(NXUS_ERR_TOO_LARGE));
        nxusSessionViewUnpin(&pin);
        return;
    }
    const u32 payload_size = (u32)payload_u64;

    u8 *buffer = (u8 *)malloc(payload_size);
    if (buffer == NULL) {
        replyError(fd, NxusCmd_ScanGetHits, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory));
        nxusSessionViewUnpin(&pin);
        return;
    }

    NxusHitBatchHeader header;
    memset(&header, 0, sizeof(header));
    header.session_id = nxusSessionId();
    /* A list sitting exactly at its capacity may have more hits that were never
       collected: say so instead of letting the client present it as complete. */
    if (hits->max_capacity != 0 && hits->count >= hits->max_capacity) {
        header.reserved |= NXUS_HITBATCH_TRUNCATED;
    }
    header.total = hits->count;
    header.value_size = hits->value_size;
    header.mapping_count = map_count;
    /* header.count is filled in below: the batch that is actually built may be
       shorter than `count` when hits are dropped (see the loop). */

    u32 offset = (u32)sizeof(header);
    for (u32 i = 0; i < map_count; i++) {
        memcpy(buffer + offset, &maps->entries[i].base, sizeof(u64));
        offset += (u32)sizeof(u64);
    }

    /* The PC resolves a hit as mapping_bases[mapping_idx] + offset and has nothing
       of its own to range-check it against (client.scan_hits() resolves an index it
       has no base for as 0).  A stale index from a mapping table that shrank (scan
       while the title remapped, so the target/generation check above did not fire)
       would therefore resolve to a completely unrelated region - and clamping the
       index to 0, the old behaviour, produced exactly that: a real-looking wrong
       address.  Drop such hits from the batch instead and count them.  The wire
       header's reserved word only has room for flags (core/nxus_protocol.h is
       shared by every client), so the batch is flagged with
       NXUS_HITBATCH_DROPPED - a page walk must not stop on an empty page while it
       is set - and the count is reported in the log ring, once per drop episode,
       because every page of the same list would otherwise repeat the same line. */
    static atomic_int logged_dropped;
    u32 written = 0;
    u32 dropped = 0;
    for (u32 i = 0; i < count; i++) {
        u32 index = req->offset + i;
        if ((u32)hits->addresses[index].mapping_idx >= map_count) {
            dropped++;
            continue;
        }
        NxusHit hit;
        memset(&hit, 0, sizeof(hit));
        hit.offset = hits->addresses[index].offset;
        hit.mapping_idx = hits->addresses[index].mapping_idx;
        hit.value_type = hits->addresses[index].reserved;
        memcpy(&hit.value, hits->values + (size_t)index * hits->value_size, hits->value_size);
        memcpy(buffer + offset, &hit, sizeof(hit));
        offset += (u32)sizeof(hit);
        written++;
    }
    if (dropped == 0) {
        /* A batch with nothing dropped re-arms the latch, so a later shrink is
           reported again instead of being swallowed by the first episode. */
        atomic_store_explicit(&logged_dropped, 0, memory_order_relaxed);
    } else if (atomic_exchange_explicit(&logged_dropped, 1, memory_order_relaxed) == 0) {
        NXUS_LOG("hits: dropped %u hit(s) whose mapping is gone", (unsigned)dropped);
    }

    header.count = written;
    /* Some of the requested hits were dropped because their mapping is gone: this
       page is lossy and may be empty even though later pages still hold hits, so
       say so on the wire instead of letting the PC's page walk read "empty" as
       "end of the list" and lose the rest.  Coexists with the truncated bit. */
    if (dropped != 0) {
        header.reserved |= NXUS_HITBATCH_DROPPED;
    }
    memcpy(buffer, &header, sizeof(header));

    /* Dropped hits were never written, so the reply is `offset` bytes - equal to
       payload_size when nothing was dropped. */
    reply(fd, NxusCmd_ScanGetHits, seq, buffer, offset);
    free(buffer);
    nxusSessionViewUnpin(&pin);
}

/* ---- LOG request (server-side protocol extension) -----------------------
 *
 * core/nxus_protocol.h is the shared wire contract and is frozen for this change,
 * so the shape of the OPTIONAL LogGet payload is declared here, with the spec the
 * PC client has to implement later.  The server is backward compatible either way:
 *
 *   NxusCmd_LogGet payload (8 bytes, optional, two little-endian u32)
 *     offset  bytes to skip from the END of the ring (0 = newest page)
 *     length  bytes wanted for this poll (0 = the default 8 KiB window)
 *
 * The ring keeps NXUS_LOG_RING_CAPACITY (16 KiB) of whole lines, so the whole
 * history is reachable in 2-3 polls: request a window, then advance `offset` by
 * (reply length - the "... (truncated N bytes)" line), because that note is
 * generated by the server and is not ring content (see nxus_log.h).  The reply
 * only ever carries whole lines: a partial line at either end of the window is
 * dropped and counted in the note.
 *
 * No payload - or one shorter than this struct - keeps the old behaviour: the
 * last 8 KiB of the ring, now cut on line boundaries instead of mid-line.
 */
#define NXUS_LOG_DEFAULT_WINDOW 8192u
typedef struct {
    u32 offset;
    u32 length;
} NxusLogRequest;
NXUS_STATIC_ASSERT(sizeof(NxusLogRequest) == 8, "NxusLogRequest must be 8 bytes");

/* ---- main dispatch ----------------------------------------------------- */

void nxusServerHandle(int fd, const NxusPacketHeader *header, const u8 *payload, u32 length, void *user) {
    (void)user;
    const u16 type = header->type;
    const u32 seq = header->seq;
    Result rc = 0;

    /* Any traffic counts as "the PC is still here": without this the pause
       watchdog would resume the target during a long scan or a hex-edit session,
       which only sends polls. */
    nxusSessionHeartbeat();

    /* Snapshots still run synchronously here, and a pointer scan does too when its
       worker thread could not be created, so while they work the connection thread
       cannot read the client's heartbeats either.  Tell the watchdog to stay quiet
       instead of resuming the target mid-operation.  A pointer scan that DID get a
       worker answers at once, so this flag only covers its setup: the polled
       PtrScanGet then feeds the watchdog like any other traffic. */
    g_CommandActive = true;
    g_CommandStartedMs = armTicksToNs(armGetSystemTick()) / 1000000ull;

    switch (type) {
        case NxusCmd_Nop:
            reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_Heartbeat:
            nxusSessionHeartbeat();
            reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_Pause:
            /* Real stop: dmnt breaks the cheat process it owns (65004 ->
               svc::BreakDebugProcess) while keeping the session, so scans and
               snapshots keep working.  Only if dmnt cannot stop it does
               pauseTarget() take the process over with an own debug session.
               A BUSY here means another pause/resume/attach owns the hand-off -
               the one refusal that a retry does fix, so it is named BUSY_STATE
               instead of going out as a bare Result. */
            rc = serverPause();
            if (R_FAILED(rc)) {
                if (resultIsBusyRetryable(rc))
                    replyBusyReason(fd, type, seq, NXUS_REASON_BUSY_STATE);
                else
                    replyError(fd, type, seq, rc);
            } else reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_Resume:
            /* Reverses whichever pause is in effect: dmnt's continue for a
               dmnt-held stop, continue + detach for a debug-session pause, plain
               continue while the PC holds a debugger. */
            rc = serverResume();
            if (R_FAILED(rc)) {
                if (resultIsBusyRetryable(rc))
                    replyBusyReason(fd, type, seq, NXUS_REASON_BUSY_STATE);
                else
                    replyError(fd, type, seq, rc);
            } else reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_ForceOpen:
            rc = nxusDmntForceOpen();
            /* dmnt owns the process now: publish pid/title/main immediately.  Status
               (and every main-relative scope the client derives from it) reads the
               session cache, which otherwise only a scan snapshot would fill. */
            if (R_SUCCEEDED(rc)) (void)nxusSessionRefreshIdentity();
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_ForceClose:
            rc = nxusDmntForceClose();
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_GetStatus: {
            NxusStatus st;
            fillStatus(&st);
            reply(fd, type, seq, &st, sizeof(st));
            break;
        }

        case NxusCmd_GetMetadata: {
            NxusProcessMetadata md;
            memset(&md, 0, sizeof(md));
            if (nxusDebugIsAttached()) {
                /* dmnt is closed: serve the values cached when we attached (the
                   client is told to scan before attaching so main/heap are filled). */
                md.process_id = nxusSessionProcessId();
                md.program_id = nxusSessionProgramId();
                md.main_nso_base = nxusSessionMainBase();
                md.main_nso_size = nxusSessionMainSize();
                reply(fd, type, seq, &md, sizeof(md));
                break;
            }
            rc = nxusDmntGetMetadata(&md);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else {
                /* The reply carries the authoritative values, so cache them here too:
                   GetStatus derives pid/program id/main from the session, and a client
                   that only asks for metadata must not leave it zeroed. */
                nxusSessionSetProcessIdentityEx(md.process_id, md.program_id,
                                                md.main_nso_base, md.main_nso_size);
                reply(fd, type, seq, &md, sizeof(md));
            }
            break;
        }

        case NxusCmd_GetMappingCount: {
            u64 count = 0;
            if (nxusDebugIsAttached()) {
                /* dmnt is closed: answer from the snapshot the session built with
                   svcQueryDebugProcessMemory instead of failing.  A snapshot taken
                   for an earlier target is re-taken first, so the PC never pages
                   through the previous title's mapping table.  The token pin is
                   dropped on both paths (the table may legitimately be NULL). */
                refreshMappingsAfterTargetChange();
                NxusViewPin pin;
                if (!nxusSessionViewPinCurrent(&pin)) {
                    NXUS_LOG("mapping count: view pin table exhausted (%u held) - refusing",
                             (unsigned)nxusSessionViewPinnedCount());
                    replyBusyReason(fd, type, seq, NXUS_REASON_SLOT_FULL);
                    break;
                }
                const NxusMappingTable *table = nxusSessionMappingsPinned(&pin);
                if (table != NULL) count = table->count;
                nxusSessionViewUnpin(&pin);
                reply(fd, type, seq, &count, sizeof(count));
                break;
            }
            rc = nxusDmntGetMappingCount(&count);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else reply(fd, type, seq, &count, sizeof(count));
            break;
        }

        case NxusCmd_GetMappings: {
            if (length < sizeof(NxusMappingsRequest)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            NxusMappingsRequest req;
            memcpy(&req, payload, sizeof(req));
            u32 max_count = req.max_count;
            if (max_count == 0 || max_count > 1024) max_count = 1024;

            NxusMemoryInfo *buffer = (NxusMemoryInfo *)malloc((size_t)max_count * sizeof(NxusMemoryInfo));
            if (buffer == NULL) { replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory)); break; }

            size_t got = 0;
            if (nxusDebugIsAttached()) {
                /* Token pin: the table is walked while it is held, and the pin is
                   dropped on every path out of this branch (a NULL table is a
                   legitimate "no snapshot", not an error, but the pin still goes).
                   Re-take the snapshot when it belongs to an earlier target: this is
                   the table the PC resolves hit addresses against. */
                refreshMappingsAfterTargetChange();
                NxusViewPin pin;
                if (!nxusSessionViewPinCurrent(&pin)) {
                    NXUS_LOG("mappings: view pin table exhausted (%u held) - refusing the page",
                             (unsigned)nxusSessionViewPinnedCount());
                    replyBusyReason(fd, type, seq, NXUS_REASON_SLOT_FULL);
                    free(buffer);
                    break;
                }
                const NxusMappingTable *table = nxusSessionMappingsPinned(&pin);
                if (table != NULL) {
                    /* The PC pages with a u64 offset.  Truncating it to u32 made the
                       page stop advancing above 4 GiB (and wrap for a negative value),
                       so the client re-read the first page for ever.  Compare in u64
                       instead: i is a u32 index, so i < start simply yields nothing
                       when the offset is past the table. */
                    const u64 start = req.offset;
                    const u32 table_count = table->count;   /* copied once */
                    for (u32 i = 0; i < table_count && got < max_count; i++) {
                        if ((u64)i < start) continue;
                        const NxusMappingEntry *m = &table->entries[i];
                        memset(&buffer[got], 0, sizeof(NxusMemoryInfo));
                        buffer[got].base_addr = m->base;
                        buffer[got].size = m->size;
                        /* the snapshot keeps the MemType: without it the PC-side
                           heap/TLS filters would see every region as "data" */
                        buffer[got].memory_type = m->type ? m->type : 4;
                        buffer[got].perm = m->reserved;
                        got++;
                    }
                }
                nxusSessionViewUnpin(&pin);
            } else {
                rc = nxusDmntGetMappings(buffer, max_count, (size_t)req.offset, &got);
                if (R_FAILED(rc)) {
                    replyError(fd, type, seq, rc);
                    free(buffer);
                    break;
                }
            }
            /* One reply must fit a net buffer.  got is bounded by max_count here
               (the buffer is sized from that), but the wire length is computed in
               u64 and checked so the u32 cast below cannot truncate silent. */
            const u64 reply_u64 = (u64)got * (u64)sizeof(NxusMemoryInfo);
            if (reply_u64 > (u64)NXUS_NET_BUF_SIZE) {
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_TOO_LARGE));
            } else {
                reply(fd, type, seq, buffer, (u32)reply_u64);
            }
            free(buffer);
            break;
        }

        case NxusCmd_Query: {
            if (length < sizeof(u64)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            u64 address = 0;
            memcpy(&address, payload, sizeof(address));
            NxusMemoryInfo info;
            memset(&info, 0, sizeof(info));
            rc = nxusDebugIsAttached() ? nxusDebugQueryMemory(address, &info)
                                       : nxusDmntQuery(address, &info);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else reply(fd, type, seq, &info, sizeof(info));
            break;
        }

        case NxusCmd_Read: {
            if (length < sizeof(NxusReadRequest)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            NxusReadRequest req;
            memcpy(&req, payload, sizeof(req));
            u32 size = req.size;
            if (size == 0 || size > NXUS_NET_BUF_SIZE - (u32)sizeof(NxusPacketHeader)) { replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_TOO_LARGE)); break; }

            u8 *buffer = (u8 *)malloc(size);
            if (buffer == NULL) { replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory)); break; }
            /* dmnt's accepted read size is undocumented: on failure retry with
               half (down to 4 KB) instead of failing the whole request. */
            u32 want = size;
            /* sessionRead picks the right source: dmnt:cht, or the debug handle
               while we hold a debug session (dmnt is closed then, so a direct
               dmnt call would fail every read - hex view, write read-back, scans). */
            int read_rc = nxusSessionReadMemory(req.address, buffer, want);
            while (read_rc != 0 && want > 4096u) {
                want /= 2;
                read_rc = nxusSessionReadMemory(req.address, buffer, want);
            }
            rc = (read_rc == 0) ? 0 : NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
            if (R_SUCCEEDED(rc)) size = want;
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else reply(fd, type, seq, buffer, size);
            free(buffer);
            break;
        }

        case NxusCmd_Write: {
            if (length < sizeof(NxusWriteHeader)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            NxusWriteHeader wh;
            memcpy(&wh, payload, sizeof(wh));
            if (wh.size == 0 || length < sizeof(NxusWriteHeader) + wh.size) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            /* While attached to the process dmnt:cht is closed, so the write
               has to go through the debug handle - otherwise hex editing (and
               the value patching the user just attached to do) silently fails. */
            if (nxusDebugIsAttached()) {
                rc = nxusDebugWriteMemory(wh.address, payload + sizeof(NxusWriteHeader), wh.size);
            } else {
                rc = nxusDmntWrite(wh.address, payload + sizeof(NxusWriteHeader), wh.size);
            }
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
            break;
        }

        case NxusCmd_GetModules: {
            /* collectModules() walks the mapping table the scan worker rebuilds
               under it (nxusSessionMappings()), so a running scan must be refused
               first - the same gate ScanGetHits / SnapshotCapture / PtrScanBegin
               use.  Without it a GetModules arriving mid-scan reads a table that
               is being re-published and can report a half-built module list. */
            if (nxusSessionScanState() == NxusScanState_Running) {
                replyBusyReason(fd, type, seq, NXUS_REASON_BUSY_STATE);
                break;
            }
            NxusModuleInfo *modules = (NxusModuleInfo *)calloc(NXUS_MAX_MODULES, sizeof(NxusModuleInfo));
            if (modules == NULL) { replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory)); break; }
            u32 found = collectModules(modules, NXUS_MAX_MODULES);
            reply(fd, type, seq, modules, found * (u32)sizeof(NxusModuleInfo));
            free(modules);
            break;
        }

        case NxusCmd_GetProcesses: {
            u64 pids[64];
            s32 count = 0;
            rc = svcGetProcessList(&count, pids, 64);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else {
                /* Never trust the kernel's count into the wire length: the reply is
                   sized from pids[], so anything outside 0..64 would read past it. */
                if (count < 0) count = 0;
                if (count > 64) count = 64;
                reply(fd, type, seq, pids, (u32)count * (u32)sizeof(u64));
            }
            break;
        }

        case NxusCmd_ScanBegin:
        case NxusCmd_ScanNext: {
            /* A pointer scan worker is holding its scratch, region array and chain
               reply (up to ~1.25 MB).  A new scan would add its chunk/window
               buffers on top of that; the pair was never resident at once while
               the walk owned the connection thread.  Refuse instead of risking the
               8 MB inner heap - the mirror image of the "a running scan refuses
               PtrScanBegin" gate. */
            if (ptrScanBusy()) {
                replyBusyReason(fd, type, seq, NXUS_REASON_BUSY_STATE);
                break;
            }
            if (length < sizeof(NxusScanRequest)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            NxusScanRequest req;
            memcpy(&req, payload, sizeof(req));
            (void)req;
            /* Optional tail, in this order:
                 [NxusRangeListHeader + entries]  (only with NXUS_SCAN_F_RANGES)
                 [NxusScanExt + pattern bytes + wildcard mask] */
            u32 value_type = NxusValueType_U32;
            u32 epsilon = 0;
            const u8 *pattern = NULL;
            const u8 *mask = NULL;
            u32 pattern_len = 0;
            u32 tail = (u32)sizeof(NxusScanRequest);

            if (req.flags & NXUS_SCAN_F_RANGES) {
                NxusRangeEntry list[NXUS_MAX_SCAN_RANGES];
                u32 next = 0;
                int count = nxusParseRangeList(payload, length, &next, list, NXUS_MAX_SCAN_RANGES);
                if (count < 0) {
                    /* malformed, or more entries than the protocol allows: reject rather
                       than clamp, which would read the ext/pattern from the wrong offset */
                    replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                     NXUS_REASON_BAD_LENGTH);
                    break;
                }
                nxusSessionSetScanRanges(list, (u32)count);
                tail = next;
            } else if (req.scope == NxusScope_Ranges) {
                /* list mode without a list: reject instead of scanning nothing */
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_ARG);
                break;
            } else {
                nxusSessionSetScanRanges(NULL, 0);
            }

            if (length >= tail + sizeof(NxusScanExt)) {
                NxusScanExt ext;
                memcpy(&ext, payload + tail, sizeof(ext));
                value_type = ext.value_type;
                epsilon = ext.epsilon_decimals;
                pattern_len = ext.pattern_len;
                const u32 room = length - tail - (u32)sizeof(NxusScanExt);
                if (pattern_len > 0) {
                    /* The wildcard mask lives at pattern + pattern_len, so the
                       declared length IS the mask offset.  Clamping it (the old
                       behaviour) moved the mask and made every "??" compare the
                       wrong byte, i.e. a silently wrong scan.  Reject a pattern
                       that does not fit the payload exactly instead. */
                    const bool want_mask = (req.flags & NXUS_SCAN_F_WILDCARD) != 0;
                    const u64 need = (u64)pattern_len * (want_mask ? 2u : 1u);
                    if (pattern_len > NXUS_SCAN_MAX_PATTERN || need > (u64)room) {
                        NXUS_LOG("scan: rejecting pattern_len=%u (room=%u, wildcard=%d) - "
                                 "the mask offset would not match the payload",
                                 (unsigned)pattern_len, (unsigned)room, want_mask ? 1 : 0);
                        replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                         NXUS_REASON_BAD_LENGTH);
                        break;
                    }
                    pattern = payload + tail + sizeof(NxusScanExt);
                    if (want_mask) mask = pattern + pattern_len;
                }
            }
            rc = (type == NxusCmd_ScanBegin)
                    ? nxusSessionScanBegin(&req, value_type, epsilon, pattern, pattern_len, mask)
                    : nxusSessionScanNext(&req, value_type, epsilon, pattern, pattern_len, mask);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else {
                NxusStatus st;
                fillStatus(&st);
                reply(fd, type, seq, &st, sizeof(st));
            }
            break;
        }

        case NxusCmd_ScanStatus: {
            NxusStatus st;
            fillStatus(&st);
            reply(fd, type, seq, &st, sizeof(st));
            break;
        }

        case NxusCmd_ScanCancel:
            rc = nxusSessionScanCancel();
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_ScanReset:
            nxusSessionReset();
            /* The PC's HEAP_BUDGET advice is "release the snapshots (or reset)", so a
               reset has to do the same thing the release command does: the scan
               results it drops are what a pointer scan was competing with, and the
               captures it leaves behind would keep the next PtrScanBegin refused. */
            snapshotReleaseSlots("ScanReset");
            reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_ScanUndo: {
            /* An undo rewinds the hit list to the baseline the previous pass
               captured, and that baseline - like the list - belongs to one target and
               one mapping table.  nxusSessionScanUndo() refuses it after a title
               switch / table rebuild (see there); name the cause and drop the stale
               results here, on the connection thread, exactly like the hits path.
               The discard helper owns the once-per-mismatch latch, so a client that
               retries the undo cannot flood the log ring.  A scan that is still
               running has no completed list to undo: it keeps the plain BUSY answer
               from the session (and the status path discards + logs the mismatch). */
            if (nxusSessionScanState() != NxusScanState_Running &&
                !nxusSessionHitsMatchTarget()) {
                discardResultsOfEarlierTarget();
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
                break;
            }
            rc = nxusSessionScanUndo();
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else {
                NxusStatus st;
                fillStatus(&st);
                reply(fd, type, seq, &st, sizeof(st));
            }
            break;
        }

        case NxusCmd_ScanGetHits: {
            /* The worker reallocs the hit arrays while it runs; reading them from
               the connection thread would be a use-after-free. */
            if (nxusSessionScanState() == NxusScanState_Running) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BUSY),
                                 NXUS_REASON_BUSY_STATE);
                break;
            }
            if (length < sizeof(NxusGetHitsRequest)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            NxusGetHitsRequest req;
            memcpy(&req, payload, sizeof(req));
            sendHits(fd, seq, &req);
            break;
        }

        case NxusCmd_SnapshotCapture: {
            /* Snapshot preparation rebuilds the mapping/region arrays the scan
               worker is reading, so a running scan must be refused first. */
            if (nxusSessionScanState() == NxusScanState_Running) {
                replyBusyReason(fd, type, seq, NXUS_REASON_BUSY_STATE);
                break;
            }
            /* Same rule for the pointer scan worker: its 256 KiB scratch, region
               array and (soon) chain reply are already on the heap, and
               estimateHeapPeak() cannot see the capture's own 256 KiB chunk on top
               of them.  Two of those buffers never coexisted before, because the
               walk owned the connection thread. */
            if (ptrScanBusy()) {
                replyBusyReason(fd, type, seq, NXUS_REASON_BUSY_STATE);
                break;
            }
            if (length < sizeof(NxusSnapshotRequest)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            NxusSnapshotRequest req;
            memcpy(&req, payload, sizeof(req));
            /* nxusSnapshotTake() rejects slot > 1 with a bare BAD_STATE; check it
               here so the reply names the argument instead of only the state. */
            if (req.slot > 1) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_SLOT);
                break;
            }
            /* nxusSnapshotTake() allocates the slot arrays on first use (and only
               frees them again on SnapshotRelease / ScanReset).  Refresh the
               accounting from the service AFTER the call instead of guessing: the
               capture can fail before or after allocation, and the charge must
               describe the arrays that actually exist.  The old pre-set bit marked
               a slot even when nothing was ever allocated and could not notice a
               release that freed the arrays. */
            NxusSnapshotSummary summary;
            memset(&summary, 0, sizeof(summary));
            rc = nxusSnapshotTake(req.slot, req.scope, req.range_begin, req.range_end,
                                  req.block_size, &summary);
            g_HeldSnapshotSlots = nxusSnapshotResidentSlots();
            NXUS_LOG_DEBUG("snapshot: slot accounting after capture (held=0x%X, "
                           "%llu B resident)",
                           (unsigned)g_HeldSnapshotSlots,
                           (unsigned long long)nxusSnapshotResidentBytes());
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else reply(fd, type, seq, &summary, sizeof(summary));
            break;
        }

        case NxusCmd_SnapshotDiff: {
            u32 from_slot = 0, to_slot = 1;
            if (length >= sizeof(NxusSnapshotDiffRequest)) {
                NxusSnapshotDiffRequest req;
                memcpy(&req, payload, sizeof(req));
                from_slot = req.from_slot;
                to_slot = req.to_slot;
            }
            NxusSnapshotSummary summary;
            memset(&summary, 0, sizeof(summary));
            /* nxusSnapshotCompare() refuses slot > 1 with a bare BAD_STATE; catch it
               first so the client knows the slot (not the state) was the problem. */
            if (from_slot > 1 || to_slot > 1) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_SLOT);
                break;
            }
            /* nxusSnapshotCompare() refuses A/B captures with different block
               sizes, but a bare BAD_STATE Result does not say why.  Mirror that
               check through the public summaries first so the client gets the
               reason code; the success path is untouched (an uncaptured slot
               reports 0, so only two real captures can mismatch). */
            NxusSnapshotSummary from_sum, to_sum;
            /* GetSummary() leaves the struct untouched for slot > 1, which a
               corrupt client can send; zero first so the check never reads
               uninitialised stack. */
            memset(&from_sum, 0, sizeof(from_sum));
            memset(&to_sum, 0, sizeof(to_sum));
            nxusSnapshotGetSummary(from_slot, &from_sum);
            nxusSnapshotGetSummary(to_slot, &to_sum);
            if (from_sum.block_size != 0 && to_sum.block_size != 0 &&
                from_sum.block_size != to_sum.block_size) {
                NXUS_LOG("snapshot diff: block size mismatch (%u vs %u) - reporting the reason",
                         (unsigned)from_sum.block_size, (unsigned)to_sum.block_size);
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_BLOCK_SIZE);
                break;
            }
            rc = nxusSnapshotCompare(from_slot, to_slot, &summary);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else reply(fd, type, seq, &summary, sizeof(summary));
            break;
        }

        case NxusCmd_SnapshotChanged: {
            /* The cached list belongs to the diff that produced it: once the
               session moved to another target (title switch, relaunch, re-attach)
               every address in it is the previous process's memory.  Refuse the
               page with BAD_STATE instead of handing those rectangles out - or,
               worse, replying "0 changed", which the client reads as "nothing
               changed in this target".  With no cached diff this stays true, so
               the old empty reply before the first SnapshotDiff is unchanged. */
            if (!nxusSnapshotDiffMatchesCurrent()) {
                NXUS_LOG("snapshot changed: the cached diff belongs to another target - "
                         "refusing the page (capture both slots and diff again)");
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
                break;
            }
            u32 offset = 0, count = 1024;
            if (length >= sizeof(NxusGetHitsRequest)) {
                NxusGetHitsRequest req;
                memcpy(&req, payload, sizeof(req));
                offset = req.offset;
                if (req.count > 0 && req.count < count) count = req.count;
            }
            NxusChangedBlockWire *blocks =
                (NxusChangedBlockWire *)calloc(count, sizeof(NxusChangedBlockWire));
            if (blocks == NULL) {
                replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory));
                break;
            }
            u32 n = nxusSnapshotGetChanged(blocks, count, offset);
            /* Same u64 sizing rule as the hit batch: the count comes from the
               client, so the wire length is computed and checked before the u32
               cast instead of being multiplied in u32. */
            const u64 reply_u64 = (u64)n * (u64)sizeof(NxusChangedBlockWire);
            if (reply_u64 > (u64)NXUS_NET_BUF_SIZE) {
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_TOO_LARGE));
            } else {
                reply(fd, type, seq, blocks, (u32)reply_u64);
            }
            free(blocks);
            break;
        }

        case NxusCmd_SnapshotRelease:
            /* No payload and no process needed: invalidating the two slots never
               touches target memory (see snapshotReleaseSlots()).  It is allowed
               while a scan or a pointer scan runs - it only drops what the heap
               estimate charges for, and nothing here reads either engine's arrays,
               which is what lets the NEXT PtrScanBegin pass the budget guard. */
            snapshotReleaseSlots("SnapshotRelease command");
            reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_PtrScanBegin:
            /* Same reason as SnapshotCapture: the pointer scan walks the mapping
               snapshot the worker rebuilds under it. */
            if (nxusSessionScanState() == NxusScanState_Running) {
                replyBusyReason(fd, type, seq, NXUS_REASON_BUSY_STATE);
                break;
            }
            handlePtrScanBegin(fd, type, seq, payload, length);
            break;

        case NxusCmd_PtrScanGet: {
            /* The walk runs on a worker thread (see the pointer scan worker
               comment): while it owns g_Chains the only honest answer is BUSY, so
               a polling client can tell "still running" from "this is the result".
               An empty list would read as "no chains found" and hide the walk. */
            const int ptr_state = atomic_load_explicit(&g_PtrJobState, memory_order_acquire);
            if (ptr_state == NxusPtrJob_Running) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BUSY),
                                 NXUS_REASON_BUSY_STATE);
                break;
            }
            if (ptr_state == NxusPtrJob_Failed) {
                /* Keep reporting the failure until the next Begin.  Clearing it to
                   Idle made the second poll answer from the empty list the failed
                   walk left behind, i.e. "no chains (complete)" - worse than an
                   error, because the client would trust it. */
                replyError(fd, type, seq, g_PtrJobResult);
                break;
            }
            /* Idle (never started / after a failure) or Done: the list is stable.
               Stable is not the same as CURRENT, though: the PC can start another
               game and then poll the result, and those chains belong to the title
               that was scanned.  Serve them only while the stamp still matches. */
            const Result owner_rc = ptrChainOwnerCheck();
            if (R_FAILED(owner_rc)) {
                replyError(fd, type, seq, owner_rc);
                break;
            }
            sendChainList(fd, seq, type);
            break;
        }

        case NxusCmd_CheatExport:
            handleCheatExport(fd, type, seq, payload, length);
            break;

        case NxusCmd_FrozenList: {
            if (nxusDebugIsAttached()) {
                /* dmnt (and with it the freeze list) is closed: an empty list is the
                   honest answer - the client labels it "no frozen addresses". */
                reply(fd, type, seq, NULL, 0);
                break;
            }
            u64 offset = 0;
            u32 max_count = 64;
            /* Paging: the request carries a u64 offset at the same place as
               NxusMappingsRequest (offset, max_count).  NxusFrozenRequest itself
               (address, width) has no offset, so a client that sends one gets the
               first page - offset 0 - and only a caller that asks for a page is
               served past it.  Ignoring the offset made every page the first one,
               and since dmnt's table holds up to 0x80 entries while the default page
               is 64, everything past the 64th entry was unreachable. */
            if (length >= sizeof(NxusMappingsRequest)) {
                NxusMappingsRequest req;
                memcpy(&req, payload, sizeof(req));
                /* The payload is ambiguous: NxusFrozenRequest {address,width} is
                   byte-compatible with NxusMappingsRequest {offset,max_count}.
                   Honouring a width (1..8) as a page size truncated the reply to a
                   couple of rows, so a value that small is treated as the
                   frozen-request shape.  The same range check gates the offset: a
                   page size outside 16..512 means the whole 16 bytes are read as a
                   NxusFrozenRequest, whose first word is an address - and taking
                   that as an offset would point past every table. */
                if (req.max_count >= 16 && req.max_count <= 512) {
                    offset = req.offset;
                    max_count = req.max_count;
                }
            }
            NxusFrozenAddressEntry *entries = (NxusFrozenAddressEntry *)calloc(max_count, sizeof(NxusFrozenAddressEntry));
            NxusFrozenEntry *wire = (NxusFrozenEntry *)calloc(max_count, sizeof(NxusFrozenEntry));
            if (entries == NULL || wire == NULL) {
                free(entries); free(wire);
                replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory));
                break;
            }
            size_t got = 0;
            rc = nxusDmntGetFrozenEntries(entries, max_count, (size_t)offset, &got);
            /* The line that makes paging observable: without it "the client
               re-reads page 0 for ever" and "dmnt has fewer entries than we asked
               for" look identical in the log.  Logged only when it says something
               - a non-first page, or a page that filled up (the truncation case
               below) - because the GUI polls FrozenList and an unconditional line
               would drown the ring buffer this diagnosis is read from. */
            if (R_SUCCEEDED(rc) && (offset != 0 || got == (size_t)max_count)) {
                NXUS_LOG("frozen: list page offset=%llu max=%u got=%u",
                         (unsigned long long)offset, (unsigned)max_count, (unsigned)got);
            }
            if (R_FAILED(rc)) {
                replyError(fd, type, seq, rc);
            } else {
                /* The reply is a bare NxusFrozenEntry[] (the client derives the
                   count from the length), so there is no header field for the
                   total.  Truncation is therefore reported here instead: a page
                   that came back full may not be the whole list, and only a dmnt
                   count tells whether it is.  One extra IPC, and only when the
                   page is full. */
                if (got == (size_t)max_count) {
                    u64 total = 0;
                    if (R_SUCCEEDED(nxusDmntGetFrozenCount(&total)) &&
                        offset + (u64)got < total) {
                        NXUS_LOG("frozen: list page is truncated (offset=%llu got=%u "
                                 "total=%llu) - ask for the next page",
                                 (unsigned long long)offset, (unsigned)got,
                                 (unsigned long long)total);
                    }
                }
                for (size_t i = 0; i < got; i++) {
                    wire[i].address = entries[i].address;
                    wire[i].value = entries[i].value;
                    wire[i].width = entries[i].width;
                }
                reply(fd, type, seq, wire, (u32)(got * sizeof(NxusFrozenEntry)));
            }
            free(entries); free(wire);
            break;
        }

        case NxusCmd_FrozenEnable: {
            if (length < sizeof(NxusFrozenRequest)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            NxusFrozenRequest req;
            memcpy(&req, payload, sizeof(req));
            /* dmnt rejects a width outside {1,2,4,8} with an opaque Result; the
               field is client input, so name it before the IPC round trip. */
            if (req.width != 1 && req.width != 2 && req.width != 4 && req.width != 8) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_ARG);
                break;
            }
            u64 value = 0;
            if (nxusDebugIsAttached()) {
                /* Freezing is a dmnt cheat-VM feature and dmnt is closed while we
                   hold the debug handle, so answer with a clear result instead of
                   a dmnt error the client cannot interpret.  Retrying cannot fix
                   this: only DebugDetach reopens dmnt, so the reason says so. */
                NXUS_LOG("frozen: enable %016llX refused - the debug session holds dmnt closed",
                         (unsigned long long)req.address);
                replyBusyReason(fd, type, seq, NXUS_REASON_DEBUG_LOCKED);
                break;
            }
            rc = nxusDmntEnableFrozen(req.address, req.width, &value);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else {
                frozenOwnedAdd(req.address);
                reply(fd, type, seq, &value, sizeof(value));
            }
            break;
        }

        case NxusCmd_FrozenDisable: {
            if (length < sizeof(u64)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            u64 address = 0;
            memcpy(&address, payload, sizeof(address));
            if (nxusDebugIsAttached()) {
                /* Nothing can be frozen while attached (FrozenEnable answers BUSY),
                   so there is nothing to remove: acknowledge instead of surfacing a
                   dmnt error the client cannot act on. */
                reply(fd, type, seq, NULL, 0);
                break;
            }
            rc = nxusDmntDisableFrozen(address);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else {
                frozenOwnedRemove(address);
                reply(fd, type, seq, NULL, 0);
            }
            break;
        }

        case NxusCmd_Config: {
            /* Two payload shapes share this command:
                 - sizeof(NxusConfig) (32 B), optionally followed by a
                   sizeof(NxusDebugConfig) (16 B) debug tail: the full settings;
                 - exactly sizeof(NxusDebugConfig) (16 B): the debug settings alone
                   (watch style, auto_continue).  The PC sends this shape when it
                   toggles stop-on-hit while a breakpoint is armed, and the hotkey /
                   watchdog / chunk fields must keep their current values - reading
                   those 16 bytes as a NxusConfig would zero the controller hotkey.
               Every other length changes nothing instead of being half-applied. */
            const bool debug_only = (length == sizeof(NxusDebugConfig));

            /* Neither shape: the old fall-through applied nothing and answered with
               the current settings, so a malformed request looked like a success. */
            if (!debug_only && length < sizeof(NxusConfig)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_CONFIG);
                break;
            }

            if (!debug_only && length >= sizeof(NxusConfig)) {
                memcpy(&g_Config, payload, sizeof(g_Config));
            /* Apply the new console log level immediately; it is the only consumer of
               NxusConfig.log_level and nothing else can reach it from outside. */
            nxusLogSetLevel(g_Config.log_level);
                nxusSessionSetWatchdogTimeout(g_Config.watchdog_timeout_ms);
                nxusSessionSetChunkSize(g_Config.chunk_size);
                nxusHidConfigure(g_Config.hotkey_mask, g_Config.hotkey_hold_ms, g_Config.hotkey_enabled);
                if (g_Config.hotkey_enabled && g_Config.hotkey_mask != 0) nxusHidStart();
            }
            /* optional tail: NxusDebugConfig (watchpoint encoding style) */
            if (debug_only || length >= sizeof(NxusConfig) + sizeof(NxusDebugConfig)) {
                NxusDebugConfig dbg;
                const u8 *dbg_src = debug_only ? payload : payload + sizeof(NxusConfig);
                memcpy(&dbg, dbg_src, sizeof(dbg));
                /* A pause that went through the debug session must survive a
                   settings round-trip: auto_continue=1 releases a held target at
                   once (that is what the setter is for), which would thaw the game
                   behind the PC's back while it still believes it is frozen.
                   Resume is the only way out of a debug-session pause.
                   The state read is a short locked section; the configure call
                   itself must not run under the lock. */
                if (dbg.auto_continue != 0 && pauseIsViaDebug()) {
                    NXUS_LOG("debug config: auto_continue kept at 0 while a debug-session pause holds the target");
                    dbg.auto_continue = 0;
                }
                nxusDebugConfigure(&dbg);
                NXUS_LOG("debug config%s: watch style=%u auto_continue=%u",
                         debug_only ? " (debug-only payload)" : "",
                         (unsigned)dbg.style, (unsigned)dbg.auto_continue);
            }
            reply(fd, type, seq, &g_Config, sizeof(g_Config));
            break;
        }

        case NxusCmd_LogGet: {
            /* Used to answer a fixed last 8 KiB, so the older half of the 16 KiB ring
               was unreachable and every reply started in the middle of a line.  The
               optional NxusLogRequest (see above) pages backwards through the whole
               ring; nxusLogWindow() cuts on line boundaries and reports what it had
               to drop.  A client that sends nothing gets the same 8 KiB window it
               always got, now made of whole lines. */
            NxusLogRequest req;
            req.offset = 0;
            req.length = NXUS_LOG_DEFAULT_WINDOW;
            if (length >= sizeof(req)) memcpy(&req, payload, sizeof(req));
            /* Clamp the request to what the ring and the reply buffer can hold: the
               fields come straight off the wire. */
            if (req.length == 0) req.length = NXUS_LOG_DEFAULT_WINDOW;
            if (req.length > NXUS_LOG_RING_CAPACITY) req.length = NXUS_LOG_RING_CAPACITY;

            static char log[NXUS_LOG_RING_CAPACITY + NXUS_LOG_NOTE_MAX + 1];
            size_t n = nxusLogWindow(log, sizeof(log), req.offset, req.length);
            reply(fd, type, seq, log, (u32)n);
            break;
        }

        /* ---- debug mode (own kernel debug session) ---- */

        case NxusCmd_DebugAttach: {
            u64 pid = 0;
            if (length >= sizeof(u64)) {
                memcpy(&pid, payload, sizeof(pid));
            }

            /* Attaching twice is a no-op (only one debug handle exists), and it
               must not query dmnt: the metadata getter auto-reopens dmnt on
               failure, which would fight the session that already owns the
               process. */
            if (nxusDebugIsAttached()) {
                NxusDebugStatus st;
                nxusDebugGetStatus(&st);
                reply(fd, type, seq, &st, sizeof(st));
                break;
            }

            /* Taking the debug handle moves the same state a pause does (g_Debug,
               the pause flag, the HW slots).  Claim the pause slot so a hotkey
               pause cannot run attach/detach concurrently: the loser gets BUSY
               instead of closing a handle the winner is still using.  That one is
               transient (the in-flight hand-off finishes), so it is BUSY_STATE. */
            if (!pauseTryEnter()) {
                replyBusyReason(fd, type, seq, NXUS_REASON_BUSY_STATE);
                break;
            }

            /* Read dmnt's metadata BEFORE taking the process.  After
               svcDebugActiveProcess dmnt is closed and this is the only source of
               program_id / main NSO base, so losing it here would make --scope main
               fail until a later dmnt session. */
            NxusProcessMetadata md;
            memset(&md, 0, sizeof(md));
            const bool have_md = R_SUCCEEDED(nxusDmntGetMetadata(&md));

            if (pid == 0) {
                pid = nxusSessionProcessId();
            }
            if (pid == 0 && have_md) {
                pid = md.process_id;
            }

            rc = nxusDebugAttach(pid);
            if (R_FAILED(rc)) {
                /* nxusDebugAttach() answers BUSY while a previous session is still
                   being released (its event thread is joined by the tick): a retry
                   a moment later succeeds, so name it instead of leaving a bare
                   BUSY that reads like "the console is busy, give up". */
                if (resultIsBusyRetryable(rc)) {
                    NXUS_LOG("debug attach: the previous session is still being released");
                    replyBusyReason(fd, type, seq, NXUS_REASON_RETRY_LATER);
                } else if (rc == (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE)) {
                    /* The only BAD_STATE nxusDebugAttach() reports is its pid
                       mismatch refusal: the kernel attached to a process other than
                       the requested pid, so the session was detached again and
                       NOTHING is attached now.  Name the rejected argument instead
                       of sending the bare state error, which a client reads as
                       "wrong moment to ask" - the pid itself is what has to be
                       corrected. */
                    NXUS_LOG("debug attach: pid=%llu is not the process the session took - "
                             "detached, nothing attached", (unsigned long long)pid);
                    replyErrorReason(fd, type, seq, rc, NXUS_REASON_BAD_ARG);
                } else {
                    replyError(fd, type, seq, rc);
                }
            } else {
                /* The attach owns the pause state now (nxusDebugAttach sets it): a
                   hotkey hold from before is no longer what keeps the target. */
                pauseClearHotkeyHold();

                /* Only a DIFFERENT process invalidates the cached identity: attaching
                   to the current game keeps main_base, which the day-1 flow (scan
                   first, attach afterwards) relies on.  When dmnt still describes the
                   process we just attached to, carry all four fields over instead of
                   zeroing main_base. */
                const bool same_process = (pid == nxusSessionProcessId());
                const bool md_matches = have_md && (md.process_id == pid);
                if (!same_process) {
                    if (md_matches) {
                        nxusSessionSetProcessIdentityEx(pid, md.program_id,
                                                        md.main_nso_base, md.main_nso_size);
                        NXUS_LOG("attached to pid=%llu: identity kept from dmnt "
                                 "(title=%016llX main=%08llX+%08llX)",
                                 (unsigned long long)pid, (unsigned long long)md.program_id,
                                 (unsigned long long)md.main_nso_base,
                                 (unsigned long long)md.main_nso_size);
                    } else {
                        nxusSessionSetProcessIdentity(pid, 0, 0);
                        NXUS_LOG("attached to pid=%llu: dmnt metadata unavailable - "
                                 "main base unknown until the next dmnt session",
                                 (unsigned long long)pid);
                    }
                } else if (md_matches && nxusSessionMainBase() == 0 && md.main_nso_base != 0) {
                    nxusSessionSetProcessIdentityEx(pid, md.program_id,
                                                    md.main_nso_base, md.main_nso_size);
                    NXUS_LOG("attached to pid=%llu: filled missing main base from dmnt "
                             "(%08llX+%08llX)",
                             (unsigned long long)pid,
                             (unsigned long long)md.main_nso_base,
                             (unsigned long long)md.main_nso_size);
                } else {
                    NXUS_LOG("attached to pid=%llu: process identity preserved "
                             "(main=%08llX+%08llX)",
                             (unsigned long long)pid,
                             (unsigned long long)nxusSessionMainBase(),
                             (unsigned long long)nxusSessionMainSize());
                }
                NxusDebugStatus st;
                nxusDebugGetStatus(&st);
                reply(fd, type, seq, &st, sizeof(st));
            }
            pauseLeave();
            break;
        }

        case NxusCmd_DebugDetach:
            /* Same serialisation as DebugAttach: the detach joins the event thread
               and closes g_Debug, which a concurrent hotkey pause would be using. */
            if (!pauseTryEnter()) {
                replyBusyReason(fd, type, seq, NXUS_REASON_BUSY_STATE);
                break;
            }
            /* The detach (thread join + handle close) runs outside the state
               lock; only the resulting pause/flag change is committed under it. */
            rc = nxusDebugDetach();
            pauseLeave();
            if (R_SUCCEEDED(rc) && pauseReleaseDebugSessionPause()) {
                /* Detaching ends a pause that went through the session: keep the
                   reported pause flag in step with the released target. */
                NXUS_LOG("debug detach released a debug-session pause");
            }
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_DebugStatus: {
            NxusDebugStatus st;
            nxusDebugGetStatus(&st);
            reply(fd, type, seq, &st, sizeof(st));
            break;
        }

        case NxusCmd_BreakSet: {
            if (length < sizeof(NxusBreakRequest)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            NxusBreakRequest request;
            memcpy(&request, payload, sizeof(request));
            /* Mirrors the checks nxusDebugSetBreak() already makes, so the client
               learns which field is wrong instead of only "bad state".  The slot is
               deliberately not checked: SetBreak auto-allocates for an out-of-range
               slot, which is the documented way to ask for a free one. */
            if (request.size != 1 && request.size != 2 && request.size != 4 && request.size != 8) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_ARG);
                break;
            }
            if (request.kind > NxusBp_Access) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_ARG);
                break;
            }
            rc = nxusDebugSetBreak(&request);
            if (R_FAILED(rc)) {
                /* Inside SetBreak, BUSY has exactly two producers (nxus_debug.c):
                   no free hardware slot for the kind, and a full break table.  Both
                   are permanent until a breakpoint is cleared, so they must not
                   share the "retry, something is running" meaning. */
                if (resultIsBusyRetryable(rc)) {
                    NXUS_LOG("break set: no free slot (kind=%u requested slot=0x%X) - "
                             "clear a breakpoint first",
                             (unsigned)request.kind, (unsigned)request.slot);
                    replyBusyReason(fd, type, seq, NXUS_REASON_SLOT_FULL);
                } else {
                    replyError(fd, type, seq, rc);
                }
            } else {
                NxusBreakEntry entries[NXUS_DEBUG_SERVER_BREAK_MAX];
                u32 n = nxusDebugGetBreaks(entries, NXUS_DEBUG_SERVER_BREAK_MAX);
                reply(fd, type, seq, entries, n * (u32)sizeof(NxusBreakEntry));
            }
            break;
        }

        case NxusCmd_BreakClear: {
            if (length < sizeof(u32)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            u32 slot = 0;
            memcpy(&slot, payload, sizeof(slot));
            /* Mirrors nxusDebugClearBreak()'s accepted set (six instruction slots
               0..5, four watch slots 0x10..0x13) so the reply names the slot. */
            if (slot > 5 && (slot < 0x10 || slot > 0x13)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_SLOT);
                break;
            }
            rc = nxusDebugClearBreak(slot);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
            break;
        }

        case NxusCmd_BreakList: {
            NxusBreakEntry entries[NXUS_DEBUG_SERVER_BREAK_MAX];
            u32 n = nxusDebugGetBreaks(entries, NXUS_DEBUG_SERVER_BREAK_MAX);
            reply(fd, type, seq, entries, n * (u32)sizeof(NxusBreakEntry));
            break;
        }

        case NxusCmd_DebugContinue:
            rc = nxusDebugContinueAll();
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_DebugStep: {
            /* Optional u64 thread_id; without it the thread the stop was published
               for is stepped (the PC usually just repeats "step"). */
            u64 thread_id = 0;
            if (length >= sizeof(u64)) memcpy(&thread_id, payload, sizeof(thread_id));
            if (thread_id == 0) thread_id = nxusDebugStoppedThread();
            rc = nxusDebugStep(thread_id);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
            break;
        }

        case NxusCmd_ThreadList: {
            NxusThreadEntry threads[NXUS_DEBUG_SERVER_MAX_THREADS];
            u32 n = nxusDebugGetThreads(threads, NXUS_DEBUG_SERVER_MAX_THREADS);
            reply(fd, type, seq, threads, n * (u32)sizeof(NxusThreadEntry));
            break;
        }

        case NxusCmd_RegsGet: {
            if (length < sizeof(u64)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            u64 thread_id = 0;
            memcpy(&thread_id, payload, sizeof(thread_id));
            NxusThreadContext ctx;
            memset(&ctx, 0, sizeof(ctx));
            rc = nxusDebugGetRegs(thread_id, &ctx);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else reply(fd, type, seq, &ctx, sizeof(ctx));
            break;
        }

        case NxusCmd_RegsSet: {
            if (length < sizeof(NxusThreadContext)) {
                replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE),
                                 NXUS_REASON_BAD_LENGTH);
                break;
            }
            NxusThreadContext ctx;
            memcpy(&ctx, payload, sizeof(ctx));
            rc = nxusDebugSetRegs(ctx.thread_id, &ctx);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
            break;
        }

        case NxusCmd_HitGet: {
            u32 count = NXUS_DEBUG_SERVER_MAX_HITS;
            if (length >= sizeof(NxusGetHitsRequest)) {
                NxusGetHitsRequest req;
                memcpy(&req, payload, sizeof(req));
                if (req.count > 0 && req.count < count) count = req.count;
            }
            NxusBreakHit *hits = (NxusBreakHit *)calloc(count, sizeof(NxusBreakHit));
            if (hits == NULL) {
                replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory));
                break;
            }
            u32 n = nxusDebugGetHits(hits, count);
            reply(fd, type, seq, hits, n * (u32)sizeof(NxusBreakHit));
            free(hits);
            break;
        }

        case NxusCmd_HitClear:
            nxusDebugClearHits();
            reply(fd, type, seq, NULL, 0);
            break;

        default:
            NXUS_LOG("unknown command 0x%04X", (unsigned)type);
            replyErrorReason(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_UNSUPPORTED),
                             NXUS_REASON_UNKNOWN_COMMAND);
            break;
    }

    g_CommandActive = false;
    /* A handler longer than the watchdog timeout leaves the timer expired, so the
       next tick would resume a paused target the moment the command returns.
       Treat the completion as client activity. */
    nxusSessionHeartbeat();
}

/* If the PC vanishes while a debug session is open, hand the process back:
   dmnt stays closed (the game's own cheats are dead) until someone reopens it,
   so a stale attach must not survive an idle client.  A pause that went through
   the session is released the same way, and the client is told with the same
   event the watchdog uses, so its "paused" state cannot go stale. */
static void reapStaleDebugSession(void) {
    if (!nxusDebugIsAttached()) return;
    if (!nxusSessionIdleExpired(NXUS_DEBUG_IDLE_TIMEOUT_MS)) return;
    /* Same hand-off claim as Pause/Resume: nxusDebugDetach() joins the event
       thread, so it must not run underneath an attach/detach that is in flight.
       If one is running, skip and retry on the next tick. */
    if (!pauseTryEnter()) return;
    NXUS_LOG("no client activity for %u ms - detaching the debug session",
             (unsigned)NXUS_DEBUG_IDLE_TIMEOUT_MS);
    nxusDebugDetach();
    if (pauseReleaseDebugSessionPause()) {
        NXUS_LOG("stale debug-session pause released");
        nxusNetSendEvent(NxusEvent_AutoResume, NULL, 0);
    }
    pauseLeave();
}

/* Keep the session's cached identity in step with dmnt, at most once a second.
   ForceOpen from the PC and a game restart both change pid / main base without any
   scan snapshotting the metadata, while Status, main-relative scopes and the GUI's
   "main+offset" all read that cache.  The hasCheatProcess probe gates the metadata
   read (no target = no need to refresh, and GetMetadata's auto-reopen must not run
   blind), and a debug session is skipped entirely because dmnt is closed then. */
static void refreshTargetIdentityThrottled(void) {
    static u64 last_ms = 0;
    const u64 now = armTicksToNs(armGetSystemTick()) / 1000000ull;
    if (last_ms != 0 && now - last_ms < 1000ull) return;
    last_ms = now;

    if (nxusDebugIsAttached()) return;
    bool has_process = false;
    if (R_FAILED(nxusDmntHasCheatProcess(&has_process)) || !has_process) return;
    (void)nxusSessionRefreshIdentity();
    /* The refresh may have moved the session to a different title (the PC can quit
       game A, start game B, and never ask for a status in between).  The stored hits
       and the mapping snapshot then describe the process we left, so drop them here
       too - once per second is enough, and with a debug session attached dmnt is
       closed, which is why this sits after the refresh instead of at the top.
       Identity only: this also runs on the main thread, where reacting to a mapping
       generation change could race a ScanBegin between its table publication and its
       owner stamp (see discardHitsOfEarlierTarget).  A rebuilt table is detected by
       the next status / hits request on the connection thread. */
    discardHitsOfEarlierTarget(false, false);
    /* Same reason, for the frozen table: a freeze stamped for the title that just
       went away cannot be released any more, and keeping it would let the release
       that runs once the client is gone touch the same address in the title that
       runs now.  Dropping is all that happens here (see
       frozenOwnedDropEarlierTarget) - this runs on the main thread too, where
       calling into dmnt to release would be an unasked-for write. */
    (void)frozenOwnedDropEarlierTarget();
}

/* The debugee exited while we were attached.  The event thread has already
   dropped g_Attached / the stop state and re-enabled dmnt's auto-reopen, but it
   cannot close the debug handle itself (nxusDebugDetach() joins the event thread,
   so calling it from there would self-deadlock).  Collect the dead session here,
   on the main thread: nxusDebugDetach() then joins the already-finished event
   thread, wipes the hardware slots, closes the handle and reopens dmnt. */
static void reapExitedDebugSession(void) {
    if (!nxusDebugExitedPending()) return;
    /* Do not join a session that a Pause/Resume is currently using: the claim
       keeps the handle stable and the next tick retries. */
    if (!pauseTryEnter()) return;
    NXUS_LOG("debug: debugee exited - releasing the dead debug session");
    Result rc = nxusDebugDetach();
    if (R_FAILED(rc)) NXUS_RESULT("debug session release after exit", rc);
    /* The process is gone, so any pause it was held for is meaningless. */
    if (pauseReleaseDebugSessionPause())
        NXUS_LOG("debug-session pause released (debugee exited)");
    pauseLeave();
}

/* How long a frozen address may outlive its client before Nxus releases it.  Long
   enough to survive a client restart, short enough that the user does not need a
   reboot when the PC crashed. */
#define NXUS_FROZEN_RELEASE_AFTER_MS 30000ull
/* Longer than the frozen grace: a client that reconnects right away should find
   its scan still running rather than silently cancelled. */
#define NXUS_SCAN_ABANDON_AFTER_MS 60000ull

void nxusServerTick(void) {
    {
        static u64 last_client_ms;
        const u64 now_ms = armTicksToNs(armGetSystemTick()) / 1000000ull;
        if (nxusNetClientFd() >= 0) {
            last_client_ms = now_ms;
            flushFrozenReleased();
        } else if (g_FrozenOwnedCount > 0) {
            /* No client: a fresh boot has no timestamp yet, so start the grace
               window on the first tick without one. */
            if (last_client_ms == 0 || now_ms - last_client_ms >= NXUS_FROZEN_RELEASE_AFTER_MS) {
                releaseOwnedFrozen();
            }
        }

        /* Deadman for the pointer-scan worker: the 90 s budget is enforced inside
           the walk, but a wedged IPC read could keep it Running for ever and that
           closes four BUSY gates (Begin/CheatExport/ScanBegin/SnapshotCapture). */
        if (ptrScanBusy()) {
            const u64 started = g_PtrJobStartedMs;
            const u64 limit_ms = NXUS_PTRSCAN_TIME_BUDGET_MS + 30000ull;  /* budget + slack */
            if (started != 0 && now_ms > started && now_ms - started > limit_ms) {
                ptrScanRequestCancel("worker exceeded its time budget");
            } else if (nxusNetClientFd() < 0 && last_client_ms != 0 &&
                       now_ms - last_client_ms >= NXUS_SCAN_ABANDON_AFTER_MS) {
                ptrScanRequestCancel("client gone");
            }
        }

        /* A scan started by a client that then disappeared keeps the worker, the SD
           baseline and the SCANNING flag alive for minutes, and a reconnecting client
           only ever gets BUSY.  Cancel it once nobody has been connected for a while. */
        if (nxusNetClientFd() < 0 && nxusSessionScanState() == NxusScanState_Running &&
            last_client_ms != 0 && now_ms - last_client_ms >= NXUS_SCAN_ABANDON_AFTER_MS) {
            NXUS_LOG("scan: no client for %llu ms - cancelling the abandoned scan",
                     (unsigned long long)(now_ms - last_client_ms));
            (void)nxusSessionScanCancel();
        }
    }

    /* Checked first: a long handler (snapshot, pointer scan) blocks the
       connection thread, so both the pause watchdog and the stale-session
       reaper would otherwise fire in the middle of it -- the reaper even closes
       the debug handle the handler is reading through. */
    if (g_CommandActive) {
        /* Protect a long legitimate handler, but never for ever: if it is stuck
           the target would stay paused with no watchdog and no reaper. */
        const u64 started = g_CommandStartedMs;
        const u64 now = armTicksToNs(armGetSystemTick()) / 1000000ull;
        /* Never declare a running scan "stuck": it legitimately holds the
           connection thread for minutes, and clearing the flag here would let the
           reaper close the debug handle under it (the use-after-free the grace
           period exists to prevent). */
        if (nxusSessionScanState() == NxusScanState_Running) return;
        if (started != 0 && now - started < NXUS_COMMAND_GRACE_MS) return;
        NXUS_LOG("a command has been running for %llu ms - watchdog re-enabled",
                 (unsigned long long)(now - started));
        g_CommandActive = false;
    }
    reapExitedDebugSession();
    reapStaleDebugSession();

    /* Hotkey pause with no client attached: nobody can send Resume, so the 15 s
       pause watchdog would thaw exactly the freeze the user asked for by pressing
       the button.  Refreshing the session's idle clock suspends it honestly, and
       means the watchdog is not already "expired" the instant a client connects -
       which would resume the target before its first command even arrived. */
    bool hotkey_hold = false;
    if (pauseIsHotkeyHold()) {
        if (nxusNetClientFd() >= 0) {
            pauseClearHotkeyHold();
            NXUS_LOG("pause: a client connected - the hotkey pause watchdog is active again");
        } else if (!nxusSessionIsPaused()) {
            /* The pause ended somewhere else (dmnt resumed, auto-continue): there
               is nothing to hold, so drop the flag instead of logging a hold that
               no longer exists. */
            pauseClearHotkeyHold();
        } else {
            hotkey_hold = true;
            nxusSessionHeartbeat();
            if (!atomic_load_explicit(&g_PauseHotkeyLogged, memory_order_relaxed)) {
                atomic_store_explicit(&g_PauseHotkeyLogged, true, memory_order_relaxed);
                NXUS_LOG("pause: hotkey pause is held without a client (watchdog suspended)");
            }
        }
    }

    refreshTargetIdentityThrottled();
    if (!hotkey_hold && nxusSessionWatchdogExpired(nxusSessionWatchdogTimeout())) {
        if (nxusDebugIsAttached()) {
            /* dmnt is closed while we hold a debug session: resuming here would fail
               and still tell the client "auto-resumed" while the target stays held. */
            NXUS_LOG("watchdog: skipped while a debug session is attached");
            return;
        }
        Result rc = nxusDmntResume();
        if (R_SUCCEEDED(rc)) {
            nxusSessionSetPaused(false);
            NXUS_LOG("watchdog: auto-resume rc=0x%08X", (unsigned)rc);
            nxusNetSendEvent(NxusEvent_AutoResume, NULL, 0);
        } else {
            NXUS_LOG("watchdog: auto-resume FAILED rc=0x%08X", (unsigned)rc);
        }
    }
}

/* ---- terminal shutdown -------------------------------------------------- */

/*
 * Stop every worker and the session this file owns, in the one order that keeps a
 * reader from outliving what it reads:
 *
 *   1. Pointer-scan worker.  It walks the target and the mapping/region views for
 *      up to the 90 s budget, so it is CANCELLED first (the engine polls
 *      g_PtrJob.budget.cancel between roots and inside the walk - the same flag
 *      PtrScanGet's cancel path sets) and only then joined.  threadWaitForExit()
 *      without the cancel would block for the rest of that budget, and not joining
 *      it at all - the state before this function existed - left a live thread
 *      reading target memory while the session and the debug handle were being
 *      torn down underneath it.
 *      ptrScanClaimSlot()/ptrScanJoinSlotLocked() are the only way the worker Thread
 *      is touched: handlePtrScanBegin() holds the same claim across its
 *      reap/create/start sequence and re-checks g_ServerExited under it, so no worker
 *      can be created behind this join and no Thread is ever joined or closed twice.
 *
 *   2. The session.  nxusSessionScanCancel() sets the scan worker's flag and
 *      nxusSessionExit() then joins that worker and frees the hit list, the SD
 *      baseline, the mapping/region views and every view pin.  Exit() repeats the
 *      cancel internally; doing it here keeps the shutdown order readable and
 *      makes sure the flag is raised BEFORE the join rather than inside it.
 *
 * The debug session (nxusDebugExit), the network (nxusNetExit) and dmnt
 * (nxusDmntExit) are deliberately NOT stopped here: they belong to other modules
 * and they are sequenced by __appExit() (main.c), which calls this function first.
 */
void nxusServerExit(void) {
    /* The compare-exchange is both the "already exited" guard and the flag the
       connection thread reads: only the first caller proceeds. */
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&g_ServerExited, &expected, true,
                                                 memory_order_acq_rel, memory_order_acquire)) {
        NXUS_LOG_DEBUG("server: exit already done - ignored");
        return;
    }

    /* 1. pointer-scan worker: cancel, then join exactly once.  The cancel is what
       makes a running walk return to ptrScanPublish() (the engine only polls the flag
       between roots / inside the walk), so the join below is bounded by the walk's
       own read loop instead of by its remaining time budget. */
    ptrScanRequestCancel("server exit");
    if (ptrScanClaimSlot(2000)) {
        /* A Begin that took the slot just before g_ServerExited became visible may have
           started a walk AFTER the cancel above was ignored (the job was not Running
           yet).  Re-issue it under the claim, so the join cannot wait for the walk's
           whole time budget. */
        ptrScanRequestCancel("server exit (worker started late)");
        if (ptrScanJoinSlotLocked()) {
            NXUS_LOG("ptrscan: worker joined and closed (server exit)");
        }
        ptrScanReleaseSlot();
    } else {
        /* A Begin on the connection thread owns the slot.  It cannot create a new
           worker any more (it re-checks g_ServerExited under the claim), and
           nxusNetExit() joins that thread right after this, so the only cost is one
           log line instead of a silent leak. */
        NXUS_LOG_ERROR("ptrscan: worker slot still claimed by a Begin at exit - "
                       "not joining (no new worker can be created)");
    }

    /* 2. a running scan, then the session itself. */
    (void)nxusSessionScanCancel();
    nxusSessionExit();
    NXUS_LOG("server: scan cancelled and session released");
}
