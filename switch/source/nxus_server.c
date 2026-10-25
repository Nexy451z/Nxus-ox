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

static Result serverPause(void);
static Result serverPauseEx(bool allow_attach);
static Result serverResume(void);
/* Defined below; forward-declared because fillStatus reports the pause state. */
static void pauseLock(void);
static void pauseUnlock(void);
static bool pauseIsViaDebug(void);
static bool pauseTryEnter(void);
static void pauseLeave(void);

/* Pointer scan results kept between PtrScanBegin and PtrScanGet/CheatExport. */
#define NXUS_PTRSCAN_MAX_RESULTS 64
static NxusPtrChain     g_Chains[NXUS_PTRSCAN_MAX_RESULTS];
static u32              g_ChainCount;
static NxusPtrScanStats g_PtrStats;
static u64              g_PtrTarget;
static u64              g_PtrModuleBase;

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
        g_PauseLockReady = true;
    }

    nxusHidInit();
    nxusHidSetCallback(onHotkeyFired, NULL);
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

/* How long the console waits for a command before it assumes the PC is gone. */
#define NXUS_DEBUG_IDLE_TIMEOUT_MS 20000u

static void fillStatus(NxusStatus *st) {
    memset(st, 0, sizeof(*st));
    st->proto_version = NXUS_PROTO_VERSION;
    st->mode = NXUS_MODE_DMNT;
    st->scan_state = nxusSessionScanState();
    st->process_id = nxusSessionProcessId();
    st->program_id = nxusSessionProgramId();
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
    if (nxusDebugIsAttached()) {
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

/* The pause state is only ever read/written in these short sections; every IPC,
   attach/detach and thread join happens outside the lock. */
static void pauseCommitState(bool via_debug, bool paused) {
    pauseLock();
    g_PauseViaDebug = via_debug;
    nxusSessionSetPaused(paused);
    pauseUnlock();
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
    return rc;
}

/* ---- module detection -------------------------------------------------- */

static u32 collectModules(NxusModuleInfo *out, u32 max_modules) {
    const NxusMappingTable *maps = nxusSessionMappings();
    if (maps == NULL || maps->count == 0) return 0;

    u32 found = 0;
    u8 page[0x200];
    for (u32 i = 0; i < maps->count && found < max_modules; i++) {
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
    return found;
}

/* ---- pointer scan ------------------------------------------------------ */

static u32 buildPtrRegions(NxusPtrRegion *out, u32 max_regions, u64 *out_module_base) {
    const NxusMappingTable *maps = nxusSessionMappings();
    const u64 module_base = nxusSessionMainBase();
    const u64 module_end = module_base + nxusSessionMainSize();
    *out_module_base = module_base;

    u32 n = 0;
    for (u32 i = 0; i < maps->count && n < max_regions; i++) {
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
    return n;
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

static void handlePtrScanBegin(int fd, u16 type, u32 seq, const u8 *payload, u32 length) {
    if (length < sizeof(NxusPtrScanRequest)) {
        replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
        return;
    }
    NxusPtrScanRequest req;
    memcpy(&req, payload, sizeof(req));

    Result rc = nxusSessionRefreshMappings();
    if (R_FAILED(rc)) { replyError(fd, type, seq, rc); return; }

    const NxusMappingTable *maps = nxusSessionMappings();
    if (maps->count == 0) { replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_NO_PROCESS)); return; }

    u32 region_cap = maps->count + 1;
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
    /* Pointer width.  An explicit 4/8 request always wins; when the client lets
       us decide (0), infer it from the module base: a 32-bit title (MHXX and
       friends) maps its main module below 4 GB and must be walked with 4-byte
       loads, because an 8-byte load would fold the neighbouring field into the
       pointer and find no chains at all.  Anything above 4 GB (or unknown) is a
       64-bit title and needs the wide loads. */
    if (req.value_width == 4 || req.value_width == 8) {
        opts.value_width = req.value_width;
    } else {
        opts.value_width = (module_base != 0 && module_base < 0x100000000ull) ? 4u : 8u;
    }
    opts.window_size = 0x400;
    opts.max_reads = 20000;      /* bounded so the console cannot be held hostage */

    NXUS_LOG("ptrscan: target=%08llX module=%08llX depth=%u width=%u regions=%u",
             (unsigned long long)req.target_address, (unsigned long long)module_base,
             (unsigned)opts.max_depth, (unsigned)opts.value_width, (unsigned)region_count);

    u32 count = 0;
    int src = nxusPtrScan(regions, region_count, req.target_address, module_base, &opts,
                          g_Chains, NXUS_PTRSCAN_MAX_RESULTS, &count,
                          nxusSessionReadCallback, NULL, scratch, 256 * 1024, &g_PtrStats, NULL);

    g_ChainCount = (src == NXUS_SCAN_OK) ? count : 0;
    g_PtrTarget = req.target_address;
    g_PtrModuleBase = module_base;

    NXUS_LOG("ptrscan: chains=%u roots=%llu reads=%llu",
             (unsigned)g_ChainCount, (unsigned long long)g_PtrStats.roots_examined,
             (unsigned long long)g_PtrStats.reads);

    free(regions);
    free(scratch);

    if (src != NXUS_SCAN_OK && src != NXUS_SCAN_ERR_CANCELLED) {
        replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
        return;
    }
    sendChainList(fd, seq, type);
}

static void handleCheatExport(int fd, u16 type, u32 seq, const u8 *payload, u32 length) {
    if (length < sizeof(NxusCheatExportRequest)) {
        replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
        return;
    }
    NxusCheatExportRequest req;
    memcpy(&req, payload, sizeof(req));
    if (req.index >= g_ChainCount) {
        replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
        return;
    }

    char *text = (char *)malloc(1024);
    if (text == NULL) { replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory)); return; }

    int written = nxusCheatGenerate(&g_Chains[req.index], (req.flags & NXUS_CHEAT_F_32BIT) ? 1 : 0,
                                    req.value, req.value_width ? req.value_width : 4,
                                    "Nxus", text, 1024);
    if (written <= 0) replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_UNSUPPORTED));
    else reply(fd, type, seq, text, (u32)written);
    free(text);
}

/* ---- scan results ------------------------------------------------------ */

static void sendHits(int fd, u32 seq, const NxusGetHitsRequest *req) {
    const NxusHitList *hits = nxusSessionHits();
    const NxusMappingTable *maps = nxusSessionMappings();

    /* Both views are published by nxus_session.c: the hit list is NULL while a
       scan is running, and the mapping table is NULL when nothing has been
       snapshotted (or after Exit).  Answering with an empty batch keeps a stale
       client from crashing the whole sysmodule. */
    if (hits == NULL) {
        replyError(fd, NxusCmd_ScanGetHits, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
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
        return;
    }
    const u32 payload_size = (u32)payload_u64;

    u8 *buffer = (u8 *)malloc(payload_size);
    if (buffer == NULL) {
        replyError(fd, NxusCmd_ScanGetHits, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory));
        return;
    }

    NxusHitBatchHeader header;
    memset(&header, 0, sizeof(header));
    header.session_id = nxusSessionId();
    header.count = count;
    header.total = hits->count;
    header.value_size = hits->value_size;
    header.mapping_count = map_count;
    memcpy(buffer, &header, sizeof(header));

    u32 offset = (u32)sizeof(header);
    for (u32 i = 0; i < map_count; i++) {
        memcpy(buffer + offset, &maps->entries[i].base, sizeof(u64));
        offset += (u32)sizeof(u64);
    }

    for (u32 i = 0; i < count; i++) {
        u32 index = req->offset + i;
        NxusHit hit;
        memset(&hit, 0, sizeof(hit));
        hit.offset = hits->addresses[index].offset;
        /* The PC resolves the hit address as mapping_bases[mapping_idx] + offset,
           with nothing of its own to range-check it against.  A stale index from a
           mapping table that shrank (scan while the title remapped) would resolve
           to somebody else's address, so clamp it to 0 instead of trusting it. */
        hit.mapping_idx = ((u32)hits->addresses[index].mapping_idx < map_count)
                              ? hits->addresses[index].mapping_idx : 0;
        hit.value_type = hits->addresses[index].reserved;
        memcpy(&hit.value, hits->values + (size_t)index * hits->value_size, hits->value_size);
        memcpy(buffer + offset, &hit, sizeof(hit));
        offset += (u32)sizeof(hit);
    }

    reply(fd, NxusCmd_ScanGetHits, seq, buffer, payload_size);
    free(buffer);
}

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

    /* Pointer scans and snapshots run synchronously here, so while they work the
       connection thread cannot read the client's heartbeats either.  Tell the
       watchdog to stay quiet instead of resuming the target mid-operation. */
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
               pauseTarget() take the process over with an own debug session. */
            rc = serverPause();
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_Resume:
            /* Reverses whichever pause is in effect: dmnt's continue for a
               dmnt-held stop, continue + detach for a debug-session pause, plain
               continue while the PC holds a debugger. */
            rc = serverResume();
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
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
                   svcQueryDebugProcessMemory instead of failing. */
                const NxusMappingTable *table = nxusSessionMappings();
                count = table ? table->count : 0;
                reply(fd, type, seq, &count, sizeof(count));
                break;
            }
            rc = nxusDmntGetMappingCount(&count);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else reply(fd, type, seq, &count, sizeof(count));
            break;
        }

        case NxusCmd_GetMappings: {
            if (length < sizeof(NxusMappingsRequest)) { replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE)); break; }
            NxusMappingsRequest req;
            memcpy(&req, payload, sizeof(req));
            u32 max_count = req.max_count;
            if (max_count == 0 || max_count > 1024) max_count = 1024;

            NxusMemoryInfo *buffer = (NxusMemoryInfo *)malloc((size_t)max_count * sizeof(NxusMemoryInfo));
            if (buffer == NULL) { replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory)); break; }

            size_t got = 0;
            if (nxusDebugIsAttached()) {
                const NxusMappingTable *table = nxusSessionMappings();
                if (table != NULL) {
                    /* The PC pages with a u64 offset.  Truncating it to u32 made the
                       page stop advancing above 4 GiB (and wrap for a negative value),
                       so the client re-read the first page for ever.  Compare in u64
                       instead: i is a u32 index, so i < start simply yields nothing
                       when the offset is past the table. */
                    const u64 start = req.offset;
                    for (u32 i = 0; i < table->count && got < max_count; i++) {
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
            if (length < sizeof(u64)) { replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE)); break; }
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
            if (length < sizeof(NxusReadRequest)) { replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE)); break; }
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
            if (length < sizeof(NxusWriteHeader)) { replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE)); break; }
            NxusWriteHeader wh;
            memcpy(&wh, payload, sizeof(wh));
            if (wh.size == 0 || length < sizeof(NxusWriteHeader) + wh.size) {
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
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
            if (length < sizeof(NxusScanRequest)) { replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE)); break; }
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
                    replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
                    break;
                }
                nxusSessionSetScanRanges(list, (u32)count);
                tail = next;
            } else if (req.scope == NxusScope_Ranges) {
                /* list mode without a list: reject instead of scanning nothing */
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
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
                        replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
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
            reply(fd, type, seq, NULL, 0);
            break;

        case NxusCmd_ScanUndo: {
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
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BUSY));
                break;
            }
            if (length < sizeof(NxusGetHitsRequest)) { replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE)); break; }
            NxusGetHitsRequest req;
            memcpy(&req, payload, sizeof(req));
            sendHits(fd, seq, &req);
            break;
        }

        case NxusCmd_SnapshotCapture: {
            /* Snapshot preparation rebuilds the mapping/region arrays the scan
               worker is reading, so a running scan must be refused first. */
            if (nxusSessionScanState() == NxusScanState_Running) {
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BUSY));
                break;
            }
            if (length < sizeof(NxusSnapshotRequest)) {
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
                break;
            }
            NxusSnapshotRequest req;
            memcpy(&req, payload, sizeof(req));
            NxusSnapshotSummary summary;
            memset(&summary, 0, sizeof(summary));
            rc = nxusSnapshotTake(req.slot, req.scope, req.range_begin, req.range_end,
                                  req.block_size, &summary);
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
            rc = nxusSnapshotCompare(from_slot, to_slot, &summary);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else reply(fd, type, seq, &summary, sizeof(summary));
            break;
        }

        case NxusCmd_SnapshotChanged: {
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

        case NxusCmd_PtrScanBegin:
            /* Same reason as SnapshotCapture: the pointer scan walks the mapping
               snapshot the worker rebuilds under it. */
            if (nxusSessionScanState() == NxusScanState_Running) {
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BUSY));
                break;
            }
            handlePtrScanBegin(fd, type, seq, payload, length);
            break;

        case NxusCmd_PtrScanGet:
            sendChainList(fd, seq, type);
            break;

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
            u32 max_count = 64;
            /* Paging: the request carries a u64 offset at the same place as
               NxusMappingsRequest (offset, max_count).  NxusFrozenRequest itself
               (address, width) has no offset, so a client that sends one gets the
               first page - offset 0 - and only a caller that asks for a page is
               served past it.  Ignoring the offset made every page the first one. */
            if (length >= sizeof(NxusMappingsRequest)) {
                NxusMappingsRequest req;
                memcpy(&req, payload, sizeof(req));
                /* Only max_count is meaningful here.  NxusFrozenRequest is
                   {address, width} and is byte-compatible with
                   NxusMappingsRequest {offset, max_count}, so honouring req.offset
                   would read an *address* as a page offset; dmnt's frozen table is
                   capped at 0x80 entries anyway and callers never page it. */
                if (req.max_count > 0 && req.max_count <= 512) max_count = req.max_count;
            }
            NxusFrozenAddressEntry *entries = (NxusFrozenAddressEntry *)calloc(max_count, sizeof(NxusFrozenAddressEntry));
            NxusFrozenEntry *wire = (NxusFrozenEntry *)calloc(max_count, sizeof(NxusFrozenEntry));
            if (entries == NULL || wire == NULL) {
                free(entries); free(wire);
                replyError(fd, type, seq, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory));
                break;
            }
            size_t got = 0;
            rc = nxusDmntGetFrozenEntries(entries, max_count, 0, &got);
            if (R_FAILED(rc)) {
                replyError(fd, type, seq, rc);
            } else {
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
            if (length < sizeof(NxusFrozenRequest)) { replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE)); break; }
            NxusFrozenRequest req;
            memcpy(&req, payload, sizeof(req));
            u64 value = 0;
            if (nxusDebugIsAttached()) {
                /* Freezing is a dmnt cheat-VM feature and dmnt is closed while we
                   hold the debug handle, so answer with a clear result instead of
                   a dmnt error the client cannot interpret. */
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BUSY));
                break;
            }
            rc = nxusDmntEnableFrozen(req.address, req.width, &value);
            if (R_FAILED(rc)) replyError(fd, type, seq, rc);
            else reply(fd, type, seq, &value, sizeof(value));
            break;
        }

        case NxusCmd_FrozenDisable: {
            if (length < sizeof(u64)) { replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE)); break; }
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
            if (R_FAILED(rc)) replyError(fd, type, seq, rc); else reply(fd, type, seq, NULL, 0);
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

            if (!debug_only && length >= sizeof(NxusConfig)) {
                memcpy(&g_Config, payload, sizeof(g_Config));
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
            static char log[8192];
            size_t n = nxusLogTail(log, sizeof(log));
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
                replyError(fd, type, seq, rc);
            } else {
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
            break;
        }

        case NxusCmd_DebugDetach:
            /* The detach (thread join + handle close) runs outside the state
               lock; only the resulting pause/flag change is committed under it. */
            rc = nxusDebugDetach();
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
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
                break;
            }
            NxusBreakRequest request;
            memcpy(&request, payload, sizeof(request));
            rc = nxusDebugSetBreak(&request);
            if (R_FAILED(rc)) {
                replyError(fd, type, seq, rc);
            } else {
                NxusBreakEntry entries[NXUS_DEBUG_SERVER_BREAK_MAX];
                u32 n = nxusDebugGetBreaks(entries, NXUS_DEBUG_SERVER_BREAK_MAX);
                reply(fd, type, seq, entries, n * (u32)sizeof(NxusBreakEntry));
            }
            break;
        }

        case NxusCmd_BreakClear: {
            if (length < sizeof(u32)) {
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
                break;
            }
            u32 slot = 0;
            memcpy(&slot, payload, sizeof(slot));
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
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
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
                replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE));
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
            replyError(fd, type, seq, NXUS_MAKE_RESULT(NXUS_ERR_UNSUPPORTED));
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

void nxusServerTick(void) {
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
    refreshTargetIdentityThrottled();
    if (nxusSessionWatchdogExpired(nxusSessionWatchdogTimeout())) {
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
