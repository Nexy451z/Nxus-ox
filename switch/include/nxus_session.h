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

void nxusSessionInit(u32 chunk_size, u32 max_hits);
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
u32  nxusSessionHitCount(void);
u32  nxusSessionMappingCount(void);
u64  nxusSessionProcessId(void);
u64  nxusSessionProgramId(void);
u64  nxusSessionMainBase(void);
u64  nxusSessionMainSize(void);
/* Replace the cached process identity (used when attaching to an explicit pid, where
   dmnt's metadata no longer describes the process we hold). */
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
const NxusScanRegion *nxusSessionRegions(u32 *out_count);

/* ---- results ---- */
const NxusHitList      *nxusSessionHits(void);
const NxusMappingTable *nxusSessionMappings(void);

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
