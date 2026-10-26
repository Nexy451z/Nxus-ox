/* Snapshot service: A/B block-hash snapshots of the target's memory. */
#pragma once

#include <switch.h>

#include "nxus_protocol.h"
#include "nxus_snapshot.h"

Result nxusSnapshotServiceInit(void);

/* Capture into slot A/B.  scope is a NxusScanScope.
 *
 * Every successful capture stamps the slot with the target identity the session
 * held when the capture started ({pid, program_id, session_id} plus the dmnt
 * target incarnation, nxusDmntTargetIncarnation, which is the only field that
 * changes when a title is restarted into the same fixed layout); a failed take,
 * a release and the next capture of that slot clear it.  The stamp is what makes
 * a later diff meaningful: hashes describe ONE process's memory, so A and B may
 * only be compared while they describe the same target. */
Result nxusSnapshotTake(u32 slot, u32 scope, u64 range_begin, u64 range_end,
                        u32 block_size, NxusSnapshotSummary *out);

/* Compare two slots and cache the changed-block list for paging.
 *
 * Refuses with NXUS_ERR_BAD_STATE (instead of returning a confident "N changed"
 * for a comparison that means nothing) when
 *   - either slot holds no capture,
 *   - A and B were captured for DIFFERENT targets (the classic case: capture A on
 *     one title, switch titles, capture B - two unrelated address spaces),
 *   - the dmnt target incarnation differs between the captures, or between the
 *     captures and the session now (a title restarted into a fixed layout: same
 *     pid, same title id, same mappings, different process),
 *   - the session has moved on from the captures' target (another title, a
 *     relaunch, a re-attach), so the addresses would be served for the wrong
 *     process,
 *   - A and B were captured with different block sizes. */
Result nxusSnapshotCompare(u32 from_slot, u32 to_slot, NxusSnapshotSummary *out);

/* Page the cached changed-block list.  Returns 0 every time once the session's
   target no longer matches the diff's (the rows belong to the previous process);
   the server checks nxusSnapshotDiffMatchesCurrent() first and refuses with
   NXUS_ERR_BAD_STATE rather than replying "0 changed". */
u32 nxusSnapshotGetChanged(NxusChangedBlockWire *out, u32 max_entries, u32 offset);

/* True while the cached diff may still be served: false only when there is a diff
   AND the session moved to another target since it ran.  True when no diff is
   cached, so a client that pages before its first diff keeps the old empty reply. */
bool nxusSnapshotDiffMatchesCurrent(void);

void nxusSnapshotGetSummary(u32 slot, NxusSnapshotSummary *out);

/* Release both captures and FREE the hash/address arrays (2 x 256 KiB once both
   slots were captured), so the memory really goes back to the 8 MB inner heap
   instead of staying resident while the bookkeeping says otherwise (SnapshotRelease
   / ScanReset).  The target stamps and the cached diff go with them, so nothing
   can be diffed or paged against a released pair.  The next capture re-allocates
   them through the same on-demand path the first capture uses
   (snapshotSlotEnsure()), so a released session keeps working; the slots simply
   read as "not captured" until then. */
void nxusSnapshotReleaseAll(void);

/* Which slots currently own their hash/address arrays (bit n = slot n), and how
   many bytes that is.  The server charges exactly this against its heap budget, so
   "released" and "resident" cannot differ. */
u32  nxusSnapshotResidentSlots(void);
u64  nxusSnapshotResidentBytes(void);
