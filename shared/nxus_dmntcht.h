/*
 * Nxus dmnt:cht client.
 *
 * The installed libnx (15.2.0 toolchain) no longer ships a dmntcht header, so
 * Nxus implements the client itself from the authoritative Atmosphère service
 * definition (stratosphere/dmnt/source/cheat/dmnt_cheat_service.hpp).
 *
 * Command ids and payload layouts mirror that interface exactly:
 *   65000 HasCheatProcess            -> bool
 *   65001 GetCheatProcessEvent       -> copy handle
 *   65002 GetCheatProcessMetadata    -> CheatProcessMetadata (0x70)
 *   65003 ForceOpenCheatProcess
 *   65004 PauseCheatProcess          -> svc::BreakDebugProcess on dmnt's debug handle (real stop)
 *   65005 ResumeCheatProcess         -> svc::ContinueDebugProcess on it
 *   65006 ForceCloseCheatProcess     <- hands the process to another debugger
 *   65100 GetCheatProcessMappingCount-> u64
 *   65101 GetCheatProcessMappings    -> sf::OutArray<svc::MemoryInfo> + u64 count, in u64 offset
 *   65102 ReadCheatProcessMemory     -> sf::OutBuffer, in {u64 addr, u64 size}
 *   65103 WriteCheatProcessMemory    -> sf::InBuffer,  in {u64 addr, u64 size}
 *   65104 QueryCheatProcessMemory    -> svc::MemoryInfo, in u64 addr
 *   65300 GetFrozenAddressCount      -> u64
 *   65301 GetFrozenAddresses         -> sf::OutArray<FrozenAddressEntry> + u64 count, in u64 offset
 *   65302 GetFrozenAddress           -> FrozenAddressEntry, in u64 addr
 *   65303 EnableFrozenAddress        -> u64 value, in {u64 addr, u64 width}
 *   65304 DisableFrozenAddress       in u64 addr
 */
#pragma once

#include <switch.h>
#include "nxus_protocol.h"

typedef struct NXUS_PACKED {
    u64 address;
    u64 value;
    u8  width;
    u8  reserved[7];
} NxusFrozenAddressEntry;
NXUS_STATIC_ASSERT(sizeof(NxusFrozenAddressEntry) == 24, "NxusFrozenAddressEntry must be 24 bytes");

Result nxusDmntInitialize(void);
void   nxusDmntExit(void);
bool   nxusDmntIsActive(void);

/* dmnt:cht's ResultCheatNotAttached (0x0032C80D): the service holds no cheat
   process to answer for.  nxusDmntPeekMetadata() returns exactly this instead of
   opening one. */
#define NXUS_DMNT_RESULT_CHEAT_NOT_ATTACHED 0x0032C80Du

/* Read/Write/Metadata and the other commands reopen dmnt automatically once after
   a failed dispatch (0x0032C80D ResultCheatNotAttached, plus any failure for the
   three legacy ones).  Disable that while the Nxus debug session owns the process:
   a concurrent read failure must not re-open dmnt and steal the process back
   mid-attach. */
void   nxusDmntSetAutoReopen(bool enabled);

Result nxusDmntHasCheatProcess(bool *out);
Result nxusDmntGetCheatProcessEvent(Handle *out_handle);
Result nxusDmntGetMetadata(NxusProcessMetadata *out);
/* Read-only metadata query - the one to use when the caller only wants to LOOK.
 *
 * It asks dmnt whether it holds a cheat process at all (65000, a pure query) and
 * answers NXUS_DMNT_RESULT_CHEAT_NOT_ATTACHED when it does not.  Unlike
 * nxusDmntGetMetadata() it never calls ForceOpen() and never runs the repair
 * retry, so it cannot take the process over from Atmosphère's cheat manager, from
 * another debugger or from Nxus's own debug session, and it cannot re-open dmnt
 * behind a failed HasCheatProcess probe.  That distinction matters for Status,
 * which is polled far more often than anything else and must stay observational:
 * the boot-time ForceOpen is a one-shot, and a status poll must not be able to
 * re-create the state the rest of the server gates on HasCheatProcess.
 *
 * Fills *out only on success.  Returns ResultCheatNotAttached when dmnt holds no
 * process, plus whatever the metadata command itself answers (a process that
 * disappeared between the two IPCs). */
Result nxusDmntPeekMetadata(NxusProcessMetadata *out);
Result nxusDmntForceOpen(void);
Result nxusDmntForceClose(void);
/* Pause/Resume the cheat process through dmnt itself.  These are the real
   commands (65004/65005): Atmosphère implements them as svc::BreakDebugProcess /
   svc::ContinueDebugProcess on the debug handle dmnt already owns.  The title
   genuinely stops and dmnt keeps the process, so reads, mappings, snapshots and
   frozen addresses keep working while it is held.  The server tries this path
   first and only falls back to an own debug session when dmnt cannot stop it. */
Result nxusDmntPause(void);
Result nxusDmntResume(void);

Result nxusDmntGetMappingCount(u64 *out_count);
Result nxusDmntGetMappings(NxusMemoryInfo *buffer, size_t max_count, size_t offset, size_t *out_count);
Result nxusDmntQuery(u64 address, NxusMemoryInfo *out);
Result nxusDmntRead(u64 address, void *buffer, size_t size);
Result nxusDmntWrite(u64 address, const void *buffer, size_t size);

Result nxusDmntGetFrozenCount(u64 *out_count);
Result nxusDmntGetFrozenEntries(NxusFrozenAddressEntry *buffer, size_t max_count, size_t offset, size_t *out_count);
Result nxusDmntEnableFrozen(u64 address, u64 width, u64 *out_value);
Result nxusDmntDisableFrozen(u64 address);
