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
 *   65004 PauseCheatProcess
 *   65005 ResumeCheatProcess
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

/* Read/Write/Metadata reopen dmnt automatically once after a failed dispatch.
   Disable that while the Nxus debug session owns the process: a concurrent read
   failure must not re-open dmnt and steal the process back mid-attach. */
void   nxusDmntSetAutoReopen(bool enabled);

Result nxusDmntHasCheatProcess(bool *out);
Result nxusDmntGetCheatProcessEvent(Handle *out_handle);
Result nxusDmntGetMetadata(NxusProcessMetadata *out);
Result nxusDmntForceOpen(void);
Result nxusDmntForceClose(void);
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
