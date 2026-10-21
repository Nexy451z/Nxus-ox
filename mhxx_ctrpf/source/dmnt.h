/*
 * Minimal dmnt:cht client for the MHXX CTRPF mod menu.
 *
 * A homebrew .nro has no debug capability, so it cannot call
 * svcDebugActiveProcess.  Atmosphère's dmnt sysmodule does hold one, and it
 * exposes the cheat-process interface to any title: after 65003
 * ForceOpenCheatProcess, dmnt owns the (stopped-for-a-moment) application
 * process and we can read/write its memory and register frozen addresses
 * through ordinary IPC.  Everything here is that interface, nothing else.
 *
 *   65000 HasCheatProcess             -> u8
 *   65002 GetCheatProcessMetadata     -> 0x70 bytes
 *   65003 ForceOpenCheatProcess
 *   65006 ForceCloseCheatProcess
 *   65102 ReadCheatProcessMemory      (In addr, OutBuffer)
 *   65103 WriteCheatProcessMemory     (In addr, InBuffer)
 *   65100 GetCheatProcessMappingCount -> u64
 *   65101 GetCheatProcessMappings     (OutArray + In offset) -> count
 *   65303 EnableFrozenAddress         (In {addr,width}) -> u64 value
 *   65304 DisableFrozenAddress        (In addr)
 */
#pragma once

#include <switch.h>

#define MHXX_TITLE_ID   0x0100C3800049C000ULL
/* build id of MHXX 1.5.1 (community code "ver.1.5.0" is the same binary) */
#define MHXX_BUILD_ID0  0xEF74504AULL
#define MHXX_BUILD_ID1  0x9D4C86E6ULL

typedef struct {
    u8  build_id[0x20];
    u64 process_id;
    u64 program_id;
    u64 main_nso_base;
    u64 main_nso_size;
    u64 heap_base;
    u64 heap_size;
    u64 alias_base;
    u64 alias_size;
    u64 aslr_base;
    u64 aslr_size;
} MhxxMetadata;

typedef struct {
    u64 addr;
    u64 size;
    u32 type;
    u32 attr;
    u32 perm;
    u32 device_refcount;
    u32 ipc_refcount;
    u32 padding;
} MhxxMemInfo;

Result mhxxDmntInit(void);
void   mhxxDmntExit(void);

Result mhxxDmntHasProcess(bool *out);
Result mhxxDmntForceOpen(void);
Result mhxxDmntForceClose(void);
Result mhxxDmntMetadata(MhxxMetadata *out);

Result mhxxDmntRead(u64 address, void *buffer, size_t size);
Result mhxxDmntWrite(u64 address, const void *buffer, size_t size);

Result mhxxDmntMappingCount(u64 *out);
Result mhxxDmntMappings(MhxxMemInfo *out, size_t max, size_t offset, size_t *out_count);

Result mhxxDmntFreeze(u64 address, u64 width, u64 *out_value);
Result mhxxDmntUnfreeze(u64 address);
