#pragma once

#include <switch.h>

#define MHXX_MAX_SITES 6
#define MHXX_MAX_DEREF 4

/* A one-word code patch: every site is an AArch32 instruction replaced in
   place.  No trampoline, no allocation, no extra page: the kernel flushes the
   instruction cache for us on every svcWriteDebugProcessMemory. */
typedef struct {
    const char *id;
    const char *name;
    const char *desc;
    int risk;                        /* 0 low, 1 medium, 2 high */
    int site_count;
    u32 offsets[MHXX_MAX_SITES];     /* main-module relative */
    u32 orig[MHXX_MAX_SITES];
    u32 patched[MHXX_MAX_SITES];
} MhxxCheat;

/* A value reachable through a static pointer chain, e.g.
   F1: *(main+0x18B9218) + 0x24. */
typedef struct {
    const char *id;
    const char *name;
    int risk;
    u32 root_off;                    /* static pointer inside main */
    int deref_count;                 /* number of extra dereferences */
    u32 deref[MHXX_MAX_DEREF];
    u32 final_off;
    u32 width;                       /* 2 or 4 */
    u32 min;
    u32 max;
    u32 def;
    const char *note;
} MhxxValue;

int  mhxxCheatCount(void);
MhxxCheat *mhxxCheatAt(int index);
int  mhxxValueCount(void);
MhxxValue *mhxxValueAt(int index);

/* Engine: dmnt-owned cheat process + main module base. */
typedef struct {
    u64 main_base;
    u64 main_size;
    u64 pid;
    u64 program_id;
    bool build_ok;
    bool open;
} MhxxEngine;

Result mhxxEngineOpen(MhxxEngine *e);      /* ForceOpen + metadata + build id */
void   mhxxEngineClose(MhxxEngine *e);

Result mhxxCheatReadWord(MhxxEngine *e, u32 offset, u32 *out);
int  mhxxCheatState(MhxxEngine *e, const MhxxCheat *c);  /* 1 on, 0 off, <0 error */
Result mhxxCheatApply(MhxxEngine *e, const MhxxCheat *c);
Result mhxxCheatRevert(MhxxEngine *e, const MhxxCheat *c);
Result mhxxCheatRevertAll(MhxxEngine *e);

Result mhxxValueResolve(MhxxEngine *e, const MhxxValue *v, u64 *out_addr);
Result mhxxValueRead(MhxxEngine *e, const MhxxValue *v, u32 *out);
Result mhxxValueWrite(MhxxEngine *e, const MhxxValue *v, u32 value);
