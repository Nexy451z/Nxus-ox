#include "cheats.h"
#include "dmnt.h"

#include <string.h>

/* ------------------------------------------------------------------ data */

static const MhxxCheat g_Cheats[] = {
    { "P1", "Money always 9,999,999", "Any money change clamps to max", 0, 2,
      { 0x51E02C, 0x51E034 }, { 0xB1A02001, 0xD3A02000 }, { 0xE1A00000, 0xE1A00000 } },
    { "P2", "Money freeze (add -> mov)", "add r1,r2,r1 becomes mov r1,r2", 0, 1,
      { 0x51E01C }, { 0xE0821001 }, { 0xE1A01002 } },
    { "P3", "Bherna points freeze", "add -> mov on the point add path", 0, 1,
      { 0x51E060 }, { 0xE0821001 }, { 0xE1A01002 } },
    { "P4", "Points always 9,999,999", "Point clamp removed", 0, 2,
      { 0x51E070, 0x51E078 }, { 0xB1A02001, 0xD3A02000 }, { 0xE1A00000, 0xE1A00000 } },
    { "P5", "Shop ignores price", "canAfford always returns 1", 0, 1,
      { 0x51E054 }, { 0xA3000001 }, { 0xE3000001 } },
    { "P6", "Point shop ignores cost", "canAffordPoints always returns 1", 0, 1,
      { 0x51E098 }, { 0xA3000001 }, { 0xE3000001 } },
    { "P7", "Infinite health", "status setter receives 9999", 1, 1,
      { 0x2EDC5C }, { 0xE1A01006 }, { 0xE302170F } },
    { "P8", "Infinite stamina", "6 stamina checks forced to true", 1, 6,
      { 0x2A0D68, 0x2A0E24, 0x2A2990, 0x29ABAC, 0x29ACF8, 0x29B9BC },
      { 0xE12FFF32, 0xE12FFF32, 0xE12FFF32, 0xE12FFF32, 0xE12FFF32, 0xE12FFF32 },
      { 0xE3A00001, 0xE3A00001, 0xE3A00001, 0xE3A00001, 0xE3A00001, 0xE3A00001 } },
    { "P9", "Sharpness always max", "blx r1 becomes max value", 1, 1,
      { 0x2AA340 }, { 0xE6B11077 }, { 0xE6BF1070 } },
    { "P10", "Hunter art gauge max", "art gauge compare patched", 1, 2,
      { 0x29F648, 0x29F64C }, { 0xE19000F3, 0xE1500002 }, { 0xE18020B3, 0xE1500000 } },
    { "P11", "Brave gauge max", "brave gauge VFP store patched", 1, 3,
      { 0x630834, 0x630838, 0x63083C }, { 0xEEF1FA10, 0xFE200A01, 0xED840A18 },
      { 0xEEBD0AC1, 0xED800A00, 0xED841A18 } },
    { "P12", "Alchemy gauge max", "alchemy gauge patched", 1, 2,
      { 0x29B8E0, 0x29B8E4 }, { 0xEE09AA08, 0xED86AA00 }, { 0xE3440800, 0xE5860000 } },
    { "P13", "Pouch items never decrease", "pouch count write forced to 0 delta", 0, 1,
      { 0x2FE558 }, { 0xE1A07002 }, { 0xE3A07000 } },
    { "P14", "Place bombs/traps in town", "tester placement check forced true", 0, 2,
      { 0x4FD324, 0x4FD370 }, { 0xE1A00005, 0xE1A00005 }, { 0xE3A00001, 0xE3A00001 } },
    { "P15", "Place traps (all testers)", "every tester check forced true", 0, 4,
      { 0x4FD0A4, 0x4FD0F0, 0x4FD218, 0x4FD264 },
      { 0xE1A00005, 0xE1A00005, 0xE1A00005, 0xE1A00005 },
      { 0xE3A00001, 0xE3A00001, 0xE3A00001, 0xE3A00001 } },
};

static const MhxxValue g_Values[] = {
    { "F1", "Zenny (money)", 0, 0x18B9218, 0, { 0, 0, 0, 0 }, 0x24, 4, 0, 9999999u, 9999999u,
      "reopen the status menu to refresh" },
    { "F2", "Bherna points", 0, 0x18B9218, 0, { 0, 0, 0, 0 }, 0x2C, 4, 0, 9999999u, 9999999u, "" },
    { "F3", "Attack (u16)", 1, 0x1879E18, 2, { 0x3618, 0xDFE8, 0, 0 }, 0x1FC, 2, 1, 65535u, 1600u, "" },
    { "F4", "Defense (u16)", 1, 0x1879E18, 2, { 0x3618, 0xDFE8, 0, 0 }, 0x20A, 2, 1, 65535u, 32765u, "" },
    { "F5", "FPS cap (f32 bits)", 1, 0x214B898, 0, { 0, 0, 0, 0 }, 0x484C, 4, 0x41F00000u, 0x43700000u, 0x42700000u,
      "60 fps = 0x42700000" },
    { "F6", "Game speed (f32 bits)", 1, 0x214B898, 0, { 0, 0, 0, 0 }, 0x4848, 4, 0x41700000u, 0x43800000u, 0x42700000u,
      "1x = 0x42700000 (60.0)" },
};

int mhxxCheatCount(void) { return (int)(sizeof(g_Cheats) / sizeof(g_Cheats[0])); }
MhxxCheat *mhxxCheatAt(int index) {
    if (index < 0 || index >= mhxxCheatCount()) return NULL;
    return (MhxxCheat *)&g_Cheats[index];
}
int mhxxValueCount(void) { return (int)(sizeof(g_Values) / sizeof(g_Values[0])); }
MhxxValue *mhxxValueAt(int index) {
    if (index < 0 || index >= mhxxValueCount()) return NULL;
    return (MhxxValue *)&g_Values[index];
}

/* ---------------------------------------------------------------- engine */

static const u8 kBuildId[8] = { 0x9D, 0x4C, 0x86, 0xE6, 0xEF, 0x74, 0x50, 0x4A };

Result mhxxEngineOpen(MhxxEngine *e) {
    memset(e, 0, sizeof(*e));
    Result rc = mhxxDmntInit();
    if (R_FAILED(rc)) return rc;

    bool has = false;
    rc = mhxxDmntHasProcess(&has);
    if (R_FAILED(rc)) return rc;
    if (!has) {
        rc = mhxxDmntForceOpen();
        if (R_FAILED(rc)) return rc;
        svcSleepThread(300000000ull);
    }

    MhxxMetadata md;
    rc = mhxxDmntMetadata(&md);
    if (R_FAILED(rc)) return rc;
    if (md.program_id != MHXX_TITLE_ID) return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    e->main_base  = md.main_nso_base;
    e->main_size  = md.main_nso_size;
    e->pid        = md.process_id;
    e->program_id = md.program_id;

    /* Verify the build id dmnt reports, then prove we are looking at the code we
       think we are: the first patch site must still hold either its original or
       its patched word.  (The NSO header itself is not mapped into the process,
       so a build id cannot be read from memory - the code signature can.) */
    if (memcmp(md.build_id, kBuildId, sizeof(kBuildId)) != 0) {
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }
    {
        u32 probe = 0;
        rc = mhxxDmntRead(e->main_base + g_Cheats[0].offsets[0], &probe, sizeof(probe));
        if (R_FAILED(rc)) return rc;
        if (probe != g_Cheats[0].orig[0] && probe != g_Cheats[0].patched[0]) {
            return MAKERESULT(Module_Libnx, LibnxError_BadInput);
        }
    }

    e->build_ok = true;
    e->open = true;
    return 0;
}

void mhxxEngineClose(MhxxEngine *e) {
    if (e->open) {
        /* Give dmnt the process back so cheats / the PC client keep working. */
        (void)mhxxDmntForceOpen();
    }
    e->open = false;
}

Result mhxxCheatReadWord(MhxxEngine *e, u32 offset, u32 *out) {
    u32 word = 0;
    Result rc = mhxxDmntRead(e->main_base + offset, &word, sizeof(word));
    if (R_SUCCEEDED(rc) && out != NULL) *out = word;
    return rc;
}

int mhxxCheatState(MhxxEngine *e, const MhxxCheat *c) {
    int patched_sites = 0;
    for (int i = 0; i < c->site_count; i++) {
        u32 word = 0;
        if (R_FAILED(mhxxCheatReadWord(e, c->offsets[i], &word))) return -1;
        if (word == c->patched[i]) patched_sites++;
        else if (word != c->orig[i]) return -2;      /* something else is there */
    }
    if (patched_sites == 0) return 0;
    if (patched_sites == c->site_count) return 1;
    return -3;                                        /* half applied */
}

Result mhxxCheatApply(MhxxEngine *e, const MhxxCheat *c) {
    for (int i = 0; i < c->site_count; i++) {
        u32 word = 0;
        Result rc = mhxxCheatReadWord(e, c->offsets[i], &word);
        if (R_FAILED(rc)) return rc;
        if (word == c->patched[i]) continue;          /* already applied */
        if (word != c->orig[i]) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
        u32 write = c->patched[i];
        rc = mhxxDmntWrite(e->main_base + c->offsets[i], &write, sizeof(write));
        if (R_FAILED(rc)) return rc;
        u32 back = 0;
        rc = mhxxCheatReadWord(e, c->offsets[i], &back);
        if (R_FAILED(rc)) return rc;
        if (back != write) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }
    return 0;
}

Result mhxxCheatRevert(MhxxEngine *e, const MhxxCheat *c) {
    for (int i = 0; i < c->site_count; i++) {
        u32 word = 0;
        Result rc = mhxxCheatReadWord(e, c->offsets[i], &word);
        if (R_FAILED(rc)) return rc;
        if (word == c->orig[i]) continue;
        if (word != c->patched[i]) continue;          /* not ours - leave it */
        u32 write = c->orig[i];
        rc = mhxxDmntWrite(e->main_base + c->offsets[i], &write, sizeof(write));
        if (R_FAILED(rc)) return rc;
    }
    return 0;
}

Result mhxxCheatRevertAll(MhxxEngine *e) {
    Result first = 0;
    for (int i = 0; i < mhxxCheatCount(); i++) {
        Result rc = mhxxCheatRevert(e, &g_Cheats[i]);
        if (R_FAILED(rc) && R_SUCCEEDED(first)) first = rc;
    }
    return first;
}

/* --------------------------------------------------------------- values */

Result mhxxValueResolve(MhxxEngine *e, const MhxxValue *v, u64 *out_addr) {
    u32 ptr = 0;
    u64 addr = e->main_base + v->root_off;
    Result rc = mhxxDmntRead(addr, &ptr, sizeof(ptr));
    if (R_FAILED(rc)) return rc;
    /* MHXX is AArch32: the heap lives above 0x80000000 (observed player object
       0x80CF5DA0), so the only sane test is "is this a plausible 32-bit user
       address", not "is it below 2 GiB". */
    if (ptr < 0x10000u || ptr >= 0xFFFFFFF0u) return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    for (int i = 0; i < v->deref_count; i++) {
        addr = (u64)ptr + v->deref[i];
        rc = mhxxDmntRead(addr, &ptr, sizeof(ptr));
        if (R_FAILED(rc)) return rc;
        if (ptr < 0x10000u || ptr >= 0xFFFFFFF0u) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }
    *out_addr = (u64)ptr + v->final_off;
    return 0;
}

Result mhxxValueRead(MhxxEngine *e, const MhxxValue *v, u32 *out) {
    u64 addr = 0;
    Result rc = mhxxValueResolve(e, v, &addr);
    if (R_FAILED(rc)) return rc;
    u32 value = 0;
    rc = mhxxDmntRead(addr, &value, v->width);
    if (R_SUCCEEDED(rc) && out != NULL) *out = value;
    return rc;
}

Result mhxxValueWrite(MhxxEngine *e, const MhxxValue *v, u32 value) {
    u64 addr = 0;
    Result rc = mhxxValueResolve(e, v, &addr);
    if (R_FAILED(rc)) return rc;
    return mhxxDmntWrite(addr, &value, v->width);
}
