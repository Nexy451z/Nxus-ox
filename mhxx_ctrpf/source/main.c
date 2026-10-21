/*
 * MHXX CTRPF Mod Menu  (mhxx_ctrpf.nro)
 *
 * A CTRPF-style on-device cheat menu for Monster Hunter XX (Switch).
 *
 * Why a homebrew .nro instead of a sysmodule: a .nro has no debug capability,
 * but Atmosphère's dmnt does, and dmnt:cht lets any title read/write the
 * attached application's memory and register frozen addresses.  So this menu
 * never calls svcDebugActiveProcess (which would fail without the debug
 * capability) and never fights Nxus/EdiZon for a session.
 *
 * Safety rules implemented here:
 *   - never write before the build id is verified twice (dmnt metadata + the
 *     NSO header on the module itself),
 *   - every patch site is compared against its expected original word first,
 *   - every write is read back and verified,
 *   - "Revert all" restores the original words,
 *   - closing the menu hands the process back to dmnt (ForceOpen).
 */
#include <switch.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "cheats.h"
#include "dmnt.h"
#include "ui.h"

#define COL_LEFT   2
#define ROW_TITLE  0
#define ROW_LIST   6
#define ROW_HELP   34
#define LIST_ROWS  27

typedef enum { IT_HEADER, IT_CHEAT, IT_VALUE, IT_TOOL } ItemKind;

typedef struct {
    ItemKind kind;
    int index;
    const char *label;
} Item;

static Item  g_Items[64];
static int   g_ItemCount;
static int   g_Selected;
static int   g_Top;
static char  g_Message[96];
static u32   g_MessageTtl;
static bool  g_Frozen[16];
static u64   g_FrozenAddr[16];
static MhxxEngine g_Engine;

/* --------------------------------------------------------------- helpers */

static void message(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_Message, sizeof(g_Message), fmt, args);
    va_end(args);
    g_MessageTtl = 60;          /* frames */
}

static void messageResult(const char *what, Result rc) {
    if (R_SUCCEEDED(rc)) message("%s: OK", what);
    else                 message("%s failed: 0x%08X", what, (unsigned)rc);
}

static void buildItems(void) {
    g_ItemCount = 0;
    g_Items[g_ItemCount++] = (Item){ IT_HEADER, 0, "CODE PATCHES  (A = toggle)" };
    for (int i = 0; i < mhxxCheatCount(); i++) {
        MhxxCheat *c = mhxxCheatAt(i);
        g_Items[g_ItemCount++] = (Item){ IT_CHEAT, i, c->name };
    }
    g_Items[g_ItemCount++] = (Item){ IT_HEADER, 1, "VALUES  (A = set, X = freeze)" };
    for (int i = 0; i < mhxxValueCount(); i++) {
        MhxxValue *v = mhxxValueAt(i);
        g_Items[g_ItemCount++] = (Item){ IT_VALUE, i, v->name };
    }
    g_Items[g_ItemCount++] = (Item){ IT_HEADER, 2, "TOOLS" };
    g_Items[g_ItemCount++] = (Item){ IT_TOOL, 0, "Verify build id again" };
    g_Items[g_ItemCount++] = (Item){ IT_TOOL, 1, "Revert all patches" };
    g_Items[g_ItemCount++] = (Item){ IT_TOOL, 2, "Exit menu (hand process back)" };
}

static bool selectable(int idx) {
    return idx >= 0 && idx < g_ItemCount && g_Items[idx].kind != IT_HEADER;
}

static void moveSelection(int delta) {
    int idx = g_Selected;
    for (int guard = 0; guard < g_ItemCount; guard++) {
        idx += delta;
        if (idx < 0) idx = g_ItemCount - 1;
        if (idx >= g_ItemCount) idx = 0;
        if (selectable(idx)) { g_Selected = idx; break; }
    }
    if (g_Selected < g_Top) g_Top = g_Selected;
    if (g_Selected >= g_Top + LIST_ROWS) g_Top = g_Selected - LIST_ROWS + 1;
    if (g_Top < 0) g_Top = 0;
}

/* ---------------------------------------------------------------- render */

static void renderValue(int idx, MhxxValue *v, char *out, size_t out_size) {
    u32 value = 0;
    Result rc = mhxxValueRead(&g_Engine, v, &value);
    if (R_FAILED(rc)) {
        snprintf(out, out_size, "  --        ");
        return;
    }
    if (g_Frozen[idx]) snprintf(out, out_size, "%9u *F*", (unsigned)value);
    else               snprintf(out, out_size, "%9u    ", (unsigned)value);
}

static void render(void) {
    uiClear();

    uiTextf(COL_LEFT, ROW_TITLE, UI_CYAN
            "MHXX CTRPF MOD MENU" UI_RESET "   " UI_DIM
            "Monster Hunter XX  /  AArch32 code + value cheats" UI_RESET);
    uiTextf(COL_LEFT, 1, UI_DIM "build " UI_RESET UI_GREEN "9D4C86E6EF74504A" UI_RESET
            UI_DIM "  verified   main=" UI_RESET "%08X" UI_DIM "  pid=" UI_RESET "%llu",
            (unsigned)g_Engine.main_base, (unsigned long long)g_Engine.pid);
    uiFill(COL_LEFT, 2, 76, '=');

    for (int row = 0; row < LIST_ROWS; row++) {
        int idx = g_Top + row;
        if (idx >= g_ItemCount) break;
        Item *it = &g_Items[idx];
        int y = ROW_LIST + row;

        if (it->kind == IT_HEADER) {
            uiTextf(COL_LEFT, y, "%s-- %s %s", UI_YELLOW, it->label,
                    "----------------------------------------------------");
            continue;
        }

        bool sel = (idx == g_Selected);
        const char *mark = sel ? ">" : " ";

        if (it->kind == IT_CHEAT) {
            MhxxCheat *c = mhxxCheatAt(it->index);
            int state = mhxxCheatState(&g_Engine, c);
            const char *on = (state == 1) ? UI_GREEN "[ON ]" UI_RESET
                            : (state == 0) ? UI_DIM   "[off]" UI_RESET
                            :                UI_RED   "[ ??]" UI_RESET;
            uiTextf(COL_LEFT, y, "%s %s %s %-2s %-34s %s",
                    sel ? UI_SEL : UI_RESET, mark, on, c->id, c->name,
                    c->risk >= 2 ? UI_RED "[high]" UI_RESET :
                    c->risk == 1 ? UI_YELLOW "[med] " UI_RESET : UI_DIM "[safe]" UI_RESET);
        } else if (it->kind == IT_VALUE) {
            MhxxValue *v = mhxxValueAt(it->index);
            char shown[24];
            renderValue(it->index, v, shown, sizeof(shown));
            uiTextf(COL_LEFT, y, "%s %s %s %-2s %-24s %s%s",
                    sel ? UI_SEL : UI_RESET, mark, UI_DIM "[mem]" UI_RESET,
                    v->id, v->name, UI_WHITE, shown);
        } else {
            uiTextf(COL_LEFT, y, "%s %s %s  %s",
                    sel ? UI_SEL : UI_RESET, mark, UI_DIM "[tool]" UI_RESET, it->label);
        }
    }

    uiFill(COL_LEFT, ROW_HELP - 1, 76, '-');
    if (g_MessageTtl > 0) {
        uiTextf(COL_LEFT, ROW_HELP, UI_YELLOW "%s" UI_RESET, g_Message);
        g_MessageTtl--;
    } else {
        uiText(COL_LEFT, ROW_HELP, "");
    }
    uiTextf(COL_LEFT, ROW_HELP + 1,
            UI_DIM "D-Pad/Stick move   " UI_RESET "A" UI_DIM " toggle/set   " UI_RESET
            "X" UI_DIM " freeze value   " UI_RESET "Y" UI_DIM " revert all   " UI_RESET
            "B" UI_DIM " exit" UI_RESET);
    uiTextf(COL_LEFT, ROW_HELP + 2,
            UI_DIM "touch: tap a row to toggle/select   /   stats: %d patches available" UI_RESET,
            mhxxCheatCount());
    uiFlush();
}

/* ---------------------------------------------------------------- actions */

static void actCheat(MhxxCheat *c) {
    int state = mhxxCheatState(&g_Engine, c);
    if (state == 1) {
        messageResult("revert", mhxxCheatRevert(&g_Engine, c));
    } else if (state == 0) {
        messageResult("apply", mhxxCheatApply(&g_Engine, c));
    } else {
        message("%s: state %d - not touching memory", c->id, state);
    }
}

static void actValue(int idx, MhxxValue *v) {
    u32 current = 0;
    if (R_FAILED(mhxxValueRead(&g_Engine, v, &current))) current = v->def;

    char title[96];
    snprintf(title, sizeof(title), "%s  -  %s", v->id, v->name);
    char hint[96];
    snprintf(hint, sizeof(hint), "current %u   range %u..%u", (unsigned)current,
             (unsigned)v->min, (unsigned)v->max);

    u32 value = current;
    bool hex = (v->risk >= 1) && (v->width == 4) && strstr(v->name, "f32") != NULL;
    if (!uiKeyboard(title, hint, &value, v->min, v->max, hex)) {
        message("cancelled");
        return;
    }
    messageResult("write", mhxxValueWrite(&g_Engine, v, value));
}

static void actFreeze(int idx, MhxxValue *v) {
    if (g_Frozen[idx]) {
        (void)mhxxDmntUnfreeze(g_FrozenAddr[idx]);
        g_Frozen[idx] = false;
        message("%s: freeze off", v->id);
        return;
    }
    u64 addr = 0;
    Result rc = mhxxValueResolve(&g_Engine, v, &addr);
    if (R_FAILED(rc)) { messageResult("resolve", rc); return; }
    u64 value = 0;
    rc = mhxxDmntFreeze(addr, v->width, &value);
    if (R_FAILED(rc)) { messageResult("freeze", rc); return; }
    g_Frozen[idx] = true;
    g_FrozenAddr[idx] = addr;
    message("%s: frozen at %08X (value %u)", v->id, (unsigned)addr, (unsigned)value);
}

static void actTool(int which) {
    switch (which) {
        case 0: {
            MhxxEngine probe;
            Result rc = mhxxEngineOpen(&probe);
            messageResult("build id verify", rc);
            break;
        }
        case 1: messageResult("revert all", mhxxCheatRevertAll(&g_Engine)); break;
        default: break;
    }
}

/* ------------------------------------------------------------------ boot */

static void bootLine(const char *tag, const char *text, const char *color) {
    static int row = 0;
    if (row == 0) {
        uiClear();
        uiTextf(2, 2, UI_CYAN
                "+==============================================================+");
        uiTextf(2, 3, "|   M H X X   C T R P F   M O D   M E N U                      |");
        uiTextf(2, 4, "|   Monster Hunter XX (Switch)  /  dmnt:cht cheat engine        |");
        uiTextf(2, 5, "+==============================================================+");
        uiTextf(2, 7, UI_DIM "target : " UI_RESET UI_YELLOW "0100C3800049C000" UI_RESET
                UI_DIM "   build id : " UI_RESET UI_YELLOW "9D4C86E6EF74504A" UI_RESET);
        uiText(2, 9, "");
    }
    uiTextf(4, 11 + row, "%s[%-12s]%s %s", color, tag, UI_RESET, text);
    row++;
    uiFlush();
    uiSleepMs(140);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    uiInit();

    bootLine("mhxx-ctrpf", "Initializing UI and input...", UI_GREEN);
    bootLine("dmnt:cht", "Opening cheat-process service...", UI_GREEN);

    Result rc = pmdmntInitialize();
    if (R_FAILED(rc)) {
        bootLine("pm:dmnt", "service init FAILED", UI_RED);
        goto fatal;
    }

    u64 pid = 0;
    if (R_FAILED(pmdmntGetApplicationProcessId(&pid)) || pid == 0) {
        bootLine("application", "no application running", UI_RED);
        bootLine("hint", "Start Monster Hunter XX, then open this menu from the album.", UI_YELLOW);
        goto fatal;
    }
    bootLine("application", "found a running application", UI_GREEN);

    rc = mhxxEngineOpen(&g_Engine);
    if (R_FAILED(rc)) {
        char text[96];
        snprintf(text, sizeof(text), "attach failed (0x%08X)", (unsigned)rc);
        bootLine("dmnt:cht", text, UI_RED);
        bootLine("hint", "The title must be MHXX 1.5.1 (9D4C86E6EF74504A).", UI_YELLOW);
        bootLine("hint", "Close Nxus debug / EdiZon attach and retry.", UI_YELLOW);
        goto fatal;
    }
    bootLine("build id", "9D4C86E6EF74504A verified (dmnt + NSO header)", UI_GREEN);
    {
        char text[96];
        snprintf(text, sizeof(text), "main %08X  size %08X  pid %llu",
                 (unsigned)g_Engine.main_base, (unsigned)g_Engine.main_size,
                 (unsigned long long)g_Engine.pid);
        bootLine("module", text, UI_GREEN);
    }
    bootLine("hooks", "AArch32 patch table ready (15 presets)", UI_GREEN);
    bootLine("menu", "Press [A] to enter, [-] or [B] to leave", UI_CYAN);

    buildItems();
    g_Selected = 1;
    g_Top = 0;
    message("ready");

    while (appletMainLoop()) {
        render();
        UiInput in;
        uiPoll(&in);

        if (in.down & (HidNpadButton_B | HidNpadButton_Plus)) break;
        if (in.down & HidNpadButton_Up)    moveSelection(-1);
        if (in.down & HidNpadButton_Down)  moveSelection(1);
        if (in.down & (HidNpadButton_StickLUp))   moveSelection(-1);
        if (in.down & (HidNpadButton_StickLDown)) moveSelection(1);

        int activate = -1;
        if (in.down & HidNpadButton_A) activate = g_Selected;
        if (in.touch_tap) {
            int row = in.touch_row - ROW_LIST;
            if (row >= 0 && row < LIST_ROWS) {
                int idx = g_Top + row;
                if (selectable(idx)) { g_Selected = idx; activate = idx; }
            }
        }

        if (in.down & HidNpadButton_Y) {
            messageResult("revert all", mhxxCheatRevertAll(&g_Engine));
        }

        int freezeIdx = -1;
        if (in.down & HidNpadButton_X) freezeIdx = g_Selected;

        if (activate >= 0) {
            Item *it = &g_Items[activate];
            if (it->kind == IT_CHEAT)      actCheat(mhxxCheatAt(it->index));
            else if (it->kind == IT_VALUE) actValue(it->index, mhxxValueAt(it->index));
            else if (it->kind == IT_TOOL) {
                if (it->index == 2) break;
                actTool(it->index);
            }
        }
        if (freezeIdx >= 0) {
            Item *it = &g_Items[freezeIdx];
            if (it->kind == IT_VALUE) actFreeze(it->index, mhxxValueAt(it->index));
        }
    }

    /* leave the game exactly as we found it as far as ownership goes */
    for (int i = 0; i < 16; i++) {
        if (g_Frozen[i]) { (void)mhxxDmntUnfreeze(g_FrozenAddr[i]); g_Frozen[i] = false; }
    }
    mhxxEngineClose(&g_Engine);
    mhxxDmntExit();
    pmdmntExit();
    uiExit();
    return 0;

fatal:
    uiClear();
    uiText(2, 36, UI_RED "Press [+] to exit." UI_RESET);
    uiText(2, 37, UI_DIM "Nothing was written to the game." UI_RESET);
    uiFlush();
    for (;;) {
        UiInput in;
        uiPoll(&in);
        if (in.down & (HidNpadButton_Plus | HidNpadButton_B)) break;
    }
    mhxxEngineClose(&g_Engine);
    mhxxDmntExit();
    pmdmntExit();
    uiExit();
    return 1;
}
