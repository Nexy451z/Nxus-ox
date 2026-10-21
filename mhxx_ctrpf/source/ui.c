#include "ui.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define LINE_MAX 256

static char g_Screen[UI_ROWS][LINE_MAX];
static PadState g_Pad;
static bool g_Touch;
static int  g_PrevTouchCount;
static int  g_TouchStartX, g_TouchStartY, g_TouchX, g_TouchY;

void uiSleepMs(u32 ms) { svcSleepThread((u64)ms * 1000000ull); }

void uiInit(void) {
    consoleInit(NULL);
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    padInitializeDefault(&g_Pad);
    hidInitializeTouchScreen();
    g_Touch = true;
    uiClear();
    uiFlush();
}

void uiExit(void) {
    consoleExit(NULL);
}

void uiClear(void) {
    for (int r = 0; r < UI_ROWS; r++) {
        g_Screen[r][0] = 0;
    }
}

static void putRaw(int col, int row, const char *text, size_t len) {
    if (row < 0 || row >= UI_ROWS) return;
    if (col < 0) { text -= col; len += (size_t)col; col = 0; }
    char *dst = g_Screen[row];
    size_t cur = strlen(dst);
    if (cur == 0) {
        /* pad with spaces so absolute positioning works */
        size_t pad = (size_t)col;
        if (pad >= LINE_MAX - 1) pad = LINE_MAX - 2;
        memset(dst, ' ', pad);
        dst[pad] = 0;
        cur = pad;
    }
    if (cur < (size_t)col) {
        size_t pad = (size_t)col - cur;
        while (pad-- && cur < LINE_MAX - 1) dst[cur++] = ' ';
        dst[cur] = 0;
    }
    for (size_t i = 0; i < len && cur < LINE_MAX - 1; i++) dst[cur++] = text[i];
    dst[cur] = 0;
}

void uiText(int col, int row, const char *text) {
    putRaw(col, row, text, strlen(text));
}

void uiTextf(int col, int row, const char *fmt, ...) {
    char buf[LINE_MAX];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    uiText(col, row, buf);
}

void uiFill(int col, int row, int width, char ch) {
    char buf[LINE_MAX];
    if (width <= 0) return;
    if (width > (int)sizeof(buf) - 1) width = (int)sizeof(buf) - 1;
    memset(buf, ch, (size_t)width);
    buf[width] = 0;
    uiText(col, row, buf);
}

void uiBox(int col, int row, int width, int height) {
    if (width < 2 || height < 2) return;
    char line[LINE_MAX];
    int w = width > (int)sizeof(line) - 1 ? (int)sizeof(line) - 1 : width;
    line[0] = '+';
    memset(line + 1, '-', (size_t)(w - 2));
    line[w - 1] = '+';
    line[w] = 0;
    uiText(col, row, line);
    uiText(col, row + height - 1, line);
    for (int r = 1; r < height - 1; r++) {
        uiText(col, row + r, "|");
        uiText(col + w - 1, row + r, "|");
    }
}

void uiFlush(void) {
    consoleClear();
    for (int r = 0; r < UI_ROWS; r++) {
        if (g_Screen[r][0]) printf("%s", g_Screen[r]);
        printf("\n");
    }
    consoleUpdate(NULL);
}

void uiPoll(UiInput *in) {
    memset(in, 0, sizeof(*in));
    padUpdate(&g_Pad);
    in->down = padGetButtonsDown(&g_Pad);
    in->held = padGetButtons(&g_Pad);
    in->touch_col = -1;
    in->touch_row = -1;

    if (g_Touch) {
        HidTouchScreenState ts;
        memset(&ts, 0, sizeof(ts));
        if (R_SUCCEEDED(hidGetTouchScreenStates(&ts, 1))) {
            int count = ts.count;
            if (count > 0) {
                g_TouchX = ts.touches[0].x;
                g_TouchY = ts.touches[0].y;
                if (g_PrevTouchCount == 0) {
                    g_TouchStartX = g_TouchX;
                    g_TouchStartY = g_TouchY;
                }
                in->touch_col = g_TouchX / UI_CELL;
                in->touch_row = g_TouchY / UI_CELL;
            } else if (g_PrevTouchCount > 0) {
                int dx = g_TouchX - g_TouchStartX;
                int dy = g_TouchY - g_TouchStartY;
                if (dx > -48 && dx < 48 && dy > -48 && dy < 48) {
                    in->touch_tap = true;
                    in->touch_col = g_TouchX / UI_CELL;
                    in->touch_row = g_TouchY / UI_CELL;
                }
            }
            g_PrevTouchCount = count;
        }
    }
    uiSleepMs(24);
}

/* ------------------------------------------------------------- keyboard */

static const char *kHexKeys[16] = {
    "0", "1", "2", "3", "4", "5", "6", "7",
    "8", "9", "A", "B", "C", "D", "E", "F",
};

static int kbdRectCol(int idx, int cols) { (void)cols; return 24 + (idx % 4) * 8; }
static int kbdRectRow(int idx) { return 14 + (idx / 4) * 3; }

bool uiKeyboard(const char *title, const char *hint, u32 *value, u32 min, u32 max, bool hex) {
    u32 base = hex ? 16u : 10u;
    u32 digits = 0;
    char error[64];
    error[0] = 0;
    int cursor = 0;                     /* 0..15 = hex/dec keys, 16 = DEL, 17 = OK, 18 = CANCEL */
    const int total = 19;

    while (true) {
        uiClear();
        uiBox(18, 8, 44, 30);
        uiTextf(20, 9, UI_CYAN "%s" UI_RESET, title);
        if (hint && hint[0]) uiText(20, 10, hint);

        char shown[32];
        if (hex) snprintf(shown, sizeof(shown), "0x%08X", (unsigned)digits);
        else     snprintf(shown, sizeof(shown), "%u", (unsigned)digits);
        uiTextf(20, 12, UI_WHITE "value: " UI_YELLOW "%s" UI_RESET, shown);
        if (error[0]) uiTextf(20, 13, UI_RED "%s" UI_RESET, error);

        int keys = hex ? 16 : 10;
        for (int i = 0; i < keys; i++) {
            int col = kbdRectCol(i, 4);
            int row = kbdRectRow(i);
            bool sel = (cursor == i);
            uiTextf(col, row, "%s[ %s ]%s", sel ? UI_SEL : UI_WHITE,
                    hex ? kHexKeys[i] : kHexKeys[i], UI_RESET);
        }
        uiTextf(56, 14, "%s[ DEL ]%s", cursor == 16 ? UI_SEL : UI_DIM, UI_RESET);
        uiTextf(56, 17, "%s[ OK  ]%s", cursor == 17 ? UI_SEL : UI_GREEN, UI_RESET);
        uiTextf(56, 20, "%s[ CXL ]%s", cursor == 18 ? UI_SEL : UI_RED, UI_RESET);

        uiText(20, 26, "D-Pad/Stick: move   A: press   B: cancel");
        uiText(20, 27, "Touch: tap a key directly");
        uiTextf(20, 29, UI_DIM "range %u .. %u%s" UI_RESET, (unsigned)min, (unsigned)max,
                hex ? "  (hex)" : "");
        uiFlush();

        UiInput in;
        uiPoll(&in);

        if (in.down & (HidNpadButton_B | HidNpadButton_Plus)) return false;
        if (in.down & HidNpadButton_Up)    cursor = (cursor + total - 1) % total;
        if (in.down & HidNpadButton_Down)  cursor = (cursor + 1) % total;
        if (in.down & HidNpadButton_Left)  cursor = (cursor + total - 1) % total;
        if (in.down & HidNpadButton_Right) cursor = (cursor + 1) % total;

        bool activate = (in.down & HidNpadButton_A) != 0;
        if (in.touch_tap) {
            for (int i = 0; i < keys; i++) {
                if (in.touch_row >= kbdRectRow(i) && in.touch_row < kbdRectRow(i) + 2 &&
                    in.touch_col >= kbdRectCol(i, 4) && in.touch_col < kbdRectCol(i, 4) + 16) {
                    cursor = i;
                    activate = true;
                }
            }
            if (in.touch_row >= 14 && in.touch_row < 16 && in.touch_col >= 56 && in.touch_col < 70) { cursor = 16; activate = true; }
            if (in.touch_row >= 17 && in.touch_row < 19 && in.touch_col >= 56 && in.touch_col < 70) { cursor = 17; activate = true; }
            if (in.touch_row >= 20 && in.touch_row < 22 && in.touch_col >= 56 && in.touch_col < 70) { cursor = 18; activate = true; }
        }
        if (!activate) continue;

        error[0] = 0;
        if (cursor < keys) {
            u32 digit = (u32)cursor;
            if (digits <= (0xFFFFFFFFu - digit) / base) digits = digits * base + digit;
        } else if (cursor == 16) {
            digits /= base;
        } else if (cursor == 18) {
            return false;
        } else {
            if (digits < min) { snprintf(error, sizeof(error), "too small (min %u)", (unsigned)min); continue; }
            if (digits > max) { snprintf(error, sizeof(error), "too large (max %u)", (unsigned)max); continue; }
            *value = digits;
            return true;
        }
    }
}
