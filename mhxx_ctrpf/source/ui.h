#pragma once

#include <switch.h>

#define UI_COLS 80
#define UI_ROWS 45
#define UI_CELL 16

#define UI_RESET  "\x1b[0m"
#define UI_DIM    "\x1b[30;1m"
#define UI_RED    "\x1b[31;1m"
#define UI_GREEN  "\x1b[32;1m"
#define UI_YELLOW "\x1b[33;1m"
#define UI_BLUE   "\x1b[34;1m"
#define UI_MAGENTA "\x1b[35;1m"
#define UI_CYAN   "\x1b[36;1m"
#define UI_WHITE  "\x1b[37;1m"
#define UI_SEL    "\x1b[46;30m"

void uiInit(void);
void uiExit(void);

void uiClear(void);
void uiText(int col, int row, const char *text);
void uiTextf(int col, int row, const char *fmt, ...);
void uiFill(int col, int row, int width, char ch);
void uiFlush(void);

typedef struct {
    u64 down;          /* buttons pressed this frame */
    u64 held;
    int touch_col;
    int touch_row;
    bool touch_tap;    /* released after a short press without moving */
} UiInput;

void uiPoll(UiInput *in);
void uiSleepMs(u32 ms);

/* Blocking modal numeric keypad (touch + dpad/stick + A/B).
   Returns true when a value was accepted. */
bool uiKeyboard(const char *title, const char *hint, u32 *value, u32 min, u32 max, bool hex);

/* Small helpers shared by the menu. */
void uiBox(int col, int row, int width, int height);
