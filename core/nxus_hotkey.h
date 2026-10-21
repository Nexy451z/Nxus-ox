#pragma once

/* Hotkey state machine.  Lives in core/ so the host tests can pin it: the same
 * latch kept the combo from re-arming (one-shot) once, and later made it fire on
 * every 10 ms poll while held.  The console only supplies (down, elapsed). */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool fired;       /* the combo reached its hold threshold this press */
    bool reported;    /* the callback already ran for this press           */
    uint32_t held_ms; /* how long the combo has been held                 */
} NxusHotkeyLatch;

void nxusHotkeyLatchInit(NxusHotkeyLatch *latch);

/* Returns true exactly once per press.
 *   down       - the combo is held right now
 *   elapsed_ms - time since the previous call
 *   hold_ms    - 0 fires immediately, otherwise the combo must be held this long
 *   enabled    - false disarms the hotkey completely (and re-arms on release) */
bool nxusHotkeyStep(NxusHotkeyLatch *latch, bool down, uint32_t elapsed_ms,
                    uint32_t hold_ms, bool enabled);