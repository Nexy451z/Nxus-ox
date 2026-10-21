#include "nxus_hotkey.h"

void nxusHotkeyLatchInit(NxusHotkeyLatch *latch) {
    if (latch == NULL) return;
    latch->fired = false;
    latch->reported = false;
    latch->held_ms = 0;
}

bool nxusHotkeyStep(NxusHotkeyLatch *latch, bool down, uint32_t elapsed_ms,
                    uint32_t hold_ms, bool enabled) {
    if (latch == NULL) return false;

    if (!enabled) {
        nxusHotkeyLatchInit(latch);
        return false;
    }

    if (!down) {
        /* released: re-arm, so the next press fires again */
        latch->fired = false;
        latch->reported = false;
        latch->held_ms = 0;
        return false;
    }

    if (!latch->fired) {
        latch->held_ms += elapsed_ms;
        if (hold_ms == 0 || latch->held_ms >= hold_ms) latch->fired = true;
    }

    if (latch->fired && !latch->reported) {
        latch->reported = true;      /* exactly one callback per press */
        return true;
    }
    return false;
}