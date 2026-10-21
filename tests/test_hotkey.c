/* Host tests for the hotkey latch: it must fire exactly once per press and
   re-arm on release (both have been regressions in this project). */
#include <stdio.h>
#include <string.h>
#include "nxus_hotkey.h"

static int failures = 0;
static int checks = 0;

static void check(int condition, const char *what) {
    checks++;
    if (!condition) {
        failures++;
        printf("  FAIL  %s\n", what);
    }
}

int main(void) {
    printf("- hotkey latch\n");
    NxusHotkeyLatch latch;

    /* immediate fire (no hold requirement): exactly one callback per press */
    nxusHotkeyLatchInit(&latch);
    check(nxusHotkeyStep(&latch, true, 10, 0, true) == true, "fires on the first held poll");
    check(nxusHotkeyStep(&latch, true, 10, 0, true) == false, "does not fire again while held");
    check(nxusHotkeyStep(&latch, true, 10, 0, true) == false, "still silent on the third poll");
    check(nxusHotkeyStep(&latch, false, 10, 0, true) == false, "release reports nothing");
    check(nxusHotkeyStep(&latch, true, 10, 0, true) == true, "re-arms and fires on the next press");

    /* hold threshold: 500 ms means 50 polls of 10 ms */
    nxusHotkeyLatchInit(&latch);
    int fired_at = -1;
    for (int i = 1; i <= 60; i++) {
        if (nxusHotkeyStep(&latch, true, 10, 500, true)) { fired_at = i; break; }
    }
    check(fired_at == 50, "fires on the 50th 10 ms poll, not before");
    check(nxusHotkeyStep(&latch, true, 10, 500, true) == false, "no repeat after the threshold");

    /* releasing early must not fire, and a later full hold must */
    nxusHotkeyLatchInit(&latch);
    for (int i = 0; i < 20; i++) (void)nxusHotkeyStep(&latch, true, 10, 500, true);
    (void)nxusHotkeyStep(&latch, false, 10, 500, true);
    fired_at = -1;
    for (int i = 1; i <= 60; i++) {
        if (nxusHotkeyStep(&latch, true, 10, 500, true)) { fired_at = i; break; }
    }
    check(fired_at == 50, "an aborted press does not shorten the next hold");

    /* disabled disarms completely and clears the latch */
    nxusHotkeyLatchInit(&latch);
    check(nxusHotkeyStep(&latch, true, 10, 0, false) == false, "disabled never fires");
    check(latch.fired == false && latch.held_ms == 0, "disabled clears the latch");
    check(nxusHotkeyStep(&latch, true, 10, 0, true) == true, "re-enabled fires again");

    printf("%d checks, %d failure(s)\n", checks, failures);
    if (failures == 0) printf("ALL HOTKEY TESTS PASSED\n");
    return failures == 0 ? 0 : 1;
}