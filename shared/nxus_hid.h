/*
 * Nxus HID hotkey.
 *
 * A sysmodule cannot use the applet input path, so this tries the hid service
 * directly and reports exactly what happened - whether a sysmodule may read the
 * controller at all is one of the questions the probe answers on real hardware.
 */
#pragma once

#include <switch.h>

typedef void (*NxusHotkeyCallback)(void *user);

void nxusHidInit(void);
void nxusHidExit(void);

/* 0 when the hid service could not be opened (see nxusHidStatus). */
int  nxusHidAvailable(void);
Result nxusHidStatus(void);
u64  nxusHidLastButtons(void);

/* Live held-button mask for opcode 8 (key-conditional cheat codes), combining
   the default pad and the handheld pad.  Updated by the HID polling worker even
   when the hotkey is disabled; 0 when the worker is not running or HID could
   not be opened.  Atomic load, safe from the server thread. */
uint64_t nxusHidHeldMask(void);

/* Combo configuration.  mask 0 disables it. */
void nxusHidConfigure(u64 mask, u32 hold_ms, u32 enabled);
void nxusHidGetConfig(u64 *out_mask, u32 *out_hold_ms, u32 *out_enabled);

/* Invoked from the HID thread when the combo fires. */
void nxusHidSetCallback(NxusHotkeyCallback callback, void *user);

/* One-shot read used by the probe: returns the buttons currently held. */
Result nxusHidReadOnce(u64 *out_buttons);

/* Start the polling thread (called once a hotkey is configured). */
void nxusHidStart(void);
