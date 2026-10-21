#include "nxus_hid.h"
#include "nxus_hotkey.h"

#include "nxus_log.h"

#include <stdatomic.h>
#include <string.h>

static Thread   g_Thread;
static bool     g_ThreadLive = false;
static bool     g_Available = false;
static Result   g_InitResult = 0;
static atomic_bool g_Stop;

static u64      g_Mask = 0;
static u32      g_HoldMs = 0;
static u32      g_Enabled = 0;
static u64      g_LastButtons = 0;

static NxusHotkeyCallback g_Callback = NULL;
static void    *g_CallbackUser = NULL;

static Mutex    g_Mutex;

void nxusHidInit(void) {
    mutexInit(&g_Mutex);
    atomic_init(&g_Stop, false);
}

void nxusHidSetCallback(NxusHotkeyCallback callback, void *user) {
    mutexLock(&g_Mutex);
    g_Callback = callback;
    g_CallbackUser = user;
    mutexUnlock(&g_Mutex);
}

void nxusHidConfigure(u64 mask, u32 hold_ms, u32 enabled) {
    mutexLock(&g_Mutex);
    g_Mask = mask;
    g_HoldMs = hold_ms;
    g_Enabled = enabled;
    mutexUnlock(&g_Mutex);
    NXUS_LOG("hotkey: mask=%08llX hold=%ums enabled=%u",
             (unsigned long long)mask, (unsigned)hold_ms, (unsigned)enabled);
}

void nxusHidGetConfig(u64 *out_mask, u32 *out_hold_ms, u32 *out_enabled) {
    mutexLock(&g_Mutex);
    if (out_mask) *out_mask = g_Mask;
    if (out_hold_ms) *out_hold_ms = g_HoldMs;
    if (out_enabled) *out_enabled = g_Enabled;
    mutexUnlock(&g_Mutex);
}

int nxusHidAvailable(void) { return g_Available ? 1 : 0; }
Result nxusHidStatus(void) { return g_InitResult; }
u64 nxusHidLastButtons(void) { return g_LastButtons; }

/* Open the input service.  A sysmodule may or may not be allowed to; log both
   attempts so hardware day 1 tells us which path works. */
static Result openInput(void) {
    Result rc = hidInitialize();
    NXUS_RESULT("hidInitialize", rc);
    if (R_SUCCEEDED(rc)) return 0;

    rc = hidsysInitialize();
    NXUS_RESULT("hidsysInitialize (fallback)", rc);
    if (R_SUCCEEDED(rc)) {
        rc = hidInitialize();
        NXUS_RESULT("hidInitialize (after hidsys)", rc);
        if (R_FAILED(rc)) hidsysExit();
    }
    return rc;
}

static void hidThread(void *arg) {
    (void)arg;

    g_InitResult = openInput();
    if (R_FAILED(g_InitResult)) {
        NXUS_LOG("hotkey: input unavailable - the hotkey stays disabled");
        return;
    }

    PadState pad;
    padInitializeDefault(&pad);
    g_Available = true;
    NXUS_LOG("hotkey: input ready");

    /* The latch lives in core/nxus_hotkey.c and is covered by host tests: it must
       fire exactly once per press and re-arm when the combo is released. */
    NxusHotkeyLatch latch;
    nxusHotkeyLatchInit(&latch);

    while (!atomic_load_explicit(&g_Stop, memory_order_relaxed)) {
        padUpdate(&pad);
        u64 buttons = padGetButtons(&pad);
        g_LastButtons = buttons;

        u64 mask;
        u32 hold_ms, enabled;
        nxusHidGetConfig(&mask, &hold_ms, &enabled);

        if (!enabled || mask == 0) {
            (void)nxusHotkeyStep(&latch, false, 0, hold_ms, false);
            svcSleepThread(20000000ull);         /* 20ms */
            continue;
        }

        const bool down = (buttons & mask) == mask;
        if (nxusHotkeyStep(&latch, down, 10, hold_ms, true)) {
            NxusHotkeyCallback callback;
            void *user;
            mutexLock(&g_Mutex);
            callback = g_Callback;
            user = g_CallbackUser;
            mutexUnlock(&g_Mutex);

            NXUS_LOG("hotkey: combo fired (buttons=%08llX)", (unsigned long long)buttons);
            if (callback != NULL) callback(user);
        }

        svcSleepThread(10000000ull);             /* 10ms poll */
    }

    if (g_Available) hidExit();
    g_Available = false;
    g_ThreadLive = false;
}

void nxusHidExit(void) {
    atomic_store_explicit(&g_Stop, true, memory_order_relaxed);
    if (g_ThreadLive) {
        threadWaitForExit(&g_Thread);
        threadClose(&g_Thread);
        g_ThreadLive = false;
    }
}

Result nxusHidReadOnce(u64 *out_buttons) {
    if (out_buttons == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    Result rc = openInput();
    if (R_FAILED(rc)) return rc;

    PadState pad;
    padInitializeDefault(&pad);
    padUpdate(&pad);
    *out_buttons = padGetButtons(&pad);
    hidExit();
    return 0;
}

/* Started lazily by the server once a hotkey is configured, so an unused
   sysmodule does not hold the input service open. */
void nxusHidStart(void) {
    if (g_ThreadLive) return;
    atomic_store_explicit(&g_Stop, false, memory_order_relaxed);
    alignas(0x1000) static u8 stack[0x4000];
    Result rc = threadCreate(&g_Thread, hidThread, NULL, stack, sizeof(stack), 0x2C, -2);
    if (R_FAILED(rc)) {
        NXUS_LOG("hotkey: threadCreate failed rc=0x%08X", (unsigned)rc);
        return;
    }
    g_ThreadLive = true;
    threadStart(&g_Thread);
}
