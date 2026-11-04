#!/bin/bash
# Host-side test runner for the Nxus portable core.
# Uses the MSYS2 gcc (works without external toolchain downloads).
set -u
cd "$(dirname "$0")" || exit 1
CC=/usr/bin/gcc
CFLAGS="-std=c11 -O2 -Wall -Wextra -I../core"

fail=0
run_test() {
    name="$1"; shift
    echo "--- building $name ---"
    # TEST_INCS carries per-test include paths / flags (e.g. the libnx stub
    # headers that let a Switch unit be compiled on the host).
    if ! $CC $CFLAGS ${TEST_INCS:-} -o "$name.exe" "$@" 2> "$name.build.log"; then
        echo "BUILD FAILED: $name"
        cat "$name.build.log"
        fail=1
        return
    fi
    if [ -s "$name.build.log" ]; then
        echo "(warnings)"; cat "$name.build.log"
    fi
    echo "--- running $name ---"
    ./"$name.exe"
    rc=$?
    if [ $rc -ne 0 ]; then echo "TEST FAILED: $name (rc=$rc)"; fail=1; fi
}

run_test test_scan test_scan.c ../core/nxus_scan.c
run_test test_ptrscan test_ptrscan.c ../core/nxus_ptrscan.c ../core/nxus_scan.c
run_test test_snapshot test_snapshot.c ../core/nxus_snapshot.c ../core/nxus_scan.c
# The budget test includes the REAL switch/include/nxus_session.h (so its caps
# cannot drift from the production macros); the stub supplies the small libnx
# surface that header pulls in through <switch.h>.
TEST_INCS="-I./stubs -I../switch/include" \
    run_test test_budget test_budget.c
run_test test_scantypes test_scantypes.c ../core/nxus_scan.c
run_test test_hotkey test_hotkey.c ../core/nxus_hotkey.c
# Server/session algorithms that nxus_server.c cannot expose to the host: the
# page-cache clamp/zero-fill, the frozen ownership table, the tick's scan-vs-
# command watchdog evaluation, and the NXUS/libnx result-code encodings.  This
# harness is self-contained on purpose, so it stays runnable while the server
# translation unit itself is being edited.
run_test test_server_logic test_server_logic.c
# The session is a Switch unit (libnx).  stubs/switch.h supplies the small libnx
# surface it uses, so the real pin/retire code is compiled and exercised on the
# host instead of being skipped.
TEST_INCS="-I./stubs -I../switch/include -I../shared -pthread" \
    run_test test_session_view test_session_view.c ../core/nxus_scan.c

# The snapshot service is a Switch unit as well: stubs/switch.h supplies libnx and
# stubs/nxus_session_stub.c supplies the session surface (controllable target
# identity, one region, reads, logging), so the test compiles the SHIPPED
# switch/source/nxus_snapshot_srv.c by including it - that is what makes the
# static per-slot / cached-diff owner stamps observable.  The core diff engine it
# calls is linked as usual.
TEST_INCS="-I./stubs -I../switch/include -I../shared -pthread" \
    run_test test_snapshot_owner test_snapshot_owner.c \
    ../core/nxus_snapshot.c ./stubs/nxus_session_stub.c

# The console-side cheat interpreter is plain C (no libnx), so the SHIPPED
# core/nxus_cheatvm.c is linked directly against a mock NxusCheatIo (memory
# array + write log + failure injection).  That exercises install validation,
# the original-byte journal and every opcode family on the host, which is where
# a width truncation or a loop counter bug would otherwise reach a title.
run_test test_cheatvm test_cheatvm.c ../core/nxus_cheatvm.c

# The cheat SERVICE above the interpreter (switch/source/nxus_cheat_srv.c) is a
# Switch unit: stubs/nxus_cheat_stub.c supplies the session/dmnt/HID/server/net
# entry points it uses (settable target identity + incarnation, a 1 MiB fake
# target, write/range failure injection, a recorded event sink) and the test
# includes the SHIPPED .c, so its static 16 ms worker step, the 3-tick auto
# disable, the PanicOff restore accounting and the upload target stamp are all
# exercised on the host.  core/nxus_cheatvm.c is linked as usual.
TEST_INCS="-I./stubs -I../switch/include -I../shared -pthread" \
    run_test test_cheat_srv test_cheat_srv.c ./stubs/nxus_cheat_stub.c ../core/nxus_cheatvm.c

echo
if [ $fail -eq 0 ]; then echo "ALL HOST TESTS PASSED"; else echo "SOME TESTS FAILED"; fi
exit $fail
