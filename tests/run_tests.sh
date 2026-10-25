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
run_test test_budget test_budget.c
run_test test_scantypes test_scantypes.c ../core/nxus_scan.c
run_test test_hotkey test_hotkey.c ../core/nxus_hotkey.c
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

echo
if [ $fail -eq 0 ]; then echo "ALL HOST TESTS PASSED"; else echo "SOME TESTS FAILED"; fi
exit $fail
