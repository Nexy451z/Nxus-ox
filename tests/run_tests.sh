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
    if ! $CC $CFLAGS -o "$name.exe" "$@" 2> "$name.build.log"; then
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
run_test test_scantypes test_scantypes.c ../core/nxus_scan.c
run_test test_hotkey test_hotkey.c ../core/nxus_hotkey.c

echo
if [ $fail -eq 0 ]; then echo "ALL HOST TESTS PASSED"; else echo "SOME TESTS FAILED"; fi
exit $fail
