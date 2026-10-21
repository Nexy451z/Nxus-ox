#!/bin/bash
# Everything that can be verified without a Nintendo Switch.
set -uo pipefail
NXUS_ROOT=/c/anyWorkspace/nx/Nxus
BASH_BIN=/c/devkitPro/msys2/usr/bin/bash.exe
export PATH="$HOME/.cargo/bin:$PATH"
fail=0

echo "############ 1. host unit tests (scan / ptrscan / snapshot, C) ############"
"$BASH_BIN" -l "$NXUS_ROOT/tests/run_tests.sh" || fail=1

echo
echo "############ 2. sysmodule build + artifact verification ############"
"$BASH_BIN" -l "$NXUS_ROOT/tools/build.sh" || fail=1

echo
echo "############ 3. PC client (Rust) build ############"
"$BASH_BIN" -l "$NXUS_ROOT/tools/build_pc.sh" || fail=1

echo
echo "############ 4. PC side tests (protocol parity + Python E2E + Rust E2E) ############"
(cd "$NXUS_ROOT/pc" && python -m unittest discover -s tests 2>&1 | tail -5) || fail=1

echo
echo "############ 5. Rust unit tests (parity with the C header) ############"
(cd "$NXUS_ROOT/pc/Nxus.Cli" && cargo test --release 2>&1 | grep -E "^test |test result" | head -20) || fail=1

echo
if [ $fail -eq 0 ]; then
    echo "=========== ALL PRE-HARDWARE CHECKS PASSED ==========="
else
    echo "=========== FAILURES PRESENT ==========="
fi
exit $fail
