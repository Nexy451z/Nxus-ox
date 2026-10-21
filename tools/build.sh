#!/bin/bash
# Build every Nxus sysmodule, force the debug capabilities into each NPDM,
# repack SD-ready exefs.nsp files and verify the results.
set -euo pipefail
NXUS_ROOT=/c/anyWorkspace/nx/Nxus
TOOLS=$NXUS_ROOT/tools
PY=python
BLDPFS0=/opt/devkitpro/tools/bin/build_pfs0

build_target() {
    dir="$1"        # switch | probe
    tid="$2"        # title id used for the SD path
    name="$3"       # target name (nso/npdm basename)

    echo "== $name ($dir) =="
    if ! make -C "$NXUS_ROOT/$dir" > "$NXUS_ROOT/$dir/build.log" 2>&1; then
        echo "BUILD FAILED"
        tail -30 "$NXUS_ROOT/$dir/build.log"
        return 1
    fi
    tail -2 "$NXUS_ROOT/$dir/build.log" | grep -E 'built|Nothing' || true

    $PY "$TOOLS/npdm_debug_patch.py" "$NXUS_ROOT/$dir/$name.npdm"
    # The PFS0 data area starts right after the string table, so a non-16-byte npdm
    # pushes the following file off a 16-byte boundary (working sysmodules are aligned).
    $PY - "$NXUS_ROOT/$dir/$name.npdm" <<'PYEOF'
import sys
p = sys.argv[1]
d = open(p, 'rb').read()
pad = (-len(d)) % 16
if pad:
    open(p, 'wb').write(d + b'\x00' * pad)
    print(f"  npdm padded {len(d)} -> {len(d) + pad}")
PYEOF

    dist="$NXUS_ROOT/dist/atmosphere/contents/$tid"
    mkdir -p "$dist/flags" "$NXUS_ROOT/$dir/pack"
    cp "$NXUS_ROOT/$dir/$name.nso"  "$NXUS_ROOT/$dir/pack/main"
    cp "$NXUS_ROOT/$dir/$name.npdm" "$NXUS_ROOT/$dir/pack/main.npdm"
    "$BLDPFS0" "$NXUS_ROOT/$dir/pack" "$dist/exefs.nsp" > /dev/null
    # The probe is staged WITHOUT boot2.flag on purpose: both sysmodules grab the
    # single dmnt:cht cheat process at boot, so enabling both makes the probe's
    # numbers look like failures.  docs/HARDWARE_DAY1.md stages them in two runs:
    #   NXUS_STAGE_PROBE=1 tools/build.sh   -> probe gets boot2.flag, nxus does not
    if [ "${NXUS_STAGE_PROBE:-0}" = "1" ]; then
        # stage 1: the probe alone boots, so its numbers are the only measurement
        [ "$name" = "probe" ] && touch "$dist/flags/boot2.flag" || rm -f "$dist/flags/boot2.flag"
    else
        [ "$name" = "nxus" ] && touch "$dist/flags/boot2.flag" || rm -f "$dist/flags/boot2.flag"
    fi

    $PY "$TOOLS/verify_artifact.py" "$dist/exefs.nsp"
    echo
}

# Sysmodule title ids live in the 0x42... range on a real console; 0x0100... is the
# homebrew *application* range and is not started at boot2 (Atmosphère 1.12.1 / FW 23).
build_target switch 4200000000004E58 nxus
build_target probe  4200000000004E59 probe

echo "== dist tree =="
find "$NXUS_ROOT/dist" -type f | sed "s|$NXUS_ROOT/||"
