#!/bin/bash
# Build every Nxus sysmodule, force the debug capabilities into each NPDM,
# repack SD-ready exefs.nsp files and verify the results.
set -euo pipefail
NXUS_ROOT=/c/anyWorkspace/nx/Nxus
TOOLS=$NXUS_ROOT/tools
PY=python
BLDPFS0=/opt/devkitpro/tools/bin/build_pfs0

# Shown in the per-folder README.txt / metadata.json so DBI, file managers and
# other agents can tell what 4200000000004E58 actually is.
NXUS_VERSION=0.1.0-alpha

build_target() {
    dir="$1"        # switch | probe
    tid="$2"        # title id used for the SD path
    name="$3"       # target name (nso/npdm basename)
    role="${4:-sysmodule}"
    description="${5:-Nxus-ox sysmodule}"
    tcp_port="${6:-7332}"
    boot2="${7:-1}"

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
    # NOTE: `[ cond ] && touch ... || rm -f ...` hides a failed touch (rm succeeds, so
    # the statement returns 0 and `set -e` never fires).  Use explicit branches.
    boot2_flag="$dist/flags/boot2.flag"
    if [ "${NXUS_STAGE_PROBE:-0}" = "1" ]; then
        # stage 1: the probe alone boots, so its numbers are the only measurement
        if [ "$name" = "probe" ]; then
            touch "$boot2_flag"
        else
            rm -f "$boot2_flag"
        fi
    else
        if [ "$name" = "nxus" ]; then
            touch "$boot2_flag"
        else
            rm -f "$boot2_flag"
        fi
    fi

    $PY "$TOOLS/verify_artifact.py" "$dist/exefs.nsp"

    # Identification metadata.
    #
    # A custom sysmodule carries no name: its NPDM has a title id and nothing else,
    # so tools that list SD contents (DBI, homebrew file managers) show the bare
    # 4200000000004E58 and the user (or another agent) cannot tell what it is.
    # Ship a plain-text + JSON description next to the exefs so the folder is
    # self-describing.  These files are inert: Atmosphère only reads exefs.nsp and
    # flags/, so nothing about the module's behaviour depends on them.

    # One timestamp for both files, so README.txt and metadata.json cannot disagree.
    built=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # README.txt: values are injected with printf, the fixed body is a QUOTED
    # heredoc so a '$' or a backtick in the text is never expanded (and `set -u`
    # cannot abort on an undefined variable inside the body).  Written to *.tmp
    # and renamed, so an interrupted run never leaves a half-written file.
    readme_tmp="$dist/README.txt.tmp"
    {
        printf '%s - part of Nxus-ox (Alpha v%s)\n' "$name" "$NXUS_VERSION"
        printf 'title id : 0x%s\n' "$tid"
        printf 'role     : %s\n' "$role"
        if [ "$tcp_port" = "0" ]; then
            printf 'tcp port : none (diagnostic only - this module does not listen)\n'
        else
            printf 'tcp port : %s\n' "$tcp_port"
        fi
        if [ "$boot2" = "1" ]; then
            printf 'boot2    : yes (flags/boot2.flag ships with this folder)\n'
        else
            printf 'boot2    : no (this folder must NOT get a flags/boot2.flag)\n'
        fi
        printf 'built    : %s\n' "$built"
        cat <<'README_EOF'

Nxus-ox is a headless remote memory scanner / pointer finder / hardware
debugger for Nintendo Switch (Atmosphère).  There is no on-screen UI: the PC
client (nxus.exe) talks to the main sysmodule over TCP port 7332.

This is the main nxus sysmodule and owns port 7332.  The optional diagnostic
probe (title id 0x4200000000004E59) must never be installed with its own
flags/boot2.flag at the same time: two custom sysmodules both taking a debug
handle fight over the same process.

PC client : nxus.exe --host <SWITCH_IP> status
Project   : https://github.com/Nexy451z/Nxus-ox
Alpha software, no warranty.  Always run on emuMMC with a NAND/SD backup.

Files here:
  exefs.nsp     the sysmodule Atmosphère loads
  flags/        boot2.flag makes it start at boot (empty file)
  metadata.json machine-readable copy of this information
README_EOF
    } > "$readme_tmp"
    mv "$readme_tmp" "$dist/README.txt"

    # metadata.json: build it with json.dump so description/role may contain
    # quotes, backslashes or newlines and still produce valid JSON.  The result
    # is re-parsed before it replaces the old file.
    meta_tmp="$dist/metadata.json.tmp"
    $PY - "$meta_tmp" "$name" "$NXUS_VERSION" "$tid" "$role" "$description" "$built" "$tcp_port" "$boot2" <<'PYEOF'
import json
import sys

out, name, version, tid, role, description, built, tcp_port, boot2 = sys.argv[1:10]
data = {
    "name": name,
    "project": "Nxus-ox",
    "version": version,
    "channel": "alpha",
    "title_id": "0x" + tid,
    "role": role,
    "description": description,
    "tcp_port": int(tcp_port),
    "boot2_flag": boot2 == "1",
    "repository": "https://github.com/Nexy451z/Nxus-ox",
    "built_utc": built,
    "warranty": "none - alpha software, use on emuMMC with a backup",
}
with open(out, "w", encoding="utf-8", newline="\n") as f:
    json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
    f.write("\n")
PYEOF
    $PY -c 'import json, sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$meta_tmp"
    mv "$meta_tmp" "$dist/metadata.json"
    echo
}

# Sysmodule title ids live in the 0x42... range on a real console; 0x0100... is the
# homebrew *application* range and is not started at boot2 (Atmosphère 1.12.1 / FW 23).
build_target switch 4200000000004E58 nxus \
    "memory scanner / pointer finder / hardware debugger (sysmodule)" \
    "Nxus-ox main sysmodule: headless remote memory scanner, pointer chain finder and hardware watchpoint/breakpoint debugger for Nintendo Switch (Atmosphère). No on-screen UI; the PC client nxus.exe connects over TCP port 7332."
build_target probe  4200000000004E59 probe \
    "hardware diagnostic probe (sysmodule, optional - does NOT listen on port 7332)" \
    "Nxus-ox diagnostic probe: answers the hardware bring-up questions (can a custom sysmodule obtain debug privileges, are hardware breakpoints per-core, which debug control words the kernel accepts) and writes the verdict to sdmc:/nxus/probe.txt. It never opens a TCP port and must not run at the same time as the main nxus sysmodule (0x4200000000004E58), because both would try to own a debug handle." \
    0 0

echo "== dist tree =="
find "$NXUS_ROOT/dist" -type f | sed "s|$NXUS_ROOT/||"
