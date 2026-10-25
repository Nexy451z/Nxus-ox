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

# The probe/boot2 rule, printed identically in the probe's README.txt and in
# DO_NOT_BOOT_TOGETHER.txt.  These two generated files used to disagree: README.txt
# said the probe "must NOT get a flags/boot2.flag" while its "Files here" block
# still listed the shared `flags/ boot2.flag makes it start at boot` line (the
# branch only added the probe file, it never replaced that line).  README.md now
# carries the same text; keep the three copies in sync.
print_probe_flag_rule() {
    cat <<'PROBE_FLAG_EOF'
The probe folder ships NO flags/boot2.flag by default.  The release zip
deliberately contains none, so the two modules cannot both boot by accident.
To measure the probe, move the main module's flag aside and create this folder's
flag by hand:

  1. rename the main module's flag (do not delete it):
       sdmc:/atmosphere/contents/4200000000004E58/flags/boot2.flag
         -> sdmc:/atmosphere/contents/4200000000004E58/flags/boot2.flag.off
  2. create an EMPTY file:
       sdmc:/atmosphere/contents/4200000000004E59/flags/boot2.flag
  3. boot/reboot the console and start a game within 30 s (boot2 modules only
     run on boot, and the probe waits at most 30 s for a title)
  4. wait for a new "===== Nxus probe run ..." block at the end of
     sdmc:/nxus/probe.txt (each run is appended, never truncated; past 512 KiB
     the previous block is rotated to sdmc:/nxus/probe.txt.1), then delete the
     probe flag again and rename the main module's flag back:
       sdmc:/atmosphere/contents/4200000000004E59/flags/boot2.flag   must not exist
       sdmc:/atmosphere/contents/4200000000004E58/flags/boot2.flag.off
         -> sdmc:/atmosphere/contents/4200000000004E58/flags/boot2.flag

tools/build.sh stages the same split automatically:
  NXUS_STAGE_PROBE=1 tools/build.sh   probe gets boot2.flag, nxus does not
  tools/build.sh                      nxus gets boot2.flag, probe does not
PROBE_FLAG_EOF
}

build_target() {
    dir="$1"        # switch | probe
    tid="$2"        # title id used for the SD path
    name="$3"       # target name (nso/npdm basename)
    role="${4:-sysmodule}"
    description="${5:-Nxus-ox sysmodule}"
    tcp_port="${6:-7332}"
    boot2="${7:-1}"
    # Space-separated title ids this module must never boot together with; they
    # end up as metadata.json "conflicts_with".  Both Nxus sysmodules fight over
    # the single dmnt:cht cheat process, so each one declares the other.
    conflicts="${8:-}"

    echo "== $name ($dir) =="
    # A typo in a title id would advertise the wrong conflict to every tool that
    # reads metadata.json, so check the shape before anything is written.
    for other_tid in $conflicts; do
        if [ "${#other_tid}" -ne 16 ]; then
            echo "ERROR: conflicts_with id '$other_tid' is not 16 hex digits" >&2
            return 1
        fi
        case "$other_tid" in
            *[!0-9A-Fa-f]*)
                echo "ERROR: conflicts_with id '$other_tid' is not hexadecimal" >&2
                return 1
                ;;
        esac
    done
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
    # The probe folder additionally ships DO_NOT_BOOT_TOGETHER.txt (the manual
    # procedure) and metadata.json names the other module in conflicts_with.
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
    # Report what actually happened, not the requested default: staging swaps which
    # folder boots, and metadata.json/README must describe the real folder.
    if [ -f "$boot2_flag" ]; then boot2=1; else boot2=0; fi

    # Identification metadata.
    #
    # A custom sysmodule carries no name: its NPDM has a title id and nothing else,
    # so tools that list SD contents (DBI, homebrew file managers) show the bare
    # 4200000000004E58 and the user (or another agent) cannot tell what it is.
    # Ship a plain-text + JSON description next to the exefs so the folder is
    # self-describing.  These files are inert: Atmosphère only reads exefs.nsp and
    # flags/, so nothing about the module's behaviour depends on them.

    # One timestamp for every generated file, so README.txt, metadata.json and the
    # probe warning cannot disagree about which build they describe.
    built=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Build identifier, so a dist folder, an SD card or a bug report can be traced
    # back to the exact source revision it came from.  These are ADDITIVE
    # metadata.json keys on purpose: verify_artifact.py validates the existing ones,
    # so an extension must never rename or drop a key.
    # Neither value may abort the build: a source tree without git (or a git that
    # refuses to run in this sandbox) yields "unknown" / false instead of failing
    # after the expensive compile.  `|| source_rev=unknown` is what keeps `set -e`
    # from turning the failed command substitution into an exit.
    source_rev=$(cd "$NXUS_ROOT" && git rev-parse --short HEAD 2>/dev/null) || source_rev=unknown
    [ -n "${source_rev:-}" ] || source_rev=unknown
    dirty=false
    if [ -n "$(cd "$NXUS_ROOT" && git status --porcelain 2>/dev/null || true)" ]; then
        dirty=true
    fi

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
        elif [ "$name" = "probe" ]; then
            # Not "must NOT get a flag": the probe is measured with a flag that is
            # created by hand for one run, then deleted again (see below).
            printf 'boot2    : no flag by default (manual flag only while measuring - see below)\n'
        else
            printf 'boot2    : no (this folder must NOT get a flags/boot2.flag)\n'
        fi
        if [ -n "$conflicts" ]; then
            conflict_list=""
            for other_tid in $conflicts; do
                conflict_list="${conflict_list:+$conflict_list, }0x$other_tid"
            done
            printf 'conflicts: %s (never boot both at once - see below)\n' "$conflict_list"
        fi
        printf 'built    : %s\n' "$built"
        cat <<'README_EOF'

Nxus-ox is a headless remote memory scanner / pointer finder / hardware
debugger for Nintendo Switch (Atmosphère).  There is no on-screen UI: the PC
client (nxus.exe) talks to the main sysmodule over TCP port 7332.

Two custom sysmodules must never boot at the same time: 0x4200000000004E58 is
the main module (owns TCP port 7332) and 0x4200000000004E59 is the optional
diagnostic probe (opens no port, appends sdmc:/nxus/probe.txt).  Both take the
single dmnt:cht cheat process, so whichever loses the race reports a wrong
verdict instead of "not available".  Give at most ONE of them a
flags/boot2.flag; metadata.json names the other title id in "conflicts_with".

PC client : nxus.exe --host <SWITCH_IP> status
Project   : https://github.com/Nexy451z/Nxus-ox
Alpha software, no warranty.  Always run on emuMMC with a NAND/SD backup.

If the module does not start, look at sdmc:/nxus/nxus.log (the run log); an init
failure that happened before the log could be opened is appended to
sdmc:/nxus/boot_fail.txt instead, with the failing step and its result code.

Files here:
  exefs.nsp     the sysmodule Atmosphère loads
README_EOF
        # "Files here" is where the probe folder contradicted itself: the shared
        # body listed `flags/ boot2.flag makes it start at boot` even though the
        # probe is staged without a flag on purpose.  The probe gets the
        # manual-flag rule instead of that line; nxus keeps the old line.  The
        # exact procedure follows (same text as DO_NOT_BOOT_TOGETHER.txt and
        # README.md).
        if [ "$name" = "probe" ]; then
            printf '  flags/        NO flag by default; create an empty flags/boot2.flag by hand\n'
            printf '                only to measure the probe, then delete it (procedure below)\n'
        else
            printf '  flags/        boot2.flag makes it start at boot (empty file)\n'
        fi
        printf '  metadata.json machine-readable copy of this information\n'
        if [ "$name" = "probe" ]; then
            printf '  DO_NOT_BOOT_TOGETHER.txt  read before giving this folder a boot2.flag\n'
            printf '\n'
            print_probe_flag_rule
        fi
    } > "$readme_tmp"
    mv "$readme_tmp" "$dist/README.txt"

    # metadata.json: build it with json.dump so description/role may contain
    # quotes, backslashes or newlines and still produce valid JSON.  The result
    # is re-parsed before it replaces the old file.  conflicts_with is always
    # emitted (a list, empty when nothing conflicts) so a consumer never has to
    # distinguish "key absent" from "no conflicts".
    meta_tmp="$dist/metadata.json.tmp"
    $PY - "$meta_tmp" "$name" "$NXUS_VERSION" "$tid" "$role" "$description" "$built" "$tcp_port" "$boot2" "$conflicts" "$source_rev" "$dirty" <<'PYEOF'
import json
import sys

(out, name, version, tid, role, description, built, tcp_port, boot2,
 conflicts, source_rev, dirty) = sys.argv[1:13]
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
    # Title ids that must not run at the same time as this module.  Both Nxus
    # sysmodules take the single dmnt:cht cheat process, so booting them together
    # makes the loser's results (the probe's verdict) wrong.
    "conflicts_with": ["0x" + other_tid for other_tid in conflicts.split()],
    "repository": "https://github.com/Nexy451z/Nxus-ox",
    "built_utc": built,
    # Build identifier (additive keys, see README "Version & Compatibility
    # Matrix"): same UTC stamp as built_utc under its documented name, the short
    # commit this folder was built from ("unknown" when git is unavailable) and
    # whether the working tree was dirty at build time.  built_utc is kept
    # unchanged so existing consumers keep working.
    "build_utc": built,
    "source_rev": source_rev,
    "dirty": dirty == "true",
    "warranty": "none - alpha software, use on emuMMC with a backup",
}
with open(out, "w", encoding="utf-8", newline="\n") as f:
    json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
    f.write("\n")
PYEOF
    $PY -c 'import json, sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$meta_tmp"
    mv "$meta_tmp" "$dist/metadata.json"

    # Coexistence warning for the probe folder.  The probe and the main module
    # both take the single dmnt:cht cheat process, so a probe that is silently
    # enabled next to the main module produces a wrong verdict.  metadata.json
    # carries the machine-readable half (conflicts_with); this file is the human
    # half and only exists in the probe folder.  Written to *.tmp and renamed,
    # same as README.txt.
    if [ "$name" = "probe" ]; then
        warn_tmp="$dist/DO_NOT_BOOT_TOGETHER.txt.tmp"
        {
            cat <<'WARN_EOF'
DO NOT BOOT THIS SYS MODULE TOGETHER WITH THE MAIN NXUS SYSMODULE
=================================================================

This folder is the optional diagnostic probe (title id 0x4200000000004E59).
It opens no TCP port; it appends its verdict to sdmc:/nxus/probe.txt.

WHY
  Both nxus sysmodules take the single dmnt:cht cheat process at boot.  If both
  start, they race for it and the loser gets "already owned" instead of a real
  answer.  The probe then records a verdict that says hardware debugging is
  unavailable, when the only problem was the other module.  The numbers in
  probe.txt are WRONG, not merely missing.

HOW
WARN_EOF
            printf '\n'
            # One procedure, three copies: the same text is in the probe's
            # README.txt (via print_probe_flag_rule) and in README.md.
            print_probe_flag_rule
            cat <<'WARN_EOF'

metadata.json in this folder states the same rule machine-readably:
  "conflicts_with": ["0x4200000000004E58"]
WARN_EOF
            printf '\nGenerated by tools/build.sh from Nxus-ox Alpha v%s at %s\n' \
                "$NXUS_VERSION" "$built"
        } > "$warn_tmp"
        mv "$warn_tmp" "$dist/DO_NOT_BOOT_TOGETHER.txt"
    else
        # A stale copy left over from an earlier probe build must not appear to
        # apply to the main module.
        rm -f "$dist/DO_NOT_BOOT_TOGETHER.txt"
    fi

    # Verify the finished folder LAST: the check inspects README.txt, metadata.json
    # and the boot2.flag rule, none of which exist before the generation above - a
    # clean checkout used to fail its very first build here.
    $PY "$TOOLS/verify_artifact.py" "$dist/exefs.nsp"

    echo
}

# Sysmodule title ids live in the 0x42... range on a real console; 0x0100... is the
# homebrew *application* range and is not started at boot2 (Atmosphère 1.12.1 / FW 23).
# The last argument is the title id each module declares in metadata.json
# "conflicts_with": the two modules fight over one dmnt:cht cheat process.
build_target switch 4200000000004E58 nxus \
    "memory scanner / pointer finder / hardware debugger (sysmodule)" \
    "Nxus-ox main sysmodule: headless remote memory scanner, pointer chain finder and hardware watchpoint/breakpoint debugger for Nintendo Switch (Atmosphère). No on-screen UI; the PC client nxus.exe connects over TCP port 7332." \
    7332 1 4200000000004E59
build_target probe  4200000000004E59 probe \
    "hardware diagnostic probe (sysmodule, optional - does NOT listen on port 7332)" \
    "Nxus-ox diagnostic probe: answers the hardware bring-up questions (can a custom sysmodule obtain debug privileges, are hardware breakpoints per-core, which debug control words the kernel accepts) and writes the verdict to sdmc:/nxus/probe.txt. It never opens a TCP port and must not run at the same time as the main nxus sysmodule (0x4200000000004E58), because both would try to own a debug handle." \
    0 0 4200000000004E58

echo "== dist tree =="
find "$NXUS_ROOT/dist" -type f | sed "s|$NXUS_ROOT/||"
