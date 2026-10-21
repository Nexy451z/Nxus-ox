#!/usr/bin/env python3
"""Force the debug capabilities into a built NPDM.

Why this exists
---------------
npdmtool accepts only ONE of allow_debug / force_debug / force_debug_prod, but a
retail console generally needs the "force" bit on top of EnableDebug for
svcDebugActiveProcess to be allowed.  The three bits live in the same
kernel-capability flag byte, which appears twice in the NPDM (once in ACID, once
in ACI0).

Bit mapping was determined empirically by building the same NPDM four times and
diffing (tools/npdm_flag_probe.ps1), cross-checked against the switchbrew NPDM
page:

    allow_debug      -> MiscFlags bit 17  (EnableDebug)
    force_debug_prod -> MiscFlags bit 18  (ForceDebugProd on 19.0.0+, ForceDebug before)
    force_debug      -> MiscFlags bit 19  (ForceDebug on 19.0.0+)

Usage:
    python npdm_debug_patch.py path/to/main.npdm
"""
import sys

# ONLY ONE bit may be set: Atmosphère's loader validates the DebugFlags capability with
# "popcount <= 1" (stratosphere/loader/source/ldr_capabilities.cpp) and silently drops a
# boot2 program whose NPDM fails that check.  force_debug alone is what a working
# sysmodule on this console uses, and it is the bit that lets us debug other processes.
DEBUG_BITS = 0x08                        # ForceDebug (bit 19 of the misc flags)
SECTIONS = ((b'ACID', 0xA0), (b'ACI0', 0x90))
FLAGS_BYTE_IN_WORD = 6                   # byte 2 of the flags word holds bits 16-23


def patch(path):
    data = bytearray(open(path, 'rb').read())
    if data[0:4] != b'META':
        raise SystemExit(f"{path}: not an NPDM (missing META magic)")
    report = []
    for magic, rel in SECTIONS:
        i = data.find(magic)
        if i < 0:
            raise SystemExit(f"{path}: section {magic!r} not found")
        off = i + rel + FLAGS_BYTE_IN_WORD
        before = data[off]
        if before & ~0x0F:
            raise SystemExit(f"{path}: unexpected flag byte 0x{before:02X} at {off:#x}")
        # clear the three bits first: make may reuse a previously patched .npdm, and a
        # plain OR then keeps 2+ bits set (which the loader rejects outright)
        data[off] = (before & ~0x0E) | DEBUG_BITS
        report.append((magic.decode(), hex(off), hex(before), hex(data[off])))
    open(path, 'wb').write(bytes(data))
    return report


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    for section, off, before, after in patch(sys.argv[1]):
        print(f"  {section}: flags byte at {off}: {before} -> {after}")
    print("NPDM debug capabilities forced on (bits 17|18|19)")
