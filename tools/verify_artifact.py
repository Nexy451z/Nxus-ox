#!/usr/bin/env python3
"""Verify a built Nxus exefs.nsp: layout, NSO sanity and the debug capabilities."""
import struct
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0])
import pfs0_tool

TID = '4200000000004E58'


def check(nsp_path, verbose=True):
    files = pfs0_tool.read(nsp_path)
    ok = True

    def report(good, msg):
        nonlocal ok
        if not good:
            ok = False
        print(('  OK   ' if good else '  FAIL ') + msg)

    report('main' in files, "exefs contains 'main'")
    report('main.npdm' in files, "exefs contains 'main.npdm'")

    main = files.get('main', b'')
    report(main[0:4] == b'NSO0', f"main is an NSO (magic {main[0:4]!r})")

    npdm = files.get('main.npdm', b'')
    report(npdm[0:4] == b'META', f"npdm magic {npdm[0:4]!r}")
    if npdm[0:4] == b'META':
        for magic, rel in ((b'ACID', 0xA0), (b'ACI0', 0x90)):
            i = npdm.find(magic)
            if i < 0:
                report(False, f"{magic.decode()} section present")
                continue
            flags = npdm[i + rel + 6]
            # Atmosphère's loader accepts AT MOST ONE debug bit (popcount <= 1); two or
            # more make it drop the program silently, even for boot2 sysmodules.
            bits = flags & 0x0E
            report(bin(bits).count("1") == 1,
                   f"{magic.decode()} debug flags = 0x{flags:02X} "
                   f"(EnableDebug={bool(flags & 2)}, ForceDebugProd={bool(flags & 4)}, ForceDebug={bool(flags & 8)})"
                   f"{'' if bin(bits).count('1') == 1 else ' <- must be exactly ONE bit'}")

    total = sum(len(v) for v in files.values())
    if verbose:
        print(f"  size: {len(open(nsp_path,'rb').read())} bytes, payload {total} bytes")
    return ok


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else rf'C:\anyWorkspace\nx\Nxus\dist\atmosphere\contents\{TID}\exefs.nsp'
    print(f"verifying {path}")
    sys.exit(0 if check(path) else 1)
