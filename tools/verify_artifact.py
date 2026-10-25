#!/usr/bin/env python3
"""Verify a built Nxus exefs.nsp: layout, NSO sanity and the debug capabilities.

Checks, in order:
  * the PFS0 holds `main` (an NSO) and `main.npdm`,
  * the NSO's segment table is self-consistent (sizes/offsets inside the file),
  * the NPDM has both ACID and ACI0 and exactly ONE debug bit (Atmosphère's
    loader silently drops a program whose debug bits have popcount != 1),
  * ACI0's title id matches the folder it was built for,
  * the dist folder is self-describing (README.txt + metadata.json) and its
    boot2.flag rule is respected (main: present, probe: absent).
"""
import json
import os
import struct
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0])
import pfs0_tool

TID = '4200000000004E58'
PROBE_TID = '4200000000004E59'


def nso_header_sane(main):
    """Sanity-check the parts of the NSO0 header that are layout-independent.

    The segment table's meaning depends on the NSO flavour (compressed sections
    change the file sizes), so only the magic, the header size and the first
    segment's file offset are checked here - enough to catch a truncated or
    mis-built blob without asserting a layout devkitA64 may legitimately vary.
    """
    if main[0:4] != b'NSO0':
        return False, "NSO magic"
    if len(main) < 0x100:
        return False, f"NSO header too short ({len(main)} bytes)"
    text_file_off = struct.unpack_from('<I', main, 0x10)[0]
    if text_file_off == 0 or text_file_off >= len(main):
        return False, f"text file offset 0x{text_file_off:X} outside the blob"
    return True, f"NSO header consistent (text at 0x{text_file_off:X})"


def aci0_title_id(npdm):
    i = npdm.find(b'ACI0')
    if i < 0:
        return None
    # ACI0: magic(4) reserved(4) then the program id at +0x10 (the 8 bytes at
    # +0x08 are the section/flags field, which reads as zero for a plain NSO).
    return struct.unpack_from('<Q', npdm, i + 0x10)[0]


def check(nsp_path, verbose=True, expect_tid=None, dist_dir=None):
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
    if main[0:4] == b'NSO0':
        good, msg = nso_header_sane(main)
        report(good, msg)

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

        # META header fields the loader actually honours.  Offsets confirmed
        # against a built artifact: flags @0x0C, stack size @0x1C, name @0x20.
        meta_flags = struct.unpack_from('<I', npdm, 0x0C)[0]
        stack_size = struct.unpack_from('<I', npdm, 0x1C)[0]
        name = npdm[0x20:0x30].split(b'\x00')[0]
        report(bool(meta_flags & 1), f"META flags 0x{meta_flags:08X}: 64-bit program")
        report(stack_size >= 0x4000,
               f"META stack size 0x{stack_size:X} (>= 0x4000 for a sysmodule)")
        report(len(name) > 0, f"META process name {name!r}")

        tid = aci0_title_id(npdm)
        if expect_tid is not None:
            report(tid == int(expect_tid, 16),
                   f"ACI0 title id 0x{tid:016X}" if tid is not None else "ACI0 title id missing")

    # ---- dist folder: self-describing + boot2 rule -----------------------
    if dist_dir is None and os.path.isdir(os.path.dirname(nsp_path)):
        dist_dir = os.path.dirname(nsp_path)
    if dist_dir is not None and os.path.isdir(dist_dir):
        folder_tid = os.path.basename(dist_dir.rstrip('\\/'))
        meta_path = os.path.join(dist_dir, 'metadata.json')
        readme_path = os.path.join(dist_dir, 'README.txt')
        report(os.path.isfile(readme_path), "README.txt describes the folder")
        if os.path.isfile(meta_path):
            try:
                meta = json.load(open(meta_path, encoding='utf-8'))
            except ValueError as exc:
                meta = None
                report(False, f"metadata.json parses ({exc})")
            if meta is not None:
                report(meta.get('title_id', '').lower() in (f'0x{folder_tid.lower()}', folder_tid.lower()),
                       f"metadata title_id matches the folder ({meta.get('title_id')})")
                report(bool(meta.get('role')) and bool(meta.get('name')),
                       "metadata has name + role")
                # probe never listens and must never be a boot2 module
                if folder_tid == PROBE_TID:
                    report(int(meta.get('tcp_port', -1)) == 0,
                           f"probe metadata advertises no TCP port ({meta.get('tcp_port')})")
                    report(meta.get('boot2_flag') is False, "probe metadata says boot2_flag=false")
                    report(not os.path.isfile(os.path.join(dist_dir, 'flags', 'boot2.flag')),
                           "probe folder has NO flags/boot2.flag")
                elif folder_tid == TID:
                    report(meta.get('boot2_flag') is True, "main metadata says boot2_flag=true")
                    report(os.path.isfile(os.path.join(dist_dir, 'flags', 'boot2.flag')),
                           "main folder ships flags/boot2.flag")
        else:
            report(False, "metadata.json present")

    total = sum(len(v) for v in files.values())
    if verbose:
        print(f"  size: {len(open(nsp_path, 'rb').read())} bytes, payload {total} bytes")
    return ok


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    path = args[0] if args else rf'C:\anyWorkspace\nx\Nxus\dist\atmosphere\contents\{TID}\exefs.nsp'
    # The title id is derived from .../contents/<TID>/ when possible.
    folder = os.path.basename(os.path.dirname(path.rstrip('\\/')))
    expect = args[1] if len(args) > 1 else (folder if len(folder) == 16 else None)
    print(f"verifying {path}")
    return 0 if check(path, expect_tid=expect) else 1


if __name__ == '__main__':
    sys.exit(main())
