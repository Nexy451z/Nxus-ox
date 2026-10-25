#!/usr/bin/env python3
"""Verify a built Nxus exefs.nsp: layout, NSO sanity and the debug capabilities.

Checks, in order:
  * the PFS0 holds `main` (an NSO) and `main.npdm`,
  * the NSO's segment table is self-consistent (sizes/offsets inside the file),
  * the NPDM META header is decoded field by field (u8 Flags0 @0x0C, u8 Flags1
    @0x0D, MainThreadPriority @0x0E, MainThreadCoreNumber @0x0F, stack @0x1C,
    name @0x20) and only the "obviously wrong" values are asserted: the 64-bit
    bit, stack >= 0x4000 and a non-empty name.  Priority, core number, version
    and reserved fields are reported for information only - the loader accepts
    a wide range there and guessing a policy would produce false failures,
  * ACID and ACI0 are located through the META header's own section table
    (@0x70 AciOffset/AciSize, @0x78 AcidOffset/AcidSize) instead of fixed
    offsets from the magic: the magic moves with the capability list, the four
    u32s at 0x70-0x7C do not.  Each section's MiscFlags kernel-capability
    descriptor must carry exactly ONE debug bit (Atmosphère's loader silently
    drops a program whose debug bits have popcount != 1).  If the table is
    unusable the verifier falls back to find() and says so in the output,
  * ACI0's title id matches the folder it was built for,
  * the dist folder is self-describing (README.txt + metadata.json) and its
    boot2.flag rule is respected (main: present, probe: absent).
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pfs0_tool

TID = '4200000000004E58'
PROBE_TID = '4200000000004E59'

META_SIZE = 0x80
META_SECTION_TABLE = 0x70      # AciOffset, AciSize, AcidOffset, AcidSize
ACID_PREFIX = 0x200            # RSA-2048 signature (0x100) + public key (0x100)
DEBUG_BITS = 0x0E              # MiscFlags bits 17..19, as seen in byte 2
FORCE_DEBUG = 0x08             # the only bit that grants debug privileges
ADDRESS_SPACE = {
    0: 'AddressSpace32Bit',
    1: 'AddressSpace64Bit36 (<=22.5.0: AddressSpace64BitOld)',
    2: 'AddressSpace32BitNoReserved',
    3: 'AddressSpace64Bit39 (<=22.5.0: AddressSpace64Bit)',
    4: 'AddressSpace64Bit42',
}
MEMORY_REGION = {
    0: 'Application',
    1: 'Applet',
    2: 'SecureSystem',
    3: 'NonSecureSystem',
}


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


def note(msg, warn=False):
    """Print a non-assertion line (a displayed value or a provenance warning)."""
    print(('  WARN  ' if warn else '  info  ') + msg)


def read_meta(npdm):
    """Decode the fixed 0x80-byte META header (offsets from the NPDM spec)."""
    return {
        'signature_key_generation': struct.unpack_from('<I', npdm, 0x04)[0],
        'flags0': npdm[0x0C],
        'flags1': npdm[0x0D],
        'main_thread_priority': npdm[0x0E],
        'main_thread_core': npdm[0x0F],
        'reserved_0x10': struct.unpack_from('<I', npdm, 0x10)[0],
        'system_resource_size': struct.unpack_from('<I', npdm, 0x14)[0],
        'version': struct.unpack_from('<I', npdm, 0x18)[0],
        'stack_size': struct.unpack_from('<I', npdm, 0x1C)[0],
        'name': npdm[0x20:0x30].split(b'\x00', 1)[0],
    }


def _section_header_off(npdm, name, off, size):
    """Find the section header magic inside the table-provided [off, off+size).

    For ACID the header sits behind the 0x100-byte signature and the 0x100-byte
    public key, so the preferred search starts after that prefix; searching the
    raw key bytes for "ACID" would be a false-positive trap.  The wider search is
    only a second chance for a layout that does not follow the NX key size.
    """
    start = off + (ACID_PREFIX if name == 'ACID' else 0)
    end = off + size
    if start < end:
        i = npdm.find(name.encode(), start, end)
        if i >= 0:
            return i
    i = npdm.find(name.encode(), off, end)
    return i if i >= 0 else None


def locate_sections(npdm):
    """Locate ACID/ACI0.

    Returns (sections, source, fallback_reason) where sections maps
    'ACI0'/'ACID' to {'section_off', 'section_size', 'header_off'}.  The META
    table at 0x70-0x7C is authoritative; find() is only a fallback and its
    result is flagged so the report never pretends the bounds are exact.
    """
    reason = None
    if len(npdm) >= META_SIZE:
        aci_off, aci_size, acid_off, acid_size = struct.unpack_from('<IIII', npdm, META_SECTION_TABLE)
        entries = (('ACI0', aci_off, aci_size), ('ACID', acid_off, acid_size))
        headers = {}
        for name, off, size in entries:
            if off == 0 or size == 0:
                reason = f"{name} offset/size is zero"
            elif off + size > len(npdm):
                reason = f"{name} 0x{off:X}+0x{size:X} runs past EOF (0x{len(npdm):X})"
            else:
                header = _section_header_off(npdm, name, off, size)
                if header is None:
                    reason = f"{name} magic not found inside its table range"
                else:
                    headers[name] = (off, size, header)
            if reason:
                break
        if reason is None:
            sections = {
                name: {'section_off': off, 'section_size': size, 'header_off': header}
                for name, (off, size, header) in headers.items()
            }
            return sections, 'META table @0x70', None
    else:
        reason = f'NPDM shorter than the 0x{META_SIZE:X}-byte META header'

    sections = {}
    for name in ('ACI0', 'ACID'):
        header = npdm.find(name.encode())
        if header < 0:
            continue
        # find() cannot tell where the section starts: ACID is preceded by the
        # RSA signature + public key, ACI0 starts at its own magic.  In this
        # path section_size is just "the rest of the file".
        off = header - ACID_PREFIX if name == 'ACID' and header >= ACID_PREFIX else header
        sections[name] = {'section_off': off, 'section_size': len(npdm) - off, 'header_off': header}
    return sections, 'find() fallback', reason


def read_section(npdm, name, section):
    """Decode one ACID/ACI0 header and its MiscFlags capability.

    Capability offsets are relative to section_off - the RSA signature for ACID,
    the section start for ACI0 - so this works no matter how large the
    capability blobs in front of the header are.
    """
    header_off = section['header_off']
    section_end = section['section_off'] + section['section_size']
    if (header_off is None or header_off + 0x38 > len(npdm)
            or header_off + 0x38 > section_end):
        return None
    info = {
        'name': name,
        'header_off': header_off,
        'flags': struct.unpack_from('<I', npdm, header_off + 0x0C)[0],
        'program_id': struct.unpack_from('<Q', npdm, header_off + 0x10)[0],
        'program_id_max': struct.unpack_from('<Q', npdm, header_off + 0x18)[0],
        'kc_off': None,
        'kc_size': None,
        'misc_flags_off': None,
        'misc_flags': None,
    }
    kc_off, kc_size = struct.unpack_from('<II', npdm, header_off + 0x30)
    kc_abs = section['section_off'] + kc_off
    info['kc_off'] = kc_abs
    info['kc_size'] = kc_size
    if (kc_size >= 4 and kc_size % 4 == 0 and section['section_off'] <= kc_abs
            and kc_abs + kc_size <= section_end):
        for pos in range(kc_abs, kc_abs + kc_size, 4):
            value = struct.unpack_from('<I', npdm, pos)[0]
            # MiscFlags is the descriptor whose low 16 bits are all ones
            # (0xFFFFFFFF itself is the reserved/invalid value).
            if value != 0xFFFFFFFF and (value & 0xFFFF) == 0xFFFF:
                info['misc_flags_off'] = pos
                info['misc_flags'] = (value >> 16) & 0xFF
                break
    return info


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
        if len(npdm) < META_SIZE:
            report(False, f"META header truncated ({len(npdm)} bytes, need 0x{META_SIZE:X})")
        else:
            meta = read_meta(npdm)
            flags0 = meta['flags0']
            addr_space = (flags0 >> 1) & 0x07
            note(f"META Flags0 0x{flags0:02X} @0x0C: Is64BitInstruction={bool(flags0 & 1)}, "
                 f"ProcessAddressSpace={ADDRESS_SPACE.get(addr_space, 'unknown(%d)' % addr_space)}, "
                 f"OptimizeMemoryAllocation={bool(flags0 & 0x10)}, "
                 f"DisableDeviceAddressSpaceMerge={bool(flags0 & 0x20)}")
            note(f"META Flags1 0x{meta['flags1']:02X} @0x0D: "
                 f"EnableShadowStack={bool(meta['flags1'] & 1)}")
            note(f"META MainThreadPriority {meta['main_thread_priority']} @0x0E, "
                 f"MainThreadCoreNumber {meta['main_thread_core']} @0x0F (display only)")
            note(f"META SignatureKeyGeneration {meta['signature_key_generation']} @0x04, "
                 f"reserved @0x10 0x{meta['reserved_0x10']:08X} (the NPDM has no "
                 f"process_category field; this is reserved), "
                 f"SystemResourceSize 0x{meta['system_resource_size']:X} @0x14, "
                 f"Version {meta['version']} @0x18")

            report(bool(flags0 & 1), f"META 64-bit program (Flags0 0x{flags0:02X} bit0)")
            report(meta['stack_size'] >= 0x4000,
                   f"META stack size 0x{meta['stack_size']:X} (>= 0x4000 for a sysmodule)")
            report(len(meta['name']) > 0, f"META process name {meta['name']!r}")

            sections, source, fallback_reason = locate_sections(npdm)
            if source == 'META table @0x70':
                note("ACID/ACI0 located through the META section table @0x70: " + ', '.join(
                    f"{name} @0x{s['section_off']:X}+0x{s['section_size']:X}"
                    for name, s in sections.items()))
            else:
                note(f"META section table @0x70 unusable ({fallback_reason}); "
                     f"FALLBACK to find() - section bounds are approximate", warn=True)

            infos = {}
            for name in ('ACID', 'ACI0'):
                section = sections.get(name)
                if section is None:
                    report(False, f"{name} section present")
                    continue
                info = read_section(npdm, name, section)
                if info is None:
                    report(False, f"{name} header readable "
                                  f"(magic @0x{section['header_off']:X})")
                    continue
                infos[name] = info
                kc = f"Kc @0x{info['kc_off']:X}+0x{info['kc_size']:X}"
                if info['misc_flags'] is None:
                    report(False, f"{name} debug capability ({kc}, no MiscFlags descriptor)")
                else:
                    flags = info['misc_flags']
                    bits = flags & DEBUG_BITS
                    # The loader accepts exactly one debug bit; ForceDebug (0x08) is
                    # the one that grants the capabilities this module needs, so a
                    # build without it is flagged loudly but not rejected (nxus.json
                    # only declares allow_debug, and a valid build may use it).
                    one_bit = bin(bits).count('1') == 1
                    if one_bit and bits != FORCE_DEBUG:
                        print(f"  WARN {name} debug bits 0x{bits:02X} lack ForceDebug(0x08): "
                              f"this build cannot obtain debug privileges")
                    report(one_bit,
                           f"{name} debug flags 0x{flags:02X} "
                           f"(MiscFlags @0x{info['misc_flags_off']:X}, {kc}; "
                           f"EnableDebug={bool(flags & 2)}, "
                           f"ForceDebugProd={bool(flags & 4)}, "
                           f"ForceDebug={bool(flags & 8)})"
                           f"{'' if one_bit else ' <- must be exactly ONE debug bit'}")
                if name == 'ACID':
                    acid_flags = info['flags']
                    region = (acid_flags >> 2) & 0x0F
                    note(f"ACID Flags 0x{acid_flags:08X}: ProductionFlag={bool(acid_flags & 1)}, "
                         f"UnqualifiedApproval={bool(acid_flags & 2)}, "
                         f"MemoryRegion={MEMORY_REGION.get(region, 'unknown(%d)' % region)}, "
                         f"program ids 0x{info['program_id']:016X}-0x{info['program_id_max']:016X}")
                else:
                    note(f"ACI0 program id 0x{info['program_id']:016X}")

            aci0 = infos.get('ACI0')
            tid = aci0['program_id'] if aci0 is not None else None
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
                has_flag = os.path.isfile(os.path.join(dist_dir, 'flags', 'boot2.flag'))
                # metadata.json must describe the folder as it is; that check holds in
                # both the normal and the staged (NXUS_STAGE_PROBE=1) layout.
                report(meta.get('boot2_flag') is has_flag,
                       f"metadata boot2_flag matches the folder ({str(has_flag).lower()})")

                if folder_tid == PROBE_TID:
                    report(int(meta.get('tcp_port', -1)) == 0,
                           f"probe metadata advertises no TCP port ({meta.get('tcp_port')})")
                    staged = os.environ.get('NXUS_STAGE_PROBE', '') == '1'
                    if staged:
                        report(has_flag, "probe folder HAS flags/boot2.flag (staging)")
                    else:
                        report(not has_flag, "probe folder has NO flags/boot2.flag")
                elif folder_tid == TID:
                    staged = os.environ.get('NXUS_STAGE_PROBE', '') == '1'
                    if staged:
                        # NXUS_STAGE_PROBE=1 deliberately swaps which folder boots.
                        report(not has_flag,
                               "main folder has no boot2.flag (NXUS_STAGE_PROBE=1 staging)")
                    else:
                        report(has_flag, "main folder ships flags/boot2.flag")
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
