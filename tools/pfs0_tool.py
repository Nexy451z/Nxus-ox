#!/usr/bin/env python3
"""Minimal PFS0 (ExeFS) reader/writer used to build and verify Nxus artifacts."""
import struct
import sys

MAGIC = b'PFS0'


def read(path):
    """Return {name: bytes} for a PFS0 container."""
    with open(path, 'rb') as f:
        blob = f.read()
    if blob[0:4] != MAGIC:
        raise SystemExit(f"{path}: not a PFS0 file")
    count, strsize, _ = struct.unpack_from('<III', blob, 4)
    entries = []
    for i in range(count):
        off, size, nameoff, _r = struct.unpack_from('<QQII', blob, 0x10 + i * 0x18)
        entries.append((off, size, nameoff))
    strtab = 0x10 + count * 0x18
    data_start = strtab + strsize
    out = {}
    for off, size, nameoff in entries:
        end = blob.index(b'\0', strtab + nameoff)
        name = blob[strtab + nameoff:end].decode()
        out[name] = blob[data_start + off:data_start + off + size]
    return out


def write(path, files):
    """files: list of (name, bytes) in the order they should be stored."""
    names = b''
    offsets = []
    for name, data in files:
        offsets.append((len(names), len(data)))
        names += name.encode() + b'\0'
    count = len(files)
    header = struct.pack('<III', count, len(names), 0)
    data_start = 0
    blob = bytearray()
    blob += MAGIC + header
    running = 0
    for (nameoff, size) in offsets:
        blob += struct.pack('<QQII', running, size, nameoff, 0)
        running += size
    blob += names
    for _name, data in files:
        blob += data
    with open(path, 'wb') as f:
        f.write(bytes(blob))
    return len(blob)


if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == 'list':
        for name, data in read(sys.argv[2]).items():
            print(f"  {name}: {len(data)} bytes")
    elif len(sys.argv) >= 3 and sys.argv[1] == 'extract':
        want = sys.argv[3] if len(sys.argv) > 3 else None
        for name, data in read(sys.argv[2]).items():
            if want is None or name == want:
                sys.stdout.buffer.write(data)
                break
    else:
        raise SystemExit(__doc__)
