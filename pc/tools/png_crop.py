"""Crop a region of a Nxus screenshot and save it losslessly (for 1:1 review).

Usage: python png_crop.py in.png out.png x y w h [scale]
Only needs the standard library: Nxus writes plain zlib PNGs.
"""
import struct
import sys
import zlib


def read_png(path):
    data = open(path, 'rb').read()
    assert data[:8] == b'\x89PNG\r\n\x1a\n', 'not a PNG'
    pos = 8
    idat = b''
    width = height = 0
    while pos < len(data):
        (length,) = struct.unpack_from('>I', data, pos)
        kind = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        if kind == b'IHDR':
            width, height, depth, color = struct.unpack_from('>IIBB', body, 0)
            assert depth == 8 and color == 6, f'unsupported PNG {depth}/{color}'
        elif kind == b'IDAT':
            idat += body
        pos += 12 + length
    raw = zlib.decompress(idat)
    stride = width * 4
    rows = []
    prev = bytearray(stride)
    at = 0
    for _ in range(height):
        filter_type = raw[at]
        at += 1
        line = bytearray(raw[at:at + stride])
        at += stride
        if filter_type == 1:
            for i in range(4, stride):
                line[i] = (line[i] + line[i - 4]) & 0xFF
        elif filter_type == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif filter_type == 3:
            for i in range(stride):
                left = line[i - 4] if i >= 4 else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif filter_type == 4:
            for i in range(stride):
                a = line[i - 4] if i >= 4 else 0
                b = prev[i]
                c = prev[i - 4] if i >= 4 else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pred) & 0xFF
        rows.append(line)
        prev = line
    return width, height, rows


def write_png(path, width, height, rows):
    raw = b''.join(b'\x00' + bytes(r) for r in rows)

    def chunk(kind, body):
        return (struct.pack('>I', len(body)) + kind + body
                + struct.pack('>I', zlib.crc32(kind + body) & 0xFFFFFFFF))

    header = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    out = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header)
           + chunk(b'IDAT', zlib.compress(raw, 6)) + chunk(b'IEND', b''))
    open(path, 'wb').write(out)


def main():
    src, dst, x, y, w, h = sys.argv[1], sys.argv[2], *[int(v) for v in sys.argv[3:7]]
    scale = int(sys.argv[7]) if len(sys.argv) > 7 else 1
    width, height, rows = read_png(src)
    x2, y2 = min(x + w, width), min(y + h, height)
    crop = []
    for row in rows[y:y2]:
        line = row[x * 4:x2 * 4]
        if scale > 1:
            big = bytearray()
            for i in range(0, len(line), 4):
                big += line[i:i + 4] * scale
            line = big
        for _ in range(scale):
            crop.append(line)
    write_png(dst, (x2 - x) * scale, len(crop), crop)
    print(f'cropped {x2 - x}x{len(crop)} -> {dst}')


if __name__ == '__main__':
    main()
