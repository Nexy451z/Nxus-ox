import struct, sys

p = sys.argv[1] if len(sys.argv) > 1 else r'C:\anyWorkspace\nx\Nxus\switch\nxus.npdm'
d = open(p, 'rb').read()
print('size', len(d), hex(len(d)))
for magic in (b'META', b'ACID', b'ACI0'):
    off = 0
    while True:
        i = d.find(magic, off)
        if i < 0:
            break
        print(magic.decode(), 'at', hex(i))
        off = i + 1

def dump(base, n=16):
    print(hex(base), d[base:base + n].hex(' '))
    for k in range(0, n, 4):
        print('   +%02X 0x%08X' % (k, struct.unpack_from('<I', d, base + k)[0]))

for base in (0x320, 0x3C0):
    dump(base, 8)
