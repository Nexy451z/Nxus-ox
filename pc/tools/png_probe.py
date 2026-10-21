"""Print an ASCII luminance map of a region, to inspect text rendering objectively."""
import sys
sys.path.insert(0, __import__('os').path.dirname(__file__))
from png_crop import read_png

path, x, y, w, h = sys.argv[1], *[int(v) for v in sys.argv[2:6]]
width, height, rows = read_png(path)
print(f"image {width}x{height}, region ({x},{y}) {w}x{h}")
chars = " .:-=+*#%@"
for row in rows[y:y + h]:
    line = ""
    for col in range(x, x + w):
        r, g, b = row[col * 4], row[col * 4 + 1], row[col * 4 + 2]
        lum = (r * 299 + g * 587 + b * 114) // 1000
        line += chars[min(9, lum * 10 // 256)]
    print(line)

# distinct colours in the region
counts = {}
for row in rows[y:y + h]:
    for col in range(x, x + w):
        key = (row[col * 4], row[col * 4 + 1], row[col * 4 + 2])
        counts[key] = counts.get(key, 0) + 1
top = sorted(counts.items(), key=lambda kv: -kv[1])[:8]
print("most common colours (r,g,b):", [(c, n) for c, n in top])
