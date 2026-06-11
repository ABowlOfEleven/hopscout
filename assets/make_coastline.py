"""Convert a coastline GeoJSON (LineString/MultiLineString) into a compact
binary of little-endian f32 (lon, lat) pairs, with a NaN/NaN pair separating
polylines. One-off asset generator; the result (coastline.bin) is committed."""
import json, struct, sys

src = sys.argv[1] if len(sys.argv) > 1 else "coast.json"
dst = sys.argv[2] if len(sys.argv) > 2 else "coastline.bin"

d = json.load(open(src))
out = bytearray()
NAN = struct.pack("<f", float("nan"))


def emit(coords):
    for lon, lat in coords:
        out.extend(struct.pack("<ff", float(lon), float(lat)))
    out.extend(NAN)
    out.extend(NAN)


n = 0
for f in d["features"]:
    g = f["geometry"]
    t = g["type"]
    if t == "LineString":
        emit(g["coordinates"]); n += 1
    elif t == "MultiLineString":
        for line in g["coordinates"]:
            emit(line); n += 1

open(dst, "wb").write(out)
print(f"wrote {len(out)} bytes, {n} polylines")
