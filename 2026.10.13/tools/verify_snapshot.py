#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Check the index formula against a saved snapshot."""
import os
import sys

SNAP = sys.argv[1] if len(sys.argv) > 1 else r"snapshot"
OUT = os.path.join(SNAP, "verdict.txt")
BITS = 16
STRIDE = 2

lines = []


def log(m):
    lines.append(str(m))
    print(m)


# ---- load chunk table ----
ptrs = []
with open(os.path.join(SNAP, "chunk_ptrs.txt")) as f:
    for row in f:
        p = row.split()
        if len(p) == 2:
            ptrs.append(int(p[1], 16))
log("chunk ptrs loaded: %d" % len(ptrs))

# ---- load dumped chunk bodies ----
bodies = {}
for i in range(16):
    p = os.path.join(SNAP, "chunk_%02d.bin" % i)
    if os.path.exists(p):
        bodies[i] = open(p, "rb").read()
log("chunk bodies loaded: %s" % sorted(bodies.keys()))


def decode(data, off):
    """Decode an FNameEntry at data[off:]. Returns (name, hdr, entry_size) or None."""
    if off < 0 or off + 2 > len(data):
        return None
    hdr = data[off] | (data[off + 1] << 8)
    ln = hdr >> 6
    wide = hdr & 1
    if ln <= 0 or ln > 0x200:
        return None
    sz = ln * (2 if wide else 1)
    if off + 2 + sz > len(data):
        return None
    raw = data[off + 2:off + 2 + sz]
    try:
        s = raw.decode("utf-16-le" if wide else "latin-1")
    except Exception:
        return None
    if not all(32 <= ord(c) < 127 for c in s):
        return None
    return s, hdr, 2 + sz + ((2 + sz) & 1)


def resolve(idx, bits=BITS):
    chunk_idx = idx >> bits
    in_off = (idx & ((1 << bits) - 1)) * STRIDE
    if chunk_idx not in bodies:
        return None, "chunk%d not dumped" % chunk_idx
    r = decode(bodies[chunk_idx], in_off)
    if not r:
        return None, "chunk%d off 0x%X invalid" % (chunk_idx, in_off)
    return r[0], "chunk%d +0x%X hdr=0x%04X" % (chunk_idx, in_off, r[1])


# ---- ground truth: entry sequence of chunk 0 ----
log("\n=== chunk[0] entry sequence (ground truth) ===")
off = 0
seq = {}
for i in range(24):
    r = decode(bodies[0], off)
    if not r:
        log("  stopped at offset 0x%X" % off)
        break
    seq[off] = r[0]
    log("  idx=%-5d off=0x%04X hdr=0x%04X  %r" % (off // 2, off, r[1], r[0]))
    off += r[2]

# ---- objects ----
log("\n=== object names via stride formula ===")
rows = []
with open(os.path.join(SNAP, "object_items.txt")) as f:
    for row in f:
        p = row.split()
        if len(p) >= 4:
            rows.append((int(p[0]), int(p[1], 16), int(p[2], 16), int(p[3], 16), int(p[4], 16) if len(p) > 4 and p[4] != "-" else None))

log("objects loaded: %d" % len(rows))

ok_name = 0
ok_class = 0
total = 0
name_counter = {}
class_counter = {}
samples = []
for oi, obj, ni, cp, ci in rows:
    total += 1
    n, nd = resolve(ni)
    c, cd = None, "n/a"
    if ci is not None:
        c, cd = resolve(ci)
    if n:
        ok_name += 1
        name_counter[n] = name_counter.get(n, 0) + 1
    if c:
        ok_class += 1
        class_counter[c] = class_counter.get(c, 0) + 1
    if oi < 30:
        samples.append("  item[%-3d] name=%-42r %-22s class=%r" % (oi, n, "[" + nd + "]", c))

log("\n".join(samples))
log("\n--- stats ---")
log("objects: %d" % total)
log("name resolved OK : %d (%.1f%%)" % (ok_name, 100.0 * ok_name / max(total, 1)))
log("class resolved OK: %d (%.1f%%)" % (ok_class, 100.0 * ok_class / max(total, 1)))
log("\ntop class names: %s" % sorted(class_counter.items(), key=lambda x: -x[1])[:12])
log("\nsample object names: %s" % sorted(name_counter.items(), key=lambda x: -x[1])[:12])

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
print("\nverdict -> %s" % OUT)
