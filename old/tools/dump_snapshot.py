#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Save a slice of the name pool and GObjects to disk."""
import ctypes
import ctypes.wintypes as wt
import os
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.ReadProcessMemory.restype = wt.BOOL
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_char_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
psapi.EnumProcessModulesEx.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_void_p), wt.DWORD,
                                       ctypes.POINTER(wt.DWORD), wt.DWORD]
psapi.EnumProcessModulesEx.restype = wt.BOOL
psapi.GetModuleBaseNameW.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.LPWSTR, wt.DWORD]
psapi.GetModuleBaseNameW.restype = wt.DWORD

OUT = sys.argv[1] if len(sys.argv) > 1 else r"snapshot"
GNAMES_RVA = 0x6EB2C00
GOBJECTS_RVA = 0x6F21838
CHUNK_DUMP_BYTES = 0x20000   # 128 KB per block

os.makedirs(OUT, exist_ok=True)
info = []


def log(m):
    info.append(str(m))
    print(m)


# ---- find process ----
pid = 0
arr = (wt.DWORD * 8192)()
need = wt.DWORD(0)
psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(need))
for i in range(need.value // ctypes.sizeof(wt.DWORD)):
    if not arr[i]:
        continue
    hh = k32.OpenProcess(0x1000, False, arr[i])
    if not hh:
        continue
    buf = ctypes.create_unicode_buffer(520)
    sz = wt.DWORD(520)
    ok = k32.QueryFullProcessImageNameW(hh, 0, buf, ctypes.byref(sz))
    k32.CloseHandle(hh)
    if ok and buf.value.lower().endswith("totclient-win64-shipping.exe"):
        pid = arr[i]
        log("pid=%d path=%s" % (pid, buf.value))
        break

if not pid:
    log("process not found")
    sys.exit(1)

h = k32.OpenProcess(0x1F0FFF, False, pid)
if not h:
    log("OpenProcess failed err=%d" % ctypes.get_last_error())
    sys.exit(2)


def rd(addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, ctypes.c_size_t(size),
                             ctypes.byref(got)):
        return buf.raw[:got.value]
    return None


def u32(a):
    d = rd(a, 4)
    return int.from_bytes(d, "little") if d and len(d) == 4 else None


def u64(a):
    d = rd(a, 8)
    return int.from_bytes(d, "little") if d and len(d) == 8 else None


# ---- module base ----
base = 0
mods = (ctypes.c_void_p * 4096)()
need = wt.DWORD(0)
if psapi.EnumProcessModulesEx(h, mods, ctypes.sizeof(mods), ctypes.byref(need), 0x03):
    for i in range(need.value // ctypes.sizeof(wt.HMODULE)):
        nb = ctypes.create_unicode_buffer(520)
        if psapi.GetModuleBaseNameW(h, mods[i], nb, 520):
            if nb.value.lower() == "totclient-win64-shipping.exe":
                base = ctypes.cast(mods[i], ctypes.c_void_p).value
                break
log("module_base=0x%X" % base)
if not base:
    log("module base not resolved")
    sys.exit(3)

pool = base + GNAMES_RVA
gobj = base + GOBJECTS_RVA
log("pool=0x%X gobjects=0x%X" % (pool, gobj))

# ---- 1. pool header ----
hdr = rd(pool, 0x200)
if hdr:
    open(os.path.join(OUT, "pool_header.bin"), "wb").write(hdr)
    log("pool_header.bin 0x200 bytes: %s" % hdr[:64].hex())

maxchunk = u32(pool + 0x8)
bytecursor = u32(pool + 0xC)
log("MaxChunkIndex=%s (0x%X)  ByteCursor=%s (0x%X)" % (maxchunk, maxchunk or 0, bytecursor, bytecursor or 0))

# ---- 2. chunk pointer table ----
nchunks = (maxchunk + 1) if maxchunk else 0
tbl = rd(pool + 0x10, max(nchunks * 8, 8))
if tbl:
    open(os.path.join(OUT, "chunk_table.bin"), "wb").write(tbl)
    log("chunk_table.bin %d bytes (%d entries)" % (len(tbl), len(tbl) // 8))

chunks = []
for i in range(nchunks):
    v = u64(pool + 0x10 + i * 8)
    if v:
        chunks.append(v)
log("valid chunk ptrs = %d" % len(chunks))
gaps = [chunks[i + 1] - chunks[i] for i in range(min(len(chunks) - 1, 12))]
log("first chunk gaps: %s" % [hex(x) for x in gaps])
if len(chunks) > 2:
    s = sorted(set(chunks[i + 1] - chunks[i] for i in range(len(chunks) - 1)))
    log("distinct gaps (all): %s" % [hex(x) for x in s[:12]])

with open(os.path.join(OUT, "chunk_ptrs.txt"), "w") as f:
    for i, c in enumerate(chunks):
        f.write("%d 0x%X\n" % (i, c))

# ---- 3. dump first N chunks ----
for i in range(min(6, len(chunks))):
    d = rd(chunks[i], CHUNK_DUMP_BYTES)
    if d:
        p = os.path.join(OUT, "chunk_%02d.bin" % i)
        open(p, "wb").write(d)
        log("chunk_%02d.bin %d bytes from 0x%X  head=%s" % (i, len(d), chunks[i], d[:32].hex()))

# ---- 4. GObjects header + object items ----
gh = rd(gobj, 0x200)
if gh:
    open(os.path.join(OUT, "gobjects_header.bin"), "wb").write(gh)
    log("gobjects_header.bin 0x200 bytes: %s" % gh[:48].hex())

objs_ptr = u64(gobj + 0x00)
log("Objects pointer = 0x%X" % (objs_ptr or 0))
if objs_ptr:
    oc0 = u64(objs_ptr)
    log("object chunk[0] = 0x%X" % (oc0 or 0))
    if oc0:
        raw = rd(oc0, 0x18 * 512)
        if raw:
            open(os.path.join(OUT, "object_chunk0.bin"), "wb").write(raw)
            log("object_chunk0.bin %d bytes (512 items)" % len(raw))
        items = []
        for oi in range(512):
            item = u64(oc0 + oi * 0x18)
            if not item:
                continue
            ni = u32(item + 0x18)
            cp = u64(item + 0x10)
            ci = u32(cp + 0x18) if cp else None
            items.append((oi, item, ni, cp, ci))
        with open(os.path.join(OUT, "object_items.txt"), "w") as f:
            for oi, item, ni, cp, ci in items:
                f.write("%d 0x%X 0x%s 0x%X %s\n" % (oi, item, format(ni, 'X') if ni is not None else "-",
                                                    cp or 0, ("0x%X" % ci) if ci is not None else "-"))
        log("object_items.txt: %d items" % len(items))
        for oi, item, ni, cp, ci in items[:8]:
            log("  item[%d] obj=0x%X name_idx=%s class_idx=%s"
                % (oi, item, ("0x%X" % ni) if ni is not None else "-",
                   ("0x%X" % ci) if ci is not None else "-"))

k32.CloseHandle(h)
with open(os.path.join(OUT, "info.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(info))
log("snapshot written to %s" % OUT)
