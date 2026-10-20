#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Grab FNamePool fields and indices from a live process."""
import ctypes
import ctypes.wintypes as wt
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03

GNAMES_RVA = 0x6EB2C00
POOL_MAXCHUNK_OFF = 0x8
POOL_BYTECURSOR_OFF = 0xC
POOL_ENTRIES_OFF = 0x10

proc_name = sys.argv[1] if len(sys.argv) > 1 else "TOTClient-Win64-Shipping.exe"
out_path = sys.argv[2] if len(sys.argv) > 2 else "probe_all.txt"

_lines = []


def log(msg):
    _lines.append(str(msg))


def footer():
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(_lines))


def find_pid(name):
    arr = (wt.DWORD * 4096)()
    needed = wt.DWORD(0)
    if not psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(needed)):
        return None
    cnt = needed.value // ctypes.sizeof(wt.DWORD)
    for i in range(cnt):
        pid = arr[i]
        if pid == 0:
            continue
        h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            continue
        buf = ctypes.create_unicode_buffer(260)
        size = wt.DWORD(260)
        ok = k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))
        k32.CloseHandle(h)
        if ok and buf.value.lower().endswith(name.lower()):
            return pid, buf.value
    return None, None


def module_base(pid, exe_name):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return None, k32.GetLastError()
    mods = (wt.HMODULE * 1024)()
    needed = wt.DWORD(0)
    if not psapi.EnumProcessModulesEx(h, ctypes.byref(mods), ctypes.sizeof(mods),
                                      ctypes.byref(needed), LIST_MODULES_ALL):
        err = k32.GetLastError()
        k32.CloseHandle(h)
        return None, err
    cnt = needed.value // ctypes.sizeof(wt.HMODULE)
    result = None
    for i in range(cnt):
        m = mods[i]
        nbuf = ctypes.create_unicode_buffer(260)
        if psapi.GetModuleBaseNameW(h, m, nbuf, 260):
            if nbuf.value.lower() == exe_name.lower():
                result = ctypes.cast(m, ctypes.c_void_p).value
                break
    k32.CloseHandle(h)
    return result, 0


class Mem:
    def __init__(self, pid):
        self.h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

    def ok(self):
        return bool(self.h)

    def read(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf,
                                 ctypes.c_size_t(size), ctypes.byref(got)):
            return buf.raw[:got.value]
        return None

    def u16(self, a):
        d = self.read(a, 2)
        return int.from_bytes(d, "little") if d and len(d) == 2 else None

    def u32(self, a):
        d = self.read(a, 4)
        return int.from_bytes(d, "little") if d and len(d) == 4 else None

    def u64(self, a):
        d = self.read(a, 8)
        return int.from_bytes(d, "little") if d and len(d) == 8 else None

    def close(self):
        if self.h:
            k32.CloseHandle(self.h)


def main():
    pid, path = find_pid(proc_name)
    if not pid:
        log("process not found: %s" % proc_name)
        footer()
        return 1
    log("pid=%d  path=%s" % (pid, path))

    base, err = module_base(pid, proc_name)
    if not base:
        log("module base not found (err=%d)" % err)
        footer()
        return 2
    log("module base = 0x%X" % base)

    mem = Mem(pid)
    if not mem.ok():
        log("OpenProcess failed err=%d" % k32.GetLastError())
        footer()
        return 3

    pool = base + GNAMES_RVA
    log("FNamePool = 0x%X" % pool)

    maxchunk = mem.u32(pool + POOL_MAXCHUNK_OFF)
    bytecursor = mem.u32(pool + POOL_BYTECURSOR_OFF)
    log("MaxChunkIndex = %s (0x%X)" % (maxchunk, maxchunk or 0))
    log("ByteCursor    = %s (0x%X)" % (bytecursor, bytecursor or 0))

    chunks = []
    for i in range(0, 0x4000 // 8):
        v = mem.u64(pool + POOL_ENTRIES_OFF + i * 8)
        if not v:
            break
        chunks.append(v)
    n = maxchunk + 1 if maxchunk else 0
    log("chunk pointers found = %d (expected MaxChunkIndex+1 = %d)" % (len(chunks), n))
    if chunks:
        log("chunk[0] = 0x%X   chunk[1] = 0x%X" % (chunks[0], chunks[1] if len(chunks) > 1 else 0))

    def header_at(a):
        h = mem.u16(a)
        if h is None:
            return None, None, None
        ln = h >> 11
        wide = (h >> 10) & 1
        return h, ln, wide

    def name_at(a):
        h, ln, wide = header_at(a)
        if h is None or ln <= 0 or ln > 0x400:
            return None
        raw = mem.read(a + 2, ln * (2 if wide else 1))
        if not raw:
            return None
        return raw.decode("utf-16-le" if wide else "latin-1", "replace")

    def walk(chunk, idx):
        cur = chunk
        for _ in range(idx):
            h, ln, wide = header_at(cur)
            if h is None or ln <= 0 or ln > 0x400:
                return None
            cur += 2 + ln * (2 if wide else 1)
        return cur

    log("\n--- chunk[0] header dump (first 64 bytes) ---")
    head = mem.read(chunks[0], 64) if chunks else None
    if head:
        log(head.hex())

    log("\n--- linear WALK (header-length stepping) ---")
    for idx in range(24):
        a = walk(chunks[0], idx) if chunks else None
        log("  idx=%2d @ %s = %r" % (idx, ("0x%X" % a) if a else "FAIL", name_at(a) if a else None))

    log("\n--- Dumper-7 stride formula (chunk + idx*2) ---")
    if chunks:
        for idx in range(24):
            a = chunks[0] + idx * 2
            log("  idx=%2d @ %#x = %r" % (idx, a, name_at(a)))

    log("\n--- cross-chunk: linear walk of chunk[1] start ---")
    if len(chunks) > 1:
        a = chunks[1]
        log("  chunk[1]+0 = %r" % name_at(a))

    mem.close()
    footer()
    return 0


if __name__ == "__main__":
    sys.exit(main())