#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Check what external access is actually possible."""
import ctypes
import ctypes.wintypes as wt
import sys
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.ReadProcessMemory.restype = wt.BOOL
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_char_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

pid = 0
arr = (wt.DWORD * 4096)()
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
        break

out = sys.argv[1] if len(sys.argv) > 1 else "diag_ext.txt"
lines = []


def log(m):
    lines.append(str(m))
    print(m)


if not pid:
    log("game process not found")
    open(out, "w").write("\n".join(lines))
    sys.exit(1)

log("pid = %d" % pid)

# --- access rights ---
h = k32.OpenProcess(0x1F0FFF, False, pid)
log("OpenProcess(ALL_ACCESS) -> %s" % ("OK" if h else "DENIED err=%d" % ctypes.get_last_error()))
if not h:
    h = k32.OpenProcess(0x0410, False, pid)
    log("OpenProcess(VM_READ|QUERY) -> %s" % ("OK" if h else "DENIED"))
if not h:
    open(out, "w").write("\n".join(lines))
    sys.exit(2)


def rd(addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, ctypes.c_size_t(size), ctypes.byref(got)):
        return buf.raw[:got.value]
    return None


# --- module enumeration ---
try:
    mods = (ctypes.c_void_p * 1024)()
    need = wt.DWORD(0)
    ok = psapi.EnumProcessModulesEx(h, mods, ctypes.sizeof(mods), ctypes.byref(need), 0x03)
    log("EnumProcessModulesEx -> %s err=%d" % (ok, ctypes.get_last_error()))
    if ok:
        nb = ctypes.create_unicode_buffer(260)
        psapi.GetModuleBaseNameW(h, ctypes.c_void_p(mods[0]), nb, 260)
        log("  first module: %s @ 0x%X" % (nb.value, mods[0] or 0))
except Exception as e:
    log("EnumProcessModulesEx exception: %r" % e)

# --- PEB route ---
try:
    class PBI(ctypes.Structure):
        _fields_ = [("Reserved1", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2), ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p)]
    pbi = PBI()
    st = ntdll.NtQueryInformationProcess(wt.HANDLE(h), 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
    log("NtQueryInformationProcess -> status=0x%X peb=0x%X" % (st & 0xFFFFFFFF, pbi.PebBaseAddress or 0))
    if pbi.PebBaseAddress:
        d = rd(pbi.PebBaseAddress + 0x10, 8)
        log("  PEB.ImageBaseAddress = %s" % (("0x%X" % int.from_bytes(d, 'little')) if d else "READ FAILED"))
except Exception as e:
    log("PEB route exception: %r" % e)

# --- brute force scan for the name pool ---
NAME_RVA = 0x6EB2C00
log("\nbrute force scan (step 0x10000):")
t0 = time.time()
found = []
BASE_LO = 0x7FF000000000
BASE_HI = 0x7FFF00000000
STEP = 0x10000
base = BASE_LO
tries = 0
while base < BASE_HI:
    tries += 1
    d = rd(base + NAME_RVA + 0x08, 4)
    if d:
        v = int.from_bytes(d, 'little')
        if 0 < v < 4096:
            found.append((base, v))
            log("  HIT base=0x%X maxChunk=%d" % (base, v))
            if len(found) >= 4:
                break
    base += STEP
elapsed = time.time() - t0
log("  scanned %d candidates in %.2fs, hits=%d" % (tries, elapsed, len(found)))

if found:
    b = found[0][0]
    log("\nverify at 0x%X:" % b)
    d = rd(b + 0x08, 8)
    log("  [base+0x08] = %s" % (d.hex() if d else "fail"))
    d = rd(b + NAME_RVA, 16)
    log("  [base+0x6EB2C00] = %s" % (d.hex() if d else "fail"))
    d = rd(b + 0x6F21838, 16)
    log("  [base+0x6F21838] (GObjects) = %s" % (d.hex() if d else "fail"))

k32.CloseHandle(h)
open(out, "w").write("\n".join(lines))
