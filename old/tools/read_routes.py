#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""See which read routes still work while EAC is running."""
import ctypes
import ctypes.wintypes as wt
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.ReadProcessMemory.restype = wt.BOOL
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_char_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ntdll.NtReadVirtualMemory.restype = ctypes.c_long
ntdll.NtReadVirtualMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ntdll.NtQueryVirtualMemory.restype = ctypes.c_long
ntdll.NtQueryVirtualMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_ulong,
                                       ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_size_t)]

out = sys.argv[1] if len(sys.argv) > 1 else "read_routes.txt"
lines = []


def log(m):
    lines.append(str(m))
    print(m)


# find pid
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

if not pid:
    log("game not found")
    open(out, "w").write("\n".join(lines))
    sys.exit(1)

h = k32.OpenProcess(0x1F0FFF, False, pid)
log("pid=%d  handle=%s" % (pid, "OK" if h else "DENIED"))

# Addresses worth probing: the image range plus a deliberately mapped address.
CANDIDATES = [
    0x7FF600000000, 0x7FF651050000, 0x7FF700000000,
    0x7FF800000000, 0x7FF900000000, 0x140000000, 0x10000,
]

buf = ctypes.create_string_buffer(16)


def try_kernel32(addr):
    got = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, 16, ctypes.byref(got))
    return (ok, got.value, ctypes.get_last_error())


def try_ntdll(addr):
    got = ctypes.c_size_t(0)
    st = ntdll.NtReadVirtualMemory(h, ctypes.c_void_p(addr), buf, 16, ctypes.byref(got))
    return (st & 0xFFFFFFFF, got.value)


log("\n=== route 1: ReadProcessMemory (kernel32) ===")
for a in CANDIDATES:
    ok, got, err = try_kernel32(a)
    log("  0x%012X -> ok=%d got=%d err=%d" % (a, ok, got, err))

log("\n=== route 2: NtReadVirtualMemory (ntdll) ===")
for a in CANDIDATES:
    st, got = try_ntdll(a)
    log("  0x%012X -> status=0x%X got=%d" % (a, st, got))

log("\n=== route 4: NtQueryVirtualMemory (ntdll) ===")


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


mbi = MEMORY_BASIC_INFORMATION()
for a in CANDIDATES:
    st = ntdll.NtQueryVirtualMemory(h, ctypes.c_void_p(a), 0, ctypes.byref(mbi),
                                    ctypes.sizeof(mbi), None)
    log("  0x%012X -> status=0x%X base=0x%X size=0x%X type=%d"
        % (a, st & 0xFFFFFFFF, mbi.BaseAddress or 0, mbi.RegionSize, mbi.Type))

k32.CloseHandle(h)
open(out, "w").write("\n".join(lines))
