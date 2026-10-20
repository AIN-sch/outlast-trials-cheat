#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""校验构建产物：PE 架构、节表、数据目录、嵌入资源、提权清单。"""
import os
import struct
import sys

HERE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin"))
MACHINE = {0x8664: "x86-64", 0x14C: "x86", 0xAA64: "ARM64"}
SUBSYS = {2: "GUI", 3: "CONSOLE"}
DIR_NAMES = ["export", "import", "resource", "exception", "security", "basereloc",
             "debug", "arch", "globalptr", "tls", "loadcfg", "boundimport",
             "iat", "delayimport", "clr", "reserved"]
RT_MANIFEST = 24


def parse(path):
    with open(path, "rb") as f:
        data = f.read()
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    machine, nsec = struct.unpack_from("<HH", data, lfanew + 4)
    opt = lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = (magic == 0x20B)
    subsys = struct.unpack_from("<H", data, opt + 68)[0]
    numdir = struct.unpack_from("<I", data, opt + (108 if is64 else 92))[0]
    dd_base = opt + (112 if is64 else 96)
    dirs = []
    for i in range(min(numdir, 16)):
        rva, size = struct.unpack_from("<II", data, dd_base + i * 8)
        dirs.append((DIR_NAMES[i] if i < len(DIR_NAMES) else str(i), rva, size))

    sections = []
    sec_off = opt + struct.unpack_from("<H", data, lfanew + 20)[0]
    for i in range(nsec):
        off = sec_off + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append((name, vaddr, vsize, rawptr, rawsize))

    return {
        "data": data, "size": len(data),
        "machine": MACHINE.get(machine, hex(machine)),
        "is64": is64, "subsys": SUBSYS.get(subsys, subsys),
        "numdir": numdir, "dirs": dirs, "sections": sections,
    }


def rva_to_off(sections, rva):
    for _name, vaddr, vsize, rawptr, rawsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawptr + (rva - vaddr)
    return None


def walk_rsrc(data, sections, base, offset, depth, trail, found):
    """Walk the resource directory tree collecting (trail, data_rva, data_size)."""
    try:
        named, ids = struct.unpack_from("<HH", data, base + offset + 12)
        total = named + ids
        for i in range(total):
            ent = base + offset + 16 + i * 8
            name_val, off_val = struct.unpack_from("<II", data, ent)
            if name_val & 0x80000000:
                key = "str@0x%X" % (name_val & 0x7FFFFFFF)
            else:
                key = name_val
            sub = off_val & 0x7FFFFFFF
            if off_val & 0x80000000:
                walk_rsrc(data, sections, base, sub, depth + 1, trail + [key], found)
            else:
                data_off, data_size = struct.unpack_from("<II", data, base + sub)
                found.append((trail + [key], data_off, data_size))
    except struct.error:
        pass


def find_manifest(p):
    rsrc = None
    for dname, rva, size in p["dirs"]:
        if dname == "resource" and rva and size:
            rsrc = rva
    if not rsrc:
        return None

    base = rva_to_off(p["sections"], rsrc)
    if base is None:
        return None

    found = []
    walk_rsrc(p["data"], p["sections"], base, 0, 0, [], found)

    for trail, data_rva, data_size in found:
        if len(trail) >= 1 and trail[0] == RT_MANIFEST:
            off = rva_to_off(p["sections"], data_rva)
            if off is None:
                continue
            return (trail, p["data"][off:off + data_size])

    # also report what resource types exist, to make a missing manifest obvious
    types = sorted(set(t[0] for t, _r, _s in found))
    return ("TYPES", types)


def main():
    for name in ("EACLoader.exe", "EACPayload.dll"):
        path = os.path.join(HERE, name)
        if not os.path.isfile(path):
            print("%s: MISSING" % name)
            continue
        p = parse(path)
        print("=== %s (%d bytes)" % (name, p["size"]))
        print("    arch=%s fmt=%s subsys=%s dirs=%d"
              % (p["machine"], "PE32+" if p["is64"] else "PE32", p["subsys"], p["numdir"]))
        rsrc = None
        for dname, rva, size in p["dirs"]:
            if size:
                print("    dir[%-12s] rva=0x%-8X size=0x%X" % (dname, rva, size))
            if dname == "resource":
                rsrc = (rva, size)
        sec = [s for s in p["sections"] if s[0] == ".rsrc"]
        if sec:
            s = sec[0]
            print("    .rsrc section: vaddr=0x%X vsize=0x%X raw=0x%X/0x%X"
                  % (s[1], s[2], s[3], s[4]))
        else:
            print("    .rsrc section: NONE")

        if rsrc and rsrc[0]:
            print("    RESOURCE OK: rva=0x%X size=0x%X" % rsrc)
        else:
            print("    RESOURCE MISSING")

        if name.lower().endswith(".exe"):
            found = find_manifest(p)
            if isinstance(found, tuple) and found and found[0] == "TYPES":
                print("    MANIFEST MISSING, resource types present: %s" % found[1])
            elif found:
                trail, blob = found
                text = blob.decode("utf-8", "replace")
                if "requireAdministrator" in text:
                    level = "requireAdministrator"
                elif "highestAvailable" in text:
                    level = "highestAvailable"
                elif "asInvoker" in text:
                    level = "asInvoker"
                else:
                    level = "unknown"
                print("    MANIFEST OK: trail=%s size=%d level=%s"
                      % (trail, len(blob), level))
                if level == "requireAdministrator":
                    print("    -> explorer will show the UAC shield and prompt on launch")
            else:
                print("    MANIFEST: not found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
