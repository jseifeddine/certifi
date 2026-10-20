#!/usr/bin/env python3
"""Print the DLLs a Windows PE executable imports, one per line.

Reads the import directory (normal and delay-load) from the PE headers, so a
DLL name that merely appears as a string somewhere in the binary isn't
reported. Standard library only, so it runs on any CI runner.

    pe-imports.py <exe>                 the DLLs
    pe-imports.py --functions <exe>     each import as DLL!function
"""
import struct
import sys


def rva_to_offset(sections, rva):
    for va, size, raw_ptr, raw_size in sections:
        if va <= rva < va + max(size, raw_size):
            return raw_ptr + (rva - va)
    raise ValueError(f"RVA {rva:#x} is not inside any section")


def c_string(data, offset):
    end = data.index(b"\0", offset)
    return data[offset:end].decode("ascii", "replace")


def thunk_names(data, sections, rva, pe32_plus):
    """Function names (or #ordinals) listed in an import lookup table."""
    width, flag = (8, 1 << 63) if pe32_plus else (4, 1 << 31)
    off = rva_to_offset(sections, rva)
    out = []
    while True:
        entry = int.from_bytes(data[off : off + width], "little")
        if entry == 0:
            return out
        if entry & flag:
            out.append(f"#{entry & 0xFFFF}")
        else:
            # IMAGE_IMPORT_BY_NAME: 2-byte hint, then the name.
            out.append(c_string(data, rva_to_offset(sections, entry & 0x7FFFFFFF) + 2))
        off += width


def imports(path, functions=False):
    with open(path, "rb") as f:
        data = f.read()

    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise ValueError(f"{path} is not a PE file")
    n_sections, = struct.unpack_from("<H", data, pe + 6)
    opt_size, = struct.unpack_from("<H", data, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from("<H", data, opt)
    # Data directories start at 96 (PE32) or 112 (PE32+) into the optional header.
    dirs = opt + (112 if magic == 0x20B else 96)
    import_rva, _ = struct.unpack_from("<II", data, dirs + 1 * 8)
    delay_rva, _ = struct.unpack_from("<II", data, dirs + 13 * 8)

    sections = []
    sec = opt + opt_size
    for i in range(n_sections):
        size, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, sec + i * 40 + 8)
        sections.append((va, size, raw_ptr, raw_size))

    names = []
    # IMAGE_IMPORT_DESCRIPTOR: 20 bytes, DLL name RVA at +12, all-zero terminator.
    if import_rva:
        off = rva_to_offset(sections, import_rva)
        while True:
            desc = struct.unpack_from("<IIIII", data, off)
            if not any(desc):
                break
            dll = c_string(data, rva_to_offset(sections, desc[3]))
            if functions:
                # OriginalFirstThunk, or FirstThunk when a linker left it out.
                table = desc[0] or desc[4]
                names += [f"{dll}!{fn}" for fn in thunk_names(data, sections, table, magic == 0x20B)]
            else:
                names.append(dll)
            off += 20
    # IMAGE_DELAYLOAD_DESCRIPTOR: 32 bytes, DLL name RVA at +4.
    if delay_rva:
        off = rva_to_offset(sections, delay_rva)
        while True:
            desc = struct.unpack_from("<8I", data, off)
            if not any(desc):
                break
            dll = c_string(data, rva_to_offset(sections, desc[1]))
            if functions:
                names += [f"{dll}!{fn}" for fn in thunk_names(data, sections, desc[4], magic == 0x20B)]
            else:
                names.append(dll)
            off += 32
    return names


if __name__ == "__main__":
    args = sys.argv[1:]
    want_functions = args[:1] == ["--functions"]
    for name in imports(args[-1], functions=want_functions):
        print(name)
