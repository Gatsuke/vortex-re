#!/usr/bin/env python3
"""Generate the minimal native-binary fixtures used by Vortex-RE's tests.

Each artifact is the smallest structurally valid instance of its format
that still exercises the interesting parser paths:

  elf64-demo    ELF64 little-endian ET_EXEC with .text/.dynsym/.dynstr/.shstrtab
                and two undefined dynamic imports (puts, malloc).
  elf32-demo    ELF32 little-endian ET_DYN with one undefined import (printf).
  pe64-demo.exe PE32+ (x86-64) with two sections and an import table naming
                KERNEL32.dll!CreateFileW and USER32.dll!MessageBoxW.
  pe32-demo.exe PE32 (i386) with one section and one import (msvcrt.dll!printf).
  dotnet-demo.exe
                PE32+ whose data directory 14 (CLR) points at a minimal
                PE/CLI header and a BSJB metadata root with #~, #Strings,
                #US, #GUID, and #Blob streams (inventory-level fixture:
                stream headers are valid, table contents are not).
  classes-dex   A DEX (version 035) with 3 strings, 2 types, 1 proto, 1
                method id, and 1 class def (Ldemo/Sample;), correct adler32
                checksum, and a map list.

Everything is deterministic; re-running this script reproduces the committed
bytes exactly. Python stdlib only.
"""

import hashlib
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent


def align(value, multiple):
    return (value + multiple - 1) // multiple * multiple


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------

SHN_UNDEF = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_DYNSYM = 11


def elf_section_header(is64, name, stype, offset, size, link=0, entsize=0, flags=0):
    """ELF32: 40 bytes (all u32); ELF64: 64 bytes (flags/addr/offset/size/align/entsize wider)."""
    if is64:
        return struct.pack(
            "<IIQQQQIIQQ",
            name,    # sh_name
            stype,   # sh_type
            flags,   # sh_flags
            0,       # sh_addr
            offset,  # sh_offset
            size,    # sh_size
            link,    # sh_link (strtab index for symtabs)
            0,       # sh_info
            4,       # sh_addralign
            entsize, # sh_entsize
        )
    return struct.pack(
        "<IIIIIIIIII",
        name,        # sh_name
        stype,       # sh_type
        flags,       # sh_flags
        0,           # sh_addr
        offset,      # sh_offset
        size,        # sh_size
        link,        # sh_link (strtab index for symtabs)
        0,           # sh_info
        4,           # sh_addralign
        entsize,     # sh_entsize
    )


def elf64_sym(name, shndx, value=0, size=0):
    return struct.pack("<IBBHQQ", name, 0x12, 0, shndx, value, size)


def elf32_sym(name, shndx, value=0, size=0):
    return struct.pack("<IIIBBH", name, value, size, 0x12, 0, shndx)


def build_elf64():
    # Layout: ELF header (64) | .text | .dynsym | .dynstr | .shstrtab | sections
    e_ident = bytes([0x7F]) + b"ELF" + bytes([2, 1, 1, 0]) + bytes([0]) + bytes(7)
    ehsize, shentsize = 64, 64

    text_off = ehsize
    text = b"\x55\x48\x89\xe5\x0f\x05\xc3"  # push rbp; mov rbp,rsp; syscall; ret

    dynsym_off = text_off + len(text)
    # Null symbol first (required), then two undefined imports.
    syms = [
        elf64_sym(0, SHN_UNDEF),
        elf64_sym(1, SHN_UNDEF),  # "puts"
        elf64_sym(6, SHN_UNDEF),  # "malloc"
    ]
    dynsym = b"".join(syms)

    dynstr_off = dynsym_off + len(dynsym)
    dynstr = b"\x00puts\x00malloc\x00"

    shstr_off = dynstr_off + len(dynstr)
    shstrtab = b"\x00.text\x00.dynsym\x00.dynstr\x00.shstrtab\x00"

    shoff = align(shstr_off + len(shstrtab), 8)
    sections = [
        elf_section_header(True, 0, 0, 0, 0),                                # NULL
        elf_section_header(True, 1, SHT_PROGBITS, text_off, len(text)),      # .text
        elf_section_header(True, 7, SHT_DYNSYM, dynsym_off, len(dynsym),
                           link=3, entsize=24),                        # .dynsym
        elf_section_header(True, 15, SHT_STRTAB, dynstr_off, len(dynstr)),   # .dynstr
        elf_section_header(True, 23, SHT_STRTAB, shstr_off, len(shstrtab)),  # .shstrtab
    ]
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,        # e_type = ET_EXEC
        0x3E,     # e_machine = x86-64
        1,        # e_version
        0x1000,   # e_entry
        0,        # e_phoff
        shoff,    # e_shoff
        0,        # e_flags
        ehsize, 0, 0,                      # e_ehsize, e_phentsize, e_phnum
        shentsize, len(sections), 4,       # e_shentsize, e_shnum, e_shstrndx
    )
    body = bytearray(ehdr)
    body += text + dynsym + dynstr + shstrtab
    body += b"\x00" * (shoff - len(body))
    body += b"".join(sections)
    return bytes(body)


def build_elf32():
    e_ident = bytes([0x7F]) + b"ELF" + bytes([1, 1, 1, 0]) + bytes([0]) + bytes(7)
    ehsize, shentsize = 52, 40

    text_off = ehsize
    text = b"\x55\xcd\x80\xc3"  # push ebp; int 0x80; ret

    dynsym_off = text_off + len(text)
    syms = [
        elf32_sym(0, SHN_UNDEF),
        elf32_sym(1, SHN_UNDEF),  # "printf"
    ]
    dynsym = b"".join(syms)

    dynstr_off = dynsym_off + len(dynsym)
    dynstr = b"\x00printf\x00"

    shstr_off = dynstr_off + len(dynstr)
    shstrtab = b"\x00.text\x00.dynsym\x00.dynstr\x00.shstrtab\x00"

    shoff = align(shstr_off + len(shstrtab), 4)
    sections = [
        elf_section_header(False, 0, 0, 0, 0),
        elf_section_header(False, 1, SHT_PROGBITS, text_off, len(text)),
        elf_section_header(False, 7, SHT_DYNSYM, dynsym_off, len(dynsym),
                           link=3, entsize=16),
        elf_section_header(False, 15, SHT_STRTAB, dynstr_off, len(dynstr)),
        elf_section_header(False, 23, SHT_STRTAB, shstr_off, len(shstrtab)),
    ]
    ehdr = e_ident + struct.pack(
        "<HHIIIIIHHHHHH",
        3,        # e_type = ET_DYN
        3,        # e_machine = i386
        1,        # e_version
        0,        # e_entry
        0,        # e_phoff
        shoff,    # e_shoff
        0,        # e_flags
        ehsize, 0, 0,
        shentsize, len(sections), 4,
    )
    body = bytearray(ehdr)
    body += text + dynsym + dynstr + shstrtab
    body += b"\x00" * (shoff - len(body))
    body += b"".join(sections)
    return bytes(body)


# ---------------------------------------------------------------------------
# PE / COFF (+ .NET)
# ---------------------------------------------------------------------------

def rva_to_offset(sections, rva):
    """sections: list of (virtual_address, virtual_size, raw_pointer, raw_size)."""
    for va, vsize, ptr, rsize in sections:
        span = max(vsize, rsize)
        if va <= rva < va + span:
            return rva - va + ptr
    return None  # not mapped (e.g. inside headers)


def cstr(text):
    return text.encode("ascii") + b"\x00"


def build_import_directory(sections, imports, thunk_size):
    """imports: list of (dll_name, [function_names]).

    Layout (all RVAs, placed inside .idata at the end of the image):
      descriptors | hint/name table | dll name strings | ILT | IAT
    Returns (bytes_blob, blob_rva, size) plus patch positions for IAT RVAs.
    """
    # The caller tells us where the blob lands via a second pass; we compute
    # sizes first, then place.
    raise NotImplementedError


def build_pe(is_pe32_plus, imports, dotnet=False):
    """Build a minimal PE with sections, imports, and (optionally) a CLR header."""
    file_align, sect_align = 0x200, 0x1000
    machine = 0x8664 if is_pe32_plus else 0x14C
    magic = 0x20B if is_pe32_plus else 0x10B
    optional_size = 240 if is_pe32_plus else 224  # fixed fields + 16 data dirs

    # --- plan sections -----------------------------------------------------
    # .text  : code + import structures (+ CLI header + metadata when dotnet)
    # .rdata : nothing meaningful, but exercises a second section
    sec_count = 2

    # We build section content first with placeholder RVAs, then fix: since
    # every structure lives in .text at a known offset, we can compute exact
    # RVAs in one planning pass.
    text_rva = sect_align  # first section VA

    # --- import structures (inside .text) ----------------------------------
    thunk_size = 8 if is_pe32_plus else 4
    ORDINAL_FLAG = 0x8000000000000000 if is_pe32_plus else 0x80000000

    # Place: descriptors (20 each + null) | names | hint/name entries | ILT | IAT
    desc_count = len(imports) + 1
    desc_size = desc_count * 20
    dll_names = [cstr(dll) for dll, _ in imports]
    hint_names = [struct.pack("<H", 0) + cstr(fn) for _, fns in imports for fn in fns]

    off = 0
    desc_off = off; off += desc_size
    hint_off = off; off += sum(len(h) for h in hint_names)
    name_off = off; off += sum(len(n) for n in dll_names)
    ilt_off = off
    total_thunks = sum(len(fns) for _, fns in imports) + len(imports)  # + null per dll
    off += total_thunks * thunk_size
    iat_off = off
    off += total_thunks * thunk_size

    # hint/name RVAs per import, and name RVAs
    hint_rvas, name_rvas = [], []
    cur = hint_off
    for h in hint_names:
        hint_rvas.append(text_rva + cur)
        cur += len(h)
    cur = name_off
    for n in dll_names:
        name_rvas.append(text_rva + cur)
        cur += len(n)

    # ILT/IAT: per dll, one entry per function (hint/name RVA), then a null
    ilt_entries, iat_entries = [], []
    idx = 0
    for i, (_, fns) in enumerate(imports):
        for _ in fns:
            ilt_entries.append(hint_rvas[idx])
            iat_entries.append(hint_rvas[idx])
            idx += 1
        ilt_entries.append(0)
        iat_entries.append(0)

    def pack_thunk(v):
        return struct.pack("<Q", v) if is_pe32_plus else struct.pack("<I", v)

    # Each DLL owns a sub-range of the ILT/IAT arrays: its thunks followed
    # by a null terminator. Record where each DLL's range starts.
    ilt_starts, cur = [], ilt_off
    for _, fns in imports:
        ilt_starts.append(cur)
        cur += (len(fns) + 1) * thunk_size
    descriptors = b""
    for i, (dll, _) in enumerate(imports):
        descriptors += struct.pack(
            "<IIIII",
            text_rva + ilt_starts[i],  # OriginalFirstThunk (this DLL's ILT)
            0,                         # TimeDateStamp
            0,                         # ForwarderChain
            name_rvas[i],              # Name
            text_rva + ilt_starts[i],  # FirstThunk (IAT mirrors the ILT layout)
        )
    descriptors += b"\x00" * 20

    ilt = b"".join(pack_thunk(v) for v in ilt_entries)
    iat = b"".join(pack_thunk(v) for v in iat_entries)

    code = b"\x55\x48\x8b\xec\xc3" if is_pe32_plus else b"\x55\x8b\xec\xc3"
    code_off = off; off += len(code)
    import_dir_rva = text_rva + desc_off
    import_dir_size = desc_size

    blob = bytearray(off)
    blob[desc_off:desc_off + len(descriptors)] = descriptors
    pos = hint_off
    for h in hint_names:
        blob[pos:pos + len(h)] = h
        pos += len(h)
    pos = name_off
    for n in dll_names:
        blob[pos:pos + len(n)] = n
        pos += len(n)
    blob[ilt_off:ilt_off + len(ilt)] = ilt
    blob[iat_off:iat_off + len(iat)] = iat
    blob[code_off:code_off + len(code)] = code

    # --- .NET CLI header + metadata (inside .text, after imports) ----------
    dotnet_dir_rva = dotnet_dir_size = 0
    if dotnet:
        cli_off = off
        # Metadata blob: version string "v4.0.30319" padded to 4, streams.
        version = b"v4.0.30319\x00"
        version_len = align(len(version), 4)
        def stream_name(name):
            # NUL-terminated, padded to a 4-byte boundary (ECMA-335 II.24.2.2).
            raw = name.encode("ascii") + b"\x00"
            return raw + b"\x00" * (-len(raw) % 4)
        stream_names = [stream_name(n) for n in
                        ["#~", "#Strings", "#US", "#GUID", "#Blob"]]
        stream_sizes = [16, 32, 16, 16, 16]

        md_header_size = 16 + version_len + 2 + 2
        stream_headers_size = sum(4 + 4 + len(n) for n in stream_names)
        md_total = md_header_size + sum(stream_sizes)
        md_rva = text_rva + cli_off + 72  # after the CLI header
        # CLI header (first 24 bytes of IMAGE_COR20_HEADER, remainder zero)
        cli = struct.pack(
            "<IHHIIII",
            72,                 # cb
            2, 5,               # Major/MinorRuntimeVersion (2.5)
            md_rva,             # MetaData RVA
            md_total,           # MetaData size
            1,                  # Flags (ILONLY)
            0x06000001,         # EntryPointToken (void Main())
        ) + b"\x00" * (72 - 24)  # remaining fixed fields
        # Metadata root: BSJB
        md = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version))
        md += version + b"\x00" * (version_len - len(version))
        md += struct.pack("<HH", 0, len(stream_names))
        cur = md_header_size
        for name, size in zip(stream_names, stream_sizes):
            md += struct.pack("<II", cur, size) + name
            cur += size
        # stream payloads (content is placeholder; sizes/offsets are what count)
        md += b"\x7e" * sum(stream_sizes)

        blob += cli + md
        dotnet_dir_rva = text_rva + cli_off
        dotnet_dir_size = 72

    # --- section table ------------------------------------------------------
    text_raw_size = align(len(blob), file_align)
    rdata_rva = text_rva + sect_align
    sections = [(text_rva, len(blob), 0x200, text_raw_size),
                (rdata_rva, 0x10, 0x200 + text_raw_size, 0x200)]

    def sec_header(name, va, vsize, ptr, rsize, chars):
        return (name.encode("ascii").ljust(8, b"\x00")
                + struct.pack("<IIIIIIII", vsize, va, rsize, ptr, 0, 0, 0, chars))

    section_table = (
        sec_header(".text", text_rva, len(blob), 0x200, text_raw_size, 0x60000020)
        + sec_header(".rdata", rdata_rva, 0x10, 0x200 + text_raw_size, 0x200, 0x40000040)
    )

    # --- headers -------------------------------------------------------------
    e_lfanew = 0x80
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew)
    dos = dos.ljust(e_lfanew, b"\x00")

    address_of_entry = text_rva + code_off
    coff = struct.pack(
        "<HHIIIHH",
        machine,
        sec_count,
        0x60000000,  # TimeDateStamp (fixed, deterministic)
        0, 0,
        optional_size,
        0x0002,      # Characteristics: EXECUTABLE_IMAGE
    )

    # Data directories (index: rva, size)
    data_dirs = [(0, 0)] * 16
    data_dirs[1] = (import_dir_rva, import_dir_size)
    if dotnet:
        data_dirs[14] = (dotnet_dir_rva, dotnet_dir_size)

    if is_pe32_plus:
        # PE32+ optional header = 112 fixed bytes + 128 directory bytes.
        optional = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            magic,           # Magic 0x20B
            14, 0,           # linker version
            0x10, 0, 0,      # SizeOfCode / Init / Uninit
            address_of_entry,
            text_rva,        # BaseOfCode
            0x140000000,     # ImageBase (u64)
            sect_align, file_align,
            6, 0,            # OS version
            0, 0,            # Image version
            6, 0,            # Subsystem version
            0,               # Win32VersionValue
            0x3000,          # SizeOfImage
            0x200,           # SizeOfHeaders
            0,               # CheckSum
            3,               # Subsystem: CUI
            0,               # DllCharacteristics
            0x100000, 0x1000, 0x10000, 0x1000,  # stack/heap reserve+commit
            0,               # LoaderFlags
            16,              # NumberOfRvaAndSizes
        )
    else:
        # PE32 optional header = 96 fixed bytes + 128 directory bytes.
        optional = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            magic,           # Magic 0x10B
            14, 0,
            0x10, 0, 0,
            address_of_entry,
            text_rva,        # BaseOfCode
            0x1000,          # BaseOfData
            0x400000,        # ImageBase (u32)
            sect_align, file_align,
            6, 0, 0, 0, 6, 0,  # OS / image / subsystem versions
            0,               # Win32VersionValue
            0x3000, 0x200, 0,  # SizeOfImage / SizeOfHeaders / CheckSum
            3, 0,            # Subsystem: CUI; DllCharacteristics
            0x100000, 0x1000, 0x10000, 0x1000,  # stack/heap
            0,               # LoaderFlags
            16,              # NumberOfRvaAndSizes
        )

    dirs_blob = b"".join(struct.pack("<II", rva, size) for rva, size in data_dirs)
    optional_full = optional + dirs_blob
    assert len(optional_full) == optional_size, (len(optional_full), optional_size)

    headers = dos + b"PE\x00\x00" + coff + optional_full + section_table
    headers = headers.ljust(0x200, b"\x00")  # headers take one file-alignment unit

    image = bytearray(headers)
    image += blob
    image += b"\x00" * (text_raw_size - len(blob))
    image += b"\x00" * 0x200  # .rdata raw data
    return bytes(image)


# ---------------------------------------------------------------------------
# DEX
# ---------------------------------------------------------------------------

def uleb128(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_dex():
    # Strings: "" (implicit), "Ldemo/Sample;", "Ldemo/Other;", "demo()V"
    # We keep string ids aligned with a plausible string pool.
    string_data = [b"", b"Ldemo/Sample;", b"Ldemo/Other;", b"demo()V"]
    string_blob = b""
    string_data_offsets = []
    for s in string_data:
        encoded = s.encode("utf-8") if isinstance(s, str) else s
        string_data_offsets.append(len(string_blob))
        string_blob += uleb128(len(encoded)) + encoded + b"\x00"

    # type_ids: descriptor idx into string ids (0-based): 1 -> Ldemo/Sample;, 2 -> Ldemo/Other;
    type_ids = struct.pack("<II", 1, 2)
    # proto_ids: shorty_idx(0), return_type_idx(0), parameters_off(0)
    proto_ids = struct.pack("<III", 0, 0, 0)
    # method_ids: class_idx(0), proto_idx(0), name_idx(3)
    method_ids = struct.pack("<HHI", 0, 0, 3)
    # class_defs: class_idx, access_flags, superclass_idx, interfaces_off,
    #             source_file_idx, annotations_off, class_data_off, static_values_off
    class_defs = struct.pack("<IIIIIIII", 0, 1, 1, 0, 0, 0, 0, 0)

    header_size = 112
    string_ids_size = len(string_data)
    type_ids_size = 2
    proto_ids_size = 1
    field_ids_size = 0
    method_ids_size = 1
    class_defs_size = 1

    # offsets computed after we know the layout
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * string_ids_size
    proto_ids_off = type_ids_off + 4 * type_ids_size
    field_ids_off = proto_ids_off + 12 * proto_ids_size
    method_ids_off = field_ids_off + 8 * field_ids_size
    class_defs_off = method_ids_off + 8 * method_ids_size
    data_off = align(class_defs_off + 32 * class_defs_size, 4)
    string_blob_off = data_off

    # map list (at data_off + string_blob + padding)
    string_blob_padded = align(len(string_blob), 4)
    map_off = string_blob_off + string_blob_padded
    # map: header u16 size, then (u16 type, u16 unused, u32 size, u32 offset)
    map_items = [
        (0x0000, 1, 0),                        # TYPE_HEADER_ITEM
        (0x0001, string_ids_size, string_ids_off),
        (0x0002, type_ids_size, type_ids_off),
        (0x0003, proto_ids_size, proto_ids_off),
        (0x0005, method_ids_size, method_ids_off),
        (0x0006, class_defs_size, class_defs_off),
        (0x2002, len(string_data), string_blob_off),  # TYPE_STRING_DATA_ITEM
        (0x0000, 1, map_off),                  # TYPE_MAP_LIST
    ]
    map_list = struct.pack("<H", len(map_items)) + b"".join(
        struct.pack("<HHII", t, 0, n, off) for t, n, off in map_items
    )

    file_size = map_off + len(map_list)

    header = bytearray(112)
    header[0:8] = b"dex\n035\x00"
    # checksum (adler32 over everything after the checksum field) and
    # signature (sha1 over the same range) are filled in after assembly.
    struct.pack_into("<I", header, 8, 0)               # checksum
    header[12:32] = b"\x00" * 20                       # signature
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)     # endian_tag
    struct.pack_into("<I", header, 44, 0)              # link_size
    struct.pack_into("<I", header, 48, 0)              # link_off
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<I", header, 56, string_ids_size)
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 64, type_ids_size)
    struct.pack_into("<I", header, 68, type_ids_off)
    struct.pack_into("<I", header, 72, proto_ids_size)
    struct.pack_into("<I", header, 76, proto_ids_off)
    struct.pack_into("<I", header, 80, field_ids_size)
    struct.pack_into("<I", header, 84, field_ids_off)
    struct.pack_into("<I", header, 88, method_ids_size)
    struct.pack_into("<I", header, 92, method_ids_off)
    struct.pack_into("<I", header, 96, class_defs_size)
    struct.pack_into("<I", header, 100, class_defs_off)
    struct.pack_into("<I", header, 104, file_size - data_off)  # data_size
    struct.pack_into("<I", header, 108, data_off)

    body = bytearray(header)
    body += b"".join(struct.pack("<I", string_blob_off + off)
                     for off in string_data_offsets)
    body += type_ids + proto_ids + method_ids + class_defs
    body += b"\x00" * (data_off - len(body))
    body += string_blob
    body += b"\x00" * (string_blob_padded - len(string_blob))
    body += map_list
    assert len(body) == file_size, (len(body), file_size)

    # signature (sha1 of bytes 32..end) first, then checksum (adler32 of
    # bytes 12..end, which includes the signature just written).
    signature = hashlib.sha1(bytes(body[32:])).digest()
    body[12:32] = signature
    checksum = zlib.adler32(bytes(body[12:]))
    struct.pack_into("<I", body, 8, checksum)
    return bytes(body)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "elf64-demo": build_elf64(),
        "elf32-demo": build_elf32(),
        "pe64-demo.exe": build_pe(True, [("KERNEL32.dll", ["CreateFileW"]),
                                         ("USER32.dll", ["MessageBoxW"])]),
        "pe32-demo.exe": build_pe(False, [("msvcrt.dll", ["printf"])]),
        "dotnet-demo.exe": build_pe(True, [("KERNEL32.dll", ["ExitProcess"])],
                                    dotnet=True),
        "classes-dex": build_dex(),
    }
    for name, blob in artifacts.items():
        path = OUT / name
        path.write_bytes(blob)
        print(f"{name}: {len(blob)} bytes  sha256={hashlib.sha256(blob).hexdigest()[:16]}")


if __name__ == "__main__":
    main()
