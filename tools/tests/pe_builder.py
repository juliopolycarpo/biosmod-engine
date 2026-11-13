"""Minimal PE builder for the replay tests: the Python twin of `synthetic::pe` in biosmod-core.

`crates/biosmod-core/tests/synthetic_pe.rs` pins the sha256 of the images below, and
`test_replay_script.py` asserts the same digests, so the two builders cannot drift apart.
"""

import struct

IMAGE_BASE = 0x1000_0000
CODE_RVA = 0x1000
FILE_ALIGN = 0x200


def _align(value, size):
    return (value + size - 1) // size * size


def pe(wide, code, relocations=()):
    """A PE32 (`wide` false) or PE32+ image with `code` at RVA 0x1000 and the entry point there.

    Example: `pe(True, b"\\xb8\\x07\\x00\\x00\\x00\\xc3")` returns 7 when called.
    """
    pages = {}
    for rva in relocations:
        kind = 10 if wide else 3
        pages.setdefault(rva & ~0xFFF, []).append((kind << 12) | (rva & 0xFFF))
    reloc = b""
    for page, entries in sorted(pages.items()):
        if len(entries) % 2:
            entries.append(0)
        reloc += struct.pack("<II", page, 8 + 2 * len(entries))
        reloc += b"".join(struct.pack("<H", entry) for entry in entries)
    sections = [(b".text\0\0\0", CODE_RVA, bytes(code), 0x6000_0020)]
    if reloc:
        sections.append((b".reloc\0\0", 0x2000, reloc, 0x4200_0040))
    optional = 0xF0 if wide else 0xE0
    header_size = _align(0x40 + 4 + 20 + optional + 40 * len(sections), FILE_ALIGN)
    out = bytearray(header_size)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x40)
    at = 0x40
    out[at : at + 4] = b"PE\0\0"
    at += 4
    struct.pack_into("<HH", out, at, 0x8664 if wide else 0x014C, len(sections))
    struct.pack_into("<HH", out, at + 16, optional, 0x0002)
    at += 20
    last = sections[-1]
    image_size = _align(last[1] + len(last[2]), 0x1000)
    struct.pack_into("<H", out, at, 0x20B if wide else 0x10B)
    struct.pack_into("<I", out, at + 16, CODE_RVA)
    base_at, tail = (24, 0x70) if wide else (28, 0x60)
    if wide:
        struct.pack_into("<Q", out, at + base_at, IMAGE_BASE)
        after_base = at + base_at + 8
    else:
        struct.pack_into("<I", out, at + base_at, IMAGE_BASE)
        after_base = at + base_at + 4
    struct.pack_into("<II", out, after_base, 0x1000, FILE_ALIGN)
    struct.pack_into("<II", out, at + 56, image_size, header_size)
    struct.pack_into("<H", out, at + 68, 11)
    struct.pack_into("<I", out, at + tail - 4, 16)
    if reloc:
        struct.pack_into("<II", out, at + tail + 5 * 8, 0x2000, len(reloc))
    table, raw = at + optional, header_size
    for name, rva, body, flags in sections:
        padded = _align(len(body), FILE_ALIGN)
        struct.pack_into("<8sIIIIIIHHI", out, table, name, len(body), rva, padded, raw, 0, 0, 0, 0, flags)
        out += body
        out += bytes(raw + padded - len(out))
        raw += padded
        table += 40
    return bytes(out)
