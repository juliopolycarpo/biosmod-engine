"""Load a PE32, PE32+ or TE image into a machine at its image base, with relocations applied."""

import hashlib
import struct

import pefile

from .errors import ImageError

PAGE = 0x1000
MACHINE_BITNESS = {0x014C: 32, 0x8664: 64}
IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_DIR64 = 0, 3, 10


class Image:
    """A mapped module: `.base`, `.size`, `.entry`, `.bitness`, `.sha256`.

    Example: `image.address(0x1658)` is the run-time address of RVA 0x1658.
    """

    def __init__(self, name, base, size, entry_rva, bitness, sha256, preferred_base, kind):
        self.name = name
        self.base = base
        self.size = size
        self.entry_rva = entry_rva
        self.bitness = bitness
        self.sha256 = sha256
        self.preferred_base = preferred_base
        self.kind = kind

    @property
    def entry(self):
        return self.base + self.entry_rva

    def address(self, rva):
        return self.base + rva

    def rva(self, address):
        return address - self.base

    def contains(self, address):
        return self.base <= address < self.base + self.size

    def as_dict(self):
        return {
            "name": self.name,
            "kind": self.kind,
            "base": self.base,
            "size": self.size,
            "entry_rva": self.entry_rva,
            "bitness": self.bitness,
            "sha256": self.sha256,
        }


def _parse_te(data):
    """Build a PE-like memory image from a TE image.

    TE keeps a 40-byte header in place of the PE headers and strips the rest. Section file
    offsets stay relative to the original file, so they shift by `stripped - 40`.
    """
    (_, machine, count, _subsystem, stripped, entry, _code, base) = struct.unpack_from("<2sHBBHIIQ", data, 0)
    relocation_rva, relocation_size = struct.unpack_from("<II", data, 24)
    delta = stripped - 40
    sections = []
    for index in range(count):
        name, vsize, vaddr, rsize, raw = struct.unpack_from("<8sIIII", data, 40 + 40 * index)
        sections.append((vaddr, max(vsize, rsize), data[raw - delta : raw - delta + rsize]))
    size = max((vaddr + length for vaddr, length, _ in sections), default=0)
    size = max(size, 0x1000)
    mapped = bytearray(size)
    mapped[: min(40 + 40 * count, size)] = data[: min(40 + 40 * count, size)]
    for vaddr, length, body in sections:
        mapped[vaddr : vaddr + len(body)] = body
    return bytearray(mapped), machine, entry, base, (relocation_rva, relocation_size)


def _apply_relocations(mapped, directory, delta, bitness):
    rva, size = directory
    if not size or not delta:
        return
    offset, end = rva, rva + size
    while offset + 8 <= end:
        page, block = struct.unpack_from("<II", mapped, offset)
        if block < 8:
            break
        for entry in struct.unpack_from("<%dH" % ((block - 8) // 2), mapped, offset + 8):
            kind, where = entry >> 12, page + (entry & 0xFFF)
            if kind == IMAGE_REL_BASED_HIGHLOW:
                value = struct.unpack_from("<I", mapped, where)[0]
                struct.pack_into("<I", mapped, where, (value + delta) & 0xFFFFFFFF)
            elif kind == IMAGE_REL_BASED_DIR64:
                value = struct.unpack_from("<Q", mapped, where)[0]
                struct.pack_into("<Q", mapped, where, (value + delta) & (2**64 - 1))
            elif kind != IMAGE_REL_BASED_ABSOLUTE:
                raise ImageError("relocation type at rva %#x: expected 0 | 3 | 10 | received %d" % (where, kind))
        offset += block


def load_pe(machine, data, *, base=None, name="module", bitness=None):
    """Map `data` (a PE32, PE32+ or TE image) into `machine` and return its `Image`.

    The image is placed at `base`, or at its preferred image base when `base` is None
    (PEI modules in a ROM keep their execute-in-place address). Base relocations are
    applied when the two differ. `bitness` is checked against the machine type.

    Example: `image = load_pe(machine, open("SioDxeInit.pe", "rb").read(), base=0x10000000)`.
    """
    data = bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    if data[:2] == b"VZ":
        mapped, machine_type, entry, preferred, directory = _parse_te(data)
        kind = "te"
    else:
        try:
            pe = pefile.PE(data=data, fast_load=False)
        except pefile.PEFormatError as error:
            raise ImageError("%s: expected a PE32, PE32+ or TE image | received %s" % (name, error)) from None
        machine_type = pe.FILE_HEADER.Machine
        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        preferred = pe.OPTIONAL_HEADER.ImageBase
        reloc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
        directory = (reloc.VirtualAddress, reloc.Size)
        mapped = bytearray(pe.get_memory_mapped_image())
        kind = "pe"
    detected = MACHINE_BITNESS.get(machine_type)
    if detected is None:
        raise ImageError("%s machine type: expected 0x14c | 0x8664 | received %#x" % (name, machine_type))
    if bitness is not None and bitness != detected:
        raise ImageError("%s bitness: expected %d | received %d from the image header" % (name, bitness, detected))
    if detected != machine.bitness:
        raise ImageError("%s bitness: expected a %d-bit machine | received a %d-bit image" % (name, machine.bitness, detected))
    placed = preferred if base is None else base
    _apply_relocations(mapped, directory, placed - preferred, detected)
    # Map from the page containing the base; an XIP base need not be page aligned in principle.
    start = placed & ~(PAGE - 1)
    lead = placed - start
    machine.map(start, lead + len(mapped), name)
    machine.write(placed, mapped)
    return Image(name, placed, len(mapped), entry, detected, digest, preferred, kind)
