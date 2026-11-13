"""B02/B03: the DDR4 detector probes DIMM slot 3 when forced-page discovery is enabled.

Runs the original `UncoreInitPeim` DDR4 detection, SPD byte read and type recognition of
either board (MR9A or PR9) against a synthetic one-DIMM SPD EEPROM, for every combination of
the EEPROM's starting page (0, 1), the CPU's retained DDR4 marker (clear, set) and the setup
page-selection policy (Auto, Enabled).

With the policy Enabled the original first reads SPD byte 0 at slave 0xA6, which is slot 3,
instead of 0xA0, 0xA2 and 0xA4: the page-reset loop reuses the outer slot counter (B02). With
the policy Auto and a clear marker the detector reads page-1 bytes as the SPD header when the
EEPROM starts on page 1 (B03). Each case checks the modeled result:

    detected DDR4   = marker set, or (policy Auto and page 0)
    readable        = marker set, or policy Enabled, or page 0
    device type     = 0x0C when readable, 0 otherwise (and the recognized memory type follows)
    Enabled         = exactly one SPD byte-0 read, at slave 0xA6
    upper byte 320  = 0xAA when DDR4 was detected; 0x55 (byte 64 wrapped) when Enabled
                      without the marker

Only the EEPROM transactions and the CPU scratch CSR (key 0x8024044) are replaced, with named
fakes; every other instruction of the module runs. The policy branch is not run: the script
sets the policy bit (context +0x5C, bit 29) directly, as the research matrix did. The result
does not prove retained SPD power, which page a failed boot started on, the POST code shown or
the community root cause.

    bme replay script tools/replay/examples/b02_b03_dimm_counter.py \\
        --module UncoreInitPeim.pe -o out/

The module comes from `bme extract <rom> --guid D71C8BA4-4AF2-4D0D-B1BA-F2409F0C20D3`. Only the
two original modules named in `BOARDS` are accepted; other digests are refused, because the
function addresses differ per image.
"""

import hashlib
import struct

import bme_replay as replay

#: Reviewed original modules by SHA-256. `rva` holds the module's own functions and the two
#: leaf helpers the harness replaces, as RVAs from the image's preferred base (the image keeps
#: that base; PEI modules run in place near 4 GiB).
BOARDS = {
    "2582bbe3fec0f81f6e14d20a79fd062ca66694010158fcd8e42f36ea09601000": {
        "board": "MR9A",
        "rva": {
            "csr_read": 0x24FFE,
            "csr_write": 0x2505F,
            "spd_read": 0x7C836,
            "page_select": 0x7C91E,
            "error_a": 0x3C388,
            "error_b": 0x271CE,
            "detect": 0x5CD00,
            "access": 0x5CD3C,
            "recognize": 0x723AA,
        },
    },
    "a645b2ea89779bcc66bfc96581aebb686aa9a6a15e7b6b232e333b292e59ed42": {
        "board": "PR9",
        "rva": {
            "csr_read": 0x25727,
            "csr_write": 0x25788,
            "spd_read": 0x7CF52,
            "page_select": 0x7D03A,
            "error_a": 0x3CA50,
            "error_b": 0x278F7,
            "detect": 0x5D41C,
            "access": 0x5D458,
            "recognize": 0x72AC6,
        },
    },
}

#: Context layout the routines use, shared by both boards.
CONTEXT, CONTEXT_SIZE = 0x0020_0000, 0x0010_0000
POLICY_FLAGS, FORCE_PAGE_BIT = 0x5C, 0x2000_0000
INIT_MODE = 0x9CC
CHANNEL_ENABLED, PRIOR_SLOT_PRESENT, DETECTED_DDR4, MEMORY_TYPE = 0x22F67, 0x230F0, 0x22F64, 0x2296E
OUTPUT = CONTEXT + 0x80000
SCRATCH_KEY = 0x8024044
BUDGET = 100_000
EEPROM_SLAVE = 0xA0


class SpdBoot:
    """One module mapped with a synthetic one-DIMM EEPROM and the CPU scratch register."""

    def __init__(self, module, table, page, marker, force):
        self.table = table["rva"]
        self.machine = replay.Machine(32)
        self.image = replay.load_pe(self.machine, module, name="UncoreInitPeim", bitness=32)
        self.machine.map(CONTEXT, CONTEXT_SIZE, "context")
        self.page = page
        self.scratch = 0x20 if marker else 0
        self.transactions = []
        self.spd = bytearray(512)
        self.spd[0] = 0x23  # DDR4: 512-byte total size, 384 bytes used
        self.spd[2] = 0x0C  # DDR4 SDRAM device type
        self.spd[64] = 0x55
        self.spd[320] = 0xAA  # tells a real upper-page read from wrapped byte 64
        self.machine.write(CONTEXT + INIT_MODE, struct.pack("<I", 8))  # full initialization
        self.machine.write(CONTEXT + POLICY_FLAGS, struct.pack("<I", FORCE_PAGE_BIT if force else 0))
        self.machine.write(CONTEXT + CHANNEL_ENABLED, b"\x01")
        self.machine.write(CONTEXT + PRIOR_SLOT_PRESENT, b"\x01")
        for name, handler in (
            ("csr_read", self.csr_read),
            ("csr_write", self.csr_write),
            ("spd_read", self.spd_read),
            ("page_select", self.page_select),
            ("error_a", self.unexpected_error),
            ("error_b", self.unexpected_error),
        ):
            self.machine.stub(self.image.address(self.table[name]), handler, "fake_" + name)

    def csr_read(self, call):
        key = call.arg(3)
        if key != SCRATCH_KEY:
            raise replay.ReplayError("CPU scratch CSR read: expected key %#x | received %#x" % (SCRATCH_KEY, key))
        return self.scratch

    def csr_write(self, call):
        key = call.arg(3)
        if key != SCRATCH_KEY:
            raise replay.ReplayError("CPU scratch CSR write: expected key %#x | received %#x" % (SCRATCH_KEY, key))
        self.scratch = call.arg(4)
        return 0

    def spd_read(self, call):
        # The iMC encoder uses DTI[7:4] and address[3:1]; bit 0 of the argument is ignored.
        slave, offset, output = call.arg(3) & 0xFFFE, call.arg(4), call.arg(5)
        present = slave == EEPROM_SLAVE
        value = self.spd[self.page * 256 + offset] if present else None
        self.transactions.append({"operation": "read", "slave": slave, "offset": offset, "present": present})
        if present:
            self.machine.write(output, bytes([value]))
        return 0 if present else 2

    def page_select(self, call):
        slave = call.arg(3) & 0xFFFE
        if slave not in (0x6C, 0x6E):
            raise replay.ReplayError("SPD page select slave: expected 0x6c | 0x6e | received %#x" % slave)
        self.page = int(slave == 0x6E)
        self.transactions.append({"operation": "select_page", "slave": slave, "page": self.page})
        return 0

    def unexpected_error(self, call):
        raise replay.ReplayError("firmware error callback at %#x: expected none | received a call" % call.address)

    def call(self, name, *args):
        return self.machine.call(self.image.address(self.table[name]), *args, budget=BUDGET).value

    def byte(self, offset):
        return self.machine.read(CONTEXT + offset, 1)[0]


def run_case(module, table, page, marker, force):
    boot = SpdBoot(module, table, page, marker, force)
    boot.call("detect", CONTEXT, 0)
    detected = boot.byte(DETECTED_DDR4)
    boot.call("access", CONTEXT, 0, 0, 0, 2, OUTPUT)
    device_type = boot.machine.read(OUTPUT, 1)[0]
    boot.call("recognize", CONTEXT, 0, 0, 0, device_type)
    memory_type = struct.unpack("<H", boot.machine.read(CONTEXT + MEMORY_TYPE, 2))[0]
    boot.call("access", CONTEXT, 0, 0, 0, 320, OUTPUT)
    upper = boot.machine.read(OUTPUT, 1)[0]
    header_reads = [t for t in boot.transactions if t["operation"] == "read" and t["offset"] == 0]
    return {
        "initial_page": page,
        "marker": marker,
        "policy": "enabled" if force else "auto",
        "detected_ddr4": bool(detected),
        "device_type": device_type,
        "memory_type": memory_type,
        "upper_spd_byte": upper,
        "header_read_slaves": [hex(t["slave"]) for t in header_reads],
        "trace_sha256": boot.machine.trace.digest(),
    }


def expected_for(page, marker, force):
    """The modeled result of the original code for one case."""
    detected = marker or (not force and page == 0)
    readable = marker or force or page == 0
    expected = {
        "detected_ddr4": detected,
        "device_type": 0x0C if readable else 0,
        "memory_type": 0x0C if readable else 0,
    }
    if force:
        expected["header_read_slaves"] = ["0xa6"]  # slot 3 instead of 0xa0 / 0xa2 / 0xa4
    if force and not marker:
        expected["upper_spd_byte"] = 0x55
    if detected:
        expected["upper_spd_byte"] = 0xAA
    return expected


def main():
    paths = replay.modules()
    if len(paths) != 1:
        raise SystemExit("--module: expected one UncoreInitPeim module | received %d" % len(paths))
    with open(paths[0], "rb") as handle:
        module = handle.read()
    digest = hashlib.sha256(module).hexdigest()
    table = BOARDS.get(digest)
    if table is None:
        raise SystemExit(
            "--module sha256: expected one of %s | received %s" % (", ".join(sorted(BOARDS)), digest)
        )
    mismatches = 0
    cases = 0
    for page in (0, 1):
        for marker in (False, True):
            for force in (False, True):
                row = run_case(module, table, page, marker, force)
                expected = expected_for(page, marker, force)
                row["board"] = table["board"]
                row["expected"] = expected
                row["ok"] = all(row[key] == value for key, value in expected.items())
                mismatches += not row["ok"]
                cases += 1
                replay.emit(row)
    replay.emit(
        {
            "summary": True,
            "board": table["board"],
            "module_sha256": digest,
            "cases": cases,
            "mismatches": mismatches,
            "passed": mismatches == 0,
        }
    )


if __name__ == "__main__":
    main()
