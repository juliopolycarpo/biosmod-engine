"""B11: generic SMM registration reads 16 bytes from shorter public PI contexts.

Runs the original `PchSmiDispatcher` registration routine (RVA 0x393C) for the public PI
interfaces whose context is 4 or 8 bytes wide (Sx, software, GPI, power button), with the
context placed so only `gap` readable bytes follow it. When fewer than 16 bytes remain
readable the original must fault at RVA 0x3A02 (the first `MOVDQU XMM0,[RSI]`); with 16 or
more it must return (success for accepted values, EFI_INVALID_PARAMETER for rejected ones).
The service tables, allocator and chipset helpers are named fakes; no instruction reaches
the host.

    bme replay script tools/replay/examples/b11_context_overread.py \\
        --module PchSmiDispatcher.pe -o out/

The module comes from `bme extract <rom> --guid B0D6ED53-B844-43F5-BD2F-61095264E77E`.
Ported from the research harness `dispatch-context/validate_candidates.py`, keeping its
original-module scenarios (the candidate comparison needs the patched modules).
"""

import struct

import bme_replay as replay

BASE = 0x0100_0000
DATA, DATA_SIZE = 0x0300_0000, 0x1_0000
REGISTER_RVA, FIRST_COPY_RVA = 0x393C, 0x3A02
CLASS_TABLE_RVA, CLASS_STRIDE, CLASS_THIS_OFFSET = 0x2858, 0x38, 0x20
LIST_HEAD_RVA = 0x2840
#: Helpers the research harness replaced with named fakes: chipset identity (0x5A28 reports a
#: supported PCH), the source-pending predicate (0x534C, nothing pending), source programming
#: (0x5520) and the sleep transition (0x4B0C). Register paths must not reach real port I/O.
STUBBED = {0x44B8: 0, 0x5A28: 1, 0x534C: 0, 0x5520: 0, 0x4B0C: 0}
#: Declared context width per native class (4 bytes: power button, 8 bytes: Sx, software, GPI).
WIDTHS = {1: 8, 2: 8, 3: 8, 6: 4}
GAPS = (0, 1, 3, 7, 15)


def q(value):
    return struct.pack("<Q", value)


EFI_SUCCESS, EFI_INVALID_PARAMETER = 0, 0x8000_0000_0000_0002
ALL_ONES = 0xFFFF_FFFF_FFFF_FFFF


def payloads():
    """(class, context bytes, accepted) from the research harness.

    `accepted` is whether the native validation accepts the value (EDK2 ranges: Sx type 0..5
    and phase 0..1, software value 0..0xFF or all ones for auto-assignment, GPI 0..15, power
    button phase 0..1). Rejected values still copy the context first, so they fault the same way.
    """
    rows = []
    for state, phase in ((0, 0), (1, 0), (3, 0), (3, 1), (4, 0), (5, 0), (6, 0), (3, 2)):
        rows.append((1, struct.pack("<II", state, phase), state <= 5 and phase <= 1))
    rows += [(2, q(value), value <= 0xFF or value == ALL_ONES) for value in (0, 1, 0xEE, 0xFF, 0x100, ALL_ONES)]
    rows += [(3, q(value), value <= 15) for value in (0, 7, 15, 16, ALL_ONES)]
    rows += [(6, struct.pack("<I", phase), phase <= 1) for phase in (0, 1, 2, 0xFFFF_FFFF)]
    return rows


def prepare(module):
    """A machine with the module mapped, its globals pointed at fake services and data mapped."""
    machine = replay.Machine(64)
    image = replay.load_pe(machine, module, base=BASE, name="PchSmiDispatcher")
    machine.map(DATA, DATA_SIZE, "data")
    smm = replay.SmmServices(machine)
    allocations = []

    def allocate(call):
        size, out = call.arg(1), call.arg(2)
        if call.arg(0) != 6 or size != 0xD0:
            raise replay.ReplayError("SmmAllocatePool: expected type 6 size 0xd0 | received type %d size %#x" % (call.arg(0), size))
        record = machine.allocate(size, fill=0xA5)
        machine.write_pointer(out, record)
        allocations.append(record)
        return 0

    smm.handle("SmmAllocatePool", allocate)
    smm.handle("SmmFreePool", lambda call: 0)
    # The module keeps SMST and PMBASE in globals; their RVAs differ by 0x20 between boards,
    # so read both operands from the RIP-relative loads they are used through.
    code = machine.read(image.address(0), min(0x6000, image.size))
    if code[0x39B2:0x39B5] != bytes.fromhex("488b05") or code[0x4553:0x4555] != bytes.fromhex("8b15"):
        raise replay.ReplayError("PchSmiDispatcher %s: expected the reviewed registration code | received other bytes" % image.sha256)
    smst_rva = 0x39B9 + struct.unpack_from("<i", code, 0x39B5)[0]
    pmbase_rva = 0x4559 + struct.unpack_from("<i", code, 0x4555)[0]
    machine.write(image.address(smst_rva), q(smm.table))
    machine.write(image.address(pmbase_rva), struct.pack("<I", 0x400))
    machine.write(image.address(LIST_HEAD_RVA), q(image.address(LIST_HEAD_RVA)) * 2)
    for rva, value in STUBBED.items():
        machine.stub(image.address(rva), lambda call, value=value: value, "helper_%x" % rva)
    return machine, image, allocations


def register(module, kind, payload, gap):
    width = WIDTHS[kind]
    assert len(payload) == width
    machine, image, allocations = prepare(module)
    context = DATA + DATA_SIZE - width - gap  # only `gap` readable bytes follow the context
    machine.write(context, payload + bytes([0xA5]) * gap)
    machine.write(DATA, q(0x123456789ABCDEF0))
    handler = machine.new_stub(lambda call: 0, "callback")
    this = image.address(CLASS_TABLE_RVA + kind * CLASS_STRIDE + CLASS_THIS_OFFSET)
    result = machine.call(image.address(REGISTER_RVA), this, handler, context, DATA, budget=100_000, capture_fault=True)
    fault = result.fault
    return {
        "class": kind,
        "width": width,
        "gap": gap,
        "context": payload.hex(),
        "outcome": "unmapped-context-read" if fault else "returned",
        "status": None if fault else result.value,
        "fault_rva": None if not fault else fault["rip"] - image.base,
        "records_allocated": len(allocations),
    }


def main():
    paths = replay.modules()
    if len(paths) != 1:
        raise SystemExit("--module: expected one PchSmiDispatcher module | received %d" % len(paths))
    module = open(paths[0], "rb").read()
    mismatches = 0
    cases = 0
    for kind, payload, accepted in payloads():
        for gap in GAPS:
            row = register(module, kind, payload, gap)
            short = WIDTHS[kind] + gap < 16
            expected = "unmapped-context-read" if short else "returned"
            expected_status = None if short else (EFI_SUCCESS if accepted else EFI_INVALID_PARAMETER)
            row["expected"] = expected
            row["expected_status"] = expected_status
            row["ok"] = (
                row["outcome"] == expected
                and row["status"] == expected_status
                and (not short or row["fault_rva"] == FIRST_COPY_RVA)
            )
            mismatches += not row["ok"]
            cases += 1
            replay.emit(row)
    replay.emit({"summary": True, "cases": cases, "mismatches": mismatches, "passed": mismatches == 0})


if __name__ == "__main__":
    main()
