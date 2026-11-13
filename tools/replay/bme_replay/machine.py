"""The emulated machine: one Unicorn instance plus the models firmware talks to.

`Machine` owns memory, a stack, a stop address, the port, MMIO and MSR buses, address
stubs that stand in for firmware services, and the event trace. It runs one function at a
time with `call`, using the Microsoft x64 convention for 64-bit images and cdecl for IA32.
"""

import struct

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INSN,
    UC_HOOK_MEM_READ_PROT,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_PROT,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_PROT,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_MEM_FETCH_PROT,
    UC_MEM_FETCH_UNMAPPED,
    UC_MEM_READ_PROT,
    UC_MEM_READ_UNMAPPED,
    UC_MEM_WRITE_PROT,
    UC_MEM_WRITE_UNMAPPED,
    UC_MODE_32,
    UC_MODE_64,
    Uc,
    UcError,
)
from unicorn import x86_const as x86

from .errors import (
    AbiViolation,
    BudgetExceeded,
    EmulationFault,
    ReplayError,
    UnmodeledAccess,
)
from .ports import PortBus
from .trace import Trace

PAGE = 0x1000
# Default scratch layout; images normally sit elsewhere (PEI images at their XIP base).
STACK_BASE, STACK_SIZE = 0x0600_0000, 0x0010_0000
HEAP_BASE, HEAP_SIZE = 0x0700_0000, 0x0040_0000
STOP_ADDRESS = 0x0800_0000
STUB_BASE, STUB_SIZE = 0x0900_0000, 0x0001_0000

X64_ARGUMENTS = (x86.UC_X86_REG_RCX, x86.UC_X86_REG_RDX, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9)
X64_NONVOLATILE = (
    x86.UC_X86_REG_RBX,
    x86.UC_X86_REG_RBP,
    x86.UC_X86_REG_RSI,
    x86.UC_X86_REG_RDI,
    x86.UC_X86_REG_R12,
    x86.UC_X86_REG_R13,
    x86.UC_X86_REG_R14,
    x86.UC_X86_REG_R15,
)
X64_VOLATILE = (
    x86.UC_X86_REG_RCX,
    x86.UC_X86_REG_RDX,
    x86.UC_X86_REG_R8,
    x86.UC_X86_REG_R9,
    x86.UC_X86_REG_R10,
    x86.UC_X86_REG_R11,
)
IA32_NONVOLATILE = (x86.UC_X86_REG_EBX, x86.UC_X86_REG_ESI, x86.UC_X86_REG_EDI, x86.UC_X86_REG_EBP)
IA32_VOLATILE = (x86.UC_X86_REG_ECX, x86.UC_X86_REG_EDX)
XMM_NONVOLATILE = tuple(getattr(x86, "UC_X86_REG_XMM%d" % n) for n in range(6, 16))
XMM_VOLATILE = tuple(getattr(x86, "UC_X86_REG_XMM%d" % n) for n in range(0, 6))

# The fault hook receives a UC_MEM_* access type, not the UC_HOOK_* it was registered under.
_FAULT_KINDS = {
    UC_MEM_READ_UNMAPPED: "read-unmapped",
    UC_MEM_WRITE_UNMAPPED: "write-unmapped",
    UC_MEM_FETCH_UNMAPPED: "fetch-unmapped",
    UC_MEM_READ_PROT: "read-protected",
    UC_MEM_WRITE_PROT: "write-protected",
    UC_MEM_FETCH_PROT: "fetch-protected",
}
_FAULT_HOOKS = (
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_READ_PROT,
    UC_HOOK_MEM_WRITE_PROT,
    UC_HOOK_MEM_FETCH_PROT,
)


def _register(name):
    return getattr(x86, "UC_X86_REG_" + name.upper())


class StubCall:
    """What a stub handler sees: the machine and the ABI arguments of the intercepted call."""

    def __init__(self, machine, name, address):
        self.machine = machine
        self.name = name
        self.address = address

    def arg(self, index):
        """Argument `index` (0-based) under the machine's calling convention."""
        return self.machine.argument(index)

    def args(self, count):
        return [self.arg(i) for i in range(count)]

    @property
    def caller(self):
        """Address the intercepted call returns to, i.e. the instruction after the `call`."""
        return self.machine.read_pointer(self.machine.register("rsp" if self.machine.bitness == 64 else "esp"))


class CallResult:
    """Outcome of `Machine.call`: `.value` (None after a captured fault), `.instructions`, `.fault`."""

    def __init__(self, value, instructions, fault=None):
        self.value = value
        self.instructions = instructions
        self.fault = fault

    def as_dict(self):
        return {"value": self.value, "instructions": self.instructions, "fault": self.fault}


class Machine:
    """An x86 machine for one image family.

    Example: `machine = Machine(64)` for DXE and SMM drivers, `Machine(32)` for PEI modules.
    """

    def __init__(self, bitness=64, *, trace=None, stack_bytes=0x1000):
        if bitness not in (32, 64):
            raise ReplayError("bitness: expected 32 | 64 | received %r" % (bitness,))
        self.bitness = bitness
        self.pointer = bitness // 8
        self.mask = (1 << bitness) - 1
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64 if bitness == 64 else UC_MODE_32)
        self.trace = trace if trace is not None else Trace()
        self.ports = PortBus(self.trace)
        self.msrs = None  # set by `attach_msrs`
        self.regions = []
        self.instructions = 0
        self._stubs = {}
        self._next_stub = STUB_BASE
        self._heap_next = HEAP_BASE
        self._pending = None
        self._fault = None
        self._stack_bytes = stack_bytes
        self.map(STACK_BASE, STACK_SIZE, "stack")
        self.map(HEAP_BASE, HEAP_SIZE, "heap")
        self.map(STOP_ADDRESS, PAGE, "stop")
        self.map(STUB_BASE, STUB_SIZE, "stubs")
        self.uc.mem_write(STUB_BASE, b"\xc3" * STUB_SIZE)
        self.uc.hook_add(UC_HOOK_CODE, self._guard(self._on_code))
        self.uc.hook_add(UC_HOOK_INSN, self._guard(self._on_port_in), None, 1, 0, x86.UC_X86_INS_IN)
        self.uc.hook_add(UC_HOOK_INSN, self._guard(self._on_port_out), None, 1, 0, x86.UC_X86_INS_OUT)
        for hook in _FAULT_HOOKS:
            self.uc.hook_add(hook, self._on_fault)

    # -- memory ---------------------------------------------------------------------------

    def map(self, address, size, name="region"):
        """Map zeroed memory; the range is widened to whole pages and may not overlap another."""
        start = address & ~(PAGE - 1)
        end = (address + size + PAGE - 1) & ~(PAGE - 1)
        for other_start, other_end, other in self.regions:
            if start < other_end and other_start < end:
                raise ReplayError(
                    "map %s %#x-%#x: expected a free range | received overlap with %s %#x-%#x"
                    % (name, start, end, other, other_start, other_end)
                )
        self.uc.mem_map(start, end - start)
        self.regions.append((start, end, name))
        return start

    def mmio(self, base, size, device, name="mmio"):
        """Map `device` over `[base, base + size)`; it gets `read(offset, size)` and `write(offset, size, value)`.

        Example: `machine.mmio(0xFED1C000, 0x1000, RegisterFile({0x3418: 0}), "rcba")`.
        """
        start = base & ~(PAGE - 1)
        end = (base + size + PAGE - 1) & ~(PAGE - 1)
        for other_start, other_end, other in self.regions:
            if start < other_end and other_start < end:
                raise ReplayError(
                    "mmio %s %#x-%#x: expected a free range | received overlap with %s"
                    % (name, start, end, other)
                )

        def read(uc, offset, width, _):
            try:
                value = device.read(offset, width)
            except BaseException as error:  # noqa: BLE001 - re-raised after emulation stops
                self._abort(error)
                return 0
            self.trace.add("mmio-read", device=name, offset=offset, size=width, value=value)
            return value

        def write(uc, offset, width, value, _):
            self.trace.add("mmio-write", device=name, offset=offset, size=width, value=value)
            try:
                device.write(offset, width, value)
            except BaseException as error:  # noqa: BLE001
                self._abort(error)

        self.uc.mmio_map(start, end - start, read, None, write, None)
        self.regions.append((start, end, name))
        return device

    def read(self, address, size):
        return bytes(self.uc.mem_read(address, size))

    def write(self, address, data):
        self.uc.mem_write(address, bytes(data))

    def read_uint(self, address, size):
        return int.from_bytes(self.read(address, size), "little")

    def write_uint(self, address, size, value):
        self.write(address, (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little"))

    def read_pointer(self, address):
        return self.read_uint(address, self.pointer)

    def write_pointer(self, address, value):
        self.write_uint(address, self.pointer, value)

    def read_utf16(self, address, limit=512):
        """A NUL-terminated UTF-16LE string, e.g. a variable name."""
        raw = bytearray()
        while len(raw) < 2 * limit:
            pair = self.read(address + len(raw), 2)
            if pair == b"\0\0":
                return raw.decode("utf-16le")
            raw += pair
        raise ReplayError("utf-16 string at %#x: expected a terminator within %d characters" % (address, limit))

    def allocate(self, size, fill=0, align=16):
        """Bump-allocate `size` bytes from the machine heap, filled with `fill`."""
        address = (self._heap_next + align - 1) & ~(align - 1)
        if address + size > HEAP_BASE + HEAP_SIZE:
            raise ReplayError("heap: expected %d free bytes | received %d" % (size, HEAP_BASE + HEAP_SIZE - address))
        self._heap_next = address + size
        self.write(address, bytes([fill]) * size)
        return address

    def register(self, name):
        return self.uc.reg_read(_register(name))

    def set_register(self, name, value):
        self.uc.reg_write(_register(name), value)

    # -- stubs ----------------------------------------------------------------------------

    def stub(self, address, handler, name=None, pops=0):
        """Intercept execution at `address`: run `handler(call)`, then return its value to the caller.

        `pops` is the number of argument bytes a stdcall callee removes (IA32 only).
        Example: `machine.stub(image.address(0x1234), lambda call: 0, "ReportStatusCode")`.
        """
        self._stubs[address] = (handler, name or "stub_%x" % address, pops)

    def new_stub(self, handler, name, pops=0):
        """A fresh stub address in the stub region, for service table entries."""
        address = self._next_stub
        self._next_stub += 16
        if self._next_stub > STUB_BASE + STUB_SIZE:
            raise ReplayError("stub region: expected a free slot | received %d stubs" % len(self._stubs))
        self.stub(address, handler, name, pops)
        return address

    def argument(self, index):
        """Argument `index` of the call being intercepted (valid inside a stub handler)."""
        sp = self.register("rsp" if self.bitness == 64 else "esp")
        if self.bitness == 64:
            if index < 4:
                return self.uc.reg_read(X64_ARGUMENTS[index])
            return self.read_uint(sp + 8 + 0x20 + 8 * (index - 4), 8)
        return self.read_uint(sp + 4 + 4 * index, 4)

    def return_from_stub(self, value, pops=0):
        """Pop the return address, set the result and clobber caller-saved state like a real callee."""
        uc = self.uc
        if self.bitness == 64:
            sp = uc.reg_read(x86.UC_X86_REG_RSP)
            target = self.read_uint(sp, 8)
            for n, register in enumerate(X64_VOLATILE):
                uc.reg_write(register, 0xA1B2C3D405060708 + n * 0x1010101)
            for n, register in enumerate(XMM_VOLATILE):
                uc.reg_write(register, 0xA5A5A5A5 + n)
            uc.reg_write(x86.UC_X86_REG_RAX, value & self.mask)
            uc.reg_write(x86.UC_X86_REG_RSP, sp + 8)
            uc.reg_write(x86.UC_X86_REG_RIP, target)
        else:
            sp = uc.reg_read(x86.UC_X86_REG_ESP)
            target = self.read_uint(sp, 4)
            for n, register in enumerate(IA32_VOLATILE):
                uc.reg_write(register, 0xA1B2C3D4 + n)
            uc.reg_write(x86.UC_X86_REG_EAX, value & self.mask)
            uc.reg_write(x86.UC_X86_REG_ESP, sp + 4 + pops)
            uc.reg_write(x86.UC_X86_REG_EIP, target)

    # -- model hooks ----------------------------------------------------------------------

    def attach_msrs(self, bus):
        """Route RDMSR and WRMSR to `bus` (`MsrBus`)."""
        self.msrs = bus

    def _abort(self, error):
        if self._pending is None:
            self._pending = error
        self.uc.emu_stop()

    def _guard(self, function):
        """Wrap a hook so an exception stops emulation and re-raises after `emu_start` returns."""

        def hook(*args):
            try:
                return function(*args)
            except BaseException as error:  # noqa: BLE001
                self._abort(error)
                return 0

        return hook

    def _on_fault(self, uc, access, address, size, value, user):
        pc = uc.reg_read(x86.UC_X86_REG_RIP if self.bitness == 64 else x86.UC_X86_REG_EIP)
        self._fault = {
            "kind": _FAULT_KINDS.get(access, "memory-fault"),
            "address": address,
            "size": size,
            "rip": pc,
        }
        return False

    def _on_code(self, uc, address, size, user):
        self.instructions += 1
        stub = self._stubs.get(address)
        if stub is not None:
            handler, name, pops = stub
            value = handler(StubCall(self, name, address))
            self.return_from_stub(0 if value is None else value, pops)
            return
        if size == 2 and self.msrs is not None:
            opcode = self.read(address, 2)
            if opcode == b"\x0f\x32":
                value = self.msrs.read(uc.reg_read(x86.UC_X86_REG_ECX))
                uc.reg_write(x86.UC_X86_REG_EAX, value & 0xFFFFFFFF)
                uc.reg_write(x86.UC_X86_REG_EDX, value >> 32)
                self._skip(address + 2)
            elif opcode == b"\x0f\x30":
                value = (uc.reg_read(x86.UC_X86_REG_EDX) << 32) | uc.reg_read(x86.UC_X86_REG_EAX)
                self.msrs.write(uc.reg_read(x86.UC_X86_REG_ECX), value)
                self._skip(address + 2)

    def _skip(self, address):
        self.uc.reg_write(x86.UC_X86_REG_RIP if self.bitness == 64 else x86.UC_X86_REG_EIP, address)

    def _on_port_in(self, uc, port, size, user):
        return self.ports.read(port, size)

    def _on_port_out(self, uc, port, size, value, user):
        self.ports.write(port, size, value)

    # -- calling convention ---------------------------------------------------------------

    def call(self, entry, *args, budget=1_000_000, seed=0, check_abi=True, capture_fault=False):
        """Run the function at `entry` with `args` until it returns, and give back its result.

        64-bit machines use the Microsoft x64 convention (RCX, RDX, R8, R9, then the stack),
        32-bit machines use cdecl. The function returns to a stop address; with `check_abi`
        the callee-saved registers and stack pointer must come back unchanged. A call that
        does not return within `budget` instructions raises `BudgetExceeded`. A memory
        fault raises `EmulationFault`, or is returned in `CallResult.fault` when
        `capture_fault` is true.

        Example: `machine.call(image.address(0x1658)).value` is the routine's EAX/RAX.
        """
        uc = self.uc
        wide = self.bitness == 64
        sp_register = x86.UC_X86_REG_RSP if wide else x86.UC_X86_REG_ESP
        pc_register = x86.UC_X86_REG_RIP if wide else x86.UC_X86_REG_EIP
        top = STACK_BASE + STACK_SIZE - 0x1000
        self.write(top - self._stack_bytes, bytes([(0x93 ^ seed) & 0xFF]) * (self._stack_bytes + 0x400))
        saved = self._seed_registers(seed)
        if wide:
            sp = top - 8
            self.write_uint(sp, 8, STOP_ADDRESS)
            for index, value in enumerate(args[4:]):
                self.write_uint(sp + 8 + 0x20 + 8 * index, 8, value)
            for register, value in zip(X64_ARGUMENTS, args):
                uc.reg_write(register, value & self.mask)
        else:
            sp = top - 4 * len(args) - 4
            self.write_uint(sp, 4, STOP_ADDRESS)
            for index, value in enumerate(args):
                self.write_uint(sp + 4 + 4 * index, 4, value)
        uc.reg_write(sp_register, sp)
        self.trace.add("call", entry=entry, args=[a & self.mask for a in args])
        before = self.instructions
        self._pending, self._fault = None, None
        error = None
        try:
            uc.emu_start(entry, STOP_ADDRESS, count=budget)
        except UcError as caught:
            error = caught
        if self._pending is not None:
            pending, self._pending = self._pending, None
            raise pending
        executed = self.instructions - before
        if self._fault is not None or error is not None:
            fault = self._fault or {"kind": "unicorn-error", "message": str(error), "rip": uc.reg_read(pc_register)}
            self.trace.add("fault", **{("reason" if key == "kind" else key): value for key, value in fault.items()})
            if capture_fault:
                return CallResult(None, executed, fault)
            raise EmulationFault(
                "call %#x: expected a return to the stop address | received %s at %#x (rip %#x)"
                % (entry, fault["kind"], fault.get("address", 0), fault["rip"]),
                fault,
            )
        if uc.reg_read(pc_register) != STOP_ADDRESS:
            raise BudgetExceeded(
                "call %#x: expected a return within %d instructions | received rip %#x after %d"
                % (entry, budget, uc.reg_read(pc_register), executed)
            )
        if check_abi:
            self._check_abi(saved, sp, seed)
        value = uc.reg_read(x86.UC_X86_REG_RAX if wide else x86.UC_X86_REG_EAX)
        self.trace.add("return", entry=entry, value=value)
        return CallResult(value, executed)

    def _seed_registers(self, seed):
        """Fill callee-saved registers with recognisable values and remember them."""
        saved = {}
        if self.bitness == 64:
            for n, register in enumerate(X64_NONVOLATILE):
                saved[register] = (0x1020304050607080 + n * 0x0101010101010101 + seed) & self.mask
            for n, register in enumerate(XMM_NONVOLATILE):
                saved[register] = 0x0123456789ABCDEF0123456789ABCDEF + n
        else:
            for n, register in enumerate(IA32_NONVOLATILE):
                saved[register] = (0x12345678 + n * 0x01111111 + seed) & self.mask
        for register, value in saved.items():
            self.uc.reg_write(register, value)
        return saved

    def _check_abi(self, saved, sp, seed):
        wide = self.bitness == 64
        sp_now = self.register("rsp" if wide else "esp")
        expected_sp = sp + (8 if wide else 4)
        if sp_now != expected_sp:
            raise AbiViolation("stack pointer: expected %#x | received %#x" % (expected_sp, sp_now))
        for register, value in saved.items():
            now = self.uc.reg_read(register)
            if now != value:
                name = _register_name(register)
                raise AbiViolation("%s: expected %#x preserved | received %#x" % (name, value, now))


def _register_name(constant):
    for name in dir(x86):
        if name.startswith("UC_X86_REG_") and getattr(x86, name) == constant:
            return name[len("UC_X86_REG_"):].lower()
    return str(constant)


def pack(fmt, *values):
    """Little-endian `struct.pack`, e.g. `pack("2I", 3, 0)` for an Sx context."""
    return struct.pack("<" + fmt, *values)
