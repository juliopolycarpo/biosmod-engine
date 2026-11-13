"""Built-in hardware models. Each is a small named fake with observable state.

Ports: `PortRegisters` (flat) and `IndexedRegisters` (index/data pair with optional banks).
MMIO: `RegisterFile`. SMBus lives in `smbus.py`. Scenarios pick these by name through
`LIBRARY`.
"""

from .errors import ReplayError, UnmodeledAccess


def word(value):
    """An integer from a JSON integer or a `0x` string.

    Example: `word("0x1658")` and `word(5720)` are both 5720.
    """
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ReplayError("number: expected an integer or a 0x string | received %r" % (value,))
    return value if isinstance(value, int) else int(value, 0)


class PortRegisters:
    """Flat port registers: reads return the stored value, writes store it.

    `values` maps a port to its initial value; `read_only` lists ports whose writes are
    dropped (and still traced by the bus). Ports not listed in `values` are not claimed.

    Example: `PortRegisters({0x404: 0x1400})`; `device.values[0x404]`.
    """

    def __init__(self, values, read_only=()):
        self.values = dict(values)
        self.read_only = set(read_only)

    def ports(self):
        return sorted(self.values)

    def port_read(self, port, size):
        return self.values[port]

    def port_write(self, port, size, value):
        if port not in self.read_only:
            self.values[port] = value


class IndexedRegisters:
    """An index port plus a data port in front of banked 8-bit registers.

    Super I/O configuration (0x2E/0x2F) and hardware-monitor (0xA25/0xA26) chips work this
    way. With `bank_register` set, writing that index selects a bank and reading it gives
    `high_nibble | bank`, as the NCT55xx hardware monitor does.

    `registers` maps `(bank, index)` to a value; any register not listed reads
    `default`. `seed` fills every register with `(seed + index * 13 + bank * 17) & 255`
    and scrambles the initial index and bank, which is how the research harnesses proved a
    routine does not depend on the power-on state.

    Example: `IndexedRegisters(0xA25, 0xA26, banks=16, bank_register=0x4E, seed=7)`.
    """

    def __init__(
        self,
        index_port,
        data_port,
        *,
        banks=1,
        bank_register=None,
        registers=None,
        default=0,
        seed=None,
        fixed_bank=0,
    ):
        self.index_port = index_port
        self.data_port = data_port
        self.bank_register = bank_register
        self.registers = {}
        self.selected = 0
        self.bank = fixed_bank
        self.high = 0x80 if bank_register is not None else 0
        self.default = default
        if seed is not None:
            for bank in range(banks):
                for index in range(256):
                    self.registers[(bank, index)] = (seed + index * 13 + bank * 17) & 255
            self.selected = seed * 7 % 256
            self.bank = seed % 8 if bank_register is not None else fixed_bank
        for key, value in (registers or {}).items():
            self.registers[tuple(key)] = value & 255

    def ports(self):
        return [self.index_port, self.data_port]

    def port_read(self, port, size):
        if port == self.index_port:
            return self.selected
        if size != 1:
            raise UnmodeledAccess("port %#x read size %d: expected 1 for an indexed data port" % (port, size))
        if self.bank_register is not None and self.selected == self.bank_register:
            return self.high | self.bank
        return self.registers.get((self.bank, self.selected), self.default)

    def port_write(self, port, size, value):
        if port == self.index_port:
            self.selected = value & 255
            return
        if size != 1:
            raise UnmodeledAccess("port %#x write size %d: expected 1 for an indexed data port" % (port, size))
        if self.bank_register is not None and self.selected == self.bank_register:
            self.high, self.bank = value & 0xF0, value & 0x0F
        else:
            self.registers[(self.bank, self.selected)] = value & 255

    def register(self, bank, index):
        """Current value of one register, for assertions on device state."""
        return self.registers.get((bank, index), self.default)


class RegisterFile:
    """MMIO registers by offset; reads of unlisted offsets raise `UnmodeledAccess` unless `default` is set.

    Example: `RegisterFile({0x3418: 0}, default=0)`.
    """

    def __init__(self, values=None, default=None):
        self.values = dict(values or {})
        self.default = default

    def read(self, offset, size):
        if offset in self.values:
            return self.values[offset] & ((1 << (8 * size)) - 1)
        if self.default is None:
            raise UnmodeledAccess("mmio offset %#x read size %d: expected a modeled register | received none" % (offset, size))
        return self.default

    def write(self, offset, size, value):
        self.values[offset] = value & ((1 << (8 * size)) - 1)


def _int_keys(mapping):
    """`{key: value}` with keys and values read through `word` (JSON integers or `0x` strings)."""
    return {word(k): word(v) for k, v in (mapping or {}).items()}


def _build_port_registers(options):
    return PortRegisters(_int_keys(options.get("values")), read_only=[word(p) for p in options.get("read_only", [])])


def _build_indexed_registers(options):
    registers = {}
    for bank, entries in (options.get("registers") or {}).items():
        for index, value in entries.items():
            registers[(word(bank), word(index))] = word(value)
    return IndexedRegisters(
        word(options["index_port"]),
        word(options["data_port"]),
        banks=word(options.get("banks", 1)),
        bank_register=_optional(options.get("bank_register")),
        registers=registers,
        default=word(options.get("default", 0)),
        seed=_optional(options.get("seed")),
        fixed_bank=word(options.get("fixed_bank", 0)),
    )


def _optional(value):
    return None if value is None else word(value)


def _build_register_file(options):
    return RegisterFile(_int_keys(options.get("values")), default=_optional(options.get("default")))


#: Device kinds a scenario can name: kind -> factory(options dict) -> device.
LIBRARY = {
    "port-registers": _build_port_registers,
    "indexed-registers": _build_indexed_registers,
    "mmio-registers": _build_register_file,
}


def build(kind, options):
    """Instantiate a library device, e.g. `build("port-registers", {"values": {"0x404": 0}})`."""
    try:
        factory = LIBRARY[kind]
    except KeyError:
        raise ReplayError("device kind %r: expected one of %s" % (kind, sorted(LIBRARY))) from None
    return factory(options)
