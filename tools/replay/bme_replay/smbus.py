"""SMBus: a PCH-style host controller on I/O ports and the slaves behind it.

`SmbusDevice` decodes the host registers (status, control, command, slave address, data)
and runs each started transaction against a `SmbusSlave`. A missing slave sets the
device-error status bit, which is what a real controller reports after a NACK.
"""

from .errors import ReplayError

HST_STS, HST_CNT, HST_CMD, XMIT_SLVA, HST_D0, HST_D1, HOST_BLOCK_DB = range(7)
STS_BUSY, STS_INTR, STS_DEV_ERR = 0x01, 0x02, 0x04
CNT_START = 0x40
PROTOCOLS = {0: "quick", 1: "byte", 2: "byte-data", 3: "word-data", 5: "block"}


class SmbusNack(Exception):
    """Raised by a slave to refuse a transaction."""


class SmbusSlave:
    """Base class: every access is refused until a subclass handles it."""

    def read_byte(self, command):
        raise SmbusNack()

    def write_byte(self, command, value):
        raise SmbusNack()

    def quick(self, write):
        raise SmbusNack()


class SpdEeprom(SmbusSlave):
    """A DDR4 SPD EEPROM image behind its 0x50+slot address.

    `data` is 256 or 512 bytes; pages are 256 bytes. The page select addresses (0x36 for
    page 0, 0x37 for page 1) are modeled by `SpdPageSelect`, which shares this object.

    Example: `SpdEeprom(bytes(512))`; `eeprom.read_byte(0x02)`.
    """

    def __init__(self, data):
        if len(data) not in (256, 512):
            raise ReplayError("spd size: expected 256 | 512 bytes | received %d" % len(data))
        self.data = bytearray(data)
        self.page = 0

    def read_byte(self, command):
        return self.data[self.page * 256 + command]

    def write_byte(self, command, value):
        self.data[self.page * 256 + command] = value


class SpdPageSelect(SmbusSlave):
    """The SPA0/SPA1 page-select addresses of a DDR4 SPD: a quick write selects the page."""

    def __init__(self, eeprom, page):
        self.eeprom = eeprom
        self.page = page

    def quick(self, write):
        if write:
            self.eeprom.page = self.page


class SmbusDevice:
    """PCH SMBus host controller on eight consecutive ports starting at `base`.

    `slaves` maps a 7-bit address to a `SmbusSlave`. Supported protocols: quick, byte,
    byte data and word data. Every transaction is traced as `smbus`.

    Example: `SmbusDevice(0xF000, {0x50: SpdEeprom(spd)})` and `machine.ports.attach(device, device.ports())`.
    """

    def __init__(self, base, slaves, trace=None):
        self.base = base
        self.slaves = dict(slaves)
        self.trace = trace
        self.registers = [0] * 8

    def ports(self):
        return range(self.base, self.base + 8)

    def port_read(self, port, size):
        return self.registers[port - self.base]

    def port_write(self, port, size, value):
        offset = port - self.base
        if offset == HST_STS:
            self.registers[HST_STS] &= ~value & 0xFF  # write one to clear
        elif offset == HST_CNT:
            self.registers[HST_CNT] = value & ~CNT_START & 0xFF
            if value & CNT_START:
                self._transact()
        else:
            self.registers[offset] = value & 0xFF

    def _transact(self):
        registers = self.registers
        protocol = PROTOCOLS.get((registers[HST_CNT] >> 2) & 7)
        address, read = registers[XMIT_SLVA] >> 1, bool(registers[XMIT_SLVA] & 1)
        command = registers[HST_CMD]
        slave = self.slaves.get(address)
        event = {"address": address, "read": read, "protocol": protocol, "command": command}
        try:
            if slave is None or protocol is None:
                raise SmbusNack()
            if protocol == "quick":
                slave.quick(not read)
            elif protocol in ("byte", "byte-data"):
                if read:
                    registers[HST_D0] = slave.read_byte(command)
                else:
                    slave.write_byte(command, registers[HST_D0])
            elif protocol == "word-data":
                if read:
                    registers[HST_D0] = slave.read_byte(command)
                    registers[HST_D1] = slave.read_byte(command + 1)
                else:
                    slave.write_byte(command, registers[HST_D0])
                    slave.write_byte(command + 1, registers[HST_D1])
            else:
                raise SmbusNack()
            registers[HST_STS] = STS_INTR
            event["status"] = "ok"
        except SmbusNack:
            registers[HST_STS] = STS_DEV_ERR
            event["status"] = "nack"
        if self.trace is not None:
            self.trace.add("smbus", **event)
