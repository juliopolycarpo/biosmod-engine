"""Port I/O: a bus that routes IN and OUT to named device models.

Nothing reaches the host. A port no device claims raises `UnmodeledAccess`, so a harness
states every port the firmware may touch.
"""

from .errors import ReplayError, UnmodeledAccess


class PortBus:
    """Routes `in`/`out` instructions to the device attached to the port.

    A device provides `port_read(port, size)` and `port_write(port, size, value)`. Every
    access is appended to the trace as `port-in` or `port-out`.

    Example: `bus.attach(PortRegisters({0x404: 0}), [0x404], "pm1-control")`.
    """

    def __init__(self, trace):
        self.trace = trace
        self._devices = {}
        self.names = {}

    def attach(self, device, ports, name=None):
        """Claim `ports` (an iterable of port numbers) for `device`."""
        label = name or type(device).__name__
        for port in ports:
            if port in self._devices:
                raise ReplayError(
                    "port %#x: expected a free port | received it claimed by %s" % (port, self.names[port])
                )
            self._devices[port] = device
            self.names[port] = label
        return device

    def _device(self, port, size, what):
        device = self._devices.get(port)
        if device is None:
            raise UnmodeledAccess("port %#x %s size %d: expected a device model | received none" % (port, what, size))
        return device

    def read(self, port, size):
        device = self._device(port, size, "read")
        value = device.port_read(port, size) & ((1 << (8 * size)) - 1)
        self.trace.add("port-in", port=port, size=size, value=value, device=self.names[port])
        return value

    def write(self, port, size, value):
        device = self._device(port, size, "write")
        value &= (1 << (8 * size)) - 1
        self.trace.add("port-out", port=port, size=size, value=value, device=self.names[port])
        device.port_write(port, size, value)

    def writes(self, port=None):
        """Recorded `port-out` events, optionally for one port: `[(port, size, value), ...]`."""
        return [
            (e["port"], e["size"], e["value"])
            for e in self.trace.of_kind("port-out")
            if port is None or e["port"] == port
        ]
