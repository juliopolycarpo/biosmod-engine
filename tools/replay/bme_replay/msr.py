"""Model-specific registers: RDMSR and WRMSR routed to a table of values or handlers."""

from .errors import UnmodeledAccess


class MsrBus:
    """MSR values by index; an unlisted MSR raises `UnmodeledAccess`.

    `values` maps an MSR index to its initial 64-bit value. `handlers` maps an index to
    `(read, write)` callables for registers with behaviour.

    Example: `MsrBus({0x1B: 0xFEE00900})`; `bus.read(0x1B)` is `0xFEE00900`.
    """

    def __init__(self, values=None, handlers=None, trace=None):
        self.values = dict(values or {})
        self.handlers = dict(handlers or {})
        self.trace = trace

    def read(self, index):
        if index in self.handlers:
            value = self.handlers[index][0]()
        elif index in self.values:
            value = self.values[index]
        else:
            raise UnmodeledAccess("msr %#x read: expected a modeled register | received none" % index)
        if self.trace is not None:
            self.trace.add("msr-read", msr=index, value=value)
        return value

    def write(self, index, value):
        if self.trace is not None:
            self.trace.add("msr-write", msr=index, value=value)
        if index in self.handlers:
            self.handlers[index][1](value)
        elif index in self.values:
            self.values[index] = value
        else:
            raise UnmodeledAccess("msr %#x write: expected a modeled register | received none" % index)
