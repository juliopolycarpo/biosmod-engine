"""bme_replay: replay firmware modules against simulated hardware.

MIT licensed, part of biosmod-engine. The package needs `unicorn`, `capstone` and `pefile`,
which `bme tools setup replay` installs into a separate environment; this package contains
no emulator code.

A harness script loads a module, attaches device models, calls a function and reports what
happened:

    import bme_replay as replay

    machine = replay.Machine(64)
    image = replay.load_pe(machine, open(replay.modules()[0], "rb").read(), base=0x10000000)
    machine.ports.attach(replay.PortRegisters({0x404: 0}), [0x404], "pm1")
    result = machine.call(image.address(0x1658), budget=100_000)
    replay.emit({"value": result.value, "digest": machine.trace.digest()})

`bme replay script harness.py --module Driver.pe -- args` runs it and records the emitted
documents in an evidence record.
"""

import json
import os
import sys

from . import devices
from .devices import IndexedRegisters, PortRegisters, RegisterFile
from .errors import (
    AbiViolation,
    BudgetExceeded,
    EmulationFault,
    ImageError,
    ReplayError,
    UnmodeledAccess,
    UnmodeledService,
)
from .machine import CallResult, Machine, StubCall, pack
from .msr import MsrBus
from .pe import Image, load_pe
from .ports import PortBus
from .services import (
    DxeServices,
    PeiServices,
    SmmServices,
    VariableStore,
    format_guid,
    parse_guid,
)
from .smbus import SmbusDevice, SmbusNack, SmbusSlave, SpdEeprom, SpdPageSelect
from .trace import Trace

__all__ = [
    "AbiViolation", "BudgetExceeded", "CallResult", "DxeServices", "EmulationFault", "Image",
    "ImageError", "IndexedRegisters", "Machine", "MsrBus", "PeiServices", "PortBus",
    "PortRegisters", "RegisterFile", "ReplayError", "SmbusDevice", "SmbusNack", "SmbusSlave",
    "SmmServices", "SpdEeprom", "SpdPageSelect", "StubCall", "Trace", "UnmodeledAccess",
    "UnmodeledService", "VariableStore", "devices", "emit", "format_guid", "load_pe",
    "modules", "pack", "parse_guid",
]

#: Environment variable naming the file `emit` appends to.
RESULT_ENV = "BME_REPLAY_RESULT"

#: Module paths given with `--module`; set by `python -m bme_replay`.
_modules = []


def modules():
    """Paths passed with `bme replay script --module`, in order.

    Example: `replay.modules()[0]` is the first `--module` path.
    """
    return list(_modules)


def emit(document):
    """Report one JSON document to bme.

    The document is appended as a line to the file named by `BME_REPLAY_RESULT`; without that
    variable it goes to standard output. bme keeps every emitted document in the evidence
    record, in order.

    Example: `replay.emit({"case": 3, "passed": True})`.
    """
    line = json.dumps(document, sort_keys=True, separators=(",", ":"), default=_json_default)
    path = os.environ.get(RESULT_ENV)
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    else:
        sys.stdout.write(line + "\n")


def _json_default(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if hasattr(value, "as_dict"):
        return value.as_dict()
    raise TypeError("emit: expected a JSON value | received %s" % type(value).__name__)
