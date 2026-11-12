"""Run a `bme.scenario/1` document: one entry point of one module against modeled hardware.

`bme replay run` validates the document and the module digest, then starts this module as
`python -m bme_replay --scenario FILE --module PE`. The run emits one document per
expectation (`{"scenario", "expectation", "kind", "passed", "expected", "received"}`) and a
last `{"scenario", "summary": true, "passed", ...}` document.
"""

import hashlib
import json

from . import devices
from .errors import ReplayError
from .machine import Machine
from .pe import load_pe
from .services import DxeServices, PeiServices, SmmServices, VariableStore

SCHEMA = "bme.scenario/1"

#: Where a module is mapped unless the scenario gives `module.base`.
DEFAULT_BASE = 0x1000_0000

#: Names an entry argument or a binding may use instead of a number.
SYMBOLS = (
    "image-base",
    "system-table",
    "boot-services",
    "runtime-services",
    "smm-table",
    "pei-services",
)


def word(value):
    """An integer from a JSON integer or a `0x` string.

    Example: `word("0x1658")` and `word(5720)` are both 5720.
    """
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ReplayError("number: expected an integer or a 0x string | received %r" % (value,))
    return value if isinstance(value, int) else int(value, 0)


class Setup:
    """A machine built from a scenario: image, devices, variables, services and symbols."""

    def __init__(self, scenario, data):
        module = scenario["module"]
        digest = hashlib.sha256(data).hexdigest()
        if digest != module["sha256"]:
            raise ReplayError("module sha256: expected %s | received %s" % (module["sha256"], digest))
        self.machine = Machine(module["bitness"])
        self.image = load_pe(
            self.machine,
            data,
            base=word(module.get("base", DEFAULT_BASE)),
            name=module.get("name", "module"),
            bitness=module["bitness"],
        )
        self.devices = {}
        for spec in scenario.get("hardware", []):
            self._attach(spec)
        self.variables = VariableStore()
        for spec in scenario.get("variables", []):
            self.variables.set(
                spec["name"], spec["guid"], bytes.fromhex(spec["data"]), spec.get("attributes", 7)
            )
        self.services = None
        self.symbols = {"image-base": self.image.base}
        self._services(scenario.get("services"))

    def _attach(self, spec):
        device = devices.build(spec["kind"], spec.get("options", {}))
        name = spec["name"]
        if spec["kind"] == "mmio-registers":
            self.machine.mmio(word(spec["base"]), word(spec["size"]), device, name)
        else:
            self.machine.ports.attach(device, device.ports(), name)
        self.devices[name] = device

    def _services(self, spec):
        if spec is None:
            return
        kind = spec["kind"]
        if kind == "dxe":
            self.services = DxeServices(self.machine, self.variables)
            self.symbols.update(
                {
                    "system-table": self.services.system_table,
                    "boot-services": self.services.boot.address,
                    "runtime-services": self.services.runtime.address,
                }
            )
        elif kind == "smm":
            self.services = SmmServices(self.machine, self.variables)
            self.symbols["smm-table"] = self.services.table
        elif kind == "pei":
            self.services = PeiServices(self.machine)
            self.symbols["pei-services"] = self.services.services
        else:
            raise ReplayError("services kind: expected dxe | smm | pei | received %r" % (kind,))
        for binding in spec.get("bind", []):
            self.machine.write_pointer(self.image.address(word(binding["rva"])), self.symbol(binding["to"]))

    def symbol(self, name):
        try:
            return self.symbols[name]
        except KeyError:
            raise ReplayError(
                "symbol %r: expected one the scenario's services provide (%s) | received none"
                % (name, ", ".join(sorted(self.symbols)))
            ) from None

    def operand(self, value):
        """An entry argument: a number, a `0x` string or a symbol name."""
        if isinstance(value, str) and value in SYMBOLS:
            return self.symbol(value)
        return word(value)

    def service_calls(self, name):
        """Argument lists of every call to service `name`, across the service tables."""
        found = []
        for table in _tables(self.services):
            found.extend(table.called(name))
        return found


def _tables(services):
    if services is None:
        return []
    return [getattr(services, attr) for attr in ("boot", "runtime", "table_") if hasattr(services, attr)]


def _register(setup, spec):
    device = _device(setup, spec, "indexed-registers")
    value = device.register(word(spec.get("bank", 0)), word(spec["index"]))
    mask = word(spec.get("mask", 0xFF))
    return value & mask, word(spec["equals"])


def _port(setup, spec):
    device = _device(setup, spec, "port-registers")
    return device.values.get(word(spec["port"])), word(spec["equals"])


def _device(setup, spec, kind):
    try:
        return setup.devices[spec["device"]]
    except KeyError:
        raise ReplayError(
            "expectation device %r: expected a %s device the scenario declares | received none"
            % (spec["device"], kind)
        ) from None


def _variable(setup, spec):
    found = setup.variables.get(spec["name"], spec["guid"])
    return (None if found is None else found[1].hex()), spec["equals"].lower()


def _service_calls(setup, spec):
    return len(setup.service_calls(spec["service"])), word(spec["count"])


def evaluate(setup, result, spec):
    """`(received, expected)` of one expectation against a finished call.

    Example: `{"kind": "return", "equals": 7}` after a routine returned 7 gives `(7, 7)`.
    """
    kind = spec["kind"]
    if kind == "return":
        return result.value, word(spec["equals"])
    if kind == "register":
        return _register(setup, spec)
    if kind == "port":
        return _port(setup, spec)
    if kind == "variable":
        return _variable(setup, spec)
    if kind == "service-calls":
        return _service_calls(setup, spec)
    raise ReplayError("expectation kind: expected return | register | port | variable | service-calls | received %r" % (kind,))


def run(scenario, data, emit):
    """Run `scenario` against the module bytes `data`, reporting each document through `emit`.

    Returns the summary document. A fault, an unmodeled access or a blown budget fails the
    scenario and is named in `error`; the expectations then report `received: null`.
    """
    if scenario.get("schema") != SCHEMA:
        raise ReplayError("scenario schema: expected %s | received %r" % (SCHEMA, scenario.get("schema")))
    setup = Setup(scenario, data)
    entry = scenario["entry"]
    args = [setup.operand(a) for a in entry.get("args", [])]
    error = result = None
    try:
        result = setup.machine.call(
            setup.image.address(word(entry["rva"])),
            *args,
            budget=scenario["budget"],
            capture_fault=True,
        )
        if result.fault is not None:
            error = "fault %s at %#x (rip %#x)" % (
                result.fault["kind"],
                result.fault.get("address", 0),
                result.fault["rip"],
            )
    except ReplayError as caught:
        error = "%s: %s" % (type(caught).__name__, caught)
    all_passed = error is None
    for index, spec in enumerate(scenario["expect"]):
        document = {"scenario": scenario["id"], "expectation": index, "kind": spec["kind"]}
        if error is None:
            received, expected = evaluate(setup, result, spec)
            passed = received == expected
        else:
            received, expected, passed = None, None, False
        document.update(passed=passed, expected=expected, received=received)
        all_passed = all_passed and passed
        emit(document)
    summary = {
        "scenario": scenario["id"],
        "summary": True,
        "passed": all_passed,
        "instructions": None if result is None else result.instructions,
        "return": None if result is None else result.value,
        "trace_sha256": setup.machine.trace.digest(),
    }
    if error is not None:
        summary["error"] = error
    emit(summary)
    return summary


def run_file(path, modules, emit):
    """Load the scenario at `path` and run it against the single module in `modules`."""
    if len(modules) != 1:
        raise ReplayError("scenario modules: expected exactly one --module | received %d" % len(modules))
    with open(path, encoding="utf-8") as handle:
        scenario = json.load(handle)
    with open(modules[0], "rb") as handle:
        data = handle.read()
    return run(scenario, data, emit)
