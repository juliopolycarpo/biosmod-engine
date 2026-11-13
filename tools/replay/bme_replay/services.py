"""Fake firmware service tables: PEI services, DXE boot and runtime services, SMM services.

Each table is built in machine memory with one stub per slot. A call runs the handler
registered for that slot, records a `service` event and returns to the caller with the
handler's value. A slot nobody handled raises `UnmodeledService`, so a harness names every
service the firmware may use. Variables live in a `VariableStore`.
"""

import uuid

from .errors import ReplayError, UnmodeledService

EFI_SUCCESS = 0
EFI_BUFFER_TOO_SMALL = 5
EFI_NOT_FOUND = 14
EFI_INVALID_PARAMETER = 2


def parse_guid(text):
    """`bytes_le` of a GUID string, e.g. `parse_guid("4E82091E-32A1-4689-8A00-CDE41ED63CDD")`."""
    return uuid.UUID(text).bytes_le


def format_guid(raw):
    """Lowercase GUID text of 16 raw bytes."""
    return str(uuid.UUID(bytes_le=bytes(raw)))


# Slot name -> byte offset, from the PI and UEFI specifications (64-bit unless noted).
PEI_LAYOUT = {
    name: 0x18 + 4 * index
    for index, name in enumerate(
        [
            "InstallPpi", "ReInstallPpi", "LocatePpi", "NotifyPpi", "GetBootMode", "SetBootMode",
            "GetHobList", "CreateHob", "FfsFindNextVolume", "FfsFindNextFile", "FfsFindSectionData",
            "InstallPeiMemory", "AllocatePages", "AllocatePool", "CopyMem", "SetMem",
            "ReportStatusCode", "ResetSystem",
        ]
    )
}
BOOT_LAYOUT = {
    name: 0x18 + 8 * index
    for index, name in enumerate(
        [
            "RaiseTPL", "RestoreTPL", "AllocatePages", "FreePages", "GetMemoryMap", "AllocatePool",
            "FreePool", "CreateEvent", "SetTimer", "WaitForEvent", "SignalEvent", "CloseEvent",
            "CheckEvent", "InstallProtocolInterface", "ReinstallProtocolInterface",
            "UninstallProtocolInterface", "HandleProtocol", "Reserved", "RegisterProtocolNotify",
            "LocateHandle", "LocateDevicePath", "InstallConfigurationTable", "LoadImage",
            "StartImage", "Exit", "UnloadImage", "ExitBootServices", "GetNextMonotonicCount",
            "Stall", "SetWatchdogTimer", "ConnectController", "DisconnectController",
            "OpenProtocol", "CloseProtocol", "OpenProtocolInformation", "ProtocolsPerHandle",
            "LocateHandleBuffer", "LocateProtocol", "InstallMultipleProtocolInterfaces",
            "UninstallMultipleProtocolInterfaces", "CalculateCrc32", "CopyMem", "SetMem",
            "CreateEventEx",
        ]
    )
}
RUNTIME_LAYOUT = {
    name: 0x18 + 8 * index
    for index, name in enumerate(
        [
            "GetTime", "SetTime", "GetWakeupTime", "SetWakeupTime", "SetVirtualAddressMap",
            "ConvertPointer", "GetVariable", "GetNextVariableName", "SetVariable",
            "GetNextHighMonotonicCount", "ResetSystem", "UpdateCapsule",
            "QueryCapsuleCapabilities", "QueryVariableInfo",
        ]
    )
}
SMM_LAYOUT = {
    "SmmInstallConfigurationTable": 0x28,
    "SmmIoMemRead": 0x30, "SmmIoMemWrite": 0x38, "SmmIoIoRead": 0x40, "SmmIoIoWrite": 0x48,
    "SmmAllocatePool": 0x50, "SmmFreePool": 0x58, "SmmAllocatePages": 0x60, "SmmFreePages": 0x68,
    "SmmStartupThisAp": 0x70,
    "SmmInstallProtocolInterface": 0xA8, "SmmUninstallProtocolInterface": 0xB0,
    "SmmHandleProtocol": 0xB8, "SmmRegisterProtocolNotify": 0xC0, "SmmLocateHandle": 0xC8,
    "SmmLocateProtocol": 0xD0, "SmiManage": 0xD8, "SmiHandlerRegister": 0xE0,
    "SmiHandlerUnRegister": 0xE8,
}


class VariableStore:
    """UEFI variables by name and vendor GUID.

    Example: `VariableStore().set("NCT5532D_SMF", "4e82091e-32a1-4689-8a00-cde41ed63cdd", bytes(28))`.
    """

    def __init__(self):
        self._items = {}

    def set(self, name, guid, data, attributes=7):
        self._items[(name, str(uuid.UUID(guid)))] = (attributes, bytes(data))

    def get(self, name, guid):
        """`(attributes, data)` or None."""
        return self._items.get((name, str(uuid.UUID(guid))))

    def delete(self, name, guid):
        self._items.pop((name, str(uuid.UUID(guid))), None)

    def names(self):
        return sorted(self._items)


class ServiceTable:
    """A table of stubbed function pointers in machine memory.

    `handle(name, handler)` registers `handler(call) -> int`; `call.arg(i)` reads the ABI
    arguments. Calls are traced as `{"kind": "service", "table": ..., "service": ...}`.
    """

    def __init__(self, machine, title, layout, size):
        self.machine = machine
        self.title = title
        self.layout = layout
        self.address = machine.allocate(size)
        self.handlers = {}
        self.calls = []
        for name, offset in layout.items():
            stub = machine.new_stub(self._dispatcher(name), "%s.%s" % (title, name))
            machine.write_pointer(self.address + offset, stub)

    def _dispatcher(self, name):
        def dispatch(call):
            handler = self.handlers.get(name)
            args = call.args(4)
            self.machine.trace.add("service", table=self.title, service=name, args=args, caller=call.caller)
            self.calls.append((name, args))
            if handler is None:
                raise UnmodeledService(
                    "%s.%s%s: expected a handler | received a call" % (self.title, name, tuple(hex(a) for a in args))
                )
            return handler(call)

        return dispatch

    def handle(self, name, handler):
        if name not in self.layout:
            raise ReplayError("%s service %r: expected one of %s" % (self.title, name, sorted(self.layout)))
        self.handlers[name] = handler

    def called(self, name):
        """Argument lists of every call to `name`."""
        return [args for service, args in self.calls if service == name]


class _Common:
    """Handlers shared by boot services and SMM services."""

    def _error(self, code):
        return (1 << (self.machine.bitness - 1)) | code

    def _install_pool_handlers(self, table, allocate, free):
        machine = self.machine

        def allocate_pool(call):
            size, out = call.arg(1), call.arg(2)
            machine.write_pointer(out, machine.allocate(size, fill=0xA5))
            return EFI_SUCCESS

        table.handle(allocate, allocate_pool)
        table.handle(free, lambda call: EFI_SUCCESS)

    def _install_protocol_handlers(self, table, name):
        machine = self.machine

        def locate(call):
            guid, out = format_guid(machine.read(call.arg(0), 16)), call.arg(2)
            interface = self.protocols.get(guid)
            if interface is None:
                return self._error(EFI_NOT_FOUND)
            machine.write_pointer(out, interface)
            return EFI_SUCCESS

        table.handle(name, locate)

    def add_protocol(self, guid, interface):
        """Make `LocateProtocol(guid)` return `interface` (an address)."""
        self.protocols[str(uuid.UUID(guid))] = interface


class DxeServices(_Common):
    """EFI boot services, runtime services and system table for 64-bit DXE modules.

    `.system_table` is the second argument of a driver entry point. GetVariable and
    SetVariable are backed by `variables`; other slots need `handle(...)`. AllocatePool,
    FreePool, LocateProtocol, Stall and the TPL calls have defaults.

    Example: `dxe = DxeServices(machine, variables)`; `machine.call(entry, 0, dxe.system_table)`.
    """

    def __init__(self, machine, variables=None):
        if machine.bitness != 64:
            raise ReplayError("DxeServices machine: expected 64-bit | received %d-bit" % machine.bitness)
        self.machine = machine
        self.variables = variables if variables is not None else VariableStore()
        self.protocols = {}
        self.boot = ServiceTable(machine, "boot", BOOT_LAYOUT, 0x200)
        self.runtime = ServiceTable(machine, "runtime", RUNTIME_LAYOUT, 0x100)
        self.system_table = machine.allocate(0x80)
        machine.write_pointer(self.system_table + 0x58, self.runtime.address)
        machine.write_pointer(self.system_table + 0x60, self.boot.address)
        self._install_pool_handlers(self.boot, "AllocatePool", "FreePool")
        self._install_protocol_handlers(self.boot, "LocateProtocol")
        for name in ("RaiseTPL", "RestoreTPL", "Stall"):
            self.boot.handle(name, lambda call: 0)
        self.runtime.handle("GetVariable", self._get_variable)
        self.runtime.handle("SetVariable", self._set_variable)

    def handle(self, name, handler, table="boot"):
        (self.boot if table == "boot" else self.runtime).handle(name, handler)

    def _get_variable(self, call):
        return _get_variable(self, call, 0)

    def _set_variable(self, call):
        return _set_variable(self, call)


class SmmServices(_Common):
    """EFI SMM system table (SMST) for 64-bit SMM drivers.

    `.table` is the SMST address. AllocatePool, FreePool and LocateProtocol have defaults;
    protocols come from `add_protocol`.

    Example: `smm = SmmServices(machine)`; `smm.add_protocol(guid, address)`.
    """

    def __init__(self, machine, variables=None):
        if machine.bitness != 64:
            raise ReplayError("SmmServices machine: expected 64-bit | received %d-bit" % machine.bitness)
        self.machine = machine
        self.variables = variables if variables is not None else VariableStore()
        self.protocols = {}
        self.table_ = ServiceTable(machine, "smm", SMM_LAYOUT, 0x100)
        self._install_pool_handlers(self.table_, "SmmAllocatePool", "SmmFreePool")
        self._install_protocol_handlers(self.table_, "SmmLocateProtocol")

    @property
    def table(self):
        return self.table_.address

    @property
    def allocations(self):
        return self.table_.called("SmmAllocatePool")

    def handle(self, name, handler):
        self.table_.handle(name, handler)


class PeiServices:
    """EFI PEI services for 32-bit PEI modules.

    `.services` is the `EFI_PEI_SERVICES **` argument. LocatePpi, GetBootMode, AllocatePool,
    CopyMem, SetMem and ReportStatusCode have defaults; install PPIs with `add_ppi`.

    Example: `pei = PeiServices(machine)`; `machine.call(entry, 0, pei.services)`.
    """

    def __init__(self, machine, boot_mode=0):
        if machine.bitness != 32:
            raise ReplayError("PeiServices machine: expected 32-bit | received %d-bit" % machine.bitness)
        self.machine = machine
        self.boot_mode = boot_mode
        self.ppis = {}
        self.table_ = ServiceTable(machine, "pei", PEI_LAYOUT, 0x100)
        self.services = machine.allocate(8)
        machine.write_pointer(self.services, self.table_.address)

        def locate(call):
            guid = format_guid(machine.read(call.arg(1), 16))
            ppi = self.ppis.get(guid)
            if ppi is None:
                return 0x80000000 | EFI_NOT_FOUND
            machine.write_pointer(call.arg(4), ppi)
            return EFI_SUCCESS

        def allocate_pool(call):
            machine.write_pointer(call.arg(2), machine.allocate(call.arg(1), fill=0xA5))
            return EFI_SUCCESS

        def get_boot_mode(call):
            machine.write_uint(call.arg(1), 4, self.boot_mode)
            return EFI_SUCCESS

        def copy_mem(call):
            machine.write(call.arg(1), machine.read(call.arg(2), call.arg(3)))
            return 0

        def set_mem(call):
            machine.write(call.arg(1), bytes([call.arg(3) & 0xFF]) * call.arg(2))
            return 0

        self.table_.handle("LocatePpi", locate)
        self.table_.handle("AllocatePool", allocate_pool)
        self.table_.handle("GetBootMode", get_boot_mode)
        self.table_.handle("CopyMem", copy_mem)
        self.table_.handle("SetMem", set_mem)
        self.table_.handle("ReportStatusCode", lambda call: EFI_SUCCESS)

    def add_ppi(self, guid, interface):
        self.ppis[str(uuid.UUID(guid))] = interface

    def handle(self, name, handler):
        self.table_.handle(name, handler)


def _get_variable(services, call, _unused):
    """GetVariable(Name, Guid, Attributes*, DataSize*, Data*)."""
    machine = services.machine
    name = machine.read_utf16(call.arg(0))
    guid = format_guid(machine.read(call.arg(1), 16))
    found = services.variables.get(name, guid)
    machine.trace.add("variable-get", name=name, guid=guid, found=found is not None)
    error = (1 << (machine.bitness - 1))
    if found is None:
        return error | EFI_NOT_FOUND
    attributes, data = found
    size_pointer = call.arg(3)
    capacity = machine.read_pointer(size_pointer)
    machine.write_pointer(size_pointer, len(data))
    if capacity < len(data):
        return error | EFI_BUFFER_TOO_SMALL
    machine.write(call.arg(4), data)
    if call.arg(2):
        machine.write_uint(call.arg(2), 4, attributes)
    return EFI_SUCCESS


def _set_variable(services, call):
    """SetVariable(Name, Guid, Attributes, DataSize, Data)."""
    machine = services.machine
    name = machine.read_utf16(call.arg(0))
    guid = format_guid(machine.read(call.arg(1), 16))
    attributes, size = call.arg(2) & 0xFFFFFFFF, call.arg(3)
    machine.trace.add("variable-set", name=name, guid=guid, size=size, attributes=attributes)
    if size == 0:
        services.variables.delete(name, guid)
    else:
        services.variables.set(name, guid, machine.read(call.arg(4), size), attributes)
    return EFI_SUCCESS
