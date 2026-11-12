"""Errors raised by the replay API. Each message names the value and the expected shape."""


class ReplayError(Exception):
    """Base class for every error this package raises on purpose."""


class UnmodeledAccess(ReplayError):
    """Firmware touched a port, MMIO address or MSR that no device model claims.

    Example: `UnmodeledAccess("port 0x80 write size 1: expected a device model | received none")`.
    """


class UnmodeledService(ReplayError):
    """Firmware called a service table slot that has no handler."""


class BudgetExceeded(ReplayError):
    """The call did not return within its instruction budget."""


class EmulationFault(ReplayError):
    """Unicorn stopped on an invalid memory access or instruction.

    `.fault` holds `{"kind", "address", "size", "rip"}` so a harness can compare it.
    """

    def __init__(self, message, fault):
        super().__init__(message)
        self.fault = fault


class AbiViolation(ReplayError):
    """A call returned without restoring a register the calling convention preserves."""


class ImageError(ReplayError):
    """A PE or TE image is malformed or cannot be mapped."""
