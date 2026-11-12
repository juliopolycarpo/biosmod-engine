"""Event trace shared by every model in one machine.

A harness reads `machine.trace.events` to assert what firmware did, and the digest of the
trace goes into the evidence record, so two runs that behave the same hash the same.
"""

import hashlib
import json


class Trace:
    """An ordered list of `{"kind": ..., **fields}` events.

    Example: `trace.add("port-out", port=0x404, size=2, value=0x1400)`.
    """

    def __init__(self):
        self.events = []

    def add(self, kind, /, **fields):
        event = {"kind": kind}
        event.update(fields)
        self.events.append(event)
        return event

    def of_kind(self, *kinds):
        """Events whose kind is one of `kinds`, e.g. `trace.of_kind("port-out")`."""
        return [e for e in self.events if e["kind"] in kinds]

    def clear(self):
        del self.events[:]

    def digest(self):
        """SHA-256 of the canonical JSON of the events."""
        data = json.dumps(self.events, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(data).hexdigest()
