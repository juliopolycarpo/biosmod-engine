"""`python -m bme_replay HARNESS.py [--module PE ...] [-- ARGS...]` runs a harness script.

`python -m bme_replay --scenario FILE --module PE` runs a `bme.scenario/1` document instead.
"""

import os
import runpy
import sys

from . import _modules


def parse(argv):
    """Split `argv` into `(harness, modules, script_args)`.

    With `--scenario FILE` first, `harness` is `("scenario", FILE)`.

    Example: `parse(["h.py", "--module", "a.pe", "--", "x"])` is `("h.py", ["a.pe"], ["x"])`.
    """
    if not argv:
        raise SystemExit("usage: python -m bme_replay HARNESS.py [--module PE ...] [-- ARGS...]")
    harness, rest = argv[0], argv[1:]
    if harness == "--scenario":
        if not rest:
            raise SystemExit("--scenario: expected a path | received none")
        harness, rest = ("scenario", rest[0]), rest[1:]
    modules, script_args = [], []
    index = 0
    while index < len(rest):
        item = rest[index]
        if item == "--":
            script_args = rest[index + 1:]
            break
        if item == "--module":
            if index + 1 >= len(rest):
                raise SystemExit("--module: expected a path | received none")
            modules.append(rest[index + 1])
            index += 2
        else:
            raise SystemExit("argument %r: expected --module PATH or -- | received it" % item)
    return harness, modules, script_args


def main(argv):
    harness, modules, script_args = parse(argv)
    _modules[:] = modules
    if isinstance(harness, tuple):
        from . import emit, scenario

        scenario.run_file(harness[1], modules, emit)
        return
    sys.argv = [harness] + script_args
    # Isolated mode (`-I`) leaves sibling helper modules off the path.
    sys.path.insert(0, os.path.dirname(os.path.abspath(harness)))
    runpy.run_path(harness, run_name="__main__")


if __name__ == "__main__":
    main(sys.argv[1:])
