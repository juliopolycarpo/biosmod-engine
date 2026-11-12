# Replay runtime

English | [Brazilian Portuguese](../pt-BR/guide/replay.md)

Replay runs original firmware instructions against simulated hardware, so a finding can be shown without a flash. The emulator is Unicorn, driven from Python; bme manages the Python environment the same way it manages Ghidra.

```sh
bme tools setup replay                         # python3 >= 3.10 creates <data dir>/replay/venv and pip installs the lock
bme tools setup replay --python /usr/bin/python3.12
bme --offline tools setup replay --wheelhouse ./wheels
bme tools status                               # the replay row: ready, attention or missing
bme tools doctor replay --deep                 # versions, then Unicorn executes one instruction
bme tools set replay /path/to/venv             # use an existing interpreter or environment
bme tools unset replay
```

## What setup installs

Setup needs only `python3` 3.10 or newer with the `venv` module (Ubuntu: `apt install python3 python3-venv`). It creates the environment in a staging directory and runs `python -m pip install --isolated --no-input --require-hashes --only-binary :all: --no-deps -r requirements.lock`. The lock, embedded from `tools/replay/requirements.lock`, pins:

| Package  | Version   |
| -------- | --------- |
| unicorn  | 2.1.4     |
| capstone | 5.0.9     |
| pefile   | 2024.8.26 |

Each pin lists the SHA-256 of every published wheel for 64-bit Linux (glibc and musl), macOS and Windows, so pip accepts a wheel on any of them and rejects everything else, including source distributions. `--isolated` ignores pip configuration and `PIP_*` variables, so a user index cannot replace the lock. `tools/replay/lock.py` regenerates the lock from the PyPI JSON API.

After installing, setup moves the environment into place, reads the versions back and has Unicorn execute one instruction. A second `setup` that finds a healthy environment from the same release changes nothing. An environment bme did not create is replaced only with `--force`, which deletes it.

`--offline` needs `--wheelhouse DIR` with the pinned wheels; pip then runs with `--no-index --find-links DIR`. Setup never installs on its own: a command that needs the runtime and cannot find it fails with `TOOL_UNAVAILABLE` and names `bme tools setup replay`.

## Locating the runtime

bme runs the interpreter from `BME_REPLAY_PYTHON`, then `tools.replay_python` (saved by `tools set replay`), then the managed environment. `tools set replay <path>` accepts an interpreter or a virtual environment directory, and refuses it unless it reports Python 3.10 or newer and exactly the pinned versions. `tools status` shows the row as optional, so a missing runtime does not make the report not ready. A saved or environment location blocks `setup`; run `bme tools unset replay` first. `tools doctor` checks the replay runtime once one is installed or chosen; `tools doctor replay` requires it.

## Running a harness

```sh
bme replay script harness.py --module PchSmiDispatcher.pe -o out/ -- --case 3
```

A harness is a Python script that imports `bme_replay`, loads the modules named with `--module` (`bme_replay.modules()`), calls firmware functions and reports with `bme_replay.emit(document)`. bme runs it as `python -I -B` in the replay environment, passes the arguments after `--` as `sys.argv[1:]`, and collects every emitted JSON document. A harness that raises, exits non-zero or runs past `--timeout` (600 s by default) fails the command with `TOOL_FAILED` and its stderr tail.

`bme_replay` is MIT code that bme embeds and writes to `<data dir>/replay/package-<digest>` before each run. A new release writes a new directory and never rewrites one that exists, so a run in progress and two runs started together do not disturb each other, and the environment is not recreated. Older digest directories stay; delete them when no run uses them. It provides:

| Piece | Use |
| ----- | --- |
| `Machine(32 or 64)`, `machine.call(address, *args, budget=N)` | Run a function under the Microsoft x64 or cdecl convention; callee-saved registers and the stack pointer are checked, an instruction budget bounds the run, a fault raises `EmulationFault` or comes back with `capture_fault=True` |
| `load_pe(machine, bytes, base=...)` | Map a PE32, PE32+ or TE image, apply relocations, check the machine type against the bitness |
| `DxeServices`, `SmmServices`, `PeiServices`, `VariableStore` | Fake service tables; GetVariable and SetVariable use the store, any other slot needs a handler or raises `UnmodeledService` |
| `machine.ports.attach(device, ports, name)`, `PortRegisters`, `IndexedRegisters` | Named port devices; a port nobody claims raises `UnmodeledAccess` |
| `machine.mmio(base, size, device, name)`, `RegisterFile` | MMIO regions |
| `machine.attach_msrs(MsrBus(...))` | RDMSR and WRMSR |
| `SmbusDevice`, `SpdEeprom` | A PCH SMBus controller with slaves |
| `machine.stub(address, handler)`, `machine.trace` | Replace a function, and read or hash the event trace |

With `-o DIR`, bme writes `result.jsonl` (the documents, one per line) and `evidence.json`, a `bme.evidence/1` record of kind `offline-validation`. Its `replay` block holds the harness name, the interpreter and package versions, the bme release, the `bme_replay` package digest, the SHA-256 of the harness and of each module, and the SHA-256 of `result.jsonl`. `--board` and `--firmware` fill the record's scope; both default to `unscoped`, and a catalog accepts the record only after they name a real board and build. Without `-o` the record is in the `--json` reply only. An existing `evidence.json` or `result.jsonl` is never overwritten.

`tools/replay/examples/b11_context_overread.py` is a complete harness: it replays the original `PchSmiDispatcher` registration with contexts placed at the end of a readable page and shows the 16-byte read faulting at RVA `3A02` when fewer than 16 bytes follow.

An emulated run shows what the instructions do against the models the harness supplies. It is not an observation on hardware, and the record says so in its `limits`.

## Licence boundary

Unicorn Engine is GPLv2. bme ships no Unicorn code: you install it into a separate environment, and bme starts that environment's Python as a subprocess and exchanges files and JSON with it. The embedded `bme_replay` package is MIT code that calls the Unicorn Python API and contains no Unicorn code. Capstone and pefile are installed the same way. The package metadata of the Unicorn 2.1.4 wheel names a BSD licence for the Python binding; check the licence of the engine library inside the wheel before redistributing it.
