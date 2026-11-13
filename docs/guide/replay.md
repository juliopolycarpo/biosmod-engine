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

With `-o DIR`, bme writes `result.jsonl` (the documents, one per line) and `evidence.json`, a `bme.evidence/1` record of kind `offline-validation`. Its `replay` block holds the harness name, the interpreter and package versions, the bme release, the `bme_replay` package digest, the SHA-256 of the harness and of each module, and the SHA-256 of `result.jsonl`. bme hashes the harness and modules before the run and the runtime reads them again by path, so a file replaced in between runs under a digest that does not match it; helper modules the harness imports are not hashed at all ([#97](https://github.com/juliopolycarpo/biosmod-engine/issues/97)). `--board` and `--firmware` fill the record's scope; both default to `unscoped`, and a catalog accepts the record only after they name a real board and build. Without `-o` the record is in the `--json` reply only. An existing `evidence.json` or `result.jsonl` is never overwritten.

`tools/replay/examples/b11_context_overread.py` is a complete harness: it replays the original `PchSmiDispatcher` registration with contexts placed at the end of a readable page and shows the 16-byte read faulting at RVA `3A02` when fewer than 16 bytes follow.

## Running a scenario

A scenario is a `bme.scenario/1` JSON file that describes one call without any Python:

```sh
bme schema scenario
bme replay run tools/replay/scenarios/smartfan-zero-policy/pwm0-seed0.json --module SioDxeInit.pe -o out/
```

It holds the module's SHA-256 and bitness (never its bytes), the entry RVA and arguments, the service tables (`dxe`, `smm` or `pei`) with the image fields to point at them, hardware models from the library (`port-registers`, `indexed-registers`, `mmio-registers`), UEFI variables present before the call, an instruction budget and the expectations. Numbers are JSON integers or `0x` strings. Each hardware model takes only its own options, and a bank in an expectation must be below the model's `banks`. A `service-calls` expectation names a slot from the table in `tools/replay/service-names.json`; the same file feeds the Python runtime, which raises on a name it does not know. An argument or binding can name an address the runtime provides: `image-base`, `system-table`, `boot-services`, `runtime-services`, `smm-table` or `pei-services`. An expectation checks the return value, an indexed register (`bank`, `index`, optional `mask`), a port, a variable or how often a service was called. Unknown fields and duplicate keys are rejected.

`bme replay run` refuses a module whose SHA-256 differs from the scenario's (`PATCH_SOURCE_MISMATCH`, before anything runs), replays the call and prints `ok` or `FAIL` for each expectation with the expected and received values. With `-o DIR` the record is written either way, with the scenario and the module listed by SHA-256 and the scenario id in the `replay` block, and with the bme release and the `bme_replay` package digest in `runtime`.

bme does not take the runtime's word for the verdict. It validates the scenario once, writes its canonical form to a scratch file and passes the file with its SHA-256; the runtime refuses to run if the digest differs. It then reads the expectations back from the scenario it validated, requires the runtime's `kind` and `expected` to match, and recomputes `passed` from `received`. A summary that carries an error never passes.

| Code | Meaning |
| --- | --- |
| `SCENARIO_INVALID` | The scenario file is malformed (unknown field, duplicate key, bad value), or its setup failed: a service slot, hardware option or binding the runtime could not build. |
| `REPLAY_FAILED` | The call ran and an expectation failed, or the call itself faulted, touched an unmodeled address or ran out of budget. The firmware did something other than the scenario expects. |
| `TOOL_FAILED` | The runtime failed: it crashed, timed out, evaluated an expectation wrongly, or returned a document that contradicts the scenario. |
| `PATCH_SOURCE_MISMATCH` | The module's SHA-256 is not the scenario's. |

The runtime reports the phase it stopped in (`setup`, `call` or `evaluate`) in the summary's `error`, and bme maps it to a code as in the table. `--json` carries every verdict in `details`.

`tools/replay/scenarios/smartfan-zero-policy` holds twelve scenarios for the MR9A `SioDxeInit` Smart Fan routine: the first PWM step of the CPU curve is 0, 1, 64 or 150, from three pseudo-random hardware-monitor states. Each expects PWM1 to hold the step unclamped. They name the module by digest only; extract it from your own image with `bme extract <rom> --guid 4E82091E-32A1-4689-8A00-CDE41ED63CDD -o SioDxeInit.pe`. The variable's vendor GUID in the scenarios is the setup VarStore GUID, not the module GUID.

`tools/replay/examples/b02_b03_dimm_counter.py` is a script for what scenarios cannot express, a stateful SPD EEPROM with page selection. It runs the DDR4 detection, SPD read and type recognition of the original `UncoreInitPeim` of the MR9A or the PR9 (extract with `--guid D71C8BA4-4AF2-4D0D-B1BA-F2409F0C20D3`) for every combination of starting page, retained DDR4 marker and page policy. With the policy Enabled the header is read at slave `0xA6` only (slot 3, instead of `0xA0`, `0xA2` and `0xA4`), and with Auto on page 1 and no marker the header is unreadable. It selects the routine table by module digest and refuses any other module. It replaces only the EEPROM transactions and the CPU scratch register, skips the policy branch and sets its bit directly, so it does not prove retained SPD power or the field root cause.

An emulated run shows what the instructions do against the models the harness supplies. It is not an observation on hardware, and the record says so in its `limits`.

## Licence boundary

Unicorn Engine is GPLv2. bme ships no Unicorn code: you install it into a separate environment, and bme starts that environment's Python as a subprocess and exchanges files and JSON with it. The embedded `bme_replay` package is MIT code that calls the Unicorn Python API and contains no Unicorn code. Capstone and pefile are installed the same way. The package metadata of the Unicorn 2.1.4 wheel names a BSD licence for the Python binding; check the licence of the engine library inside the wheel before redistributing it.
