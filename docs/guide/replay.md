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

## Licence boundary

Unicorn Engine is GPLv2. bme ships no Unicorn code: you install it into a separate environment, and bme starts that environment's Python as a subprocess and exchanges files and JSON with it. Capstone and pefile are installed the same way. The package metadata of the Unicorn 2.1.4 wheel names a BSD licence for the Python binding; check the licence of the engine library inside the wheel before redistributing it.
