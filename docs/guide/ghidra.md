# Analysis toolchain

```sh
bme tools doctor              # read-only: JDK, Ghidra version, extension
bme tools setup ghidra        # pinned install under the data directory (Linux)
bme tools doctor --deep       # also starts Ghidra headless on a probe file
bme tools analyze --project work/p --output work/x Module.pe [...]
```

`setup` installs Ghidra 12.2 and builds ghidra-firmware-utils from a pinned commit with a small compatibility patch for 12.2. The Ghidra and Gradle archives are checked against pinned SHA-256 digests before extraction. Extraction refuses unsafe paths and symlinks and has size and count limits; everything is staged and moved into place only when complete. An existing install that bme did not make is replaced only with `--force`. Gradle fetches the extension's build dependencies from Maven repositories; those are not pinned by bme.

Requirements: JDK 21 or newer and git. Offline: pass `--offline` with `--ghidra-zip`, `--gradle-home` and `--firmware-utils-src`.

`bme tools paths` shows where things live. Set `GHIDRA_INSTALL_DIR` or `tools.ghidra_home` in the config file to use another installation; `doctor` reports a version mismatch because the scripts are tested on 12.2 only.

`analyze` writes, per module, `NAME.c` (approximate decompilation), `NAME.asm` (instructions with exact bytes) and `NAME.json` (functions, calls and ranges), plus `ghidra.log`. Check bytes in the `.asm` before writing a hunk; the C output is a reading aid.
