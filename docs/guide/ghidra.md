# Analysis toolchain

English | [Brazilian Portuguese](../pt-BR/guide/ghidra.md)

```sh
bme tools status              # every tool: version, location, install command (never fails)
bme tools doctor              # read-only: JDK, Ghidra version, extension
bme tools setup ghidra        # pinned install under the data directory (Linux)
bme tools doctor --deep       # also starts Ghidra headless on a probe file
bme tools analyze --project work/p --output work/x Module.pe [...]
```

`status` lists Ghidra, ghidra-firmware-utils, the Java runtime and JDK, git and flashrom. Each row has a state (`ready`, `attention` or `missing`), the version, the path with where it came from (`managed`, `config`, an environment variable or `PATH`) and the command that installs it. bme installs only Ghidra itself; for Java, git and flashrom it prints the package-manager command for your distribution and never runs `sudo`. Setup installs only into bme's own directory and checks Java and git before it downloads, so `status` marks the install as blocked while a saved location (`bme tools unset ghidra`) or `GHIDRA_INSTALL_DIR` is in use, while the JDK or git is not ready, or while bme's own directory holds a Ghidra or extension directory that setup did not install (move it away, or replace it with `bme tools setup ghidra --force`, which deletes it). Setup runs on Linux only; elsewhere `status` offers no setup command. Each version probe in `status` stops after 15 s. NASM appears as an optional row: only maintainers who rebuild a patch from its assembly source under `catalog/provenance` need it, and bme never runs it, so a missing NASM does not make `status` report not ready and has no saved location. `status` exits 0 even when a tool is missing, so scripts can read `--json`; `doctor` keeps its non-zero exit.

`setup` installs Ghidra 12.2 and builds ghidra-firmware-utils from a pinned commit with a small compatibility patch for 12.2. The Ghidra and Gradle archives are checked against pinned SHA-256 digests before extraction. Extraction refuses unsafe paths and symlinks and has size and count limits; each archive is staged before its directory is installed; the headless startup check runs afterward. An existing install that bme did not make is replaced only with `--force`. Gradle fetches the extension's build dependencies from Maven repositories; those are not pinned by bme.

## Recover an interrupted setup

Setup stages each directory before replacing it, but replacement uses two renames, not an atomic directory transaction. Do not run concurrent setup commands for the same locations. If setup stops between renames, the target may be missing and its previous contents remain in a sibling named `.bme-backup-<target-name>`. Older versions used `.bme-old-<process-id>` without recording the target name. Setup refuses to proceed when it finds a retained backup and reports its path.

1. Stop any running setup. Inspect the reported backup, the target and any `.staging-*` or `.bme-staging-*` directories before changing them. A legacy `.bme-old-*` name alone does not identify its original target.
2. If the target is missing and you have identified its backup, rename the backup to the target in the same parent directory. If both exist, inspect them and keep whichever contents you need; move or remove the backup only after deciding. Do not delete an unknown backup.
3. Retry `bme tools setup ghidra`. If an interrupted source clone left a nonempty incomplete checkout, inspect the `ghidra-firmware-utils` directory under the cache shown by `bme tools paths`; after preserving anything needed, remove that incomplete checkout and retry. Unused staging directories from a terminated process can also be removed after inspection.

A failed startup check can leave the newly installed Ghidra and extension in place; run `bme tools doctor --deep` after recovery. These steps do not protect against power loss or filesystem failure during writes.

Requirements: JDK 21 or newer and git. Offline: pass `--offline` with `--ghidra-zip`, `--gradle-home` and `--firmware-utils-src`.

`bme tools paths` shows where things live. To use an existing installation, run `bme tools set ghidra /path/to/ghidra_12.2_PUBLIC`; it checks for `support/analyzeHeadless` and saves `tools.ghidra_home`. `GHIDRA_INSTALL_DIR` overrides the saved value. `bme tools unset ghidra` goes back to the managed install. `doctor` reports a version mismatch because the scripts are tested on 12.2 only.

The same works for flashrom: `bme tools set flashrom /path/to/flashrom` runs `--version` to confirm the program and saves `tools.flashrom`. If the group or others can write the file (a self-built flashrom under umask 002), `set` warns and `status` shows `attention`, because root refuses it for chip commands; `chmod go-w <path>` fixes it.

`analyze` writes, per module, `NAME.c` (approximate decompilation), `NAME.asm` (instructions with exact bytes) and `NAME.json` (functions, calls and ranges), plus `ghidra.log`. Check bytes in the `.asm` before writing a hunk; the C output is a reading aid.
