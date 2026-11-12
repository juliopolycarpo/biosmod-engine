# Biosmod Engine

English | [Brazilian Portuguese](README.pt-BR.md)

`bme` inspects firmware images, finds cataloged defects, builds verified patched copies. The CLI is one executable with no runtime dependencies. Humans and agents use the same commands; add `--json` for one machine-readable document per run. `bme-gui` provides a Linux desktop interface to the same engine.

Inputs are never modified and outputs are always new files. Only the `bme flash` commands touch a flash chip: on Linux they diagnose the system, find the chip, back it up and write an image through flashrom, and a write requires a backup that matches the chip.

The first catalog covers two AMI Aptio boards audited in [x99-bios-fixes](https://github.com/juliopolycarpo/x99-bios-fixes):

| Board profile                    | Chipset | Firmware build        |
| -------------------------------- | ------- | --------------------- |
| `machinist-mr9a-pro-q87-rev-1.2` | Q87     | `mnx99mr9apro-230322` |
| `machinist-pr9-b85`              | B85     | `x99ha00m-20221202`   |

Records for other boards can live in your own catalogs (`bme guide catalogs`, `bme guide porting`).

## Quick start

```sh
cargo build --release          # target/release/bme
bme scan dump.bin
bme patch dump.bin --recommended
bme verify dump.bin dump.patched.bin
```

```
Source: official (Builtin, catalog official 1.0.0)
Firmware: mnx99mr9apro-230322 (board profile machinist-mr9a-pro-q87-rev-1.2), 33/33 recorded modules match
  ID               STATE           TIER         TITLE
  B01-B06          DEFECT PRESENT  recommended  Bound standard iMC transfers and propagate ordinary writer errors
  B02-B03          DEFECT PRESENT  recommended  Separate DIMM counters and establish page zero during Auto discovery
  …
Plannable on this exact build: A02, A03, A07, B01-B06, B02-B03, B05, B08, B09, B10, B11, H01 (--allow-hold --assert superio-nct5532d), …
Recommended: B01-B06 B02-B03
```

To read and write the chip on Linux:

```sh
bme flash doctor
sudo bme flash backup -o dump.bin
sudo bme flash write dump.patched.bin --backup dump.bin --dry-run
```

Read `bme guide flashing` before writing anything to a chip, and keep a programmer recovery path (`bme guide recovery`).

## Desktop interface

On Linux x86_64, build and run the matched pair:

```sh
cargo build --release -p biosmod-cli -p biosmod-gui
target/release/bme-gui
```

The desktop interface scans an image, builds a copy from selected patches and independently verifies it. Its **Flash chip** page diagnoses the system, backs up the chip and writes a checked image. It follows the system light or dark theme, with a manual choice in Settings. The interface supports English and Brazilian Portuguese; English is the default. See the [desktop guide](docs/guide/gui.md) for dependencies, installation, limits and troubleshooting.

## What it does

- Parses Intel flash descriptor images and EFI firmware volumes, including nested and LZMA-compressed volumes, with depth, size and expansion limits.
- Matches modules by FFS GUID and exact SHA-256 against catalog records. Fixes already present are recognized and kept.
- Applies equal-length and appended hunks, re-encodes LZMA byte-identically to the original toolchain (liblzma, statically linked), recomputes checksums and moves movable files into free space when a module grows. Execute-in-place files never move.
- Re-parses every output, requires each selected patch to read back as fixed and every byte outside a per-component allowlist to be unchanged, then publishes the image and its manifest without replacing existing files.

Anything outside this (other compression formats, capsules, signed updates, PEI relocation) is an explicit error. Valid checksums do not mean a platform will accept a modified image.

## Parity with the reference

The official catalog was converted from x99-bios-fixes at commit `765e7a80ae8337c0953dc0da41de5f28b56c5c92`. With the real dumps, `bme` reproduces byte for byte:

- the three MR9A images that were flashed and read back (stage 1, stage 2, breadcrumb diagnostic revision 2);
- the reference full builds for both boards;
- every record built alone on both stock dumps: 29 identical outputs, and the 7 cases the reference refuses (manual packing, not applicable) are refused too.

`cargo nextest run --locked --release --test real_roms --success-output final` repeats these checks when the dumps are named by `BME_ROM_*` variables (see the test file). A test whose dump is missing still passes; nextest hides output from passing tests by default, so `--success-output final` is what prints its `skipped: BME_ROM_* is not set` line in the summary.

The reference tools are covered by commands: `scan`, `patch`, `extract`, `replace` and `derive` (x99fix); `tools setup ghidra`, `tools analyze` and `tools doctor` (setup-ghidra.sh, ghidra-analyze.sh); the breadcrumb builder is the `MRC-BREADCRUMBS` diagnostic record, and `diag breadcrumbs read` replaces read_breadcrumbs.py.

## Commands

| Command                                                            | Purpose                                                       |
| ------------------------------------------------------------------ | ------------------------------------------------------------- |
| `ifr`                                                              | Setup forms: questions, varstore offsets, options, defaults, conditions |
| `nvram`                                                            | NVRAM variables (NVAR, VSS): record states, defaults, Setup field stored vs default |
| `inspect` (`--files`, `--acpi`)                                    | descriptor regions, volumes, files and stored ACPI tables     |
| `scan`                                                             | detected build and every patch state                          |
| `patch`, `export`, `verify`                                          | builds, optional recipes and verification                                 |
| `extract`, `replace`                                               | one module or ACPI table out, an edited module back in        |
| `compare`, `compare --functions`, `compare --acpi`                 | pair two images' modules by GUID, two `tools analyze` exports by function, or two ACPI namespaces by method |
| `derive`                                                           | draft a variant for another build by unique signatures        |
| `catalog validate/index/add/list/remove/update/show/import-x99fix` | catalog sources and maintenance                               |
| `case init/record/status/export`                                   | record an investigation, draft an unknown board, export a submission |
| `tools status/set/unset/doctor/setup ghidra/analyze/paths`         | see, locate and install Ghidra 12.2 with ghidra-firmware-utils |
| `tools setup replay`                                               | Python environment with hash-locked Unicorn, Capstone and pefile |
| `diag breadcrumbs decode/read`                                     | MR9A MRC checkpoint diagnostic (read uses ports 72h/73h only) |
| `diag acpi capture`                                                | hashed bundle of ACPI tables, sleep state and kernel sleep messages with an evidence record (Linux, root) |
| `diag smbios`                                                      | decode the SMBIOS table: BIOS, system, board and memory devices with slot widths and speeds; without root, model-level fields only (Linux) |
| `diag suspend pm-test`                                             | run one kernel suspend test stage that stops at its checkpoint, report the suspend counters, always restore `pm_test` (Linux, root) |
| `diag superio read`                                                | identify the Super I/O chip by ID and read its hardware-monitor registers; only access selectors are written (Linux, root) |
| `flash doctor`, `flash probe`, `flash backup`, `flash write`       | diagnose, find, back up and write the chip via flashrom (Linux) |
| `dev synthetic`                                                    | a synthetic image and catalog to try everything safely        |
| `version`, `capabilities`, `schema`, `guide`                       | contracts and built-in documentation                          |

`bme guide` lists the documentation topics; the same files are in [docs/guide](docs/guide).

## Documentation

- [Architecture](docs/architecture.md): crates, data flow and safety checks
- [Formats](docs/formats.md): supported firmware structures and limits
- [Setup forms (IFR)](docs/guide/ifr.md): decode questions, offsets and defaults
- [NVRAM variables](docs/guide/nvram.md): record states, saved defaults and stored Setup values
- [Protocol](docs/guide/agents.md), [trust](docs/guide/trust.md), [catalogs](docs/guide/catalogs.md), [recovery](docs/guide/recovery.md), [host diagnostics](docs/guide/diagnostics.md), [cases](docs/guide/cases.md)
- [Linux desktop qualification](docs/linux-desktop-qualification.md): tested environments and limits
- [Desktop guide](docs/guide/gui.md): Linux setup and build workflow
- [Contributing](CONTRIBUTING.md), including board and patch submissions
- [Baseline measurements](docs/baseline.md)

## License

Project code is MIT; see [LICENSE](LICENSE). The desktop app uses Slint under its [Royalty-free License 2.0](packaging/linux/licenses/Slint-Royalty-free-2.0.md), with attribution in About. The Linux archive includes dependency notices. `tools/ghidra/PeimUEFIHelper.java` and `tools/ghidra/ghidra-firmware-utils-12.2.patch` derive from ghidra-firmware-utils and stay under Apache-2.0; see [tools/ghidra/NOTICE](tools/ghidra/NOTICE).

Patch records contain short excerpts of vendor firmware: the original bytes of each change and 16 bytes of context, so a patch can find and check its target. That vendor code is not covered by this license. Vendor images are not included.
