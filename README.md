# Biosmod Engine

`bme` inspects firmware images, finds cataloged defects, plans guarded patches and builds verified patched copies. The CLI is one executable with no runtime dependencies. Humans and agents use the same commands; add `--json` for one machine-readable document per run. `bme-gui` provides a Linux desktop interface to the same engine.

`bme` never reads or writes a flash chip. Inputs are never modified and outputs are always new files.

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
bme plan dump.bin --select recommended -o plan.json
bme patch dump.bin --plan plan.json -o fixed.bin
bme verify dump.bin fixed.bin
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

Read `bme guide flashing` before writing anything to a chip, and keep a programmer recovery path (`bme guide recovery`).

## Desktop interface

On Linux x86_64, build and run the matched pair:

```sh
cargo build --release -p biosmod-cli -p biosmod-gui
target/release/bme-gui
```

The desktop interface scans an image, reviews a plan, builds a new copy and independently verifies it. It follows the system light or dark theme, with a manual choice in Sources & tools. See the [desktop guide](docs/guide/gui.md) for dependencies, installation, limits and troubleshooting.

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

`cargo test --release --test real_roms` repeats these checks when the dumps are named by `BME_ROM_*` variables (see the test file). Without them those tests are skipped and say so.

The reference tools are covered by commands: `scan`, `patch`, `extract`, `replace` and `derive` (x99fix); `tools setup ghidra`, `tools analyze` and `tools doctor` (setup-ghidra.sh, ghidra-analyze.sh); the breadcrumb builder is the `MRC-BREADCRUMBS` diagnostic record, and `diag breadcrumbs read` replaces read_breadcrumbs.py.

## Commands

| Command                                                            | Purpose                                                       |
| ------------------------------------------------------------------ | ------------------------------------------------------------- |
| `inspect`                                                          | descriptor regions, volumes and files                         |
| `scan`                                                             | detected build and every patch state                          |
| `plan`, `patch`, `verify`                                          | reviewed, reproducible builds                                 |
| `extract`, `replace`                                               | one module out, an edited module back in                      |
| `derive`                                                           | draft a variant for another build by unique signatures        |
| `catalog validate/index/add/list/remove/update/show/import-x99fix` | catalog sources and maintenance                               |
| `tools doctor/setup ghidra/analyze/paths`                          | Ghidra 12.2 with ghidra-firmware-utils                        |
| `diag breadcrumbs decode/read`                                     | MR9A MRC checkpoint diagnostic (read uses ports 72h/73h only) |
| `dev synthetic`                                                    | a synthetic image and catalog to try everything safely        |
| `version`, `capabilities`, `schema`, `guide`                       | contracts and built-in documentation                          |

`bme guide` lists the documentation topics; the same files are in [docs/guide](docs/guide).

## Documentation

- [Architecture](docs/architecture.md): crates, data flow and safety checks
- [Formats](docs/formats.md): supported firmware structures and limits
- [Protocol](docs/guide/agents.md), [trust](docs/guide/trust.md), [catalogs](docs/guide/catalogs.md), [recovery](docs/guide/recovery.md)
- [Desktop guide](docs/guide/gui.md): Linux setup and reviewed build workflow
- [Contributing](CONTRIBUTING.md), including board and patch submissions
- [Baseline measurements](docs/baseline.md)

## License

Project code is MIT; see [LICENSE](LICENSE). The desktop app uses Slint under its [Royalty-free License 2.0](packaging/linux/licenses/Slint-Royalty-free-2.0.md), with attribution in About. The Linux archive includes dependency notices. `tools/ghidra/PeimUEFIHelper.java` and `tools/ghidra/ghidra-firmware-utils-12.2.patch` derive from ghidra-firmware-utils and stay under Apache-2.0; see [tools/ghidra/NOTICE](tools/ghidra/NOTICE).

Patch records contain short excerpts of vendor firmware: the original bytes of each change and 16 bytes of context, so a patch can find and check its target. That vendor code is not covered by this license. Vendor images are not included.
