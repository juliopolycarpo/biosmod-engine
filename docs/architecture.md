# Architecture

English | [Brazilian Portuguese](pt-BR/architecture.md)

Three crates in one workspace:

| Crate                            | Owns                                                                                                   | Never does                                |
| -------------------------------- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------- |
| `biosmod-core` (library)         | firmware parsing, catalog models and validation, patch matching, planning, rebuilding and verification | filesystem, network or terminal I/O       |
| `biosmod-cli` (binary `bme`)     | arguments, files, catalog sources, configuration, downloads, subprocesses, output                      | interpret firmware on its own             |
| `biosmod-gui` (binary `bme-gui`) | presentation, reviewed session state and `bme` subprocess supervision                                  | interpret or patch firmware independently |

Core functions take bytes and a `FileSource` and return typed `Result`s with a stable `Code`. The CLI wraps them in the `bme/1` envelope.

The GUI invokes a compatible `bme` as a subprocess. It keeps reviewed plan bytes in a private session directory, applies only a plan generated in that session, and checks the independent verification result. It stores presentation settings separately from CLI source and trust configuration. CLI and core builds do not depend on Slint.

## Core modules

| Module                     | Role                                                                                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `firmware`                 | descriptor regions, FV/FFS/section parsing with depth and decode budgets; `pe` for PE32/TE; `rebuild` for checksums, LZMA re-encoding and volume reflow |
| `codec`                    | liblzma wrapper: bounded decoding and encoding that reproduces the original stream parameters                                                           |
| `catalog`                  | typed documents (`bme.catalog/1`, `bme.board/1`, `bme.patch/1`, `bme.evidence/1`) and loading through a verified index                                  |
| `json`                     | strict parsing: duplicate keys and trailing data are errors                                                                                             |
| `validation`               | semantic rules: references, symmetric conflicts, cycles, hunk geometry, layering, facts                                                                 |
| `patch`                    | hunk application, reversal, state and masked signature search                                                                                           |
| `analysis`                 | module matching (undoing known fixes), build detection, patch states, scan reports                                                                      |
| `plan`                     | selection resolution, composition, structural checks, in-place or reflowed rebuild, independent verification; plan and manifest documents               |
| `schema`                   | JSON Schemas generated from the document types                                                                                                          |
| `legacy`                   | conversion of x99-bios-fixes schema-1 records                                                                                                           |
| `breadcrumbs`, `synthetic` | MR9A CMOS diagnostic decoding; vendor-free test firmware                                                                                                |

## Build pipeline

1. **Resolve**: expand supersession, check conflicts, hold/diagnostic/manual gates, required facts and requirements.
2. **Match**: for each component, find the module by GUID and leaf kind, reverse any recognized fixes, and require the recorded source hash. Layered components are checked against their `input_sha256` first.
3. **Context**: modules named in a variant's `context` must match reviewed hashes.
4. **Compose**: apply base fixes, then layered ones; single-patch results must match their recorded hashes.
5. **Structure**: optional checks (XIP image base, no relocated bytes). ACPI tables are spliced back into their container.
6. **Rebuild**: rebuilt files keep their slot when they fit; otherwise the volume is reflowed into free space. XIP, fixed, top and data-carrying pad files never move.
7. **Verify**: re-parse; every selected and carried patch must read `fixed`; every byte outside the allowlist must equal the input; PE module hashes must match.
8. **Publish** (CLI): stage image and manifest in the output directory, sync, link the manifest then the image without replacing anything. A failure after the manifest is published removes it; if that fails too, `PUBLISH_INCOMPLETE` names what remains.

## Trust boundaries

- Catalog files are untrusted input: size limits, strict parsing, index hashes, path rules, then semantic validation.
- Plans are untrusted: `patch --plan` recomputes everything and compares.
- Remote catalogs are trusted only through a locally configured minisign key, and only as validated snapshots.
- Downloaded tool archives are trusted only through pinned digests.

## Deliberately absent

No daemon, plugin framework, database or flashing code. The GUI uses the same `--json` protocol as other clients.
