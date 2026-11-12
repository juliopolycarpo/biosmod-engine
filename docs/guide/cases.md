# Cases

English | [Brazilian Portuguese](../pt-BR/guide/cases.md)

An investigation produces more than patches: findings with no fix yet, results of commands you ran, drafts of a board the catalog does not know. A case is a directory that keeps them together and says what produced each one.

```
case.json               bme.case/1: inputs by digest, engine and catalog versions, the artifact list
artifacts/              recorded results: 001-scan.json, 002-inspect.json, 003-module.bin
drafts/board.json       unreviewed board profile (bme.board/1)
drafts/firmware.json    unreviewed firmware build, banner strings and module inventory (bme.firmware-draft/1)
findings/<id>.json      findings the case holds (bme.finding/1); edit or add your own
```

Dumps are listed by file name, SHA-256 and size, never copied into the case. Nothing in a case names a path on your machine.

## Start from a dump

```sh
bme case init dump.bin -o work/mr9a-case
```

`init` refuses an existing directory. It hashes the dump, scans it with detector signatures and stores that scan as `artifacts/001-scan.json`. Then it drafts, from what the image says about itself:

- a firmware build: the id and version string come from the build banner (`X99H BIOS Date: 12/02/2022 Ver: X99HA00M` becomes `x99ha00m-20221202`), the size from the image, and `drafts/firmware.json` adds the banner strings and the GUID, length and SHA-256 of every PE32 and ACPI module. An image without a banner gets `fw-<sha256 prefix>`.
- a board profile listing that build and no patches. `--board-id` names it; the default is `draft-<firmware id>`.
- a finding under `findings/` for every detector that reports `likely-present`, so a defect class known from other builds shows up before any variant exists. The draft finding is open, affects only this build, drops the patches and detectors of the catalog record, and cites the scan as evidence.

When the same machine holds the board, `init` adds its SMBIOS identity (vendor, model, revision from `/sys/class/dmi/id`). It does so only when the machine's BIOS date appears in the image's banner, so a dump of another build never inherits the host's identity. Otherwise vendor and model read `Unknown`.

Every draft says `DRAFT (unreviewed)` in its description or note. Check vendor, model and revision against the physical board before you share it. `init` also takes `--catalog` and `--allow-unsigned-local` as `scan` does; the case records which catalog it used.

## Record what you run

```sh
bme case record work/mr9a-case -- extract dump.bin --guid <guid> -o Module.pe
bme case record work/mr9a-case -- inspect dump.bin --files
```

`record` runs the command inside `bme` and stores:

- its `--json` document as `artifacts/NNN-<command>.json`;
- every file it creates, found through `-o`/`--output` or named with `--artifact PATH` (repeatable), as `artifacts/NNN-<file name>`;
- every directory it creates the same way, copied whole as `artifacts/NNN-<directory name>/` with the SHA-256 and length of each file listed in `case.json`. Names inside must use `A-Z a-z 0-9 . _ -` and not start with a dot, and symbolic links are refused;
- in `case.json`, for each artifact: the SHA-256 and length, the exact arguments, the `bme` version, the catalog snapshot, the digests of every existing file the arguments name, and the time.

A failed command records nothing. Outputs must not exist before the command runs. `case record` does not nest. The mechanism takes any `bme` subcommand, so commands added later record without changes to `case`.

## Check a case

```sh
bme case status work/mr9a-case --input dump.bin
```

`status` re-hashes every artifact and every input and reports:

| Report | Meaning |
|---|---|
| `verified` | the bytes match the record |
| `changed` | the file exists with other bytes; for a directory, a file differs or was added |
| `missing` | the file is absent |
| `stale` | an artifact came from another `bme` version or catalog snapshot than the current one, or from an input that differs from the case's |
| findings | the finding documents in `findings/` and their status |

`changed` or `missing` ends the command with exit code `1` and error code `CASE_DRIFT`; `error.details` holds the full report, down to the changed, missing or added files of a directory artifact. Stale results do not fail the check: record them again.

Inputs are found by name. `--input` takes a file, a directory that holds the dumps, or `NAME=PATH`. A file whose name differs matches by digest. Without `--input`, `status` looks for each name in the working directory and beside the case directory. Pass `--catalog` (and `--allow-unsigned-local`) to judge staleness against a catalog other than the official one.

A case moves to another machine as a plain directory. There, `bme case status DIR --input /path/to/dumps` proves the same dumps and the same artifacts.

## Export a submission

```sh
bme case export work/mr9a-case -o submission
bme catalog validate submission
```

`export` refuses changed artifacts and an existing output. It writes a catalog directory: `boards/` from `drafts/board.json`, the build, `findings/` from the case, one `evidence/` record per artifact (offline validation, with the command shown without directories and the artifact digest), and the firmware draft under `provenance/`. The exported findings drop patches, since patches do not travel with a case, and a `fixed-by-patch` finding becomes `open`. A finding's `evidence` may name artifact ids such as `001-scan`; export turns them into evidence ids.

`export` loads its own output as a catalog before it finishes, so `bme catalog validate submission` and `bme catalog index` accept it. `bme scan dump.bin --catalog submission --allow-unsigned-local` reads it. All of it is marked draft: review it, then submit it as described in [CONTRIBUTING](../../CONTRIBUTING.md).
