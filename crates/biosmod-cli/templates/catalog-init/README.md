# {title}

A [Biosmod Engine](https://github.com/juliopolycarpo/biosmod-engine) catalog: the board profile, findings, patches and evidence for one board or one board family. `bme guide catalogs` describes every document.

## Layout

| Path | Holds | In git |
|---|---|---|
| `catalog.json` | the index: id, version, and the length and SHA-256 of every file in `boards/`, `findings/`, `patches/`, `evidence/` and `provenance/` | yes |
| `boards/` | board and revision profiles with the firmware builds they ship | yes |
| `findings/` | one defect or observation per file, patched or not | yes |
| `patches/` | one patch record per file, with one variant per firmware build | yes |
| `evidence/` | one hardware observation per file, bound to the image that was flashed | yes |
| `provenance/` | sources you wrote: assembly, harness scripts | yes |
| `notes/` | investigation notes in prose | yes |
| `work/` | dumps, cases, extracted modules, tool output | no |

Git records no empty directory: each directory reaches a clone with its first file.

## What stays out of git

`.gitignore` admits the paths marked "yes", `README*`, `LICENSE*`, `.github/`, `catalog.json.minisig`, `.gitignore` and `.gitattributes`. Anything else at the top level is ignored: a new top-level file does not appear in `git status` until you add a `!/name` line for it.

In every directory it also ignores firmware images and extracted modules (`*.bin`, `*.rom`, `*.pe`), ACPI tables, analysis projects, executables, archives, videos, PDFs and key files.

Patterns cannot read text. Before you commit a file under `notes/` or `provenance/`, check that it has no:

- serial number, UUID or MAC address (kernel logs, `dmidecode` output and network listings carry them);
- disassembly or decompiled code of a vendor module beyond the lines a finding quotes;
- path of your machine.

Name a dump or a flashed image by file name, SHA-256 and size. Never commit it.

## Work on it

```sh
cp /path/to/dump.bin work/
bme case init work/dump.bin -o work/case      # scan, draft a board profile and firmware build
bme case export work/case -o work/submission  # draft records to review and copy into boards/, findings/, evidence/, provenance/
bme catalog index .                           # after every change to a record
bme catalog validate .
bme scan work/dump.bin --catalog . --allow-unsigned-local
```

`bme guide cases` and `bme guide porting` cover the investigation itself.

## Commits

One record per commit, with the id in the scope and the defect in the subject, so `git log` and code search find it by id, module or symptom:

```text
feat(board): add ACME X99-A rev 1.0 with firmware X99A 2023-01-10
feat(H11): record unbounded PCU mailbox and UBOX semaphore waits
fix(B09): widen every inventoried SMM configuration-table counter
test(evidence): boot ACME X99-A with B01-B06 and B02-B03 flashed
docs(notes): describe the S3 resume investigation
```

`feat` adds a board or a finding, `fix` adds or changes a patch record together with the findings it fixes, `test` adds a hardware observation. A commit that changes a file in an indexed directory carries the re-indexed `catalog.json` and passes `bme catalog validate .`.

## Releases

`bme catalog update` refuses a version it already accepted with other content, and a version older than the newest one it accepted. So `version` in `catalog.json` changes only in a release commit: raise it, run `bme catalog index .`, sign `catalog.json` with minisign, commit `catalog.json.minisig` and tag the commit. Users register the tag's raw `catalog.json` URL:

```sh
bme catalog add {id} https://example.org/path/to/catalog.json --trust-key <public key>
bme catalog update {id}
```

Give them the public key outside this repository. A key committed here proves nothing.
