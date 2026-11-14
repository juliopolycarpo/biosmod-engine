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
| `.github/workflows/validate.yml` | CI: `bme catalog index . --check` and `bme catalog validate .` on every push and pull request | yes |
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
cp /path/to/your-dump.bin work/dump.bin
bme case init work/dump.bin -o work/case      # scan, draft a board profile and firmware build
bme case export work/case -o work/submission  # draft records, unreviewed
# Review the drafts, then copy the records you accept into the catalog.
for kind in boards findings evidence provenance; do
  if [ -d work/submission/$kind ]; then cp -R work/submission/$kind/. $kind/; fi
done
bme catalog index .                           # after every change to a record
bme catalog validate .
bme scan work/dump.bin --catalog . --allow-unsigned-local
```

`bme guide cases` and `bme guide porting` cover the investigation itself.

## Share a record with another board

A defect this board shares with another board keeps the same id and the same text in both repositories. Each repository holds only the variant for its own firmware build.

```sh
bme catalog merge . ../other-board --check   # fails with the record, field and both values when a shared record drifted
bme derive --patch B02-B03 --from-firmware <other build id> --component <module> --module Module.pe > draft.json
```

`bme derive` drafts the variant for this board's build from the other board's record; review it hunk by hunk (`bme guide porting`). A patch that does not apply to this board's build gets a `not-applicable` variant with its reason. Copy the other board's finding with an empty `affects.builds` and no code reference of that build, and list it in the patch's `findings` but not in the board's. `bme catalog split` keeps these records, and merging the board catalogs brings them back. To start from the bundled records, run `bme catalog split official --board <board id> -o <dir> --id <id>`.

The optional `repository` field of `catalog.json` holds this repository's `https` URL (`bme catalog init --repository` writes it); `bme catalog merge` copies it into `sources`.

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

`bme guide publishing` has the `minisign` commands, the URL shapes (a tag, a subdirectory) and the unsigned alternative.

## Continuous check

`.github/workflows/validate.yml` runs `bme catalog index . --check` and `bme catalog validate .` on every push and pull request. No `bme` release exists yet, and `bme` does not record the commit it was built from, so the workflow installs the head of the engine's `main` branch (`cargo install --locked --git https://github.com/juliopolycarpo/biosmod-engine --branch main biosmod-cli`). That head is not pinned. A catalog declares the `engine` it needs (`^0.1` at the start), and `catalog validate` fails with `requires engine` once `main` moves past it. To make the check repeatable, replace `--branch main` in the workflow with `--rev <commit>` or `--tag <tag>`.
