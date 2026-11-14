# Catalogs

English | [Brazilian Portuguese](../pt-BR/guide/catalogs.md)

A catalog is a directory with a fixed layout:

```
catalog.json            index: id, version, engine requirement, optional `repository` and `sources`, every file's path, kind, length and sha256
boards/<id>.json        board and revision profile (bme.board/1)
patches/<id>.json       one patch record (bme.patch/1)
findings/<id>.json      one defect or observation, with or without a patch (bme.finding/1)
evidence/<id>.json      one scoped hardware observation (bme.evidence/1)
provenance/...          supporting files (assembly sources, notes); hashed, never interpreted
```

The official catalog is compiled into `bme`. `bme schema <name>` prints the JSON Schema of each document. Schemas cover shape; `bme catalog validate` also checks references, geometry and hashes.

## Start a device repository

```sh
bme catalog init acme-x99 --id acme-x99 --title "Acme X99 family"
```

`init` writes a directory for one board or board family and does not run git. It refuses an existing directory, an id outside the identifier rule (1-64 characters of `A-Za-z0-9._-`, starting alphanumeric) and the id `official`. `--title` defaults to the id.

`--repository URL` writes the URL of the repository that will hold the catalog into `catalog.json` as `repository`; `catalog split` takes the flag too. The URL must start with `https://`, have a host, carry no credentials, whitespace or control characters, and have at most 2048 characters. `bme` never contacts it. `bme catalog index` keeps the field, and `bme catalog merge` copies it into `sources`.

```sh
bme catalog init acme-x99 --id acme-x99 --repository https://example.org/acme/acme-x99
```

```
catalog.json            empty bme.catalog/1 at version 0.1.0; `bme catalog index` keeps it current
README.md               layout, work loop, commit convention and release rule
.gitignore              allowlist of the paths git tracks
.gitattributes          LF line endings, so the indexed hashes hold on every checkout
.github/workflows/      validate.yml runs `bme catalog index . --check` and `bme catalog validate .` on push and pull request
boards/ findings/ patches/ evidence/ provenance/    the catalog records
notes/                  investigation notes in prose
work/                   dumps, cases, extracted modules, tool output; stays local
```

Git tracks the catalog layout and nothing else: a new top-level path stays local until you add a `!/name` line to `.gitignore`. Git records no empty directory, so each directory reaches a clone with its first file. In every directory, `.gitignore` also ignores firmware images and extracted modules (`*.bin`, `*.rom`, `*.pe`), ACPI tables, archives, PDFs and key files. A dump carries serial numbers and MAC addresses, so it stays out of the history; name it by file name, SHA-256 and size. Copy the dump into `work/` and run `bme case init work/dump.bin -o work/case`: `bme case status` looks for inputs beside the case directory.

Commit one record per commit, with its id in the scope (`feat(H11): record unbounded PCU mailbox waits`) and the re-indexed `catalog.json` in the same commit; check it with `bme catalog index . --check` and `bme catalog validate .`. Change `version` only in a release commit: `bme catalog update` refuses a version it already accepted with other content. Raise it, run `bme catalog index .`, sign `catalog.json` with minisign, commit `catalog.json.minisig` and tag the commit. Users register the tag's raw `catalog.json` URL with `bme catalog add --trust-key`. [Publish a catalog](publishing.md) (`bme guide publishing`) has the signing commands and the URLs.

## Share records between boards

A defect two boards share keeps one id in every board catalog, such as `B02-B03` in the bundled catalog. Each catalog holds the same text and only its own build's variant.

```sh
bme catalog split official --board machinist-pr9-b85 -o pr9-repo --id pr9-b85
bme catalog merge . ../other-board --check
bme catalog merge . ../other-board -o both-boards --id both-boards
```

- `split SOURCE --board BOARD_ID -o DIR --id ID [--repository URL]` starts a board repository from a catalog directory or `official`. It writes the `catalog init` scaffold plus the board's records, and lists every patch, finding, evidence record and provenance file it left out. A patch stays when one of the board's builds has a variant, `applicable` or `not-applicable`. A finding stays when it affects one of the board's builds or a kept patch lists it in `findings`; the second kind may end with no affected build. A `fixed-by-patch` finding left with no patch in `patches` becomes `open`. Evidence stays when it names the board. Provenance stays under the id of a kept record. The catalog keeps the `engine` requirement of its source. It fails when a kept patch requires a dropped patch, when a kept patch lists a finding the catalog does not define, or when a patch with an applicable variant lists a finding that affects none of the board's builds.
- `merge --check SOURCE SOURCE...` writes nothing. It exits 0 with the count of shared records when the catalogs agree, and fails with the record, field, both values and both catalog ids when a shared record drifted. Sources with one catalog id are named `id (#1)`, `id (#2)` by their position. When a source lists `sources` and another given source has the id of one entry, it prints one `pin` line per entry: `pinned`, or `moved` with the pinned and the current digest, plus the first 12 characters of the entry's commit when it has one (`moved (pinned <digest> at commit 1a2b3c4d5e6f, current <digest>)`). A moved pin does not fail the check, because the records can still agree.
- `merge SOURCE SOURCE... -o DIR --id ID` writes a catalog directory with the union, at version `0.1.0` unless `--version` says otherwise. `--description TEXT` sets its description. `--bundled` replaces `--id` and writes the reserved id `official`: the engine repository regenerates `catalog/` with it.

Records match by id. Board lists, patch variants, finding builds, code references and evidence are unioned in the order the sources are given. A finding that is `open` in one catalog and `fixed-by-patch` in another becomes `fixed-by-patch`. Every other field must be equal, and so must the `engine` requirement and the bytes of a provenance file. Patch relations (`requires`, `supersedes`, `conflicts`) and a finding's `patches` must agree on every patch both catalogs define. Code references of a build both catalogs list, and those without a build, must be equal too.

A board catalog records "this patch does not apply here" as a `not-applicable` variant with its reason, next to the finding of that defect with no affected build. `catalog validate` accepts a finding with an empty `affects.builds` only when a patch lists it in `findings` and no patch that lists it has an `applicable` variant. The board does not list that finding in its own `findings`. `split` keeps these records, so merging the board catalogs alone rebuilds a multi-board catalog. `merge -o` writes `sources`: one entry per merged catalog, in order, with its `id`, `version` and `manifest_sha256`, the SHA-256 of its `catalog.json`. An entry also has `repository`, copied from the source's `catalog.json`, and `commit`, when the source directory is a git checkout. Each is omitted when absent.

```json
"sources": [
  {
    "id": "pr9-b85",
    "version": "0.1.0",
    "manifest_sha256": "<sha256 of the source's catalog.json>",
    "repository": "https://example.org/acme/pr9-b85",
    "commit": "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b"
  }
]
```

The digest decides what was merged. `repository` and `commit` say where to fetch that content. `merge` reads the commit from the source's `.git` files without running git: it is the checkout's HEAD at merge time (40 hex characters, or 64 in a SHA-256 repository), including a worktree or submodule whose `.git` is a file. A directory that is not a git checkout, and `official`, get no commit. Uncommitted changes are covered by the digest, not by the commit.

## Boards and firmware builds

A board profile names the vendor, model and revision, and how the revision is known (`observed`, `unverified`, `unknown`). It lists the firmware builds it ships. Patch variants are keyed by firmware build id. A build id belongs to one board of a catalog: two boards that ship the same image get two build ids.

`facts` are hardware statements firmware cannot prove, such as "the Super I/O is an NCT5532D". A variant that depends on one lists it in `requires_facts`, and users must pass `--assert <fact-id>`.

## Patch records

```json
{
  "schema": "bme.patch/1",
  "id": "B05",
  "version": "1.0.0",
  "class": "correction",
  "tier": "recommended",
  "requires": [], "supersedes": [], "conflicts": [],
  "variants": {
    "mnx99mr9apro-230322": {"status": "applicable", "components": [ ... ]},
    "x99ha00m-20221202": {"status": "not-applicable", "reason": "..."}
  }
}
```

- `class` is `correction` or `diagnostic` (needs `--allow-diagnostic`).
- `tier` is `recommended`, `optional` or `hold` (needs `--allow-hold`).
- `packing: manual` marks changes the automatic packer cannot fit; they are reported but never planned.
- `requires` must be selected or already fixed. `supersedes` lists records this one contains. `conflicts` are symmetric and never combined.

A component names one module (`ffs_guid`, `leaf` `pe32` or `acpi-table`), its exact source and result hashes and sizes, and hunks. A hunk is `replace` (same length) or `append` (at the end of the module). `layer_on` plus `input_sha256` describe a patch written against the result of other patches, such as a diagnostic built on top of corrections. `checks` request extra structural checks (`xip_image_base`, `no_relocated_bytes`). `context` requires other modules to match reviewed hashes.

## Findings

A finding records a defect or observation independent of any patch, so one with no fix yet still has a home. The official catalog holds the audit register as one document per row.

```json
{
  "schema": "bme.finding/1",
  "id": "B09",
  "title": "SMM library byte counter over the configuration-table count",
  "priority": "P2",
  "status": "fixed-by-patch",
  "affects": {"label": "MR9A PRO and PR9", "builds": ["mnx99mr9apro-230322", "x99ha00m-20221202"]},
  "owner": {"description": "...", "modules": [{"ui_name": "OEMSmi", "ffs_guid": "..."}], "references": [...]},
  "confidence": {"finding": {"grade": "C0"}, "condition": {"grade": "C3", "note": "trigger"}},
  "description": "...", "not_established": "...", "remediation": "...",
  "evidence": [], "patches": ["B09"]
}
```

- `confidence.finding` grades the code behavior or observation; `confidence.condition` grades the cause or trigger that makes it matter. Both use `C0` (established) to `C3` (speculative), with an optional `note` for the aspect graded.
- `status` is `open`, `fixed-by-patch`, `retired` (withdrawn by later analysis) or `wont-fix` (understood, no change justified).
- `affects.builds` lists firmware build ids; the boards follow from the profiles that ship them. `owner.modules` names the owning FFS file by UI name and GUID, and `owner.references` points to functions or offsets, optionally per build.
- `evidence` lists `bme.evidence/1` ids. `description` states the defect, `not_established` what the analysis does not show, and `remediation` the fix strategy or why there is none.
- A patch lists the findings it resolves in `fixes` (a subset of its `findings`), and each of them lists the patch in `patches`. Validation checks both directions: a `fixed-by-patch` finding needs at least one patch, a patch cannot fix an unknown finding, and the patch's recorded grade for a finding must start with the finding's grade. Every id in a patch's `findings` must name a finding of the catalog: `patch <id>: findings: expected ids of findings in this catalog | received <unknown id>`. A board-scoped load (`catalog validate boards/<id>.json`) loads only the findings its patches fix and its board lists, so it checks `findings` ids against the index of `catalog.json` instead.
- A board lists the findings that concern it in `findings`. `bme scan` prints the open findings of the detected build after the patch table.

The six columns of the audit register (ID, Priority, Confidence, Board / owning code, Finding and status, Patch strategy / fix confidence) map to `id`, `priority`, `confidence`, `affects.label` with `owner.description`, `description` with `not_established`, and `remediation`. `biosmod_core::register` renders findings as that table and parses it back without loss.

### Detectors

A finding can carry `detectors` that find its code in builds the catalog has no variant for. A patch variant matches one build exactly; a detector describes the defective code with masks over addresses and displacements, so one record covers every build that compiles the same routine. A hit never makes a patch applicable: it reports the defect as `likely-present` for the module that holds it, next to the patch states, and `bme scan` prints it for any image.

```json
{
  "id": "byte-counter-scan",
  "title": "8-bit index over a native-width configuration-table count",
  "anchor": {"in": "pe32"},
  "signatures": [
    {"label": "bl-rdx", "defect": {"bytes": "fec30fb6c3483bc272d9"}, "fixed": {"bytes": "48ffc39090483bda72d9"}}
  ],
  "expect": {"min_per_module": 1, "max_per_module": 1}
}
```

This is the shape of the B09 record, shortened to one of its four signatures. B09 leaves `module_kind` out because its copies sit in both DXE drivers and SMM modules.

- `anchor` selects the bytes searched: `{"in": "pe32"}` for the PE32 or TE image of each module, optionally limited by `module_kind` (`peim`, `dxe`, `smm`, by FFS file type) or `ffs_guid`, and `{"in": "dsdt"}` for the DSDT table.
- A signature has a `defect` pattern and, when a catalog patch produces it, a `fixed` pattern. `wild` lists byte indices that match any value. Derive both from patch hunks rather than copying vendor bytes from elsewhere. A pattern needs at least 4 non-wild bytes: fewer match too much code to name a defect.
- `expect` bounds the defect sites per module (default exactly one). A module outside that range is `unexpected-count`, which needs review instead of a claim. Sites are listed up to one past the maximum; the module is then marked `truncated` and the real count is higher.
- Per-module states are `likely-present`, `unexpected-count` and `fixed-pattern` (only the corrected shape occurs, so the defect is absent from the shape the pattern covers). A detector as a whole takes the most urgent module state (`unexpected-count`, then `likely-present`). It is `fixed-pattern` only when every candidate module was readable, `unsupported` when a module it could cover sits in an encapsulation this engine cannot read (the scan text adds an "N unreadable" note to any hit), and `absent` when nothing matches. `absent` does not prove a defect missing from code the pattern does not cover.

## Evidence

An evidence record is one observation: board, firmware build, configuration, the exact patch versions, the `image_sha256` that was flashed, what was seen, and its limits. It is attached to those patch versions only. A record never claims a fix works in general. A `bme scan` patch row lists a record in `evidence` only when the record's `firmware` is the build the scan detected, so a scan of one board's image lists none of another board's observations. With no detected build the rows list no evidence.

## Indexing

Never edit hashes by hand:

```sh
bme catalog index path/to/catalog          # rewrite the files list
bme catalog index path/to/catalog --check  # CI: fail when stale
bme catalog validate path/to/catalog
```

`bme catalog import-x99fix ~/x99-bios-fixes/patches --map mr9a=mnx99mr9apro-230322 --map pr9=x99ha00m-20221202 --commit <sha> -o catalog/patches` converts reference records.
