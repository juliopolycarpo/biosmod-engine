# Catalogs

English | [Brazilian Portuguese](../pt-BR/guide/catalogs.md)

A catalog is a directory with a fixed layout:

```
catalog.json            index: id, version, engine requirement, every file's path, kind, length and sha256
boards/<id>.json        board and revision profile (bme.board/1)
patches/<id>.json       one patch record (bme.patch/1)
evidence/<id>.json      one scoped hardware observation (bme.evidence/1)
provenance/...          supporting files (assembly sources, notes); hashed, never interpreted
```

The official catalog is compiled into `bme`. `bme schema <name>` prints the JSON Schema of each document. Schemas cover shape; `bme catalog validate` also checks references, geometry and hashes.

## Boards and firmware builds

A board profile names the vendor, model and revision, and how the revision is known (`observed`, `unverified`, `unknown`). It lists the firmware builds it ships. Patch variants are keyed by firmware build id, not by board, so two boards that ship the same build share one variant.

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

## Evidence

An evidence record is one observation: board, firmware build, configuration, the exact patch versions, the `image_sha256` that was flashed, what was seen, and its limits. It is attached to those patch versions only. A record never claims a fix works in general.

## Indexing

Never edit hashes by hand:

```sh
bme catalog index path/to/catalog          # rewrite the files list
bme catalog index path/to/catalog --check  # CI: fail when stale
bme catalog validate path/to/catalog
```

`bme catalog import-x99fix ~/x99-bios-fixes/patches --map mr9a=mnx99mr9apro-230322 --map pr9=x99ha00m-20221202 --commit <sha> -o catalog/patches` converts reference records.
