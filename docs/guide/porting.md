# Porting a fix to another build

English | [Brazilian Portuguese](../pt-BR/guide/porting.md)

Many X99-family boards ship related AMI Aptio images. A defect fixed on one build may sit at another offset on yours. bme never patches a module whose hash differs from a recorded source, so you need a variant for your build first.

1. Read your chip (`bme guide flashing`) and scan it: `bme scan dump.bin`. On an unknown build, `likely-present` means every hunk signature of a record matched exactly once. Finding detectors in the catalog also run on unknown builds: a `likely-present` detector hit names the modules that hold the defect and where to derive the variant.
2. Extract the module: `bme extract dump.bin --guid <ffs_guid> -o Module.pe`. To see which modules of your build differ from the reference build, run `bme compare reference.bin dump.bin`: a pair reported `identical-after-normalization` has the same code at another image base, so the reference offsets still apply; the normalized bytes are for the report only and are never written to an image.
3. Analyze it and the reference module: `bme tools analyze --project work/p --output work/x Module.pe` (`bme guide ghidra`).
4. Draft offsets: `bme derive --patch B02-B03 --from-firmware mnx99mr9apro-230322 --component UncoreInitPeim --module Module.pe > draft.json`. The draft is marked `UNREVIEWED`. It takes offsets, original bytes and context from your module and keeps the reference's replacement bytes. `review_offsets` lists hunks whose original bytes differ from the reference (masked addresses or displacements); their replacement bytes almost certainly need recomputing. Hunks not listed can still embed reference addresses.
5. For every hunk: find it in both `.asm` exports, confirm the surrounding function does the same thing, recompute addresses and displacements, and disassemble the patched bytes.
6. Add a board profile and firmware build for your board, add the reviewed component under `variants.<your-firmware-id>`, remove the `draft` field, and run `bme catalog index` and `bme catalog validate`.
7. `bme scan dump.bin --catalog ./my-catalog --allow-unsigned-local` should now report `present`, and a built image `fixed`.

Record a hardware observation only for an image you actually flashed, with its digest.

To see which ACPI methods differ, run `bme compare --acpi A B`, where A and B are ROM images or raw `.aml` tables. Tables pair by signature plus OEM table ID. For each pair, bme walks the AML namespace without executing it and lists methods and named objects that were added, removed or changed, by their full path as stored in the table (padded names such as `\_SB_.PCI0`). `--objects` also lists every object of each table with a hash. `--disassemble DIR` additionally runs `iasl -d` and writes one unified diff per changed method into `DIR`; it needs `iasl` on `PATH` (package `acpica-tools`, listed as an optional row by `bme tools status`) and refuses to overwrite existing files. Without `--disassemble` bme never calls `iasl`. The walk reads declarations only, so a method that is conditionally defined inside another method's body does not appear.
