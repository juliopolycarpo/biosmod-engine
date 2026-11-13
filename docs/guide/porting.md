# Porting a fix to another build

English | [Brazilian Portuguese](../pt-BR/guide/porting.md)

Many X99-family boards ship related AMI Aptio images. A defect fixed on one build may sit at another offset on yours. bme never patches a module whose hash differs from a recorded source, so you need a variant for your build first.

1. Read your chip (`bme guide flashing`) and scan it: `bme scan dump.bin`. On an unknown build, `likely-present` means every hunk signature of a record matched exactly once.
2. Extract the module: `bme extract dump.bin --guid <ffs_guid> -o Module.pe`. To see which modules of your build differ from the reference build, run `bme compare reference.bin dump.bin`: a pair reported `identical-after-normalization` has the same code at another image base, so the reference offsets still apply; the normalized bytes are for the report only and are never written to an image.
3. Analyze it and the reference module: `bme tools analyze --project work/p --output work/x Module.pe` (`bme guide ghidra`).
4. Draft offsets: `bme derive --patch B02-B03 --from-firmware mnx99mr9apro-230322 --component UncoreInitPeim --module Module.pe > draft.json`. The draft is marked `UNREVIEWED`. It takes offsets, original bytes and context from your module and keeps the reference's replacement bytes. `review_offsets` lists hunks whose original bytes differ from the reference (masked addresses or displacements); their replacement bytes almost certainly need recomputing. Hunks not listed can still embed reference addresses.
5. For every hunk: find it in both `.asm` exports, confirm the surrounding function does the same thing, recompute addresses and displacements, and disassemble the patched bytes.
6. Add a board profile and firmware build for your board, add the reviewed component under `variants.<your-firmware-id>`, remove the `draft` field, and run `bme catalog index` and `bme catalog validate`.
7. `bme scan dump.bin --catalog ./my-catalog --allow-unsigned-local` should now report `present`, and a built image `fixed`.

Record a hardware observation only for an image you actually flashed, with its digest.
