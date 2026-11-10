# Supported formats

English | [Brazilian Portuguese](pt-BR/formats.md)

| Structure | Support |
|---|---|
| Intel flash descriptor | regions reported by `inspect`; BIOS region not required for parsing |
| Firmware volumes | FFSv2 and FFSv3 file systems; other volumes are listed as opaque |
| FFS files | header and data checksums verified on input and rebuilt on output; large-file headers |
| Sections | decoded: FV image, GUID-defined LZMA, GUID-defined CRC32 (checked); leaves: PE32, TE, raw, UI and the rest. Compression sections (type 01) and other GUID-defined encodings stay opaque, so modules inside them report `unsupported` |
| LZMA | decode bounded to 64 MiB per section and 512 MiB per image; re-encoding reproduces the original properties and is checked by decoding |
| ACPI | DSDT inside a raw section (`leaf: acpi-table`), table checksum maintained by the hunk itself |
| PE32/PE32+ | section tables, image base, base relocations, direct branch fields (for signature masking) |
| TE | executable-leaf matching and image-base checks; relocation coverage returns `FORMAT_UNSUPPORTED` |

Limits: images up to 64 MiB, nesting depth 16, catalog files up to 8 MiB, 4096 files per catalog.

Not supported (explicit `FORMAT_UNSUPPORTED` or `PACKING_REFUSED`): EFI standard compression, TianoCompress, Brotli and other GUID-defined encodings, capsules, signed update containers, moving PEI or other execute-in-place modules, resizing a module mid-image, semantic ACPI editing.

Valid checksums are not a signature. bme never strips or recomputes authentication data and cannot tell whether a platform will accept a modified image.
