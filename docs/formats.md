# Supported formats

English | [Brazilian Portuguese](pt-BR/formats.md)

| Structure | Support |
|---|---|
| Intel flash descriptor | regions reported by `inspect`; BIOS region not required for parsing |
| Firmware volumes | FFSv2 and FFSv3 file systems; other volumes are listed as opaque |
| FFS files | header and data checksums verified on input and rebuilt on output; large-file headers |
| ACPI | DSDT inside a raw section (`leaf: acpi-table`), table checksum maintained by the hunk itself; `inspect --acpi` lists every checksum-valid table in PE32, TE and raw sections (stored set only) |
| Sections | decoded: FV image, GUID-defined LZMA, GUID-defined CRC32 (checked), compression sections of type 1 (EFI 1.1 and Tiano), GUID-defined Brotli and LZMA F86; leaves: PE32, TE, raw, UI and the rest. Other compression types and GUID-defined encodings stay opaque, so modules inside them report `unsupported`; `inspect --files` and the failing command name each opaque section with its GUID, image offset and reason |
| LZMA | decode bounded to 64 MiB per section and 512 MiB per image; re-encoding reproduces the original properties and is checked by decoding. The only encoding that rebuild supports |
| EFI and Tiano compression | decode only. The stream has no checksum, so bme decodes it as Tiano (5-bit position count) and as EFI 1.1 (4-bit) and keeps the first result that parses as a section stream; `inspect --files` shows which one (`tiano` or `efi`). The decoded length must equal the section header's |
| Brotli | decode only. GUID `3D532050-5CDA-4FD0-879E-0F7F630D5AFB`, EDK II layout: 16-byte header (decoded size, scratch size) then the stream; the stream must produce exactly the declared size |
| LZMA F86 | decode only. GUID `D42AE6BD-1352-4BFB-909A-CA72A6EAE889`: LZMA, then the x86 BCJ filter (instruction pointer 0) |
| Decode-only encodings | share the LZMA bounds: 64 MiB per section and 512 MiB per image, checked against the declared size before decoding. Extracting, scanning and inspecting work; rebuilding or patching a module inside one fails with `FORMAT_UNSUPPORTED` naming the encoding and the section's image offset (inside decoded content, its offset in that stream plus the section it was decoded from), and `scan` reports such patches as `unsupported` |
| PE32/PE32+ | section tables, image base, base relocations, direct branch fields (for signature masking) |
| HII / IFR | package lists in PE, TE or raw bytes (`bme ifr`): string packages (SCSU, UCS-2) and form packages; read-only |
| NVRAM stores | AMI NVAR (records, `next` chains, GUID table, `StdDefaults`/`MfgDefaults` nested stores) and EDK II VSS/VSS2 and `$VSS` (plain and authenticated headers) via `bme nvram`; read-only |
| TE | executable-leaf matching and image-base checks; relocation coverage returns `FORMAT_UNSUPPORTED` |

Limits: images up to 64 MiB, nesting depth 16, catalog files up to 8 MiB, 4096 files per catalog.

Multiple disjoint DSDTs in one RAW section can be selected independently by `table_offset`. When the catalog identifies multiple tables in one file, their ranges must not overlap and a table cannot be resized. Each table patch must maintain its own checksum.

Not supported (explicit `FORMAT_UNSUPPORTED` or `PACKING_REFUSED`): rebuilding inside EFI, Tiano, Brotli or LZMA F86 sections, compression sections of other types, other GUID-defined encodings, Insyde and Phoenix vendor variants, capsules, signed update containers, moving PEI or other execute-in-place modules, resizing a module mid-image, semantic ACPI editing.

Valid checksums are not a signature. bme never strips or recomputes authentication data and cannot tell whether a platform will accept a modified image.
