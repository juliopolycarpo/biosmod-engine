# Setup forms (IFR)

English | [Brazilian Portuguese](../pt-BR/guide/ifr.md)

`bme ifr` reads the Setup menu of an AMI Aptio image without external tools. It finds the HII package lists inside PE modules, decodes the string and form packages, and prints every question with the data a Setup patch needs: prompt, question ID, variable store (name and GUID), offset, width, range, options, defaults and the `SuppressIf`, `GrayOutIf` and `DisableIf` conditions around it.

```sh
bme ifr dump.bin                                          # every PE that holds IFR
bme ifr dump.bin --guid 899407D7-99FE-43D8-9A21-79EC328CAC21 --json
bme extract dump.bin --guid 899407D7-99FE-43D8-9A21-79EC328CAC21 -o Setup.pe
bme ifr Setup.pe --language en-US
```

The input is a firmware image or a bare PE, TE or raw section. With an image, `--guid` limits the decode to one FFS file; without it, every PE32 or TE module with a form package is decoded (Setup, platform pages, flash tools). `--language` picks the string package: `en-US` by default, otherwise the first language present.

## Reading the table

One table per form, one row per question:

```
0x0019  one_of  "ACPI Sleep State"  Setup+0xa/2  0x0..0x0  default 0  0="Suspend Disabled" (default, mfg)  suppress: ideqval 0x17 == 1 && grayout: ideqval 0xd3 == 1
```

- `Setup+0xa/2` is variable store `Setup`, byte offset `0x0A`, width 2 bytes. A question stores its value at that offset of the NVRAM variable (the store GUID and name identify the variable).
- `default N` comes from an explicit `Default` opcode, then from an option flagged default, then from the checkbox flags. `(default, mfg)` marks options flagged as standard and manufacturing default.
- Conditions are listed from the outermost scope in. `ideqval 0x17 == 1` means "question `0x17` equals 1". A question is hidden while its `suppress` condition holds, and read-only while a `grayout` or `disable` condition holds.
- A condition can wrap a whole form (AMI Platform does this). Its questions list that condition too, and the form carries it in `forms[].conditions`. A form inside a question or another form is still rejected.
- `--json` returns the full structure under `data.modules[].package_lists[].form_sets[].forms[].statements[]`. Besides the table columns it has `opcode_offset` (bytes from the start of the module), `varstore_id`, `question_flags`, option offsets and every explicit `Default` with its default ID (0 standard, 1 manufacturing).

Prompts are not unique. The same prompt can appear in several forms under different conditions, so match on question ID or on prompt plus conditions.

## Limits

- Read-only. Nothing is written to the image.
- Opcode lengths, nesting (64 scopes) and package bounds are checked. A malformed package fails with `FORMAT_INVALID` naming the offset and opcode, for example `opcode End (0x29) at 0x31: End without an open scope`.
- On an image, a module whose forms are malformed is reported as a `warning:` line (and in `data.diagnostics` with `--json`) while the other modules still print. With `--guid` the same failure is an error.
- Condition text is capped at 1024 bytes and 512 expression opcodes; a longer expression ends with `…`.
- Package lists must close exactly on their declared length; standalone form packages without a list header are not found.
- Expression conditions that bme does not know render as `opcode_0xNN`; the scope structure is still followed.
- Date and time defaults are not decoded to values.
- 8-bit (SCSU) string blocks are read as Latin-1; UCS-2 blocks are decoded in full. Font blocks are rejected.
- Offsets and widths come from the form, not from a running system. Whether the firmware honors an out-of-range value is a hardware question.
