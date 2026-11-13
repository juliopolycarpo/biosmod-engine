# NVRAM variables

English | [Brazilian Portuguese](../pt-BR/guide/nvram.md)

`bme nvram` reads the variable stores inside a firmware image: what Setup saved, what the defaults say and what older writes left behind. It answers "what is the stored value of this Setup field, and does it match the default?" without booting the board. It is read-only.

This is a separate guide from [Setup forms](ifr.md) because the workflow differs: `bme ifr` explains a question, `bme nvram` shows the bytes the firmware keeps for it. `--field` joins the two.

```sh
bme nvram dump.bin                                   # active records of every store
bme nvram dump.bin --all-records                     # plus history, deleted and orphan records
bme nvram dump.bin --name Setup --store nvar@0x840060
bme nvram dump.bin --field "ACPI Sleep State"        # stored value in every copy, next to the IFR default
bme nvram dump.bin --field "Memory Frequency" --question-id 0xc35
bme nvram dump.bin --name Setup --store StdDefaults --dump -o Setup.default.bin
```

The input is a firmware image (stores are found from the parsed volumes) or one bare NVAR or VSS store.

## Where the stores are

Stores are located structurally, never by searching for `NVAR`; the NVRAM PEI module contains that string as a constant.

- AMI NVAR: an FFS file whose body starts with an `NVAR` record. The stock dumps use a raw file `CEF5B9A3-476D-497F-9FDC-E98143E0422C` filling a 0x40000-byte volume. An all-0xFF file with that GUID is listed as an empty store.
- EDK II VSS and VSS2: a raw file or file-less volume body that starts with a `VARIABLE_STORE_HEADER` (variable store GUID `DDCF3616`, `DDCF3617` or the authenticated `AAF32C78`) or with `$VSS`. Plain and authenticated variable headers are handled. `$FSS`, Intel `TotalSize` headers and Apple variants are not.
- AMI default stores: a record named `StdDefaults` or `MfgDefaults` with GUID `4599D26F-1A11-49B8-B91F-858745CFF824` holds a complete NVAR store of default values, with its own GUID table. It is listed as a nested store (`nvar@0x840060:StdDefaults`) next to its parent.

Store labels (`nvar@0x840060`, `nvar@0x840060:StdDefaults`, `vss@0x…`) carry the image offset of the store. `--store TEXT` keeps stores whose label contains `TEXT`, ignoring case. An image can hold several stores: the PR9 dump has two NVAR stores with different contents (0x800060 and 0x840060). bme reports each on its own and does not guess which one the firmware treats as live.

## Records and states

Each row is one record. An NVAR variable is a chain: the first record carries name and GUID, later data-only records are updates linked by `next`. bme follows the chain and reports:

| State | Meaning |
| --- | --- |
| `active` | the current value: last record of a valid chain, or a VSS record in `ADDED` state |
| `superseded` | history: an older record of a variable that has a newer one |
| `deleted` | NVAR valid bit clear (the whole chain when the first record is invalid), or VSS `DELETED` |
| `incomplete` | VSS header written but data never completed |
| `orphan` | NVAR data-only record that no variable record links to; its name is lost |

A VSS record in deleted transition becomes `superseded` when a completed update of the same variable exists, and `active` otherwise, the way EDK II recovers from an interrupted update.

Per record the table and JSON show store, state, name, GUID, data size, image offset of the record header, flags and the data SHA-256. JSON also has the derived EFI attributes, chain position, extended-header attributes and checksum byte (shown, not verified). NVAR keeps no EFI attributes; bme derives non-volatile and boot-service always, runtime from the NVAR runtime flag.

Variables are identified by name and GUID. The `Setup` variable exists twice in the stock default stores: `EC87D643-…` (the 0x6C or 0x7D byte Setup) and `80E1202E-…` (6 bytes, the recovery form). Filter with `--guid` when the name is not enough.

`--dump -o FILE` writes the data of exactly one record and refuses to overwrite. When filters leave several records it fails with `TARGET_AMBIGUOUS` and lists them; narrow with `--name`, `--guid`, `--store`.

## Size check

NVRAMDxe resets a store when a variable's size differs from the one it expects, so check before changing Setup. When the image has Setup forms, each record is compared with the IFR variable store of the same name and GUID:

```
nvar@0x840060  active  Setup  EC87D643-…  0x6c  …
```

A mismatch prints `0x30 (IFR 0x40: MISMATCH)` and sets `size_mismatch` in JSON. PR9 `Setup` is 0x6C bytes and MR9A 0x7D. A mismatch is a fact about a record, not an error: `PlatformLang`, `BootOrder` and `LegacyDevOrder` are declared with 2 bytes and stored longer, which is normal.

A module whose forms are malformed does not stop the listing: it is reported as a `warning:` line (and under `ifr_diagnostics` in JSON), and its variable stores get no size check. `--field` prints the same warnings, since the skipped module may have held the question.

## Reading a Setup field

`--field "PROMPT"` resolves the question with the IFR decoder, then prints its bytes in every stored copy of the variable beside the form default:

```
"ACPI Sleep State" (question 0x0019): Setup EC87D643-… +0xa, 2 byte(s); IFR variable store 0x6c bytes
IFR default: standard 0x0, manufacturing 0x0
STORE                      STATE   DEFAULTS  RECORD    SIZE  STORED  VS DEFAULT
nvar@0x800060              active  -         0x805873  0x6c  0x0     equal
nvar@0x800060:StdDefaults  active  standard  0x800077  0x6c  0x0     equal
```

- `DEFAULTS` marks records of a defaults store; those are the saved defaults. Rows without it are the values Setup wrote. With `--all-records`, superseded and deleted records appear too, in image order, so the history of the field is visible.
- `VS DEFAULT` compares with the IFR default (standard, or manufacturing for a `MfgDefaults` store). It says `-` when the form states no default or the value is wider than 8 bytes (then `STORED` is the hex bytes).
- A record shorter than `offset + width` shows `outside record` and the size mismatch.
- Prompts repeat. If several questions share the prompt, `--field` fails with `TARGET_AMBIGUOUS` and lists each question ID with its form set; pick one with `--question-id` (decimal or `0x` hex). Questions on the same storage with the same defaults count as one field, so "Memory Frequency", offered three times at `IntelSetup+0x1248`, needs no ID when their defaults agree.
- Questions without variable storage (actions, text) fail with `TARGET_NOT_FOUND`. `--field` needs an image with Setup forms; a bare store gives `USAGE`.

## Corrupt records

A record that cannot be decoded is listed under `issues` with its image offset and the invalid value within the expected shape (`record size: expected 10..=0x2a3 | received 32767`). The walk then resumes at the next `NVAR` signature or `0x55AA` marker, so one damaged record hides nothing after it. Bad GUID indexes, unterminated names, broken extended headers, links that point nowhere or into a loop, and VSS size fields that leave the store are all reported this way.

## Limits

- Offsets are image offsets. Top-level volumes only; stores inside compressed sections are not searched.
- The NVAR GUID table is found by scanning back from the file end until an erased slot, but never past the last record that frames correctly, so a store with no erased gap before the table keeps its records. Damage right in front of a gapless table can still be read as table entries. When the records name more GUID indexes than fit after them, the walk reports `GUID table: expected N entries after the last record`.
- Extended-header layout (attribute byte, optional checksum byte, trailing size) follows UEFITool's `nvram.h`. No stock dump uses it, so that path, inline GUIDs, UCS-2 NVAR names and all VSS support are checked against synthetic stores only. Checksums, timestamps and HMAC data are not verified.
- A live NVRAM region is not part of every dump: the stock MR9A image holds only the `StdDefaults` store, so every value it shows is a saved default. Values Setup wrote need a dump read from a board that has saved Setup.
