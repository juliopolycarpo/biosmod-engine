# MRC checkpoint breadcrumbs (MR9A diagnostic)

English | [Brazilian Portuguese](../pt-BR/guide/breadcrumbs.md)

When memory training stops on `b0` or `b7`, the POST display shows only the major code and the next boot overwrites it. The breadcrumb diagnostic keeps the full MRC checkpoint (major, minor, 16-bit location) in upper-bank CMOS `E0`-`E9`. If a pass dies before it ends, it freezes that checkpoint so Linux can read it after the next good boot.

It is a `diagnostic` record (`MRC-BREADCRUMBS`), layered on B01-B06 and B02-B03 for the MR9A build `mnx99mr9apro-230322`:

```sh
bme plan dump.bin --select B01-B06 B02-B03 MRC-BREADCRUMBS --allow-diagnostic -o plan.json
```

The record checks the module's XIP image base, that no relocation covers a patched byte, and that CmosPei, CmosDxe and PlatformEarlyInit match reviewed hashes. Its assembly source is in the catalog's `provenance/` directory.

## Reading

```sh
sudo bme diag breadcrumbs read
bme diag breadcrumbs decode a1 00 00 00 bf ff ff ff ff 00
```

`read` selects indexes through port 72h and reads 73h. It never touches port 70h (that index register also holds the NMI mask) and never writes a CMOS data byte. A CMOS clear erases the record: after a stuck boot, recover with the DIMM or GPU change first and read before clearing CMOS.

| Index | Meaning |
|---|---|
| `E0` | state: `A0`, plus `2` for slot 1, plus `1` once the pass has ended; anything else means not armed |
| `E1`-`E4` | slot 0, packed checkpoint, little-endian |
| `E5`-`E8` | slot 1 |
| `E9` | failed-pass count, saturates at `FF` |

## Limits

- Completed-pass logging has one hardware observation; retention of a failed pass is not validated. In a no-RAM test that reached POST `53`, no failed record was retained after restoring RAM. The cause is unresolved.
- A stored pass is not a boot verdict: `BF` ends MRC, not the boot. Later errors such as no-GPU `d6` are outside its scope.
- The record is best effort: no checksum, not reset-atomic, not synchronized with other CMOS writers.
- The location field is checkpoint-specific; bme prints it raw.
