# Host diagnostics (`bme diag`)

English | [Brazilian Portuguese](../pt-BR/guide/diagnostics.md)

Several findings rest on what the running machine reports, such as the ACPI tables the kernel published and the sleep states it offers. `bme diag` reads those facts, hashes them and writes a receipt, so someone else can check a claim from the files alone. The MRC checkpoint reader has [its own guide](breadcrumbs.md).

All of it needs Linux. Commands that read protected files or ports need root; run them with `sudo` or `pkexec`.

## Shared rules

- **Read-only unless the command says otherwise.** The only file a read-only command creates is its new output directory.
- **New outputs only.** A capture directory that exists, even empty, is refused before the host is read. Nothing is overwritten or merged into.
- **A receipt for every reading.** A `bme.evidence/1` record of kind `hardware-observation` names the command, the boot ID (`/proc/sys/kernel/random/boot_id`), the kernel release and the SHA-256 of the artifacts, in its `host` object. Board and firmware come from DMI and are not resolved against a catalog, so `bme catalog validate` does not accept these records as catalog evidence; they are receipts.
- **No identity beyond the model.** Serial numbers, UUIDs and asset tags are never copied.
- **Hardware access goes through traits.** The code reads files, the kernel log and ports through `biosmod-host` traits and the tests use named fakes (`FakeSysfs`, `FakeKernelLog`, `FakePrivilege`); no test touches the machine it runs on.

## ACPI capture

```sh
sudo bme diag acpi capture -o capture-2026-11-12
```

Creates the directory and fills it with:

| Path | Content |
|---|---|
| `acpi/tables/` | every file under `/sys/firmware/acpi/tables`, with its sysfs name: `DSDT`, `SSDT1`, `dynamic/SSDT3`, `data/BERT`. Symlinks, anything that is not a regular file, and the per-unit licence tables `MSDM` and `SLIC` are listed as skipped |
| `power/mem_sleep`, `power/state` | the sleep modes the kernel offers and the one selected |
| `kernel/sleep.log` | the kernel messages about suspend, resume and sleep states, as `dmesg` formats them |
| `identity/` | `boot_id`, `osrelease` and `version` |
| `dmi/` | the model fields of `/sys/class/dmi/id` (vendor, product, board, BIOS and chassis names and versions) |
| `manifest.json` | `bme.host-capture/1`: the command, time, boot ID, kernel release, bytes and SHA-256 of every file above, and the sources that were skipped with the reason |
| `evidence.json` | the receipt; its `host.digests` holds the SHA-256 of `manifest.json`, so one digest covers the bundle |

`evidence.json` is written last: a directory without it is an interrupted capture. If any write fails, `bme` removes the directory it created, and reports `PUBLISH_INCOMPLETE` if that fails too.

The kernel log comes from `/dev/kmsg`, read non-blocking, because it needs no helper program and is the same source `dmesg` uses. It is readable without root when `kernel.dmesg_restrict` is 0; the capture itself needs root for the tables.

Tables keep the sysfs names, which are the ACPI signatures, so they pair with the ACPI tables `bme extract` writes from an image. `bme` has no command that compares the two yet.

## Limits

- The tables are what the kernel published at this boot. Firmware patches tables during POST and the OS may load dynamic ones, so they can differ from the tables stored in the image on the chip.
- The kernel messages cover what the ring buffer still holds; a long uptime may have dropped an earlier suspend.
- The receipt shows what one machine reported at one boot. One observation does not change a patch's general confidence.
