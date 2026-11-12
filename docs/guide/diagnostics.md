# Host diagnostics (`bme diag`)

English | [Brazilian Portuguese](../pt-BR/guide/diagnostics.md)

Several findings rest on what the running machine reports, such as the ACPI tables the kernel published, the sleep states it offers and the registers of the fan controller and how far a suspend gets. `bme diag` reads those facts, hashes them and writes a receipt, so someone else can check a claim from the files alone. The MRC checkpoint reader has [its own guide](breadcrumbs.md).

All of it needs Linux. Commands that read protected files or ports need root; run them with `sudo` or `pkexec`.

## Shared rules

- **Read-only unless the command says otherwise.** The only file a read-only command creates is its new output directory. `diag superio read` also writes the chip's access selectors and `diag suspend pm-test` writes `/sys/power/pm_test` and `/sys/power/state`; nothing else is written.
- **New outputs only.** A capture directory that exists, even empty, is refused before the host is read. Nothing is overwritten or merged into.
- **A refusal is an error, not a guess.** `HOST_REFUSED` means the user, the detected chip or the requested mode is outside what the command's safety rules cover; no configuration was changed, and at most a chip probe wrote its access selectors. `HOST_FAILED` is the other way round: the command ran, the result is a failure, and the evidence was saved anyway.
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

## Super I/O registers

```sh
sudo bme diag superio read
sudo bme diag superio read --json -o fan-controller-2026-11-12
sudo bme diag superio read --unbound-only
```

Reads the fan controller the way the one-off scripts did, with the safety rules built in:

0. **It checks for a kernel driver first.** A bound `nct6775` caches the monitor's bank selection and writes fan registers on its own schedule; switching the bank through `/dev/port` behind it can misdirect one of its writes, and the kernel's region claims do not cover `/dev/port`. `bme` looks for a hwmon device whose `name` the chip table lists for the family (`/sys/class/hwmon/*/name`) and for a `/proc/ioports` entry labelled with the module. Other Super I/O drivers count too (`it87`, `f71882fg`, `w83627ehf`, `nct6683` hwmon names), and so does any holder of a configuration port in `/proc/ioports` that is not a firmware reservation (`pnp`, `motherboard`, `PCI`, `ACPI`), and any claim that overlaps the monitor's own ports once the chip reports them (checked before a bank register is written). Only `nct6775` has a checked sysfs layout, so for it, if found, no port is touched: the reading is what the driver publishes (`pwmN`, `pwmN_enable`, `pwmN_auto_point*`, `fanN_input`, `tempN_input`, `tempN_label` and the other `pwm`, `fan` and `temp` files), and it states that the register map, the banks and anything the driver does not expose are not available through sysfs. `--unbound-only` turns the `nct6775` case into `HOST_REFUSED` naming the module; every other claimant is refused with `HOST_REFUSED` whether or not the flag is given, naming the claimant (the `/proc/ioports` label may not be a module name). Either way the message gives the step for a person to run, `sudo modprobe -r nct6775`; `bme` never unloads a driver. A hwmon or ioports listing that exists but cannot be read is an error, not "no driver". In `--json` the reading carries `source`: `raw-ports` or `hwmon-sysfs`.
1. It probes the configuration ports 2Eh and 4Eh: the entry key, then the chip ID. An address where nothing answers is left alone.
2. It looks the ID up in the chip table. An ID no entry claims is refused with `HOST_REFUSED` and the ID in the message; the chip is left in the state it was found in. The low nibble of the ID is the silicon revision and is ignored (the MR9A's chip answers `0xC562`; the datasheet lists `0xC561`). The table entry is named for the family, `NCT5532D/NCT6779D`: the Linux `nct6775` driver documents the two together under ID `0xC56x`, so the ID alone does not say which one the board carries; the chip marking does.
3. It reads the logical devices the map lists (activation and, where the device has one, the I/O base), then the hardware-monitor registers the map lists, bank by bank, through the monitor's index and data ports.
4. It leaves configuration mode and puts the monitor bank register back.

The only writes are **access selectors**: the entry and exit keys, register indexes, the logical device number register and the monitor's bank register. The previous logical device and bank selection are restored on every path, including a failure halfway through. No fan, sensor or NVRAM register is written. The tests enforce this with a fake chip that rejects any other data-port write.

`--json` returns `reading` (`chip_id`, `hwm_active`, `hwm_base`, `registers` by bank and register, `logical_devices`) and the `evidence` record; the field names follow the hand-made `live-controller.json` of the MR9A fan-stop analysis, and on that board the values match it. With `-o DIR` the reading is also saved as `superio.json` with `manifest.json` and `evidence.json`, like a capture.

The chips are data in `crates/biosmod-host/data/superio.json`: configuration ports, entry and exit keys, ID registers, value and mask, logical devices, the hardware-monitor access protocol and the registers to read, plus a `source` naming the document the map came from. Adding an NCT67xx, ITE IT87xx or Fintek F718xx is a new entry with its own source; the loader rejects an entry without one. Only the NCT5532D/NCT6779D family is listed today.

It needs root and `/dev/port` (Linux); `--device` names another file for testing.

## Suspend test stages

```sh
sudo bme diag suspend pm-test --stage freezer -o pm-freezer-2026-11-12 --i-understand-this-suspends
```

Runs one stage of the kernel's suspend test. `/sys/power/pm_test` makes the next suspend stop at a checkpoint, wait five seconds and unwind, so the stages up to that point run without the machine sleeping. The stages, in the order the kernel reaches them:

| Stage | What has run when it stops |
| --- | --- |
| `freezer` | user space and kernel threads are frozen |
| `devices` | every device driver suspended |
| `platform` | the firmware's suspend preparation (ACPI `_PTS`) |
| `processors` | the non-boot processors are offline |
| `core` | the system core devices are suspended |

The command takes `--stage` and `--i-understand-this-suspends`, which is required: the desktop freezes for several seconds and a stage that goes wrong can leave the machine hung. Save your work first. It runs one stage per run, so a failure names its stage.

What it checks, in order, and refuses with `HOST_REFUSED` before writing anything:

1. The user is root.
2. The stage is not `none`: that is a real sleep, and a command that cannot wake the machine is not a diagnostic.
3. `/sys/power/pm_test` lists the stage and currently selects `none`. A test somebody else armed is not touched. A leftover from a killed run looks the same, so the refusal names the repair: `echo none > /sys/power/pm_test`, to run once nothing else is testing.
4. `/sys/power/state` lists `mem`.
5. For `platform`, `processors` and `core`, `/sys/power/mem_sleep` selects `deep`. With `s2idle` the kernel never reaches those checkpoints, and the write would be a real sleep. `freezer` and `devices` stop before the mode matters, so they run under `s2idle`, which is what the MR9A boots with.

Then it reads `/sys/power/suspend_stats` and the kernel log, flushes file buffers (`sync`), writes the stage, **reads it back** and only then writes `mem`. If the selection did not take effect, `mem` is never written. Whatever happens next, it writes `none` back and reads that back too; if that fails, the error says `echo none > /sys/power/pm_test`, because the stage is still armed and the next suspend of any kind would stop there.

The verdict is the machine's own counters: **pass** is exactly one more `success` and no more `fail`. A counted failure is **fail**; a run that could not arm or trigger the test, with no counter moving, is **error**. The report has the counters before and after, their delta, the start and finish times and the kernel messages that appeared during the run. It is saved as `pm-test.json` and `kernel/delta.log` with the manifest and the evidence record. A **fail** or **error** is still saved, and then the command exits with `HOST_FAILED` and the report in the error details.

## Limits

- The tables are what the kernel published at this boot. Firmware patches tables during POST and the OS may load dynamic ones, so they can differ from the tables stored in the image on the chip.
- The kernel messages cover what the ring buffer still holds; a long uptime may have dropped an earlier suspend.
- The Super I/O reading is a snapshot: temperatures, fan speeds and duty cycles move. Register meanings come from the chip's map, not from this board's wiring; which header a fan channel drives is not established. Probing writes the entry key to ports 2Eh and 4Eh, as every Super I/O driver does; a different device decoding those ports would see it.
- A pm-test pass says the kernel's steps up to that stage worked. It does not say the machine can enter and leave the sleep state: no real sleep happens, and the platform's own resume path is not exercised. Intermittent failures need repeated runs. The stages and the guards were written from the kernel's documented behavior and tested against an in-memory fake of `/sys/power`; no run on real hardware backs them yet.
- The receipt shows what one machine reported at one boot. One observation does not change a patch's general confidence.
