# Before and after flashing

English | [Brazilian Portuguese](../pt-BR/guide/flashing.md)

On Linux, `bme flash` drives [flashrom](https://flashrom.org) to diagnose the system, find the chip, back it up and write an image. The desktop interface has the same steps on its **Flash chip** page. A bad or interrupted write leaves a board that will not POST; only flash if you can recover with an external programmer and your backup (`bme guide recovery`).

`flash doctor` runs as any user. The other commands need access to the programmer, which usually means root: run them with `sudo`.

## 1. Diagnose

```sh
bme flash doctor                      # the chip of this machine (programmer: internal)
bme flash doctor -p ch341a_spi        # an external programmer
```

It prints the board and firmware the system reports, the catalog board profile with the same vendor and model, the flashrom version, and one line per condition that helps or blocks chip access:

| Check | What it reads |
| --- | --- |
| `flashrom` | the executable chosen by `--flashrom`, `BME_FLASHROM`, `bme tools set flashrom <path>`, then `PATH`, `/usr/sbin`, `/sbin` and `/usr/local/sbin`, in that order |
| `privileges` | whether the command runs as root |
| `kernel-lockdown`, `secure-boot` | lockdown blocks the internal programmer; it usually comes with Secure Boot |
| `internal-access` | `iomem=relaxed`, or a kernel driver that claims the SPI controller |
| `bios-write-protection` | `BIOS_CNTL` of the Intel PCH (root only): with `SMM_BWP` set the BIOS region cannot be written from the OS |
| `mtd` | kernel flash devices usable as `-p linux_mtd:dev=N` |
| `usb-programmer` | connected CH341A, FT2232H, FT232H or Dediprog programmers |

Root never reads your configuration, and it runs only an absolute path to a regular file that neither the group nor other users can write: a looser `--flashrom` or `BME_FLASHROM` is refused before anything starts. Without root, a configuration file that does not load stops a flash command that would read `tools.flashrom`, rather than falling back to `PATH`; `--flashrom` and `BME_FLASHROM` still work. The desktop app asks `bme tools paths` which flashrom is in use before each chip command and stops if that lookup fails. Under `sudo`, pass `--flashrom <path>` or `BME_FLASHROM` to use a saved location; the next-step hints repeat the path as an absolute one, and the desktop app passes a saved or `BME_FLASHROM` path for you. `bme tools status` shows where flashrom was found and how to install it.

`FAIL` stops every chip operation until fixed. `WARN` names what to try if an operation is refused. The doctor never starts a programmer.

`-p` takes any flashrom programmer: `internal`, `ch341a_spi`, `linux_mtd:dev=0`, `ft2232_spi:type=2232H`. With an external programmer, power the board off, unplug it and seat the clip first.

## 2. Find the chip

```sh
sudo bme flash probe -p ch341a_spi
```

If several chip definitions match, read the marking on the chip and pass one to the next commands with `--chip`.

## 3. Back up

```sh
sudo bme flash backup -p ch341a_spi -o dump.bin
```

The chip is read twice and the dump is saved only if both reads are identical and not blank. The file is new (nothing is overwritten) and is handed back to the user who ran `sudo`. The dump holds board-specific data: the Intel ME region, a GbE MAC address if present, serial numbers and NVRAM settings. Keep it; it is the only way back.

On some boards the internal programmer cannot read the ME region. `--region` reads around it:

```sh
sudo bme flash backup -o bios.bin --region bios
```

That dump holds the descriptor and the named regions, with erased bytes elsewhere. It can restore those regions, not the whole chip.

## 4. Build from that dump

```sh
bme scan dump.bin
bme patch dump.bin --recommended -o patched.bin
bme verify dump.bin patched.bin
```

Read `patched.bin.manifest.json`: it lists every changed component and region.

## 5. Check, then write

```sh
sudo bme flash write patched.bin --backup dump.bin -p ch341a_spi --dry-run
sudo bme flash write patched.bin --backup dump.bin -p ch341a_spi --confirm <image sha256>
```

`flash write` refuses unless all of these hold:

- the image parses as firmware and has the size of the backup;
- the image equals the backup outside the regions being written;
- the chip, read now, equals the backup in the descriptor and in those regions;
- `--confirm` repeats the image SHA-256 that `--dry-run` printed.

By default only the `bios` region of the Intel flash descriptor is written, so the ME and GbE regions stay untouched. `--region NAME` selects other regions; `--whole-chip` writes every byte and is required for chips without a descriptor. After flashrom writes and verifies, `bme` reads the written regions back and compares them with the image.

`FLASH_REFUSED` means nothing was written. `FLASH_FAILED` means the write or the read-back failed and the chip may hold a partial image: if the board is still running, leave it on and follow `bme guide recovery`.

After a successful write the old dump no longer matches the chip. To write again, or to restore, take a new backup first.

## 6. Test one change at a time

Boot several times, cold and warm, and note the POST codes. Then move to the next change. If something regresses you will know which change caused it.

## Desktop interface

**Flash chip** runs the same commands: **Diagnose**, **Find chip**, **Back up chip**, **Check** (the dry run) and **Flash chip**. With **Ask for administrator rights** ticked, the chip commands run through `pkexec`, which needs a polkit agent (every major desktop has one). **Flash chip** stays disabled until a check passed for the current programmer, image and backup and you tick the recovery confirmation.

## Limits

Only Linux is supported; elsewhere write the image with a programmer and its own software. `bme` does not use vendor flashers: AMI's tools may reject a modified image or refuse to write some regions. Writing from the OS does not bypass firmware write protection, Intel Boot Guard or signature checks. A matching read-back shows what the chip holds, not that the board will boot.

## Evidence

If an image boots or fails, the result is useful to others only with its exact digest. Record the `sha256` of what you flashed, the board revision, the catalog patch versions and what you observed; `bme guide catalogs` describes evidence records.
