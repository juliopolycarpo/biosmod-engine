# Before and after flashing

`bme` does not flash. These steps are for writing its output with an external SPI programmer. A bad image leaves a board that will not POST; only flash if you can recover with a programmer (`bme guide recovery`).

## 1. Read the chip twice and keep the dump

Power the board off and unplug it. With a CH341A and a SOIC-8 clip:

```sh
flashrom -p ch341a_spi -r dump1.bin
flashrom -p ch341a_spi -r dump2.bin
cmp dump1.bin dump2.bin && sha256sum dump1.bin
```

Two identical reads mean the clip is seated. The dump also holds board-specific data: the Intel ME region, a GbE MAC address if present, serial numbers and NVRAM settings. Keep it.

## 2. Build from that dump

```sh
bme scan dump1.bin
bme patch dump1.bin --select recommended -o patched.bin
bme verify dump1.bin patched.bin
```

Read `patched.bin.manifest.json`: it lists every changed component and region.

## 3. Write only the BIOS region

```sh
flashrom -p ch341a_spi --ifd -i bios -w patched.bin
```

`--ifd -i bios` leaves the ME and GbE regions untouched. flashrom verifies after writing; read the chip back once more and compare the BIOS region if you want a second check.

## 4. Test one change at a time

Boot several times, cold and warm, and note the POST codes. Then move to the next change. If something regresses you will know which change caused it.

## In-OS flashers

AMI's tools may reject a modified image or refuse to write some regions. A programmer avoids that and keeps a recovery path. bme does not document in-OS flashing.

## Evidence

If an image boots or fails, the result is useful to others only with its exact digest. Record the `sha256` of what you flashed, the board revision, the catalog patch versions and what you observed; `bme guide catalogs` describes evidence records.
