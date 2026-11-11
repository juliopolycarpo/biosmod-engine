# Recovery

English | [Brazilian Portuguese](../pt-BR/guide/recovery.md)

If the board does not POST after a flash:

1. Power off and unplug. Clip the programmer onto the SPI chip.
2. Write the BIOS region of your original dump back: `flashrom -p ch341a_spi --ifd -i bios -w dump.bin`.
3. If the descriptor or ME region was overwritten by mistake, write the whole original dump: `flashrom -p ch341a_spi -w dump.bin`.
4. Clear CMOS (jumper or battery) only after reading anything you still need from it, such as MRC breadcrumbs (`bme guide breadcrumbs`).

These steps call flashrom directly because `bme flash write` only writes over a chip that equals a backup, and a half-written chip equals none. To restore through `bme` instead, dump the chip as it is now and use that as the backup:

```sh
sudo bme flash backup -p ch341a_spi -o broken.bin
sudo bme flash write dump.bin --backup broken.bin -p ch341a_spi --dry-run
```

If `bme flash write` reported `FLASH_FAILED` and the board is still running, do not power it off: firmware already loaded keeps running from memory. Restore from the running system with the same two commands and `-p internal`.

If flashrom cannot detect the chip, check the clip orientation (pin 1), that the board is unplugged, and the programmer's voltage (most X99 boards use 3.3 V chips; check the marking).

Keep the failing image and its manifest. Its digest lets others match your report against the exact bytes.
