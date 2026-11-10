# Recovery

English | [Brazilian Portuguese](../pt-BR/guide/recovery.md)

If the board does not POST after a flash:

1. Power off and unplug. Clip the programmer onto the SPI chip.
2. Write the BIOS region of your original dump back: `flashrom -p ch341a_spi --ifd -i bios -w dump1.bin`.
3. If the descriptor or ME region was overwritten by mistake, write the whole original dump: `flashrom -p ch341a_spi -w dump1.bin`.
4. Clear CMOS (jumper or battery) only after reading anything you still need from it, such as MRC breadcrumbs (`bme guide breadcrumbs`).

If flashrom cannot detect the chip, check the clip orientation (pin 1), that the board is unplugged, and the programmer's voltage (most X99 boards use 3.3 V chips; check the marking).

Keep the failing image and its manifest. Its digest lets others match your report against the exact bytes.
