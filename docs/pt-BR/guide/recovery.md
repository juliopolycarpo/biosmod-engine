# Recuperação

[English](../../guide/recovery.md) | Português (Brasil)

Se a placa não passar pelo POST após a gravação:

1. Desligue e desconecte a placa da tomada. Prenda o clip do gravador ao chip SPI.
2. Grave novamente a região BIOS do dump original: `flashrom -p ch341a_spi --ifd -i bios -w dump1.bin`.
3. Se o descriptor ou a região ME tiver sido sobrescrito por engano, grave todo o dump original: `flashrom -p ch341a_spi -w dump1.bin`.
4. Limpe o CMOS (jumper ou bateria) somente depois de ler o que ainda precisar, como os breadcrumbs MRC (`bme guide breadcrumbs`).

Se o flashrom não detectar o chip, confira a orientação do clip (pino 1), se a placa está desconectada da tomada e a tensão do gravador (a maioria das placas X99 usa chips de 3,3 V; confira a marcação).

Guarde a imagem que falhou e seu manifesto. O hash permite associar seu relato aos bytes exatos.
