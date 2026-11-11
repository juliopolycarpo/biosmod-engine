# Recuperação

[English](../../guide/recovery.md) | Português (Brasil)

Se a placa não passar pelo POST após a gravação:

1. Desligue e desconecte a placa da tomada. Prenda o clip do gravador ao chip SPI.
2. Grave novamente a região BIOS do dump original: `flashrom -p ch341a_spi --ifd -i bios -w dump.bin`.
3. Se o descriptor ou a região ME tiver sido sobrescrito por engano, grave todo o dump original: `flashrom -p ch341a_spi -w dump.bin`.
4. Limpe o CMOS (jumper ou bateria) somente depois de ler o que ainda precisar, como os breadcrumbs MRC (`bme guide breadcrumbs`).

Esses passos chamam o flashrom diretamente porque `bme flash write` só grava sobre um chip igual a um backup, e um chip gravado pela metade não é igual a nenhum. Para restaurar pelo `bme`, leia o chip como ele está agora e use essa leitura como backup:

```sh
sudo bme flash backup -p ch341a_spi -o broken.bin
sudo bme flash write dump.bin --backup broken.bin -p ch341a_spi --dry-run
```

Se `bme flash write` informou `FLASH_FAILED` e a placa ainda estiver ligada, não a desligue: o firmware já carregado continua em execução na memória. Restaure a partir do sistema em execução com os mesmos dois comandos e `-p internal`.

Se o flashrom não detectar o chip, confira a orientação do clip (pino 1), se a placa está desconectada da tomada e a tensão do gravador (a maioria das placas X99 usa chips de 3,3 V; confira a marcação).

Guarde a imagem que falhou e seu manifesto. O hash permite associar seu relato aos bytes exatos.
