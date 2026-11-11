# Antes e depois de gravar

[English](../../guide/flashing.md) | Português (Brasil)

O `bme` não grava chips. Estes passos são para gravar sua saída com um gravador SPI externo. Uma imagem incorreta pode impedir o POST da placa; grave somente se puder recuperá-la com um gravador (`bme guide recovery`).

## 1. Leia o chip duas vezes e guarde o dump

Desligue a placa e desconecte-a da tomada. Com um CH341A e um clip SOIC-8:

```sh
flashrom -p ch341a_spi -r dump1.bin
flashrom -p ch341a_spi -r dump2.bin
cmp dump1.bin dump2.bin && sha256sum dump1.bin
```

Duas leituras idênticas indicam que o clip está bem encaixado. O dump também contém dados específicos da placa: a região Intel ME, um endereço MAC GbE se houver, números de série e configurações NVRAM. Guarde-o.

## 2. Gere a imagem a partir desse dump

```sh
bme scan dump1.bin
bme patch dump1.bin --recommended -o patched.bin
bme verify dump1.bin patched.bin
```

Leia `patched.bin.manifest.json`: ele lista todos os componentes e regiões alterados.

## 3. Grave somente a região BIOS

```sh
flashrom -p ch341a_spi --ifd -i bios -w patched.bin
```

`--ifd -i bios` preserva as regiões ME e GbE. O flashrom verifica após gravar; leia o chip novamente e compare a região BIOS se quiser uma segunda conferência.

## 4. Teste uma alteração por vez

Inicialize várias vezes, a frio e a quente, e anote os códigos POST. Depois passe à próxima alteração. Se houver regressão, você saberá qual alteração a causou.

## Gravadores executados no sistema operacional

As ferramentas da AMI podem rejeitar uma imagem modificada ou recusar a gravação de algumas regiões. Um gravador evita isso e mantém um caminho de recuperação. O bme não documenta gravação a partir do sistema operacional.

## Evidências

Se uma imagem inicializar ou falhar, o resultado só será útil a outras pessoas com seu hash exato. Registre o `sha256` do que foi gravado, a revisão da placa, as versões dos patches do catálogo e o que observou; `bme guide catalogs` descreve registros de evidências.
