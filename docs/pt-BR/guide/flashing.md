# Antes e depois de gravar

[English](../../guide/flashing.md) | Português (Brasil)

No Linux, `bme flash` usa o [flashrom](https://flashrom.org) para diagnosticar o sistema, localizar o chip, fazer o backup e gravar uma imagem. A interface gráfica tem os mesmos passos na página **Gravar chip**. Uma gravação errada ou interrompida pode impedir o POST da placa; grave somente se puder recuperá-la com um gravador externo e o seu backup (`bme guide recovery`).

`flash doctor` funciona com qualquer usuário. Os outros comandos precisam de acesso ao gravador, o que normalmente exige root: execute-os com `sudo`.

## 1. Diagnostique

```sh
bme flash doctor                      # the chip of this machine (programmer: internal)
bme flash doctor -p ch341a_spi        # an external programmer
```

O comando mostra a placa e o firmware informados pelo sistema, o perfil de placa do catálogo com o mesmo fabricante e modelo, a versão do flashrom e uma linha para cada condição que ajuda ou impede o acesso ao chip:

| Verificação | O que é lido |
| --- | --- |
| `flashrom` | o executável escolhido por `--flashrom`, `BME_FLASHROM`, `bme tools set flashrom <caminho>`, depois `PATH`, `/usr/sbin`, `/sbin` e `/usr/local/sbin`, nessa ordem |
| `privileges` | se o comando está sendo executado como root |
| `kernel-lockdown`, `secure-boot` | o lockdown bloqueia o programador interno; ele normalmente acompanha o Secure Boot |
| `internal-access` | `iomem=relaxed`, ou um driver do kernel que ocupa o controlador SPI |
| `bios-write-protection` | `BIOS_CNTL` do PCH Intel (somente root): com `SMM_BWP` ativo, a região BIOS não pode ser gravada a partir do sistema operacional |
| `mtd` | dispositivos flash do kernel utilizáveis como `-p linux_mtd:dev=N` |
| `usb-programmer` | gravadores CH341A, FT2232H, FT232H ou Dediprog conectados |

Root não lê a sua configuração e só executa um caminho absoluto para um arquivo regular que nem o grupo nem outros usuários possam escrever: um `--flashrom` ou `BME_FLASHROM` mais permissivo é recusado antes de qualquer coisa começar. Sem root, um arquivo de configuração que não carrega interrompe um comando flash que leria `tools.flashrom`, em vez de recorrer ao `PATH`; `--flashrom` e `BME_FLASHROM` continuam funcionando. O aplicativo desktop pergunta a `bme tools paths` qual flashrom está em uso antes de cada comando de chip e para se essa consulta falhar. Com `sudo`, passe `--flashrom <caminho>` ou `BME_FLASHROM` para usar um local salvo; as dicas de próximo passo repetem o caminho como absoluto, e o aplicativo desktop passa um caminho salvo ou de `BME_FLASHROM` por você. `bme tools status` mostra onde o flashrom foi encontrado e como instalá-lo.

`FAIL` impede qualquer operação no chip até ser corrigido. `WARN` indica o que tentar se uma operação for recusada. O diagnóstico nunca aciona um gravador.

`-p` aceita qualquer programador do flashrom: `internal`, `ch341a_spi`, `linux_mtd:dev=0`, `ft2232_spi:type=2232H`. Com um gravador externo, desligue a placa, desconecte-a da tomada e encaixe o clip antes.

## 2. Localize o chip

```sh
sudo bme flash probe -p ch341a_spi
```

Se várias definições de chip corresponderem, leia a marcação no chip e informe uma delas aos próximos comandos com `--chip`.

## 3. Faça o backup

```sh
sudo bme flash backup -p ch341a_spi -o dump.bin
```

O chip é lido duas vezes e o dump só é salvo se as duas leituras forem idênticas e não estiverem em branco. O arquivo é novo (nada é sobrescrito) e é devolvido ao usuário que executou o `sudo`. O dump contém dados específicos da placa: a região Intel ME, um endereço MAC GbE se houver, números de série e configurações NVRAM. Guarde-o; ele é o único caminho de volta.

Em algumas placas o programador interno não consegue ler a região ME. `--region` lê ao redor dela:

```sh
sudo bme flash backup -o bios.bin --region bios
```

Esse dump contém o descriptor e as regiões indicadas, com bytes apagados no restante. Ele pode restaurar essas regiões, não o chip inteiro.

## 4. Gere a imagem a partir desse dump

```sh
bme scan dump.bin
bme patch dump.bin --recommended -o patched.bin
bme verify dump.bin patched.bin
```

Leia `patched.bin.manifest.json`: ele lista todos os componentes e regiões alterados.

## 5. Confira e depois grave

```sh
sudo bme flash write patched.bin --backup dump.bin -p ch341a_spi --dry-run
sudo bme flash write patched.bin --backup dump.bin -p ch341a_spi --confirm <image sha256>
```

`flash write` recusa a operação a menos que tudo isto seja verdade:

- a imagem é reconhecida como firmware e tem o tamanho do backup;
- a imagem é igual ao backup fora das regiões que serão gravadas;
- o chip, lido agora, é igual ao backup no descriptor e nessas regiões;
- `--confirm` repete o SHA-256 da imagem mostrado por `--dry-run`.

Por padrão somente a região `bios` do Intel flash descriptor é gravada, o que preserva as regiões ME e GbE. `--region NAME` seleciona outras regiões; `--whole-chip` grava todos os bytes e é obrigatório para chips sem descriptor. Depois que o flashrom grava e verifica, o `bme` lê novamente as regiões gravadas e as compara com a imagem.

`FLASH_REFUSED` significa que nada foi gravado. `FLASH_FAILED` significa que a gravação ou a releitura falhou e o chip pode conter uma imagem parcial: se a placa ainda estiver ligada, mantenha-a assim e siga `bme guide recovery`.

Depois de uma gravação bem-sucedida, o dump antigo não corresponde mais ao chip. Para gravar de novo, ou para restaurar, faça primeiro um novo backup.

## 6. Teste uma alteração por vez

Inicialize várias vezes, a frio e a quente, e anote os códigos POST. Depois passe à próxima alteração. Se houver regressão, você saberá qual alteração a causou.

## Interface gráfica

**Gravar chip** executa os mesmos comandos: **Diagnosticar**, **Localizar chip**, **Fazer backup do chip**, **Conferir** (a simulação) e **Gravar chip**. Com **Pedir direitos de administrador** marcado, os comandos do chip são executados pelo `pkexec`, que precisa de um agente polkit (todos os principais ambientes gráficos têm um). **Gravar chip** fica desativado até que uma conferência tenha passado para o programador, a imagem e o backup atuais e você marque a confirmação de recuperação.

## Limites

Somente o Linux é suportado; em outros sistemas, grave a imagem com um gravador e o software dele. O `bme` não usa os gravadores dos fabricantes: as ferramentas da AMI podem rejeitar uma imagem modificada ou recusar a gravação de algumas regiões. Gravar a partir do sistema operacional não contorna a proteção de escrita do firmware, o Intel Boot Guard nem verificações de assinatura. Uma releitura idêntica mostra o que o chip contém, não que a placa vai inicializar.

## Evidências

Se uma imagem inicializar ou falhar, o resultado só será útil a outras pessoas com seu hash exato. Registre o `sha256` do que foi gravado, a revisão da placa, as versões dos patches do catálogo e o que observou; `bme guide catalogs` descreve registros de evidências.
