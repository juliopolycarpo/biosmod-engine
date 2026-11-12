# Diagnósticos do host (`bme diag`)

[English](../../guide/diagnostics.md) | Português (Brasil)

Vários achados dependem do que a máquina em execução informa, como as tabelas ACPI que o kernel publicou, os estados de suspensão que ele oferece e os registradores do controlador de ventoinhas e até onde uma suspensão chega. `bme diag` lê esses fatos, calcula seus hashes e escreve um recibo, para que outra pessoa confira uma afirmação apenas pelos arquivos. O leitor de checkpoints MRC tem [guia próprio](breadcrumbs.md).

Tudo exige Linux. Comandos que leem arquivos ou portas protegidos exigem root; execute com `sudo` ou `pkexec`.

## Regras comuns

- **Somente leitura, salvo quando o comando disser o contrário.** O único arquivo que um comando de leitura cria é o seu novo diretório de saída. `diag superio read` também grava os seletores de acesso do chip e `diag suspend pm-test` grava `/sys/power/pm_test` e `/sys/power/state`; nada além disso é gravado.
- **Somente saídas novas.** Um diretório de captura que já existe, mesmo vazio, é recusado antes de ler o host. Nada é sobrescrito nem mesclado.
- **Uma recusa é um erro, não um palpite.** `HOST_REFUSED` significa que o usuário, o chip detectado ou o modo pedido está fora do que as regras de segurança do comando cobrem; nenhuma configuração foi alterada e, no máximo, uma sondagem de chip gravou seus seletores de acesso. `HOST_FAILED` é o inverso: o comando rodou, o resultado é uma falha e a evidência foi salva mesmo assim.
- **Um recibo para cada leitura.** Um registro `bme.evidence/1` do tipo `hardware-observation` informa o comando, o boot ID (`/proc/sys/kernel/random/boot_id`), a versão do kernel e o SHA-256 dos artefatos, no objeto `host`. Placa e firmware vêm do DMI e não são resolvidos em um catálogo; por isso `bme catalog validate` não aceita esses registros como evidência de catálogo. São recibos.
- **Nenhuma identidade além do modelo.** Números de série, UUIDs e etiquetas de patrimônio nunca são copiados.
- **O acesso ao hardware passa por traits.** O código lê arquivos, o log do kernel e portas por traits de `biosmod-host` e os testes usam fakes nomeados (`FakeSysfs`, `FakeKernelLog`, `FakePrivilege`); nenhum teste toca a máquina em que roda.

## Captura ACPI

```sh
sudo bme diag acpi capture -o capture-2026-11-12
```

Cria o diretório e o preenche com:

| Caminho | Conteúdo |
|---|---|
| `acpi/tables/` | todo arquivo sob `/sys/firmware/acpi/tables`, com o nome do sysfs: `DSDT`, `SSDT1`, `dynamic/SSDT3`, `data/BERT`. Links simbólicos, o que não for arquivo regular e as tabelas de licença por unidade `MSDM` e `SLIC` são listados como ignorados |
| `power/mem_sleep`, `power/state` | os modos de suspensão que o kernel oferece e o selecionado |
| `kernel/sleep.log` | as mensagens do kernel sobre suspensão, retomada e estados de sono, no formato do `dmesg` |
| `identity/` | `boot_id`, `osrelease` e `version` |
| `dmi/` | os campos de modelo de `/sys/class/dmi/id` (fabricante, produto, placa, BIOS e chassi, nomes e versões) |
| `manifest.json` | `bme.host-capture/1`: o comando, a hora, o boot ID, a versão do kernel, os bytes e o SHA-256 de cada arquivo acima, e as fontes ignoradas com o motivo |
| `evidence.json` | o recibo; seu `host.digests` guarda o SHA-256 de `manifest.json`, então um único hash cobre o pacote |

`evidence.json` é escrito por último: um diretório sem ele é uma captura interrompida. Se qualquer gravação falhar, o `bme` remove o diretório que criou e informa `PUBLISH_INCOMPLETE` se isso também falhar.

O log do kernel vem de `/dev/kmsg`, lido sem bloquear, porque não precisa de programa auxiliar e é a mesma fonte do `dmesg`. Ele é legível sem root quando `kernel.dmesg_restrict` é 0; a captura em si exige root por causa das tabelas.

As tabelas mantêm os nomes do sysfs, que são as assinaturas ACPI, então combinam com as tabelas ACPI que `bme extract` grava a partir de uma imagem. O `bme` ainda não tem comando que compare as duas.

## Registradores do Super I/O

```sh
sudo bme diag superio read
sudo bme diag superio read --json -o fan-controller-2026-11-12
sudo bme diag superio read --unbound-only
```

Lê o controlador de ventoinhas como faziam os scripts avulsos, com as regras de segurança embutidas:

0. **Antes, verifica se há driver do kernel.** Um `nct6775` ligado guarda em cache o banco selecionado do monitor e grava nos registradores das ventoinhas no próprio ritmo; trocar o banco por `/dev/port` por trás dele pode desviar uma das gravações, e as reservas de região do kernel não cobrem `/dev/port`. O `bme` procura um dispositivo hwmon cujo `name` a tabela de chips lista para a família (`/sys/class/hwmon/*/name`) e uma entrada de `/proc/ioports` com o nome do módulo. Outros drivers de Super I/O também contam (nomes hwmon de `it87`, `f71882fg`, `w83627ehf`, `nct6683`), assim como qualquer detentor de uma porta de configuração em `/proc/ioports` que não seja reserva do firmware (`pnp`, `motherboard`, `PCI`, `ACPI`), e qualquer reserva que se sobreponha às portas do próprio monitor assim que o chip as informa (verificado antes de gravar em um registrador de banco). Só o `nct6775` tem layout de sysfs verificado, então para ele, se achar, nenhuma porta é tocada: a leitura é o que o driver publica (`pwmN`, `pwmN_enable`, `pwmN_auto_point*`, `fanN_input`, `tempN_input`, `tempN_label` e os demais arquivos `pwm`, `fan` e `temp`), e o resultado diz que o mapa de registradores, os bancos e o que o driver não expõe não estão disponíveis pelo sysfs. `--unbound-only` transforma o caso do `nct6775` em `HOST_REFUSED` com o nome do módulo; qualquer outro detentor é recusado com `HOST_REFUSED` com ou sem a opção, com o nome do detentor (o rótulo de `/proc/ioports` pode não ser nome de módulo). Nos dois casos a mensagem traz o passo para a pessoa executar, `sudo modprobe -r nct6775`; o `bme` nunca descarrega um driver. Uma listagem de hwmon ou ioports que existe mas não pode ser lida é erro, não "sem driver". Em `--json` a leitura traz `source`: `raw-ports` ou `hwmon-sysfs`.
1. Sonda as portas de configuração 2Eh e 4Eh: a chave de entrada e depois o ID do chip. Um endereço em que nada responde é deixado em paz.
2. Procura o ID na tabela de chips. Um ID que nenhuma entrada reivindica é recusado com `HOST_REFUSED` e o ID na mensagem; o chip fica no estado em que foi encontrado. O nibble baixo do ID é a revisão do silício e é ignorado (o chip da MR9A responde `0xC562`; a folha de dados lista `0xC561`). A entrada da tabela leva o nome da família, `NCT5532D/NCT6779D`: o driver `nct6775` do Linux documenta os dois juntos sob o ID `0xC56x`, então o ID sozinho não diz qual deles a placa tem; quem diz é a marcação do chip.
3. Lê os dispositivos lógicos que o mapa lista (ativação e, quando o dispositivo tem, a base de E/S) e depois os registradores do monitor de hardware que o mapa lista, banco a banco, pelas portas de índice e de dados do monitor.
4. Sai do modo de configuração e devolve o registrador de banco do monitor.

As únicas gravações são **seletores de acesso**: as chaves de entrada e saída, os índices de registrador, o registrador de número do dispositivo lógico e o registrador de banco do monitor. A seleção anterior de dispositivo lógico e de banco é restaurada em todos os caminhos, inclusive numa falha no meio da leitura. Nenhum registrador de ventoinha, sensor ou NVRAM é gravado. Os testes garantem isso com um chip falso que rejeita qualquer outra gravação na porta de dados.

`--json` devolve `reading` (`chip_id`, `hwm_active`, `hwm_base`, `registers` por banco e registrador, `logical_devices`) e o registro `evidence`; os nomes dos campos seguem o `live-controller.json` feito à mão na análise de parada das ventoinhas da MR9A e, nessa placa, os valores coincidem com ele. Com `-o DIR` a leitura também é salva como `superio.json`, com `manifest.json` e `evidence.json`, como uma captura.

Os chips são dados em `crates/biosmod-host/data/superio.json`: portas de configuração, chaves de entrada e saída, registradores de ID, valor e máscara, dispositivos lógicos, o protocolo de acesso ao monitor de hardware e os registradores a ler, mais um campo `source` com o documento de origem do mapa. Adicionar um NCT67xx, ITE IT87xx ou Fintek F718xx é incluir uma entrada com a própria fonte; o carregador rejeita entrada sem fonte. Hoje só a família NCT5532D/NCT6779D está listada.

Exige root e `/dev/port` (Linux); `--device` indica outro arquivo para testes.

## Estágios do teste de suspensão

```sh
sudo bme diag suspend pm-test --stage freezer -o pm-freezer-2026-11-12 --i-understand-this-suspends
```

Executa um estágio do teste de suspensão do kernel. `/sys/power/pm_test` faz a próxima suspensão parar em um ponto de verificação, esperar cinco segundos e desfazer, de modo que os estágios até ali rodam sem a máquina dormir. Os estágios, na ordem em que o kernel os alcança:

| Estágio | O que já rodou quando ele para |
| --- | --- |
| `freezer` | espaço de usuário e threads do kernel congelados |
| `devices` | todos os drivers de dispositivo suspensos |
| `platform` | a preparação de suspensão do firmware (ACPI `_PTS`) |
| `processors` | os processadores não principais estão offline |
| `core` | os dispositivos do núcleo do sistema estão suspensos |

O comando recebe `--stage` e `--i-understand-this-suspends`, que é obrigatório: a área de trabalho congela por vários segundos e um estágio que dê errado pode travar a máquina. Salve seu trabalho antes. Ele roda um estágio por execução, de modo que uma falha nomeia o seu estágio.

O que ele confere, em ordem, e recusa com `HOST_REFUSED` antes de gravar qualquer coisa:

1. O usuário é root.
2. O estágio não é `none`: isso é uma suspensão real, e um comando que não consegue acordar a máquina não é um diagnóstico.
3. `/sys/power/pm_test` lista o estágio e seleciona `none` no momento. Um teste armado por outra pessoa não é tocado. Um resto de uma execução interrompida tem a mesma aparência, então a recusa traz o reparo: `echo none > /sys/power/pm_test`, para rodar quando nada mais estiver testando.
4. `/sys/power/state` lista `mem`.
5. Para `platform`, `processors` e `core`, `/sys/power/mem_sleep` seleciona `deep`. Com `s2idle` o kernel nunca chega a esses pontos e a gravação seria uma suspensão real. `freezer` e `devices` param antes de o modo importar e, por isso, rodam com `s2idle`, que é o que a MR9A usa ao iniciar.

Depois lê `/sys/power/suspend_stats` e o log do kernel, descarrega os buffers de arquivo (`sync`), grava o estágio, **relê** e só então grava `mem`. Se a seleção não tiver efeito, `mem` nunca é gravado. Aconteça o que acontecer, grava `none` de volta e também relê; se isso falhar, o erro diz `echo none > /sys/power/pm_test`, porque o estágio continua armado e a próxima suspensão de qualquer tipo pararia ali.

O veredicto são os contadores da própria máquina: **pass** é exatamente um `success` a mais e nenhum `fail` a mais. Uma falha contada é **fail**; uma execução que não conseguiu armar ou disparar o teste, sem nenhum contador se mexer, é **error**. O relatório traz os contadores antes e depois, a diferença, os horários de início e fim e as mensagens do kernel surgidas durante a execução. Ele é salvo como `pm-test.json` e `kernel/delta.log`, com o manifesto e o registro de evidência. Um **fail** ou **error** também é salvo e então o comando termina com `HOST_FAILED` e o relatório nos detalhes do erro.

## Limites

- As tabelas são as que o kernel publicou nesta inicialização. O firmware altera tabelas durante o POST e o sistema pode carregar tabelas dinâmicas, então elas podem diferir das tabelas guardadas na imagem do chip.
- As mensagens do kernel cobrem o que o buffer circular ainda guarda; um uptime longo pode ter descartado uma suspensão anterior.
- A leitura do Super I/O é um instantâneo: temperaturas, velocidades e ciclos de trabalho das ventoinhas mudam. O significado dos registradores vem do mapa do chip, não da fiação desta placa; qual conector uma ventoinha aciona não fica estabelecido. A sondagem grava a chave de entrada nas portas 2Eh e 4Eh, como todo driver de Super I/O; outro dispositivo que decodifique essas portas a veria.
- Um pm-test aprovado diz que as etapas do kernel até aquele estágio funcionaram. Não diz que a máquina consegue entrar no estado de suspensão e sair dele: nenhuma suspensão real acontece e o caminho de retomada da própria plataforma não é exercitado. Falhas intermitentes pedem várias execuções. Os estágios e as proteções foram escritos a partir do comportamento documentado do kernel e testados contra um falso em memória de `/sys/power`; nenhuma execução em hardware real os respalda ainda.
- O recibo mostra o que uma máquina informou em uma inicialização. Uma observação não muda a confiança geral de um patch.
