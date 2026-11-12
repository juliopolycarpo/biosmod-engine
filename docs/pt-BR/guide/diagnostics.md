# Diagnósticos do host (`bme diag`)

[English](../../guide/diagnostics.md) | Português (Brasil)

Vários achados dependem do que a máquina em execução informa, como as tabelas ACPI que o kernel publicou, os estados de suspensão que ele oferece e os registradores do controlador de ventoinhas. `bme diag` lê esses fatos, calcula seus hashes e escreve um recibo, para que outra pessoa confira uma afirmação apenas pelos arquivos. O leitor de checkpoints MRC tem [guia próprio](breadcrumbs.md).

Tudo exige Linux. Comandos que leem arquivos ou portas protegidos exigem root; execute com `sudo` ou `pkexec`.

## Regras comuns

- **Somente leitura, salvo quando o comando disser o contrário.** O único arquivo que um comando de leitura cria é o seu novo diretório de saída. `diag superio read` também grava os seletores de acesso do chip, e nada além disso.
- **Somente saídas novas.** Um diretório de captura que já existe, mesmo vazio, é recusado antes de ler o host. Nada é sobrescrito nem mesclado.
- **Uma recusa é um erro, não um palpite.** `HOST_REFUSED` significa que o usuário, o chip detectado ou o modo pedido está fora do que as regras de segurança do comando cobrem; nenhuma configuração foi alterada e, no máximo, uma sondagem de chip gravou seus seletores de acesso.
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
```

Lê o controlador de ventoinhas como faziam os scripts avulsos, com as regras de segurança embutidas:

1. Sonda as portas de configuração 2Eh e 4Eh: a chave de entrada e depois o ID do chip. Um endereço em que nada responde é deixado em paz.
2. Procura o ID na tabela de chips. Um ID que nenhuma entrada reivindica é recusado com `HOST_REFUSED` e o ID na mensagem; o chip fica no estado em que foi encontrado. O nibble baixo do ID é a revisão do silício e é ignorado (o NCT5532D da MR9A responde `0xC562`; a folha de dados lista `0xC561`).
3. Lê os dispositivos lógicos que o mapa lista (ativação e, quando o dispositivo tem, a base de E/S) e depois os registradores do monitor de hardware que o mapa lista, banco a banco, pelas portas de índice e de dados do monitor.
4. Sai do modo de configuração e devolve o registrador de banco do monitor.

As únicas gravações são **seletores de acesso**: as chaves de entrada e saída, os índices de registrador, o registrador de número do dispositivo lógico e o registrador de banco do monitor. A seleção anterior de dispositivo lógico e de banco é restaurada em todos os caminhos, inclusive numa falha no meio da leitura. Nenhum registrador de ventoinha, sensor ou NVRAM é gravado. Os testes garantem isso com um chip falso que rejeita qualquer outra gravação na porta de dados.

`--json` devolve `reading` (`chip_id`, `hwm_active`, `hwm_base`, `registers` por banco e registrador, `logical_devices`) e o registro `evidence`; os nomes dos campos seguem o `live-controller.json` feito à mão na análise de parada das ventoinhas da MR9A e, nessa placa, os valores coincidem com ele. Com `-o DIR` a leitura também é salva como `superio.json`, com `manifest.json` e `evidence.json`, como uma captura.

Os chips são dados em `crates/biosmod-host/data/superio.json`: portas de configuração, chaves de entrada e saída, registradores de ID, valor e máscara, dispositivos lógicos, o protocolo de acesso ao monitor de hardware e os registradores a ler, mais um campo `source` com o documento de origem do mapa. Adicionar um NCT67xx, ITE IT87xx ou Fintek F718xx é incluir uma entrada com a própria fonte; o carregador rejeita entrada sem fonte. Hoje só o NCT5532D está listado.

Exige root e `/dev/port` (Linux); `--device` indica outro arquivo para testes.

## Limites

- As tabelas são as que o kernel publicou nesta inicialização. O firmware altera tabelas durante o POST e o sistema pode carregar tabelas dinâmicas, então elas podem diferir das tabelas guardadas na imagem do chip.
- As mensagens do kernel cobrem o que o buffer circular ainda guarda; um uptime longo pode ter descartado uma suspensão anterior.
- A leitura do Super I/O é um instantâneo: temperaturas, velocidades e ciclos de trabalho das ventoinhas mudam. O significado dos registradores vem do mapa do chip, não da fiação desta placa; qual conector uma ventoinha aciona não fica estabelecido. A sondagem grava a chave de entrada nas portas 2Eh e 4Eh, como todo driver de Super I/O; outro dispositivo que decodifique essas portas a veria.
- O recibo mostra o que uma máquina informou em uma inicialização. Uma observação não muda a confiança geral de um patch.
