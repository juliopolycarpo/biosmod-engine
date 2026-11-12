# Diagnósticos do host (`bme diag`)

[English](../../guide/diagnostics.md) | Português (Brasil)

Vários achados dependem do que a máquina em execução informa, como as tabelas ACPI que o kernel publicou e os estados de suspensão que ele oferece. `bme diag` lê esses fatos, calcula seus hashes e escreve um recibo, para que outra pessoa confira uma afirmação apenas pelos arquivos. O leitor de checkpoints MRC tem [guia próprio](breadcrumbs.md).

Tudo exige Linux. Comandos que leem arquivos ou portas protegidos exigem root; execute com `sudo` ou `pkexec`.

## Regras comuns

- **Somente leitura, salvo quando o comando disser o contrário.** O único arquivo que um comando de leitura cria é o seu novo diretório de saída.
- **Somente saídas novas.** Um diretório de captura que já existe, mesmo vazio, é recusado antes de ler o host. Nada é sobrescrito nem mesclado.
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

## Limites

- As tabelas são as que o kernel publicou nesta inicialização. O firmware altera tabelas durante o POST e o sistema pode carregar tabelas dinâmicas, então elas podem diferir das tabelas guardadas na imagem do chip.
- As mensagens do kernel cobrem o que o buffer circular ainda guarda; um uptime longo pode ter descartado uma suspensão anterior.
- O recibo mostra o que uma máquina informou em uma inicialização. Uma observação não muda a confiança geral de um patch.
