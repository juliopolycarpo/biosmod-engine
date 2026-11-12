# Casos

[English](../../guide/cases.md) | Português (Brasil)

Uma investigação produz mais do que patches: achados ainda sem correção, resultados de comandos que você executou, rascunhos de uma placa que o catálogo não conhece. Um caso é um diretório que mantém tudo isso junto e registra o que produziu cada item.

```
case.json               bme.case/1: entradas por digest, versões do motor e do catálogo, lista de artefatos
artifacts/              resultados registrados: 001-scan.json, 002-inspect.json, 003-module.bin
drafts/board.json       perfil de placa não revisado (bme.board/1)
drafts/firmware.json    versão de firmware não revisada, textos de identificação e inventário de módulos (bme.firmware-draft/1)
findings/<id>.json      achados do caso (bme.finding/1); edite ou adicione os seus
```

Os dumps são listados por nome de arquivo, SHA-256 e tamanho, e nunca são copiados para o caso. Nada em um caso nomeia um caminho da sua máquina.

## Começar a partir de um dump

```sh
bme case init dump.bin -o work/mr9a-case
```

O `init` recusa um diretório existente. Ele calcula o hash do dump, executa o scan com assinaturas de detectores e guarda o resultado em `artifacts/001-scan.json`. Em seguida, elabora o rascunho com o que a imagem diz sobre si mesma:

- uma versão de firmware: o id e a string de versão vêm do banner de compilação (`X99H BIOS Date: 12/02/2022 Ver: X99HA00M` vira `x99ha00m-20221202`), o tamanho vem da imagem, e `drafts/firmware.json` acrescenta os textos do banner e o GUID, o tamanho e o SHA-256 de cada módulo PE32 e de tabela ACPI. Uma imagem sem banner recebe `fw-<prefixo do sha256>`.
- um perfil de placa que lista essa versão e nenhum patch. `--board-id` define o nome; o padrão é `draft-<id do firmware>`.
- um achado em `findings/` para cada detector que informa `likely-present`, de modo que uma classe de defeito conhecida de outras versões apareça antes de existir qualquer variante. O achado rascunhado fica aberto, afeta somente esta versão, descarta os patches e os detectores do registro do catálogo e cita o scan como evidência.

Quando a própria máquina contém a placa, o `init` acrescenta a identidade SMBIOS (fabricante, modelo e revisão de `/sys/class/dmi/id`). Isso só acontece quando a data da BIOS da máquina aparece no banner da imagem; assim, o dump de outra versão nunca herda a identidade do host. Caso contrário, fabricante e modelo ficam como `Unknown`.

Todo rascunho traz `DRAFT (unreviewed)` na descrição ou na nota. Confira fabricante, modelo e revisão na placa física antes de compartilhar. O `init` também aceita `--catalog` e `--allow-unsigned-local`, como o `scan`; o caso registra qual catálogo usou.

## Registrar o que você executa

```sh
bme case record work/mr9a-case -- extract dump.bin --guid <guid> -o Module.pe
bme case record work/mr9a-case -- inspect dump.bin --files
```

O `record` executa o comando dentro do `bme` e guarda:

- o documento `--json` dele como `artifacts/NNN-<comando>.json`;
- cada arquivo que ele cria, encontrado por `-o`/`--output` ou indicado com `--artifact CAMINHO` (repetível), como `artifacts/NNN-<nome do arquivo>`;
- em `case.json`, para cada artefato: o SHA-256 e o tamanho, os argumentos exatos, a versão do `bme`, o snapshot do catálogo, os digests de cada arquivo existente citado nos argumentos e o horário.

Um comando que falha não registra nada. As saídas não podem existir antes de o comando rodar. O `case record` não se aninha. O mecanismo aceita qualquer subcomando do `bme`; comandos adicionados depois são registrados sem mudanças em `case`.

## Verificar um caso

```sh
bme case status work/mr9a-case --input dump.bin
```

O `status` recalcula o hash de cada artefato e de cada entrada e informa:

| Relatório | Significado |
|---|---|
| `verified` | os bytes correspondem ao registro |
| `changed` | o arquivo existe com outros bytes |
| `missing` | o arquivo não existe |
| `stale` | um artefato veio de outra versão do `bme` ou de outro snapshot de catálogo que o atual, ou de uma entrada diferente da do caso |
| achados | os documentos de achado em `findings/` e o status deles |

`changed` ou `missing` encerra o comando com código de saída `1` e código de erro `CASE_DRIFT`; `error.details` traz o relatório completo. Resultados `stale` não reprovam a verificação: registre-os de novo.

As entradas são encontradas pelo nome. `--input` aceita um arquivo, um diretório com os dumps ou `NOME=CAMINHO`. Um arquivo com nome diferente corresponde pelo digest. Sem `--input`, o `status` procura cada nome no diretório de trabalho e ao lado do diretório do caso. Use `--catalog` (e `--allow-unsigned-local`) para avaliar a obsolescência em relação a outro catálogo que não o oficial.

Um caso passa para outra máquina como um diretório comum. Lá, `bme case status DIR --input /caminho/dos/dumps` comprova os mesmos dumps e os mesmos artefatos.

## Exportar uma submissão

```sh
bme case export work/mr9a-case -o submission
bme catalog validate submission
```

O `export` recusa artefatos alterados e uma saída existente. Ele grava um diretório de catálogo: `boards/` a partir de `drafts/board.json`, a versão, `findings/` a partir do caso, um registro em `evidence/` por artefato (validação offline, com o comando exibido sem diretórios e o digest do artefato) e o rascunho do firmware em `provenance/`. Os achados exportados descartam os patches, porque patches não viajam com um caso, e um achado `fixed-by-patch` passa a `open`. O campo `evidence` de um achado pode citar ids de artefato como `001-scan`; a exportação os converte em ids de evidência.

O `export` carrega a própria saída como catálogo antes de terminar; assim, `bme catalog validate submission` e `bme catalog index` a aceitam. `bme scan dump.bin --catalog submission --allow-unsigned-local` a lê. Tudo é marcado como rascunho: revise e envie conforme descrito em [CONTRIBUTING](../../../CONTRIBUTING.pt-BR.md).
