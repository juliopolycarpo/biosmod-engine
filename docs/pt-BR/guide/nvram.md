# Variáveis NVRAM

[English](../../guide/nvram.md) | Português (Brasil)

`bme nvram` lê os armazenamentos de variáveis dentro de uma imagem de firmware: o que o Setup salvou, o que os padrões dizem e o que gravações antigas deixaram para trás. Ele responde "qual é o valor armazenado deste campo do Setup, e ele bate com o padrão?" sem dar boot na placa. É somente leitura.

Este guia é separado de [Formulários do Setup](ifr.md) porque o fluxo é outro: `bme ifr` explica uma pergunta, `bme nvram` mostra os bytes que o firmware guarda para ela. `--field` junta os dois.

```sh
bme nvram dump.bin                                   # registros ativos de todos os armazenamentos
bme nvram dump.bin --all-records                     # mais histórico, apagados e órfãos
bme nvram dump.bin --name Setup --store nvar@0x840060
bme nvram dump.bin --field "ACPI Sleep State"        # valor armazenado em cada cópia, ao lado do padrão do IFR
bme nvram dump.bin --field "Memory Frequency" --question-id 0xc35
bme nvram dump.bin --name Setup --store StdDefaults --dump -o Setup.default.bin
```

A entrada é uma imagem de firmware (os armazenamentos são achados a partir dos volumes lidos) ou um armazenamento NVAR ou VSS avulso.

## Onde ficam os armazenamentos

Os armazenamentos são localizados pela estrutura, nunca procurando `NVAR`; o módulo PEI da NVRAM contém essa string como constante.

- AMI NVAR: um arquivo FFS cujo corpo começa com um registro `NVAR`. Os dumps originais usam um arquivo raw `CEF5B9A3-476D-497F-9FDC-E98143E0422C` que preenche um volume de 0x40000 bytes. Um arquivo todo 0xFF com esse GUID aparece como armazenamento vazio.
- EDK II VSS e VSS2: um arquivo raw ou corpo de volume sem arquivos que começa com um `VARIABLE_STORE_HEADER` (GUID `DDCF3616`, `DDCF3617` ou o autenticado `AAF32C78`) ou com `$VSS`. Cabeçalhos de variável simples e autenticados são tratados. `$FSS`, cabeçalhos Intel com `TotalSize` e variantes Apple não são.
- Armazenamentos de padrões da AMI: um registro chamado `StdDefaults` ou `MfgDefaults` com GUID `4599D26F-1A11-49B8-B91F-858745CFF824` guarda um armazenamento NVAR completo de valores padrão, com tabela de GUIDs própria. Ele aparece como armazenamento aninhado (`nvar@0x840060:StdDefaults`) ao lado do pai.

Os rótulos (`nvar@0x840060`, `nvar@0x840060:StdDefaults`, `vss@0x…`) trazem o offset do armazenamento na imagem. `--store TEXTO` mantém os armazenamentos cujo rótulo contém `TEXTO`, sem diferenciar maiúsculas. Uma imagem pode ter vários: o dump do PR9 tem dois armazenamentos NVAR com conteúdos diferentes (0x800060 e 0x840060). O bme relata cada um separadamente e não adivinha qual o firmware trata como o ativo.

## Registros e estados

Cada linha é um registro. Uma variável NVAR é uma cadeia: o primeiro registro traz nome e GUID, os seguintes são registros só de dados ligados por `next`. O bme segue a cadeia e informa:

| Estado | Significado |
| --- | --- |
| `active` | o valor atual: último registro de uma cadeia válida, ou registro VSS no estado `ADDED` |
| `superseded` | histórico: registro antigo de uma variável que tem um mais novo |
| `deleted` | bit de validade do NVAR zerado (a cadeia inteira quando o primeiro registro é inválido), ou VSS `DELETED` |
| `incomplete` | cabeçalho VSS gravado, mas dados nunca concluídos |
| `orphan` | registro NVAR só de dados que nenhum registro de variável aponta; o nome se perdeu |

Um registro VSS em transição de exclusão vira `superseded` quando existe uma atualização concluída da mesma variável, e `active` caso contrário, como o EDK II se recupera de uma atualização interrompida.

Por registro, a tabela e o JSON mostram armazenamento, estado, nome, GUID, tamanho dos dados, offset do cabeçalho na imagem, flags e o SHA-256 dos dados. O JSON traz ainda os atributos EFI derivados, a posição na cadeia, os atributos do cabeçalho estendido e o byte de checksum (exibido, não verificado). O NVAR não guarda atributos EFI; o bme deriva non-volatile e boot-service sempre, e runtime a partir da flag runtime do NVAR.

As variáveis são identificadas por nome e GUID. A variável `Setup` existe duas vezes nos armazenamentos de padrões originais: `EC87D643-…` (o Setup de 0x6C ou 0x7D bytes) e `80E1202E-…` (6 bytes, o formulário de recuperação). Filtre com `--guid` quando o nome não bastar.

`--dump -o ARQUIVO` grava os dados de exatamente um registro e se recusa a sobrescrever. Se os filtros deixarem vários registros, falha com `TARGET_AMBIGUOUS` e os lista; restrinja com `--name`, `--guid`, `--store`.

## Verificação de tamanho

O NVRAMDxe reinicia um armazenamento quando o tamanho de uma variável difere do esperado, então confira antes de mudar o Setup. Quando a imagem tem formulários do Setup, cada registro é comparado com o variable store do IFR de mesmo nome e GUID:

```
nvar@0x840060  active  Setup  EC87D643-…  0x6c  …
```

Uma divergência imprime `0x30 (IFR 0x40: MISMATCH)` e marca `size_mismatch` no JSON. O `Setup` do PR9 tem 0x6C bytes e o do MR9A 0x7D. A divergência é um fato sobre o registro, não um erro: `PlatformLang`, `BootOrder` e `LegacyDevOrder` são declarados com 2 bytes e armazenados maiores, o que é normal.

Um módulo com formulários malformados não interrompe a listagem: ele aparece como linha `warning:` (e em `ifr_diagnostics` no JSON), e seus variable stores ficam sem verificação de tamanho. `--field` imprime os mesmos avisos, pois o módulo ignorado pode ter guardado a pergunta.

## Lendo um campo do Setup

`--field "PROMPT"` resolve a pergunta com o decodificador IFR e imprime seus bytes em cada cópia armazenada da variável, ao lado do padrão do formulário:

```
"ACPI Sleep State" (question 0x0019): Setup EC87D643-… +0xa, 2 byte(s); IFR variable store 0x6c bytes
IFR default: standard 0x0, manufacturing 0x0
STORE                      STATE   DEFAULTS  RECORD    SIZE  STORED  VS DEFAULT
nvar@0x800060              active  -         0x805873  0x6c  0x0     equal
nvar@0x800060:StdDefaults  active  standard  0x800077  0x6c  0x0     equal
```

- `DEFAULTS` marca registros de um armazenamento de padrões; esses são os padrões salvos. Linhas sem a marca são os valores que o Setup gravou. Com `--all-records`, registros superseded e deleted também aparecem, em ordem de imagem, e o histórico do campo fica visível.
- `VS DEFAULT` compara com o padrão do IFR (standard, ou manufacturing para um armazenamento `MfgDefaults`). Mostra `-` quando o formulário não declara padrão ou o valor tem mais de 8 bytes (então `STORED` traz os bytes em hexadecimal).
- Um registro menor que `offset + width` mostra `outside record` e a divergência de tamanho.
- Prompts se repetem. Se várias perguntas compartilham o prompt, `--field` falha com `TARGET_AMBIGUOUS` e lista cada ID de pergunta com seu form set; escolha uma com `--question-id` (decimal ou hexadecimal com `0x`). Perguntas no mesmo armazenamento e com os mesmos padrões contam como um só campo, então "Memory Frequency", oferecida três vezes em `IntelSetup+0x1248`, dispensa o ID quando os padrões coincidem.
- Perguntas sem armazenamento em variável (ações, textos) falham com `TARGET_NOT_FOUND`. `--field` precisa de uma imagem com formulários do Setup; um armazenamento avulso dá `USAGE`.

## Registros corrompidos

Um registro que não pode ser decodificado aparece em `issues` com o offset na imagem e o valor inválido dentro do formato esperado (`record size: expected 10..=0x2a3 | received 32767`). A leitura então segue na próxima assinatura `NVAR` ou marcador `0x55AA`, de modo que um registro danificado não esconde o que vem depois. Índices de GUID inválidos, nomes sem terminador, cabeçalhos estendidos quebrados, ligações que apontam para lugar nenhum ou para um laço, e campos de tamanho VSS que saem do armazenamento são relatados assim.

## Limites

- Os offsets são offsets da imagem. Só volumes de nível superior; armazenamentos dentro de seções comprimidas não são procurados.
- A tabela de GUIDs do NVAR é achada voltando do fim do arquivo até o separador apagado; um armazenamento sem espaço livre antes da tabela pode ser lido errado.
- O layout do cabeçalho estendido (byte de atributos, byte de checksum opcional, tamanho no final) segue o `nvram.h` do UEFITool. Nenhum dump original o usa, então esse caminho, GUIDs embutidos, nomes NVAR em UCS-2 e todo o suporte a VSS são verificados apenas com armazenamentos sintéticos. Checksums, timestamps e dados HMAC não são verificados.
- Nem todo dump traz uma região NVRAM ativa: a imagem original do MR9A só tem o armazenamento `StdDefaults`, então todo valor que ela mostra é um padrão salvo. Valores gravados pelo Setup exigem um dump lido de uma placa que já salvou o Setup.
