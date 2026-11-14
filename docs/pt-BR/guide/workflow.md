# Fluxo de trabalho

[English](../../guide/workflow.md) | Português (Brasil)

Estes comandos nunca acessam um chip flash nem modificam a imagem de entrada; o acesso ao chip é separado (`bme guide flashing`).

```sh
bme scan dump.bin
bme patch dump.bin --recommended
bme verify dump.bin dump.patched.bin
```

## Analisar e selecionar

`scan` identifica a versão pelo `version_string` registrado contra o banner da imagem, ou por todos os hashes de módulos registrados quando não há banner para comparar, e informa o estado de cada patch: `present`, `fixed`, `partial`, `likely-present`, `likely-fixed`, `not-detected`, `not-applicable` ou `unsupported`. Somente registros `present` em uma versão conhecida podem ser selecionados para geração. `fixed` indica que a correção já está presente; `partial` indica que apenas alguns hunks foram aplicados. `likely-*` indica assinaturas correspondentes em uma versão desconhecida e é uma pista para portabilidade. Quando alguns módulos casam mas a identidade não, `scan` imprime `Firmware: unknown; closest cataloged build ...` e não planeja nada; `--firmware` sobrepõe isso. `not-detected` não prova a ausência de um defeito; `not-applicable` significa que o catálogo exclui a versão, e `unsupported` que o formato não pode ser decodificado. Em separado, `scan` executa os detectores de achados do catálogo em qualquer versão e lista os módulos onde uma assinatura de classe de defeito casa como `likely-present`; veja a seção de detectores em `bme guide catalogs`.

Escolha IDs de unidades de aplicação, como `B01-B06` e `B02-B03`, em vez dos IDs de cada achado. IDs podem ser qualificados como `official::B02-B03@1.0.0`. Como alternativa, `--recommended` seleciona correções presentes e aplicáveis do nível recomendado que não exigem afirmações de hardware. A seleção completa é validada em conjunto; pré-requisitos devem estar selecionados ou já instalados, e conflitos podem impedir a geração.

Alguns registros exigem `--assert <fact>` para hardware confirmado na placa física, `--allow-hold` para efeitos desconhecidos no hardware ou `--allow-diagnostic` para patches de diagnóstico. `bme catalog show` lista os fatos necessários.

## Listar tabelas ACPI armazenadas

```sh
bme inspect dump.bin --acpi
bme inspect dump.bin --acpi --json
bme extract dump.bin --leaf acpi-table --guid <owning-guid> --signature SSDT --oem-table-id PmMgt -o PmMgt.aml
```

`inspect --acpi` examina toda seção PE32, TE e raw decodificada em busca de cabeçalhos ACPI cuja assinatura tem quatro caracteres imprimíveis, cujo tamanho cabe na seção, cuja revisão vai de 1 a 0x20, cujos OEM ID, OEM table ID e ID do criador são ASCII imprimível preenchido com NUL e cujos bytes somam zero módulo 256. A regra de texto evita que código e dados de PE correspondam por acaso; uma tabela real com ID binário não seria listada. Cada tabela distinta (por SHA-256) aparece uma vez, com assinatura, revisão, tamanho, OEM ID, OEM table ID, revisão OEM, criador, SHA-256 e todos os locais: GUID e nome UI do arquivo FFS dono, caminho da seção, tipo da seção e deslocamento dentro dela. Cada local também traz `file_offset`, o deslocamento do arquivo dono na imagem, e `compressed`, verdadeiro quando a tabela está armazenada comprimida. Arquivos em volumes aninhados dentro de seções FV image também são examinados; seus locais listam os arquivos envolventes em `nested_in`, do mais externo para o mais interno, cada um com `guid` e `file_offset`. `compressed` também é verdadeiro quando um volume envolvente está atrás de uma seção comprimida. Um arquivo que só existe em conteúdo decodificado não tem deslocamento na imagem, então seu `file_offset` é `null`; a entrada mais interna de `nested_in` com deslocamento é o arquivo armazenado que o contém. O JSON traz a lista em `data.acpi.tables` e repete a declaração de escopo em `data.acpi.notice`.

A lista é o conjunto armazenado, não o que o firmware publica em tempo de execução. FADT, MADT e tabelas semelhantes costumam ser montadas durante o boot e não têm checksum armazenado válido, por isso não aparecem. Uma tabela com checksum armazenado que o firmware altera antes de publicar é listada como armazenada.

`extract --leaf acpi-table` sem seletor mantém o significado original: a DSDT no deslocamento 0 da seção raw do arquivo que começa com ela. `--signature`, `--oem-table-id` e `--sha256` escolhem qualquer tabela listada do arquivo indicado por `--guid`, inclusive tabelas dentro de seções PE32, e gravam seus bytes exatos. Um seletor que corresponde a várias tabelas distintas falha com `TARGET_AMBIGUOUS` e as nomeia; `--sha256` sempre escolhe uma. O JSON mantém as chaves da forma sem seletor (`output`, `length`, `sha256`, `compressed`, `file_offset`) e acrescenta `table`; `file_offset` é `null` para uma tabela em um arquivo que só existe em conteúdo decodificado. `replace` continua tratando somente a forma da DSDT.

## Gerar e visualizar

```sh
bme patch dump.bin B01-B06 B02-B03
bme patch dump.bin --recommended --dry-run
bme patch dump.bin B01-B06 B02-B03 -o fixed.bin
```

`patch dump.bin` exige uma seleção. IDs posicionais, `--recommended`, uma receita salva e a opção legada `--select` não podem ser combinados. Sem `-o`, a saída fica ao lado da entrada, com `.patched` antes da última extensão ou no fim do nome caso não haja extensão. O manifesto é `<output>.manifest.json`; destinos existentes nunca são sobrescritos.

`--dry-run` resolve, gera e verifica em memória sem publicar arquivos. Com `-o`, o JSON informa `proposed_output` em vez dos campos de saída publicada. A visualização não reserva um caminho nem substitui a validação de uma geração posterior.

Antes da publicação, a saída é analisada novamente, os patches selecionados e mantidos devem ser lidos como corrigidos e os bytes fora da lista permitida devem corresponder à entrada. A CLI prepara imagem e manifesto ao lado do destino e os publica sem substituir arquivos existentes.

## Salvar e reproduzir uma seleção

```sh
bme export dump.bin -o selection.json
bme export dump.bin B01-B06 B02-B03 -o explicit-selection.json
bme patch dump.bin --from selection.json
bme verify dump.bin dump.patched.bin --from selection.json
```

Por padrão, a exportação usa a seleção recomendada atual e exige um novo arquivo de saída. Ela gera e valida em memória e grava apenas a receita. O documento `bme.plan/1` registra IDs concretos, hash de entrada, catálogo fixado, política, alterações de componentes e hash esperado da saída; ele não contém um catálogo independente. A reprodução recarrega o catálogo fixado, reconstrói a operação e compara o documento e a saída. Ela recusa substituições de seleção, catálogo, firmware e política; catálogos locais não assinados ainda podem exigir `--allow-unsigned-local` explícito.

Receitas e manifestos incluem uma impressão digital dos insumos de compilação do mecanismo. `patch --from` e `verify` recusam uma impressão ausente ou diferente com `PLAN_INVALID`; guarde o mecanismo correspondente para reproduzir ou verificar artefatos antigos. `bme version --json` a informa em `data.build_fingerprint`. A impressão identifica insumos registrados, mas não é uma assinatura do executável nem prova de binários idênticos.

## Verificar

`verify` confere os hashes de entrada e saída contra o manifesto, analisa novamente a saída, verifica alterações permitidas e estados dos patches e reconstrói a geração a partir do catálogo fixado quando disponível. Verificações obrigatórias que não podem ser executadas produzem `VERIFICATION_INCOMPLETE`. A verificação offline não comprova que a imagem inicializará.

## Quando a versão não está no catálogo

Uma análise que não encontra uma versão conhecida, ou um defeito que você quer entender antes de aplicar patches, inicia uma investigação: abra um caso, leia o Setup (`ifr`), as variáveis salvas (`nvram`) e as tabelas ACPI armazenadas (`inspect --acpi`), compare com uma versão de referência e exporte o que aprendeu. Os passos estão no fluxo de investigação de `bme guide agents`; o registro, a verificação de deriva e a exportação estão em `bme guide cases`.

## Compatibilidade

`bme plan dump.bin --select recommended -o plan.json`, `patch --select`, `patch --plan` e `verify --plan` continuam disponíveis. `--plan` é um alias de `--from`; impressões digitais de receitas e manifestos antigos ainda exigem o mecanismo correspondente.
