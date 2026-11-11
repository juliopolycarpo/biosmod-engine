# Fluxo de trabalho

[English](../../guide/workflow.md) | Português (Brasil)

Estes comandos nunca acessam um chip flash nem modificam a imagem de entrada; o acesso ao chip é separado (`bme guide flashing`).

```sh
bme scan dump.bin
bme patch dump.bin --recommended
bme verify dump.bin dump.patched.bin
```

## Analisar e selecionar

`scan` identifica a versão pelos hashes de módulos registrados e informa o estado de cada patch: `present`, `fixed`, `partial`, `likely-present`, `likely-fixed`, `not-detected`, `not-applicable` ou `unsupported`. Somente registros `present` em uma versão conhecida podem ser selecionados para geração. `fixed` indica que a correção já está presente; `partial` indica que apenas alguns hunks foram aplicados. `likely-*` indica assinaturas correspondentes em uma versão desconhecida e é uma pista para portabilidade. `not-detected` não prova a ausência de um defeito; `not-applicable` significa que o catálogo exclui a versão, e `unsupported` que o formato não pode ser decodificado.

Escolha IDs de unidades de aplicação, como `B01-B06` e `B02-B03`, em vez dos IDs de cada achado. IDs podem ser qualificados como `official::B02-B03@1.0.0`. Como alternativa, `--recommended` seleciona correções presentes e aplicáveis do nível recomendado que não exigem afirmações de hardware. A seleção completa é validada em conjunto; pré-requisitos devem estar selecionados ou já instalados, e conflitos podem impedir a geração.

Alguns registros exigem `--assert <fact>` para hardware confirmado na placa física, `--allow-hold` para efeitos desconhecidos no hardware ou `--allow-diagnostic` para patches de diagnóstico. `bme catalog show` lista os fatos necessários.

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

## Compatibilidade

`bme plan dump.bin --select recommended -o plan.json`, `patch --select`, `patch --plan` e `verify --plan` continuam disponíveis. `--plan` é um alias de `--from`; impressões digitais de receitas e manifestos antigos ainda exigem o mecanismo correspondente.
