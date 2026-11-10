# Fluxo de trabalho

[English](../../guide/workflow.md) | Português (Brasil)

O `bme` trabalha em uma cópia do firmware. Ele nunca abre um chip flash e toda saída é um novo arquivo.

```sh
bme scan dump.bin                                   # which build is this, which defects are present
bme plan dump.bin --select recommended -o plan.json # resolve and dry-build in memory
bme patch dump.bin --plan plan.json -o fixed.bin    # rebuild, verify, publish fixed.bin + manifest
bme verify dump.bin fixed.bin                       # independent check, any time later
```

## Análise

`scan` detecta a versão do firmware por correspondência com hashes de módulos registrados. Cada patch recebe um estado:

| Estado | Significado |
|---|---|
| `present` | o defeito existe e o módulo corresponde exatamente à origem registrada |
| `fixed` | a correção registrada já foi aplicada |
| `partial` | alguns hunks foram aplicados e outros não; nada será gerado sobre ele |
| `likely-present` / `likely-fixed` | versão desconhecida: cada assinatura de hunk correspondeu exatamente uma vez |
| `not-detected` | o código difere ou o módulo está ausente; isso não prova a ausência do defeito |
| `not-applicable` | o registro diz que esta versão não tem o defeito |
| `unsupported` | o módulo usa um formato que o bme não decodifica |

Somente registros `present` em uma versão conhecida podem ser planejados. Resultados `likely-*` são pistas para portabilidade (`bme guide porting`).

## Seleção

`--select` aceita IDs (`B05`), IDs qualificados (`lab::B05@1.2.0`) ou `recommended` (toda correção planejável de nível 1). Alguns registros exigem mais:

- `--assert <fact>`: o registro depende de hardware que o firmware não pode comprovar, por exemplo qual Super I/O está instalado. Confira a placa e declare o fato por seu ID (`bme catalog show` os lista).
- `--allow-hold`: registros cujo efeito no hardware é desconhecido.
- `--allow-diagnostic`: patches de diagnóstico como os breadcrumbs MRC. Eles não são correções.

Substituições e conflitos são resolvidos automaticamente; `plan` lista todas as observações.

## Plano e patch

`plan` grava um plano JSON com o hash de entrada, a cópia fixada do catálogo (hash do manifesto e cada arquivo consumido), a seleção, fatos, flags, cada alteração de componente, a lista de bytes permitidos e o hash esperado da saída.

`patch --plan` trata o plano como entrada não confiável: relê a entrada, recarrega o catálogo fixado offline, reconstrói do início e exige o mesmo plano e hash de saída. Qualquer divergência resulta em `PLAN_INPUT_CHANGED` ou `OUTPUT_VERIFICATION_FAILED`, sem gravar nada.

`patch --select` planeja e gera em um passo.

Antes da publicação, cada saída é analisada novamente, cada patch selecionado ou mantido deve ser lido como corrigido e cada byte fora da lista permitida deve ser igual à entrada. A imagem e `<output>.manifest.json` são preparados ao lado do destino e movidos para o lugar sem substituir arquivos existentes.

## Verificação

`verify` confere os hashes de entrada e saída contra o manifesto, analisa novamente a saída, compara bytes fora da lista permitida, confirma estados dos patches e reproduz a geração a partir do catálogo fixado quando ele ainda está disponível. Ele informa verificações ignoradas separadamente e nunca afirma que a imagem inicializará.
