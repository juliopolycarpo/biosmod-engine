# Formulários do Setup (IFR)

[English](../../guide/ifr.md) | Português (Brasil)

`bme ifr` lê o menu Setup de uma imagem AMI Aptio sem ferramentas externas. Ele localiza as listas de pacotes HII dentro dos módulos PE, decodifica os pacotes de strings e de formulários e mostra cada pergunta com os dados que um patch de Setup precisa: texto, ID da pergunta, variable store (nome e GUID), offset, largura, intervalo, opções, valores padrão e as condições `SuppressIf`, `GrayOutIf` e `DisableIf` ao redor dela.

```sh
bme ifr dump.bin                                          # todo PE que contém IFR
bme ifr dump.bin --guid 899407D7-99FE-43D8-9A21-79EC328CAC21 --json
bme extract dump.bin --guid 899407D7-99FE-43D8-9A21-79EC328CAC21 -o Setup.pe
bme ifr Setup.pe --language en-US
```

A entrada é uma imagem de firmware ou uma seção PE, TE ou raw isolada. Com uma imagem, `--guid` limita a decodificação a um arquivo FFS; sem ele, todo módulo PE32 ou TE com pacote de formulários é decodificado (Setup, páginas da plataforma, ferramentas de flash). `--language` escolhe o pacote de strings: `en-US` por padrão, senão o primeiro idioma presente.

## Lendo a tabela

Uma tabela por formulário, uma linha por pergunta:

```
0x0019  one_of  "ACPI Sleep State"  Setup+0xa/2  0x0..0x0  default 0  0="Suspend Disabled" (default, mfg)  suppress: ideqval 0x17 == 1 && grayout: ideqval 0xd3 == 1
```

- `Setup+0xa/2` é o variable store `Setup`, offset `0x0A` em bytes, largura de 2 bytes. A pergunta guarda o valor nesse offset da variável NVRAM (o GUID e o nome do store identificam a variável).
- `default N` vem de um opcode `Default` explícito, depois de uma opção marcada como padrão, depois dos flags do checkbox. `(default, mfg)` marca opções com flag de padrão normal e de fabricação.
- As condições aparecem da mais externa para a mais interna. `ideqval 0x17 == 1` significa "a pergunta `0x17` vale 1". A pergunta fica oculta enquanto a condição `suppress` vale e fica somente leitura enquanto uma condição `grayout` ou `disable` vale.
- Uma condição pode envolver um formulário inteiro (o Platform da AMI faz isso). As perguntas dele listam essa condição e o formulário a traz em `forms[].conditions`. Um formulário dentro de uma pergunta ou de outro formulário continua sendo rejeitado.
- `--json` devolve a estrutura completa em `data.modules[].package_lists[].form_sets[].forms[].statements[]`. Além das colunas da tabela, traz `opcode_offset` (bytes desde o início do módulo), `varstore_id`, `question_flags`, offsets das opções e cada `Default` explícito com seu ID (0 padrão, 1 fabricação).

Os textos das perguntas não são únicos. O mesmo texto pode aparecer em vários formulários com condições diferentes; compare pelo ID da pergunta ou pelo texto mais as condições.

## Limites

- Somente leitura. Nada é gravado na imagem.
- Comprimentos de opcode, aninhamento (64 escopos) e limites de pacote são verificados. Um pacote malformado falha com `FORMAT_INVALID` indicando offset e opcode, por exemplo `opcode End (0x29) at 0x31: End without an open scope`.
- Em uma imagem, um módulo com formulários malformados aparece como linha `warning:` (e em `data.diagnostics` com `--json`) e os demais módulos continuam sendo exibidos. Com `--guid`, a mesma falha é um erro.
- O texto de uma condição é limitado a 1024 bytes e 512 opcodes de expressão; uma expressão maior termina com `…`.
- As listas de pacotes precisam fechar exatamente no comprimento declarado; pacotes de formulário avulsos, sem cabeçalho de lista, não são encontrados.
- Expressões de condição que o bme não conhece aparecem como `opcode_0xNN`; a estrutura de escopos continua sendo seguida.
- Valores padrão de data e hora não são decodificados.
- Blocos de string de 8 bits (SCSU) são lidos como Latin-1; blocos UCS-2 são decodificados por completo. Blocos de fonte são rejeitados.
- Offsets e larguras vêm do formulário, não de um sistema em execução. Se o firmware aceita um valor fora do intervalo é uma questão de hardware.
