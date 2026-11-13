# O protocolo JSON

[English](../../guide/agents.md) | Português (Brasil)

Passe `--json` a qualquer comando. A saída padrão contém exatamente um documento JSON, tanto em sucesso quanto em falha; mensagens de progresso vão para stderr (`--quiet` as silencia). O `bme` nunca solicita entrada interativa.

```json
{"protocol": "bme/1", "product": "biosmod-engine", "version": "0.1.0", "command": "scan", "ok": true, "data": { ... }}
{"protocol": "bme/1", "product": "biosmod-engine", "version": "0.1.0", "command": "patch", "ok": false,
 "error": {"code": "PLAN_INPUT_CHANGED", "message": "...", "details": { ... }}}
```

`bme schema envelope` mostra o esquema do envelope; `bme schema plan` e `bme schema manifest` descrevem os documentos em `data`.

Códigos de saída: `0` sucesso, `1` falha controlada (veja `error.code`), `2` erro de uso, `3` publicação incompleta (um arquivo de saída pode existir sem seu par; `error.details` indica o que restou).

`verify` retorna saída `1` e `VERIFICATION_INCOMPLETE` quando as verificações obrigatórias do catálogo não podem ser executadas. Seu `error.details` contém o relatório de verificação (`complete: false`, `checks`, `skipped` e `notice`). Engines antigas podem retornar esse relatório em `data` com saída `0`; clientes devem sempre inspecionar a conclusão e as verificações obrigatórias antes de informar sucesso.

`capabilities.data.desktop_workflow: 1` identifica o fluxo protegido da interface: recusas conservadoras de layout de firmware e verificação incompleta explícita. A interface também exige `direct_patch_workflow: 1`; protocolo e versão do pacote iguais não são suficientes. Os campos JSON `inspect.path`, `patch.output` e `patch.manifest_file` são textos para exibição; caminhos Unix com bytes que não são UTF-8 usam caracteres de substituição. Preserve os caminhos originais do sistema operacional ao executar operações posteriores, em vez de reconstruí-los a partir desses textos.

`bme capabilities --json` lista comandos, se cada um grava arquivos ou usa a rede, formatos suportados, limites e todos os códigos de erro com seus significados. O vetor `verification_required_checks` identifica as verificações que precisam passar exatamente uma vez para que o relatório esteja completo. Os campos `exit_codes` e `error_codes` definem os códigos de saída e sua relação com os erros. Clientes de interface associam esses valores à conexão validada e rejeitam relatórios incompletos ou contraditórios.

## Fluxo para agentes

1. Execute `bme scan dump.bin --json` e examine `data.sources[].report.patches[]`, incluindo `state`, `plannable`, `blocked` e `requires_facts`.
2. Peça ao usuário que confirme fatos de hardware; nunca os afirme em nome dele. Siga a política de autorização do solicitante para gerar uma cópia.
3. Selecione IDs concretos de unidades de aplicação ou use `--recommended`. Opcionalmente, execute `bme patch dump.bin <ids> --dry-run --json` para examinar `data.plan.components`, `notes` e `changed`, ou `bme export dump.bin <ids> -o selection.json --json` para salvar uma receita.
4. Execute `bme patch dump.bin <ids> -o out.bin --json` e `bme verify dump.bin out.bin --json`. Informe `complete`, `checks` e `skipped` como retornados. Verificação offline não significa que a imagem inicializa.

Clientes que vinculam a geração a uma análise exibida podem passar `--expect-input-sha256` e `--expect-source-sha256` da entrada e de `snapshot_sha256` da fonte selecionada no scan. Uma divergência falha com `PLAN_INPUT_CHANGED`; analise novamente antes de selecionar. O hash identifica uma cópia validada da fonte, não uma assinatura. Dry-run e export aceitam as mesmas proteções. A reprodução com `--from` usa as fixações da receita e recusa sobrescrever essas proteções.

Um agente nunca deve gravar um chip. A gravação é decisão do usuário e exige um caminho de recuperação com gravador.

## Fluxo de investigação

Para uma versão desconhecida, um defeito suspeito ou uma afirmação sobre a máquina em execução, trabalhe em um caso e deixe cada comando registrar um hash. É um caminho separado do patch: nada aqui grava uma imagem ou um chip.

1. **Abra um caso.** `bme case init dump.bin -o work/case --json` analisa o dump, elabora uma placa e lista os resultados dos detectores como achados (`bme guide cases`).
2. **Leia a imagem.** Execute cada leitor pelo caso com `bme case record work/case -- <comando>`, para que a saída seja guardada sem caminhos locais e com hash:
   - `ifr dump.bin` decodifica os formulários do Setup: offsets das perguntas, opções, padrões e condições (`bme guide ifr`).
   - `nvram dump.bin --field "ACPI Sleep State"` lista as variáveis armazenadas e compara o valor salvo de uma pergunta do Setup com o padrão (`bme guide nvram`).
   - `inspect dump.bin --acpi` lista as tabelas ACPI que a imagem guarda.
3. **Compare.** `compare reference.bin dump.bin` pareia módulos, `compare --functions A.json B.json` pareia as funções de duas exportações de `tools analyze` e `compare --acpi A B` pareia tabelas ACPI por método. Em `--acpi`, qualquer lado pode ser um diretório de `bme diag acpi capture`, que confronta o que a máquina em execução publicou com o que a imagem guarda (`bme guide porting`).
4. **Observe a máquina.** Os comandos `diag` leem do host as tabelas ACPI, o controlador de ventoinhas, o SMBIOS e as etapas de suspensão (`bme guide diagnostics`). Exigem root e alguns tocam o hardware; peça autorização ao usuário antes de executar um e nunca execute `diag suspend` em nome dele. Um comando `diag` registrado que falha guarda a falha como artefato.
5. **Feche o ciclo.** `bme case status work/case --input dump.bin` informa artefatos `changed`, `missing` ou `unlisted` como `CASE_DRIFT`; `bme case export` transforma o caso em um diretório de catálogo com placa preliminar, achados e evidências que `bme catalog validate` aceita.

Informe o que cada artefato mostra e cite seu id (`002-ifr`). Um achado permanece `open` até uma pessoa revisá-lo: evidência offline não mostra que uma placa inicializa.
