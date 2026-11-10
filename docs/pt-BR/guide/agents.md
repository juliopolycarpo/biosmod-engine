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

`capabilities.data.desktop_workflow: 1` identifica o fluxo protegido da interface: recusas conservadoras de layout de firmware e verificação incompleta explícita. A interface exige esse marcador mesmo quando uma engine antiga anuncia o mesmo protocolo e versão do pacote. Os campos JSON `inspect.path`, `patch.output` e `patch.manifest_file` são textos para exibição; caminhos Unix com bytes que não são UTF-8 usam caracteres de substituição. Preserve os caminhos originais do sistema operacional ao executar operações posteriores, em vez de reconstruí-los a partir desses textos.

`bme capabilities --json` lista comandos, se cada um grava arquivos ou usa a rede, formatos suportados, limites e todos os códigos de erro com seus significados.

## Um ciclo seguro para agentes

1. Execute `bme scan dump.bin --json` e leia `data.sources[].report.patches[]`: `state`, `plannable`, `blocked`, `requires_facts`.
2. Peça ao usuário que confirme cada fato de hardware; nunca o afirme em nome dele.
3. Execute `bme plan dump.bin --select <ids> -o plan.json --json`; mostre `data.plan.components`, `notes` e `changed` ao usuário.
4. Execute `bme patch dump.bin --plan plan.json -o out.bin --json` somente após o usuário aprovar o plano.
5. Execute `bme verify dump.bin out.bin --json`. Informe `complete`, `checks` e `skipped` como estão. Verificação offline não significa que a imagem inicializa.

Um agente nunca deve gravar um chip. A gravação é decisão do usuário e exige um caminho de recuperação com gravador.
