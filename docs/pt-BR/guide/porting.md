# Portar uma correção para outra versão

[English](../../guide/porting.md) | Português (Brasil)

Muitas placas da família X99 usam imagens AMI Aptio relacionadas. Um defeito corrigido em uma versão pode estar em outro deslocamento na sua. O bme nunca aplica patches a um módulo cujo hash difere de uma origem registrada; primeiro é necessária uma variante para sua versão.

1. Leia o chip (`bme guide flashing`) e execute `bme scan dump.bin`. Em uma versão desconhecida, `likely-present` indica que cada assinatura de hunk de um registro correspondeu exatamente uma vez.
2. Extraia o módulo: `bme extract dump.bin --guid <ffs_guid> -o Module.pe`.
3. Analise-o e ao módulo de referência: `bme tools analyze --project work/p --output work/x Module.pe` (`bme guide ghidra`).
4. Gere deslocamentos preliminares: `bme derive --patch B02-B03 --from-firmware mnx99mr9apro-230322 --component UncoreInitPeim --module Module.pe > draft.json`. O rascunho é marcado como `UNREVIEWED`. Ele obtém deslocamentos, bytes originais e contexto do seu módulo e mantém os bytes de substituição da referência. `review_offsets` lista hunks cujos bytes originais diferem da referência (endereços ou deslocamentos mascarados); seus bytes de substituição quase certamente precisam ser recalculados. Hunks não listados ainda podem conter endereços da referência.
5. Para cada hunk, localize-o nas duas exportações `.asm`, confirme que a função ao redor faz o mesmo, recalcule endereços e deslocamentos e desmonte os bytes modificados.
6. Adicione um perfil de placa e uma versão de firmware para sua placa, adicione o componente revisado em `variants.<your-firmware-id>`, remova o campo `draft` e execute `bme catalog index` e `bme catalog validate`.
7. `bme scan dump.bin --catalog ./my-catalog --allow-unsigned-local` deve informar `present`, e uma imagem gerada deve informar `fixed`.

Registre uma observação de hardware somente para uma imagem que você tenha gravado, com seu hash.
