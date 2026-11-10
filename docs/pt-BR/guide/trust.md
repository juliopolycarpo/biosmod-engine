# Fontes e confiança

[English](../../guide/trust.md) | Português (Brasil)

O `bme` lê dados de patches de fontes de catálogo:

| Fonte | Confiança | Como é lida |
|---|---|---|
| `official` | incorporada ao executável | sempre disponível, offline |
| diretório local registrado | chave minisign ou `--allow-unsigned-local` explícito no registro | lido no local, com verificação do hash de cada arquivo |
| catálogo HTTPS registrado | chave minisign obrigatória | somente por uma cópia local validada |
| caminho direto (`--catalog ./dir`) | nenhuma | recusado sem `--allow-unsigned-local` |

```sh
bme catalog add lab https://example.org/catalog/catalog.json --trust-key lab.pub
bme catalog update lab
bme scan dump.bin --catalog lab
```

A chave é configurada localmente. Chaves dentro de um catálogo nunca são consideradas confiáveis.

## Atualizações

`catalog update` é o único comando que usa a rede. Ele baixa `catalog.json` e `catalog.json.minisig`, verifica a assinatura dos bytes exatos, baixa cada arquivo indexado e confere seu tamanho e hash. A nova cópia é validada por completo em um diretório temporário e ativada com uma única renomeação. Em caso de falha, a cópia anterior permanece ativa.

Atualizações são recusadas se o ID do catálogo mudar, se a versão for anterior a uma já aceita (rollback) ou se uma versão aceita reaparecer com conteúdo diferente. Somente HTTPS; redirecionamentos apenas na mesma origem; corpos têm tamanho limitado.

## Combinar fontes

`--catalog` pode ser repetido. Uma seleção usa uma fonte; selecionar patches de duas fontes é recusado. Um ID sem qualificação definido por duas fontes carregadas resulta em `TARGET_AMBIGUOUS`; qualifique-o como `ALIAS::ID`. O alias `official` é reservado.

## Receitas

Uma receita exportada fixa o alias da fonte, a confiança, o hash do manifesto e cada arquivo consumido. `patch --from` recarrega essa fonte offline e recusa qualquer diferença. A receita não contém o catálogo nem concede permissão para usar uma fonte local não assinada. Editá-la não permite ignorar a validação.
