# Breadcrumbs de checkpoints MRC (diagnóstico MR9A)

[English](../../guide/breadcrumbs.md) | Português (Brasil)

Quando o treinamento de memória para em `b0` ou `b7`, o visor POST mostra apenas o código principal e a próxima inicialização o sobrescreve. O diagnóstico de breadcrumbs mantém o checkpoint MRC completo (principal, secundário e localização de 16 bits) no banco superior do CMOS, `E0`–`E9`. Se uma passagem falhar antes de terminar, ele congela esse checkpoint para que o Linux possa lê-lo após a próxima inicialização bem-sucedida.

É um registro `diagnostic` (`MRC-BREADCRUMBS`), em camadas sobre B01-B06 e B02-B03 para a versão MR9A `mnx99mr9apro-230322`:

```sh
bme patch dump.bin B01-B06 B02-B03 MRC-BREADCRUMBS --allow-diagnostic
```

O registro verifica a base da imagem XIP do módulo, que nenhuma relocação cubra um byte modificado e que CmosPei, CmosDxe e PlatformEarlyInit correspondam a hashes revisados. Seu código assembly está no diretório `provenance/` do catálogo.

## Leitura

```sh
sudo bme diag breadcrumbs read
bme diag breadcrumbs decode a1 00 00 00 bf ff ff ff ff 00
```

`read` seleciona índices pela porta 72h e lê a 73h. Ele nunca acessa a porta 70h (cujo registrador de índice também contém a máscara NMI) e nunca grava um byte de dados CMOS. Limpar o CMOS apaga o registro: após uma inicialização travada, recupere primeiro com a troca de DIMM ou GPU e leia antes de limpar o CMOS.

| Índice | Significado |
|---|---|
| `E0` | estado: `A0`, mais `2` para slot 1, mais `1` depois que a passagem termina; qualquer outro valor indica que não está armado |
| `E1`–`E4` | slot 0, checkpoint compactado, little-endian |
| `E5`–`E8` | slot 1 |
| `E9` | número de passagens com falha, saturado em `FF` |

## Limites

- O registro de passagem concluída tem uma observação de hardware; a retenção de uma passagem com falha não foi validada. Em um teste sem RAM que chegou ao POST `53`, nenhum registro de falha foi retido após restaurar a RAM. A causa permanece desconhecida.
- Uma passagem armazenada não é um veredito de inicialização: `BF` termina o MRC, não a inicialização. Erros posteriores, como `d6` por ausência de GPU, estão fora do escopo.
- O registro é de melhor esforço: sem checksum, não atômico em relação a reset e sem sincronização com outros gravadores de CMOS.
- O campo de localização é específico do checkpoint; o bme o mostra sem interpretação.
