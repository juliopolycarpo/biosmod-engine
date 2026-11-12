# Formatos suportados

[English](../formats.md) | Português (Brasil)

| Estrutura | Suporte |
|---|---|
| Intel flash descriptor | regiões informadas por `inspect`; a região BIOS não é necessária para análise |
| Volumes de firmware | sistemas de arquivos FFSv2 e FFSv3; outros volumes são listados como opacos |
| Arquivos FFS | checksums de cabeçalho e dados verificados na entrada e reconstruídos na saída; cabeçalhos de arquivos grandes |
| ACPI | DSDT em uma seção raw (`leaf: acpi-table`), checksum da tabela mantido pelo próprio hunk; `inspect --acpi` lista toda tabela com checksum válido em seções PE32, TE e raw (somente o conjunto armazenado) |
| Seções | decodificadas: imagem FV, LZMA definido por GUID, CRC32 definido por GUID (verificado), seções de compressão do tipo 1 (EFI 1.1 e Tiano), Brotli e LZMA F86 definidos por GUID; folhas: PE32, TE, raw, UI e demais. Outros tipos de compressão e codificações definidas por GUID permanecem opacos; módulos neles são informados como `unsupported`; `inspect --files` e o comando que falha informam cada seção opaca com seu GUID, deslocamento na imagem e motivo |
| LZMA | decodificação limitada a 64 MiB por seção e 512 MiB por imagem; a recodificação reproduz as propriedades originais e é conferida por decodificação. É a única codificação que a reconstrução suporta |
| Compressão EFI e Tiano | somente decodificação. O fluxo não tem checksum; o bme o decodifica como Tiano (contagem de posições com 5 bits) e como EFI 1.1 (4 bits) e mantém o primeiro resultado que é analisado como fluxo de seções; `inspect --files` mostra qual foi (`tiano` ou `efi`). O tamanho decodificado deve ser igual ao do cabeçalho da seção |
| Brotli | somente decodificação. GUID `3D532050-5CDA-4FD0-879E-0F7F630D5AFB`, layout do EDK II: cabeçalho de 16 bytes (tamanho decodificado, tamanho de scratch) e depois o fluxo; o fluxo deve produzir exatamente o tamanho declarado |
| LZMA F86 | somente decodificação. GUID `D42AE6BD-1352-4BFB-909A-CA72A6EAE889`: LZMA e depois o filtro x86 BCJ (ponteiro de instrução 0) |
| Codificações somente de decodificação | compartilham os limites do LZMA: 64 MiB por seção e 512 MiB por imagem, conferidos contra o tamanho declarado antes de decodificar. Extrair, varrer e inspecionar funcionam; reconstruir ou aplicar patch em um módulo dentro delas falha com `FORMAT_UNSUPPORTED`, informando a codificação e o deslocamento da seção na imagem (dentro de conteúdo decodificado, seu deslocamento nesse fluxo mais a seção de onde ele foi decodificado), e `scan` informa esses patches como `unsupported` |
| PE32/PE32+ | tabelas de seções, base da imagem, relocações de base e campos de desvio direto (para mascaramento de assinaturas) |
| HII / IFR | listas de pacotes em bytes PE, TE ou raw (`bme ifr`): pacotes de strings (SCSU, UCS-2) e de formulários; somente leitura |
| Armazenamentos NVRAM | AMI NVAR (registros, cadeias `next`, tabela de GUIDs, armazenamentos aninhados `StdDefaults`/`MfgDefaults`) e EDK II VSS/VSS2 e `$VSS` (cabeçalhos simples e autenticados) via `bme nvram`; somente leitura |
| TE | correspondência de folhas executáveis e verificações da base da imagem; a cobertura de relocações retorna `FORMAT_UNSUPPORTED` |

Limites: imagens de até 64 MiB, profundidade de aninhamento 16, arquivos de catálogo de até 8 MiB e 4096 arquivos por catálogo.

Várias DSDTs sem sobreposição em uma seção RAW podem ser selecionadas independentemente por `table_offset`. Quando o catálogo identifica várias tabelas em um arquivo, seus intervalos não podem se sobrepor e nenhuma tabela pode ser redimensionada. O patch de cada tabela deve manter seu próprio checksum.

Não suportados (`FORMAT_UNSUPPORTED` ou `PACKING_REFUSED` explícito): reconstruir dentro de seções EFI, Tiano, Brotli ou LZMA F86, seções de compressão de outros tipos, outras codificações definidas por GUID, variantes de fornecedor da Insyde e da Phoenix, cápsulas, contêineres de atualização assinados, mover PEI ou outros módulos executados no local, redimensionar um módulo no meio da imagem e edição semântica de ACPI.

Checksums válidos não são uma assinatura. O bme nunca remove nem recalcula dados de autenticação e não pode dizer se uma plataforma aceitará uma imagem modificada.
