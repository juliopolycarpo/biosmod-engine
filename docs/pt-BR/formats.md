# Formatos suportados

[English](../formats.md) | Português (Brasil)

| Estrutura | Suporte |
|---|---|
| Intel flash descriptor | regiões informadas por `inspect`; a região BIOS não é necessária para análise |
| Volumes de firmware | sistemas de arquivos FFSv2 e FFSv3; outros volumes são listados como opacos |
| Arquivos FFS | checksums de cabeçalho e dados verificados na entrada e reconstruídos na saída; cabeçalhos de arquivos grandes |
| Seções | decodificadas: imagem FV, LZMA definido por GUID, CRC32 definido por GUID (verificado); folhas: PE32, TE, raw, UI e demais. Seções de compressão (tipo 01) e outras codificações definidas por GUID permanecem opacas; módulos nelas são informados como `unsupported` |
| LZMA | decodificação limitada a 64 MiB por seção e 512 MiB por imagem; a recodificação reproduz as propriedades originais e é conferida por decodificação |
| ACPI | DSDT em uma seção raw (`leaf: acpi-table`), checksum da tabela mantido pelo próprio hunk |
| PE32/PE32+ | tabelas de seções, base da imagem, relocações de base e campos de desvio direto (para mascaramento de assinaturas) |
| TE | correspondência de folhas executáveis e verificações da base da imagem; a cobertura de relocações retorna `FORMAT_UNSUPPORTED` |

Limites: imagens de até 64 MiB, profundidade de aninhamento 16, arquivos de catálogo de até 8 MiB e 4096 arquivos por catálogo.

Não suportados (`FORMAT_UNSUPPORTED` ou `PACKING_REFUSED` explícito): compressão padrão EFI, TianoCompress, Brotli e outras codificações definidas por GUID, cápsulas, contêineres de atualização assinados, mover PEI ou outros módulos executados no local, redimensionar um módulo no meio da imagem e edição semântica de ACPI.

Checksums válidos não são uma assinatura. O bme nunca remove nem recalcula dados de autenticação e não pode dizer se uma plataforma aceitará uma imagem modificada.
