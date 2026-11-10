# Ferramentas de análise

[English](../../guide/ghidra.md) | Português (Brasil)

```sh
bme tools doctor              # read-only: JDK, Ghidra version, extension
bme tools setup ghidra        # pinned install under the data directory (Linux)
bme tools doctor --deep       # also starts Ghidra headless on a probe file
bme tools analyze --project work/p --output work/x Module.pe [...]
```

`setup` instala o Ghidra 12.2 e compila o ghidra-firmware-utils de um commit fixado, com um pequeno patch de compatibilidade com a versão 12.2. Os arquivos do Ghidra e do Gradle são conferidos contra hashes SHA-256 fixados antes da extração. A extração recusa caminhos inseguros e links simbólicos e tem limites de tamanho e quantidade; tudo é preparado e movido para o destino somente quando estiver completo. Uma instalação existente não feita pelo bme só é substituída com `--force`. O Gradle baixa as dependências de compilação da extensão de repositórios Maven; elas não são fixadas pelo bme.

Requisitos: JDK 21 ou posterior e git. Para uso offline, passe `--offline` com `--ghidra-zip`, `--gradle-home` e `--firmware-utils-src`.

`bme tools paths` mostra os caminhos. Configure `GHIDRA_INSTALL_DIR` ou `tools.ghidra_home` no arquivo de configuração para usar outra instalação; `doctor` informa uma versão divergente porque os scripts foram testados apenas com a 12.2.

`analyze` grava, para cada módulo, `NAME.c` (descompilação aproximada), `NAME.asm` (instruções com bytes exatos) e `NAME.json` (funções, chamadas e intervalos), além de `ghidra.log`. Confira os bytes no `.asm` antes de escrever um hunk; a saída C serve como auxílio de leitura.
