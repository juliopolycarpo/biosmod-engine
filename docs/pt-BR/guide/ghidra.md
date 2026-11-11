# Ferramentas de análise

[English](../../guide/ghidra.md) | Português (Brasil)

```sh
bme tools status              # every tool: version, location, install command (never fails)
bme tools doctor              # read-only: JDK, Ghidra version, extension
bme tools setup ghidra        # pinned install under the data directory (Linux)
bme tools doctor --deep       # also starts Ghidra headless on a probe file
bme tools analyze --project work/p --output work/x Module.pe [...]
```

`status` lista o Ghidra, o ghidra-firmware-utils, o Java (runtime e JDK), o git e o flashrom. Cada linha tem um estado (`ready`, `attention` ou `missing`), a versão, o caminho com a origem (`managed`, `config`, uma variável de ambiente ou `PATH`) e o comando que instala a ferramenta. O bme instala apenas o Ghidra; para Java, git e flashrom ele imprime o comando do gerenciador de pacotes da sua distribuição e nunca executa `sudo`. `status` termina com código 0 mesmo quando falta uma ferramenta, então scripts podem ler `--json`; `doctor` mantém o código de saída diferente de zero.

`setup` instala o Ghidra 12.2 e compila o ghidra-firmware-utils de um commit fixado, com um pequeno patch de compatibilidade com a versão 12.2. Os arquivos do Ghidra e do Gradle são conferidos contra hashes SHA-256 fixados antes da extração. A extração recusa caminhos inseguros e links simbólicos e tem limites de tamanho e quantidade; cada arquivo é preparado antes da instalação do diretório; a verificação de inicialização headless acontece depois. Uma instalação existente não feita pelo bme só é substituída com `--force`. O Gradle baixa as dependências de compilação da extensão de repositórios Maven; elas não são fixadas pelo bme.

## Recuperar uma instalação interrompida

O setup prepara cada diretório antes de substituí-lo, mas a substituição usa duas operações de renomeação e não é uma transação atômica de diretório. Não execute comandos de setup simultâneos para os mesmos locais. Se o setup parar entre as renomeações, o destino pode ficar ausente e o conteúdo anterior permanecer em um diretório vizinho chamado `.bme-backup-<nome-do-destino>`. Versões anteriores usavam `.bme-old-<id-do-processo>` sem registrar o nome do destino. O setup recusa continuar quando encontra um backup retido e informa seu caminho.

1. Pare qualquer setup em execução. Examine o backup informado, o destino e os diretórios `.staging-*` ou `.bme-staging-*` antes de alterá-los. O nome antigo `.bme-old-*` não identifica, por si só, o destino original.
2. Se o destino estiver ausente e você tiver identificado seu backup, renomeie o backup para o destino no mesmo diretório pai. Se ambos existirem, examine-os e guarde o conteúdo necessário; mova ou remova o backup somente depois de decidir. Não apague um backup desconhecido.
3. Execute `bme tools setup ghidra` novamente. Se um clone interrompido deixou uma cópia incompleta e não vazia, examine o diretório `ghidra-firmware-utils` no cache mostrado por `bme tools paths`; depois de preservar o que for necessário, remova essa cópia incompleta e tente novamente. Diretórios de preparação não usados por um processo encerrado também podem ser removidos após inspeção.

Uma falha na verificação de inicialização pode deixar o Ghidra e a extensão recém-instalados no lugar; execute `bme tools doctor --deep` após a recuperação. Essas etapas não protegem contra falta de energia ou falha do sistema de arquivos durante as gravações.

Requisitos: JDK 21 ou posterior e git. Para uso offline, passe `--offline` com `--ghidra-zip`, `--gradle-home` e `--firmware-utils-src`.

`bme tools paths` mostra os caminhos. Para usar uma instalação existente, execute `bme tools set ghidra /caminho/para/ghidra_12.2_PUBLIC`; o comando confere `support/analyzeHeadless` e grava `tools.ghidra_home`. `GHIDRA_INSTALL_DIR` tem precedência sobre o valor gravado. `bme tools unset ghidra` volta à instalação gerenciada. `doctor` informa uma versão divergente porque os scripts foram testados apenas com a 12.2.

O mesmo vale para o flashrom: `bme tools set flashrom /caminho/para/flashrom` executa `--version` para confirmar o programa e grava `tools.flashrom`.

`analyze` grava, para cada módulo, `NAME.c` (descompilação aproximada), `NAME.asm` (instruções com bytes exatos) e `NAME.json` (funções, chamadas e intervalos), além de `ghidra.log`. Confira os bytes no `.asm` antes de escrever um hunk; a saída C serve como auxílio de leitura.
