# Biosmod Engine

[English](README.md) | Português (Brasil)

`bme` inspeciona imagens de firmware, encontra defeitos catalogados, gera cópias modificadas e verificadas. A CLI é um único executável sem dependências de execução. Pessoas e agentes usam os mesmos comandos; adicione `--json` para obter um documento legível por máquina por execução. `bme-gui` oferece uma interface gráfica Linux para a mesma engine.

As entradas nunca são modificadas e as saídas são sempre novos arquivos. Somente os comandos `bme flash` acessam um chip flash: no Linux eles diagnosticam o sistema, localizam o chip, fazem o backup e gravam uma imagem pelo flashrom, e a gravação exige um backup que corresponda ao chip.

O primeiro catálogo cobre duas placas AMI Aptio auditadas em [x99-bios-fixes](https://github.com/juliopolycarpo/x99-bios-fixes):

| Perfil de placa | Chipset | Versão do firmware |
|---|---|---|
| `machinist-mr9a-pro-q87-rev-1.2` | Q87 | `mnx99mr9apro-230322` |
| `machinist-pr9-b85` | B85 | `x99ha00m-20221202` |

Registros para outras placas podem ficar em seus próprios catálogos (`bme guide catalogs`, `bme guide porting`).

## Início rápido

```sh
cargo build --release          # target/release/bme
bme scan dump.bin
bme patch dump.bin --recommended
bme verify dump.bin dump.patched.bin
```

```text
Source: official (Builtin, catalog official 1.0.0)
Firmware: mnx99mr9apro-230322 (board profile machinist-mr9a-pro-q87-rev-1.2), 33/33 recorded modules match
  ID               STATE           TIER         TITLE
  B01-B06          DEFECT PRESENT  recommended  Bound standard iMC transfers and propagate ordinary writer errors
  B02-B03          DEFECT PRESENT  recommended  Separate DIMM counters and establish page zero during Auto discovery
  …
Plannable on this exact build: A02, A03, A07, B01-B06, B02-B03, B05, B08, B09, B10, B11, H01 (--allow-hold --assert superio-nct5532d), …
Recommended: B01-B06 B02-B03
```

Para ler e gravar o chip no Linux:

```sh
bme flash doctor
sudo bme flash backup -o dump.bin
sudo bme flash write dump.patched.bin --backup dump.bin --dry-run
```

Leia `bme guide flashing` antes de gravar qualquer chip e mantenha um caminho de recuperação com gravador (`bme guide recovery`).

## Interface gráfica

No Linux x86_64, compile e execute o par correspondente:

```sh
cargo build --release -p biosmod-cli -p biosmod-gui
target/release/bme-gui
```

A interface analisa uma imagem, gera uma cópia a partir dos patches selecionados e a verifica independentemente. Ela acompanha o tema claro ou escuro do sistema, com escolha manual em Configurações. A interface oferece inglês e português brasileiro; o inglês é o padrão. Veja o [guia da interface](docs/pt-BR/guide/gui.md) para dependências, instalação, limites e solução de problemas.

## O que faz

- Analisa imagens com Intel flash descriptor e volumes de firmware EFI, incluindo volumes aninhados e comprimidos com LZMA, com limites de profundidade, tamanho e expansão.
- Corresponde módulos por GUID FFS e SHA-256 exato aos registros do catálogo. Correções já presentes são reconhecidas e mantidas.
- Aplica hunks de mesmo tamanho e de acréscimo, recodifica LZMA de forma idêntica à ferramenta original (liblzma, ligada estaticamente), recalcula checksums e move arquivos móveis para espaço livre quando um módulo cresce. Arquivos executados no local nunca se movem.
- Analisa cada saída novamente, exige que cada patch selecionado seja lido como corrigido e que cada byte fora de uma lista permitida por componente permaneça inalterado; então publica a imagem e seu manifesto sem substituir arquivos existentes.

Qualquer coisa fora disso (outros formatos de compressão, cápsulas, atualizações assinadas, relocação PEI) resulta em erro explícito. Checksums válidos não significam que uma plataforma aceitará uma imagem modificada.

## Equivalência com a referência

O catálogo oficial foi convertido de x99-bios-fixes no commit `765e7a80ae8337c0953dc0da41de5f28b56c5c92`. Com os dumps reais, `bme` reproduz byte a byte:

- as três imagens MR9A que foram gravadas e lidas de volta (estágio 1, estágio 2, diagnóstico de breadcrumbs revisão 2);
- as compilações completas de referência para ambas as placas;
- cada registro gerado isoladamente nos dois dumps originais: 29 saídas idênticas, e os 7 casos recusados pela referência (empacotamento manual, não aplicável) também são recusados.

`cargo nextest run --locked --release --test real_roms --success-output final` repete essas verificações quando os dumps são indicados pelas variáveis `BME_ROM_*` (veja o arquivo de teste). Um teste cujo dump está ausente ainda passa; o nextest oculta por padrão a saída de testes aprovados, então `--success-output final` imprime a linha `skipped: BME_ROM_* is not set` no resumo.

As ferramentas de referência são cobertas pelos comandos: `scan`, `patch`, `extract`, `replace` e `derive` (x99fix); `tools setup ghidra`, `tools analyze` e `tools doctor` (setup-ghidra.sh, ghidra-analyze.sh); o gerador de breadcrumbs é o registro de diagnóstico `MRC-BREADCRUMBS`, e `diag breadcrumbs read` substitui read_breadcrumbs.py.

## Comandos

| Comando | Finalidade |
|---|---|
| `ifr` | formulários do Setup: perguntas, offsets de varstore, opções, padrões e condições |
| `nvram` | variáveis NVRAM (NVAR, VSS): estados dos registros, padrões, campo do Setup armazenado vs padrão |
| `inspect` (`--files`, `--acpi`) | regiões de descriptor, volumes, arquivos e tabelas ACPI armazenadas |
| `scan` | versão detectada e cada estado de patch |
| `patch`, `export`, `verify` | geração, receitas opcionais e verificação |
| `extract`, `replace` | extrair um módulo ou tabela ACPI e inserir o módulo editado |
| `compare`, `compare --functions`, `compare --acpi` | parear os módulos de duas imagens por GUID, duas exportações de `tools analyze` por função, ou dois namespaces ACPI por método |
| `derive` | elaborar uma variante para outra versão por assinaturas únicas |
| `catalog validate/index/add/list/remove/update/show/import-x99fix` | fontes e manutenção de catálogos |
| `tools status/set/unset/doctor/setup ghidra/analyze/paths` | ver, localizar e instalar o Ghidra 12.2 com ghidra-firmware-utils |
| `diag breadcrumbs decode/read` | diagnóstico de checkpoint MRC do MR9A (read usa somente portas 72h/73h) |
| `flash doctor`, `flash probe`, `flash backup`, `flash write` | diagnosticar, localizar, fazer backup e gravar o chip pelo flashrom (Linux) |
| `dev synthetic` | imagem e catálogo sintéticos para experimentar com segurança |
| `version`, `capabilities`, `schema`, `guide` | contratos e documentação incorporada |

`bme guide` lista os tópicos da documentação em inglês; os mesmos arquivos estão em [docs/guide](docs/guide). As traduções estão em [docs/pt-BR/guide](docs/pt-BR/guide).

## Documentação

- [Arquitetura](docs/pt-BR/architecture.md): crates, fluxo de dados e verificações de segurança
- [Formatos](docs/pt-BR/formats.md): estruturas de firmware suportadas e limites
- [Variáveis NVRAM](docs/pt-BR/guide/nvram.md): estados dos registros, padrões salvos e valores armazenados do Setup
- [Protocolo](docs/pt-BR/guide/agents.md), [confiança](docs/pt-BR/guide/trust.md), [catálogos](docs/pt-BR/guide/catalogs.md), [recuperação](docs/pt-BR/guide/recovery.md)
- [Qualificação da interface no Linux](docs/pt-BR/linux-desktop-qualification.md): ambientes testados e limites
- [Interface gráfica](docs/pt-BR/guide/gui.md): configuração Linux e fluxo de geração
- [Como contribuir](CONTRIBUTING.pt-BR.md), incluindo envio de placas e patches
- [Medições de referência](docs/pt-BR/baseline.md)

## Licença

O código do projeto é MIT; veja [LICENSE](LICENSE). O aplicativo gráfico usa Slint sob sua [Royalty-free License 2.0](packaging/linux/licenses/Slint-Royalty-free-2.0.md), com atribuição em Sobre. O pacote Linux inclui avisos de dependências. `tools/ghidra/PeimUEFIHelper.java` e `tools/ghidra/ghidra-firmware-utils-12.2.patch` derivam de ghidra-firmware-utils e permanecem sob Apache-2.0; veja [tools/ghidra/NOTICE](tools/ghidra/NOTICE).

Registros de patches contêm trechos curtos de firmware de fornecedor: os bytes originais de cada alteração e 16 bytes de contexto, para que um patch possa encontrar e conferir seu alvo. Esse código do fornecedor não é coberto por esta licença. Imagens de fornecedores não estão incluídas.
