# Arquitetura

[English](../architecture.md) | Português (Brasil)

Quatro crates em um workspace:

| Crate | Responsabilidade | Nunca faz |
|---|---|---|
| `biosmod-core` (biblioteca) | análise de firmware, modelos e validação de catálogo, correspondência de patches, planejamento, reconstrução e verificação | I/O de sistema de arquivos, rede ou terminal |
| `biosmod-host` (biblioteca) | leituras da máquina em execução para `bme diag`: sysfs e procfs, log do kernel, portas de E/S, usuário efetivo e recibos | interpretar firmware, imprimir |
| `biosmod-cli` (executável `bme`) | argumentos, arquivos, fontes de catálogo, configuração, downloads, subprocessos (Ghidra, flashrom) e saída | interpretar firmware por conta própria |
| `biosmod-gui` (executável `bme-gui`) | apresentação, estado da sessão e supervisão do subprocesso `bme` | interpretar ou modificar firmware independentemente |

Funções do core recebem bytes e um `FileSource` e retornam `Result`s tipados com um `Code` estável. A CLI os encapsula no envelope `bme/1`.

A interface chama um `bme` compatível como subprocesso. Ela vincula a geração direta à entrada e à cópia do catálogo exibidas, mantém os bytes de receitas importadas em uma sessão privada e confere o resultado da verificação independente. Ela armazena preferências de apresentação separadamente da configuração de fontes e confiança da CLI. Compilações do core e da CLI não dependem do Slint.

## Módulos do core

| Módulo | Função |
|---|---|
| `firmware` | regiões de descriptor, análise FV/FFS/seções com limites de profundidade e decodificação; `pe` para PE32/TE; `rebuild` para checksums, recodificação LZMA e reorganização de volume |
| `ifr` | decodificador somente leitura dos formulários do Setup (UEFI IFR): listas de pacotes HII, pacotes de strings e de formulários, perguntas com offsets de varstore, opções, padrões e condições |
| `nvram` | leitor somente leitura dos armazenamentos de variáveis do firmware: AMI NVAR (cadeias, tabela de GUIDs, `StdDefaults`/`MfgDefaults`) e EDK II VSS/VSS2, com estados dos registros, verificação de tamanho contra o IFR e leitura de campos do Setup |
| `codec` | wrapper liblzma (decodificação limitada, codificação que reproduz os parâmetros do fluxo original) e decodificação de EFI/Tiano, Brotli e LZMA F86 |
| `catalog` | documentos tipados (`bme.catalog/1`, `bme.board/1`, `bme.patch/1`, `bme.evidence/1`) e carregamento por índice verificado |
| `json` | análise estrita: chaves duplicadas e dados adicionais são erros |
| `validation` | regras semânticas: referências, conflitos simétricos, ciclos, geometria de hunks, camadas e fatos |
| `patch` | aplicação e reversão de hunks, estado e busca de assinaturas mascaradas |
| `analysis` | correspondência de módulos (desfazendo correções conhecidas), detecção de versão, estados de patches e relatórios de análise |
| `plan` | resolução de seleção, composição, verificações estruturais, reconstrução no local ou com reorganização, verificação independente; documentos de plano e manifesto |
| `schema` | JSON Schemas gerados a partir dos tipos de documento |
| `legacy` | conversão de registros schema-1 do x99-bios-fixes |
| `breadcrumbs`, `synthetic` | decodificação de diagnóstico CMOS do MR9A; firmware de teste sem conteúdo de fornecedor |

## Etapas de geração

1. **Resolver**: expandir substituições, verificar conflitos, restrições de hold/diagnóstico/manual, fatos e requisitos necessários.
2. **Localizar**: para cada componente, localizar o módulo por GUID e tipo de folha, reverter correções reconhecidas e exigir o hash de origem registrado. Componentes em camadas são conferidos primeiro contra seu `input_sha256`.
3. **Contexto**: módulos no `context` de uma variante devem corresponder aos hashes revisados.
4. **Compor**: aplicar correções de base e depois as em camadas; resultados de patch único devem corresponder aos hashes registrados.
5. **Estrutura**: verificações opcionais (base da imagem XIP, ausência de bytes relocados). Tabelas ACPI são recolocadas em seu contêiner.
6. **Reconstruir**: arquivos reconstruídos mantêm sua posição se couberem; caso contrário, o volume é reorganizado no espaço livre. Arquivos XIP, fixos, de topo e de preenchimento com dados nunca se movem.
7. **Verificar**: analisar novamente; cada patch selecionado e mantido deve ser lido como `fixed`; cada byte fora da lista permitida deve ser igual à entrada; hashes de módulos PE devem corresponder.
8. **Publicar** (CLI): preparar imagem e manifesto no diretório de saída, sincronizar e criar links primeiro para o manifesto e depois para a imagem, sem substituir nada. Uma falha após publicar o manifesto o remove; se isso também falhar, `PUBLISH_INCOMPLETE` informa o que restou.

## Acesso ao chip flash

`bme flash` é o único caminho de código que chega a um chip, e faz isso executando o flashrom; o `bme` não tem drivers de gravadores. `flash doctor` lê sysfs, procfs e efivarfs. `flash probe` e `flash backup` leem o chip. `flash write` é o único comando que o altera, depois destas verificações: a imagem é reconhecida e tem o tamanho do backup, a imagem é igual ao backup fora das regiões gravadas, o chip lido agora é igual ao backup, e quem chama repete o SHA-256 da imagem. Os limites das regiões vêm do analisador de flash descriptor do núcleo e chegam ao flashrom como um arquivo de layout. As regiões gravadas são lidas novamente e comparadas.

Os comandos flash retornam antes de a configuração do usuário ser carregada, porque com `sudo` ou `pkexec` o diretório pessoal é o do root. A interface executa os comandos do chip pelo `pkexec` quando solicitado e os trata como não interrompíveis: ela não pode sinalizar um processo root, e uma gravação precisa terminar.

## Limites de confiança

- Arquivos de catálogo são entrada não confiável: limites de tamanho, análise estrita, hashes do índice, regras de caminhos e validação semântica.
- Receitas não são confiáveis: `patch --from` recalcula e compara tudo.
- Catálogos remotos só são confiáveis por uma chave minisign configurada localmente e como cópias validadas.
- Arquivos de ferramentas baixados só são confiáveis por hashes fixados.
- O flashrom vem de `--flashrom`, `BME_FLASHROM`, `tools.flashrom`, `PATH` ou dos diretórios sbin, nessa ordem (root ignora `tools.flashrom`); sua saída só é interpretada para nomes de chip, e todo resultado relevante é conferido lendo o chip.

## Ausências deliberadas

Não há daemon, infraestrutura de plugins, banco de dados ou drivers de gravadores. A interface usa o mesmo protocolo `--json` dos demais clientes.
