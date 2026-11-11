# Interface gráfica no Linux

[English](../../guide/gui.md) | Português (Brasil)

`bme-gui` é um cliente gráfico para `bme`. Ele lê imagens de firmware e cria novos arquivos de saída. Somente a página **Gravar chip** acessa um chip flash, por meio de `bme flash` e do flashrom. A interface executa todas as requisições offline, exceto **Baixar e instalar** na página Fontes e ferramentas, que baixa o Ghidra fixado. A verificação examina a imagem offline e não comprova segurança de inicialização, compatibilidade física com a placa ou aceitação pela verificação de assinatura da plataforma.

## Compilar e executar

Linux x86_64 é o primeiro alvo da interface. A interface exige Rust 1.92 ou posterior; core e CLI mantêm o mínimo Rust 1.88. Compile os dois executáveis juntos:

```sh
cargo build --locked --release -p biosmod-cli -p biosmod-gui
target/release/bme-gui
```

A interface procura `bme` ao lado do próprio executável. Para usar outra instalação, escolha-a em **Configurações** ou inicie `bme-gui --engine /absolute/path/to/bme`. A alternativa deve passar pela negociação de protocolo e anunciar `desktop_workflow: 1` e `direct_patch_workflow: 1`; um executável antigo com a mesma versão do pacote não é suficiente. Nenhum mecanismo é carregado de um diretório de imagem ou catálogo.

A compilação usa Slint 1.18.1 com backend winit e renderizadores de GPU e software. A interface se liga a fontconfig, FreeType, libgcc e glibc. O ambiente gráfico também precisa de fontes, XKB e bibliotecas cliente Wayland ou X11; a renderização por GPU também exige uma pilha OpenGL/EGL funcional. Algumas bibliotecas gráficas e de janelas são carregadas dinamicamente. Os diálogos nativos de arquivo usam o portal XDG do ambiente gráfico e um backend de portal. A entrada manual de caminho permanece disponível se o portal estiver indisponível. Para forçar renderização por software:

```sh
SLINT_BACKEND=winit-software target/release/bme-gui
```

A CI usa Ubuntu 24.04 x86_64 (glibc 2.39) como alvo do pacote e exercita conexões X11 e Wayland sem monitor separadamente. O [relatório de qualificação da interface no Linux](../linux-desktop-qualification.md) registra os resultados em VM limpa para GNOME e Plasma, escala e leitor de tela no pacote e nas versões de desktop testados. O comportamento da interface no Windows e macOS ainda não foi qualificado.

A janela inicia no tamanho mínimo suportado de 760×600, deixando espaço para painéis e decorações em desktops pequenos. Redimensione-a para ter uma área de trabalho maior.

## Pacote Linux

Compile na base Ubuntu 24.04 pretendida para evitar exigir uma glibc mais recente:

```sh
./packaging/linux/archive.sh
```

O pacote em `dist/` contém os executáveis correspondentes, uma entrada de aplicativo, um ícone e avisos de licença. Extraia-o e execute `bin/bme-gui`, ou copie seus diretórios `bin/` e `share/` para `~/.local/` e verifique que `~/.local/bin` está no `PATH`. O pacote não é uma sandbox e compartilha configuração, cache e fontes de catálogo da CLI. O sistema ainda fornece bibliotecas gráficas, de fontes, teclado e portal.

O código do projeto é MIT. A distribuição gráfica usa a Slint Royalty-free Desktop, Mobile, and Web Applications License 2.0; **Sobre** exibe o widget AboutSlint exigido. O pacote contém essa licença e os avisos das dependências de execução em `share/licenses/biosmod-engine/`.

## Analisar, selecionar e gerar

1. Escolha uma imagem, inspecione-a, escolha uma fonte de catálogo e execute o scan. Um perfil de placa identifica informações do catálogo, não a revisão ou os componentes de uma placa física.
2. Selecione correções elegíveis clicando em um resultado ou pressionando Espaço ou Enter. **Recomendados** seleciona as linhas recomendadas pelo mecanismo quando toda a recomendação é elegível. Linhas que exigem afirmações de hardware, permissões hold ou de diagnóstico, ou seleção conjunta de pré-requisitos não podem ser selecionadas aqui. A ausência de detecção não prova a ausência de um defeito.
3. Escolha um caminho de saída e pressione **Gerar cópia com patches**. Por padrão, `.patched` é inserido antes da última extensão da entrada. Caminhos existentes da imagem e do manifesto não são sobrescritos. Se a imagem ou o catálogo mudou desde o scan, execute-o novamente e revise a seleção.
4. A interface verifica independentemente a saída publicada e o manifesto. Ela informa conclusão somente quando todas as verificações obrigatórias passam. Uma falha de publicação pode deixar artefatos; inspecione os caminhos informados. Uma verificação incompleta não é um resultado verificado.

**Visualizar alterações** gera e valida opcionalmente em memória para mostrar alterações de componentes e a saída esperada; não publica arquivos nem autoriza uma geração posterior. **Exportar seleção** salva a seleção visível em um novo arquivo de receita. As duas ações usam a entrada e a fonte do scan exibido.

**Abrir arquivo de seleção** carrega uma receita exata para reprodução após validação com a imagem, o catálogo e o mecanismo atuais. A interface mantém uma cópia privada e não permite que a receita conceda permissões não suportadas ou troque o catálogo selecionado. Uma receita exige o catálogo fixado e a compilação correspondente do mecanismo. Para reabrir uma saída, escolha a imagem original e a saída; o manifesto deve estar ao lado dela em `<output>.manifest.json`. Um arquivo de seleção opcional também pode ser usado para comparação.

**Fontes e ferramentas** lista as fontes de catálogo (somente leitura; use a CLI para registrá-las ou atualizá-las) e um cartão por ferramenta externa: Ghidra, ghidra-firmware-utils, Java, JDK, git, flashrom e o NASM opcional. O cartão mostra estado, versão e local. **Baixar e instalar** só aparece quando nada o bloqueia (um local salvo ou a falta do JDK ou do git bloqueiam; o cartão diz o que fazer antes) e obtém o Ghidra fixado com as mesmas verificações de `bme tools setup ghidra`; leva minutos e pode ser cancelado. **Escolher local…** grava uma pasta do Ghidra ou um programa flashrom existente, e **Restaurar** o esquece. Para Java, git e flashrom o cartão mostra o comando do gerenciador de pacotes para você executar. A interface nunca executa `sudo`.

## Gravar chip

A página **Gravar chip** funciona no Linux com o flashrom instalado e um mecanismo que anuncie `flash_workflow: 1`. `bme guide flashing` explica cada passo e suas recusas.

1. Informe um programador do flashrom (`internal` para esta máquina, `ch341a_spi` para um CH341A) e pressione **Diagnosticar**. O relatório mostra a placa, o perfil de placa correspondente no catálogo e o que ajuda ou impede o acesso ao chip.
2. **Localizar chip** identifica o chip. Se várias definições corresponderem, use a CLI com `--chip`; a página não tem campo para o chip.
3. Escolha um novo arquivo de backup com **Novo…** e pressione **Fazer backup do chip**. O chip é lido duas vezes; arquivos existentes não são sobrescritos.
4. Gere uma cópia com patches a partir desse backup na página Fluxo de trabalho. **Gravar esta saída…**, na visão de resultados, leva a saída como imagem.
5. **Conferir** compara o chip com o backup e lista as regiões e o número de bytes que vão mudar. Nada é gravado. **Chip inteiro** serve para chips sem Intel flash descriptor.
6. Marque a confirmação de recuperação e pressione **Gravar chip**. A gravação repete exatamente o programador, a imagem e o backup conferidos; editar qualquer um deles exige nova conferência. O chip é lido novamente em seguida.

Com **Pedir direitos de administrador** marcado, Localizar chip, Fazer backup do chip, Conferir e Gravar chip executam o `bme` pelo `pkexec`, que mostra a janela de autenticação do ambiente gráfico. Desmarque quando a interface já tiver acesso ao gravador, por exemplo por regras udev para um gravador USB. Diagnosticar nunca pede; execute `sudo bme flash doctor` para incluir os bits de proteção de escrita do BIOS.

Backup, conferência e gravação não podem ser cancelados, e a janela permanece aberta até terminarem. Se uma gravação falhar depois de iniciada, o status informa que o chip pode conter uma imagem parcial: mantenha a placa ligada e siga `bme guide recovery`.

## Configurações e diagnóstico

O tema padrão acompanha o ambiente gráfico e usa o tema claro como alternativa. **Configurações** também oferece opções explícitas clara e escura. O seletor de idioma oferece English (o padrão) e Português (Brasil); as alterações são aplicadas imediatamente e salvas com as demais preferências. O texto do aplicativo segue essa escolha; controles nativos de seleção de arquivo podem seguir o idioma do ambiente gráfico. Diagnósticos do mecanismo e textos do catálogo permanecem no idioma original. As preferências de tema, idioma e caminho do mecanismo são armazenadas em `$BME_CONFIG_HOME/gui.json` quando `BME_CONFIG_HOME` está definido; caso contrário, ficam em `$XDG_CONFIG_HOME/biosmod-engine/gui.json` ou `~/.config/biosmod-engine/gui.json`. Valores vazios e caminhos XDG relativos são ignorados. Valores relativos de `BME_*_HOME` são resolvidos a partir do diretório de inicialização da interface e enviados como caminhos absolutos ao mecanismo. Editar o mecanismo invalida a conexão anterior imediatamente; a preferência é salva ao pressionar Enter ou quando o campo perde o foco. Escolher um executável com Procurar salva imediatamente. Caminhos de imagem e saída não são salvos ali.

Operações somente de leitura podem ser canceladas. A geração de uma cópia não pode ser cancelada com segurança pela interface; aguarde a publicação terminar. Se o processo for interrompido externamente, confira os dois caminhos de saída antes de tentar novamente. A página Diagnóstico pode copiar ou exportar mensagens recentes com tamanho limitado. Revise essas mensagens quanto a caminhos locais antes de compartilhá-las.

## Limites do firmware

O mecanismo alinha arquivos FFS em relação ao volume, permitindo analisar e reorganizar volumes em qualquer deslocamento da imagem. Em imagens com descriptor, endereços flash mapeiam o fim da região BIOS para 4 GiB. Tabelas ACPI catalogadas em deslocamentos disjuntos de uma seção RAW suportam alterações de mesmo tamanho e verificação independente, usando GUID, seção folha e deslocamento da tabela como identidade ([#36](https://github.com/juliopolycarpo/biosmod-engine/pull/36)). Sobreposições e redimensionamentos de múltiplas tabelas que possam mover outra tabela são recusados. Verificações de cobertura de relocação TE continuam não suportadas e retornam `FORMAT_UNSUPPORTED`.

Quando a verificação independente não pode terminar, a CLI informa `VERIFICATION_INCOMPLETE` com o relatório parcial nos detalhes do erro. A interface mantém resultados incompletos separados dos verificados.

## Validação da interface anterior registrada em 2026-11-09

O fluxo sintético real passou pelo controlador e pelo loop de eventos Slint, incluindo exportação de plano e verificação independente automática. Os bytes de saída e a semântica do manifesto correspondem a uma execução equivalente da CLI. Execuções nativas em Ubuntu 26.04/GNOME passaram com renderização por software Wayland nos temas claro e escuro, renderização acelerada Wayland e renderização por software X11 via XWayland. Isso é separado da qualificação de um desktop Xorg nativo.

Testes de callbacks sem monitor cobrem habilitação, invalidação de entrada, planos importados, recuperação de publicação, cancelamento/fechamento e exportação. A inspeção AT-SPI nativa encontrou os controles principais e seus rótulos de acessibilidade. Essa verificação não comprova um fluxo completo com leitor de tela ou somente teclado. Layouts foram renderizados em 1080×780 e 760×600. Após o refinamento da interface, capturas nativas com renderização por software Wayland nos dois tamanhos e temas cobriram todas as páginas no mesmo host Ubuntu 26.04/GNOME; nenhum outro desktop foi verificado novamente. Testes com ROMs de fornecedores foram ignorados porque nenhuma entrada `BME_ROM_*` estava configurada; nenhum teste de inicialização em hardware foi realizado.
