# Qualificação da interface no Linux

[English](../linux-desktop-qualification.md) | Português (Brasil)

O pacote da PR #47 passou nas verificações registradas em uma VM limpa Ubuntu 24.04.5 x86_64 em 2026-11-10, no commit `ef16c82119d56b878dee16cab68c12e8c768bf96`. O pacote da [execução 42868520102 da CI](https://github.com/juliopolycarpo/biosmod-engine/actions/runs/42868520102) tinha SHA-256 `c0bbd32ed03ddd011f21e5b89dcc54c058e6d89e8b1e1677c03b16a89ea9d7a7`, verificado no host e na VM. A VM usou QEMU/KVM virtio VGA e Mesa llvmpipe.

| Sessão | Resultados |
| --- | --- |
| GNOME 46 Wayland, Mutter | Fluxo por teclado, portal, área de transferência e Orca passaram. Em 1920×1440, escala de tela 1,25 com escala de texto 1,5 manteve visíveis a área estreita de Ferramentas e o rodapé. |
| GNOME 46 Xorg | O mesmo fluxo passou. No mínimo de 760×600, a escala de texto 1 → 1,5 → 1 mudou a geometria do cliente para 1140×900 e de volta sem pânico. A escala experimental de tela 1,25 com texto 1,5 manteve visíveis a revisão e o rodapé. |
| Plasma 5.27.11 Wayland, KWin | O mesmo fluxo passou. A escala de saída 1 → 1,25 → 1 manteve ativa a interface com renderização por software. Femtovg explícito também resistiu a mudanças de escala e respondeu à navegação por teclado. |

Cada sessão usou renderização por software para analisar a imagem sintética, selecionar CX, planejar, gerar e verificar automaticamente de forma independente. Eventos de teclado físico controlaram a interface; AT-SPI observou seu estado. O Orca anunciou o estado do patch, os detalhes do plano e a conclusão da verificação. Exportar, reabrir e cancelar no portal preservou a revisão importada e devolveu o foco. A cópia substituiu um valor distinto na área de transferência, e a colagem preencheu um campo limpo. O Orca também anunciou um erro de caminho inválido e, com atraso de oito segundos no mecanismo, uma mensagem de execução e uma de conclusão. As duas sessões Wayland usaram conexões Wayland nativas.

O título e o rodapé iniciais couberam em 1280×800, e o redimensionamento por teclado funcionou nas três sessões. No GNOME Wayland, Ferramentas mostrou `TOOL_UNAVAILABLE` e os caminhos de configuração, cache e dados; ao mudar para português, o título em cache mudou de Paths para Caminhos sem outra solicitação de ferramentas. No KDE, a fonte geral do desktop foi definida como Noto Sans 15 pt e a interface permaneceu utilizável; não foi comprovado que o Slint herdou essa fonte.

O `ldd` encontrou as bibliotecas dos dois executáveis. Rust, Cargo, Ghidra e Java não estavam no `PATH` durante as verificações de execução. O Femtovg usou Mesa llvmpipe e emitiu avisos EGL DRI2, continuando a responder; nenhuma GPU física foi testada. As gravações do Orca vieram de um monitor PipeWire; a reprodução de áudio físico não foi testada. Nenhum firmware foi gravado ou inicializado, e a verificação offline não comprova a inicialização segura do hardware. Os resultados se aplicam ao pacote e às versões de desktop testados.

## Repetir o fluxo sintético

Extraia o pacote e entre no diretório raiz extraído em uma sessão gráfica. Crie um catálogo local e uma imagem isolados sem acesso à rede:

```sh
qualification_root=$(mktemp -d)
export BME_CONFIG_HOME="$qualification_root/config" BME_CACHE_HOME="$qualification_root/cache" BME_DATA_HOME="$qualification_root/data"
./bin/bme dev synthetic -o "$qualification_root/fixture"
./bin/bme catalog add lab "$qualification_root/fixture/catalog" --allow-unsigned-local
SLINT_BACKEND=winit-software ./bin/bme-gui "$qualification_root/fixture/synthetic.bin"
```

Inspecione a imagem e analise com a fonte `lab`, selecione CX, revise o plano e gere um arquivo em um caminho novo. Confirme a conclusão da verificação offline. Apague `$qualification_root` após a execução.
