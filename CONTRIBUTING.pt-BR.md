# Como contribuir

[English](CONTRIBUTING.md) | Português (Brasil)

## Código

Instale [cargo-nextest](https://nexte.st/docs/installation/pre-built-binaries/) (a CI usa 0.9.150). O nextest executa cada teste em seu próprio processo e agenda testes de executáveis diferentes em paralelo. Execute doctests separadamente com `cargo test --doc`.

```sh
cargo fmt --all --check
cargo clippy -p biosmod-core -p biosmod-host -p biosmod-cli --all-targets -- -D warnings
cargo nextest run --locked -p biosmod-core -p biosmod-host -p biosmod-cli
cargo test --locked --doc -p biosmod-core -p biosmod-host -p biosmod-cli
cargo build -p biosmod-cli
cargo clippy -p biosmod-gui --all-targets -- -D warnings
cargo nextest run --locked -p biosmod-gui
cargo test --locked --doc -p biosmod-gui
```

Use `--profile ci` para os limites de tempo e relatórios de falha da CI. Execuções gráficas nativas em X11 ou Wayland usam `--test-threads 1` para que as janelas não disputem o foco; testes sem monitor usam o paralelismo padrão do nextest. Compile a CLI antes dos testes de integração da interface, pois eles executam `target/debug/bme`.

Para verificar o portal de seleção de arquivos em uma sessão de desktop, use `cargo test -p biosmod-gui --test native_dialog -- --ignored --nocapture`. O teste abre o seletor de planos em português por dois segundos; em seguida, o processo termina e fecha o diálogo. Execute-o com cada backend de exibição.

Core e CLI mantêm Rust 1.88 e cobertura de Linux, Windows e macOS. A interface Linux exige Rust 1.92 e suas bibliotecas nativas de janelas e gráficos. A CI a verifica separadamente em Ubuntu 24.04, com testes básicos de renderização por software em X11 e Wayland. Ao alterar a interface, confira ambas as sessões, navegação por teclado, escala e diálogos de arquivo; testes sem monitor não qualificam a integração gráfica por si só.

- O core nunca faz I/O; a CLI nunca interpreta firmware por conta própria (veja [arquitetura](docs/pt-BR/architecture.md)).
- Cada função nova recebe um teste. Correções de bugs começam com um teste que falha pelo motivo relatado.
- I/O externo em testes usa fakes nomeados (`FakeTransport`, `FakeTools`, `FakeCmos`, `FakeFlashChip`, `FakeSysfs`, `FakeKernelLog`, `FakePrivilege`, `FixedClock`, `RecordingPorts`, `FakeSuperIoPorts`, `FakePowerSysfs`, `UnreadableKernelLog`, `RootOnlyFiles`), nunca rede ou hardware real.
- Erros informam o valor inválido e a forma esperada: `module size: expected 604832 | received 604800`.
- A CI obrigatória não deve depender de ROMs de fornecedores ou downloads grandes. Testes que precisam de dumps reais os leem das variáveis `BME_ROM_*` e informam quando são ignorados.
- Commits seguem Conventional Commits, uma preocupação por commit, com corpo.

Depois de alterar um tipo de documento, gere novamente os schemas versionados: `BME_UPDATE_SCHEMAS=1 cargo nextest run --locked --test cli`.

## Traduções

O inglês é a fonte canônica. Ao alterar um documento em inglês, revise sua tradução brasileira correspondente e atualize manualmente o SHA-256 da fonte em `docs/i18n-manifest.json` somente após a revisão. O hash registra a revisão da versão da fonte, não comprova a qualidade da tradução. Novos arquivos Markdown em `docs/` exigem contraparte e entrada no manifesto. Preserve comandos, flags, exemplos JSON e saída da CLI em inglês. Execute `python3 tools/check-doc-translations.py` e `python3 -m unittest discover -s tools/tests` para verificar cobertura, atualidade e links locais.

Para mensagens da interface, instale o extrator correspondente com `cargo install slint-tr-extractor --version 1.18.1 --locked` e execute `python3 tools/update-gui-translations.py` para atualizar os catálogos ou acrescente `--check` para conferi-los. Revise traduções alteradas e mantenha os identificadores e detalhes técnicos originais.

Use termos consistentes: firmware, patch e catálogo; traduza manifest como manifesto e offline verification como verificação offline. A CLI e seu protocolo continuam em inglês.

## Caches da CI

Cada job armazena downloads do Cargo e crates de dependências compilados com `Swatinem/rust-cache`. PRs podem restaurar caches de `main`; jobs de PR bem-sucedidos também salvam caches para execuções posteriores do mesmo PR. O GitHub isola caches de PR de `main` e de outros PRs.

Caches são separados por job, sistema operacional e arquitetura do runner, compilador e ambiente de compilação (incluindo `RUSTFLAGS`). Manifestos Cargo, lockfiles, arquivos de toolchain e configuração Cargo contribuem para invalidação automática. Após alterar uma dependência, a action pode restaurar um cache antigo e o Cargo recompila as dependências conforme necessário. Jobs de MSRV e da interface definem `RUSTUP_TOOLCHAIN` antes de procurar o cache para que metadados e compilações usem o mesmo compilador.

Crates do workspace e estado de compilação incremental são excluídos pela limpeza padrão da action. Artefatos de dependências debug e release são armazenados, mas cada perfil ainda precisa de uma compilação inicial. Ausência de cache e remoção pelo GitHub são esperadas; cada job também deve funcionar com cache vazio. Downloads da toolchain Rust e pacotes de sistema do job gráfico são instalados separadamente em cada runner.

## Perfis de placa e registros de patches

Um registro é aceito quando outra pessoa pode conferi-lo apenas com os arquivos.

1. Adicione ou atualize `catalog/boards/<id>.json`. Informe como a revisão é conhecida (`observed` na placa, `unverified` em anúncio ou `unknown`). IDs de placa usam letras minúsculas.
2. Adicione a variante sob o ID da versão do firmware em `catalog/patches/<id>.json`. Hunks precisam dos bytes originais exatos, 16 bytes de contexto em cada lado e hashes de origem e resultado. Variantes portadas começam com `bme derive` e devem ser revisadas hunk por hunk (`bme guide porting`).
3. Coloque em `catalog/provenance/` o código assembly ou as notas necessários para revisar a alteração.
4. Execute `bme catalog index catalog` e `bme catalog validate catalog`.
5. No PR, informe qual é o achado, como foi demonstrado (executado, analisado ou plausível), o que a correção não cobre e como conferiu o resultado.

Observações de hardware ficam em `catalog/evidence/`, com o `image_sha256` exato gravado, versões dos patches, configuração e limites. Uma observação nunca aumenta a confiança geral de um registro. Nunca inclua imagens de fornecedores ou módulos extraídos.

## Segurança

Informe vulnerabilidades de análise, confiança de catálogo ou instalação de ferramentas em particular pelos avisos de segurança do GitHub, não em issues públicas.
