# Ambiente de replay

[English](../../guide/replay.md) | Português (Brasil)

O replay executa instruções originais do firmware contra hardware simulado, para demonstrar um achado sem gravar a flash. O emulador é o Unicorn, controlado por Python; o bme gerencia o ambiente Python como gerencia o Ghidra.

```sh
bme tools setup replay                         # python3 >= 3.10 cria <data dir>/replay/venv e o pip instala o lock
bme tools setup replay --python /usr/bin/python3.12
bme --offline tools setup replay --wheelhouse ./wheels
bme tools status                               # a linha replay: ready, attention ou missing
bme tools doctor replay --deep                 # versões, depois o Unicorn executa uma instrução
bme tools set replay /path/to/venv             # usa um interpretador ou ambiente existente
bme tools unset replay
```

## O que o setup instala

O setup precisa apenas de `python3` 3.10 ou mais novo com o módulo `venv` (Ubuntu: `apt install python3 python3-venv`). Ele cria o ambiente em um diretório temporário e executa `python -m pip install --isolated --no-input --require-hashes --only-binary :all: --no-deps -r requirements.lock`. O lock, embutido de `tools/replay/requirements.lock`, fixa:

| Pacote   | Versão    |
| -------- | --------- |
| unicorn  | 2.1.4     |
| capstone | 5.0.9     |
| pefile   | 2024.8.26 |

Cada pacote lista o SHA-256 de todo wheel publicado para Linux 64 bits (glibc e musl), macOS e Windows; o pip aceita um wheel de qualquer uma dessas plataformas e rejeita o resto, inclusive distribuições de código-fonte. `--isolated` ignora a configuração do pip e as variáveis `PIP_*`, então um índice do usuário não substitui o lock. `tools/replay/lock.py` regenera o lock a partir da API JSON do PyPI.

Depois de instalar, o setup move o ambiente para o lugar, lê as versões de volta e faz o Unicorn executar uma instrução. Um segundo `setup` que encontra um ambiente saudável da mesma versão não altera nada. Um ambiente que o bme não criou só é substituído com `--force`, que o apaga.

`--offline` exige `--wheelhouse DIR` com os wheels fixados; o pip então roda com `--no-index --find-links DIR`. O setup nunca instala sozinho: um comando que precisa do ambiente e não o encontra falha com `TOOL_UNAVAILABLE` e cita `bme tools setup replay`.

## Localizar o ambiente

O bme usa o interpretador de `BME_REPLAY_PYTHON`, depois `tools.replay_python` (salvo por `tools set replay`), depois o ambiente gerenciado. `tools set replay <caminho>` aceita um interpretador ou um diretório de ambiente virtual e o recusa, a menos que informe Python 3.10 ou mais novo e exatamente as versões fixadas. `tools status` mostra a linha como opcional, então a ausência do ambiente não torna o relatório não pronto. Um local salvo ou vindo de variável bloqueia o `setup`; execute `bme tools unset replay` antes. `tools doctor` verifica o replay quando há um ambiente instalado ou escolhido; `tools doctor replay` o exige.

## Limite de licença

O Unicorn Engine é GPLv2. O bme não distribui código do Unicorn: você o instala em um ambiente separado, e o bme inicia o Python desse ambiente como subprocesso e troca arquivos e JSON com ele. Capstone e pefile são instalados do mesmo modo. Os metadados do wheel do Unicorn 2.1.4 indicam licença BSD para o binding Python; confira a licença da biblioteca do motor dentro do wheel antes de redistribuí-lo.
