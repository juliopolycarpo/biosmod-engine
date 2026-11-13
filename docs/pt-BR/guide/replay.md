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

## Executar um harness

```sh
bme replay script harness.py --module PchSmiDispatcher.pe -o out/ -- --case 3
```

Um harness é um script Python que importa `bme_replay`, carrega os módulos informados com `--module` (`bme_replay.modules()`), chama funções do firmware e relata com `bme_replay.emit(documento)`. O bme o executa como `python -I -B` no ambiente do replay, passa os argumentos depois de `--` como `sys.argv[1:]` e coleta cada documento JSON emitido. Um harness que levanta exceção, termina com código diferente de zero ou passa de `--timeout` (600 s por padrão) faz o comando falhar com `TOOL_FAILED` e o final do stderr.

`bme_replay` é código MIT que o bme embute e grava em `<diretório de dados>/replay/package-<digest>` antes de cada execução. Uma versão nova grava um diretório novo e nunca reescreve um que já existe, então uma execução em andamento e duas execuções iniciadas juntas não se atrapalham, e o ambiente não é recriado. Os diretórios de digests antigos ficam; apague-os quando nenhuma execução os usar. Ele oferece:

| Peça | Uso |
| ---- | --- |
| `Machine(32 ou 64)`, `machine.call(endereço, *args, budget=N)` | Executa uma função na convenção Microsoft x64 ou cdecl; registradores preservados e o ponteiro de pilha são verificados, um orçamento de instruções limita a execução, uma falha levanta `EmulationFault` ou volta com `capture_fault=True` |
| `load_pe(machine, bytes, base=...)` | Mapeia uma imagem PE32, PE32+ ou TE, aplica realocações e confere o tipo de máquina com a largura |
| `DxeServices`, `SmmServices`, `PeiServices`, `VariableStore` | Tabelas de serviço falsas; GetVariable e SetVariable usam o repositório, qualquer outro slot precisa de um tratador ou levanta `UnmodeledService` |
| `machine.ports.attach(dispositivo, portas, nome)`, `PortRegisters`, `IndexedRegisters` | Dispositivos de porta nomeados; uma porta que ninguém reivindica levanta `UnmodeledAccess` |
| `machine.mmio(base, tamanho, dispositivo, nome)`, `RegisterFile` | Regiões MMIO |
| `machine.attach_msrs(MsrBus(...))` | RDMSR e WRMSR |
| `SmbusDevice`, `SpdEeprom` | Um controlador SMBus do PCH com escravos |
| `machine.stub(endereço, tratador)`, `machine.trace` | Substitui uma função e lê ou calcula o hash do rastro de eventos |

Com `-o DIR`, o bme grava `result.jsonl` (os documentos, um por linha) e `evidence.json`, um registro `bme.evidence/1` do tipo `offline-validation`. O bloco `replay` traz o nome do harness, as versões do interpretador e dos pacotes, a versão do bme, o digest do pacote `bme_replay`, o SHA-256 do harness e de cada módulo e o SHA-256 de `result.jsonl`. `--board` e `--firmware` definem o escopo do registro; ambos são `unscoped` por padrão, e um catálogo só aceita o registro depois que nomeiam uma placa e uma build reais. Sem `-o`, o registro aparece só na resposta de `--json`. Um `evidence.json` ou `result.jsonl` existente nunca é sobrescrito.

`tools/replay/examples/b11_context_overread.py` é um harness completo: reexecuta o registro original do `PchSmiDispatcher` com contextos no fim de uma página legível e mostra a leitura de 16 bytes falhando no RVA `3A02` quando restam menos de 16 bytes.

## Executar um cenário

Um cenário é um arquivo JSON `bme.scenario/1` que descreve uma chamada sem nenhum Python:

```sh
bme schema scenario
bme replay run tools/replay/scenarios/smartfan-zero-policy/pwm0-seed0.json --module SioDxeInit.pe -o out/
```

Ele traz o SHA-256 e a largura em bits do módulo (nunca os bytes), o RVA de entrada e os argumentos, as tabelas de serviço (`dxe`, `smm` ou `pei`) com os campos da imagem que apontam para elas, modelos de hardware da biblioteca (`port-registers`, `indexed-registers`, `mmio-registers`), variáveis UEFI presentes antes da chamada, um orçamento de instruções e as expectativas. Os números são inteiros JSON ou strings `0x`. Cada modelo de hardware aceita só as próprias opções, e um banco em uma expectativa precisa ser menor que o `banks` do modelo. Uma expectativa `service-calls` nomeia um slot da tabela em `tools/replay/service-names.json`; o mesmo arquivo alimenta o runtime Python, que falha diante de um nome que não conhece. Um argumento ou vínculo pode nomear um endereço que o runtime fornece: `image-base`, `system-table`, `boot-services`, `runtime-services`, `smm-table` ou `pei-services`. Uma expectativa confere o valor de retorno, um registrador indexado (`bank`, `index` e `mask` opcional), uma porta, uma variável ou quantas vezes um serviço foi chamado. Campos desconhecidos e chaves duplicadas são rejeitados.

O `bme replay run` recusa um módulo cujo SHA-256 difere do cenário (`PATCH_SOURCE_MISMATCH`, antes de executar qualquer coisa), reexecuta a chamada e imprime `ok` ou `FAIL` para cada expectativa, com os valores esperado e recebido. Com `-o DIR` o registro é gravado nos dois casos, com o cenário e o módulo listados por SHA-256, o id do cenário no bloco `replay` e a versão do bme e o digest do pacote `bme_replay` em `runtime`.

O bme não aceita o veredito do runtime como dado. Ele valida o cenário uma vez, grava a forma canônica em um arquivo temporário e passa o arquivo com o SHA-256; o runtime se recusa a executar se o digest diferir. Depois lê as expectativas do cenário que validou, exige que `kind` e `expected` do runtime coincidam e recalcula `passed` a partir de `received`. Um resumo que traz erro nunca passa.

| Código | Significado |
| --- | --- |
| `SCENARIO_INVALID` | O arquivo do cenário é malformado (campo desconhecido, chave duplicada, valor inválido), ou a preparação falhou: um slot de serviço, uma opção de hardware ou um vínculo que o runtime não conseguiu montar. |
| `REPLAY_FAILED` | A chamada executou e uma expectativa falhou, ou a própria chamada gerou falha, tocou um endereço não modelado ou esgotou o orçamento. O firmware fez algo diferente do que o cenário espera. |
| `TOOL_FAILED` | O runtime falhou: travou, estourou o tempo, avaliou uma expectativa errado ou devolveu um documento que contradiz o cenário. |
| `PATCH_SOURCE_MISMATCH` | O SHA-256 do módulo não é o do cenário. |

O runtime informa a fase em que parou (`setup`, `call` ou `evaluate`) no `error` do resumo, e o bme a converte em código como na tabela. `--json` traz todos os veredictos em `details`.

`tools/replay/scenarios/smartfan-zero-policy` reúne doze cenários da rotina de Smart Fan do `SioDxeInit` da MR9A: o primeiro degrau de PWM da curva da CPU vale 0, 1, 64 ou 150, a partir de três estados pseudoaleatórios do monitor de hardware. Cada um espera que o PWM1 guarde o degrau sem limitação. Eles nomeiam o módulo só pelo digest; extraia-o da sua própria imagem com `bme extract <rom> --guid 4E82091E-32A1-4689-8A00-CDE41ED63CDD -o SioDxeInit.pe`. O GUID de fornecedor da variável nos cenários é o GUID do VarStore do setup, não o GUID do módulo.

`tools/replay/examples/b02_b03_dimm_counter.py` é um script para o que cenários não expressam, uma EEPROM SPD com estado e seleção de página. Ele executa a detecção de DDR4, a leitura do SPD e o reconhecimento do tipo do `UncoreInitPeim` original da MR9A ou da PR9 (extraia com `--guid D71C8BA4-4AF2-4D0D-B1BA-F2409F0C20D3`) para cada combinação de página inicial, marcador de DDR4 retido e política de página. Com a política Enabled o cabeçalho é lido só no escravo `0xA6` (slot 3, em vez de `0xA0`, `0xA2` e `0xA4`), e com Auto na página 1 sem marcador o cabeçalho fica ilegível. Ele escolhe a tabela de rotinas pelo digest do módulo e recusa qualquer outro módulo. Substitui apenas as transações da EEPROM e o registrador de rascunho da CPU, pula o ramo da política e define o bit diretamente, então não prova a energia retida do SPD nem a causa raiz em campo.

Uma execução emulada mostra o que as instruções fazem contra os modelos que o harness fornece. Não é uma observação em hardware, e o registro diz isso em `limits`.

## Limite de licença

O Unicorn Engine é GPLv2. O bme não distribui código do Unicorn: você o instala em um ambiente separado, e o bme inicia o Python desse ambiente como subprocesso e troca arquivos e JSON com ele. O pacote embutido `bme_replay` é código MIT que chama a API Python do Unicorn e não contém código do Unicorn. Capstone e pefile são instalados do mesmo modo. Os metadados do wheel do Unicorn 2.1.4 indicam licença BSD para o binding Python; confira a licença da biblioteca do motor dentro do wheel antes de redistribuí-lo.
