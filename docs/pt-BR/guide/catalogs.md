# Catálogos

[English](../../guide/catalogs.md) | Português (Brasil)

Um catálogo é um diretório com estrutura fixa:

```
catalog.json            index: id, version, engine requirement, every file's path, kind, length and sha256
boards/<id>.json        board and revision profile (bme.board/1)
patches/<id>.json       one patch record (bme.patch/1)
findings/<id>.json      one defect or observation, with or without a patch (bme.finding/1)
evidence/<id>.json      one scoped hardware observation (bme.evidence/1)
provenance/...          supporting files (assembly sources, notes); hashed, never interpreted
```

O catálogo oficial é incorporado ao `bme`. `bme schema <name>` mostra o JSON Schema de cada documento. Esquemas cobrem a estrutura; `bme catalog validate` também verifica referências, geometria e hashes.

## Iniciar um repositório de dispositivo

```sh
bme catalog init acme-x99 --id acme-x99 --title "Acme X99 family"
```

`init` grava um diretório para uma placa ou família de placas e não executa git. Ele recusa um diretório existente, um id fora da regra de identificadores (1-64 caracteres de `A-Za-z0-9._-`, começando por letra ou dígito) e o id `official`. `--title` usa o id por padrão.

```
catalog.json            empty bme.catalog/1 at version 0.1.0; `bme catalog index` keeps it current
README.md               layout, work loop, commit convention and release rule
.gitignore              allowlist of the paths git tracks
.gitattributes          LF line endings, so the indexed hashes hold on every checkout
boards/ findings/ patches/ evidence/ provenance/    the catalog records
notes/                  investigation notes in prose
work/                   dumps, cases, extracted modules, tool output; stays local
```

O git rastreia a estrutura do catálogo e nada além: um novo caminho no nível superior fica local até você adicionar uma linha `!/nome` ao `.gitignore`. O git não registra diretório vazio, então cada diretório chega a um clone com seu primeiro arquivo. Em qualquer diretório, o `.gitignore` também ignora imagens de firmware e módulos extraídos (`*.bin`, `*.rom`, `*.pe`), tabelas ACPI, arquivos compactados, PDFs e chaves. Um dump contém números de série e endereços MAC, então fica fora do histórico; cite-o por nome de arquivo, SHA-256 e tamanho. Copie o dump para `work/` e execute `bme case init work/dump.bin -o work/case`: `bme case status` procura as entradas ao lado do diretório do caso.

Faça um commit por registro, com o id no escopo (`feat(H11): record unbounded PCU mailbox waits`) e o `catalog.json` reindexado no mesmo commit; confira com `bme catalog index . --check` e `bme catalog validate .`. Altere `version` apenas em um commit de release: `bme catalog update` recusa uma versão que já aceitou com outro conteúdo. Aumente-a, execute `bme catalog index .`, assine `catalog.json` com minisign, faça commit de `catalog.json.minisig` e crie uma tag no commit. Os usuários registram a URL raw do `catalog.json` da tag com `bme catalog add --trust-key`. O `README.md` gerado traz os detalhes.

## Compartilhar registros entre placas

Um defeito que duas placas compartilham mantém um único id em cada catálogo de placa, como `B02-B03` no catálogo embutido. Cada catálogo traz o mesmo texto e apenas a variante do seu próprio build.

```sh
bme catalog split official --board machinist-pr9-b85 -o pr9-repo --id pr9-b85
bme catalog merge . ../other-board --check
bme catalog merge . ../other-board -o both-boards --id both-boards
```

- `split SOURCE --board BOARD_ID -o DIR --id ID` inicia um repositório de placa a partir de um diretório de catálogo ou de `official`. Ele grava a estrutura de `catalog init` mais os registros da placa e lista cada patch, finding, registro de evidência e arquivo de procedência que deixou de fora. Um patch fica quando um build da placa tem uma variante `applicable`. Um finding fica quando afeta um build da placa, e um finding `fixed-by-patch` que perde todos os patches vira `open`. A evidência fica quando cita a placa. A procedência fica sob o id de um registro mantido. O comando falha quando um patch mantido exige um patch descartado ou cita um finding descartado.
- `merge --check SOURCE SOURCE...` não grava nada. Termina com código 0 e a contagem de registros compartilhados quando os catálogos concordam, e falha com o registro, o campo, os dois valores e os dois ids de catálogo quando um registro compartilhado divergiu.
- `merge SOURCE SOURCE... -o DIR --id ID` grava um diretório de catálogo com a união, na versão `0.1.0` salvo `--version`. Execute-o com `official` primeiro para reconstruir os registros embutidos.

Os registros são pareados por id. Listas da placa, variantes de patch, builds de finding, referências de código e evidências são unidas na ordem em que as fontes foram dadas. Um finding `open` em um catálogo e `fixed-by-patch` em outro vira `fixed-by-patch`. Todos os outros campos devem ser iguais, assim como o requisito `engine` e os bytes de um arquivo de procedência. As relações entre patches (`requires`, `supersedes`, `conflicts`) e os `patches` de um finding devem concordar em todo patch que os dois catálogos definem. As referências de código de um build que os dois catálogos listam, e as que não têm build, também devem ser iguais.

Uma variante `not-applicable` para o build de outra placa existe apenas em um catálogo que define os dois builds. Um catálogo de placa não pode carregá-la, então `split` a descarta e a união de catálogos de placa não a traz de volta.

## Placas e versões de firmware

Um perfil de placa informa fabricante, modelo e revisão, e como a revisão é conhecida (`observed`, `unverified`, `unknown`). Ele lista as versões de firmware fornecidas. Variantes de patches são identificadas pelo ID da versão de firmware, não da placa; duas placas com a mesma versão compartilham uma variante.

`facts` são afirmações sobre hardware que o firmware não pode comprovar, como "o Super I/O é um NCT5532D". Uma variante que depende de um fato o lista em `requires_facts`, e o usuário deve passar `--assert <fact-id>`.

## Registros de patches

```json
{
  "schema": "bme.patch/1",
  "id": "B05",
  "version": "1.0.0",
  "class": "correction",
  "tier": "recommended",
  "requires": [], "supersedes": [], "conflicts": [],
  "variants": {
    "mnx99mr9apro-230322": {"status": "applicable", "components": [ ... ]},
    "x99ha00m-20221202": {"status": "not-applicable", "reason": "..."}
  }
}
```

- `class` é `correction` ou `diagnostic` (exige `--allow-diagnostic`).
- `tier` é `recommended`, `optional` ou `hold` (exige `--allow-hold`).
- `packing: manual` marca alterações que o empacotador automático não consegue acomodar; são informadas, mas nunca planejadas.
- `requires` deve estar selecionado ou já corrigido. `supersedes` lista registros contidos neste. `conflicts` são simétricos e nunca combinados.

Um componente identifica um módulo (`ffs_guid`, `leaf` `pe32` ou `acpi-table`), seus hashes e tamanhos exatos de origem e resultado, e hunks. Um hunk é `replace` (mesmo tamanho) ou `append` (no fim do módulo). `layer_on` e `input_sha256` descrevem um patch escrito sobre o resultado de outros, como um diagnóstico sobre correções. `checks` solicita verificações estruturais adicionais (`xip_image_base`, `no_relocated_bytes`). `context` exige que outros módulos correspondam a hashes revisados.

## Achados

Um achado registra um defeito ou uma observação independente de qualquer patch, então um achado ainda sem correção também tem onde ficar. O catálogo oficial guarda o registro da auditoria como um documento por linha.

```json
{
  "schema": "bme.finding/1",
  "id": "B09",
  "title": "SMM library byte counter over the configuration-table count",
  "priority": "P2",
  "status": "fixed-by-patch",
  "affects": {"label": "Both", "builds": ["mnx99mr9apro-230322", "x99ha00m-20221202"]},
  "owner": {"description": "...", "modules": [{"ui_name": "OEMSmi", "ffs_guid": "..."}], "references": [...]},
  "confidence": {"finding": {"grade": "C0"}, "condition": {"grade": "C3", "note": "trigger"}},
  "description": "...", "not_established": "...", "remediation": "...",
  "evidence": [], "patches": ["B09"]
}
```

- `confidence.finding` gradua o comportamento do código ou a observação; `confidence.condition` gradua a causa ou o gatilho que o torna relevante. Ambos usam `C0` (estabelecido) a `C3` (especulativo), com `note` opcional para o aspecto graduado.
- `status` é `open`, `fixed-by-patch`, `retired` (retirado por análise posterior) ou `wont-fix` (entendido, sem alteração justificada).
- `affects.builds` lista IDs de versões de firmware; as placas vêm dos perfis que as fornecem. `owner.modules` identifica o arquivo FFS pelo nome de UI e GUID, e `owner.references` aponta funções ou offsets, opcionalmente por versão.
- `evidence` lista IDs `bme.evidence/1`. `description` descreve o defeito, `not_established` o que a análise não mostra e `remediation` a estratégia de correção ou o motivo de não haver uma.
- Um patch lista em `fixes` os achados que resolve (subconjunto de `findings`), e cada um deles lista o patch em `patches`. A validação confere os dois sentidos: um achado `fixed-by-patch` precisa de ao menos um patch, um patch não pode corrigir um achado desconhecido, e a confiança registrada no patch para um achado deve começar com a nota do achado.
- Uma placa lista em `findings` os achados que a envolvem. `bme scan` mostra os achados abertos da versão detectada após a tabela de patches.

As seis colunas do registro da auditoria (ID, Priority, Confidence, Board / owning code, Finding and status, Patch strategy / fix confidence) correspondem a `id`, `priority`, `confidence`, `affects.label` com `owner.description`, `description` com `not_established`, e `remediation`. `biosmod_core::register` renderiza os achados nessa tabela e a lê de volta sem perdas.

### Detectores

Um achado pode carregar `detectors` que localizam seu código em versões sem variante no catálogo. A variante de um patch casa exatamente uma versão; um detector descreve o código defeituoso com máscaras sobre endereços e deslocamentos, e um registro cobre toda versão que compila a mesma rotina. Um acerto nunca torna um patch aplicável: ele informa o defeito como `likely-present` no módulo que o contém, ao lado dos estados dos patches, e `bme scan` o mostra para qualquer imagem.

```json
{
  "id": "byte-counter-scan",
  "title": "8-bit index over a native-width configuration-table count",
  "anchor": {"in": "pe32"},
  "signatures": [
    {"label": "bl-rdx", "defect": {"bytes": "fec30fb6c3483bc272d9"}, "fixed": {"bytes": "48ffc39090483bda72d9"}}
  ],
  "expect": {"min_per_module": 1, "max_per_module": 1}
}
```

Esta é a forma do registro B09, reduzido a uma de suas quatro assinaturas. B09 omite `module_kind` porque suas cópias estão em drivers DXE e em módulos SMM.

- `anchor` escolhe os bytes pesquisados: `{"in": "pe32"}` para a imagem PE32 ou TE de cada módulo, com limite opcional por `module_kind` (`peim`, `dxe`, `smm`, pelo tipo de arquivo FFS) ou `ffs_guid`, e `{"in": "dsdt"}` para a tabela DSDT.
- Uma assinatura tem um padrão `defect` e, quando um patch do catálogo o produz, um padrão `fixed`. `wild` lista os índices de bytes que casam com qualquer valor. Derive ambos dos hunks dos patches em vez de copiar bytes do fabricante de outro lugar. Um padrão precisa de ao menos 4 bytes sem `wild`: menos que isso casa com código demais para indicar um defeito.
- `expect` limita os pontos de defeito por módulo (padrão: exatamente um). Um módulo fora dessa faixa fica `unexpected-count`, que pede revisão em vez de uma afirmação. Os pontos são listados até um acima do máximo; o módulo fica então marcado como `truncated` e a contagem real é maior.
- Os estados por módulo são `likely-present`, `unexpected-count` e `fixed-pattern` (só o formato corrigido ocorre, então o defeito não está no formato que o padrão cobre). O detector como um todo assume o estado mais urgente entre os módulos (`unexpected-count`, depois `likely-present`). Ele só é `fixed-pattern` quando todo módulo candidato foi lido, é `unsupported` quando um módulo que ele poderia cobrir está numa encapsulação que este motor não lê (o texto do scan acrescenta uma nota "N unreadable" a qualquer acerto) e `absent` quando nada casa. `absent` não prova a ausência do defeito em código que o padrão não cobre.

## Evidências

Um registro de evidência é uma observação: placa, versão do firmware, configuração, versões exatas dos patches, `image_sha256` gravado, o que foi observado e seus limites. Ele está associado somente a essas versões dos patches. Um registro nunca afirma que uma correção funciona em geral.

## Indexação

Nunca edite hashes manualmente:

```sh
bme catalog index path/to/catalog          # rewrite the files list
bme catalog index path/to/catalog --check  # CI: fail when stale
bme catalog validate path/to/catalog
```

`bme catalog import-x99fix ~/x99-bios-fixes/patches --map mr9a=mnx99mr9apro-230322 --map pr9=x99ha00m-20221202 --commit <sha> -o catalog/patches` converte registros de referência.
