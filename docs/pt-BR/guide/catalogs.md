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
