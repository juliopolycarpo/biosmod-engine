# Catálogos

[English](../../guide/catalogs.md) | Português (Brasil)

Um catálogo é um diretório com estrutura fixa:

```
catalog.json            index: id, version, engine requirement, every file's path, kind, length and sha256
boards/<id>.json        board and revision profile (bme.board/1)
patches/<id>.json       one patch record (bme.patch/1)
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
