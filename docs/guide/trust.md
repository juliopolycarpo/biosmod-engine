# Sources and trust

English | [Brazilian Portuguese](../pt-BR/guide/trust.md)

`bme` reads patch data from catalog sources:

| Source | Trust | How it is read |
|---|---|---|
| `official` | compiled into the binary | always available, offline |
| registered local directory | minisign key, or explicit `--allow-unsigned-local` at registration | read in place, every file hash-checked |
| registered HTTPS catalog | minisign key, required | only through a validated local snapshot |
| direct path (`--catalog ./dir`) | none | refused unless `--allow-unsigned-local` is passed |

```sh
bme catalog add lab https://example.org/catalog/catalog.json --trust-key lab.pub
bme catalog update lab
bme scan dump.bin --catalog lab
```

The key is configured locally. Keys inside a catalog are never trusted.

## Updates

Only `catalog update` and `tools setup ghidra` use the network. `tools setup ghidra` checks every archive against a pinned SHA-256 digest (see [the analysis toolchain](ghidra.md)). `catalog update` downloads `catalog.json` and `catalog.json.minisig`, verifies the signature over the exact bytes, then downloads every indexed file and checks its length and hash. The new snapshot is fully validated in a staging directory and then activated in one rename. On any failure the previous snapshot stays active.

Updates are refused when the catalog id changes, when the version is older than one already accepted (rollback), or when an accepted version reappears with different content. HTTPS only; redirects only within the same origin; bodies are size-limited.

## Mixing sources

`--catalog` can repeat. One selection uses one source; selecting patches from two sources is refused. An unqualified id defined by two loaded sources is `TARGET_AMBIGUOUS`; qualify it as `ALIAS::ID`. The alias `official` is reserved.

## Recipes

An exported recipe pins the source alias, trust, manifest digest and every consumed file. `patch --from` reloads that source offline and refuses if anything differs. The recipe does not contain the catalog or grant permission to use an unsigned local source. Editing it cannot bypass validation.
