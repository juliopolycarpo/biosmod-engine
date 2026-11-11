# Workflow

English | [Brazilian Portuguese](../pt-BR/guide/workflow.md)

These commands never open a flash chip or modify the input image; chip access is separate (`bme guide flashing`).

```sh
bme scan dump.bin
bme patch dump.bin --recommended
bme verify dump.bin dump.patched.bin
```

## Scan and select

`scan` identifies the build from recorded module hashes and reports each patch state: `present`, `fixed`, `partial`, `likely-present`, `likely-fixed`, `not-detected`, `not-applicable` or `unsupported`. Only `present` records on a known build can be selected for a build. `fixed` means the fix is already present; `partial` means only some hunks are applied. `likely-*` means signatures matched on an unknown build and is a lead for porting. `not-detected` does not prove a defect is absent; `not-applicable` means the catalog excludes the build, and `unsupported` means the format cannot be decoded.

Choose application-unit IDs, such as `B01-B06` and `B02-B03`, rather than their individual finding IDs. IDs can be qualified as `official::B02-B03@1.0.0`. Alternatively, `--recommended` selects present, applicable corrections in the recommended tier that need no hardware assertions. The complete selection is validated together; prerequisites must be selected or already installed, and conflicts can prevent a build.

Some records require `--assert <fact>` for hardware confirmed on the physical board, `--allow-hold` for unknown hardware effects, or `--allow-diagnostic` for diagnostic patches. `bme catalog show` lists required facts.

## Build and preview

```sh
bme patch dump.bin B01-B06 B02-B03
bme patch dump.bin --recommended --dry-run
bme patch dump.bin B01-B06 B02-B03 -o fixed.bin
```

A bare `patch dump.bin` requires a selection. Positional IDs, `--recommended`, a saved recipe and the legacy `--select` option cannot be mixed. Without `-o`, the output is beside the input with `.patched` inserted before its final extension, or appended if there is no extension. The manifest is `<output>.manifest.json`; existing destinations are never overwritten.

`--dry-run` resolves, builds and verifies in memory without publishing files. With `-o`, JSON reports `proposed_output` instead of published output fields. A preview does not reserve a path or replace validation during a later build.

Before publication, the output is re-parsed, selected and preserved patches must read back as fixed, and bytes outside the allowlist must match the input. The CLI stages the image and manifest beside the destination and publishes without replacing existing files.

## Save and replay a selection

```sh
bme export dump.bin -o selection.json
bme export dump.bin B01-B06 B02-B03 -o explicit-selection.json
bme patch dump.bin --from selection.json
bme verify dump.bin dump.patched.bin --from selection.json
```

Export defaults to the current recommended selection and requires a new output file. It builds and validates in memory, then writes only the recipe. The `bme.plan/1` document captures concrete IDs, input digest, catalog pin, policy, component changes and expected output digest; it does not contain a self-contained catalog. Replay reloads the pinned catalog, reconstructs the operation and compares the document and output. It rejects selection, catalog, firmware and policy overrides; local unsigned catalogs may still require explicit `--allow-unsigned-local`.

Recipes and manifests include an engine build-input fingerprint. `patch --from` and `verify` reject a missing or different fingerprint with `PLAN_INVALID`; retain the matching engine to replay or verify older artifacts. `bme version --json` reports it as `data.build_fingerprint`. The fingerprint identifies recorded build inputs, not an executable signature or proof of identical binaries.

## Verify

`verify` checks input and output digests against the manifest, re-parses the output, checks allowed changes and patch states, and reconstructs the build from the pinned catalog when available. Required checks that cannot run produce `VERIFICATION_INCOMPLETE`. Offline verification does not establish that the image will boot.

## Compatibility

`bme plan dump.bin --select recommended -o plan.json`, `patch --select`, `patch --plan` and `verify --plan` remain supported. `--plan` is an alias for `--from`; old recipe and manifest fingerprints still require a matching engine build.
