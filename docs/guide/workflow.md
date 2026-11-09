# Workflow

`bme` works on a copy of your firmware. It never opens a flash chip, and every output is a new file.

```sh
bme scan dump.bin                                   # which build is this, which defects are present
bme plan dump.bin --select recommended -o plan.json # resolve and dry-build in memory
bme patch dump.bin --plan plan.json -o fixed.bin    # rebuild, verify, publish fixed.bin + manifest
bme verify dump.bin fixed.bin                       # independent check, any time later
```

## Scan

`scan` detects the firmware build by matching recorded module hashes. Each patch gets a state:

| State | Meaning |
|---|---|
| `present` | the defect is there and the module matches the recorded source exactly |
| `fixed` | the recorded fix is already applied |
| `partial` | some hunks are applied, others are not; nothing will be built on it |
| `likely-present` / `likely-fixed` | unknown build: every hunk signature matched exactly once |
| `not-detected` | the code differs or the module is missing; this does not prove the defect is absent |
| `not-applicable` | the record says this build does not have the defect |
| `unsupported` | the module is in a format bme cannot decode |

Only `present` records on a known build are plannable. `likely-*` results are leads for porting (`bme guide porting`).

## Select

`--select` takes ids (`B05`), qualified ids (`lab::B05@1.2.0`) or `recommended` (every plannable tier-1 correction). Some records need more:

- `--assert <fact>`: the record depends on hardware the firmware cannot prove, for example which Super I/O is fitted. Check the board, then assert the fact by its id (`bme catalog show` lists them).
- `--allow-hold`: records whose hardware effect is unknown.
- `--allow-diagnostic`: diagnostic patches such as the MRC breadcrumbs. They are not corrections.

Supersession and conflicts are resolved for you; `plan` lists every note.

## Plan and patch

`plan` writes a JSON plan with the input digest, the pinned catalog snapshot (manifest digest and every consumed file), the selection, facts, flags, every component change, the byte allowlist and the expected output digest.

`patch --plan` treats the plan as untrusted: it re-reads the input, reloads the pinned catalog offline, rebuilds from scratch and requires the same plan and output digest. Any drift is `PLAN_INPUT_CHANGED` or `OUTPUT_VERIFICATION_FAILED`, and nothing is written.

`patch --select` plans and builds in one step.

Before publishing, every output is re-parsed, every selected and carried patch must read back as fixed, and every byte outside the allowlist must equal the input. The image and `<output>.manifest.json` are staged next to the target and moved into place without replacing existing files.

## Verify

`verify` checks the input and output digests against the manifest, re-parses the output, compares bytes outside the allowlist, confirms patch states and reproduces the build from the pinned catalog when that catalog is still available. It reports skipped checks separately and never claims the image will boot.
