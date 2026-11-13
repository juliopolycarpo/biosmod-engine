# The JSON protocol

English | [Brazilian Portuguese](../pt-BR/guide/agents.md)

Pass `--json` to any command. stdout then carries exactly one JSON document, for successes and failures alike; progress notes go to stderr (`--quiet` silences them). `bme` never prompts.

```json
{"protocol": "bme/1", "product": "biosmod-engine", "version": "0.1.0", "command": "scan", "ok": true, "data": { ... }}
{"protocol": "bme/1", "product": "biosmod-engine", "version": "0.1.0", "command": "patch", "ok": false,
 "error": {"code": "PLAN_INPUT_CHANGED", "message": "...", "details": { ... }}}
```

`bme schema envelope` prints the envelope schema; `bme schema plan` and `bme schema manifest` describe the documents inside `data`.

Exit codes: `0` success, `1` controlled failure (see `error.code`), `2` usage error, `3` publication incomplete (an output file may exist without its partner; `error.details` names what remains).

`verify` returns exit `1` and `VERIFICATION_INCOMPLETE` when required catalog checks cannot run. Its `error.details` contains the verification report (`complete: false`, `checks`, `skipped`, and `notice`). Older engines may return this report under `data` with exit `0`; clients must always inspect completeness and the required checks before reporting verification success.

`capabilities.data.desktop_workflow: 1` identifies the guarded desktop workflow: conservative firmware-layout refusals and explicit incomplete verification. The GUI also requires `direct_patch_workflow: 1`; matching protocol and package versions alone are insufficient. JSON `inspect.path`, `patch.output`, and `patch.manifest_file` are display strings; Unix paths containing non-UTF-8 bytes use replacement characters. Keep the original OS paths when invoking later operations instead of reconstructing paths from these strings.

`bme capabilities --json` lists commands, whether each writes files or uses the network, supported formats, limits and every error code with its meaning. Its `verification_required_checks` array names the checks that must each pass exactly once for a complete verification report. The `exit_codes` and `error_codes` fields define process statuses and their error-code mappings. Desktop clients bind these values to a validated connection and reject incomplete or contradictory reports.

## Agent workflow

1. Run `bme scan dump.bin --json` and inspect `data.sources[].report.patches[]`, including `state`, `plannable`, `blocked` and `requires_facts`.
2. Ask the user to confirm hardware facts; never assert them on the user's behalf. Follow the caller's authorization policy for building a copy.
3. Select concrete application-unit IDs or use `--recommended`. Optionally run `bme patch dump.bin <ids> --dry-run --json` to inspect `data.plan.components`, `notes` and `changed`, or `bme export dump.bin <ids> -o selection.json --json` to save a recipe.
4. Run `bme patch dump.bin <ids> -o out.bin --json` and `bme verify dump.bin out.bin --json`. Report `complete`, `checks` and `skipped` as returned. Offline verification does not mean the image boots.

Clients binding a build to a displayed scan can pass `--expect-input-sha256` and `--expect-source-sha256` from the scan input and selected source's `snapshot_sha256`. A mismatch fails with `PLAN_INPUT_CHANGED`; scan again before choosing a selection. The source digest identifies a validated snapshot, not a signature. Dry-run and export accept the same guards. Replay via `--from` uses the recipe pins and rejects guard overrides.

Never write a chip from an agent. Flashing is the user's decision and needs a programmer recovery path.

## Investigation workflow

For an unknown build, a suspected defect or a claim about the running machine, work in a case and let each command leave a digest behind. This is a separate path from patching: nothing here writes an image or a chip.

1. **Open a case.** `bme case init dump.bin -o work/case --json` scans the dump, drafts a board and lists the detector hits as findings (`bme guide cases`).
2. **Read the image.** Run each reader through the case with `bme case record work/case -- <command>`, so its output is stored without local paths and hashed:
   - `ifr dump.bin` decodes the Setup forms: question offsets, options, defaults and conditions (`bme guide ifr`).
   - `nvram dump.bin --field "ACPI Sleep State"` lists the stored variables and compares a Setup question's saved value with its default (`bme guide nvram`).
   - `inspect dump.bin --acpi` lists the ACPI tables the image stores.
3. **Compare.** `compare reference.bin dump.bin` pairs modules, `compare --functions A.json B.json` pairs the functions of two `tools analyze` exports and `compare --acpi A B` pairs ACPI tables by method. For `--acpi`, either side may be a `bme diag acpi capture` directory, which sets what the running machine published against what the image stores (`bme guide porting`).
4. **Observe the machine.** `diag` commands read ACPI tables, the fan controller, SMBIOS and suspend stages from the host (`bme guide diagnostics`). They need root and some touch hardware, so ask the user before running one, and never run `diag suspend` on their behalf. A recorded `diag` command that fails keeps its failure as an artifact.
5. **Close the loop.** `bme case status work/case --input dump.bin` reports `changed`, `missing` or `unlisted` artifacts as `CASE_DRIFT`; `bme case export` turns the case into a catalog directory of draft board, findings and evidence that `bme catalog validate` accepts.

Report what each artifact shows and cite its id (`002-ifr`). A finding stays `open` until a person reviews it: offline evidence does not show that a board boots.
