# The JSON protocol

Pass `--json` to any command. stdout then carries exactly one JSON document, for successes and failures alike; progress notes go to stderr (`--quiet` silences them). `bme` never prompts.

```json
{"protocol": "bme/1", "product": "biosmod-engine", "version": "0.1.0", "command": "scan", "ok": true, "data": { ... }}
{"protocol": "bme/1", "product": "biosmod-engine", "version": "0.1.0", "command": "patch", "ok": false,
 "error": {"code": "PLAN_INPUT_CHANGED", "message": "...", "details": { ... }}}
```

`bme schema envelope` prints the envelope schema; `bme schema plan` and `bme schema manifest` describe the documents inside `data`.

Exit codes: `0` success, `1` controlled failure (see `error.code`), `2` usage error, `3` publication incomplete (an output file may exist without its partner; `error.details` names what remains).

`bme capabilities --json` lists commands, whether each writes files or uses the network, supported formats, limits and every error code with its meaning.

## A safe agent loop

1. `bme scan dump.bin --json` and read `data.sources[].report.patches[]`: `state`, `plannable`, `blocked`, `requires_facts`.
2. Ask the user to confirm any hardware fact; never assert one on their behalf.
3. `bme plan dump.bin --select <ids> -o plan.json --json`; show the user `data.plan.components`, `notes` and `changed`.
4. `bme patch dump.bin --plan plan.json -o out.bin --json` only after the user approves that plan.
5. `bme verify dump.bin out.bin --json`. Report `complete`, `checks` and `skipped` as they are. Offline verification does not mean the image boots.

Never write a chip from an agent. Flashing is the user's decision and needs a programmer recovery path.
