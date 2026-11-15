#!/usr/bin/env bash
# Profile-guided optimization training workload for `bme`.
#
# Usage: packaging/linux/pgo-train.sh <bme-binary> [rounds]
#
# Runs the commands the release `bme` spends its time in against the image and catalog from
# `bme dev synthetic`: no vendor ROM and no network. Run with an instrumented binary, each
# invocation leaves a raw profile for `llvm-profdata merge`. Run with any other binary it is a
# smoke test of the same commands. Every command must exit 0; the first one that does not stops
# the script and is reported with its exit status and stderr.
#
# `ifr` and `nvram` are left out: the synthetic image has no HII form package or variable store,
# so they exit with TARGET_NOT_FOUND and would only teach the profile an error path.
set -euo pipefail

default_rounds=40

if [[ $# -lt 1 || $# -gt 2 ]]; then
  printf 'pgo-train: expected <bme-binary> [rounds] | received %d arguments\n' "$#" >&2
  exit 2
fi
bme_binary=$1
rounds=${2:-$default_rounds}
if [[ ! -x $bme_binary || -d $bme_binary ]]; then
  printf 'pgo-train: expected an executable bme binary | received %q\n' "$bme_binary" >&2
  exit 2
fi
if [[ ! $rounds =~ ^[1-9][0-9]*$ ]]; then
  printf 'pgo-train: expected rounds to be a positive integer | received %q\n' "$rounds" >&2
  exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/bme-pgo-train.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
stderr_file="$work/stderr.txt"
round=setup

# Run `bme` with the given arguments, discarding stdout. A nonzero exit names the round, the
# command line and the first line of stderr.
run_bme() {
  local status=0
  "$bme_binary" "$@" > /dev/null 2> "$stderr_file" || status=$?
  if [[ $status -ne 0 ]]; then
    printf 'pgo-train: round %s: expected exit 0 | received exit %d from: bme %s\n' \
      "$round" "$status" "${*//$work/<work>}" >&2
    printf 'pgo-train: stderr: %s\n' "$(head -n 1 "$stderr_file" | sed "s#$work#<work>#g")" >&2
    exit 1
  fi
}

run_bme dev synthetic -o "$work/synthetic" -q
image=$work/synthetic/synthetic.bin
catalog=(--catalog "$work/synthetic/catalog" --allow-unsigned-local --offline -q)

for ((round = 1; round <= rounds; round++)); do
  patched=$work/patched.bin
  recipe=$work/recipe.json
  run_bme scan "$image" "${catalog[@]}"
  run_bme scan "$image" "${catalog[@]}" --json
  run_bme inspect "$image" --files --offline -q
  run_bme inspect "$image" --acpi --offline -q
  run_bme patch "$image" --recommended "${catalog[@]}" --dry-run
  run_bme patch "$image" --recommended "${catalog[@]}" -o "$patched"
  run_bme verify "$image" "$patched" --offline -q
  run_bme export "$image" --recommended "${catalog[@]}" -o "$recipe"
  run_bme patch "$image" --from "$recipe" --allow-unsigned-local --offline -q --dry-run
  run_bme version --offline -q
  # Publication refuses existing paths, so each round starts clean.
  rm -f "$patched" "$patched".* "$recipe"
done
printf 'pgo-train: %d rounds done\n' "$rounds"
