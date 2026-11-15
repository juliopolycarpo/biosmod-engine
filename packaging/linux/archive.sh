#!/usr/bin/env bash
set -euo pipefail

# Usage: packaging/linux/archive.sh [--pgo]
#
# --pgo builds the shipped `bme` with profile-guided optimization. It needs the toolchain's
# `llvm-tools` component (`rustup component add llvm-tools`) and adds about 3.5 minutes: an
# instrumented build, the workload in pgo-train.sh, then the profile-use build. `bme-gui`
# always comes from the plain build.
pgo=0
for argument in "$@"; do
  case $argument in
    --pgo) pgo=1 ;;
    *)
      printf 'archive.sh: expected [--pgo] | received %q\n' "$argument" >&2
      exit 2
      ;;
  esac
done

# Physical path: build.rs canonicalizes the workspace root before it replaces it in RUSTFLAGS.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$repo_root"

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  printf 'expected Linux x86_64 | received %s %s\n' "$(uname -s)" "$(uname -m)" >&2
  exit 1
fi

target=x86_64-unknown-linux-gnu
staging=$(mktemp -d "${TMPDIR:-/tmp}/bme-package.XXXXXXXX")
trap 'rm -rf "$staging"' EXIT

# The PGO build keeps its own target directories under $staging, outside the cached target
# directory, and a fresh one every run: Cargo does not track the profile file's contents, so a
# reused directory would keep a binary built from an older profile.
pgo_bme=
if ((pgo)); then
  host=$(rustc -vV | sed -n 's/^host: //p')
  profdata_tool="$(rustc --print sysroot)/lib/rustlib/$host/bin/llvm-profdata"
  if [[ ! -x $profdata_tool ]]; then
    printf 'archive.sh: expected llvm-profdata at %s | received no such file; run: rustup component add llvm-tools\n' \
      "$profdata_tool" >&2
    exit 1
  fi
  raw_profiles="$staging/pgo/raw"
  # `build.rs` hashes RUSTFLAGS into the build fingerprint that `verify` and `patch --from`
  # compare, after replacing the checkout root with `<workspace>`. The profile therefore lives
  # at a path below the root, so every checkout hashes the same flag string. The raw-profile
  # directory of the instrumented build is never part of the shipped binary's flags.
  profile="$repo_root/target/pgo/bme.profdata"
  mkdir -p "$raw_profiles" "$(dirname "$profile")"
  rm -f "$profile"
  RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Cprofile-generate=$raw_profiles" \
    CARGO_TARGET_DIR="$staging/pgo/target-generate" \
    cargo build --locked --release --target "$target" -p biosmod-cli
  packaging/linux/pgo-train.sh "$staging/pgo/target-generate/$target/release/bme"
  shopt -s nullglob
  raw_files=("$raw_profiles"/*.profraw)
  shopt -u nullglob
  if ((${#raw_files[@]} == 0)); then
    printf 'archive.sh: expected *.profraw files in %s | received none\n' "$raw_profiles" >&2
    exit 1
  fi
  "$profdata_tool" merge -o "$profile" "${raw_files[@]}"
  RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Cprofile-use=$profile" \
    CARGO_TARGET_DIR="$staging/pgo/target-use" \
    cargo build --locked --release --target "$target" -p biosmod-cli
  pgo_bme="$staging/pgo/target-use/$target/release/bme"
  # Only the profile-use build reads the profile; do not leave it in the cached target directory.
  rm -rf "$repo_root/target/pgo"
  cargo build --locked --release --target "$target" -p biosmod-gui
else
  cargo build --locked --release --target "$target" -p biosmod-cli -p biosmod-gui
fi
metadata_file="$staging/cargo-metadata.json"
cargo metadata --locked --format-version 1 --filter-platform "$target" > "$metadata_file"
version=$(python3 -c 'import json,sys; print(next(p["version"] for p in json.load(open(sys.argv[1]))["packages"] if p["name"] == "biosmod-gui"))' "$metadata_file")
package="biosmod-engine-${version}-linux-x86_64"
root="$staging/$package"
mkdir -p "$root/bin" "$root/share/applications" "$root/share/icons/hicolor/scalable/apps" "$root/share/licenses/biosmod-engine"
target_dir=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["target_directory"])' "$metadata_file")
install -m 755 "${pgo_bme:-$target_dir/$target/release/bme}" "$target_dir/$target/release/bme-gui" "$root/bin/"
install -m 644 packaging/linux/dev.polycarpo.biosmod-engine.desktop "$root/share/applications/"
install -m 644 packaging/linux/dev.polycarpo.biosmod-engine.svg "$root/share/icons/hicolor/scalable/apps/"
install -m 644 LICENSE packaging/linux/licenses/* "$root/share/licenses/biosmod-engine/"
python3 packaging/linux/collect-notices.py "$root/share/licenses/biosmod-engine/third-party" "$metadata_file"
install -m 644 README.md README.pt-BR.md CONTRIBUTING.md CONTRIBUTING.pt-BR.md LICENSE "$root/"
cp -R docs "$root/docs"
# Documentation license/provenance links retain their repository-relative paths.
mkdir -p "$root/packaging/linux" "$root/tools/ghidra"
cp -R packaging/linux/licenses "$root/packaging/linux/licenses"
install -m 644 tools/ghidra/NOTICE tools/ghidra/LICENSE-Apache-2.0.txt "$root/tools/ghidra/"
mkdir -p dist
# xz -9e: the 0.1.0 archive is 9,437,296 bytes against 13,844,306 for gzip and 10,479,802 for
# zstd -19, for about 17 s more compression time. Extraction needs about 65 MiB of memory.
tar -C "$staging" -cf - "$package" | xz -9e -T1 > "dist/$package.tar.xz"
printf 'Created %s\n' "dist/$package.tar.xz"
