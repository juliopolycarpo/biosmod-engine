#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  printf 'expected Linux x86_64 | received %s %s\n' "$(uname -s)" "$(uname -m)" >&2
  exit 1
fi

target=x86_64-unknown-linux-gnu
cargo build --locked --release --target "$target" -p biosmod-cli -p biosmod-gui
staging=$(mktemp -d "${TMPDIR:-/tmp}/bme-package.XXXXXXXX")
trap 'rm -rf "$staging"' EXIT
metadata_file="$staging/cargo-metadata.json"
cargo metadata --locked --format-version 1 --filter-platform "$target" > "$metadata_file"
version=$(python3 -c 'import json,sys; print(next(p["version"] for p in json.load(open(sys.argv[1]))["packages"] if p["name"] == "biosmod-gui"))' "$metadata_file")
package="biosmod-engine-${version}-linux-x86_64"
root="$staging/$package"
mkdir -p "$root/bin" "$root/share/applications" "$root/share/icons/hicolor/scalable/apps" "$root/share/licenses/biosmod-engine"
target_dir=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["target_directory"])' "$metadata_file")
install -m 755 "$target_dir/$target/release/bme" "$target_dir/$target/release/bme-gui" "$root/bin/"
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
