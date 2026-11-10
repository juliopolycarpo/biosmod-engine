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
tar -C "$staging" -czf "dist/$package.tar.gz" "$package"
printf 'Created %s\n' "dist/$package.tar.gz"
