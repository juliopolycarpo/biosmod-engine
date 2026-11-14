//! Embed the official catalog listed in `catalog/catalog.json` into the binary and
//! record the git commit the build runs from.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One line of `git <arguments>` output run in `directory`; `None` when git is
/// missing, fails, or prints nothing.
fn git_line(directory: &Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!line.is_empty()).then_some(line)
}

/// The commit checked out in `workspace`, when `workspace` is the root of a git
/// work tree. A source tree unpacked inside some other repository is not a
/// checkout of the engine, so the top level must be `workspace` itself.
///
/// Also tells cargo to rerun this script when HEAD moves.
fn checkout_commit(workspace: &Path) -> Option<String> {
    let top_level = PathBuf::from(git_line(workspace, &["rev-parse", "--show-toplevel"])?);
    if top_level.canonicalize().ok()? != workspace.canonicalize().ok()? {
        return None;
    }
    // Rerun when the checked-out commit changes. `HEAD` changes on a branch switch,
    // the branch's own ref (loose or packed) on a commit, and the log on both; the
    // log alone is not enough because a repository can have reflogs turned off.
    let branch = git_line(workspace, &["symbolic-ref", "--quiet", "HEAD"]);
    let watched = ["HEAD", "logs/HEAD", "packed-refs"]
        .into_iter()
        .chain(branch.as_deref());
    for name in watched {
        // `--git-path` answers relative to the directory git ran in.
        let path = workspace.join(git_line(workspace, &["rev-parse", "--git-path", name])?);
        // Cargo reruns on every build for a registered path that does not exist.
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    let commit = git_line(workspace, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    (commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit())).then_some(commit)
}

fn main() {
    let workspace = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    // Empty outside a git checkout, e.g. a build from a source archive.
    println!(
        "cargo:rustc-env=BME_BUILD_COMMIT={}",
        checkout_commit(&workspace).unwrap_or_default()
    );
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../catalog");
    let manifest = root.join("catalog.json");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let mut out = String::from(
        "/// Official catalog files embedded at build time: (relative path, bytes).\npub static FILES: &[(&str, &[u8])] = &[\n",
    );
    if manifest.exists() {
        out += &format!(
            "    (\"catalog.json\", include_bytes!({:?})),\n",
            manifest.canonicalize().unwrap()
        );
        let text = fs::read_to_string(&manifest).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&text).expect("catalog/catalog.json is JSON");
        for entry in value["files"].as_array().expect("files array") {
            let path = entry["path"].as_str().expect("path string");
            assert!(
                !path.contains("..") && !path.starts_with('/'),
                "unsafe catalog path {path}"
            );
            let file = root.join(path);
            println!("cargo:rerun-if-changed={}", file.display());
            out += &format!(
                "    ({path:?}, include_bytes!({:?})),\n",
                file.canonicalize().unwrap()
            );
        }
    }
    out += "];\n";
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("embedded.rs"),
        out,
    )
    .unwrap();
}
