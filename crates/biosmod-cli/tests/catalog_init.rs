//! `bme catalog init`: the scaffold it writes, what it refuses, and the `.gitignore` it ships.

mod common;

use common::{Sandbox, s};
use std::fs;
use std::path::Path;
use std::process::Command;

const DIRECTORIES: [&str; 7] = [
    "boards",
    "evidence",
    "findings",
    "notes",
    "patches",
    "provenance",
    "work",
];

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn fresh_scaffold_validates_and_its_index_is_current() {
    let sandbox = Sandbox::new();
    let repo = sandbox.path("repo");
    let init = sandbox.run(["catalog", "init", s(&repo), "--id", "acme-x99"]);
    assert_eq!(init.code, 0, "{}", init.stderr);

    let validate = sandbox.run(["catalog", "validate", s(&repo), "--json"]);
    assert_eq!(validate.code, 0, "{}", validate.stdout);
    let summary = &validate.json()["data"];
    assert_eq!(
        (summary["id"].as_str(), summary["version"].as_str()),
        (Some("acme-x99"), Some("0.1.0"))
    );
    assert_eq!(summary["files"], 0);

    let index = sandbox.run(["catalog", "index", s(&repo), "--check"]);
    assert_eq!(index.code, 0, "{}{}", index.stdout, index.stderr);
}

#[test]
fn scaffold_holds_the_documented_tree_and_nothing_else() {
    let sandbox = Sandbox::new();
    let repo = sandbox.path("repo");
    let init = sandbox.run(["catalog", "init", s(&repo), "--id", "acme-x99"]);
    assert_eq!(init.code, 0, "{}", init.stderr);

    let mut expected: Vec<String> = DIRECTORIES.iter().map(|d| d.to_string()).collect();
    expected
        .extend([".gitattributes", ".gitignore", "README.md", "catalog.json"].map(String::from));
    expected.sort();
    assert_eq!(names_in(&repo), expected, "(repository tree)");
    for directory in DIRECTORIES {
        assert!(
            names_in(&repo.join(directory)).is_empty(),
            "({directory}/): expected an empty directory"
        );
    }
    let readme = fs::read_to_string(repo.join("README.md")).unwrap();
    assert!(readme.starts_with("# acme-x99\n"), "{readme}");
    assert!(
        readme.contains("bme catalog add acme-x99 "),
        "(README): expected the id in the register command"
    );
    let manifest = fs::read_to_string(repo.join("catalog.json")).unwrap();
    assert_eq!(
        manifest,
        "{\n  \"schema\": \"bme.catalog/1\",\n  \"id\": \"acme-x99\",\n  \"version\": \"0.1.0\",\n  \"title\": \"acme-x99\",\n  \"engine\": \"^0.1\",\n  \"files\": []\n}\n"
    );
}

#[test]
fn json_reply_names_the_directory_catalog_files_and_directories() {
    let sandbox = Sandbox::new();
    let repo = sandbox.path("repo");
    let init = sandbox.run([
        "catalog",
        "init",
        s(&repo),
        "--id",
        "acme-x99",
        "--title",
        "Acme X99 family",
        "--json",
    ]);
    assert_eq!(init.code, 0, "{}", init.stderr);
    let doc = init.json();
    assert_eq!(doc["command"], "catalog init");
    assert_eq!(
        doc["data"],
        serde_json::json!({
            "directory": s(&repo),
            "id": "acme-x99",
            "title": "Acme X99 family",
            "version": "0.1.0",
            "files": ["README.md", ".gitignore", ".gitattributes", "catalog.json"],
            "directories": DIRECTORIES,
        })
    );
    let readme = fs::read_to_string(repo.join("README.md")).unwrap();
    assert!(readme.starts_with("# Acme X99 family\n"), "{readme}");
    let validate = sandbox.run(["catalog", "validate", s(&repo)]);
    assert!(
        validate.stdout.contains("valid: acme-x99 0.1.0"),
        "{}",
        validate.stdout
    );
}

#[test]
fn text_reply_says_what_git_tracks_and_that_git_was_not_run() {
    let sandbox = Sandbox::new();
    let repo = sandbox.path("repo");
    let init = sandbox.run(["catalog", "init", s(&repo), "--id", "acme-x99"]);
    assert_eq!(init.code, 0, "{}", init.stderr);
    for expected in [
        "Created device repository acme-x99 0.1.0",
        "work/ and any other top-level path stay local",
        "bme did not run git",
        "bme case init",
        "/work/dump.bin -o",
        "bme catalog index",
        "bme catalog validate",
    ] {
        assert!(
            init.stdout.contains(expected),
            "(text reply): expected {expected:?} | received:\n{}",
            init.stdout
        );
    }
    assert!(
        !repo.join(".git").exists(),
        "(repository): expected no .git directory, bme must not run git"
    );
}

#[test]
fn refuses_an_existing_directory_and_changes_nothing_in_it() {
    let sandbox = Sandbox::new();
    let repo = sandbox.path("repo");
    fs::create_dir(&repo).unwrap();
    fs::write(repo.join("notes.txt"), b"mine").unwrap();
    let run = sandbox.run(["catalog", "init", s(&repo), "--id", "acme-x99", "--json"]);
    assert_eq!((run.code, run.error_code().as_str()), (1, "OUTPUT_EXISTS"));
    assert!(
        run.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("already exists"),
        "{}",
        run.stdout
    );
    assert_eq!(names_in(&repo), ["notes.txt"], "(existing directory)");
    assert_eq!(fs::read(repo.join("notes.txt")).unwrap(), b"mine");
}

#[test]
fn refuses_the_reserved_official_id_and_creates_nothing() {
    let sandbox = Sandbox::new();
    let repo = sandbox.path("repo");
    let run = sandbox.run(["catalog", "init", s(&repo), "--id", "official", "--json"]);
    assert_eq!(
        (run.code, run.error_code().as_str()),
        (1, "CATALOG_INVALID")
    );
    assert_eq!(
        run.json()["error"]["message"],
        "catalog id: expected an id other than the reserved \"official\" | received: official"
    );
    assert!(!repo.exists(), "(repository): expected nothing created");
}

#[test]
fn refuses_invalid_ids_and_titles_and_creates_nothing() {
    let sandbox = Sandbox::new();
    let repo = sandbox.path("repo");
    let long_id = "a".repeat(65);
    for id in ["bad id", "-dash", "../escape", long_id.as_str()] {
        // `--id=VALUE` keeps a leading dash from reading as a flag.
        let run = sandbox.run(["catalog", "init", s(&repo), &format!("--id={id}"), "--json"]);
        assert_eq!(
            (run.code, run.error_code().as_str()),
            (1, "CATALOG_INVALID"),
            "(id {id:?})"
        );
        let message = run.json()["error"]["message"].as_str().unwrap().to_string();
        assert!(
            message.contains(&format!("{id:?}"))
                && message
                    .contains("expected 1-64 characters [A-Za-z0-9._-] starting alphanumeric"),
            "(id {id:?}): expected the value and the identifier rule | received: {message}"
        );
        assert!(!repo.exists(), "(id {id:?}): expected nothing created");
    }
    let run = sandbox.run([
        "catalog",
        "init",
        s(&repo),
        "--id",
        "acme-x99",
        "--title",
        "two\nlines",
        "--json",
    ]);
    assert_eq!(
        (run.code, run.error_code().as_str()),
        (1, "CATALOG_INVALID")
    );
    assert!(!repo.exists(), "(title): expected nothing created");
}

#[test]
fn requires_the_id_flag() {
    let sandbox = Sandbox::new();
    let run = sandbox.run(["catalog", "init", s(&sandbox.path("repo")), "--json"]);
    assert_eq!((run.code, run.error_code().as_str()), (2, "USAGE"));
}

#[test]
fn capabilities_list_catalog_init_as_a_writer_with_no_network() {
    let sandbox = Sandbox::new();
    let capabilities = sandbox.run(["capabilities", "--json"]).json();
    let commands = capabilities["data"]["commands"].as_array().unwrap();
    let init = commands
        .iter()
        .find(|command| command["name"] == "catalog init")
        .unwrap_or_else(|| panic!("(capabilities): expected catalog init | received {commands:?}"));
    assert_eq!(init["network"], false);
    assert_eq!(
        init["writes"],
        serde_json::json!(["device repository directory"])
    );
}

/// Run `git` with the user's and the system's configuration ignored, and `HOME` and
/// `XDG_CONFIG_HOME` moved into `home`, so no global excludes file reaches the verdicts
/// and they come from the scaffolded files alone.
fn git(repo: &Path, home: &Path, args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        // An empty file, not `/dev/null`, so the isolation also holds on Windows.
        .env("GIT_CONFIG_GLOBAL", home.join("empty-gitconfig"))
        .env("GIT_CONFIG_SYSTEM", home.join("empty-gitconfig"))
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .output()
}

/// Paths the scaffold's `.gitignore` must keep out of git.
const IGNORED: [&str; 9] = [
    "work/dump.bin",
    "dump.bin",
    "stray-notes.txt",
    "notes/Module.pe",
    "provenance/DSDT.aml",
    "notes/capture.log",
    "notes/board.pdf",
    "minisign.key",
    "notes/x.dump/body.bin",
];

/// Paths it must leave visible to git.
const TRACKED: [&str; 13] = [
    "catalog.json",
    "catalog.json.minisig",
    "boards/a.json",
    "patches/B01.json",
    "findings/B01.json",
    "evidence/e.json",
    "provenance/fix.asm",
    "notes/s3.md",
    "README.md",
    ".gitignore",
    ".gitattributes",
    ".github/workflows/validate.yml",
    "LICENSE",
];

#[test]
fn gitignore_keeps_firmware_and_identifiers_out_and_the_catalog_in() {
    let sandbox = Sandbox::new();
    let repo = sandbox.path("repo");
    let home = sandbox.path("git-home");
    fs::create_dir(&home).unwrap();
    fs::write(home.join("empty-gitconfig"), b"").unwrap();
    let init = sandbox.run(["catalog", "init", s(&repo), "--id", "acme-x99"]);
    assert_eq!(init.code, 0, "{}", init.stderr);

    // The command under test never runs git; the test makes the directory a repository
    // so `git check-ignore` has one to read.
    match git(&repo, &home, &["init", "--quiet"]) {
        Ok(output) if output.status.success() => {}
        Ok(output) => panic!(
            "(git init): expected success | received {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ),
        // A missing git must fail: a silent skip would let a broken template pass.
        Err(error) => panic!("(git): expected git on PATH | received: {error}"),
    }
    for path in IGNORED.iter().chain(&TRACKED) {
        let file = repo.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        if !file.exists() {
            fs::write(&file, b"x").unwrap();
        }
    }
    let mut wrong = Vec::new();
    for (paths, want_ignored) in [(&IGNORED[..], true), (&TRACKED[..], false)] {
        for path in paths {
            let output = git(
                &repo,
                &home,
                &["check-ignore", "--no-index", "-q", "--", path],
            )
            .unwrap();
            let ignored = match output.status.code() {
                Some(0) => true,
                Some(1) => false,
                _ => panic!(
                    "(git check-ignore {path}): expected exit 0 or 1 | received {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ),
            };
            if ignored != want_ignored {
                wrong.push(format!(
                    "{path}: expected {} | received {}",
                    if want_ignored { "ignored" } else { "tracked" },
                    if ignored { "ignored" } else { "tracked" },
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "(.gitignore): {wrong:#?}");
}
