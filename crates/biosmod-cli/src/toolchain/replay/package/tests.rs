//! Embedded package tests: what is written, when it is rewritten, and that nothing is missing.

use super::*;

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("package directory is readable")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn every_python_file_of_the_package_is_embedded() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/replay/bme_replay");
    let on_disk: Vec<String> = names_in(&source)
        .into_iter()
        .filter(|n| n.ends_with(".py"))
        .collect();
    let mut embedded: Vec<String> = FILES.iter().map(|(n, _)| n.to_string()).collect();
    embedded.sort();
    assert_eq!(
        embedded, on_disk,
        "(tools/replay/bme_replay): expected every .py file in FILES | received a difference"
    );
}

#[test]
fn the_digest_is_hex_and_follows_the_content() {
    let first = digest();
    assert_eq!(first.len(), 64, "{first}");
    assert!(first.bytes().all(|b| b.is_ascii_hexdigit()), "{first}");
    assert_eq!(first, digest());
}

#[test]
fn ensure_writes_every_file_and_the_digest_into_a_digest_named_directory() {
    let data = tempfile::tempdir().unwrap();
    let root = ensure(data.path()).unwrap();
    assert_eq!(root, package_root(data.path()));
    assert_eq!(
        root.file_name().unwrap().to_string_lossy(),
        format!("package-{}", digest()),
        "(package directory): expected a name derived from the digest"
    );
    let package = root.join("bme_replay");
    let mut expected: Vec<String> = FILES.iter().map(|(n, _)| n.to_string()).collect();
    expected.push(DIGEST_FILE.into());
    expected.sort();
    assert_eq!(names_in(&package), expected);
    assert_eq!(
        fs::read_to_string(package.join(DIGEST_FILE)).unwrap(),
        digest()
    );
    assert_eq!(
        fs::read_to_string(package.join("trace.py")).unwrap(),
        FILES.iter().find(|(n, _)| *n == "trace.py").unwrap().1
    );
    assert!(
        names_in(root.parent().unwrap())
            .iter()
            .all(|n| !n.starts_with(".")),
        "(replay dir): expected no staging leftovers"
    );
}

#[test]
fn ensure_leaves_a_current_package_untouched() {
    let data = tempfile::tempdir().unwrap();
    let root = ensure(data.path()).unwrap();
    let marker = root.join("bme_replay").join("trace.py");
    fs::write(&marker, "# edited by hand").unwrap();
    ensure(data.path()).unwrap();
    assert_eq!(
        fs::read_to_string(&marker).unwrap(),
        "# edited by hand",
        "(trace.py): expected a matching digest to skip the rewrite | received a rewrite"
    );
}

#[test]
fn an_older_release_directory_is_left_alone_while_a_new_one_is_written() {
    let data = tempfile::tempdir().unwrap();
    let replay = data.path().join("replay");
    // `package` is where earlier releases kept the live copy, with a stale digest.
    for older in [
        replay.join("package"),
        replay.join(format!("package-{}", "0".repeat(64))),
    ] {
        fs::create_dir_all(older.join("bme_replay")).unwrap();
        fs::write(older.join("bme_replay/.digest"), "0".repeat(64)).unwrap();
        fs::write(older.join("bme_replay/trace.py"), "# running now").unwrap();
    }
    let root = ensure(data.path()).unwrap();
    assert_eq!(root, package_root(data.path()));
    for older in ["package".to_string(), format!("package-{}", "0".repeat(64))] {
        assert_eq!(
            fs::read_to_string(replay.join(&older).join("bme_replay/trace.py")).unwrap(),
            "# running now",
            "({older}): expected it untouched while another run may use it"
        );
    }
}

#[test]
fn concurrent_runs_share_one_package_and_never_replace_a_live_one() {
    let data = tempfile::tempdir().unwrap();
    // A run still uses the copy an earlier release left in `package`, whose digest is stale.
    let legacy = data.path().join("replay/package/bme_replay");
    fs::create_dir_all(&legacy).unwrap();
    fs::write(legacy.join(DIGEST_FILE), "0".repeat(64)).unwrap();
    let live = legacy.join("live.marker");
    fs::write(&live, "in use").unwrap();
    let fresh = tempfile::tempdir().unwrap();
    let roots: Vec<(PathBuf, PathBuf)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|at| {
                let data = if at % 2 == 0 {
                    data.path()
                } else {
                    fresh.path()
                };
                scope.spawn(move || (data.to_path_buf(), ensure(data).unwrap()))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (data, root) in &roots {
        assert_eq!(root, &package_root(data), "(returned root)");
        assert!(
            root.join("bme_replay").join(DIGEST_FILE).is_file(),
            "(package at {}): expected a complete directory",
            root.display()
        );
    }
    assert!(
        live.is_file(),
        "(live package): expected it never renamed or rewritten"
    );
    for dir in [data.path(), fresh.path()] {
        assert!(
            names_in(&dir.join("replay"))
                .iter()
                .all(|n| !n.starts_with(".")),
            "(replay dir {}): expected no staging leftovers",
            dir.display()
        );
    }
}

#[test]
fn a_package_directory_without_the_right_digest_is_an_error_naming_it() {
    let data = tempfile::tempdir().unwrap();
    let broken = package_root(data.path());
    fs::create_dir_all(broken.join("bme_replay")).unwrap();
    let error = ensure(data.path()).unwrap_err().to_string();
    assert!(
        error.contains(&broken.display().to_string()) && error.contains("digest"),
        "(broken package): expected an error naming {} and the digest | received {error}",
        broken.display()
    );
}
