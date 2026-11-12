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
fn ensure_writes_every_file_and_the_digest() {
    let data = tempfile::tempdir().unwrap();
    let root = ensure(data.path()).unwrap();
    assert_eq!(root, package_root(data.path()));
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
fn ensure_refreshes_the_package_when_the_digest_differs() {
    let data = tempfile::tempdir().unwrap();
    let root = ensure(data.path()).unwrap();
    let package = root.join("bme_replay");
    fs::write(package.join("trace.py"), "# stale").unwrap();
    fs::write(package.join(DIGEST_FILE), "0".repeat(64)).unwrap();
    ensure(data.path()).unwrap();
    assert_eq!(
        fs::read_to_string(package.join("trace.py")).unwrap(),
        FILES.iter().find(|(n, _)| *n == "trace.py").unwrap().1
    );
    assert_eq!(
        fs::read_to_string(package.join(DIGEST_FILE)).unwrap(),
        digest()
    );
    assert!(
        names_in(root.parent().unwrap())
            .iter()
            .all(|n| !n.starts_with(".")),
        "(replay dir): expected no staging or backup leftovers"
    );
}
