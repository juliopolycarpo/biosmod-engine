use super::*;
use crate::testkit::{FakeTransport, Signer25519, temp_paths};
use biosmod_core::synthetic::Fixture;

const URL: &str = "https://catalogs.example/lab/catalog.json";

/// Publish the synthetic catalog (optionally with a different version) on the fake transport.
fn serve(transport: &FakeTransport, signer: &Signer25519, version: &str, tweak: &str) -> Vec<u8> {
    let mut files = Fixture::new(0x07).catalog_files();
    let manifest_at = files.iter().position(|(p, _)| p == "catalog.json").unwrap();
    let mut manifest: serde_json::Value = serde_json::from_slice(&files[manifest_at].1).unwrap();
    manifest["id"] = "lab".into();
    manifest["version"] = version.into();
    manifest["title"] = format!("lab catalog {tweak}").into();
    files[manifest_at].1 = serde_json::to_vec_pretty(&manifest).unwrap();
    for (path, bytes) in &files {
        transport.put(&format!("https://catalogs.example/lab/{path}"), bytes);
    }
    let bytes = files[manifest_at].1.clone();
    transport.put(&format!("{URL}.minisig"), &signer.sign(&bytes));
    bytes
}

fn registered(paths: &Paths, signer: &Signer25519) -> Config {
    let mut config = Config::default();
    add(&mut config, "lab", URL, Some(&signer.public()), false).unwrap();
    config.save(paths).unwrap();
    config
}

#[test]
fn signed_update_activates_a_snapshot_that_loads_offline() {
    let (_dir, paths) = temp_paths();
    let signer = Signer25519::new(7);
    let transport = FakeTransport::default();
    serve(&transport, &signer, "1.0.0", "a");
    let config = registered(&paths, &signer);
    assert_eq!(
        load("lab", &config, &paths, LoadPolicy::default())
            .unwrap_err()
            .code,
        Code::SourceUnavailable
    );
    let updated = update("lab", &config, &paths, &transport).unwrap();
    assert!(updated.changed);
    let loaded = load("lab", &config, &paths, LoadPolicy::default()).unwrap();
    assert_eq!(
        (loaded.trust, loaded.catalog.manifest.id.as_str()),
        (Trust::Signed, "lab")
    );
    assert!(
        !update("lab", &config, &paths, &transport).unwrap().changed,
        "same digest is a no-op"
    );
}

#[test]
fn bad_signature_changed_file_and_interruption_keep_the_previous_snapshot() {
    let (_dir, paths) = temp_paths();
    let signer = Signer25519::new(7);
    let transport = FakeTransport::default();
    serve(&transport, &signer, "1.0.0", "a");
    let config = registered(&paths, &signer);
    let first = update("lab", &config, &paths, &transport)
        .unwrap()
        .manifest_sha256;

    // Signed by another key.
    let manifest = serve(&transport, &signer, "1.1.0", "b");
    transport.put(
        &format!("{URL}.minisig"),
        &Signer25519::new(9).sign(&manifest),
    );
    assert_eq!(
        update("lab", &config, &paths, &transport).unwrap_err().code,
        Code::SourceUpdateRejected
    );

    // Correct signature, but a file differs from the signed index.
    serve(&transport, &signer, "1.1.0", "b");
    transport.put("https://catalogs.example/lab/patches/PA.json", b"{}");
    let error = update("lab", &config, &paths, &transport).unwrap_err();
    assert_eq!(error.code, Code::SourceUpdateRejected, "{error}");

    // Connection drops part-way.
    serve(&transport, &signer, "1.1.0", "b");
    transport.requests.borrow_mut().clear();
    *transport.fail_after.borrow_mut() = Some(4);
    assert_eq!(
        update("lab", &config, &paths, &transport).unwrap_err().code,
        Code::SourceUnavailable
    );
    *transport.fail_after.borrow_mut() = None;

    let state = Store::new(&paths, "lab").state().unwrap().unwrap();
    assert_eq!(state.current, first, "previous snapshot stays active");
    assert!(load("lab", &config, &paths, LoadPolicy::default()).is_ok());
    // A later good update succeeds and removes interrupted staging directories.
    assert!(update("lab", &config, &paths, &transport).unwrap().changed);
    let leftovers = fs::read_dir(paths.cache.join("sources/lab/snapshots"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".staging-"))
        .count();
    assert_eq!(leftovers, 0);
}

#[test]
fn rollback_and_same_version_replacement_are_refused() {
    let (_dir, paths) = temp_paths();
    let signer = Signer25519::new(7);
    let transport = FakeTransport::default();
    let config = registered(&paths, &signer);
    serve(&transport, &signer, "1.2.0", "a");
    update("lab", &config, &paths, &transport).unwrap();
    serve(&transport, &signer, "1.1.0", "old");
    assert!(
        update("lab", &config, &paths, &transport)
            .unwrap_err()
            .message
            .contains("rollback")
    );
    serve(&transport, &signer, "1.2.0", "different");
    assert!(
        update("lab", &config, &paths, &transport)
            .unwrap_err()
            .message
            .contains("different content")
    );
}

#[test]
fn registration_rules() {
    let (_dir, paths) = temp_paths();
    let mut config = Config::default();
    assert_eq!(
        add(
            &mut config,
            "official",
            URL,
            Some(&Signer25519::new(1).public()),
            false
        )
        .unwrap_err()
        .code,
        Code::Usage
    );
    assert_eq!(
        add(
            &mut config,
            "lab",
            "http://insecure.example/c.json",
            Some(&Signer25519::new(1).public()),
            false
        )
        .unwrap_err()
        .code,
        Code::SourceUntrusted
    );
    assert_eq!(
        add(&mut config, "lab", URL, None, false).unwrap_err().code,
        Code::SourceUntrusted
    );
    let catalog_dir = tempfile::tempdir().unwrap();
    for (path, bytes) in Fixture::new(0x07).catalog_files() {
        let target = catalog_dir.path().join(&path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
    let dir = catalog_dir.path().to_str().unwrap();
    assert_eq!(
        add(&mut config, "dev", dir, None, false).unwrap_err().code,
        Code::SourceUntrusted
    );
    add(&mut config, "dev", dir, None, true).unwrap();
    assert_eq!(
        load("dev", &config, &paths, LoadPolicy::default())
            .unwrap()
            .trust,
        Trust::UnsignedLocal
    );
    // Direct paths require explicit policy; board files resolve their indexed closure.
    let board = catalog_dir.path().join("boards/synthetic-board.json");
    let board = board.to_str().unwrap();
    assert_eq!(
        load(board, &config, &paths, LoadPolicy::default())
            .unwrap_err()
            .code,
        Code::SourceUntrusted
    );
    let loaded = load(
        board,
        &config,
        &paths,
        LoadPolicy {
            allow_unsigned_local: true,
        },
    )
    .unwrap();
    assert!(matches!(loaded.catalog.scope, Scope::Board(_)));
    assert_eq!(loaded.catalog.boards.len(), 1);
}

#[test]
fn dir_source_refuses_symlink_escapes() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.json"), b"{}").unwrap();
    fs::create_dir(dir.path().join("patches")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        outside.path().join("secret.json"),
        dir.path().join("patches/X.json"),
    )
    .unwrap();
    let source = DirSource::new(dir.path()).unwrap();
    #[cfg(unix)]
    assert!(
        source
            .read("patches/X.json", 100)
            .unwrap_err()
            .message
            .contains("outside")
    );
    assert!(source.read("../x.json", 100).is_err());
}

#[test]
fn signed_loads_use_the_verified_manifest_bytes() {
    let catalog_dir = tempfile::tempdir().unwrap();
    for (path, bytes) in Fixture::new(0x07).catalog_files() {
        let target = catalog_dir.path().join(&path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
    let dir = DirSource::new(catalog_dir.path()).unwrap();
    let verified = dir.read("catalog.json", MAX_MANIFEST_BYTES).unwrap();
    // The directory changes after verification; the load must not follow it.
    let mut swapped: serde_json::Value = serde_json::from_slice(&verified).unwrap();
    swapped["title"] = "swapped".into();
    fs::write(
        catalog_dir.path().join("catalog.json"),
        serde_json::to_vec(&swapped).unwrap(),
    )
    .unwrap();
    let catalog = Catalog::load(&Verified::new(&dir, verified.clone()), Scope::All).unwrap();
    assert_eq!(catalog.manifest_sha256, Digest256::of(&verified));
    assert_eq!(catalog.manifest.title, "Synthetic test catalog");
}

#[test]
fn local_is_a_reserved_alias() {
    let mut config = Config::default();
    let error = add(&mut config, "local", "/tmp", None, true).unwrap_err();
    assert!(error.message.contains("reserved"), "{error}");
}
