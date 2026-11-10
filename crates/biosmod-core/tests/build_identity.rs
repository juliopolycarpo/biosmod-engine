//! Build identity input collection and framing tests.

#[path = "../build_identity.rs"]
mod build_identity;

use std::collections::BTreeMap;
use std::fs;

#[test]
fn fingerprints_ignore_checkout_root_and_detect_input_and_setting_changes() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    for root in [first.path(), second.path()] {
        fs::create_dir_all(root.join("src/nested")).unwrap();
        fs::write(root.join("src/nested/b.rs"), b"b").unwrap();
        fs::write(root.join("src/a.rs"), b"a").unwrap();
    }
    let inputs = ["src"];
    let mut settings = BTreeMap::from([("target".to_string(), "x86_64-test".to_string())]);
    let digest = |root: &std::path::Path, settings: &BTreeMap<String, String>| {
        let entries = build_identity::collect_inputs(root, &inputs).unwrap();
        build_identity::fingerprint(root, &entries, settings).unwrap()
    };
    let baseline = digest(first.path(), &settings);
    assert_eq!(baseline.len(), 64);
    assert_eq!(
        baseline,
        digest(second.path(), &settings),
        "identical trees at different roots"
    );
    fs::write(second.path().join("src/a.rs"), b"changed").unwrap();
    assert_ne!(baseline, digest(second.path(), &settings), "source edit");
    fs::write(second.path().join("src/a.rs"), b"a").unwrap();
    fs::write(second.path().join("src/new.rs"), b"new").unwrap();
    assert_ne!(
        baseline,
        digest(second.path(), &settings),
        "source addition"
    );
    fs::remove_file(second.path().join("src/new.rs")).unwrap();
    assert_eq!(baseline, digest(second.path(), &settings));
    fs::remove_file(second.path().join("src/a.rs")).unwrap();
    assert_ne!(baseline, digest(second.path(), &settings), "source removal");
    settings.insert("target".into(), "aarch64-test".into());
    assert_ne!(
        baseline,
        digest(first.path(), &settings),
        "build setting change"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_input_is_refused() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    symlink("outside", root.path().join("src/link.rs")).unwrap();
    let error = build_identity::collect_inputs(root.path(), &["src"]).unwrap_err();
    assert!(
        error.to_string().contains("symlinks are not supported"),
        "{error}"
    );
}

#[test]
fn checkout_paths_in_settings_are_normalized() {
    let first = std::path::Path::new("/first/checkout");
    let second = std::path::Path::new("/other/checkout");
    assert_eq!(
        build_identity::normalize_setting(first, "--remap-path-prefix=/first/checkout=src"),
        build_identity::normalize_setting(second, "--remap-path-prefix=/other/checkout=src")
    );
    assert_eq!(
        build_identity::normalize_setting(first, "-C opt-level=2"),
        "-C opt-level=2"
    );
}

#[test]
fn native_tool_setting_names_cover_host_target_and_triple_forms() {
    let names = build_identity::native_setting_names(
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
    );
    for name in [
        "CC",
        "CXX",
        "AR",
        "CFLAGS",
        "HOST_CC",
        "TARGET_CXXFLAGS",
        "CC_aarch64-unknown-linux-gnu",
        "CC_aarch64_unknown_linux_gnu",
        "CFLAGS_x86_64_unknown_linux_gnu",
        "ARFLAGS_aarch64_unknown_linux_gnu",
    ] {
        assert!(
            names.contains(name),
            "expected watched native setting {name}"
        );
    }
}

#[cfg(unix)]
#[test]
fn invalid_utf8_native_setting_is_refused_without_collisions() {
    use std::os::unix::ffi::OsStringExt;
    for byte in [0xfe, 0xff] {
        let value = std::ffi::OsString::from_vec(vec![b'c', b'c', byte]);
        let error = build_identity::decode_setting("CC", value).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("CC: build identity setting must be UTF-8"),
            "{error}"
        );
    }
    assert_eq!(
        build_identity::decode_setting("CC", "cc".into()).unwrap(),
        "cc"
    );
}

#[test]
fn native_setting_names_normalize_dots_and_dashes_like_cc() {
    let names = build_identity::native_setting_names("x86_64-host", "custom.v1-target");
    assert!(names.contains("CFLAGS_custom_v1_target"));
    assert!(names.contains("CC_custom.v1-target"));
    assert_eq!(
        build_identity::decode_setting("CC", "cc".into()).unwrap(),
        "cc"
    );
}
