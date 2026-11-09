use super::*;
use crate::testkit::FakeTransport;
use std::cell::RefCell;
use std::io::Cursor;
use zip::write::SimpleFileOptions;

/// Build a zip in memory from `(name, contents, unix mode)`; a `None` body adds a directory.
fn zip_of(entries: &[(&str, Option<&[u8]>, u32)]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, body, mode) in entries {
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(*mode);
        match body {
            Some(bytes) => {
                writer.start_file(*name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
            None => writer.add_directory(*name, options).unwrap(),
        }
    }
    writer.finish().unwrap().into_inner()
}

fn sha(bytes: &[u8]) -> String {
    biosmod_core::util::sha256_hex(bytes)
}

/// Pretends to be javac, git, gradle and analyzeHeadless; records every call.
struct FakeTools {
    calls: RefCell<Vec<String>>,
    java: &'static str,
    extension_zip: Vec<u8>,
    headless_output: &'static str,
}

impl FakeTools {
    fn new() -> FakeTools {
        let extension = zip_of(&[
            ("ghidra-firmware-utils/", None, 0o755),
            ("ghidra-firmware-utils/data/types.gdt", Some(b"gdt"), 0o644),
            (
                "ghidra-firmware-utils/extension.properties",
                Some(b"version=12.2\n"),
                0o644,
            ),
        ]);
        FakeTools {
            calls: RefCell::new(vec![]),
            java: "javac 21.0.5",
            extension_zip: extension,
            headless_output: "INFO  REPORT: Import succeeded with language x86",
        }
    }
}

impl Runner for FakeTools {
    fn run(&self, invocation: &Invocation) -> Result<Finished> {
        let program = invocation
            .program
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let words = invocation.words();
        self.calls
            .borrow_mut()
            .push(format!("{program} {}", words.join(" ")));
        let ok = |stdout: &str| {
            Ok(Finished {
                status: Some(0),
                stdout: stdout.into(),
                ..Finished::default()
            })
        };
        match program.as_str() {
            "javac" | "java" => Ok(Finished {
                status: Some(0),
                stderr: self.java.into(),
                ..Finished::default()
            }),
            "git" if words.first().map(String::as_str) == Some("clone") => {
                fs::create_dir_all(Path::new(&words[3]).join(".git")).unwrap();
                ok("")
            }
            "git" if words.get(2).map(String::as_str) == Some("rev-parse") => {
                ok(&format!("{}\n", Profile::pinned().firmware_utils_commit))
            }
            "git" => ok("git version 2.50"),
            "gradle" => {
                let source = PathBuf::from(&words[3]);
                fs::create_dir_all(source.join("dist")).unwrap();
                fs::write(
                    source.join("dist/ghidra_12.2_PUBLIC_20261108_ghidra-firmware-utils.zip"),
                    &self.extension_zip,
                )
                .unwrap();
                ok("")
            }
            "analyzeHeadless" => ok(self.headless_output),
            other => panic!("unexpected program {other}"),
        }
    }
}

fn ghidra_zip() -> Vec<u8> {
    zip_of(&[
        ("ghidra_12.2_PUBLIC/", None, 0o755),
        (
            "ghidra_12.2_PUBLIC/support/analyzeHeadless",
            Some(b"#!/bin/sh\n"),
            0o755,
        ),
        (
            "ghidra_12.2_PUBLIC/Ghidra/application.properties",
            Some(b"application.version=12.2\n"),
            0o644,
        ),
    ])
}

fn gradle_zip() -> Vec<u8> {
    zip_of(&[("gradle-9.3.1/bin/gradle", Some(b"#!/bin/sh\n"), 0o755)])
}

/// A profile whose digests match the fake archives, served by a fake transport.
fn world() -> (FakeTransport, Profile) {
    let (ghidra, gradle) = (ghidra_zip(), gradle_zip());
    let mut profile = Profile::pinned();
    profile.ghidra_sha256 = sha(&ghidra);
    profile.gradle_sha256 = sha(&gradle);
    let transport = FakeTransport::default();
    transport.put(&profile.ghidra_url, &ghidra);
    transport.put(&profile.gradle_url, &gradle);
    (transport, profile)
}

fn setup_args() -> SetupArgs {
    SetupArgs {
        prefix: None,
        ghidra_zip: None,
        gradle_home: None,
        firmware_utils_src: None,
        force: false,
        skip_check: false,
    }
}

#[test]
fn install_verifies_stages_and_checks_startup() {
    let dir = tempfile::tempdir().unwrap();
    let tools = FakeTools::new();
    let (transport, profile) = world();
    let env = Env {
        runner: &tools,
        transport: &transport,
        offline: false,
        data: dir.path().join("data"),
        cache: dir.path().join("cache"),
        profile,
    };
    let installed = install(&env, &setup_args(), &mut |_| {}).unwrap();
    assert_eq!(
        installed.ghidra,
        dir.path().join("data/tools/ghidra_12.2_PUBLIC")
    );
    assert!(installed.extension.join("data/types.gdt").is_file());
    assert_eq!(installed.startup_check, Some(true));
    let calls = tools.calls.borrow().join("\n");
    assert!(
        calls.contains(&format!(
            "git -C {} apply",
            dir.path().join("cache/ghidra-firmware-utils").display()
        )),
        "{calls}"
    );
    assert!(calls.contains("buildExtension"), "{calls}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(headless(&installed.ghidra))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o111,
            0o111,
            "analyzeHeadless keeps its executable bits"
        );
    }
    let home = GhidraHome {
        path: installed.ghidra.clone(),
        origin: "managed",
    };
    assert!(
        inspect(&env, &home).iter().all(|c| c.ok),
        "{:?}",
        inspect(&env, &home)
    );

    // A second run reuses everything this profile installed, without downloading.
    let requests = transport.requests.borrow().len();
    install(&env, &setup_args(), &mut |_| {}).unwrap();
    assert_eq!(transport.requests.borrow().len(), requests);
    let leftovers: Vec<_> = fs::read_dir(dir.path().join("data/tools"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(
        leftovers.len(),
        1,
        "no staging directories remain: {leftovers:?}"
    );
}

#[test]
fn tampered_archive_is_rejected_before_extraction() {
    let dir = tempfile::tempdir().unwrap();
    let tools = FakeTools::new();
    let (transport, profile) = world();
    transport.put(
        &profile.ghidra_url,
        &zip_of(&[(
            "ghidra_12.2_PUBLIC/support/analyzeHeadless",
            Some(b"evil"),
            0o755,
        )]),
    );
    let env = Env {
        runner: &tools,
        transport: &transport,
        offline: false,
        data: dir.path().join("data"),
        cache: dir.path().join("cache"),
        profile,
    };
    let error = install(&env, &setup_args(), &mut |_| {}).unwrap_err();
    assert_eq!(error.code, Code::ToolSetupFailed, "{error}");
    assert!(error.message.contains("SHA-256: expected"), "{error}");
    assert!(!dir.path().join("data/tools/ghidra_12.2_PUBLIC").exists());
    let downloads = dir.path().join("cache/downloads");
    assert_eq!(
        fs::read_dir(downloads).unwrap().count(),
        0,
        "the partial download is discarded"
    );
}

#[test]
fn old_jdk_and_foreign_install_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut tools = FakeTools::new();
    tools.java = "javac 17.0.2";
    let (transport, profile) = world();
    let env = Env {
        runner: &tools,
        transport: &transport,
        offline: false,
        data: dir.path().join("data"),
        cache: dir.path().join("cache"),
        profile: profile.clone(),
    };
    let error = install(&env, &setup_args(), &mut |_| {}).unwrap_err();
    assert_eq!(error.code, Code::ToolUnavailable);
    assert!(
        error
            .message
            .contains("expected version >= 21 | received 17"),
        "{error}"
    );

    let tools = FakeTools::new();
    let env = Env {
        runner: &tools,
        transport: &transport,
        offline: false,
        data: dir.path().join("data"),
        cache: dir.path().join("cache"),
        profile,
    };
    fs::create_dir_all(dir.path().join("data/tools/ghidra_12.2_PUBLIC")).unwrap();
    let error = install(&env, &setup_args(), &mut |_| {}).unwrap_err();
    assert!(error.message.contains("pass --force"), "{error}");
    let forced = SetupArgs {
        force: true,
        ..setup_args()
    };
    assert!(install(&env, &forced, &mut |_| {}).is_ok());
}

#[test]
fn offline_setup_requires_local_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let tools = FakeTools::new();
    let env = Env {
        runner: &tools,
        transport: &crate::transport::Offline,
        offline: true,
        data: dir.path().into(),
        cache: dir.path().into(),
        profile: Profile::pinned(),
    };
    assert_eq!(
        install(&env, &setup_args(), &mut |_| {}).unwrap_err().code,
        Code::SourceUnavailable
    );
}

#[test]
fn failed_startup_check_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let mut tools = FakeTools::new();
    tools.headless_output = "ERROR: could not start";
    let (transport, profile) = world();
    let env = Env {
        runner: &tools,
        transport: &transport,
        offline: false,
        data: dir.path().join("data"),
        cache: dir.path().join("cache"),
        profile,
    };
    let error = install(&env, &setup_args(), &mut |_| {}).unwrap_err();
    assert!(error.message.contains("startup check failed"), "{error}");
}

#[test]
fn zip_extraction_refuses_escapes_symlinks_and_oversize() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, bytes: Vec<u8>| {
        let path = dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        path
    };
    let slip = write("slip.zip", zip_of(&[("../evil", Some(b"x"), 0o644)]));
    let out = tempfile::tempdir().unwrap();
    assert!(
        extract_zip(&slip, out.path(), Limits::TOOL)
            .unwrap_err()
            .message
            .contains("unsafe path")
    );

    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_symlink("link", "/etc/passwd", SimpleFileOptions::default())
        .unwrap();
    let link = write("link.zip", writer.finish().unwrap().into_inner());
    assert!(
        extract_zip(&link, out.path(), Limits::TOOL)
            .unwrap_err()
            .message
            .contains("symlinks")
    );

    let big = write("big.zip", zip_of(&[("a", Some(&[0u8; 64]), 0o644)]));
    let limits = Limits {
        max_entries: 10,
        max_total: 32,
    };
    assert!(
        extract_zip(&big, out.path(), limits)
            .unwrap_err()
            .message
            .contains("exceeds the limit")
    );
    let many = write(
        "many.zip",
        zip_of(&[("a", Some(b"1"), 0o644), ("b", Some(b"2"), 0o644)]),
    );
    assert!(
        extract_zip(
            &many,
            out.path(),
            Limits {
                max_entries: 1,
                max_total: 100
            }
        )
        .unwrap_err()
        .message
        .contains("entries exceed")
    );
}

#[test]
fn java_versions_parse_from_both_formats() {
    assert_eq!(java_major("javac 21.0.5"), Some(21));
    assert_eq!(java_major("openjdk version \"25\" 2025-09-16"), Some(25));
    assert_eq!(java_major("java version \"1.8.0_381\""), Some(8));
    assert_eq!(java_major("no version here"), None);
}

#[test]
fn analysis_writes_scripts_and_reports_failures() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("ghidra");
    fs::create_dir_all(home.join("support")).unwrap();
    fs::write(headless(&home), b"").unwrap();
    fs::create_dir_all(extension_dir(&home).join("data")).unwrap();
    let module = dir.path().join("Uncore.pe");
    fs::write(&module, b"MZ").unwrap();
    let tools = FakeTools::new();
    let home = GhidraHome {
        path: home,
        origin: "config",
    };
    let reply = run_analysis(
        &tools,
        &home,
        &dir.path().join("p"),
        &dir.path().join("x"),
        std::slice::from_ref(&module),
        60,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(reply.data["files"], serde_json::json!([]));
    let call = tools.calls.borrow().last().unwrap().clone();
    assert!(
        call.contains("-postScript ExportFirmware.java")
            && call.contains("-analysisTimeoutPerFile 60"),
        "{call}"
    );

    let missing = run_analysis(
        &tools,
        &home,
        &dir.path().join("p"),
        &dir.path().join("x"),
        &[dir.path().join("none.pe")],
        60,
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(missing.code, Code::Io);
    let absent = GhidraHome {
        path: dir.path().join("nowhere"),
        origin: "managed",
    };
    assert_eq!(
        run_analysis(
            &tools,
            &absent,
            dir.path(),
            dir.path(),
            &[module],
            60,
            &mut |_| {}
        )
        .unwrap_err()
        .code,
        Code::ToolUnavailable
    );
}
