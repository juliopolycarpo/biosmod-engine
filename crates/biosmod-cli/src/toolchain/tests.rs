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
                let target = Path::new(&words[3]);
                if target.exists() && fs::read_dir(target).unwrap().next().is_some() {
                    return Ok(Finished {
                        status: Some(128),
                        stderr: format!("{}: destination is not empty", target.display()),
                        ..Finished::default()
                    });
                }
                fs::create_dir_all(target.join(".git")).unwrap();
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
    fs::create_dir_all(dir.path().join("x")).unwrap();
    for ext in ["c", "asm", "json"] {
        fs::write(dir.path().join("x").join(format!("Uncore.{ext}")), b"stale").unwrap();
    }
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
    .unwrap_err();
    assert_eq!(reply.code, Code::ToolFailed);
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

struct FakeExporter {
    incomplete: Option<&'static str>,
    missing: Option<&'static str>,
    calls: RefCell<Vec<String>>,
}

impl Runner for FakeExporter {
    fn run(&self, invocation: &Invocation) -> Result<Finished> {
        let args = invocation.words();
        let import = args.iter().position(|s| s == "-import").unwrap();
        let export = args
            .iter()
            .position(|s| s == "ExportFirmware.java")
            .unwrap();
        let name = Path::new(&args[import + 1])
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .trim_end_matches(".pe");
        self.calls.borrow_mut().push(name.to_string());
        let dir = Path::new(&args[export + 1]);
        for ext in ["c", "asm", "json"] {
            if self.missing == Some(name) && ext == "json" {
                continue;
            }
            fs::write(dir.join(format!("{name}.{ext}")), b"partial").unwrap();
        }
        if self.incomplete != Some(name) {
            fs::write(dir.join(".bme-export-complete"), b"complete").unwrap();
        }
        Ok(Finished {
            status: Some(0),
            ..Finished::default()
        })
    }
}

#[test]
fn analysis_requires_completion_for_each_module() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let home = root.join("ghidra");
    fs::create_dir_all(home.join("support")).unwrap();
    fs::write(headless(&home), b"").unwrap();
    fs::create_dir_all(extension_dir(&home).join("data")).unwrap();
    let home = GhidraHome {
        path: home,
        origin: "config",
    };
    let modules = [root.join("one.pe"), root.join("two.pe")];
    for module in &modules {
        fs::write(module, b"MZ").unwrap();
    }
    let output = root.join("exports");
    fs::create_dir_all(&output).unwrap();
    for ext in ["c", "asm", "json"] {
        fs::write(output.join(format!("two.{ext}")), b"stale").unwrap();
    }
    let runner = FakeExporter {
        incomplete: Some("two"),
        missing: None,
        calls: RefCell::new(vec![]),
    };
    let error = run_analysis(
        &runner,
        &home,
        &root.join("project"),
        &output,
        &modules,
        60,
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(error.code, Code::ToolFailed);
    assert!(error.message.contains("two.pe"));
    assert_eq!(*runner.calls.borrow(), ["one", "two"]);
    let runner = FakeExporter {
        incomplete: None,
        missing: Some("two"),
        calls: RefCell::new(vec![]),
    };
    let error = run_analysis(
        &runner,
        &home,
        &root.join("project"),
        &output,
        &modules,
        60,
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(error.code, Code::ToolFailed);
    assert!(error.message.contains("two.json"));
    let runner = FakeExporter {
        incomplete: None,
        missing: None,
        calls: RefCell::new(vec![]),
    };
    let reply = run_analysis(
        &runner,
        &home,
        &root.join("project"),
        &output,
        &modules,
        60,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(reply.data["files"].as_array().unwrap().len(), 6);
    assert_eq!(*runner.calls.borrow(), ["one", "two"]);
}

/// Records the timeout of every Ghidra run, then defers to `FakeExporter`.
struct RecordingHeadless {
    inner: FakeExporter,
    timeouts: RefCell<Vec<Duration>>,
}

impl Runner for RecordingHeadless {
    fn run(&self, invocation: &Invocation) -> Result<Finished> {
        self.timeouts.borrow_mut().push(invocation.timeout);
        self.inner.run(invocation)
    }
}

/// A Ghidra home whose `analyzeHeadless` is `script`, plus two module files.
fn home_with_headless(root: &Path, script: &[u8]) -> (GhidraHome, [PathBuf; 2]) {
    use std::os::unix::fs::PermissionsExt;
    let home = root.join("ghidra");
    fs::create_dir_all(home.join("support")).unwrap();
    fs::write(headless(&home), script).unwrap();
    fs::set_permissions(headless(&home), fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(extension_dir(&home).join("data")).unwrap();
    let modules = [root.join("one.pe"), root.join("two.pe")];
    for module in &modules {
        fs::write(module, b"MZ").unwrap();
    }
    let home = GhidraHome {
        path: home,
        origin: "config",
    };
    (home, modules)
}

#[test]
fn analysis_budgets_the_timeout_per_module_run() {
    let dir = tempfile::tempdir().unwrap();
    let (home, modules) = home_with_headless(dir.path(), b"");
    let runner = RecordingHeadless {
        inner: FakeExporter {
            incomplete: None,
            missing: None,
            calls: RefCell::new(vec![]),
        },
        timeouts: RefCell::new(vec![]),
    };
    run_analysis(
        &runner,
        &home,
        &dir.path().join("project"),
        &dir.path().join("exports"),
        &modules,
        60,
        &mut |_| {},
    )
    .unwrap();
    let expected = Duration::from_secs(60 + 900);
    assert_eq!(
        *runner.timeouts.borrow(),
        [expected, expected],
        "expected one timeout of analysis timeout + 900s per single-module run"
    );
}

/// Imports print the module name; the export stage writes the files `run_analysis` collects.
const FAKE_HEADLESS: &[u8] = br#"#!/bin/sh
prev=
for arg in "$@"; do
  [ "$prev" = -import ] && module=$arg
  [ "$prev" = ExportFirmware.java ] && dir=$arg
  prev=$arg
done
name=$(basename "$module" .pe)
echo "imported $name"
for ext in c asm json; do echo x > "$dir/$name.$ext"; done
echo done > "$dir/.bme-export-complete"
"#;

#[test]
fn analysis_log_keeps_the_output_of_every_module() {
    let dir = tempfile::tempdir().unwrap();
    let (home, modules) = home_with_headless(dir.path(), FAKE_HEADLESS);
    let output = dir.path().join("exports");
    run_analysis(
        &System,
        &home,
        &dir.path().join("project"),
        &output,
        &modules,
        60,
        &mut |_| {},
    )
    .unwrap();
    let log = fs::read_to_string(output.join("ghidra.log")).unwrap();
    assert!(
        log.contains("imported one") && log.contains("imported two"),
        "ghidra.log: expected output of both modules | received {log:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_analysis_output_is_displayable() {
    use std::os::unix::ffi::OsStringExt;
    let dir = tempfile::tempdir().unwrap();
    let (home, modules) = home_with_headless(dir.path(), b"");
    let output = dir
        .path()
        .join(std::ffi::OsString::from_vec(b"exports-\xff".to_vec()));
    let runner = FakeExporter {
        incomplete: None,
        missing: None,
        calls: RefCell::new(vec![]),
    };
    let reply = run_analysis(
        &runner,
        &home,
        &dir.path().join("project"),
        &output,
        &modules,
        60,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(reply.data["output"], output.to_string_lossy().as_ref());
    assert_eq!(
        reply.data["log"],
        output.join("ghidra.log").to_string_lossy().as_ref()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_tool_paths_serialize_in_replies() {
    use std::os::unix::ffi::OsStringExt;
    let path = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/ghidra-\xff".to_vec()));
    let home = GhidraHome {
        path: path.clone(),
        origin: "config",
    };
    let failed = checks_reply(vec![check("test", false, "missing")], &home).unwrap_err();
    assert_eq!(
        failed.details.unwrap()["ghidra_home"]["path"],
        path.to_string_lossy().as_ref()
    );
    let installed = Installed {
        ghidra: path.clone(),
        extension: path.clone(),
        profile: Profile::pinned(),
        startup_check: None,
    };
    let reply = Reply::new(installed, "");
    assert_eq!(reply.data["ghidra"], path.to_string_lossy().as_ref());
    assert_eq!(reply.data["extension"], path.to_string_lossy().as_ref());
}

#[test]
fn interrupted_replacement_requires_recovery_before_retrying_setup() {
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
    let prefix = env.data.join("tools");
    let target = prefix.join(&env.profile.ghidra_dirname);
    let backup = prefix.join(".bme-old-424242");
    let unrelated = prefix.join("unrelated");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&unrelated).unwrap();
    fs::write(target.join("prior"), b"prior installation").unwrap();
    fs::write(unrelated.join("keep"), b"unrelated installation").unwrap();
    // A process can die after the first rename and before publishing its staged tree.
    fs::rename(&target, &backup).unwrap();
    let mut args = setup_args();
    args.force = true;
    let error = install(&env, &args, &mut |_| {})
        .expect_err("interrupted replacement must require recovery");
    assert!(
        error.message.contains(&backup.display().to_string()),
        "expected backup path in error: {error}"
    );
    assert!(
        !target.exists(),
        "{}: retry must not hide the interrupted replacement",
        target.display()
    );
    assert_eq!(
        fs::read(backup.join("prior")).unwrap(),
        b"prior installation"
    );
    assert_eq!(
        fs::read(unrelated.join("keep")).unwrap(),
        b"unrelated installation"
    );
    fs::rename(&backup, &target).unwrap();
    let installed =
        install(&env, &args, &mut |_| {}).expect("retry after restoring backup succeeds");
    assert!(installed.extension.join("data/types.gdt").is_file());
    assert_eq!(
        fs::read(unrelated.join("keep")).unwrap(),
        b"unrelated installation"
    );
}

/// Interrupt the first source clone after Ghidra was installed; later calls delegate normally.
struct InterruptFirstClone {
    inner: FakeTools,
    interrupt: std::cell::Cell<bool>,
}

impl Runner for InterruptFirstClone {
    fn run(&self, invocation: &Invocation) -> Result<Finished> {
        if invocation
            .program
            .file_name()
            .is_some_and(|name| name == "git")
            && invocation
                .words()
                .first()
                .is_some_and(|word| word == "clone")
            && self.interrupt.replace(false)
        {
            let words = invocation.words();
            let target = Path::new(&words[3]);
            fs::create_dir_all(target).unwrap();
            fs::write(target.join("partial-clone"), b"partial").unwrap();
            panic!("simulated interruption during source clone");
        }
        self.inner.run(invocation)
    }
}

#[test]
fn interrupted_source_clone_preserves_installed_tools_and_retry_completes() {
    let dir = tempfile::tempdir().unwrap();
    let tools = InterruptFirstClone {
        inner: FakeTools::new(),
        interrupt: std::cell::Cell::new(true),
    };
    let (transport, profile) = world();
    let env = Env {
        runner: &tools,
        transport: &transport,
        offline: false,
        data: dir.path().join("data"),
        cache: dir.path().join("cache"),
        profile,
    };
    let unrelated = env.data.join("tools/unrelated/keep");
    fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
    fs::write(&unrelated, b"preserved").unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        install(&env, &setup_args(), &mut |_| {})
    }));
    let panic = outcome.expect_err("clone must be interrupted");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"simulated interruption during source clone")
    );
    let ghidra = env.data.join("tools").join(&env.profile.ghidra_dirname);
    assert!(
        headless(&ghidra).is_file(),
        "completed Ghidra installation must survive interruption"
    );
    assert_eq!(fs::read(&unrelated).unwrap(), b"preserved");
    let partial = env.cache.join(EXTENSION);
    assert_eq!(fs::read(partial.join("partial-clone")).unwrap(), b"partial");
    let error =
        install(&env, &setup_args(), &mut |_| {}).expect_err("partial clone must be reported");
    assert!(
        error.message.contains("destination is not empty"),
        "{error}"
    );
    // Remove only the incomplete checkout, then retry the setup.
    fs::remove_dir_all(&partial).unwrap();
    let installed =
        install(&env, &setup_args(), &mut |_| {}).expect("retry completes interrupted setup");
    assert_eq!(installed.ghidra, ghidra);
    assert!(installed.extension.join("data/types.gdt").is_file());
    assert_eq!(fs::read(&unrelated).unwrap(), b"preserved");
}

#[test]
fn target_specific_backup_survives_an_interrupted_activation_and_blocks_retry() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("ghidra");
    let staged = dir.path().join("staged");
    let backup = backup_path(&target);
    fs::create_dir(&target).unwrap();
    fs::write(target.join("prior"), b"prior").unwrap();
    fs::create_dir(&staged).unwrap();
    fs::write(staged.join("new"), b"new").unwrap();
    fs::rename(&target, &backup).unwrap();
    let error = replace_dir(&staged, &target).unwrap_err();
    assert!(
        error.message.contains(&backup.display().to_string()),
        "{error}"
    );
    assert!(!target.exists());
    assert_eq!(fs::read(backup.join("prior")).unwrap(), b"prior");
    assert_eq!(fs::read(staged.join("new")).unwrap(), b"new");
    fs::rename(&backup, &target).unwrap();
    replace_dir(&staged, &target).unwrap();
    assert_eq!(fs::read(target.join("new")).unwrap(), b"new");
    assert!(!backup.exists());
}

#[test]
fn activation_failure_restores_previous_directory() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("ghidra");
    let missing = dir.path().join("missing-stage");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("prior"), b"prior").unwrap();
    let error = replace_dir(&missing, &target).unwrap_err();
    assert!(
        error.message.contains(&target.display().to_string()),
        "{error}"
    );
    assert_eq!(fs::read(target.join("prior")).unwrap(), b"prior");
    assert!(!backup_path(&target).exists());
}

#[test]
fn active_target_and_retained_backup_are_both_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("gradle-9.3.1");
    let backup = backup_path(&target);
    let staged = dir.path().join("staged");
    fs::create_dir(&target).unwrap();
    fs::create_dir(&backup).unwrap();
    fs::create_dir(&staged).unwrap();
    fs::write(target.join("new"), b"new").unwrap();
    fs::write(backup.join("old"), b"old").unwrap();
    fs::write(staged.join("next"), b"next").unwrap();
    let error = replace_dir(&staged, &target).unwrap_err();
    assert!(
        error.message.contains(&backup.display().to_string()),
        "{error}"
    );
    assert_eq!(fs::read(target.join("new")).unwrap(), b"new");
    assert_eq!(fs::read(backup.join("old")).unwrap(), b"old");
    assert_eq!(fs::read(staged.join("next")).unwrap(), b"next");
}

#[test]
fn tools_paths_reports_a_relative_flashrom_override_as_an_absolute_path() {
    // The desktop app hands this path to pkexec, which starts root in another directory.
    let get = |key: &str| (key == crate::flash::FLASHROM_OVERRIDE).then(|| "bin/flashrom".into());
    let location = flashrom_location(&get, None).unwrap();
    let path = location["path"].as_str().unwrap_or_default();
    assert!(
        Path::new(path).is_absolute() && path.ends_with("bin/flashrom"),
        "(tools paths, BME_FLASHROM=bin/flashrom): expected an absolute path ending in bin/flashrom | received {location}"
    );
    assert_eq!(location["origin"], crate::flash::FLASHROM_OVERRIDE);
}
