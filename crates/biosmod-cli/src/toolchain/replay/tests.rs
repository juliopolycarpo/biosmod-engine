//! Replay runtime tests. Programs are answered by `FakeReplayPython`; no interpreter, pip or
//! network runs.

use super::*;
use crate::toolchain::Profile;
use crate::transport::Offline;
use std::cell::{Cell, RefCell};

/// Pretends to be `python3` (creates environments) and the environment's `python` (runs pip
/// and the probes). Installing flips `installed`, as pip would.
struct FakeReplayPython {
    calls: RefCell<Vec<String>>,
    base_version: &'static str,
    has_venv_module: bool,
    venv_error: Option<&'static str>,
    pip_error: Option<&'static str>,
    selftest_ok: bool,
    installed: Cell<bool>,
    /// Versions reported once installed.
    installed_versions: Vec<(&'static str, Option<&'static str>)>,
    lock_seen: RefCell<Option<String>>,
    /// Working directory of each call, in call order, beside `calls`.
    cwds: RefCell<Vec<Option<PathBuf>>>,
}

impl FakeReplayPython {
    fn new() -> FakeReplayPython {
        FakeReplayPython {
            calls: RefCell::new(Vec::new()),
            base_version: "3.14.4",
            has_venv_module: true,
            venv_error: None,
            pip_error: None,
            selftest_ok: true,
            installed: Cell::new(false),
            installed_versions: PACKAGES.iter().map(|(n, v)| (*n, Some(*v))).collect(),
            lock_seen: RefCell::new(None),
            cwds: RefCell::new(Vec::new()),
        }
    }

    /// An interpreter that already has the packages, as `tools set` and `status` meet it.
    fn already_installed() -> FakeReplayPython {
        let fake = FakeReplayPython::new();
        fake.installed.set(true);
        fake
    }

    fn with_versions(
        mut self,
        versions: Vec<(&'static str, Option<&'static str>)>,
    ) -> FakeReplayPython {
        self.installed_versions = versions;
        self
    }

    fn pip_calls(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .filter(|c| c.contains("-m pip"))
            .cloned()
            .collect()
    }
}

fn ok(stdout: &str) -> Result<Finished> {
    Ok(Finished {
        status: Some(0),
        stdout: stdout.into(),
        ..Finished::default()
    })
}

fn exit(status: i32, stderr: &str) -> Result<Finished> {
    Ok(Finished {
        status: Some(status),
        stderr: stderr.into(),
        ..Finished::default()
    })
}

impl Runner for FakeReplayPython {
    fn run(&self, invocation: &Invocation) -> Result<Finished> {
        let mut words = invocation.words();
        self.calls.borrow_mut().push(format!(
            "{} {}",
            invocation.program.display(),
            words.join(" ")
        ));
        self.cwds.borrow_mut().push(invocation.cwd.clone());
        // `-I` only isolates the interpreter; the fake answers the same either way.
        if words.first().map(String::as_str) == Some("-I") {
            words.remove(0);
        }
        if !invocation.program.to_string_lossy().contains("/") && !self.base_exists() {
            return Err(Error::new(
                Code::ToolUnavailable,
                format!(
                    "{}: No such file or directory",
                    invocation.program.display()
                ),
            ));
        }
        let script = words.last().cloned().unwrap_or_default();
        if words.first().map(String::as_str) == Some("-m") && words[1] == "venv" {
            if let Some(error) = self.venv_error {
                return exit(1, error);
            }
            let target = PathBuf::from(&words[2]);
            fs::create_dir_all(target.join("bin")).unwrap();
            fs::write(target.join("bin/python"), "#!/bin/sh\n").unwrap();
            return ok("");
        }
        if words.get(1).map(String::as_str) == Some("pip") {
            if let Some(error) = self.pip_error {
                return exit(1, error);
            }
            let at = words.iter().position(|w| w == "-r").unwrap();
            *self.lock_seen.borrow_mut() = Some(fs::read_to_string(&words[at + 1]).unwrap());
            self.installed.set(true);
            return ok("Successfully installed");
        }
        if script.contains("find_spec") {
            return ok(&format!(
                "{{\"python\": \"{}\", \"venv\": {}}}\n",
                self.base_version, self.has_venv_module
            ));
        }
        if script.contains("selftest ok") {
            return if self.selftest_ok {
                ok("selftest ok\n")
            } else {
                exit(1, "AssertionError: inc eax did not run")
            };
        }
        if script.contains("importlib.metadata") {
            let packages: Vec<String> = self
                .installed_versions
                .iter()
                .map(|(name, version)| match version {
                    Some(v) if self.installed.get() => format!("\"{name}\": \"{v}\""),
                    _ => format!("\"{name}\": null"),
                })
                .collect();
            return ok(&format!(
                "{{\"python\": \"{}\", \"packages\": {{{}}}}}\n",
                self.base_version,
                packages.join(", ")
            ));
        }
        panic!(
            "unexpected invocation: {} {}",
            invocation.program.display(),
            words.join(" ")
        );
    }
}

impl FakeReplayPython {
    /// The bare `python3` name resolves only when a base interpreter exists on this fake system.
    fn base_exists(&self) -> bool {
        self.base_version != "missing"
    }
}

struct Scene {
    root: tempfile::TempDir,
}

impl Scene {
    fn new() -> Scene {
        Scene {
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn data(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn env<'a>(&self, runner: &'a dyn Runner, offline: bool) -> Env<'a> {
        Env {
            runner,
            transport: &Offline,
            offline,
            data: self.data(),
            cache: self.root.path().join("cache"),
            profile: Profile::pinned(),
        }
    }

    /// The managed interpreter, with a file standing at its path.
    fn managed_python(&self) -> ReplayHome {
        let python = venv_python(&managed_venv(&self.data()));
        fs::create_dir_all(python.parent().unwrap()).unwrap();
        fs::write(&python, "#!/bin/sh\n").unwrap();
        ReplayHome {
            python,
            origin: "managed",
        }
    }
}

fn setup_args() -> ReplaySetupArgs {
    ReplaySetupArgs {
        python: None,
        wheelhouse: None,
        force: false,
    }
}

fn install(
    scene: &Scene,
    fake: &FakeReplayPython,
    args: &ReplaySetupArgs,
) -> Result<ReplayInstalled> {
    install_replay(&scene.env(fake, false), args, &mut |_| {})
}

#[test]
fn the_lock_pins_exactly_the_packages_the_checks_expect_with_sha256_hashes() {
    let mut pinned = Vec::new();
    let mut hashes: BTreeMap<String, usize> = BTreeMap::new();
    let mut current = String::new();
    for line in LOCK.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(hash) = line.strip_prefix("--hash=sha256:") {
            let hash = hash.trim_end_matches(['\\', ' ']);
            assert!(
                hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                "(lock hash for {current}): expected 64 hex digits | received {hash:?}"
            );
            *hashes.entry(current.clone()).or_default() += 1;
        } else {
            let requirement = line.trim_end_matches(['\\', ' ']);
            let (name, version) = requirement.split_once("==").unwrap_or_else(|| {
                panic!("(lock line): expected name==version | received {line:?}")
            });
            current = name.to_string();
            pinned.push((name.to_string(), version.to_string()));
        }
    }
    let expected: Vec<(String, String)> = PACKAGES
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
    assert_eq!(pinned, expected, "(lock pins): expected PACKAGES");
    for (name, _) in PACKAGES {
        assert!(
            hashes.get(name).copied().unwrap_or(0) >= 1,
            "(lock hashes for {name}): expected at least one | received none"
        );
    }
    assert!(
        hashes["unicorn"] >= 4,
        "(unicorn wheels): expected Linux x86_64 and aarch64, macOS and Windows hashes | received {}",
        hashes["unicorn"]
    );
}

#[test]
fn the_interpreter_comes_from_the_variable_then_the_configuration_then_the_managed_environment() {
    let data = Path::new("/d");
    let mut config = Config::default();
    let none = |_: &str| None;
    let managed = replay_home(&none, &config, data);
    assert_eq!(
        (managed.python.as_path(), managed.origin),
        (Path::new("/d/replay/venv/bin/python"), "managed")
    );
    config.tools.replay_python = Some("/opt/py/bin/python".into());
    let saved = replay_home(&none, &config, data);
    assert_eq!(
        (saved.python.as_path(), saved.origin),
        (Path::new("/opt/py/bin/python"), "config")
    );
    let variable = |key: &str| (key == OVERRIDE).then(|| OsString::from("/env/python"));
    let overridden = replay_home(&variable, &config, data);
    assert_eq!(
        (overridden.python.as_path(), overridden.origin),
        (Path::new("/env/python"), OVERRIDE)
    );
}

#[test]
fn an_environment_directory_resolves_to_its_interpreter() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(interpreter(dir.path()), dir.path().join("bin/python"));
    let file = dir.path().join("python3.12");
    assert_eq!(interpreter(&file), file);
}

#[test]
fn versions_name_each_package_that_differs_from_the_pin() {
    let versions = Versions {
        python: "3.9.2".into(),
        packages: BTreeMap::from([
            ("unicorn".to_string(), Some("2.0.1".to_string())),
            ("capstone".to_string(), Some("5.0.9".to_string())),
            ("pefile".to_string(), None),
        ]),
    };
    assert!(!versions.python_ok(), "(python 3.9.2): expected below 3.10");
    assert_eq!(
        versions.mismatches(),
        [
            "unicorn: expected 2.1.4 | received 2.0.1",
            "pefile: expected 2024.8.26 | received none"
        ]
    );
    assert_eq!(
        versions.summary(),
        "unicorn 2.0.1, capstone 5.0.9, pefile none"
    );
    assert_eq!(parse_python("3.14.4"), Some((3, 14)));
    assert_eq!(parse_python("three"), None);
}

#[test]
fn a_missing_runtime_is_tool_unavailable_and_names_the_setup_command() {
    let error = missing_runtime("python3: not found");
    assert_eq!(error.code, Code::ToolUnavailable);
    assert!(
        error.message.ends_with("(run `bme tools setup replay`)"),
        "(missing runtime message): expected the setup command | received {}",
        error.message
    );
}

#[test]
fn probing_reports_versions_and_unreadable_output() {
    let fake = FakeReplayPython::already_installed();
    let versions = probe_versions(&fake, Path::new("/v/bin/python"), PROBE_TIMEOUT).unwrap();
    assert_eq!(versions.python, "3.14.4");
    assert!(versions.mismatches().is_empty());
    let silent = FakeReplayPython::new().with_versions(vec![]);
    silent.installed.set(true);
    let absent = probe_versions(&silent, Path::new("/v/bin/python"), PROBE_TIMEOUT).unwrap();
    assert_eq!(absent.packages["unicorn"], None);
}

#[test]
fn checks_report_a_complete_environment_and_run_the_selftest_when_deep() {
    let scene = Scene::new();
    let home = scene.managed_python();
    let fake = FakeReplayPython::already_installed();
    let checks = replay_checks(&scene.env(&fake, false), &home, true);
    let names: Vec<(&str, bool)> = checks.iter().map(|c| (c.check, c.ok)).collect();
    assert_eq!(
        names,
        [
            ("replay-python", true),
            ("replay-packages", true),
            ("replay-emulation", true)
        ]
    );
    let shallow = replay_checks(&scene.env(&fake, false), &home, false);
    assert_eq!(shallow.len(), 2, "(shallow doctor): expected no selftest");
}

#[test]
fn checks_name_a_missing_package_and_a_failed_selftest() {
    let scene = Scene::new();
    let home = scene.managed_python();
    let old = FakeReplayPython::already_installed().with_versions(vec![
        ("unicorn", Some("2.0.1")),
        ("capstone", Some("5.0.9")),
        ("pefile", Some("2024.8.26")),
    ]);
    let checks = replay_checks(&scene.env(&old, false), &home, true);
    let packages = checks
        .iter()
        .find(|c| c.check == "replay-packages")
        .unwrap();
    assert!(
        !packages.ok
            && packages
                .detail
                .contains("unicorn: expected 2.1.4 | received 2.0.1")
            && packages.detail.contains("bme tools setup replay"),
        "(replay-packages): expected the mismatch and the setup command | received {packages:?}"
    );
    assert!(
        checks.iter().all(|c| c.check != "replay-emulation"),
        "(deep after a package mismatch): expected the selftest skipped"
    );
    let mut broken = FakeReplayPython::already_installed();
    broken.selftest_ok = false;
    let checks = replay_checks(&scene.env(&broken, false), &home, true);
    let emulation = checks.last().unwrap();
    assert_eq!(emulation.check, "replay-emulation");
    assert!(!emulation.ok && emulation.detail.contains("inc eax did not run"));
}

#[test]
fn a_python_that_cannot_run_fails_the_python_check_with_the_setup_command() {
    struct NoPython;
    impl Runner for NoPython {
        fn run(&self, invocation: &Invocation) -> Result<Finished> {
            Err(Error::new(
                Code::ToolUnavailable,
                format!(
                    "{}: No such file or directory",
                    invocation.program.display()
                ),
            ))
        }
    }
    let scene = Scene::new();
    let home = ReplayHome {
        python: "/nowhere/bin/python".into(),
        origin: "config",
    };
    let checks = replay_checks(&scene.env(&NoPython, false), &home, true);
    assert_eq!(checks.len(), 1);
    assert!(
        !checks[0].ok && checks[0].detail.contains("run `bme tools setup replay`"),
        "(replay-python): expected failure naming the setup command | received {:?}",
        checks[0]
    );
}

#[test]
fn setup_creates_the_environment_installs_the_lock_with_hash_checking_and_verifies_it() {
    let scene = Scene::new();
    let fake = FakeReplayPython::new();
    let installed = install(&scene, &fake, &setup_args()).unwrap();
    assert!(installed.installed);
    assert_eq!(
        installed.python,
        venv_python(&managed_venv(&scene.data())),
        "(managed interpreter)"
    );
    let pip = fake.pip_calls();
    assert_eq!(pip.len(), 1, "(pip calls): expected one | received {pip:?}");
    for flag in [
        "--isolated",
        "--require-hashes",
        "--no-deps",
        "--only-binary :all:",
    ] {
        assert!(
            pip[0].contains(flag),
            "(pip install): expected {flag} | received {}",
            pip[0]
        );
    }
    assert!(
        !pip[0].contains("--no-index"),
        "(online pip install): expected the index in use | received {}",
        pip[0]
    );
    assert_eq!(fake.lock_seen.borrow().as_deref(), Some(LOCK));
    let venv = managed_venv(&scene.data());
    assert!(
        marker_current(&venv),
        "(marker): expected one for this release"
    );
    assert!(
        !fs::read_dir(venv.parent().unwrap())
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(".staging-")),
        "(staging directory): expected it removed"
    );
}

#[test]
fn setup_runs_venv_and_pip_isolated_from_the_callers_directory() {
    let scene = Scene::new();
    let fake = FakeReplayPython::new();
    install(&scene, &fake, &setup_args()).unwrap();
    let calls = fake.calls.borrow();
    let cwds = fake.cwds.borrow();
    for (at, call) in calls.iter().enumerate() {
        let tool = if call.contains("-m venv") {
            "venv"
        } else if call.contains("-m pip") {
            "pip"
        } else {
            continue;
        };
        assert!(
            call.split_whitespace().any(|w| w == "-I"),
            "(python -m {tool}): expected the -I flag | received {call}"
        );
        let cwd = cwds[at].as_deref().unwrap_or(Path::new("<caller>"));
        assert!(
            cwd.starts_with(managed_venv(&scene.data()).parent().unwrap())
                && cwd.to_string_lossy().contains(".staging-"),
            "(python -m {tool} cwd): expected the staging directory | received {}",
            cwd.display()
        );
    }
    assert!(
        calls.iter().any(|c| c.contains("-m venv")) && calls.iter().any(|c| c.contains("-m pip"))
    );
}

#[test]
fn a_second_setup_changes_nothing() {
    let scene = Scene::new();
    let fake = FakeReplayPython::new();
    install(&scene, &fake, &setup_args()).unwrap();
    let again = install(&scene, &fake, &setup_args()).unwrap();
    assert!(
        !again.installed,
        "(second setup): expected already installed"
    );
    assert_eq!(
        fake.pip_calls().len(),
        1,
        "(pip calls): expected no second install"
    );
}

#[test]
fn offline_setup_needs_a_wheelhouse_and_installs_from_it_without_the_index() {
    let scene = Scene::new();
    let fake = FakeReplayPython::new();
    let refused = install_replay(&scene.env(&fake, true), &setup_args(), &mut |_| {}).unwrap_err();
    assert_eq!(refused.code, Code::SourceUnavailable);
    assert!(
        refused.message.contains("--wheelhouse"),
        "{}",
        refused.message
    );
    assert!(
        fake.calls.borrow().is_empty(),
        "(refused setup): expected no program run"
    );

    let wheels = scene.root.path().join("wheels");
    fs::create_dir_all(&wheels).unwrap();
    let args = ReplaySetupArgs {
        wheelhouse: Some(wheels.clone()),
        ..setup_args()
    };
    install_replay(&scene.env(&fake, true), &args, &mut |_| {}).unwrap();
    let pip = &fake.pip_calls()[0];
    assert!(
        pip.contains("--no-index --find-links")
            && pip.contains(&wheels.to_string_lossy().into_owned()),
        "(offline pip install): expected --no-index --find-links <wheelhouse> | received {pip}"
    );
    let missing = ReplaySetupArgs {
        wheelhouse: Some(scene.root.path().join("absent")),
        ..setup_args()
    };
    let error = install(&scene, &fake, &missing).unwrap_err();
    assert_eq!(error.code, Code::Usage);
}

#[test]
fn setup_refuses_an_old_python_a_missing_venv_module_and_a_missing_python() {
    let scene = Scene::new();
    let mut old = FakeReplayPython::new();
    old.base_version = "3.9.2";
    let error = install(&scene, &old, &setup_args()).unwrap_err();
    assert_eq!(error.code, Code::ToolUnavailable);
    assert!(
        error
            .message
            .contains("expected Python >= 3.10 | received 3.9.2"),
        "{}",
        error.message
    );
    let mut bare = FakeReplayPython::new();
    bare.has_venv_module = false;
    let error = install(&scene, &bare, &setup_args()).unwrap_err();
    assert_eq!(error.code, Code::ToolUnavailable);
    assert!(
        error.message.contains("apt install python3-venv"),
        "{}",
        error.message
    );
    let mut absent = FakeReplayPython::new();
    absent.base_version = "missing";
    let error = install(&scene, &absent, &setup_args()).unwrap_err();
    assert_eq!(error.code, Code::ToolUnavailable);
    assert!(
        error.message.contains("apt install python3"),
        "{}",
        error.message
    );
    assert!(
        !managed_venv(&scene.data()).exists(),
        "(refused setups): expected no environment created"
    );
}

#[test]
fn a_venv_that_cannot_bootstrap_pip_names_python3_venv() {
    let scene = Scene::new();
    let mut fake = FakeReplayPython::new();
    fake.venv_error = Some(
        "The virtual environment was not created successfully because ensurepip is not available.",
    );
    let error = install(&scene, &fake, &setup_args()).unwrap_err();
    assert_eq!(error.code, Code::ToolUnavailable);
    assert!(error.message.contains("python3-venv"), "{}", error.message);
}

#[test]
fn a_failed_pip_install_leaves_no_environment_and_reports_pips_output() {
    let scene = Scene::new();
    let mut fake = FakeReplayPython::new();
    fake.pip_error = Some("THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE");
    let error = install(&scene, &fake, &setup_args()).unwrap_err();
    assert_eq!(error.code, Code::ToolSetupFailed);
    assert!(
        error.message.contains("DO NOT MATCH THE HASHES"),
        "{}",
        error.message
    );
    assert!(
        !managed_venv(&scene.data()).exists(),
        "(failed install): expected the target untouched"
    );
}

#[test]
fn a_failed_selftest_after_installation_is_a_setup_failure() {
    let scene = Scene::new();
    let mut fake = FakeReplayPython::new();
    fake.selftest_ok = false;
    let error = install(&scene, &fake, &setup_args()).unwrap_err();
    assert_eq!(error.code, Code::ToolSetupFailed);
    assert!(
        error.message.contains("selftest failed"),
        "{}",
        error.message
    );
}

#[test]
fn an_environment_setup_did_not_make_is_replaced_only_with_force() {
    let scene = Scene::new();
    let venv = managed_venv(&scene.data());
    fs::create_dir_all(venv.join("bin")).unwrap();
    fs::write(venv.join("bin/python"), "#!/bin/sh\n").unwrap();
    let fake = FakeReplayPython::new();
    let error = install(&scene, &fake, &setup_args()).unwrap_err();
    assert_eq!(error.code, Code::ToolSetupFailed);
    assert!(error.message.contains("--force"), "{}", error.message);
    assert_eq!(leftover_venv(&venv), Some(venv.clone()));
    let forced = ReplaySetupArgs {
        force: true,
        ..setup_args()
    };
    install(&scene, &fake, &forced).unwrap();
    assert!(
        marker_current(&venv),
        "(forced setup): expected a marked environment"
    );
    assert_eq!(leftover_venv(&venv), None);
}

#[test]
fn set_accepts_an_environment_with_the_pinned_versions_and_refuses_others() {
    let dir = tempfile::tempdir().unwrap();
    let python = dir.path().join("bin/python");
    fs::create_dir_all(python.parent().unwrap()).unwrap();
    fs::write(&python, "#!/bin/sh\n").unwrap();
    let good = FakeReplayPython::already_installed();
    let (found, versions) = validate_location(&good, dir.path()).unwrap();
    assert_eq!(found, python);
    assert_eq!(
        versions.summary(),
        "unicorn 2.1.4, capstone 5.0.9, pefile 2024.8.26"
    );
    let old = FakeReplayPython::already_installed().with_versions(vec![
        ("unicorn", Some("2.0.1")),
        ("capstone", Some("5.0.9")),
        ("pefile", Some("2024.8.26")),
    ]);
    let error = validate_location(&old, dir.path()).unwrap_err();
    assert_eq!(error.code, Code::Usage);
    assert!(
        error
            .message
            .contains("unicorn: expected 2.1.4 | received 2.0.1"),
        "{}",
        error.message
    );
    let error = validate_location(&good, &dir.path().join("elsewhere")).unwrap_err();
    assert_eq!(error.code, Code::Usage);
    assert!(error.message.contains("not found"), "{}", error.message);
}
