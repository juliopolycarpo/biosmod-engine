//! Script runner tests. `FakeReplayScript` answers the version probe and the launcher; no
//! interpreter runs.

use super::*;
use crate::toolchain::{Finished, Profile, Runner};
use crate::transport::Offline;
use std::cell::RefCell;

/// Pretends to be the environment's `python`: reports versions for the probe and, for the
/// launcher, writes `emitted` to the result file the way `bme_replay.emit` would.
struct FakeReplayScript {
    python_version: &'static str,
    unicorn_version: &'static str,
    emitted: &'static str,
    exit_status: i32,
    stderr: &'static str,
    /// Grow the result file to this many bytes (sparse), as a runaway harness would.
    result_len: Option<u64>,
    launches: RefCell<Vec<Invocation>>,
}

impl FakeReplayScript {
    fn new(emitted: &'static str) -> FakeReplayScript {
        FakeReplayScript {
            python_version: "3.14.4",
            unicorn_version: "2.1.4",
            emitted,
            exit_status: 0,
            stderr: "",
            result_len: None,
            launches: RefCell::new(Vec::new()),
        }
    }
}

impl Runner for FakeReplayScript {
    fn run(&self, invocation: &Invocation) -> Result<Finished> {
        let words = invocation.words();
        let script = words.join(" ");
        if script.contains("importlib.metadata") {
            return Ok(Finished {
                status: Some(0),
                stdout: format!(
                    "{{\"python\": \"{}\", \"packages\": {{\"unicorn\": \"{}\", \"capstone\": \"5.0.9\", \"pefile\": \"2024.8.26\"}}}}\n",
                    self.python_version, self.unicorn_version
                ),
                ..Finished::default()
            });
        }
        assert!(
            script.contains("bme_replay.__main__"),
            "(runner): expected the version probe or the launcher | received {script}"
        );
        self.launches.borrow_mut().push(invocation.clone());
        let (_, result) = invocation
            .env
            .iter()
            .find(|(key, _)| key == RESULT_ENV)
            .expect("the launcher gets a result file");
        if !self.emitted.is_empty() {
            fs::write(result, self.emitted).unwrap();
        }
        if let Some(len) = self.result_len {
            fs::File::create(result).unwrap().set_len(len).unwrap();
        }
        Ok(Finished {
            status: Some(self.exit_status),
            stderr: self.stderr.into(),
            ..Finished::default()
        })
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

    fn env<'a>(&self, runner: &'a dyn Runner) -> Env<'a> {
        Env {
            runner,
            transport: &Offline,
            offline: false,
            data: self.root.path().join("data"),
            cache: self.root.path().join("cache"),
            profile: Profile::pinned(),
        }
    }

    /// A file standing where the interpreter should be.
    fn home(&self) -> ReplayHome {
        let python = self.root.path().join("venv/bin/python");
        fs::create_dir_all(python.parent().unwrap()).unwrap();
        fs::write(&python, "#!/bin/sh\n").unwrap();
        ReplayHome {
            python,
            origin: "managed",
        }
    }
}

fn run<'a>(harness: &'a Path, modules: &'a [PathBuf], args: &'a [String]) -> ScriptRun<'a> {
    ScriptRun {
        harness,
        modules,
        args,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn emitted_documents_come_back_in_order_with_their_raw_text() {
    let scene = Scene::new();
    let fake = FakeReplayScript::new("{\"case\":1}\n\n{\"case\":2}\n");
    let output = run_script(
        &scene.env(&fake),
        &scene.home(),
        &run(Path::new("h.py"), &[], &[]),
    )
    .unwrap();
    assert_eq!(
        output.documents,
        [
            serde_json::json!({"case": 1}),
            serde_json::json!({"case": 2})
        ]
    );
    assert_eq!(output.raw, "{\"case\":1}\n\n{\"case\":2}\n");
    assert_eq!(
        output.versions.packages["unicorn"].as_deref(),
        Some("2.1.4")
    );
}

#[test]
fn the_launcher_gets_the_package_dir_harness_modules_and_script_arguments() {
    let scene = Scene::new();
    let fake = FakeReplayScript::new("");
    let modules = [PathBuf::from("a.pe"), PathBuf::from("b.pe")];
    let args = ["--case".to_string(), "3".to_string()];
    run_script(
        &scene.env(&fake),
        &scene.home(),
        &run(Path::new("h.py"), &modules, &args),
    )
    .unwrap();
    let launches = fake.launches.borrow();
    let words = launches[0].words();
    let package_dir = package::package_root(&scene.root.path().join("data"));
    assert_eq!(
        &words[..3],
        ["-I", "-B", "-c"],
        "(interpreter flags): expected isolated mode without bytecode"
    );
    assert_eq!(
        words[4..],
        [
            package_dir.to_string_lossy().into_owned(),
            "h.py".into(),
            "--module".into(),
            "a.pe".into(),
            "--module".into(),
            "b.pe".into(),
            "--".into(),
            "--case".into(),
            "3".into(),
        ]
    );
}

#[test]
fn running_a_script_writes_the_embedded_package_first() {
    let scene = Scene::new();
    let fake = FakeReplayScript::new("");
    run_script(
        &scene.env(&fake),
        &scene.home(),
        &run(Path::new("h.py"), &[], &[]),
    )
    .unwrap();
    let init =
        package::package_root(&scene.root.path().join("data")).join("bme_replay/__init__.py");
    assert!(
        init.is_file(),
        "{}: expected the package after a run",
        init.display()
    );
}

#[test]
fn a_missing_interpreter_names_the_setup_command() {
    let scene = Scene::new();
    let fake = FakeReplayScript::new("");
    let home = ReplayHome {
        python: scene.root.path().join("nowhere/python"),
        origin: "managed",
    };
    let error =
        run_script(&scene.env(&fake), &home, &run(Path::new("h.py"), &[], &[])).unwrap_err();
    assert_eq!(error.code, Code::ToolUnavailable, "{error}");
    assert!(
        error
            .message
            .contains("expected a Python interpreter | received none")
            && error.message.ends_with("(run `bme tools setup replay`)"),
        "{error}"
    );
    assert!(fake.launches.borrow().is_empty());
}

#[test]
fn a_package_at_the_wrong_version_is_unavailable() {
    let scene = Scene::new();
    let mut fake = FakeReplayScript::new("");
    fake.unicorn_version = "2.0.1";
    let error = run_script(
        &scene.env(&fake),
        &scene.home(),
        &run(Path::new("h.py"), &[], &[]),
    )
    .unwrap_err();
    assert_eq!(error.code, Code::ToolUnavailable, "{error}");
    assert!(
        error
            .message
            .contains("unicorn: expected 2.1.4 | received 2.0.1"),
        "{error}"
    );
}

#[test]
fn an_old_python_is_unavailable() {
    let scene = Scene::new();
    let mut fake = FakeReplayScript::new("");
    fake.python_version = "3.9.2";
    let error = run_script(
        &scene.env(&fake),
        &scene.home(),
        &run(Path::new("h.py"), &[], &[]),
    )
    .unwrap_err();
    assert_eq!(error.code, Code::ToolUnavailable, "{error}");
    assert!(
        error
            .message
            .contains("expected Python >= 3.10 | received 3.9.2"),
        "{error}"
    );
}

#[test]
fn a_failing_harness_reports_its_exit_status_and_stderr() {
    let scene = Scene::new();
    let mut fake = FakeReplayScript::new("");
    fake.exit_status = 1;
    fake.stderr = "bme_replay.errors.UnmodeledAccess: port 0x80 read size 1";
    let error = run_script(
        &scene.env(&fake),
        &scene.home(),
        &run(Path::new("h.py"), &[], &[]),
    )
    .unwrap_err();
    assert_eq!(error.code, Code::ToolFailed, "{error}");
    assert!(
        error
            .message
            .contains("expected exit status 0 | received exit status 1")
            && error
                .message
                .contains("UnmodeledAccess: port 0x80 read size 1"),
        "{error}"
    );
}

#[test]
fn a_result_line_that_is_not_json_names_its_line() {
    let scene = Scene::new();
    let fake = FakeReplayScript::new("{\"ok\":true}\nnot json\n");
    let error = run_script(
        &scene.env(&fake),
        &scene.home(),
        &run(Path::new("h.py"), &[], &[]),
    )
    .unwrap_err();
    assert_eq!(error.code, Code::ToolFailed, "{error}");
    assert!(
        error
            .message
            .contains("h.py result line 2: expected one JSON document"),
        "{error}"
    );
}

#[test]
fn a_harness_that_emits_nothing_has_no_documents() {
    let scene = Scene::new();
    let fake = FakeReplayScript::new("");
    let output = run_script(
        &scene.env(&fake),
        &scene.home(),
        &run(Path::new("h.py"), &[], &[]),
    )
    .unwrap();
    assert!(output.documents.is_empty() && output.raw.is_empty());
}

#[test]
fn a_result_file_over_the_limit_is_refused_without_reading_it() {
    let scene = Scene::new();
    let mut fake = FakeReplayScript::new("{}\n");
    fake.result_len = Some(MAX_RESULT_BYTES + 1);
    let error = run_script(
        &scene.env(&fake),
        &scene.home(),
        &run(Path::new("h.py"), &[], &[]),
    )
    .unwrap_err();
    assert_eq!(error.code, Code::ToolFailed);
    assert!(
        error.message.contains(&format!("{}", MAX_RESULT_BYTES + 1))
            && error.message.contains(&format!("{MAX_RESULT_BYTES}")),
        "(result file): expected the limit {MAX_RESULT_BYTES} and the size {} named | received {}",
        MAX_RESULT_BYTES + 1,
        error.message
    );
}
