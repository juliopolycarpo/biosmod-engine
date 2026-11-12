//! `tools status|set|doctor` for the replay runtime, against a shell stand-in for Python.

#![cfg(unix)]

mod common;

use common::{Sandbox, s};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Answers the probe scripts bme runs the way a Python with the pinned packages would.
const FAKE_PYTHON_PINNED: &str = r#"#!/bin/sh
case "$*" in
  *importlib.metadata*) echo '{"python": "3.14.4", "packages": {"unicorn": "2.1.4", "capstone": "5.0.9", "pefile": "2024.8.26"}}' ;;
  *"selftest ok"*) echo 'selftest ok' ;;
esac
"#;

fn fake_python(sandbox: &Sandbox, script: &str) -> PathBuf {
    let program = sandbox.path("fake-python");
    fs::write(&program, script).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    program
}

#[test]
fn doctor_replay_without_a_runtime_fails_with_tool_unavailable_and_the_setup_command() {
    let sandbox = Sandbox::new();
    let run = sandbox.run(["tools", "doctor", "replay", "--json"]);
    assert_eq!(run.error_code(), "TOOL_UNAVAILABLE", "{}", run.stdout);
    let message = run.json()["error"]["message"].to_string();
    assert!(message.contains("replay-python"), "{message}");
    let details = run.json()["error"]["details"].to_string();
    assert!(
        details.contains("run `bme tools setup replay`"),
        "(doctor details): expected the setup command | received {details}"
    );
}

#[test]
fn plain_doctor_skips_a_replay_runtime_nobody_installed() {
    let sandbox = Sandbox::new();
    let run = sandbox.run(["tools", "doctor", "--json"]);
    let text = run.stdout.clone() + &run.stderr;
    assert!(
        !text.contains("replay-"),
        "(plain doctor): expected no replay check without a runtime | received {text}"
    );
}

#[test]
fn set_status_doctor_and_paths_agree_on_a_saved_replay_interpreter() {
    let sandbox = Sandbox::new();
    let python = fake_python(&sandbox, FAKE_PYTHON_PINNED);
    let set = sandbox.run(["tools", "set", "replay", s(&python), "--json"]);
    assert_eq!(set.code, 0, "{}", set.stdout);
    assert_eq!(
        set.json()["data"]["version"],
        "unicorn 2.1.4, capstone 5.0.9, pefile 2024.8.26"
    );
    let status = sandbox.run(["tools", "status", "--json"]).json();
    let row = status["data"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == "replay")
        .unwrap_or_else(|| panic!("(tools status): expected a replay row | received {status}"));
    assert_eq!(
        (
            row["health"].as_str(),
            row["origin"].as_str(),
            row["optional"].as_bool()
        ),
        (Some("ready"), Some("config"), Some(true)),
        "{row}"
    );
    let doctor = sandbox.run(["tools", "doctor", "replay", "--deep", "--json"]);
    assert_eq!(doctor.code, 0, "{}", doctor.stdout);
    let names: Vec<String> = doctor.json()["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["check"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        names,
        ["replay-python", "replay-packages", "replay-emulation"]
    );
    let paths = sandbox.run(["tools", "paths", "--json"]).json();
    assert_eq!(paths["data"]["replay"]["origin"], "config", "{paths}");
    let unset = sandbox.run(["tools", "unset", "replay", "--json"]);
    assert_eq!(unset.code, 0, "{}", unset.stdout);
    let paths = sandbox.run(["tools", "paths", "--json"]).json();
    assert_eq!(paths["data"]["replay"]["origin"], "managed", "{paths}");
}

#[test]
fn set_refuses_a_python_without_the_pinned_packages() {
    let sandbox = Sandbox::new();
    let python = fake_python(
        &sandbox,
        "#!/bin/sh\necho '{\"python\": \"3.14.4\", \"packages\": {\"unicorn\": null, \"capstone\": null, \"pefile\": null}}'\n",
    );
    let run = sandbox.run(["tools", "set", "replay", s(&python), "--json"]);
    assert_eq!(
        (run.code, run.error_code().as_str()),
        (2, "USAGE"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout
            .contains("unicorn: expected 2.1.4 | received none"),
        "{}",
        run.stdout
    );
}

#[test]
fn offline_setup_without_a_wheelhouse_is_refused_before_anything_runs() {
    let sandbox = Sandbox::new();
    let run = sandbox.run(["--offline", "tools", "setup", "replay", "--json"]);
    assert_eq!(run.error_code(), "SOURCE_UNAVAILABLE", "{}", run.stdout);
    assert!(run.stdout.contains("--wheelhouse"), "{}", run.stdout);
}
