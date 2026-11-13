//! `bme replay run`, against a shell stand-in for the replay Python. The stand-in reports what
//! the runtime reports for a scenario with one expectation: one expectation document and a
//! summary. Emulation itself is covered by `tools/tests`; the real module by `real_roms.rs`.

#![cfg(unix)]

mod common;

use biosmod_core::catalog::Evidence;
use biosmod_core::util::Digest256;
use common::{Sandbox, s};
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const MODULE: &[u8] = b"MZ module bytes";

/// The launcher call arrives as `-I -B -c <launcher> <package dir> --scenario S --module M`.
const PASSING_PYTHON: &str = r#"#!/bin/sh
case "$*" in
  *importlib.metadata*)
    echo '{"python": "3.14.4", "packages": {"unicorn": "2.1.4", "capstone": "5.0.9", "pefile": "2024.8.26"}}' ;;
  *bme_replay.__main__*)
    shift 5
    echo '{"expectation": 0, "kind": "return", "passed": true, "expected": 7, "received": 7, "scenario": "synthetic"}' >> "$BME_REPLAY_RESULT"
    echo "{\"summary\": true, \"passed\": true, \"argv\": \"$*\"}" >> "$BME_REPLAY_RESULT" ;;
esac
"#;

const FAILING_EXPECTATION_PYTHON: &str = r#"#!/bin/sh
case "$*" in
  *importlib.metadata*)
    echo '{"python": "3.14.4", "packages": {"unicorn": "2.1.4", "capstone": "5.0.9", "pefile": "2024.8.26"}}' ;;
  *bme_replay.__main__*)
    echo '{"expectation": 0, "kind": "return", "passed": false, "expected": 7, "received": 9, "scenario": "synthetic"}' >> "$BME_REPLAY_RESULT"
    echo '{"summary": true, "passed": false, "scenario": "synthetic"}' >> "$BME_REPLAY_RESULT" ;;
esac
"#;

fn fake_python(sandbox: &Sandbox, script: &str) -> PathBuf {
    let program = sandbox.path("fake-python");
    fs::write(&program, script).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    program
}

fn scenario_text(module_sha256: &str) -> String {
    json!({
        "schema": "bme.scenario/1",
        "id": "synthetic",
        "description": "returns seven",
        "module": {"sha256": module_sha256, "bitness": 64},
        "entry": {"rva": "0x1000"},
        "budget": 1000,
        "expect": [{"kind": "return", "equals": 7}]
    })
    .to_string()
}

/// A scenario for `MODULE` and the module itself.
fn inputs(sandbox: &Sandbox) -> (PathBuf, PathBuf) {
    let scenario = sandbox.path("synthetic.json");
    let module = sandbox.path("Synthetic.pe");
    fs::write(&scenario, scenario_text(&Digest256::of(MODULE).to_string())).unwrap();
    fs::write(&module, MODULE).unwrap();
    (scenario, module)
}

#[test]
fn a_passing_scenario_reports_each_expectation_and_records_the_run() {
    let sandbox = Sandbox::new();
    let python = fake_python(&sandbox, PASSING_PYTHON);
    let (scenario, module) = inputs(&sandbox);
    let out = sandbox.path("out");
    let run = sandbox.run_with_env(
        [
            "replay",
            "run",
            s(&scenario),
            "--module",
            s(&module),
            "-o",
            s(&out),
            "--board",
            "mr9a",
            "--json",
        ],
        &[("BME_REPLAY_PYTHON", &python)],
    );
    assert_eq!(run.code, 0, "{}\n{}", run.stdout, run.stderr);
    let reply = run.json();
    assert_eq!(reply["data"]["passed"], true, "{reply}");
    assert_eq!(reply["data"]["expectations"][0]["received"], 7, "{reply}");

    let record: Evidence =
        serde_json::from_slice(&fs::read(out.join("evidence.json")).unwrap()).unwrap();
    let replay = record.replay.expect("a replay block");
    assert_eq!(replay.scenario.as_deref(), Some("synthetic"));
    let roles: Vec<(&str, &str)> = replay
        .inputs
        .iter()
        .map(|i| (i.role.as_str(), i.name.as_str()))
        .collect();
    assert_eq!(
        roles,
        [("scenario", "synthetic.json"), ("module", "Synthetic.pe")]
    );
    assert_eq!(replay.inputs[1].sha256, Digest256::of(MODULE));
    assert_eq!(record.board, "mr9a");
    assert!(
        record
            .observations
            .contains(&"synthetic: 1 of 1 expectations passed".to_string()),
        "{:?}",
        record.observations
    );
}

#[test]
fn the_runtime_gets_the_scenario_and_the_module() {
    let sandbox = Sandbox::new();
    let python = fake_python(&sandbox, PASSING_PYTHON);
    let (scenario, module) = inputs(&sandbox);
    let run = sandbox.run_with_env(
        [
            "replay",
            "run",
            s(&scenario),
            "--module",
            s(&module),
            "--json",
        ],
        &[("BME_REPLAY_PYTHON", &python)],
    );
    assert_eq!(run.code, 0, "{}\n{}", run.stdout, run.stderr);
    let reply = run.json();
    let argv = reply["data"]["documents"][1]["argv"]
        .as_str()
        .unwrap()
        .to_string();
    let words: Vec<&str> = argv.split(' ').collect();
    assert_eq!(words[0], "--scenario", "(runtime argv) {argv}");
    assert_ne!(
        words[1],
        s(&scenario),
        "(scenario argument): expected bme's scratch copy | received the user's file"
    );
    assert_eq!(words[2], "--scenario-sha256", "(runtime argv) {argv}");
    assert_eq!(words[3].len(), 64, "(scenario digest) {argv}");
    assert_eq!(
        &words[4..],
        ["--module", s(&module)],
        "(runtime argv): expected the module last | received {argv}"
    );
}

#[test]
fn a_failed_expectation_fails_the_command_but_the_record_is_still_written() {
    let sandbox = Sandbox::new();
    let python = fake_python(&sandbox, FAILING_EXPECTATION_PYTHON);
    let (scenario, module) = inputs(&sandbox);
    let out = sandbox.path("out");
    let run = sandbox.run_with_env(
        [
            "replay",
            "run",
            s(&scenario),
            "--module",
            s(&module),
            "-o",
            s(&out),
            "--json",
        ],
        &[("BME_REPLAY_PYTHON", &python)],
    );
    assert_eq!(run.error_code(), "REPLAY_FAILED", "{}", run.stdout);
    let error = run.json()["error"].clone();
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("expected every expectation to pass | received 0 of 1 expectations passed (expectation 0 (return): expected 7 | received 9)"),
        "{error}"
    );
    assert_eq!(
        error["details"]["expectations"][0]["expected"], 7,
        "{error}"
    );
    assert_eq!(
        error["details"]["expectations"][0]["received"], 9,
        "{error}"
    );
    assert!(out.join("evidence.json").is_file());
    assert!(out.join("result.jsonl").is_file());
}

#[test]
fn a_module_with_another_digest_is_refused_before_the_runtime_starts() {
    let sandbox = Sandbox::new();
    let (scenario, module) = inputs(&sandbox);
    fs::write(&module, b"another module").unwrap();
    // No runtime is configured: reaching it would be TOOL_UNAVAILABLE.
    let run = sandbox.run([
        "replay",
        "run",
        s(&scenario),
        "--module",
        s(&module),
        "--json",
    ]);
    assert_eq!(run.error_code(), "PATCH_SOURCE_MISMATCH", "{}", run.stdout);
    let message = run.json()["error"]["message"].as_str().unwrap().to_string();
    assert!(
        message.contains(&format!(
            "expected module sha256 {} | received {}",
            Digest256::of(MODULE),
            Digest256::of(b"another module")
        )),
        "{message}"
    );
}

#[test]
fn a_scenario_with_an_unknown_field_is_refused_naming_it() {
    let sandbox = Sandbox::new();
    let (scenario, module) = inputs(&sandbox);
    let text = fs::read_to_string(&scenario)
        .unwrap()
        .replace("\"budget\"", "\"budgett\"");
    fs::write(&scenario, text).unwrap();
    let run = sandbox.run([
        "replay",
        "run",
        s(&scenario),
        "--module",
        s(&module),
        "--json",
    ]);
    assert_eq!(run.error_code(), "SCENARIO_INVALID", "{}", run.stdout);
    assert!(run.stdout.contains("budgett"), "{}", run.stdout);
}

#[test]
fn a_missing_runtime_is_tool_unavailable_with_the_setup_command() {
    let sandbox = Sandbox::new();
    let (scenario, module) = inputs(&sandbox);
    let run = sandbox.run([
        "replay",
        "run",
        s(&scenario),
        "--module",
        s(&module),
        "--json",
    ]);
    assert_eq!(run.error_code(), "TOOL_UNAVAILABLE", "{}", run.stdout);
}

#[test]
fn an_output_directory_that_holds_results_is_refused_before_anything_runs() {
    let sandbox = Sandbox::new();
    let python = fake_python(&sandbox, PASSING_PYTHON);
    let (scenario, module) = inputs(&sandbox);
    let out = sandbox.path("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("result.jsonl"), "").unwrap();
    let run = sandbox.run_with_env(
        [
            "replay",
            "run",
            s(&scenario),
            "--module",
            s(&module),
            "-o",
            s(&out),
            "--json",
        ],
        &[("BME_REPLAY_PYTHON", &python)],
    );
    assert_eq!(run.error_code(), "OUTPUT_EXISTS", "{}", run.stdout);
}

/// A runtime that stopped in `phase`: its one expectation failed and the summary names the error.
fn python_stopping_in(phase: &str) -> String {
    format!(
        r#"#!/bin/sh
case "$*" in
  *importlib.metadata*)
    echo '{{"python": "3.14.4", "packages": {{"unicorn": "2.1.4", "capstone": "5.0.9", "pefile": "2024.8.26"}}}}' ;;
  *bme_replay.__main__*)
    echo '{{"expectation": 0, "kind": "return", "passed": false, "expected": null, "received": null, "scenario": "synthetic"}}' >> "$BME_REPLAY_RESULT"
    echo '{{"summary": true, "passed": false, "scenario": "synthetic", "error": {{"phase": "{phase}", "type": "Boom", "message": "stopped in {phase}"}}}}' >> "$BME_REPLAY_RESULT" ;;
esac
"#
    )
}

#[test]
fn the_phase_a_run_stopped_in_picks_the_error_code() {
    for (phase, code) in [
        ("setup", "SCENARIO_INVALID"),
        ("call", "REPLAY_FAILED"),
        ("evaluate", "TOOL_FAILED"),
    ] {
        let sandbox = Sandbox::new();
        let python = fake_python(&sandbox, &python_stopping_in(phase));
        let (scenario, module) = inputs(&sandbox);
        let run = sandbox.run_with_env(
            [
                "replay",
                "run",
                s(&scenario),
                "--module",
                s(&module),
                "--json",
            ],
            &[("BME_REPLAY_PYTHON", &python)],
        );
        assert_eq!(
            run.error_code(),
            code,
            "(phase {phase}): expected {code} | received {}",
            run.stdout
        );
        assert!(
            run.stdout.contains(&format!("stopped in {phase}")),
            "(phase {phase}): expected the runtime's message in the reply | received {}",
            run.stdout
        );
    }
}
