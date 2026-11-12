//! `bme replay script`, against a shell stand-in for the replay Python. The stand-in answers
//! the version probe and, for the launcher, appends documents to `BME_REPLAY_RESULT` the way
//! `bme_replay.emit` does. The emulation itself is covered by `tools/tests`.

#![cfg(unix)]

mod common;

use biosmod_core::catalog::{Evidence, EvidenceKind};
use biosmod_core::util::Digest256;
use common::{Sandbox, s};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// The launcher call arrives as `-I -B -c <launcher> <package dir> <harness> [--module M]... [-- ARGS]`.
const FAKE_PYTHON: &str = r#"#!/bin/sh
case "$*" in
  *importlib.metadata*)
    echo '{"python": "3.14.4", "packages": {"unicorn": "2.1.4", "capstone": "5.0.9", "pefile": "2024.8.26"}}' ;;
  *bme_replay.__main__*)
    shift 4
    shift 1
    echo "{\"case\": 1, \"argv\": \"$*\"}" >> "$BME_REPLAY_RESULT"
    echo '{"case": 2}' >> "$BME_REPLAY_RESULT" ;;
esac
"#;

const FAILING_PYTHON: &str = r#"#!/bin/sh
case "$*" in
  *importlib.metadata*)
    echo '{"python": "3.14.4", "packages": {"unicorn": "2.1.4", "capstone": "5.0.9", "pefile": "2024.8.26"}}' ;;
  *bme_replay.__main__*)
    echo "bme_replay.errors.UnmodeledAccess: port 0x80 read size 1" >&2
    exit 1 ;;
esac
"#;

fn fake_python(sandbox: &Sandbox, script: &str) -> PathBuf {
    let program = sandbox.path("fake-python");
    fs::write(&program, script).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    program
}

fn inputs(sandbox: &Sandbox) -> (PathBuf, PathBuf) {
    let harness = sandbox.path("fan.py");
    let module = sandbox.path("SioDxeInit.pe");
    fs::write(&harness, "print('harness')\n").unwrap();
    fs::write(&module, b"MZ module bytes").unwrap();
    (harness, module)
}

#[test]
fn a_run_writes_the_documents_and_an_evidence_record_that_names_every_input() {
    let sandbox = Sandbox::new();
    let python = fake_python(&sandbox, FAKE_PYTHON);
    let (harness, module) = inputs(&sandbox);
    let out = sandbox.path("out");
    let run = sandbox.run_with_env(
        [
            "replay",
            "script",
            s(&harness),
            "--module",
            s(&module),
            "-o",
            s(&out),
            "--board",
            "mr9a",
            "--firmware",
            "mr9a-230322",
            "--json",
            "--",
            "--case",
            "3",
        ],
        &[("BME_REPLAY_PYTHON", &python)],
    );
    assert_eq!(run.code, 0, "{}\n{}", run.stdout, run.stderr);
    let reply = run.json();
    let documents = reply["data"]["documents"].as_array().unwrap();
    assert_eq!(documents.len(), 2, "{reply}");
    assert_eq!(
        documents[0]["argv"],
        format!("{} --module {} -- --case 3", s(&harness), s(&module)),
        "(harness argv): expected the harness, its modules and the arguments after `--`"
    );

    let raw = fs::read_to_string(out.join("result.jsonl")).unwrap();
    assert_eq!(raw.lines().count(), 2, "{raw}");
    let record: Evidence =
        serde_json::from_slice(&fs::read(out.join("evidence.json")).unwrap()).unwrap();
    assert_eq!(record.kind, EvidenceKind::OfflineValidation);
    assert_eq!(
        (record.board.as_str(), record.firmware.as_str()),
        ("mr9a", "mr9a-230322")
    );
    let replay = record.replay.expect("a replay block");
    assert_eq!(replay.harness, "fan.py");
    assert_eq!(replay.runtime["unicorn"], "2.1.4");
    assert_eq!(replay.runtime["python"], "3.14.4");
    assert_eq!(replay.output_sha256, Digest256::of(raw.as_bytes()));
    let digests: Vec<(String, String, Digest256)> = replay
        .inputs
        .iter()
        .map(|i| (i.role.clone(), i.name.clone(), i.sha256))
        .collect();
    assert_eq!(
        digests,
        [
            (
                "harness".to_string(),
                "fan.py".to_string(),
                Digest256::of(b"print('harness')\n")
            ),
            (
                "module".to_string(),
                "SioDxeInit.pe".to_string(),
                Digest256::of(b"MZ module bytes")
            ),
        ]
    );
    assert!(record.id.starts_with("replay-fan-"), "{}", record.id);
}

#[test]
fn a_run_without_an_output_directory_still_returns_the_record() {
    let sandbox = Sandbox::new();
    let python = fake_python(&sandbox, FAKE_PYTHON);
    let (harness, _) = inputs(&sandbox);
    let run = sandbox.run_with_env(
        ["replay", "script", s(&harness), "--json"],
        &[("BME_REPLAY_PYTHON", &python)],
    );
    assert_eq!(run.code, 0, "{}\n{}", run.stdout, run.stderr);
    let reply = run.json();
    assert_eq!(reply["data"]["written"], serde_json::json!([]), "{reply}");
    assert_eq!(reply["data"]["evidence"]["board"], "unscoped", "{reply}");
}

#[test]
fn an_output_directory_that_holds_results_is_refused_before_anything_runs() {
    let sandbox = Sandbox::new();
    let python = fake_python(&sandbox, FAKE_PYTHON);
    let (harness, _) = inputs(&sandbox);
    let out = sandbox.path("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("evidence.json"), "{}").unwrap();
    let run = sandbox.run_with_env(
        ["replay", "script", s(&harness), "-o", s(&out), "--json"],
        &[("BME_REPLAY_PYTHON", &python)],
    );
    assert_eq!(run.error_code(), "OUTPUT_EXISTS", "{}", run.stdout);
    assert!(!out.join("result.jsonl").exists());
}

#[test]
fn a_missing_runtime_is_tool_unavailable_with_the_setup_command() {
    let sandbox = Sandbox::new();
    let (harness, _) = inputs(&sandbox);
    let run = sandbox.run(["replay", "script", s(&harness), "--json"]);
    assert_eq!(run.error_code(), "TOOL_UNAVAILABLE", "{}", run.stdout);
    let message = run.json()["error"]["message"].as_str().unwrap().to_string();
    assert!(
        message.ends_with("(run `bme tools setup replay`)"),
        "(message): expected the setup command | received {message}"
    );
}

#[test]
fn a_harness_that_exits_nonzero_is_tool_failed_with_its_stderr() {
    let sandbox = Sandbox::new();
    let python = fake_python(&sandbox, FAILING_PYTHON);
    let (harness, _) = inputs(&sandbox);
    let run = sandbox.run_with_env(
        ["replay", "script", s(&harness), "--json"],
        &[("BME_REPLAY_PYTHON", &python)],
    );
    assert_eq!(run.error_code(), "TOOL_FAILED", "{}", run.stdout);
    assert!(
        run.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("UnmodeledAccess: port 0x80 read size 1"),
        "{}",
        run.stdout
    );
}

#[test]
fn a_missing_harness_file_is_an_io_error_naming_the_path() {
    let sandbox = Sandbox::new();
    let python = fake_python(&sandbox, FAKE_PYTHON);
    let missing = sandbox.path("nope.py");
    let run = sandbox.run_with_env(
        ["replay", "script", s(&missing), "--json"],
        &[("BME_REPLAY_PYTHON", &python)],
    );
    assert_eq!(run.error_code(), "IO", "{}", run.stdout);
    assert!(run.stdout.contains("nope.py"), "{}", run.stdout);
}
