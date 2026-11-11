use super::*;
use serde_json::json;
use std::sync::atomic::AtomicBool;

fn envelope(command: &str, ok: bool, body: Value) -> Vec<u8> {
    let mut value = json!({"product": "biosmod-engine", "protocol": "bme/1", "version": "0.1.0", "command": command, "ok": ok});
    value[if ok { "data" } else { "error" }] = body;
    serde_json::to_vec(&value).unwrap()
}

fn fake_capability_contract() -> Value {
    json!({
        "verification_required_checks": ["input-digest", "patch-states"],
        "exit_codes": {"ok": 0, "failed": 1, "usage": 2, "publication_incomplete": 3},
        "error_codes": [
            {"code":"USAGE", "exit":2},
            {"code":"PUBLISH_INCOMPLETE", "exit":3},
            {"code":"VERIFICATION_INCOMPLETE", "exit":1},
            {"code":"IO", "exit":1}
        ]
    })
}

fn fake_contract() -> EngineContract {
    EngineContract::from_capabilities(&fake_capability_contract()).unwrap()
}

#[test]
fn arguments_keep_paths_and_qualified_selection_as_separate_arguments() {
    let selection = ScannedSelection {
        source: "lab".into(),
        ids: vec!["lab::PA@1.0.0".into(), "lab::DG@1.0.0".into()],
        input_sha256: "0".repeat(64),
        source_sha256: "1".repeat(64),
    };
    let request = Request::Build {
        image: "-firmware with spaces.bin".into(),
        selection: PatchSelection::Scanned(selection.clone()),
        destination: PatchDestination::Publish("new output.bin".into()),
    };
    let args = request.args(Path::new("/tmp/work")).unwrap();
    assert_eq!(
        &args[..6],
        &[
            "patch",
            "/tmp/work/-firmware with spaces.bin",
            "--output=/tmp/work/new output.bin",
            "--json",
            "--offline",
            "--catalog=lab",
        ]
        .map(OsString::from)
    );
    assert_eq!(
        &args[6..],
        &[
            format!("--expect-input-sha256={}", selection.input_sha256),
            format!("--expect-source-sha256={}", selection.source_sha256),
            "--".into(),
            "lab::PA@1.0.0".into(),
            "lab::DG@1.0.0".into(),
        ]
        .map(OsString::from)
    );
    let invalid = Request::Export {
        image: "a".into(),
        selection: ScannedSelection {
            ids: Vec::new(),
            ..selection
        },
        output: "b".into(),
    };
    assert_eq!(
        invalid.args(Path::new("/tmp")).unwrap_err().kind,
        ErrorKind::Configuration
    );
}

#[cfg(unix)]
#[test]
fn arguments_preserve_non_utf8_paths() {
    use std::os::unix::ffi::OsStringExt;
    let image = PathBuf::from(OsString::from_vec(b"image-\xff.bin".to_vec()));
    let request = Request::Inspect {
        image: image.clone(),
    };
    let args = request.args(Path::new("/tmp")).unwrap();
    assert_eq!(args[1], Path::new("/tmp").join(image).into_os_string());
}

#[test]
fn decodes_only_consistent_envelopes() {
    let bytes = envelope("scan", true, json!({"sources": []}));
    assert_eq!(
        decode("scan", 0, &bytes, "note").unwrap().data["sources"],
        json!([])
    );
    assert_eq!(
        decode("plan", 0, &bytes, "").unwrap_err().kind,
        ErrorKind::Protocol
    );
    assert_eq!(
        decode("scan", 1, &bytes, "").unwrap_err().kind,
        ErrorKind::Protocol
    );
    assert_eq!(
        decode("scan", 0, b"{", "").unwrap_err().kind,
        ErrorKind::Protocol
    );
    let wrong_protocol = String::from_utf8(bytes).unwrap().replace("bme/1", "bme/2");
    assert_eq!(
        decode("scan", 0, wrong_protocol.as_bytes(), "")
            .unwrap_err()
            .kind,
        ErrorKind::Protocol
    );
    let bad = envelope(
        "usage",
        false,
        json!({"code": "USAGE", "message": "invalid args"}),
    );
    let error = decode("scan", 2, &bad, "warning").unwrap_err();
    assert_eq!(
        (
            error.kind,
            error.code.as_deref(),
            error.diagnostics.as_str()
        ),
        (ErrorKind::Engine, Some("USAGE"), "warning")
    );
    assert_eq!(
        decode_with_contract("scan", 1, &bad, "", Some(&fake_contract()))
            .unwrap_err()
            .kind,
        ErrorKind::Protocol
    );
    let incomplete = envelope(
        "patch",
        false,
        json!({"code": "PUBLISH_INCOMPLETE", "message": "partial", "details": {"output": "a"}}),
    );
    let error = decode("patch", 3, &incomplete, "").unwrap_err();
    assert_eq!(error.details.unwrap()["output"], "a");
    let two = [
        envelope("scan", true, json!({})),
        envelope("scan", true, json!({})),
    ]
    .concat();
    assert_eq!(
        decode("scan", 0, &two, "").unwrap_err().kind,
        ErrorKind::Protocol
    );
    let mut invalid: Value = serde_json::from_slice(&envelope("scan", true, json!({}))).unwrap();
    invalid["error"] = Value::Null;
    assert_eq!(
        decode("scan", 0, &serde_json::to_vec(&invalid).unwrap(), "")
            .unwrap_err()
            .kind,
        ErrorKind::Protocol
    );
    let null_data = envelope("scan", true, Value::Null);
    assert_eq!(decode("scan", 0, &null_data, "").unwrap().data, Value::Null);
    let bad_code = envelope("scan", false, json!({"code":"bad-code", "message":"wrong"}));
    assert_eq!(
        decode("scan", 1, &bad_code, "").unwrap_err().kind,
        ErrorKind::Protocol
    );
}

#[test]
fn verification_requires_complete_unique_passing_checks() {
    let contract = fake_contract();
    let checks: Vec<Value> = contract
        .required_checks
        .iter()
        .map(|name| json!({"check": name, "ok": true}))
        .collect();
    let mut data = json!({"complete": true, "checks": checks, "skipped": [], "notice": "offline"});
    assert!(verification_complete(&data, &contract).unwrap());
    data["complete"] = json!(false);
    assert!(!verification_complete(&data, &contract).unwrap());
    data["complete"] = json!(true);
    data["skipped"] = json!([{"check": "x", "reason": "unavailable"}]);
    assert!(!verification_complete(&data, &contract).unwrap());
    data["skipped"] = json!([]);
    data["checks"][0]["ok"] = json!(false);
    assert!(!verification_complete(&data, &contract).unwrap());
    data["checks"][0]["ok"] = json!(true);
    let duplicate = data["checks"][0].clone();
    data["checks"].as_array_mut().unwrap().push(duplicate);
    assert!(!verification_complete(&data, &contract).unwrap());
    data["notice"] = json!(null);
    assert_eq!(
        verification_complete(&data, &contract).unwrap_err().kind,
        ErrorKind::Protocol
    );
}

#[test]
fn handshake_requires_matching_identity_and_advertised_contract() {
    let commands = [
        "inspect",
        "scan",
        "export",
        "patch",
        "patch --dry-run",
        "verify",
        "catalog validate|index|show|import-x99fix",
        "catalog add|list|remove",
        "tools doctor|paths",
    ]
    .map(|name| json!({"name": name}));
    let docs = [
        ("plan", "bme.plan/1"),
        ("manifest", "bme.manifest/1"),
        ("catalog", "bme.catalog/1"),
        ("patch", "bme.patch/1"),
    ]
    .map(|(name, schema)| json!({"name": name, "schema": schema}));
    let version = Reply {
        version: "0.1.0".into(),
        data: json!({"engine":"0.1.0", "protocol":"bme/1"}),
        diagnostics: String::new(),
    };
    let mut cap = Reply {
        version: "0.1.0".into(),
        data: json!({"engine":"0.1.0", "protocol":"bme/1", "commands": commands, "documents": docs, "desktop_workflow": 1, "direct_patch_workflow": 1}),
        diagnostics: String::new(),
    };
    cap.data
        .as_object_mut()
        .unwrap()
        .extend(fake_capability_contract().as_object().unwrap().clone());
    assert!(validate_handshake(&version, &cap).is_ok());
    cap.data["engine"] = json!("0.2.0");
    let mismatch = validate_handshake(&version, &cap).unwrap_err();
    assert!(
        mismatch.message.contains("0.2.0") && mismatch.message.contains("0.1.0"),
        "handshake mismatch: expected both engine versions in the message | received {}",
        mismatch.message
    );
    cap.data["engine"] = json!("0.1.0");
    cap.data.as_object_mut().unwrap().remove("desktop_workflow");
    let failure = validate_handshake(&version, &cap).unwrap_err();
    assert_eq!(failure.kind, ErrorKind::Protocol);
    assert!(failure.message.contains("desktop_workflow"));
    cap.data["desktop_workflow"] = json!(2);
    assert_eq!(
        validate_handshake(&version, &cap).unwrap_err().kind,
        ErrorKind::Protocol
    );
    cap.data["desktop_workflow"] = json!(1);
    cap.data
        .as_object_mut()
        .unwrap()
        .remove("direct_patch_workflow");
    let failure = validate_handshake(&version, &cap).unwrap_err();
    assert!(failure.message.contains("direct_patch_workflow"));
    assert!(failure.message.contains("matching bundled bme"));
    cap.data["direct_patch_workflow"] = json!(1);
    cap.data["documents"][0]["schema"] = json!("bme.plan/2");
    assert_eq!(
        validate_handshake(&version, &cap).unwrap_err().kind,
        ErrorKind::Protocol
    );
}

#[cfg(unix)]
#[test]
fn timeout_covers_inherited_pipes_after_leader_exits() {
    let fake = FakeEngine::new("printf warning >&2; sleep 1 & exit 0");
    let started = Instant::now();
    let error = fake
        .engine()
        .with_timeout(Duration::from_millis(50))
        .run(&Request::Version, &AtomicBool::new(false))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
    assert_eq!(error.diagnostics, "warning");
    assert!(
        started.elapsed() < Duration::from_millis(700),
        "timeout should not wait for a descendant holding pipes"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn timeout_does_not_wait_for_a_descendant_that_escaped_the_group() {
    let fake = FakeEngine::new("setsid sh -c 'exec sleep 1' & echo $! > child.pid; exit 0");
    let started = Instant::now();
    let error = fake
        .engine()
        .with_timeout(Duration::from_millis(80))
        .run(&Request::Version, &AtomicBool::new(false))
        .unwrap_err();
    let pid: i32 = std::fs::read_to_string(fake.dir.path().join("child.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: this PID is the test-owned escaped process, recorded by its parent.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    assert_eq!(error.kind, ErrorKind::Timeout);
    assert!(started.elapsed() < Duration::from_millis(700));
}

#[cfg(target_os = "linux")]
#[test]
fn timeout_terminates_descendants_in_the_owned_process_group() {
    let fake = FakeEngine::new("sleep 10 & echo $! > child.pid; exit 0");
    let error = fake
        .engine()
        .with_timeout(Duration::from_millis(80))
        .run(&Request::Version, &AtomicBool::new(false))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
    let pid: u32 = std::fs::read_to_string(fake.dir.path().join("child.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let stat = PathBuf::from(format!("/proc/{pid}/stat"));
    let stopped = (0..50).any(|_| {
        let state = std::fs::read_to_string(&stat).ok();
        let dead = state.as_deref().is_none_or(|s| {
            s.rsplit_once(") ")
                .is_some_and(|(_, rest)| rest.starts_with('Z'))
        });
        if !dead {
            thread::sleep(Duration::from_millis(10));
        }
        dead
    });
    assert!(stopped, "child {pid}: expected termination after timeout");
}

#[cfg(unix)]
#[test]
fn cancellation_covers_inherited_pipes_after_leader_exits() {
    let fake = FakeEngine::new("sleep 1 & exit 0");
    let cancelled = std::sync::Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    let trigger = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        flag.store(true, Ordering::Relaxed);
    });
    let started = Instant::now();
    let error = fake
        .engine()
        .run(&Request::Version, &cancelled)
        .unwrap_err();
    trigger.join().unwrap();
    assert_eq!(error.kind, ErrorKind::Cancelled);
    assert!(
        started.elapsed() < Duration::from_millis(700),
        "cancellation should not wait for a descendant holding pipes"
    );
}

#[test]
fn drain_bounds_storage_without_stopping_reader() {
    let result = drain(&b"abcdef"[..], 3).unwrap();
    assert_eq!(result.bytes, b"abc");
    assert!(result.overflow);
    assert!(!drain(&b"abc"[..], 3).unwrap().overflow);
}

#[cfg(unix)]
struct FakeEngine {
    dir: tempfile::TempDir,
    path: PathBuf,
}
#[cfg(unix)]
impl FakeEngine {
    fn new(script: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        // /bin/sh reads the fake command file as data. Executing a freshly written
        // script directly can race the host's executable scanner and return ETXTBSY.
        for command in ["version", "patch", "export"] {
            std::fs::write(dir.path().join(command), script).unwrap();
        }
        let path = PathBuf::from("/bin/sh");
        Self { dir, path }
    }
    fn engine(&self) -> Engine {
        Engine::new(&self.path, self.dir.path()).unwrap()
    }
}

#[cfg(unix)]
#[test]
fn engine_drains_streams_and_preserves_bounded_diagnostics() {
    let fake = FakeEngine::new(
        "head -c 300000 /dev/zero | tr '\\0' x >&2\nprintf '%s' '{\"product\":\"biosmod-engine\",\"protocol\":\"bme/1\",\"version\":\"0.1.0\",\"command\":\"version\",\"ok\":true,\"data\":{}}'",
    );
    let reply = fake
        .engine()
        .with_env("BME_CONFIG_HOME", fake.dir.path())
        .run(&Request::Version, &AtomicBool::new(false))
        .unwrap();
    assert!(reply.diagnostics.ends_with("[diagnostics truncated]"));
    assert!(reply.diagnostics.len() < MAX_DIAGNOSTICS + 100);
}

#[cfg(unix)]
#[test]
fn engine_reports_launch_timeout_and_cancel_separately() {
    let fake = FakeEngine::new("exec sleep 10");
    let missing = Engine::new(fake.dir.path().join("missing"), fake.dir.path()).unwrap();
    assert_eq!(
        missing
            .run(&Request::Version, &AtomicBool::new(false))
            .unwrap_err()
            .kind,
        ErrorKind::Launch
    );
    let engine = fake.engine().with_timeout(Duration::from_millis(40));
    let timeout = engine
        .run(&Request::Version, &AtomicBool::new(false))
        .unwrap_err();
    assert_eq!(timeout.kind, ErrorKind::Timeout, "{timeout:?}");
    assert_eq!(
        engine
            .run(&Request::Version, &AtomicBool::new(true))
            .unwrap_err()
            .kind,
        ErrorKind::Cancelled
    );
    assert_eq!(
        Engine::new("relative", fake.dir.path()).unwrap_err().kind,
        ErrorKind::Configuration
    );
}

#[cfg(unix)]
#[test]
fn subprocess_replies_distinguish_malformed_output_and_incomplete_publication() {
    let malformed = FakeEngine::new("printf '%s' '{incomplete'; printf '%s' 'engine warning' >&2");
    let error = malformed
        .engine()
        .run(&Request::Version, &AtomicBool::new(false))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Protocol);
    assert_eq!(error.diagnostics, "engine warning");

    let incomplete = FakeEngine::new(
        "printf '%s' '{\"product\":\"biosmod-engine\",\"protocol\":\"bme/1\",\"version\":\"0.1.0\",\"command\":\"patch\",\"ok\":false,\"error\":{\"code\":\"PUBLISH_INCOMPLETE\",\"message\":\"image exists without manifest\",\"details\":{\"output\":\"retained.bin\"}}}'; exit 3",
    );
    let request = Request::Build {
        image: "image".into(),
        selection: PatchSelection::Recipe("selection.json".into()),
        destination: PatchDestination::Publish("output".into()),
    };
    let error = incomplete
        .engine()
        .with_contract(Arc::new(fake_contract()))
        .run(&request, &AtomicBool::new(false))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Engine);
    assert_eq!(error.code.as_deref(), Some("PUBLISH_INCOMPLETE"));
    assert_eq!(error.details.unwrap()["output"], "retained.bin");
}

#[cfg(unix)]
#[test]
fn engine_drains_oversized_json_and_reports_interruptions() {
    let oversized =
        FakeEngine::new("head -c 300000 /dev/zero >&2 & head -c 67108865 /dev/zero; wait");
    let error = oversized
        .engine()
        .run(&Request::Version, &AtomicBool::new(false))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::OutputLimit);
    assert!(error.diagnostics.ends_with("[diagnostics truncated]"));

    let interrupted = FakeEngine::new("kill -TERM $$");
    assert_eq!(
        interrupted
            .engine()
            .run(&Request::Version, &AtomicBool::new(false))
            .unwrap_err()
            .kind,
        ErrorKind::Interrupted
    );
}

#[cfg(unix)]
#[test]
fn publication_is_not_killed_by_cancel_or_read_timeout() {
    let fake = FakeEngine::new(
        "sleep 0.1; printf '%s' '{\"product\":\"biosmod-engine\",\"protocol\":\"bme/1\",\"version\":\"0.1.0\",\"command\":\"patch\",\"ok\":true,\"data\":{}}'",
    );
    let scanned = ScannedSelection {
        source: "lab".into(),
        ids: vec!["lab::PA@1.0.0".into()],
        input_sha256: "0".repeat(64),
        source_sha256: "1".repeat(64),
    };
    let engine = fake
        .engine()
        .with_contract(Arc::new(fake_contract()))
        .with_timeout(Duration::from_millis(1));
    let cancel = AtomicBool::new(true);
    for selection in [
        PatchSelection::Scanned(scanned.clone()),
        PatchSelection::Recipe("selection.json".into()),
    ] {
        let request = Request::Build {
            image: "image".into(),
            selection,
            destination: PatchDestination::Publish("output".into()),
        };
        let result = engine.run(&request, &cancel);
        assert!(result.is_ok(), "{result:?}");
    }
    let preview = Request::Build {
        image: "image".into(),
        selection: PatchSelection::Scanned(scanned.clone()),
        destination: PatchDestination::Preview,
    };
    assert_eq!(
        engine.run(&preview, &cancel).unwrap_err().kind,
        ErrorKind::Cancelled
    );

    let export_engine = FakeEngine::new(
        "sleep 0.1; printf '%s' '{\"product\":\"biosmod-engine\",\"protocol\":\"bme/1\",\"version\":\"0.1.0\",\"command\":\"export\",\"ok\":true,\"data\":{}}'",
    );
    let result = export_engine
        .engine()
        .with_contract(Arc::new(fake_contract()))
        .with_timeout(Duration::from_millis(1))
        .run(
            &Request::Export {
                image: "image".into(),
                selection: scanned,
                output: "selection.json".into(),
            },
            &cancel,
        );
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn advertised_exit_codes_control_envelope_validation() {
    let mut data = fake_capability_contract();
    data["exit_codes"] = json!({"ok":0, "failed":11, "usage":12, "publication_incomplete":13});
    data["error_codes"] = json!([
        {"code":"USAGE", "exit":12}, {"code":"PUBLISH_INCOMPLETE", "exit":13},
        {"code":"VERIFICATION_INCOMPLETE", "exit":11}, {"code":"IO", "exit":11}
    ]);
    let contract = EngineContract::from_capabilities(&data).unwrap();
    let failure = envelope("scan", false, json!({"code":"IO", "message":"not found"}));
    let received = decode_with_contract("scan", 11, &failure, "", Some(&contract)).unwrap_err();
    assert_eq!(received.kind, ErrorKind::Engine);
    let mismatch = decode_with_contract("scan", 1, &failure, "", Some(&contract)).unwrap_err();
    assert_eq!(mismatch.kind, ErrorKind::Protocol);
    assert!(
        mismatch.message.contains("11") && mismatch.message.contains("1"),
        "{mismatch}"
    );
    let unknown = envelope(
        "scan",
        false,
        json!({"code":"UNADVERTISED", "message":"not found"}),
    );
    assert_eq!(
        decode_with_contract("scan", 11, &unknown, "", Some(&contract))
            .unwrap_err()
            .kind,
        ErrorKind::Protocol
    );
    let success = envelope("scan", true, json!({}));
    assert_eq!(
        decode_with_contract("scan", 11, &success, "", Some(&contract))
            .unwrap_err()
            .kind,
        ErrorKind::Protocol
    );
}

#[test]
fn handshake_rejects_invalid_verification_and_exit_contracts() {
    let valid = fake_capability_contract();
    let mut invalid = Vec::new();
    for checks in [
        json!(null),
        json!([]),
        json!(["x", "x"]),
        json!([""]),
        json!([1]),
    ] {
        let mut data = valid.clone();
        data["verification_required_checks"] = checks;
        invalid.push(data);
    }
    for exits in [
        json!(null),
        json!({"ok":0,"failed":1,"usage":1,"publication_incomplete":3}),
        json!({"ok":1,"failed":2,"usage":3,"publication_incomplete":4}),
    ] {
        let mut data = valid.clone();
        data["exit_codes"] = exits;
        invalid.push(data);
    }
    let mut missing = valid.clone();
    missing["error_codes"] = json!([]);
    invalid.push(missing);
    let mut duplicate = valid.clone();
    duplicate["error_codes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"code":"USAGE","exit":2}));
    invalid.push(duplicate);
    for data in invalid {
        let error = EngineContract::from_capabilities(&data).unwrap_err();
        assert_eq!(
            error.kind,
            ErrorKind::Protocol,
            "invalid capability: {data}"
        );
        assert!(error.message.contains("received"), "{error}");
    }
}

#[test]
fn verification_uses_the_advertised_checks_and_rejects_malformed_rows() {
    let mut data = fake_capability_contract();
    data["verification_required_checks"] = json!(["new-check"]);
    let contract = EngineContract::from_capabilities(&data).unwrap();
    let mut report = json!({"complete":true, "checks":[{"check":"new-check", "ok":true}], "skipped":[], "notice":"offline"});
    assert!(verification_complete(&report, &contract).unwrap());
    report["checks"] = json!([]);
    assert!(!verification_complete(&report, &contract).unwrap());
    report["checks"] = json!([{"check":"new-check", "ok":true}, {"check":"new-check", "ok":true}]);
    assert!(!verification_complete(&report, &contract).unwrap());
    report["checks"] = json!([{"check":"new-check", "ok":false}]);
    assert!(!verification_complete(&report, &contract).unwrap());
    report["checks"] = json!([{"check":"new-check", "ok":"true"}]);
    assert!(!verification_complete(&report, &contract).unwrap());
}

#[test]
fn duplicate_unadvertised_verification_checks_are_incomplete() {
    let contract = fake_contract();
    let report = json!({"complete":true, "checks":[
        {"check":"input-digest", "ok":true}, {"check":"patch-states", "ok":true},
        {"check":"future-check", "ok":true}, {"check":"future-check", "ok":true}
    ], "skipped":[], "notice":"offline"});
    assert!(
        !verification_complete(&report, &contract).unwrap(),
        "verification: expected duplicate future-check to be incomplete | received complete"
    );
}

#[cfg(unix)]
#[test]
fn verify_preserves_native_output_and_manifest_paths() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let output = PathBuf::from(OsString::from_vec(b"output-\xff.bin".to_vec()));
    let request = Request::VerifyResult {
        input: "/tmp/input.bin".into(),
        output: output.clone(),
        manifest: crate::controller::manifest_path(&output),
        recipe: None,
    };
    let args = request.args(Path::new("/tmp")).unwrap();
    assert!(
        args.iter()
            .any(|arg| arg.as_bytes() == b"/tmp/output-\xff.bin"),
        "verify output: expected raw bytes | received {args:?}"
    );
    assert!(
        args.iter()
            .any(|arg| arg.as_bytes() == b"--manifest=/tmp/output-\xff.bin.manifest.json"),
        "verify manifest: expected raw bytes | received {args:?}"
    );
}

#[test]
fn malformed_verification_fields_name_the_expected_type_and_received_value() {
    let contract = fake_contract();
    for (field, expected) in [
        ("complete", "a boolean"),
        ("checks", "an array"),
        ("skipped", "an array"),
        ("notice", "a string"),
    ] {
        let mut report =
            json!({"complete": false, "checks": [], "skipped": [], "notice": "offline"});
        report[field] = json!(42);
        let error = verification_complete(&report, &contract).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Protocol);
        assert_eq!(
            error.message,
            format!("verification {field}: expected {expected} | received 42"),
            "verification {field}: expected a diagnostic naming its type and invalid value"
        );
    }
}

/// Measure one complete version request or an 8 MiB JSON reply; run only during a reserved timing slot.
#[cfg(unix)]
#[test]
#[ignore = "manual supervision timing probe"]
fn supervision_timing_probe() {
    let scenario = std::env::var("BME_SUPERVISION_SCENARIO").expect("BME_SUPERVISION_SCENARIO");
    let cancel = AtomicBool::new(false);
    if scenario == "version" {
        let binary = PathBuf::from(std::env::var_os("BME_TEST_ENGINE").expect("BME_TEST_ENGINE"));
        let directory = tempfile::tempdir().unwrap();
        let engine = Engine::new(binary, directory.path()).unwrap();
        let start = Instant::now();
        let reply = engine.run(&Request::Version, &cancel).unwrap();
        let elapsed = start.elapsed();
        assert!(!reply.version.is_empty());
        println!(
            "supervision_sample scenario=version elapsed_ns={}",
            elapsed.as_nanos()
        );
    } else if scenario == "handshake" {
        let binary = PathBuf::from(std::env::var_os("BME_TEST_ENGINE").expect("BME_TEST_ENGINE"));
        let directory = tempfile::tempdir().unwrap();
        let engine = Engine::new(binary, directory.path()).unwrap();
        let start = Instant::now();
        let reply = engine.handshake(&cancel).unwrap();
        let elapsed = start.elapsed();
        assert!(!reply.version.is_empty());
        println!(
            "supervision_sample scenario=handshake elapsed_ns={}",
            elapsed.as_nanos()
        );
    } else if scenario == "scan" || scenario == "tools" {
        use crate::controller::{Action, Outcome, Session};
        let binary = PathBuf::from(std::env::var_os("BME_TEST_ENGINE").expect("BME_TEST_ENGINE"));
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let fixture = root.join("fixture");
        let mut command = Command::new(&binary);
        command
            .env("BME_CONFIG_HOME", root.join("config"))
            .env("BME_CACHE_HOME", root.join("cache"))
            .env("BME_DATA_HOME", root.join("data"));
        let output = command
            .args(["dev", "synthetic", "-o"])
            .arg(&fixture)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(&binary)
            .env("BME_CONFIG_HOME", root.join("config"))
            .env("BME_CACHE_HOME", root.join("cache"))
            .env("BME_DATA_HOME", root.join("data"))
            .args(["catalog", "add", "lab"])
            .arg(fixture.join("catalog"))
            .arg("--allow-unsigned-local")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "catalog fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let engine = Engine::new(&binary, root)
            .unwrap()
            .with_env("BME_CONFIG_HOME", root.join("config"))
            .with_env("BME_CACHE_HOME", root.join("cache"))
            .with_env("BME_DATA_HOME", root.join("data"));
        let mut session = Session::new().unwrap();
        let result = session.prepare(Action::Connect).unwrap().run(&engine);
        assert!(session.finish(result));
        assert!(session.connected, "connect: {}", session.status);
        session.image = Some(fixture.join("synthetic.bin"));
        session.source = "lab".into();
        let action = if scenario == "scan" {
            Action::Scan
        } else {
            Action::Tools
        };
        let job = session.prepare(action).unwrap();
        let start = Instant::now();
        let completion = job.run(&engine);
        let elapsed = start.elapsed();
        assert!(session.finish(completion));
        assert_eq!(
            session.outcome,
            Outcome::Idle,
            "{scenario}: {}",
            session.status
        );
        if scenario == "scan" {
            assert!(session.scan.is_some());
        } else {
            assert!(session.tool_report.is_some());
        }
        println!(
            "supervision_sample scenario={scenario} elapsed_ns={}",
            elapsed.as_nanos()
        );
    } else if scenario == "large" {
        let fake = FakeEngine::new(concat!(
            "printf '%s' '{\"product\":\"biosmod-engine\",\"protocol\":\"bme/1\",\"version\":\"0.1.0\",\"command\":\"version\",\"ok\":true,\"data\":{\"payload\":\"'\n",
            "head -c 8388608 /dev/zero | tr '\\000' a\n",
            "printf '%s' '\"}}'\n"
        ));
        let engine = fake.engine();
        let start = Instant::now();
        let reply = engine.run(&Request::Version, &cancel).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(
            reply.data["payload"].as_str().unwrap().len(),
            8 * 1024 * 1024
        );
        println!(
            "supervision_sample scenario=large elapsed_ns={}",
            elapsed.as_nanos()
        );
    } else {
        panic!(
            "BME_SUPERVISION_SCENARIO: expected version, handshake, or large | received {scenario:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn timeout_still_applies_when_child_closes_both_pipes() {
    let fake = FakeEngine::new("exec 1>&- 2>&-; sleep 10");
    let started = Instant::now();
    let error = fake
        .engine()
        .with_timeout(Duration::from_millis(50))
        .run(&Request::Version, &AtomicBool::new(false))
        .unwrap_err();
    assert_eq!(
        error.kind,
        ErrorKind::Timeout,
        "closed pipes: expected timeout | received {error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(700),
        "closed pipes: expected bounded timeout | received {:?}",
        started.elapsed()
    );
}

/// Named read-only pair fake that observes overlap and cancellation.
struct PairFixture {
    started: std::sync::atomic::AtomicUsize,
    observed_cancel: AtomicBool,
}

impl PairFixture {
    fn new() -> Self {
        Self {
            started: std::sync::atomic::AtomicUsize::new(0),
            observed_cancel: AtomicBool::new(false),
        }
    }

    fn execute(&self, cancel: &AtomicBool, fail: bool) -> Result<Reply, EngineError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_millis(500);
        while self.started.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        if self.started.load(Ordering::SeqCst) < 2 {
            return Err(EngineError::new(
                ErrorKind::Timeout,
                "pair: both workers did not start",
            ));
        }
        if fail {
            return Err(EngineError::new(ErrorKind::Protocol, "fixture failure"));
        }
        while !cancel.load(Ordering::Relaxed) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        if cancel.load(Ordering::Relaxed) {
            self.observed_cancel.store(true, Ordering::SeqCst);
            return Err(EngineError::new(ErrorKind::Cancelled, "fixture cancelled")
                .diagnostics("fixture cancellation diagnostic"));
        }
        Err(EngineError::new(
            ErrorKind::Timeout,
            "pair: cancellation was not delivered",
        ))
    }
}

#[test]
fn pair_starts_both_workers_and_cancels_peer_on_failure() {
    let fixture = PairFixture::new();
    let cancel = AtomicBool::new(false);
    let result = run_pair(
        &cancel,
        |c| fixture.execute(c, true),
        |c| fixture.execute(c, false),
    );
    let error = result.unwrap_err();
    assert_eq!(
        error.kind,
        ErrorKind::Protocol,
        "pair: expected fixture failure | received {error:?}"
    );
    assert!(
        fixture.observed_cancel.load(Ordering::SeqCst),
        "pair: expected peer cancellation"
    );
}

#[test]
fn pair_forwards_user_cancellation_to_both_workers() {
    let fixture = PairFixture::new();
    let cancel = AtomicBool::new(false);
    thread::scope(|scope| {
        scope.spawn(|| {
            while fixture.started.load(Ordering::SeqCst) < 2 {
                thread::yield_now();
            }
            cancel.store(true, Ordering::SeqCst);
        });
        let error = run_pair(
            &cancel,
            |c| fixture.execute(c, false),
            |c| fixture.execute(c, false),
        )
        .unwrap_err();
        assert_eq!(
            error.kind,
            ErrorKind::Cancelled,
            "pair: expected user cancellation | received {error:?}"
        );
        assert!(fixture.observed_cancel.load(Ordering::SeqCst));
        assert!(
            error
                .diagnostics
                .contains("fixture cancellation diagnostic")
        );
    });
}

#[cfg(unix)]
#[test]
fn pair_reaps_the_running_engine_when_its_peer_fails() {
    let failing = FakeEngine::new("sleep 0.1; printf invalid");
    let waiting = FakeEngine::new("echo $$ > child.pid; exec sleep 10");
    let first = failing.engine();
    let second = waiting.engine();
    let started = Instant::now();
    let error = run_pair(
        &AtomicBool::new(false),
        |cancel| first.run(&Request::Version, cancel),
        |cancel| second.run(&Request::Version, cancel),
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        ErrorKind::Protocol,
        "pair: expected malformed reply | received {error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "pair: expected prompt peer termination | received {:?}",
        started.elapsed()
    );
    let pid: u32 = std::fs::read_to_string(waiting.dir.path().join("child.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    #[cfg(target_os = "linux")]
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "pair: expected worker {pid} to be reaped"
    );
}

#[test]
fn append_diagnostics_retains_nonempty_messages() {
    let mut diagnostics = String::new();
    append_diagnostics(&mut diagnostics, "first");
    append_diagnostics(&mut diagnostics, "");
    append_diagnostics(&mut diagnostics, "second");
    assert_eq!(diagnostics, "first\nsecond");
}

#[cfg(unix)]
struct HandshakeWarningsEngine {
    directory: tempfile::TempDir,
}

#[cfg(unix)]
impl HandshakeWarningsEngine {
    fn new(capability_version: &str, large_warnings: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut capabilities = fake_capability_contract();
        capabilities.as_object_mut().unwrap().extend(json!({
            "engine": capability_version, "protocol":"bme/1", "desktop_workflow":1, "direct_patch_workflow":1,
            "commands":[{"name":"inspect"},{"name":"scan"},{"name":"export"},{"name":"patch"},{"name":"patch --dry-run"},{"name":"verify"},
                {"name":"catalog validate|index|show|import-x99fix"},{"name":"catalog add|list|remove"},{"name":"tools doctor|paths"}],
            "documents":[{"name":"plan","schema":"bme.plan/1"},{"name":"manifest","schema":"bme.manifest/1"},{"name":"catalog","schema":"bme.catalog/1"},{"name":"patch","schema":"bme.patch/1"}]
        }).as_object().unwrap().clone());
        for (name, version, data) in [
            (
                "version",
                "0.1.0",
                json!({"engine":"0.1.0","protocol":"bme/1"}),
            ),
            ("capabilities", capability_version, capabilities),
        ] {
            let response = json!({"product":"biosmod-engine","protocol":"bme/1","version":version,"command":name,"ok":true,"data":data});
            let warning = if large_warnings {
                "head -c 300000 /dev/zero | tr '\\000' x >&2".to_owned()
            } else {
                format!("printf '%s' '{name} warning' >&2")
            };
            let script = format!("{warning}\nprintf '%s' '{}'\n", response);
            std::fs::write(directory.path().join(name), script).unwrap();
        }
        Self { directory }
    }

    fn engine(&self) -> Engine {
        Engine::new("/bin/sh", self.directory.path()).unwrap()
    }
}

#[cfg(unix)]
#[test]
fn handshake_keeps_warnings_from_both_successful_replies() {
    let fake = HandshakeWarningsEngine::new("0.1.0", false);
    let reply = fake.engine().handshake(&AtomicBool::new(false)).unwrap();
    assert_eq!(reply.diagnostics, "version warning\ncapabilities warning");
}

#[cfg(unix)]
#[test]
fn handshake_mismatch_keeps_warnings_from_both_replies() {
    let fake = HandshakeWarningsEngine::new("0.2.0", false);
    let error = fake
        .engine()
        .handshake(&AtomicBool::new(false))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Protocol);
    assert!(error.message.contains("0.1.0") && error.message.contains("0.2.0"));
    assert_eq!(error.diagnostics, "version warning\ncapabilities warning");
}

#[cfg(unix)]
#[test]
fn handshake_warnings_remain_bounded_for_both_processes() {
    let fake = HandshakeWarningsEngine::new("0.1.0", true);
    let reply = fake.engine().handshake(&AtomicBool::new(false)).unwrap();
    assert_eq!(
        reply.diagnostics.matches("[diagnostics truncated]").count(),
        2
    );
    assert!(
        reply.diagnostics.len() <= 2 * (MAX_DIAGNOSTICS + "\n[diagnostics truncated]".len()) + 1
    );
}

#[test]
fn flash_arguments_carry_programmer_paths_and_confirmation() {
    let words = |request: &Request| -> Vec<String> {
        request
            .args(Path::new("/work"))
            .unwrap()
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    };
    assert_eq!(
        words(&Request::FlashDoctor {
            programmer: "internal".into()
        }),
        [
            "flash",
            "doctor",
            "--programmer=internal",
            "--json",
            "--offline"
        ]
    );
    let backup = Request::FlashBackup {
        programmer: "ch341a_spi".into(),
        output: "dump.bin".into(),
        elevate: true,
    };
    assert_eq!(
        words(&backup),
        [
            "flash",
            "backup",
            "--programmer=ch341a_spi",
            "--output=/work/dump.bin",
            "--json",
            "--offline"
        ]
    );
    assert!(backup.elevated() && backup.uninterruptible());
    let write = |confirm: Option<&str>, whole_chip| Request::FlashWrite {
        programmer: "linux_mtd:dev=0".into(),
        image: "/images/patched.bin".into(),
        backup: "/images/dump.bin".into(),
        whole_chip,
        confirm: confirm.map(str::to_owned),
        elevate: false,
    };
    assert_eq!(
        words(&write(None, false)),
        [
            "flash",
            "write",
            "/images/patched.bin",
            "--backup=/images/dump.bin",
            "--programmer=linux_mtd:dev=0",
            "--dry-run",
            "--json",
            "--offline"
        ]
    );
    let digest = "a".repeat(64);
    assert_eq!(
        words(&write(Some(&digest), true))[5..7],
        ["--whole-chip".to_owned(), format!("--confirm={digest}")]
    );
    assert!(
        !write(None, false).elevated() && write(None, false).uninterruptible(),
        "(flash check): expected an unprivileged request that still runs to completion"
    );
    let doctor = Request::FlashDoctor {
        programmer: "internal".into(),
    };
    assert!(!doctor.elevated() && !doctor.uninterruptible());
}

/// Stands in for the engine behind an elevation program: every flash command prints `reply`.
#[cfg(unix)]
struct FakeElevatedEngine {
    dir: tempfile::TempDir,
}

#[cfg(unix)]
impl FakeElevatedEngine {
    fn new(script: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("engine.sh"), script).unwrap();
        Self { dir }
    }

    /// `/bin/sh` plays pkexec: it runs the engine file it is handed with the same arguments.
    fn engine(&self) -> Engine {
        Engine::new(self.dir.path().join("engine.sh"), self.dir.path())
            .unwrap()
            .with_elevation("/bin/sh")
            .with_contract(Arc::new(fake_contract()))
    }
}

#[cfg(unix)]
#[test]
fn elevated_requests_run_through_the_elevation_program() {
    let fake = FakeElevatedEngine::new(
        "printf '%s' \"$*\" > arguments.txt\nprintf '%s' '{\"product\":\"biosmod-engine\",\"protocol\":\"bme/1\",\"version\":\"0.1.0\",\"command\":\"flash probe\",\"ok\":true,\"data\":{\"chips\":[{\"name\":\"W25Q128.V\"}]}}'",
    );
    let probe = |elevate| Request::FlashProbe {
        programmer: "internal".into(),
        elevate,
    };
    let reply = fake
        .engine()
        .run(&probe(true), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(reply.data["chips"][0]["name"], "W25Q128.V");
    assert_eq!(
        std::fs::read_to_string(fake.dir.path().join("arguments.txt")).unwrap(),
        "flash probe --programmer=internal --json --offline"
    );
    // Without elevation the engine file itself is executed, which this data file cannot be.
    let error = fake
        .engine()
        .run(&probe(false), &AtomicBool::new(false))
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Launch, "{error}");
}

#[cfg(unix)]
#[test]
fn dismissed_authorization_is_a_definite_refusal() {
    for status in [126, 127] {
        let fake = FakeElevatedEngine::new(&format!("echo 'Request dismissed' >&2\nexit {status}"));
        let error = fake
            .engine()
            .run(
                &Request::FlashBackup {
                    programmer: "internal".into(),
                    output: "/tmp/dump.bin".into(),
                    elevate: true,
                },
                &AtomicBool::new(false),
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Configuration, "{error}");
        assert!(
            error.message.contains(&format!(
                "expected authorization through /bin/sh | received exit status {status}"
            )),
            "{error}"
        );
        assert_eq!(error.diagnostics.trim(), "Request dismissed");
    }
    let missing = Engine::new("/missing/bme", "/")
        .unwrap()
        .with_elevation("/missing/pkexec")
        .with_contract(Arc::new(fake_contract()))
        .run(
            &Request::FlashProbe {
                programmer: "internal".into(),
                elevate: true,
            },
            &AtomicBool::new(false),
        )
        .unwrap_err();
    assert_eq!(missing.kind, ErrorKind::Launch, "{missing}");
    assert!(
        missing
            .message
            .contains("expected /missing/pkexec (polkit) to start the engine"),
        "{missing}"
    );
}
