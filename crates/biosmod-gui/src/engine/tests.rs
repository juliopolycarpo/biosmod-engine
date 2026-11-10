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
    let req = Request::Plan {
        image: "-firmware with spaces.bin".into(),
        source: "lab".into(),
        selection: vec!["lab::PA@1.0.0".into(), "lab::DG@1.0.0".into()],
        output: "new plan.json".into(),
    };
    let args = req.args(Path::new("/tmp/work")).unwrap();
    assert_eq!(
        args,
        [
            "plan",
            "/tmp/work/-firmware with spaces.bin",
            "--catalog=lab",
            "--select=lab::PA@1.0.0,lab::DG@1.0.0",
            "--output=/tmp/work/new plan.json",
            "--json",
            "--offline"
        ]
        .map(OsString::from)
    );
    let invalid = Request::Plan {
        image: "a".into(),
        source: "lab".into(),
        selection: vec!["a,b".into()],
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
        "plan",
        "patch",
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
        data: json!({"engine":"0.1.0", "protocol":"bme/1", "commands": commands, "documents": docs, "desktop_workflow": 1}),
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
        for command in ["version", "patch"] {
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
    let request = Request::Patch {
        image: "image".into(),
        plan: "plan".into(),
        output: "output".into(),
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
    let request = Request::Patch {
        image: "image".into(),
        plan: "plan".into(),
        output: "output".into(),
    };
    let result = fake
        .engine()
        .with_contract(Arc::new(fake_contract()))
        .with_timeout(Duration::from_millis(1))
        .run(&request, &AtomicBool::new(true));
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
fn verify_uses_engine_default_manifest_for_raw_output_path() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let output = PathBuf::from(OsString::from_vec(b"output-\xff.bin".to_vec()));
    let request = Request::Verify {
        input: "/tmp/input.bin".into(),
        output: output.clone(),
        plan: "/tmp/review.json".into(),
    };
    let args = request.args(Path::new("/tmp")).unwrap();
    assert!(
        args.iter()
            .any(|arg| arg.as_bytes() == b"/tmp/output-\xff.bin"),
        "verify output: expected raw bytes | received {args:?}"
    );
    assert!(
        !args
            .iter()
            .any(|arg| arg.as_bytes().starts_with(b"--manifest")),
        "verify arguments: expected engine default manifest | received {args:?}"
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
        panic!("BME_SUPERVISION_SCENARIO: expected version or large | received {scenario:?}");
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
