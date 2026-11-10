use super::*;

#[test]
fn imported_jobs_reject_nonregular_files_and_stale_results() {
    let directory = tempfile::tempdir().unwrap();
    let mut session = Session::new().unwrap();
    let path = directory.path().join("plan.json");
    std::fs::write(&path, br#"{"schema":"bme.plan/1"}"#).unwrap();
    let job = session.prepare_import(&path).unwrap();
    session.invalidate();
    assert!(!session.finish(job.run()));
    assert!(session.review.is_none());
    assert!(
        session
            .import_review(directory.path())
            .unwrap_err()
            .contains("regular file")
    );
    let job = session.prepare_import(&path).unwrap();
    session.cancel.store(true, Ordering::Relaxed);
    assert!(session.finish(job.run()));
    assert_eq!(session.outcome, Outcome::Interrupted);
}

#[cfg(unix)]
#[test]
fn imported_fifo_is_refused() {
    use std::os::unix::ffi::OsStrExt;
    let directory = tempfile::tempdir().unwrap();
    let fifo = directory.path().join("plan.pipe");
    let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_path is terminated and names a file in this private test directory.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let mut session = Session::new().unwrap();
    assert!(
        session
            .import_review(&fifo)
            .unwrap_err()
            .contains("regular file")
    );
}
use serde_json::json;

fn reply_payload(data: Value) -> Payload {
    Payload {
        reply: Reply {
            version: "0.1.0".into(),
            data,
            diagnostics: String::new(),
        },
        extra: None,
        review: None,
    }
}

fn fake_engine_contract() -> Arc<EngineContract> {
    Arc::new(
        EngineContract::from_capabilities(&json!({
            "verification_required_checks": ["input-digest", "patch-states"],
            "exit_codes": {"ok":0, "failed":1, "usage":2, "publication_incomplete":3},
            "error_codes":[{"code":"USAGE","exit":2}, {"code":"PUBLISH_INCOMPLETE","exit":3},
                {"code":"VERIFICATION_INCOMPLETE","exit":1}, {"code":"TOOL_UNAVAILABLE","exit":1}]
        }))
        .unwrap(),
    )
}

#[test]
fn semantic_incomplete_verification_is_not_reported_as_verified() {
    let mut session = Session::new().unwrap();
    session.engine_contract = Some(fake_engine_contract());
    let data = json!({"complete": false, "checks": [{"check": "input-digest", "ok": true}], "skipped": [{"check": "patch-states and reproduction", "reason": "catalog unavailable"}], "notice": "Offline verification does not prove boot behavior."});
    session.accept(Action::Verify, reply_payload(data)).unwrap();
    assert_eq!(session.outcome, Outcome::VerificationIncomplete);
    assert!(session.status.contains("incomplete"));
    assert_eq!(
        session.verification_report.as_ref().unwrap()["skipped"][0]["reason"],
        "catalog unavailable",
        "incomplete verification: expected the retained report"
    );
}

#[test]
fn bounded_regular_file_read_refuses_oversized_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plan.json");
    std::fs::write(&path, b"12345").unwrap();
    assert_eq!(read_regular_file(&path, 5).unwrap(), b"12345");
    let error = read_regular_file(&path, 4).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error}");
    assert!(error.to_string().contains("at most 4 bytes"), "{error}");
}

#[test]
fn apply_refused_before_launch_does_not_report_unknown_publication() {
    let mut session = Session::new().unwrap();
    let mut error = EngineError::new(ErrorKind::Configuration, "reviewed plan changed");
    error.code = None;
    session.fail(Action::Build, error);
    assert!(
        !session.status.contains("outcome unknown"),
        "pre-launch refusal: expected a definite status | received {}",
        session.status
    );
}

#[test]
fn build_transport_failure_keeps_the_destination_and_reports_unknown_publication() {
    let mut session = Session::new().unwrap();
    let output = PathBuf::from("/tmp/output.bin");
    session.set_output(Some(output.clone()));
    session.fail(
        Action::Build,
        EngineError::new(ErrorKind::Protocol, "invalid response"),
    );
    assert_eq!(session.outcome, Outcome::PublicationUnknown);
    assert_eq!(session.status_kind, Status::PublicationUnknown);
    assert_eq!(session.output.as_ref(), Some(&output));
    assert!(session.manifest.is_none());
}

#[test]
fn engine_reported_incomplete_verification_is_summarized_not_dumped() {
    let mut session = Session::new().unwrap();
    let mut error = EngineError::new(ErrorKind::Engine, "verification: expected all checks");
    error.code = Some("VERIFICATION_INCOMPLETE".into());
    error.details = Some(
        json!({"complete": false, "checks": [{"check": "input-digest", "ok": true}], "skipped": [{"check": "patch-states and reproduction", "reason": "catalog unavailable"}], "notice": "Offline only"}),
    );
    session.fail(Action::Verify, error);
    assert_eq!(session.outcome, Outcome::VerificationIncomplete);
    assert!(
        session.result_details.is_empty()
            && session.verification_report.as_ref().unwrap()["skipped"][0]["check"]
                == "patch-states and reproduction",
        "incomplete verification: expected the retained report instead of a dump | received {}",
        session.result_details
    );
}

#[test]
fn verification_does_not_trust_complete_without_required_checks() {
    let mut session = Session::new().unwrap();
    session.engine_contract = Some(fake_engine_contract());
    let data = json!({"complete": true, "checks": [], "skipped": [], "notice": "offline"});
    session.accept(Action::Verify, reply_payload(data)).unwrap();
    assert_eq!(session.outcome, Outcome::VerificationIncomplete);
}

#[test]
fn diagnostics_export_refuses_to_overwrite_and_manifest_keeps_os_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report ü.txt");
    write_new_file(&path, b"first").unwrap();
    assert_eq!(
        write_new_file(&path, b"second").unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read_to_string(path).unwrap(), "first");
    assert_eq!(
        manifest_path(Path::new("/tmp/name with spaces.bin")),
        PathBuf::from("/tmp/name with spaces.bin.manifest.json")
    );
}

#[test]
fn imported_review_prepares_its_snapshot_before_presentation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plan.json");
    std::fs::write(
        &path,
        br#"{"schema":"bme.plan/1","notes":["retained source snapshot"]}"#,
    )
    .unwrap();
    let mut session = Session::new().unwrap();
    session.import_review(&path).unwrap();
    let review = session.review.as_ref().unwrap();
    assert!(
        review.recipe_path().is_some() && review.snapshot.as_str() == pretty(&review.document),
        "imported review: expected a read-only review with its pretty snapshot | received {:?}",
        review.snapshot
    );
}

#[test]
fn review_snapshots_share_the_retained_bytes_and_document() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plan.json");
    std::fs::write(&path, br#"{"schema":"bme.plan/1"}"#).unwrap();
    let mut session = Session::new().unwrap();
    session.import_review(&path).unwrap();
    let review = session.review.as_ref().unwrap();
    let snapshot = review.clone();
    assert_eq!(
        review.bytes.as_ptr(),
        snapshot.bytes.as_ptr(),
        "review snapshot: expected shared immutable bytes | received a full copy"
    );
    assert!(
        std::ptr::eq(&review.document, &snapshot.document),
        "review snapshot: expected a shared immutable document"
    );
}

#[test]
fn dismissed_notice_restores_the_status_it_replaced_once() {
    let mut session = Session::new().unwrap();
    session.set_detailed_status(Status::Failed, "engine stopped", "", "engine stopped");
    session.set_notice(Status::PreferencesError, "read-only", "", "first");
    session.set_notice(Status::PreferencesNoLocation, "", "", "second");
    session.dismiss_notice();
    assert_eq!(
        (
            session.status_kind,
            session.status_detail.as_str(),
            session.status.as_str()
        ),
        (Status::Failed, "engine stopped", "engine stopped"),
        "dismissed notices: expected the status before the first notice"
    );
    session.set_notice(Status::PreferencesError, "read-only", "", "notice");
    session.set_status(Status::Scanned);
    session.dismiss_notice();
    assert_eq!(
        session.status_kind,
        Status::Scanned,
        "workflow status after a notice: expected dismiss_notice to keep it"
    );
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "set_status(Failed): expected a status without details")]
fn set_status_rejects_a_status_that_needs_details() {
    Session::new().unwrap().set_status(Status::Failed);
}

#[test]
fn new_session_starts_with_the_start_guidance() {
    let session = Session::new().unwrap();
    assert_eq!(
        (session.status_kind, session.status.as_str()),
        (Status::Start, "Choose a firmware image to get started."),
        "new session status"
    );
}

#[test]
fn connected_session_uses_its_advertised_verification_checks() {
    let mut session = Session::new().unwrap();
    let capability = json!({
        "verification_required_checks": ["new-check"],
        "exit_codes": {"ok":0, "failed":1, "usage":2, "publication_incomplete":3},
        "error_codes":[{"code":"USAGE","exit":2}, {"code":"PUBLISH_INCOMPLETE","exit":3},
            {"code":"VERIFICATION_INCOMPLETE","exit":1}, {"code":"TOOL_UNAVAILABLE","exit":1}]
    });
    session
        .accept(Action::Connect, reply_payload(capability))
        .unwrap();
    let report = json!({"complete":true, "checks":[{"check":"new-check", "ok":true}], "skipped":[], "notice":"offline"});
    session
        .accept(Action::Verify, reply_payload(report))
        .unwrap();
    assert_eq!(
        session.outcome,
        Outcome::Verified,
        "advertised required check should pass"
    );
    let missing = json!({"complete":true, "checks":[{"check":"other-check", "ok":true}], "skipped":[], "notice":"offline"});
    session
        .accept(Action::Verify, reply_payload(missing))
        .unwrap();
    assert_eq!(
        session.outcome,
        Outcome::VerificationIncomplete,
        "missing advertised check must remain incomplete"
    );
    session.fail(
        Action::Connect,
        EngineError::new(ErrorKind::Protocol, "invalid capabilities"),
    );
    assert!(session.engine_contract.is_none());
}

#[test]
fn verification_refuses_a_manifest_other_than_the_engines_default() {
    let mut session = Session::new().unwrap();
    session.connected = true;
    session.engine_contract = Some(fake_engine_contract());
    session.image = Some("/tmp/original.bin".into());
    session.output = Some("/tmp/output.bin".into());
    session.manifest = Some("/tmp/other.manifest.json".into());
    session.review = Some(Arc::new(Review::imported(
        "/tmp/plan.json".into(),
        b"{}".to_vec(),
        json!({}),
    )));
    assert!(
        matches!(
            session.prepare(Action::Verify),
            Err(PreparationError::Manifest)
        ),
        "verify: expected refusal for a non-default manifest | received an accepted job"
    );
}

#[test]
fn changing_image_retains_only_imported_review_or_opened_output() {
    for (generated, keep_review, keep_output) in [
        (Some(true), false, false),
        (Some(false), true, true),
        (None, false, true),
    ] {
        let mut session = Session::new().unwrap();
        session.review = generated.map(|generated| {
            Arc::new(if generated {
                Review::preview(json!({}))
            } else {
                Review::imported("/tmp/review.json".into(), b"{}".to_vec(), json!({}))
            })
        });
        session.output = Some("/tmp/output.bin".into());
        session.manifest = Some("/tmp/output.bin.manifest.json".into());
        session.change_image(Some("/tmp/new-image.bin".into()));
        assert_eq!(
            session.review.is_some(),
            keep_review,
            "review {generated:?}: expected retained={keep_review}"
        );
        assert_eq!(
            session.output.as_deref(),
            Some(Path::new(if keep_output {
                "/tmp/output.bin"
            } else {
                "/tmp/new-image.patched.bin"
            })),
            "review {generated:?}: expected retained or default output"
        );
        assert_eq!(
            session.manifest.is_some(),
            keep_output,
            "review {generated:?}: expected manifest retained={keep_output}"
        );
        assert_eq!(
            session.image.as_deref(),
            Some(Path::new("/tmp/new-image.bin"))
        );
    }
}

#[test]
fn starting_operation_clears_previous_outcome_and_sets_busy() {
    let mut session = Session::new().unwrap();
    session.outcome = Outcome::Verified;
    let _job = session
        .prepare_import(Path::new("/tmp/review.json"))
        .unwrap();
    assert_eq!(
        session.outcome,
        Outcome::Idle,
        "starting import: expected previous verified result cleared"
    );
    assert!(session.busy(), "starting import: expected active worker");
}

#[cfg(unix)]
struct MissingToolsEngine {
    directory: tempfile::TempDir,
}

#[cfg(unix)]
impl MissingToolsEngine {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("tools"), r#"
case "$1" in
  doctor)
    printf '%s' 'doctor warning' >&2
    printf '%s' '{"product":"biosmod-engine","protocol":"bme/1","version":"0.1.0","command":"tools doctor","ok":false,"error":{"code":"TOOL_UNAVAILABLE","message":"missing optional tools","details":{"ghidra_home":{"path":"/missing/ghidra","origin":"fixture"},"checks":[{"check":"java","ok":false,"detail":"not installed"}]}}}'
    exit 1 ;;
  paths)
    printf '%s' 'paths warning' >&2
    printf '%s' '{"product":"biosmod-engine","protocol":"bme/1","version":"0.1.0","command":"tools paths","ok":true,"data":{"config":"fixture-config"}}' ;;
  *) exit 99 ;;
esac
"#).unwrap();
        Self { directory }
    }

    fn engine(&self) -> Engine {
        Engine::new("/bin/sh", self.directory.path()).unwrap()
    }
}

#[cfg(unix)]
#[test]
fn missing_optional_tools_show_doctor_checks_and_paths() {
    let fake = MissingToolsEngine::new();
    let mut session = Session::new().unwrap();
    session.connected = true;
    session.engine_contract = Some(fake_engine_contract());
    let completion = session.prepare(Action::Tools).unwrap().run(&fake.engine());
    assert!(session.finish(completion));
    assert_eq!(
        session.outcome,
        Outcome::Idle,
        "tools: expected report | received {}",
        session.status
    );
    let (doctor, paths) = session
        .tool_report
        .as_deref()
        .expect("tools: expected doctor report");
    assert_eq!(doctor["error"]["code"], "TOOL_UNAVAILABLE");
    assert_eq!(doctor["error"]["message"], "missing optional tools");
    assert_eq!(doctor["checks"][0]["check"], "java");
    assert_eq!(doctor["checks"][0]["ok"], false);
    assert_eq!(paths.as_ref().unwrap()["config"], "fixture-config");
    assert!(session.diagnostics.contains("doctor warning"));
    assert!(session.diagnostics.contains("paths warning"));
}

#[cfg(unix)]
#[test]
fn malformed_or_unrelated_doctor_failures_do_not_produce_a_tools_report() {
    for (original, replacement, expected) in [
        (
            r#""checks":[{"check":"java","ok":false,"detail":"not installed"}]"#,
            r#""checks":null"#,
            ErrorKind::Protocol,
        ),
        (
            "TOOL_UNAVAILABLE",
            "VERIFICATION_INCOMPLETE",
            ErrorKind::Engine,
        ),
        (
            r#""product":"biosmod-engine""#,
            r#""product":"unexpected-engine""#,
            ErrorKind::Protocol,
        ),
    ] {
        let fake = MissingToolsEngine::new();
        let path = fake.directory.path().join("tools");
        let script = std::fs::read_to_string(&path).unwrap();
        assert!(script.contains(original), "fixture: expected {original}");
        std::fs::write(path, script.replacen(original, replacement, 1)).unwrap();
        let mut session = Session::new().unwrap();
        session.connected = true;
        session.engine_contract = Some(fake_engine_contract());
        let job = session.prepare(Action::Tools).unwrap();
        let error = match job.execute(&fake.engine()) {
            Ok(_) => panic!("tools doctor: expected {expected:?} | received success"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind, expected,
            "tools doctor: expected {expected:?} | received {error:?}"
        );
        assert!(session.tool_report.is_none());
    }
}

#[cfg(unix)]
#[test]
fn tools_rejects_inconsistent_versions_and_honors_cancellation() {
    let fake = MissingToolsEngine::new();
    let path = fake.directory.path().join("tools");
    let script = std::fs::read_to_string(&path).unwrap();
    let original = r#""version":"0.1.0","command":"tools paths""#;
    let replacement = r#""version":"0.2.0","command":"tools paths""#;
    assert!(script.contains(original));
    std::fs::write(path, script.replacen(original, replacement, 1)).unwrap();
    let mut session = Session::new().unwrap();
    session.connected = true;
    session.engine_contract = Some(fake_engine_contract());
    let job = session.prepare(Action::Tools).unwrap();
    let error = match job.execute(&fake.engine()) {
        Ok(_) => panic!("tools versions: expected refusal | received success"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Protocol);
    assert!(error.message.contains("0.1.0") && error.message.contains("0.2.0"));
    assert!(error.diagnostics.contains("doctor warning"));
    assert!(error.diagnostics.contains("paths warning"));
    let mut session = Session::new().unwrap();
    session.connected = true;
    session.engine_contract = Some(fake_engine_contract());
    let job = session.prepare(Action::Tools).unwrap();
    job.cancel.store(true, Ordering::Relaxed);
    let error = match job.execute(&fake.engine()) {
        Ok(_) => panic!("tools cancellation: expected refusal | received success"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Cancelled);
}

#[cfg(unix)]
struct MismatchedScanEngine {
    directory: tempfile::TempDir,
}

#[cfg(unix)]
impl MismatchedScanEngine {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("scan"), r#"printf 'scan warning' >&2
printf '%s' '{"product":"biosmod-engine","protocol":"bme/1","version":"0.1.0","command":"scan","ok":true,"data":{}}'
"#).unwrap();
        std::fs::write(directory.path().join("catalog"), r#"printf 'catalog warning' >&2
printf '%s' '{"product":"biosmod-engine","protocol":"bme/1","version":"0.2.0","command":"catalog show","ok":true,"data":{}}'
"#).unwrap();
        Self { directory }
    }

    fn engine(&self) -> Engine {
        Engine::new("/bin/sh", self.directory.path()).unwrap()
    }
}

#[cfg(unix)]
#[test]
fn scan_rejects_mismatched_engine_versions_and_retains_both_diagnostics() {
    let fake = MismatchedScanEngine::new();
    let mut session = Session::new().unwrap();
    session.connected = true;
    session.engine_contract = Some(fake_engine_contract());
    session.image = Some("/tmp/fixture.bin".into());
    session.source = "lab".into();
    let job = session.prepare(Action::Scan).unwrap();
    let error = match job.execute(&fake.engine()) {
        Ok(_) => panic!("scan versions: expected refusal | received success"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Protocol);
    assert!(error.message.contains("0.1.0") && error.message.contains("0.2.0"));
    assert!(error.diagnostics.contains("scan warning"));
    assert!(error.diagnostics.contains("catalog warning"));
}
