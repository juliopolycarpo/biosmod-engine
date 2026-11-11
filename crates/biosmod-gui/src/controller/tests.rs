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
fn incomplete_verification_must_match_the_build_receipt() {
    let expected_digest = "a".repeat(64);
    let changed_digest = "b".repeat(64);
    for (digest, version, expected_outcome) in [
        (
            expected_digest.as_str(),
            "1.0.0",
            Outcome::VerificationIncomplete,
        ),
        (
            changed_digest.as_str(),
            "1.0.0",
            Outcome::VerificationFailed,
        ),
        (
            expected_digest.as_str(),
            "1.0.1",
            Outcome::VerificationFailed,
        ),
    ] {
        let mut session = Session::new().unwrap();
        session.open_output(PathBuf::from("/tmp/output.bin"));
        session.manifest_receipt = Some(expected_digest.clone());
        session.engine_version = Some("1.0.0".into());
        let mut error = EngineError::new(ErrorKind::Engine, "catalog unavailable");
        error.code = Some("VERIFICATION_INCOMPLETE".into());
        error.version = Some(Box::new(version.into()));
        error.details = Some(json!({"manifest_sha256": digest, "complete": false}));

        session.fail(Action::Verify, error);

        assert_eq!(
            session.outcome, expected_outcome,
            "verification of manifest {digest} with engine {version}: {}",
            session.status
        );
        if expected_outcome == Outcome::VerificationFailed {
            assert!(session.verification_report.is_none());
            assert!(
                session
                    .status
                    .contains(&format!("received \"{digest}\" from version {version}")),
                "{}",
                session.status
            );
        } else {
            assert!(session.verification_report.is_some());
        }
    }
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

/// Pretends to be `bme tools ...`: answers from a script and logs every argument list.
#[cfg(unix)]
struct FakeToolsEngine {
    directory: tempfile::TempDir,
}

#[cfg(unix)]
const TOOL_ROWS: &str = r#"{"ready":false,"platform":"linux","tools":[{"id":"flashrom","name":"flashrom","purpose":"reads and writes the SPI flash chip","health":"missing","version":null,"path":null,"origin":"none","detail":"not found in PATH or the sbin directories","install":{"method":"package-manager","command":"sudo apt install flashrom","automatic":false},"custom_location":true}]}"#;

#[cfg(unix)]
impl FakeToolsEngine {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let script = format!(
            r#"echo "$@" >> "$(dirname "$0")/calls.log"
reply() {{ printf '%s' "{{\"product\":\"biosmod-engine\",\"protocol\":\"bme/1\",\"version\":\"$3\",\"command\":\"tools $1\",\"ok\":true,\"data\":$2}}"; }}
case "$1" in
  status)
    printf '%s' 'status warning' >&2
    reply status '{rows}' 0.1.0 ;;
  paths) reply paths '{{"flashrom":null}}' 0.1.0 ;;
  set) reply set '{{"tool":"flashrom"}}' 0.1.0 ;;
  unset) reply unset '{{"tool":"flashrom"}}' 0.1.0 ;;
  setup) printf '%s' 'install note' >&2; reply "setup ghidra" '{{"startup_check":true}}' 0.1.0 ;;
  *) exit 99 ;;
esac
"#,
            rows = TOOL_ROWS
        );
        std::fs::write(directory.path().join("tools"), script).unwrap();
        Self { directory }
    }

    fn engine(&self) -> Engine {
        Engine::new("/bin/sh", self.directory.path()).unwrap()
    }

    /// The argument lists the fake engine received, one per call.
    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.directory.path().join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Replace `original` in the script, failing if the fixture changed.
    fn alter(&self, original: &str, replacement: &str) {
        let path = self.directory.path().join("tools");
        let script = std::fs::read_to_string(&path).unwrap();
        assert!(script.contains(original), "fixture: expected {original}");
        std::fs::write(path, script.replacen(original, replacement, 1)).unwrap();
    }
}

#[cfg(unix)]
fn connected_session() -> Session {
    let mut session = Session::new().unwrap();
    session.connected = true;
    session.tools_supported = true;
    session.engine_contract = Some(fake_engine_contract());
    session
}

#[cfg(unix)]
#[test]
fn tools_report_keeps_rows_and_diagnostics() {
    let fake = FakeToolsEngine::new();
    let mut session = connected_session();
    let completion = session.prepare(Action::Tools).unwrap().run(&fake.engine());
    assert!(session.finish(completion));
    assert_eq!(
        session.outcome,
        Outcome::Idle,
        "tools: expected report | received {}",
        session.status
    );
    let report = session
        .tool_report
        .as_deref()
        .expect("tools: expected a report");
    assert_eq!(report["tools"][0]["id"], "flashrom");
    assert_eq!(report["tools"][0]["health"], "missing");
    assert_eq!(
        report["tools"][0]["install"]["command"],
        "sudo apt install flashrom"
    );
    assert!(session.diagnostics.contains("status warning"));
    assert_eq!(fake.calls(), ["status --json --offline"]);
}

#[cfg(unix)]
#[test]
fn malformed_status_reports_do_not_replace_the_tools_report() {
    for (original, replacement) in [
        (r#""health":"missing""#, r#""health":"odd""#),
        (r#""id":"flashrom""#, r#""id":7"#),
    ] {
        let fake = FakeToolsEngine::new();
        fake.alter(original, replacement);
        let mut session = connected_session();
        let completion = session.prepare(Action::Tools).unwrap().run(&fake.engine());
        assert!(session.finish(completion));
        assert_eq!(
            session.outcome,
            Outcome::Failed,
            "tools status: expected a rejected report for {replacement} | received {}",
            session.status
        );
        assert!(session.tool_report.is_none());
    }
}

#[cfg(unix)]
#[test]
fn choosing_a_tool_location_saves_it_then_refreshes_the_report() {
    let fake = FakeToolsEngine::new();
    let mut session = connected_session();
    session.queue_tool_change(ToolChange::Choose {
        tool: LocatableTool::Flashrom,
        path: "/opt/fr/flashrom".into(),
    });
    let completion = session
        .prepare(Action::ToolChange)
        .unwrap()
        .run(&fake.engine());
    assert!(session.finish(completion));
    assert_eq!(session.outcome, Outcome::Idle, "{}", session.status);
    assert_eq!(
        fake.calls(),
        [
            "set flashrom /opt/fr/flashrom --json --offline",
            "status --json --offline"
        ]
    );
    assert!(session.tool_report.is_some());
    assert!(session.diagnostics.contains("status warning"));
}

#[cfg(unix)]
#[test]
fn resetting_a_tool_location_runs_unset() {
    let fake = FakeToolsEngine::new();
    let mut session = connected_session();
    session.queue_tool_change(ToolChange::Reset {
        tool: LocatableTool::Ghidra,
    });
    let completion = session
        .prepare(Action::ToolChange)
        .unwrap()
        .run(&fake.engine());
    assert!(session.finish(completion));
    assert_eq!(fake.calls()[0], "unset ghidra --json --offline");
}

#[cfg(unix)]
#[test]
fn installing_ghidra_is_the_only_request_allowed_online() {
    let fake = FakeToolsEngine::new();
    let mut session = connected_session();
    session.queue_tool_change(ToolChange::InstallGhidra);
    let completion = session
        .prepare(Action::ToolInstall)
        .unwrap()
        .run(&fake.engine());
    assert!(session.finish(completion));
    assert_eq!(session.outcome, Outcome::Idle, "{}", session.status);
    let calls = fake.calls();
    assert_eq!(
        calls[0], "setup ghidra --json",
        "install must not pass --offline"
    );
    assert_eq!(calls[1], "status --json --offline");
    assert!(session.diagnostics.contains("install note"));
}

#[cfg(unix)]
#[test]
fn a_tool_change_needs_the_matching_queued_change() {
    let mut session = connected_session();
    let error = match session.prepare(Action::ToolChange) {
        Err(error) => error,
        Ok(_) => panic!("tool change: expected a refusal without a queued change"),
    };
    assert_eq!(error, PreparationError::Engine);
    session.queue_tool_change(ToolChange::InstallGhidra);
    let error = match session.prepare(Action::ToolChange) {
        Err(error) => error,
        Ok(_) => panic!("tool change: expected a refusal for an install queued as a change"),
    };
    assert_eq!(error, PreparationError::Engine);
}

#[cfg(unix)]
#[test]
fn a_tool_change_followed_by_a_status_of_another_version_is_rejected() {
    let fake = FakeToolsEngine::new();
    fake.alter(
        r#"0.1.0 ;;
  paths)"#,
        r#"0.2.0 ;;
  paths)"#,
    );
    let mut session = connected_session();
    session.queue_tool_change(ToolChange::Reset {
        tool: LocatableTool::Flashrom,
    });
    let job = session.prepare(Action::ToolChange).unwrap();
    let error = match job.execute(&fake.engine()) {
        Ok(_) => panic!("tools: expected a version mismatch | received success"),
        Err(error) => error,
    };
    assert!(
        error
            .message
            .contains("expected matching change and status versions | received 0.1.0 and 0.2.0"),
        "{error:?}"
    );
}

#[cfg(unix)]
#[test]
fn tools_honor_cancellation_before_starting() {
    let fake = FakeToolsEngine::new();
    let mut session = connected_session();
    let job = session.prepare(Action::Tools).unwrap();
    job.cancel.store(true, Ordering::Relaxed);
    let error = match job.execute(&fake.engine()) {
        Ok(_) => panic!("tools cancellation: expected refusal | received success"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Cancelled);
}

#[cfg(unix)]
fn write_flash_doctor(fake: &FakeToolsEngine) {
    std::fs::write(
        fake.directory.path().join("flash"),
        r#"echo "$@" >> "$(dirname "$0")/calls.log"
printf '%s' '{"product":"biosmod-engine","protocol":"bme/1","version":"0.1.0","command":"flash doctor","ok":true,"data":{"checks":[]}}'
"#,
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn flash_commands_learn_the_saved_flashrom_before_running() {
    let fake = FakeToolsEngine::new();
    fake.alter(
        r#"'{"flashrom":null}'"#,
        r#"'{"flashrom":{"path":"/opt/fr/flashrom","origin":"config"}}'"#,
    );
    write_flash_doctor(&fake);
    let mut session = connected_session();
    session.flash.supported = true;
    let job = session.prepare(Action::FlashDoctor).unwrap();
    job.execute(&fake.engine()).unwrap();
    let calls = fake.calls();
    assert_eq!(
        calls[0], "paths --json --offline",
        "(flash job): expected the cheap paths lookup, not a tool probe"
    );
    assert_eq!(
        calls[1],
        "doctor --programmer=internal --json --offline --flashrom=/opt/fr/flashrom"
    );
}

#[cfg(unix)]
#[test]
fn flash_commands_repeat_an_environment_flashrom_that_pkexec_would_drop() {
    let fake = FakeToolsEngine::new();
    fake.alter(
        r#"'{"flashrom":null}'"#,
        r#"'{"flashrom":{"path":"/opt/env/flashrom","origin":"BME_FLASHROM"}}'"#,
    );
    write_flash_doctor(&fake);
    let mut session = connected_session();
    session.flash.supported = true;
    let job = session.prepare(Action::FlashDoctor).unwrap();
    job.execute(&fake.engine()).unwrap();
    assert_eq!(
        fake.calls()[1],
        "doctor --programmer=internal --json --offline --flashrom=/opt/env/flashrom",
        "(flash job, BME_FLASHROM origin): expected the environment flashrom on the command line"
    );
}

#[cfg(unix)]
#[test]
fn flash_commands_leave_a_path_flashrom_to_the_engine_lookup() {
    let fake = FakeToolsEngine::new();
    fake.alter(
        r#"'{"flashrom":null}'"#,
        r#"'{"flashrom":{"path":"/usr/sbin/flashrom","origin":"PATH"}}'"#,
    );
    write_flash_doctor(&fake);
    let mut session = connected_session();
    session.flash.supported = true;
    let job = session.prepare(Action::FlashDoctor).unwrap();
    job.execute(&fake.engine()).unwrap();
    assert_eq!(
        fake.calls()[1],
        "doctor --programmer=internal --json --offline",
        "(flash job, PATH origin): expected no --flashrom flag"
    );
}

#[cfg(unix)]
#[test]
fn flash_commands_add_no_flashrom_flag_without_a_saved_one() {
    let fake = FakeToolsEngine::new();
    write_flash_doctor(&fake);
    let mut session = connected_session();
    session.flash.supported = true;
    session
        .prepare(Action::FlashDoctor)
        .unwrap()
        .execute(&fake.engine())
        .unwrap();
    assert_eq!(
        fake.calls()[1],
        "doctor --programmer=internal --json --offline"
    );
}

#[cfg(unix)]
#[test]
fn a_failed_flashrom_lookup_stops_the_flash_command_instead_of_using_path() {
    let fake = FakeToolsEngine::new();
    fake.alter("  paths) reply paths", "  paths) exit 3; reply paths");
    write_flash_doctor(&fake);
    let mut session = connected_session();
    session.flash.supported = true;
    let result = session
        .prepare(Action::FlashDoctor)
        .unwrap()
        .execute(&fake.engine());
    assert!(
        result.is_err(),
        "(flash job, failing tools paths): expected an error | received a reply"
    );
    assert!(
        fake.calls().iter().all(|call| !call.starts_with("doctor")),
        "(flash job): expected no flash command after a failed lookup | received {:?}",
        fake.calls()
    );
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

/// A connected session whose engine advertises the flash commands.
fn flash_session() -> Session {
    let mut session = Session::new().unwrap();
    session.connected = true;
    session.engine_contract = Some(fake_engine_contract());
    session.flash.supported = true;
    session.flash.elevate = false;
    session
}

fn checked_flash_session() -> Session {
    let mut session = flash_session();
    session.edit_flash(|flash| {
        flash.programmer = " ch341a_spi ".into();
        flash.image = Some("/images/patched.bin".into());
        flash.backup = Some("/images/dump.bin".into());
    });
    let digest = "c".repeat(64);
    session
        .accept(
            Action::FlashCheck,
            reply_payload(json!({"dry_run": true, "written": false, "image_sha256": digest, "confirm": digest, "regions": []})),
        )
        .unwrap();
    session
}

#[test]
fn flash_actions_name_their_missing_inputs() {
    let mut session = flash_session();
    for (action, expected) in [
        (Action::FlashBackup, PreparationError::FlashBackup),
        (Action::FlashCheck, PreparationError::FlashImage),
        (Action::FlashWrite, PreparationError::FlashCheck),
    ] {
        assert_eq!(session.prepare(action).err(), Some(expected), "{action:?}");
    }
    session.edit_flash(|flash| flash.programmer = "  ".into());
    assert_eq!(
        session.prepare(Action::FlashDoctor).err(),
        Some(PreparationError::Programmer)
    );
    session.flash.supported = false;
    assert_eq!(
        session.prepare(Action::FlashProbe).err(),
        Some(PreparationError::FlashUnsupported)
    );
    assert!(!session.busy());
}

#[test]
fn a_check_covers_only_the_inputs_it_ran_with() {
    let mut session = checked_flash_session();
    assert!(session.flash_checked());
    assert_eq!(session.status_kind, Status::FlashChecked);
    assert_eq!(
        session.prepare(Action::FlashWrite).err(),
        Some(PreparationError::FlashAcknowledge),
        "(write): expected the recovery confirmation to be required"
    );
    session.edit_flash(|flash| flash.acknowledged = true);
    assert!(
        session.can_flash_write(),
        "(acknowledging): expected the check to stay valid"
    );
    session.edit_flash(|flash| flash.elevate = true);
    assert!(session.can_flash_write(), "(elevation): not a write input");

    session.edit_flash(|flash| flash.image = Some("/images/other.bin".into()));
    assert!(!session.flash_checked() && !session.flash.acknowledged);
    assert_eq!(session.status_kind, Status::FlashInputs);
    assert_eq!(
        session.prepare(Action::FlashWrite).err(),
        Some(PreparationError::FlashCheck)
    );
}

#[test]
fn flash_write_repeats_the_checked_inputs_and_digest() {
    let mut session = checked_flash_session();
    session.edit_flash(|flash| flash.acknowledged = true);
    let job = session.prepare(Action::FlashWrite).unwrap();
    let Request::FlashWrite {
        programmer,
        image,
        backup,
        confirm,
        ..
    } = &job.request
    else {
        panic!(
            "(flash write job): expected a flash write request | received {:?}",
            job.request
        );
    };
    assert_eq!(programmer, "ch341a_spi");
    assert_eq!(
        (image, backup),
        (
            &PathBuf::from("/images/patched.bin"),
            &PathBuf::from("/images/dump.bin")
        )
    );
    assert_eq!(confirm.as_deref(), Some("c".repeat(64).as_str()));
    assert!(session.flashing() && session.publishing());
}

#[test]
fn flash_receipts_must_match_the_request() {
    let mut session = flash_session();
    session.edit_flash(|flash| flash.backup = Some("/images/dump.bin".into()));
    let error = session
        .accept(
            Action::FlashBackup,
            reply_payload(json!({"output": "/elsewhere/dump.bin", "sha256": "d".repeat(64)})),
        )
        .unwrap_err();
    assert!(
        error.message.contains("expected the requested output path"),
        "{error}"
    );
    session
        .accept(
            Action::FlashBackup,
            reply_payload(json!({"output": "/images/dump.bin", "sha256": "d".repeat(64)})),
        )
        .unwrap();
    assert_eq!(session.status, "Chip backed up to /images/dump.bin");

    let error = session
        .accept(
            Action::FlashCheck,
            reply_payload(json!({"dry_run": true, "written": false, "image_sha256": "e".repeat(64), "confirm": "f".repeat(64)})),
        )
        .unwrap_err();
    assert!(
        error
            .message
            .contains("expected the image SHA-256 to confirm"),
        "{error}"
    );
    assert!(!session.flash_checked());
    assert!(
        session
            .accept(Action::FlashProbe, reply_payload(json!({"chips": []})))
            .is_err()
    );
}

#[test]
fn flash_write_outcomes_separate_refusal_success_and_unknown() {
    let written = |digest: &str| json!({"written": true, "verified": true, "image_sha256": digest});

    let mut session = checked_flash_session();
    session
        .accept(Action::FlashWrite, reply_payload(written(&"c".repeat(64))))
        .unwrap();
    assert_eq!(session.outcome, Outcome::ChipWritten);
    assert_eq!(session.status_kind, Status::FlashWritten);
    assert!(
        !session.flash_checked(),
        "(after writing): expected a new check before another write"
    );

    let mut session = checked_flash_session();
    let error = session
        .accept(Action::FlashWrite, reply_payload(written(&"0".repeat(64))))
        .unwrap_err();
    session.fail(Action::FlashWrite, error);
    assert_eq!(session.outcome, Outcome::ChipWriteUnknown);

    let mut refused = EngineError::new(
        ErrorKind::Engine,
        "chip at 0x3040 (bios): expected the backup byte",
    );
    refused.code = Some("FLASH_REFUSED".into());
    let mut session = checked_flash_session();
    session.fail(Action::FlashWrite, refused);
    assert_eq!(session.outcome, Outcome::Failed);
    assert_eq!(session.status_kind, Status::Failed);
    assert!(
        matches!(
            session.flash.report.as_deref(),
            Some(FlashReport::Failure(message, _)) if message.starts_with("FLASH_REFUSED: chip at 0x3040")
        ),
        "(flash report): expected the refusal | received {:?}",
        session.flash.report
    );

    for error in [
        {
            let mut failed = EngineError::new(ErrorKind::Engine, "read-back after writing");
            failed.code = Some("FLASH_FAILED".into());
            failed
        },
        EngineError::new(ErrorKind::Interrupted, "engine process interrupted"),
    ] {
        let mut session = checked_flash_session();
        session.fail(Action::FlashWrite, error);
        assert_eq!(session.outcome, Outcome::ChipWriteUnknown);
        assert_eq!(session.status_kind, Status::FlashOutcomeUnknown);
        assert!(
            session.status.contains("restore the backup"),
            "{}",
            session.status
        );
        assert!(!session.flash_checked());
    }
}

#[test]
fn flash_failures_leave_the_patch_workflow_results_alone() {
    let mut session = flash_session();
    session.result_details = "verification report".into();
    session.fail(
        Action::FlashProbe,
        EngineError::new(ErrorKind::Configuration, "administrator rights: dismissed"),
    );
    assert_eq!(session.result_details, "verification report");
    assert_eq!(session.outcome, Outcome::Failed);
    assert!(session.diagnostics.contains("administrator rights"));
}

#[test]
fn connecting_enables_flash_only_for_engines_that_advertise_it() {
    let capabilities = |flash: Value| {
        let mut data = json!({
            "verification_required_checks": ["input-digest"],
            "exit_codes": {"ok":0, "failed":1, "usage":2, "publication_incomplete":3},
            "error_codes":[{"code":"USAGE","exit":2}, {"code":"PUBLISH_INCOMPLETE","exit":3},
                {"code":"VERIFICATION_INCOMPLETE","exit":1}]
        });
        data["flash_workflow"] = flash;
        data
    };
    let mut session = Session::new().unwrap();
    session
        .accept(Action::Connect, reply_payload(capabilities(json!(1))))
        .unwrap();
    assert!(session.flash.supported);
    session
        .accept(Action::Connect, reply_payload(capabilities(Value::Null)))
        .unwrap();
    assert!(!session.flash.supported);
}

#[test]
fn an_engine_without_tools_workflow_refuses_the_tools_page_and_drops_the_queued_change() {
    let mut session = Session::new().unwrap();
    session.connected = true;
    session.engine_contract = Some(fake_engine_contract());
    session.queue_tool_change(ToolChange::InstallGhidra);
    for action in [Action::Tools, Action::ToolInstall] {
        let error = session.prepare(action).err();
        assert_eq!(
            error,
            Some(PreparationError::ToolsUnsupported),
            "({action:?}, engine without tools_workflow): expected a refusal"
        );
    }
    session.tools_supported = true;
    assert_eq!(
        session.prepare(Action::ToolInstall).err(),
        Some(PreparationError::Engine),
        "(queued change): expected the refused install to have dropped the queue"
    );
}

#[cfg(unix)]
#[test]
fn a_failed_flashrom_lookup_before_a_write_does_not_claim_the_chip_changed() {
    let fake = FakeToolsEngine::new();
    fake.alter("  paths) reply paths", "  paths) exit 3; reply paths");
    write_flash_doctor(&fake);
    let mut session = connected_session();
    session.flash.supported = true;
    session.flash.acknowledged = true;
    session.flash.checked = Some(CheckedWrite {
        programmer: "internal".into(),
        image: "/tmp/image.bin".into(),
        backup: "/tmp/backup.bin".into(),
        whole_chip: false,
        image_sha256: "0".repeat(64),
    });
    let job = session.prepare(Action::FlashWrite).unwrap();
    assert!(session.finish(job.run(&fake.engine())));
    assert_eq!(
        (session.status_kind, session.outcome),
        (Status::Failed, Outcome::Failed),
        "(flash write, failing tools paths): expected a plain failure, nothing ran | received {:?} and {:?}",
        session.status_kind,
        session.outcome
    );
    assert!(
        fake.calls()
            .iter()
            .all(|call| !call.starts_with("doctor") && !call.contains("write")),
        "(flash write): expected no flash command | received {:?}",
        fake.calls()
    );
}
