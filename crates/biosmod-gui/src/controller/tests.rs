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
fn imported_fifo_is_refused_and_publication_keeps_non_utf8_paths() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
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
    let output = directory
        .path()
        .join(std::ffi::OsString::from_vec(b"output-\xff.bin".to_vec()));
    session.output = Some(output.clone());
    session
        .accept(
            Action::Apply,
            Payload {
                reply: Reply {
                    version: "0.1.0".into(),
                    data: serde_json::json!({"manifest_file":"lossy display text"}),
                    diagnostics: String::new(),
                },
                extra: None,
                review: None,
            },
        )
        .unwrap();
    assert_eq!(session.manifest, Some(manifest_path(&output)));
}
use serde_json::json;

fn verification_payload(data: Value) -> Payload {
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

#[test]
fn semantic_incomplete_verification_is_not_reported_as_verified() {
    let mut session = Session::new().unwrap();
    let data = json!({"complete": false, "checks": [{"check": "input-digest", "ok": true}], "skipped": [{"check": "patch-states and reproduction", "reason": "catalog unavailable"}], "notice": "Offline verification does not prove boot behavior."});
    session
        .accept(Action::Verify, verification_payload(data))
        .unwrap();
    assert_eq!(session.outcome, Outcome::VerificationIncomplete);
    assert!(session.status.contains("incomplete"));
    assert!(session.result_details.contains("catalog unavailable"));
}

#[test]
fn verification_does_not_trust_complete_without_required_checks() {
    let mut session = Session::new().unwrap();
    let data = json!({"complete": true, "checks": [], "skipped": [], "notice": "offline"});
    session
        .accept(Action::Verify, verification_payload(data))
        .unwrap();
    assert_eq!(session.outcome, Outcome::VerificationIncomplete);
}

#[test]
fn diagnostics_export_refuses_to_overwrite_and_manifest_keeps_os_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report ü.txt");
    export_diagnostics(&path, "first").unwrap();
    assert_eq!(
        export_diagnostics(&path, "second").unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read_to_string(path).unwrap(), "first");
    assert_eq!(
        manifest_path(Path::new("/tmp/name with spaces.bin")),
        PathBuf::from("/tmp/name with spaces.bin.manifest.json")
    );
}
