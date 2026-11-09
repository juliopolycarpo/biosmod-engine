//! End-to-end controller coverage with the real CLI and isolated synthetic data.

use biosmod_gui::controller::{Action, Outcome, Session, manifest_path};
use biosmod_gui::engine::Engine;
use serde_json::Value;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

struct SyntheticEngine {
    directory: tempfile::TempDir,
    binary: PathBuf,
    image: PathBuf,
    engine: Engine,
}

impl SyntheticEngine {
    fn new() -> Self {
        let binary = std::env::var_os("BME_TEST_ENGINE")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/bme")
            });
        let binary = binary.canonicalize().unwrap_or_else(|error| panic!(
            "bme test engine {}: expected a built CLI executable; run cargo build -p biosmod-cli or set BME_TEST_ENGINE | received {error}",
            binary.display()
        ));
        let directory = tempfile::Builder::new()
            .prefix("bme-gui-workflow-")
            .tempdir()
            .unwrap();
        let root = directory.path();
        let fixture = root.join("synthetic fixture ü");
        let setup = |args: &[OsString]| {
            let output = Command::new(&binary)
                .args(args)
                .env("BME_CONFIG_HOME", root.join("config"))
                .env("BME_CACHE_HOME", root.join("cache"))
                .env("BME_DATA_HOME", root.join("data"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fixture setup: expected success | received {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        };
        setup(&[
            "dev".into(),
            "synthetic".into(),
            "-o".into(),
            fixture.as_os_str().into(),
        ]);
        setup(&[
            "catalog".into(),
            "add".into(),
            "lab".into(),
            fixture.join("catalog").into_os_string(),
            "--allow-unsigned-local".into(),
        ]);
        let engine = Engine::new(&binary, root)
            .unwrap()
            .with_env("BME_CONFIG_HOME", root.join("config"))
            .with_env("BME_CACHE_HOME", root.join("cache"))
            .with_env("BME_DATA_HOME", root.join("data"));
        let image = fixture.join("synthetic.bin");
        Self {
            directory,
            binary,
            image,
            engine,
        }
    }

    fn cli(&self, args: &[OsString]) -> Value {
        let root = self.directory.path();
        let output = Command::new(&self.binary)
            .args(args)
            .env("BME_CONFIG_HOME", root.join("config"))
            .env("BME_CACHE_HOME", root.join("cache"))
            .env("BME_DATA_HOME", root.join("data"))
            .arg("--json")
            .arg("--offline")
            .output()
            .unwrap();
        let value: Value =
            serde_json::from_slice(&output.stdout).expect("CLI output: expected bme JSON");
        assert!(
            output.status.success() && value["ok"] == true,
            "CLI command: expected success | received {value}"
        );
        value["data"].clone()
    }

    fn session(&self) -> Session {
        let mut session = Session::new().unwrap();
        step(&mut session, &self.engine, Action::Connect);
        session.image = Some(self.image.clone());
        session.source = "lab".into();
        step(&mut session, &self.engine, Action::Inspect);
        step(&mut session, &self.engine, Action::Scan);
        session
    }
}

fn step(session: &mut Session, engine: &Engine, action: Action) {
    let completion = session
        .prepare(action)
        .unwrap_or_else(|e| panic!("{action:?}: expected preparation | received {e}"))
        .run(engine);
    assert!(
        session.finish(completion),
        "{action:?}: expected current result"
    );
    assert_eq!(
        session.outcome,
        Outcome::Idle,
        "{action:?}: expected success | received {}",
        session.status
    );
}

#[test]
fn real_engine_controller_workflow_and_plan_safety() {
    let fixture = SyntheticEngine::new();
    let mut session = fixture.session();
    let patches = &session.scan.as_ref().unwrap().report.patches;
    let index = patches
        .iter()
        .position(|p| p.id == "PA" && p.selectable())
        .expect("synthetic PA: expected selectable correction");
    session.toggle(index);
    step(&mut session, &fixture.engine, Action::Plan);
    let reviewed = session.review.as_ref().unwrap().clone();
    assert!(reviewed.generated);
    assert!(session.review_text().contains("PA"));

    let root = fixture.directory.path();
    let output = root.join("gui output.bin");
    session.output = Some(output.clone());
    assert!(session.can_apply());
    let job = session.prepare(Action::Apply).unwrap();
    std::fs::write(&reviewed.path, b"{}").unwrap();
    assert!(session.finish(job.run(&fixture.engine)));
    assert_eq!(session.outcome, Outcome::Failed);
    assert!(
        session.status.contains("reviewed plan changed"),
        "{}",
        session.status
    );
    assert!(!output.exists());

    step(&mut session, &fixture.engine, Action::Plan);
    let approved = session.review.as_ref().unwrap().clone();
    let existing = root.join("existing.bin");
    std::fs::write(&existing, b"keep existing output").unwrap();
    session.output = Some(existing.clone());
    let result = session.prepare(Action::Apply).unwrap().run(&fixture.engine);
    assert!(session.finish(result));
    assert_eq!(session.outcome, Outcome::Failed);
    assert!(
        session.status.contains("OUTPUT_EXISTS"),
        "{}",
        session.status
    );
    assert_eq!(std::fs::read(existing).unwrap(), b"keep existing output");

    step(&mut session, &fixture.engine, Action::Plan);
    session.output = Some(output.clone());
    step(&mut session, &fixture.engine, Action::Apply);
    assert_eq!(
        session.manifest.as_deref(),
        Some(manifest_path(&output).as_path())
    );
    let verify = session
        .prepare(Action::Verify)
        .unwrap()
        .run(&fixture.engine);
    assert!(session.finish(verify));
    assert_eq!(session.outcome, Outcome::Verified, "{}", session.status);
    assert!(session.status.contains("Offline verification complete"));

    let cli_plan = root.join("cli-plan.json");
    let cli_output = root.join("cli-output.bin");
    let selection = approved.document["requested"][0].as_str().unwrap();
    fixture.cli(&[
        "plan".into(),
        fixture.image.as_os_str().into(),
        "--catalog".into(),
        "lab".into(),
        "--select".into(),
        selection.into(),
        "-o".into(),
        cli_plan.as_os_str().into(),
    ]);
    fixture.cli(&[
        "patch".into(),
        fixture.image.as_os_str().into(),
        "--plan".into(),
        cli_plan.as_os_str().into(),
        "-o".into(),
        cli_output.as_os_str().into(),
    ]);
    assert_eq!(
        std::fs::read(&output).unwrap(),
        std::fs::read(&cli_output).unwrap(),
        "GUI output: expected byte-identical CLI output"
    );
    let gui_manifest: Value =
        serde_json::from_slice(&std::fs::read(manifest_path(&output)).unwrap()).unwrap();
    let cli_manifest: Value =
        serde_json::from_slice(&std::fs::read(manifest_path(&cli_output)).unwrap()).unwrap();
    assert_eq!(
        gui_manifest["plan"], cli_manifest["plan"],
        "manifest plan: expected identical CLI semantics"
    );
    assert_eq!(gui_manifest["verification"], cli_manifest["verification"]);
    assert_eq!(
        gui_manifest["plan"]["output"]["sha256"],
        cli_manifest["plan"]["output"]["sha256"]
    );

    let imported_source = root.join("imported-plan.json");
    std::fs::write(&imported_source, &approved.bytes).unwrap();
    let mut imported = fixture.session();
    imported.import_review(&imported_source).unwrap();
    imported.open_output(output.clone());
    assert!(!imported.can_apply());
    assert!(imported.prepare(Action::Apply).is_err());
    std::fs::write(&imported_source, b"external edit").unwrap();
    assert_eq!(
        std::fs::read(&imported.review.as_ref().unwrap().path).unwrap(),
        approved.bytes
    );
    let verify = imported
        .prepare(Action::Verify)
        .unwrap()
        .run(&fixture.engine);
    assert!(imported.finish(verify));
    assert_eq!(imported.outcome, Outcome::Verified, "{}", imported.status);

    let stale = imported.prepare(Action::Scan).unwrap().run(&fixture.engine);
    imported.image = Some(root.join("another image.bin"));
    imported.invalidate();
    assert!(
        !imported.finish(stale),
        "stale scan: expected rejection after image change"
    );
    assert!(imported.scan.is_none());
    assert!(imported.review.is_none());
    assert!(!imported.busy());
    imported.source = "another-source".into();
    imported.invalidate();
    assert!(!imported.can_apply());
}

#[test]
fn recommendation_is_resolved_by_engine_and_changes_invalidate_review() {
    let fixture = SyntheticEngine::new();
    let mut session = fixture.session();
    step(&mut session, &fixture.engine, Action::Recommended);
    let requested = session.review.as_ref().unwrap().document["requested"]
        .as_array()
        .unwrap();
    assert_eq!(
        requested,
        &[Value::from("lab::PA@1.0.0"), Value::from("lab::PB@1.0.0")]
    );
    let index = session
        .scan
        .as_ref()
        .unwrap()
        .report
        .patches
        .iter()
        .position(|p| p.id == "PA")
        .unwrap();
    session.toggle(index);
    assert!(session.review.is_none());
    step(&mut session, &fixture.engine, Action::Plan);
    session.source = "official".into();
    session.invalidate();
    assert!(session.review.is_none());
    assert!(session.scan.is_none());
}
