//! End-to-end controller coverage with the real CLI and isolated synthetic data.

mod common;

use biosmod_gui::controller::{Action, Outcome, Session, manifest_path};
use biosmod_gui::engine::Engine;
use serde_json::Value;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

struct SyntheticEngine {
    directory: tempfile::TempDir,
    binary: PathBuf,
    image: PathBuf,
    engine: Engine,
}

impl SyntheticEngine {
    fn new() -> Self {
        let binary = common::test_engine();
        let directory = tempfile::Builder::new()
            .prefix("bme-gui-workflow-")
            .tempdir()
            .unwrap();
        let root = directory.path();
        let image = common::setup_fixture(&binary, root);
        let engine = Engine::new(&binary, root)
            .unwrap()
            .with_env("BME_CONFIG_HOME", root.join("config"))
            .with_env("BME_CACHE_HOME", root.join("cache"))
            .with_env("BME_DATA_HOME", root.join("data"));
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
    assert!(reviewed.document["selected"].to_string().contains("PA"));

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
    assert!(
        !session.status.contains("outcome unknown"),
        "refused before launch: expected a definite status | received {}",
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
    assert!(session.can_recommend());
    session.select_recommended();
    let scan = session.scan.as_ref().unwrap();
    let selected: Vec<_> = scan
        .report
        .patches
        .iter()
        .filter(|patch| patch.selected)
        .map(|patch| patch.id.as_str())
        .collect();
    assert_eq!(selected, ["PA", "PB"]);
    assert!(!session.busy());
    assert!(session.review.is_none());
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

#[cfg(unix)]
#[test]
fn language_switch_preserves_engine_request_and_firmware_result() {
    use biosmod_gui::{
        desktop::{Desktop, bind},
        i18n::Language,
        settings::{PreferencesStore, Settings},
        ui::AppWindow,
    };
    use std::os::unix::fs::PermissionsExt;

    i_slint_backend_testing::init_no_event_loop();
    let window = AppWindow::new().unwrap();
    Language::En.select().unwrap();
    let fixture = SyntheticEngine::new();
    let mut session = fixture.session();
    let index = session
        .scan
        .as_ref()
        .unwrap()
        .report
        .patches
        .iter()
        .position(|patch| patch.id == "PA" && patch.selectable())
        .unwrap();
    session.toggle(index);
    step(&mut session, &fixture.engine, Action::Plan);
    let reviewed = session.review.as_ref().unwrap().clone();
    let reviewed_bytes = reviewed.bytes.clone();

    // This forwarding fake records exactly what the GUI sends while the real CLI
    // performs publication, so a locale-dependent request cannot hide in the result.
    let root = fixture.directory.path();
    let wrapper = root.join("recording-engine");
    let args_path = root.join("recorded-args");
    let env_path = root.join("recorded-env");
    let calls_path = root.join("recorded-calls");
    std::fs::write(&wrapper, "#!/bin/sh\nprintf 'call\\n' >> \"$BME_TRACE_CALLS\"\nprintf '%s\\0' \"$@\" > \"$BME_TRACE_ARGS\"\nenv -0 | sort -z > \"$BME_TRACE_ENV\"\nexec \"$BME_REAL_ENGINE\" \"$@\"\n").unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let engine = Engine::new(&wrapper, root)
        .unwrap()
        .with_env("BME_REAL_ENGINE", &fixture.binary)
        .with_env("BME_TRACE_ARGS", &args_path)
        .with_env("BME_TRACE_ENV", &env_path)
        .with_env("BME_TRACE_CALLS", &calls_path)
        .with_env("BME_CONFIG_HOME", root.join("config"))
        .with_env("BME_CACHE_HOME", root.join("cache"))
        .with_env("BME_DATA_HOME", root.join("data"));
    let output = root.join("same-output.bin");
    session.set_output(Some(output.clone()));
    step(&mut session, &engine, Action::Apply);
    let english_output = std::fs::read(&output).unwrap();
    let manifest_path = manifest_path(&output);
    let english_manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let english_args = std::fs::read(&args_path).unwrap();
    let english_env = std::fs::read(&env_path).unwrap();
    std::fs::remove_file(&output).unwrap();
    std::fs::remove_file(&manifest_path).unwrap();

    let calls_before = std::fs::read(&calls_path).unwrap();
    let mut desktop = Desktop::new(
        wrapper.clone(),
        Settings::default(),
        PreferencesStore::Writable(root.join("gui.json")),
    )
    .unwrap();
    desktop.session = session;
    let state = bind(&window, desktop);
    window.invoke_language_changed(1);
    assert_eq!(
        std::fs::read(&calls_path).unwrap(),
        calls_before,
        "language selection unexpectedly started the engine"
    );
    assert_eq!(
        reviewed.bytes, reviewed_bytes,
        "reviewed plan bytes changed on language selection"
    );
    let mut state = state.lock().unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &reviewed,
        state.session.review.as_ref().unwrap()
    ));
    assert_eq!(std::fs::read(&reviewed.path).unwrap(), reviewed_bytes);
    state.session.set_output(Some(output.clone()));
    step(&mut state.session, &engine, Action::Apply);
    let portuguese_manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    assert_eq!(
        std::fs::read(&args_path).unwrap(),
        english_args,
        "engine arguments changed with GUI language"
    );
    assert_eq!(
        std::fs::read(&env_path).unwrap(),
        english_env,
        "engine environment changed with GUI language"
    );
    assert_eq!(
        std::fs::read(&output).unwrap(),
        english_output,
        "firmware bytes changed with GUI language"
    );
    assert_eq!(portuguese_manifest["plan"], english_manifest["plan"]);
    assert_eq!(
        portuguese_manifest["verification"],
        english_manifest["verification"]
    );
    Language::En.select().unwrap();
}

#[test]
fn guarded_engine_requests_preview_export_build_and_verify() {
    use biosmod_gui::engine::{
        EngineContract, PatchDestination, PatchSelection, Request, ScannedSelection,
    };
    use std::sync::{Arc, atomic::AtomicBool};

    let fixture = SyntheticEngine::new();
    let cancel = AtomicBool::new(false);
    let capabilities = fixture.engine.handshake(&cancel).unwrap();
    let contract = EngineContract::from_capabilities(&capabilities.data).unwrap();
    let engine = fixture.engine.clone().with_contract(Arc::new(contract));
    let image = fixture.image.clone();
    let scan = engine
        .run(
            &Request::Scan {
                image: image.clone(),
                source: "lab".into(),
            },
            &cancel,
        )
        .unwrap()
        .data;
    let scanned = ScannedSelection {
        source: "lab".into(),
        ids: vec!["lab::PA@1.0.0".into()],
        input_sha256: scan["input"]["sha256"].as_str().unwrap().into(),
        source_sha256: scan["sources"][0]["snapshot_sha256"]
            .as_str()
            .unwrap()
            .into(),
    };
    let root = fixture.directory.path();
    let recipe = root.join("selection file.json");
    let output = root.join("new image.bin");
    let preview = engine
        .run(
            &Request::Build {
                image: image.clone(),
                selection: PatchSelection::Scanned(scanned.clone()),
                destination: PatchDestination::Preview,
            },
            &cancel,
        )
        .unwrap()
        .data;
    assert_eq!(preview["dry_run"], true);
    assert_eq!(
        preview["plan"]["requested"],
        serde_json::json!(["lab::PA@1.0.0"])
    );
    assert!(!output.exists());
    assert!(!recipe.exists());

    let export = engine
        .run(
            &Request::Export {
                image: image.clone(),
                selection: scanned.clone(),
                output: recipe.clone(),
            },
            &cancel,
        )
        .unwrap()
        .data;
    assert_eq!(export["plan"], preview["plan"]);
    let replay = engine
        .run(
            &Request::Build {
                image: image.clone(),
                selection: PatchSelection::Recipe(recipe.clone()),
                destination: PatchDestination::Preview,
            },
            &cancel,
        )
        .unwrap()
        .data;
    assert_eq!(replay["plan"], preview["plan"]);
    assert!(!output.exists());

    let build = engine
        .run(
            &Request::Build {
                image: image.clone(),
                selection: PatchSelection::Scanned(scanned),
                destination: PatchDestination::Publish(output.clone()),
            },
            &cancel,
        )
        .unwrap()
        .data;
    assert_eq!(build["manifest"]["plan"], preview["plan"]);
    for recipe in [None, Some(recipe)] {
        let verification = engine
            .run(
                &Request::VerifyResult {
                    input: image.clone(),
                    output: output.clone(),
                    manifest: manifest_path(&output),
                    recipe,
                },
                &cancel,
            )
            .unwrap()
            .data;
        assert_eq!(verification["complete"], true);
        assert_eq!(verification["manifest_sha256"], build["manifest_sha256"]);
    }
}
