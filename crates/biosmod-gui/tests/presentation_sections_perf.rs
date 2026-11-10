//! Opt-in measurement of output-edit callbacks with real retained engine reports.

mod common;

use biosmod_gui::controller::{Action, Outcome, Session};
use biosmod_gui::desktop::{Desktop, bind};
use biosmod_gui::engine::Engine;
use biosmod_gui::i18n::Language;
use biosmod_gui::settings::{PreferencesStore, Settings};
use biosmod_gui::ui::AppWindow;
use std::time::Instant;

fn run_action(session: &mut Session, engine: &Engine, action: Action) {
    let completion = session.prepare(action).unwrap().run(engine);
    assert!(
        session.finish(completion),
        "{action:?}: expected current result"
    );
    assert_eq!(
        session.outcome,
        Outcome::Idle,
        "{action:?}: {}",
        session.status
    );
}

#[test]
#[ignore = "manual presentation callback timing probe"]
fn presentation_sections_callback_cost() {
    i_slint_backend_testing::init_no_event_loop();
    let scenario = std::env::var("BME_PRESENTATION_SCENARIO").expect("BME_PRESENTATION_SCENARIO");
    let diagnostic_bytes = match scenario.as_str() {
        "empty" => 0,
        "recent" => 64 * 1024,
        "bounded" => 256 * 1024,
        _ => panic!(
            "BME_PRESENTATION_SCENARIO: expected empty, recent, or bounded | received {scenario:?}"
        ),
    };
    let binary = common::test_engine();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let image = common::setup_fixture(&binary, root);
    let engine = Engine::new(&binary, root)
        .unwrap()
        .with_env("BME_CONFIG_HOME", root.join("config"))
        .with_env("BME_CACHE_HOME", root.join("cache"))
        .with_env("BME_DATA_HOME", root.join("data"));
    let mut desktop =
        Desktop::new(binary, Settings::default(), PreferencesStore::Unavailable).unwrap();
    run_action(&mut desktop.session, &engine, Action::Connect);
    desktop.session.image = Some(image);
    desktop.session.source = "lab".into();
    run_action(&mut desktop.session, &engine, Action::Inspect);
    run_action(&mut desktop.session, &engine, Action::Scan);
    let index = desktop
        .session
        .scan
        .as_ref()
        .unwrap()
        .report
        .patches
        .iter()
        .position(|patch| patch.id == "PA" && patch.selectable())
        .unwrap();
    desktop.session.toggle(index);
    run_action(&mut desktop.session, &engine, Action::Preview);
    run_action(&mut desktop.session, &engine, Action::Tools);
    let source_bytes = desktop.session.source_details.len();
    let tool_bytes = serde_json::to_string(&desktop.session.tool_report.as_deref())
        .unwrap()
        .len();
    let plan_bytes = desktop.session.review.as_ref().unwrap().bytes.len();
    let patches = desktop.session.scan.as_ref().unwrap().report.patches.len();
    assert!(source_bytes > 0 && tool_bytes > 0 && plan_bytes > 0 && patches > 0);
    if scenario == "empty" {
        desktop.session.source_details.clear();
        desktop.session.tool_report = None;
        desktop.session.diagnostics.clear();
    } else {
        let line = "engine: examined firmware and catalog; bounded recent diagnostic output\n";
        desktop.session.diagnostics =
            line.repeat(diagnostic_bytes / line.len() + 1)[..diagnostic_bytes].into();
    }
    let window = AppWindow::new().unwrap();
    Language::En.select().unwrap();
    let state = bind(&window, desktop);
    for index in 0..5 {
        window.invoke_output_edited(format!("/tmp/warmup-{index}.bin").into());
    }
    let started = Instant::now();
    for index in 0..40 {
        window.invoke_output_edited(format!("/tmp/output-{index}.bin").into());
    }
    let nanos = started.elapsed().as_nanos();
    let state = state.lock().unwrap();
    assert!(state.session.review.is_some() && state.session.scan.is_some());
    assert_eq!(window.get_diagnostics().len(), diagnostic_bytes);
    if scenario != "empty" {
        assert!(!window.get_tool_details().is_empty());
        assert!(!window.get_source_details().is_empty());
    }
    println!(
        "sections_sample scenario={scenario} callbacks=40 elapsed_ns={nanos} source_bytes={source_bytes} tool_bytes={tool_bytes} plan_bytes={plan_bytes} patches={patches} diagnostics_bytes={diagnostic_bytes}"
    );
}
