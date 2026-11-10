//! Opt-in probe for UI callback latency with retained plans of different sizes.

use biosmod_gui::desktop::{Desktop, bind};
use biosmod_gui::i18n::Language;
use biosmod_gui::settings::{PreferencesStore, Settings};
use biosmod_gui::ui::AppWindow;
use std::time::Instant;

#[test]
#[ignore = "manual synthetic performance probe; run with --ignored --nocapture"]
fn output_edit_latency_with_retained_plan() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    for size in [64 * 1024, 1024 * 1024, 15 * 1024 * 1024] {
        let path = dir.path().join("plan.json");
        let document = serde_json::json!({"schema":"bme.plan/1", "notes":["x".repeat(size)]});
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        let mut desktop = Desktop::new(
            "/missing/bme".into(),
            Settings::default(),
            PreferencesStore::Unavailable,
        )
        .unwrap();
        desktop.session.import_review(&path).unwrap();
        let window = AppWindow::new().unwrap();
        biosmod_gui::i18n::Language::En.select().unwrap();
        let state = bind(&window, desktop);
        window.invoke_output_edited("/tmp/warmup.bin".into());
        let started = Instant::now();
        for index in 0..5 {
            window.invoke_output_edited(format!("/tmp/output-{index}.bin").into());
        }
        let elapsed = started.elapsed().as_secs_f64() * 1000. / 5.;
        assert!(
            window
                .get_plan_details()
                .contains("Read-only imported plan")
        );
        assert!(!window.get_can_apply(), "imported plan must stay read-only");
        assert_eq!(
            state
                .lock()
                .unwrap()
                .session
                .output
                .as_ref()
                .unwrap()
                .to_str(),
            Some("/tmp/output-4.bin")
        );
        println!("plan_kib={} output_edit_mean_ms={elapsed:.6}", size / 1024);
    }
}

#[test]
#[ignore = "manual synthetic performance probe; run with --ignored --nocapture"]
fn plan_presentation_cost_by_language() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    for language in [Language::En, Language::PtBr] {
        for size in [64 * 1024, 1024 * 1024, 15 * 1024 * 1024] {
            let path = dir.path().join("plan.json");
            let document = serde_json::json!({"schema":"bme.plan/1", "source": {"snapshot": "x".repeat(size)}});
            std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
            let settings = Settings {
                language,
                ..Settings::default()
            };
            let desktop = Desktop::new(
                "/missing/bme".into(),
                settings,
                PreferencesStore::Unavailable,
            )
            .unwrap();
            let window = AppWindow::new().unwrap();
            language.select().unwrap();
            let state = bind(&window, desktop);
            // import_review runs the worker-side preparation inline here.
            let started = Instant::now();
            state.lock().unwrap().session.import_review(&path).unwrap();
            let prepare = started.elapsed().as_secs_f64() * 1000.;
            // The next UI callback presents the new review on the UI thread.
            let started = Instant::now();
            window.invoke_output_edited("/tmp/output.bin".into());
            let present = started.elapsed().as_secs_f64() * 1000.;
            assert!(
                window.get_plan_snapshot().len() > size,
                "plan details: expected the snapshot"
            );
            println!(
                "language={} plan_kib={} prepare_ms={prepare:.3} present_ms={present:.3}",
                language.identifier(),
                size / 1024
            );
        }
    }
    Language::En.select().unwrap();
}
