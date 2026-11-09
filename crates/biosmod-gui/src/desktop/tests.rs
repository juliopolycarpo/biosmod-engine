use super::*;
use crate::controller::Review;
use crate::model::SourceReport;
use serde_json::json;
use slint::platform::{WindowEvent, WindowEventDispatchResult};
use std::cell::Cell;
use std::rc::Rc;

#[test]
fn incomplete_publication_shows_recovery_and_import_does_not_block_close() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    {
        let mut state = state.lock().unwrap();
        state.session.outcome = Outcome::PublicationIncomplete;
        state.session.result_details = "Remaining manifest and staged image".into();
        sync(&window, &state);
    }
    assert_eq!(window.get_stage(), 3);
    assert!(
        window
            .get_result_title()
            .starts_with("Publication incomplete")
    );
    assert!(window.get_result_details().contains("staged image"));
    window.show().unwrap();
    let _job = state
        .lock()
        .unwrap()
        .session
        .prepare_import(std::path::Path::new("/stalled/plan.json"))
        .unwrap();
    window.window().dispatch_event(WindowEvent::CloseRequested);
    assert!(
        !window.window().is_visible(),
        "read-only import must not prevent closing the window"
    );
}

fn fake_review(generated: bool) -> Review {
    Review {
        path: PathBuf::from("/tmp/reviewed-plan.json"),
        bytes: b"{}".to_vec(),
        document: json!({}),
        generated,
    }
}

fn fake_scan() -> SourceReport {
    serde_json::from_value(json!({
        "alias": "lab", "trust": "local", "catalog": "fixture", "catalog_version": "1",
        "report": {"firmware": "synthetic", "boards": [], "patches": [{
            "id": "PA", "version": "1.0.0", "title": "Correction", "class": "correction",
            "tier": "optional", "state": "present", "plannable": true, "manual": false,
            "detail": "present", "requires_facts": [], "evidence": []
        }]}
    }))
    .unwrap()
}

fn bound_window(settings: Settings, settings_path: Option<PathBuf>) -> (AppWindow, Shared) {
    let window = AppWindow::new().unwrap();
    let desktop =
        Desktop::new(PathBuf::from("/missing/fake-bme"), settings, settings_path).unwrap();
    let state = bind(&window, desktop);
    (window, state)
}

fn make_reviewable(state: &Shared, generated: bool) {
    let mut state = state.lock().unwrap();
    state.session.connected = true;
    state.session.image = Some(PathBuf::from("/tmp/image.bin"));
    state.session.source = "lab".into();
    state.session.output = Some(PathBuf::from("/tmp/output.bin"));
    state.session.scan = Some(fake_scan());
    state.session.review = Some(fake_review(generated));
}

#[test]
fn callbacks_invalidate_review_for_inputs_and_keep_it_for_output_choice() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    make_reviewable(&state, true);
    sync(&window, &state.lock().unwrap());
    assert!(window.get_can_apply());
    assert!(window.get_can_recommend());
    assert_eq!(window.get_stage(), 2);

    window.invoke_output_edited("/tmp/another-output.bin".into());
    assert!(state.lock().unwrap().session.review.is_some());
    assert!(window.get_can_apply());
    assert_eq!(
        window.get_manifest_path(),
        "/tmp/another-output.bin.manifest.json"
    );

    window.invoke_image_edited("/tmp/other-image.bin".into());
    assert!(state.lock().unwrap().session.review.is_none());
    assert!(!window.get_can_apply());
    assert!(!window.get_can_recommend());
    assert_eq!(window.get_stage(), 0);

    make_reviewable(&state, true);
    window.invoke_source_edited("other".into());
    assert!(state.lock().unwrap().session.review.is_none());
    assert_eq!(state.lock().unwrap().session.source, "other");

    make_reviewable(&state, true);
    window.invoke_engine_edited("/tmp/new-bme".into());
    let state = state.lock().unwrap();
    assert!(state.session.review.is_none());
    assert!(!state.session.connected);
    assert!(!window.get_can_apply());
}

#[test]
fn imported_review_is_read_only_and_theme_choice_persists() {
    i_slint_backend_testing::init_no_event_loop();
    let temp = tempfile::tempdir().unwrap();
    let settings_path = temp.path().join("settings.json");
    let settings = Settings {
        theme: 2,
        engine: None,
    };
    settings.save(&settings_path).unwrap();
    let loaded = Settings::load(&settings_path).unwrap();
    let (window, state) = bound_window(loaded, Some(settings_path.clone()));
    assert_eq!(window.get_theme_choice(), 2);
    make_reviewable(&state, false);
    sync(&window, &state.lock().unwrap());
    assert_eq!(window.get_stage(), 2);
    assert!(!window.get_can_apply());
    window.invoke_theme_changed(1);
    assert_eq!(Settings::load(&settings_path).unwrap().theme, 1);
    window.invoke_back_to_selection();
    assert!(state.lock().unwrap().session.review.is_none());
    assert_eq!(window.get_stage(), 1);
}

#[test]
fn window_close_respects_active_read_and_publication() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, _state) = bound_window(Settings::default(), None);
    window.show().unwrap();
    assert_eq!(
        window
            .window()
            .dispatch_event_with_result(WindowEvent::CloseRequested)
            .unwrap(),
        WindowEventDispatchResult::Accepted
    );
    assert!(!window.window().is_visible());

    let (window, state_read) = bound_window(Settings::default(), None);
    make_reviewable(&state_read, true);
    state_read
        .lock()
        .unwrap()
        .session
        .prepare(Action::Inspect)
        .unwrap();
    window.show().unwrap();
    assert_eq!(
        window
            .window()
            .dispatch_event_with_result(WindowEvent::CloseRequested)
            .unwrap(),
        WindowEventDispatchResult::Rejected
    );
    let state_read = state_read.lock().unwrap();
    assert!(state_read.closing);
    assert!(state_read.session.cancel.load(Ordering::Relaxed));
    assert!(window.window().is_visible());
    drop(state_read);

    window.hide().unwrap();
    let (publishing_window, publishing_state) = bound_window(Settings::default(), None);
    make_reviewable(&publishing_state, true);
    publishing_state
        .lock()
        .unwrap()
        .session
        .prepare(Action::Apply)
        .unwrap();
    publishing_window.show().unwrap();
    assert_eq!(
        publishing_window
            .window()
            .dispatch_event_with_result(WindowEvent::CloseRequested)
            .unwrap(),
        WindowEventDispatchResult::Rejected
    );
    let state = publishing_state.lock().unwrap();
    assert!(!state.closing);
    assert!(!state.session.cancel.load(Ordering::Relaxed));
    assert!(publishing_window.window().is_visible());
    drop(state);

    let (export_window, export_state) = bound_window(Settings::default(), None);
    export_state.lock().unwrap().exporting = true;
    export_window.show().unwrap();
    assert_eq!(
        export_window
            .window()
            .dispatch_event_with_result(WindowEvent::CloseRequested)
            .unwrap(),
        WindowEventDispatchResult::Rejected
    );
    let state = export_state.lock().unwrap();
    assert!(state.closing);
    assert!(!state.session.cancel.load(Ordering::Relaxed));
    assert!(export_window.window().is_visible());
    drop(state);
    finish_export(
        &export_window,
        &export_state,
        std::path::Path::new("/tmp/plan.json"),
        Ok(()),
    );
    assert!(!export_window.window().is_visible());
    assert!(!export_state.lock().unwrap().exporting);
}

#[test]
fn selecting_a_patch_and_picker_paths_update_the_session() {
    i_slint_backend_testing::init_no_event_loop();
    let temp = tempfile::tempdir().unwrap();
    let (window, state) = bound_window(Settings::default(), None);
    make_reviewable(&state, true);
    sync(&window, &state.lock().unwrap());
    window.invoke_toggle_patch(0);
    assert!(window.get_can_plan());
    assert!(!window.get_can_apply());
    assert!(state.lock().unwrap().session.review.is_none());

    let plan = temp.path().join("saved plan.json");
    std::fs::write(&plan, br#"{"schema":"bme.plan/1"}"#).unwrap();
    let mut state = state.lock().unwrap();
    state.session.import_review(&plan).unwrap();
    assert!(!state.session.review.as_ref().unwrap().generated);
    let output = temp.path().join("output image.bin");
    apply_picked(&mut state, PathKind::ExistingOutput, output.clone());
    assert_eq!(state.session.manifest, Some(manifest_path(&output)));
    apply_picked(
        &mut state,
        PathKind::Image,
        temp.path().join("other image.bin"),
    );
    assert!(state.session.review.is_some());
    assert!(state.session.manifest.is_some());
    state.session.diagnostics = "fake diagnostic".into();
    let log = temp.path().join("diagnostics.txt");
    apply_picked(&mut state, PathKind::Diagnostics, log.clone());
    assert_eq!(std::fs::read_to_string(log).unwrap(), "fake diagnostic");
}

#[test]
fn reopening_plan_and_output_in_either_order_allows_verification_after_choosing_image() {
    i_slint_backend_testing::init_no_event_loop();
    let temp = tempfile::tempdir().unwrap();
    let plan = temp.path().join("saved-plan.json");
    std::fs::write(&plan, br#"{"schema":"bme.plan/1"}"#).unwrap();
    let output = temp.path().join("output.bin");
    let image = temp.path().join("original.bin");
    for plan_first in [true, false] {
        let (window, state) = bound_window(Settings::default(), None);
        {
            let mut state = state.lock().unwrap();
            state.session.connected = true;
            if plan_first {
                state.session.import_review(&plan).unwrap();
                apply_picked(&mut state, PathKind::ExistingOutput, output.clone());
            } else {
                apply_picked(&mut state, PathKind::ExistingOutput, output.clone());
                state.session.import_review(&plan).unwrap();
            }
            sync(&window, &state);
        }
        assert!(
            !window.get_can_verify(),
            "verification requires the original image"
        );
        window.invoke_image_edited(image.to_string_lossy().as_ref().into());
        assert!(
            window.get_can_verify(),
            "plan_first={plan_first}: choosing the original image must retain the imported plan and output"
        );
        assert!(!window.get_can_apply(), "an imported plan is read-only");
    }
    let (window, state) = bound_window(Settings::default(), None);
    state.lock().unwrap().session.connected = true;
    window.invoke_open_output_path(output.to_string_lossy().as_ref().into());
    window.invoke_image_edited(image.to_string_lossy().as_ref().into());
    {
        let mut state = state.lock().unwrap();
        assert_eq!(
            state.session.output.as_ref(),
            Some(&output),
            "choosing the original must retain the opened output"
        );
        state.session.import_review(&plan).unwrap();
        sync(&window, &state);
    }
    assert!(window.get_can_verify());
    assert!(!window.get_can_apply());
}

#[test]
fn typing_relative_paths_does_not_replace_the_input_with_an_absolute_path() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, _state) = bound_window(Settings::default(), None);
    window.set_image_path("folder/image.bin".into());
    window.invoke_image_edited("folder/image.bin".into());
    assert_eq!(window.get_image_path(), "folder/image.bin");
    window.set_output_path("results/output.bin".into());
    window.invoke_output_edited("results/output.bin".into());
    assert_eq!(window.get_output_path(), "results/output.bin");
    window.set_engine_path("tools/bme".into());
    window.invoke_engine_edited("tools/bme".into());
    assert_eq!(window.get_engine_path(), "tools/bme");
}

#[test]
fn registered_timer_remains_live_until_stopped() {
    i_slint_backend_testing::init_no_event_loop();
    let calls = Rc::new(Cell::new(0));
    let captured = calls.clone();
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(1),
        move || captured.set(captured.get() + 1),
    );
    let id = register_timer(timer);
    i_slint_backend_testing::mock_elapsed_time(Duration::from_secs(1));
    assert_eq!(calls.get(), 1);
    stop_timer(id);
    i_slint_backend_testing::mock_elapsed_time(Duration::from_secs(1));
    assert_eq!(calls.get(), 1);
}

#[test]
fn plan_export_preserves_exact_bytes_and_refuses_existing_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reviewed plan.json");
    let reviewed = b"{\n  \"schema\": \"bme.plan/1\"\n}\n";
    write_plan(&path, reviewed).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), reviewed);
    assert_eq!(
        write_plan(&path, b"different").unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read(path).unwrap(), reviewed);
}
