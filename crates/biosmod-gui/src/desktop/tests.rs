use super::*;
use crate::controller::Review;
use crate::model::Patch;
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

fn fake_review(generated: bool) -> Arc<Review> {
    Arc::new(Review::new(
        PathBuf::from("/tmp/reviewed-plan.json"),
        b"{}".to_vec(),
        json!({}),
        generated,
    ))
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
    let preferences =
        settings_path.map_or(PreferencesStore::Unavailable, PreferencesStore::Writable);
    bound_window_with_store(settings, preferences)
}

fn bound_window_with_store(
    settings: Settings,
    preferences: PreferencesStore,
) -> (AppWindow, Shared) {
    let window = AppWindow::new().unwrap();
    settings.language.select().unwrap();
    let desktop = Desktop::new(PathBuf::from("/missing/fake-bme"), settings, preferences).unwrap();
    let state = bind(&window, desktop);
    (window, state)
}

struct MissingPortugueseCatalog;

impl MissingPortugueseCatalog {
    fn select(language: Language) -> Result<(), slint::SelectBundledTranslationError> {
        assert_eq!(language, Language::PtBr);
        Err(slint::SelectBundledTranslationError::LanguageNotFound {
            available_languages: ["en".into()].as_slice().into(),
        })
    }
}

#[test]
fn rejected_language_restores_selector_and_preserves_review_and_preferences() {
    i_slint_backend_testing::init_no_event_loop();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("gui.json");
    let settings = Settings::default();
    settings.save(&path).unwrap();
    let saved = std::fs::read(&path).unwrap();
    let window = AppWindow::new().unwrap();
    Language::En.select().unwrap();
    let desktop = Desktop::new(
        PathBuf::from("/missing/fake-bme"),
        settings,
        PreferencesStore::Writable(path.clone()),
    )
    .unwrap();
    let state = bind_with_language_selector(&window, desktop, MissingPortugueseCatalog::select);
    make_reviewable(&state, true);
    let review = state.lock().unwrap().session.review.clone().unwrap();
    // ComboBox updates its two-way index before calling the native callback.
    window.set_language_index(1);
    window.invoke_language_changed(1);
    assert_eq!(
        window.get_language_index(),
        0,
        "language selector: expected active English index 0 after rejection"
    );
    assert!(
        window.get_status().starts_with("language pt-BR:"),
        "language error: expected rejected pt-BR catalog | received {:?}",
        window.get_status()
    );
    assert!(
        window
            .get_plan_details()
            .starts_with("Generated in this session")
    );
    let state = state.lock().unwrap();
    assert_eq!(state.settings.language, Language::En);
    assert!(Arc::ptr_eq(&review, state.session.review.as_ref().unwrap()));
    assert_eq!(std::fs::read(path).unwrap(), saved);
}

#[test]
fn protected_preferences_name_the_unreadable_file_and_stay_untouched() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gui.json");
    std::fs::write(&path, b"{bad-json").unwrap();
    let (window, state) = bound_window_with_store(
        Settings::default(),
        PreferencesStore::Protected(path.clone()),
    );
    window.invoke_theme_changed(2);
    let status = window.get_status();
    assert_eq!(
        state.lock().unwrap().session.status_kind,
        Status::PreferencesProtected,
        "protected preferences: expected status PreferencesProtected | received {status:?}"
    );
    assert!(
        status.contains(path.to_str().unwrap()) && !status.contains("no writable configuration"),
        "protected preferences: expected the malformed file path | received {status:?}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"{bad-json");
}

#[test]
fn plan_summary_keeps_component_identity_and_policy() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, _state) = bound_window(Settings::default(), None);
    let plan = json!({"firmware":"synthetic", "components":[{"name":"ACPI", "ffs_guid":"guid", "table_offset":128, "file_offset":4096, "patches":["A"]}], "facts":["board-rev"], "allow_hold":true, "allow_diagnostic":false, "source":{"manifest_sha256":"pinned"}});
    let review = Review::new(PathBuf::from("/tmp/plan.json"), Vec::new(), plan, true);
    let text = plan_summary(&window, &review);
    for expected in [
        "Generated in this session\n\nFirmware: synthetic",
        "ACPI · guid · table offset 128 · file offset 4096\n  A\n",
        "Hardware assertions: board-rev",
        "Allow hold: true · Allow diagnostic: false\nNone\n",
        "Complete plan and source snapshot\n",
    ] {
        assert!(
            text.contains(expected),
            "plan summary: expected {expected:?} | received {text:?}"
        );
    }
}

#[test]
fn verification_summary_preserves_passes_skips_and_notice() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, _state) = bound_window(Settings::default(), None);
    let report = json!({"checks":[{"check":"input-digest","ok":true},{"check":"new-check","ok":false}],"skipped":[{"check":"reproduction","reason":"catalog unavailable"}],"notice":"Offline checks only"});
    let text = verification_summary(&window, &report);
    for expected in [
        "PASS  Original image digest",
        "INCOMPLETE  new-check",
        "SKIPPED  reproduction\ncatalog unavailable",
        "Offline checks only",
    ] {
        assert!(
            text.contains(expected),
            "verification summary: expected {expected:?} | received {text:?}"
        );
    }
}

#[test]
fn portuguese_verification_translates_missing_skip_and_notice_fields() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, _state) = bound_window(Settings::default(), None);
    Language::PtBr.select().unwrap();
    let text = verification_summary(&window, &json!({"skipped": [{}]}));
    Language::En.select().unwrap();
    assert!(
        !text.contains("unknown") && text.matches("desconhecido").count() == 3,
        "verification placeholders: expected three \"desconhecido\" | received {text:?}"
    );
}

#[test]
fn language_switch_refreshes_review_rows_and_verification_without_changing_session() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gui.json");
    let (window, state) = bound_window(Settings::default(), Some(path.clone()));
    make_reviewable(&state, true);
    {
        let mut state = state.lock().unwrap();
        state.session.set_status(Status::Scanned);
        state.session.verification_report = Some(
            json!({"checks":[{"check":"input-digest","ok":true},{"check":"future-code","ok":false}],"skipped":[{"check":"opaque-code","reason":"original reason"}],"notice":"Raw notice"}),
        );
        sync(&window, &state);
    }
    let review = state.lock().unwrap().session.review.clone().unwrap();
    assert_eq!(
        window.get_patches().row_data(0).unwrap().state,
        "Defect present"
    );
    window.invoke_language_changed(1);
    assert_eq!(
        window.get_patches().row_data(0).unwrap().state,
        "Defeito presente"
    );
    assert!(window.get_plan_details().starts_with("Gerado nesta sessão"));
    assert_eq!(
        window.get_status(),
        "Exame concluído. Selecione correções ou revise a recomendação do mecanismo."
    );
    assert!(
        window
            .get_result_details()
            .contains("APROVADO  Hash da imagem original")
    );
    assert!(window.get_result_details().contains("future-code"));
    assert!(window.get_result_details().contains("original reason"));
    assert_eq!(
        localized_status(&window, Status::Failed, "", "UNKNOWN_CODE: original detail"),
        "Falha na operação: UNKNOWN_CODE: original detail"
    );
    assert_eq!(window.get_plan_snapshot(), "{}");
    assert_eq!(
        window.get_plan_snapshot().as_str().as_ptr(),
        review.snapshot.as_str().as_ptr(),
        "language switch: expected shared snapshot | received a copy"
    );
    assert!(window.get_result_details().contains("Raw notice"));
    assert_eq!(Settings::load(&path).unwrap().language, Language::PtBr);
    {
        let state = state.lock().unwrap();
        assert!(Arc::ptr_eq(&review, state.session.review.as_ref().unwrap()));
        assert_eq!(
            state.session.image.as_deref(),
            Some(Path::new("/tmp/image.bin"))
        );
        assert_eq!(state.session.source, "lab");
        assert!(!state.session.busy());
    }
    window.invoke_language_changed(0);
    assert_eq!(
        window.get_patches().row_data(0).unwrap().state,
        "Defect present"
    );
    assert_eq!(window.get_plan_details(), plan_summary(&window, &review));
    assert_eq!(Settings::load(&path).unwrap().language, Language::En);
}

#[test]
fn switching_language_during_import_preserves_job_and_localizes_completion() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let settings_path = dir.path().join("gui.json");
    let plan_path = dir.path().join("plan.json");
    std::fs::write(&plan_path, br#"{"schema":"bme.plan/1"}"#).unwrap();
    let (window, state) = bound_window(Settings::default(), Some(settings_path));
    make_reviewable(&state, true);
    let review = state.lock().unwrap().session.review.clone().unwrap();
    let job = state
        .lock()
        .unwrap()
        .session
        .prepare_import(&plan_path)
        .unwrap();
    window.invoke_language_changed(1);
    {
        let state = state.lock().unwrap();
        assert!(state.session.busy());
        assert!(Arc::ptr_eq(&review, state.session.review.as_ref().unwrap()));
        assert!(!state.session.cancel.load(Ordering::Relaxed));
    }
    {
        let mut state = state.lock().unwrap();
        assert!(state.session.finish(job.run()));
        sync(&window, &state);
    }
    assert_eq!(
        window.get_status(),
        "Plano importado: apenas revisão e verificação. Escolha sua imagem original e saída."
    );
    assert!(!state.lock().unwrap().session.busy());
    Language::En.select().unwrap();
}

#[test]
fn successful_save_restores_the_status_a_save_error_replaced() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    std::fs::write(&config, b"blocks the directory").unwrap();
    let (window, state) = bound_window(Settings::default(), Some(config.join("gui.json")));
    state.lock().unwrap().session.set_status(Status::Scanned);
    window.invoke_theme_changed(2);
    assert_eq!(
        state.lock().unwrap().session.status_kind,
        Status::PreferencesError
    );
    std::fs::remove_file(&config).unwrap();
    window.invoke_theme_changed(1);
    assert_eq!(
        window.get_status(),
        localized_status(&window, Status::Scanned, "", ""),
        "status after a recovered save: expected the scan guidance | received {:?}",
        window.get_status()
    );
}

#[test]
fn language_selection_survives_a_failed_save_for_the_session() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let parent_file = dir.path().join("not-a-directory");
    std::fs::write(&parent_file, b"existing").unwrap();
    let (window, state) = bound_window(Settings::default(), Some(parent_file.join("gui.json")));
    window.invoke_language_changed(1);
    assert_eq!(state.lock().unwrap().settings.language, Language::PtBr);
    assert_eq!(
        state.lock().unwrap().session.status_kind,
        Status::PreferencesError
    );
    assert_eq!(
        window.get_status(),
        window
            .global::<UiText>()
            .invoke_preferences_error(state.lock().unwrap().session.status_detail.as_str().into())
    );
    window.invoke_language_changed(0);
    assert_eq!(state.lock().unwrap().settings.language, Language::En);
    assert!(
        window
            .get_status()
            .starts_with("Could not save preferences:")
    );
    assert_eq!(std::fs::read(&parent_file).unwrap(), b"existing");
}

#[test]
fn every_precondition_has_a_localized_message() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, _) = bound_window(Settings::default(), None);
    for error in [
        PreparationError::Busy,
        PreparationError::Engine,
        PreparationError::Image,
        PreparationError::ImportPath,
        PreparationError::Scan,
        PreparationError::Selection,
        PreparationError::Build,
        PreparationError::Output,
        PreparationError::Plan,
        PreparationError::Manifest,
        PreparationError::WaitImport,
    ] {
        Language::En.select().unwrap();
        let english = localized_status(&window, Status::Precondition(error), "", "");
        assert_eq!(
            english.as_str(),
            error.to_string(),
            "precondition {error:?}"
        );
        Language::PtBr.select().unwrap();
        let portuguese = localized_status(&window, Status::Precondition(error), "", "");
        assert_ne!(
            portuguese, english,
            "precondition {error:?}: untranslated {english}"
        );
    }
    Language::En.select().unwrap();
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
fn clearing_the_engine_path_restores_the_default_engine_choice() {
    i_slint_backend_testing::init_no_event_loop();
    let temp = tempfile::tempdir().unwrap();
    let settings_path = temp.path().join("settings.json");
    let (window, state) = bound_window(Settings::default(), Some(settings_path.clone()));
    window.invoke_engine_edited("/tmp/custom-bme".into());
    window.invoke_engine_committed("/tmp/custom-bme".into());
    assert_eq!(
        Settings::load(&settings_path).unwrap().engine,
        Some(PathBuf::from("/tmp/custom-bme"))
    );
    window.invoke_engine_edited("".into());
    window.invoke_engine_committed("".into());
    let saved = Settings::load(&settings_path).unwrap().engine;
    assert_eq!(
        saved, None,
        "cleared engine field: expected no saved engine | received {saved:?}"
    );
    let engine = state.lock().unwrap().engine_path.clone();
    assert!(
        engine.is_absolute() && engine.ends_with("bme"),
        "cleared engine field: expected the absolute sibling bme | received {}",
        engine.display()
    );
}

#[test]
fn imported_review_is_read_only_and_theme_choice_persists() {
    i_slint_backend_testing::init_no_event_loop();
    let temp = tempfile::tempdir().unwrap();
    let settings_path = temp.path().join("settings.json");
    let settings = Settings {
        theme: 2,
        engine: None,
        ..Settings::default()
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
        ExportKind::Plan,
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
    NewFileWriter.write_new(&path, reviewed).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), reviewed);
    assert_eq!(
        NewFileWriter
            .write_new(&path, b"different")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read(path).unwrap(), reviewed);
}

#[test]
fn patch_model_survives_selection_and_unrelated_sync() {
    use slint::Model;
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    make_reviewable(&state, true);
    sync(&window, &state.lock().unwrap());
    let model = window.get_patches();
    window.invoke_toggle_patch(0);
    assert!(
        model == window.get_patches(),
        "patch selection: expected the same model and focused row | received a replacement model"
    );
    assert!(model.row_data(0).unwrap().selected);
    window.invoke_output_edited("/tmp/other.bin".into());
    assert!(
        model == window.get_patches(),
        "output edit replaced the patch model"
    );
    window.invoke_toggle_patch(0);
    assert!(!model.row_data(0).unwrap().selected);
    state.lock().unwrap().session.scan = None;
    sync(&window, &state.lock().unwrap());
    assert_eq!(model.row_count(), 0);
}

#[test]
fn review_presentation_shares_the_prepared_snapshot() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    let document = json!({"source": {"manifest_sha256": "pinned"}, "notes": ["preserved"]});
    let review = Arc::new(Review::new(
        "/tmp/plan.json".into(),
        b"exact bytes".to_vec(),
        document.clone(),
        false,
    ));
    state.lock().unwrap().session.review = Some(review.clone());
    sync(&window, &state.lock().unwrap());
    let snapshot = window.get_plan_snapshot();
    assert_eq!(snapshot.as_str(), crate::model::pretty(&document));
    assert_eq!(snapshot, review.snapshot);
    assert_eq!(
        snapshot.as_str().as_ptr(),
        review.snapshot.as_str().as_ptr(),
        "review snapshot: expected the UI to share the worker-prepared bytes | received a copy"
    );
}

#[test]
fn review_presentation_tracks_replacement_and_invalidation() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    make_reviewable(&state, true);
    sync(&window, &state.lock().unwrap());
    assert!(
        window
            .get_plan_details()
            .starts_with("Generated in this session")
    );
    let first = window.get_plan_details();
    window.invoke_output_edited("/tmp/other.bin".into());
    assert_eq!(
        first.as_str().as_ptr(),
        window.get_plan_details().as_str().as_ptr(),
        "unchanged review: expected the presented plan to be reused | received a new rendering"
    );
    state.lock().unwrap().session.review = Some(fake_review(false));
    sync(&window, &state.lock().unwrap());
    assert!(
        window
            .get_plan_details()
            .starts_with("Read-only imported plan")
    );
    window.invoke_back_to_selection();
    assert!(window.get_plan_details().is_empty());
    assert!(window.get_plan_snapshot().is_empty());
}

struct FakeExportWriter {
    writes: std::sync::mpsc::Sender<(std::thread::ThreadId, PathBuf, Vec<u8>)>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    completed: std::sync::mpsc::Sender<()>,
}

impl ExportWriter for FakeExportWriter {
    fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.writes
            .send((std::thread::current().id(), path.into(), bytes.to_vec()))
            .unwrap();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(2))
            .expect("fake export: expected the test to release the stalled writer");
        self.completed.send(()).unwrap();
        Ok(())
    }
}

#[test]
fn diagnostics_export_runs_off_the_event_loop_and_serializes_writes() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    let (sender, receiver) = std::sync::mpsc::channel();
    let (release, gate) = std::sync::mpsc::channel();
    let (completed, finished) = std::sync::mpsc::channel();
    {
        let mut state = state.lock().unwrap();
        state.export_writer = Arc::new(FakeExportWriter {
            writes: sender,
            release: Mutex::new(gate),
            completed,
        });
        state.session.diagnostics = "retained diagnostics".into();
    }
    let path = PathBuf::from("/stalled-filesystem/diagnostics.txt");
    start_export_diagnostics(&window, &state, path.clone());
    let (writer_thread, written_path, bytes) = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("diagnostics export: expected a submitted write");
    assert_ne!(
        writer_thread,
        std::thread::current().id(),
        "diagnostics export: expected worker I/O | received an event-loop write"
    );
    assert_eq!(written_path, path);
    assert_eq!(bytes, b"retained diagnostics");
    assert!(window.get_busy());
    window.invoke_output_edited("/must-not-change.bin".into());
    assert!(state.lock().unwrap().session.output.is_none());
    window.show().unwrap();
    assert_eq!(
        window
            .window()
            .dispatch_event_with_result(WindowEvent::CloseRequested)
            .unwrap(),
        WindowEventDispatchResult::Rejected
    );
    start_export_diagnostics(&window, &state, "/another-file.txt".into());
    assert!(
        receiver.try_recv().is_err(),
        "a second export must not submit while one is active"
    );
    release.send(()).unwrap();
    finished
        .recv_timeout(Duration::from_secs(2))
        .expect("export worker did not settle after release");
    finish_export(&window, &state, &path, ExportKind::Diagnostics, Ok(()));
    assert!(!window.window().is_visible());
    assert!(!state.lock().unwrap().exporting);
}

#[test]
fn diagnostics_export_reports_refusals_and_partial_files_and_allows_retry() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    let path = Path::new("/tmp/diagnostics.txt");
    state.lock().unwrap().exporting = true;
    finish_export(
        &window,
        &state,
        path,
        ExportKind::Diagnostics,
        Err(std::io::ErrorKind::AlreadyExists.into()),
    );
    assert!(!window.get_busy());
    assert!(
        window
            .get_status()
            .contains("Diagnostics export /tmp/diagnostics.txt: file already exists")
    );
    state.lock().unwrap().exporting = true;
    finish_export(
        &window,
        &state,
        path,
        ExportKind::Diagnostics,
        Err(std::io::ErrorKind::WriteZero.into()),
    );
    assert!(window.get_status().contains("partial file may remain"));
    assert!(!state.lock().unwrap().exporting);
    state.lock().unwrap().exporting = true;
    finish_export(&window, &state, path, ExportKind::Diagnostics, Ok(()));
    assert!(window.get_status().starts_with("Diagnostics exported to"));
}

#[test]
fn partial_engine_edits_do_not_persist_through_other_preference_changes() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gui.json");
    let settings = Settings {
        theme: 0,
        engine: Some("/tmp/committed-bme".into()),
        ..Settings::default()
    };
    settings.save(&path).unwrap();
    let (window, state) = bound_window(settings, Some(path.clone()));
    make_reviewable(&state, true);
    window.invoke_engine_edited("/tmp/partial-b".into());
    assert!(!state.lock().unwrap().session.connected);
    assert!(state.lock().unwrap().session.review.is_none());
    assert_eq!(
        Settings::load(&path).unwrap().engine,
        Some("/tmp/committed-bme".into()),
        "Engine draft: expected the last committed preference | received a saved partial path"
    );
    window.invoke_theme_changed(2);
    assert_eq!(
        Settings::load(&path).unwrap().engine,
        Some("/tmp/committed-bme".into())
    );
}

#[test]
fn engine_commit_keeps_a_matching_handshake_and_picker_choices_persist() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gui.json");
    let (window, state) = bound_window(Settings::default(), Some(path.clone()));
    window.invoke_engine_edited("/tmp/committed-bme".into());
    state.lock().unwrap().session.connected = true;
    window.invoke_engine_committed("/tmp/committed-bme".into());
    assert!(
        state.lock().unwrap().session.connected,
        "committing an unchanged engine must retain its handshake"
    );
    assert_eq!(
        Settings::load(&path).unwrap().engine,
        Some("/tmp/committed-bme".into())
    );
    apply_picked(
        &mut state.lock().unwrap(),
        PathKind::Engine,
        "/tmp/picked-bme".into(),
    );
    assert_eq!(
        Settings::load(&path).unwrap().engine,
        Some("/tmp/picked-bme".into())
    );
    assert!(!state.lock().unwrap().session.connected);
}

#[test]
fn focus_loss_can_commit_the_current_engine_without_changing_an_active_job() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gui.json");
    let (window, state) = bound_window(Settings::default(), Some(path.clone()));
    window.invoke_engine_edited("/tmp/current-bme".into());
    state
        .lock()
        .unwrap()
        .session
        .prepare(Action::Connect)
        .unwrap();
    window.invoke_engine_committed("/tmp/current-bme".into());
    assert_eq!(
        Settings::load(&path).unwrap().engine,
        Some("/tmp/current-bme".into())
    );
    window.invoke_engine_committed("/tmp/different-bme".into());
    assert_eq!(
        state.lock().unwrap().engine_path,
        PathBuf::from("/tmp/current-bme")
    );
    assert!(state.lock().unwrap().session.busy());
    assert_eq!(
        Settings::load(&path).unwrap().engine,
        Some("/tmp/current-bme".into())
    );
}

#[test]
fn cancellation_and_file_operations_publish_visible_busy_feedback() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    make_reviewable(&state, true);
    state
        .lock()
        .unwrap()
        .session
        .prepare(Action::Inspect)
        .unwrap();
    sync(&window, &state.lock().unwrap());
    assert!(window.get_can_cancel());
    window.invoke_cancel_operation();
    assert_eq!(
        window.get_operation_label(),
        "Stopping operation…",
        "Cancel: expected immediate visible acknowledgement"
    );
    assert!(
        !window.get_can_cancel(),
        "Cancel must be disabled while stopping"
    );
    let (window, state) = bound_window(Settings::default(), None);
    window.set_elapsed("12s".into());
    state.lock().unwrap().dialog_open = true;
    sync(&window, &state.lock().unwrap());
    assert_eq!(window.get_operation_label(), "Choosing file");
    assert!(window.get_elapsed().is_empty());
    state.lock().unwrap().dialog_open = false;
    state.lock().unwrap().exporting = true;
    sync(&window, &state.lock().unwrap());
    assert_eq!(window.get_operation_label(), "Exporting file");
}

#[test]
fn activity_timer_resets_elapsed_and_stops_after_completion() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    window.set_elapsed("37s".into());
    let id = start_timer(&window, &state);
    assert_eq!(window.get_elapsed(), "0s");
    state.lock().unwrap().started = Instant::now() - Duration::from_secs(4);
    i_slint_backend_testing::mock_elapsed_time(Duration::from_secs(1));
    assert_eq!(window.get_elapsed(), "4s");
    stop_timer(id);
    state.lock().unwrap().started = Instant::now() - Duration::from_secs(9);
    i_slint_backend_testing::mock_elapsed_time(Duration::from_secs(1));
    assert_eq!(window.get_elapsed(), "4s");
}

#[test]
fn opening_a_plan_resets_the_previous_operations_elapsed_time() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plan.json");
    std::fs::write(&path, br#"{"schema":"bme.plan/1"}"#).unwrap();
    let (window, state) = bound_window(Settings::default(), None);
    window.set_elapsed("37s".into());
    start_import(&window, &state, path);
    assert_eq!(
        window.get_elapsed(),
        "0s",
        "plan import: expected a fresh activity clock | received the previous operation's elapsed time"
    );
    assert_eq!(window.get_operation_label(), "Opening plan");
}

#[test]
fn patch_rows_separate_detail_from_limits_and_selection_eligibility() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, _state) = bound_window(Settings::default(), None);
    let patch: Patch = serde_json::from_value(json!({
        "id":"PA","version":"1.0.0","title":"Correction","class":"correction","tier":"optional",
        "state":"likely-present","plannable":false,"manual":false,"detail":"signature in another build",
        "evidence":["obs-1"]
    }))
    .unwrap();
    let row = patch_row(&window, "lab", &patch);
    assert_eq!(row.id, "lab::PA@1.0.0");
    assert_eq!(row.state, "Likely present");
    assert_eq!(row.tone, Tone::Quiet);
    assert_eq!(row.detail, "signature in another build");
    assert!(
        row.blocker.contains("Desktop selection requires"),
        "blocker: expected the selection notice | received {:?}",
        row.blocker
    );
    assert!(row.evidence.starts_with("Scoped evidence: obs-1"));
    assert!(!row.selectable, "diagnostic rows are never selectable");

    let mut present = patch;
    present.state = "present".into();
    present.plannable = true;
    present.evidence.clear();
    assert!(patch_row(&window, "lab", &present).selectable);
    let row = patch_row(&window, "lab", &present);
    assert_eq!(row.tone, Tone::Attention);
    assert_eq!(row.blocker, "");
    assert_eq!(
        row.evidence,
        "No hardware observations for this patch version."
    );

    let mut blocked = present.clone();
    blocked.plannable = false;
    blocked.blocked = Some("needs prerequisite".into());
    blocked.requires_facts.push("physical-board".into());
    let blocker = patch_row(&window, "lab", &blocked).blocker;
    let limits: Vec<_> = blocker.lines().collect();
    assert!(
        limits.len() == 3
            && limits[0] == "needs prerequisite"
            && limits[1].contains("physical-board"),
        "blocker: expected engine blocker, facts, selection notice without the detail | received {limits:?}"
    );
}

#[test]
fn patch_rows_name_every_engine_state_in_english() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, _state) = bound_window(Settings::default(), None);
    let mut patch = fake_scan().report.patches.remove(0);
    for (state, label) in [
        ("present", "Defect present"),
        ("partial", "Partially patched"),
        ("fixed", "Fixed"),
        ("likely-present", "Likely present"),
        ("likely-fixed", "Likely fixed"),
        ("not-detected", "Not detected"),
        ("not-applicable", "Not applicable"),
        ("unsupported", "Unsupported"),
        ("new-state", "new-state"),
    ] {
        patch.state = state.into();
        assert_eq!(
            patch_row(&window, "lab", &patch).state,
            label,
            "state {state}: label"
        );
    }
}

#[test]
fn facts_describe_the_image_and_scan_source() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, _state) = bound_window(Settings::default(), None);
    let inspection = json!({"length": 36864, "volumes": [{}, {}], "sha256": "abc123", "descriptor_regions": null});
    let facts = image_facts(&window, Some(&inspection));
    let pairs: Vec<_> = facts
        .iter()
        .map(|f| (f.label.to_string(), f.value.to_string()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("Size".into(), "36,864 bytes".into()),
            ("Volumes".into(), "2".into()),
            ("Layout".into(), "Bare BIOS / firmware volumes".into()),
        ],
        "image facts"
    );
    assert_eq!(image_sha(Some(&inspection)), "abc123");
    assert!(image_facts(&window, None).is_empty() && image_sha(None).is_empty());

    let scan = scan_facts(&window, &fake_scan());
    assert_eq!(scan[0].value, "lab · fixture 1");
    assert_eq!(scan[2].value, "synthetic");
    assert_eq!(scan[3].value, "none matched");
}

#[test]
fn digit_grouping_leaves_non_numbers_alone() {
    for (input, expected) in [
        ("0", "0"),
        ("999", "999"),
        ("1000", "1,000"),
        ("36864", "36,864"),
        ("16777216", "16,777,216"),
        ("null", "null"),
        ("", ""),
    ] {
        assert_eq!(group_digits(input), expected, "group_digits({input:?})");
    }
}

#[test]
fn row_sync_updates_in_place_and_replaces_foreign_models() {
    let row = |label: &str| Fact {
        label: label.into(),
        value: "v".into(),
    };
    let model = ModelRc::new(VecModel::from(vec![row("a"), row("b")]));
    let kept = model.clone();
    sync_rows(model.clone(), vec![row("a"), row("c")], |_| {
        panic!("sync_rows: expected the existing VecModel to be updated in place")
    });
    assert_eq!(kept.row_data(1).unwrap().label, "c");
    sync_rows(model, vec![row("x")], |_| panic!("resize stays in place"));
    assert_eq!(kept.row_count(), 1);
    let replaced = Cell::new(false);
    sync_rows(ModelRc::default(), vec![row("n")], |m| {
        replaced.set(m.row_count() == 1)
    });
    assert!(
        replaced.get(),
        "foreign model: expected a replacement VecModel"
    );
}

#[test]
fn status_tone_tracks_the_operation_outcome_and_engine_connection() {
    for (outcome, tone) in [
        (Outcome::Idle, Tone::Quiet),
        (Outcome::Verified, Tone::Good),
        (Outcome::VerificationIncomplete, Tone::Attention),
        (Outcome::Interrupted, Tone::Attention),
        (Outcome::Failed, Tone::Danger),
        (Outcome::PublicationIncomplete, Tone::Danger),
    ] {
        assert_eq!(status_tone(outcome), tone, "outcome {outcome:?}");
    }
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    {
        let mut state = state.lock().unwrap();
        state.session.connected = false;
        state.session.outcome = Outcome::Failed;
        sync(&window, &state);
    }
    assert_eq!(
        window.get_engine_tone(),
        Tone::Attention,
        "disconnected engine"
    );
    assert_eq!(window.get_status_tone(), Tone::Danger, "failed operation");
    {
        let mut state = state.lock().unwrap();
        state.session.connected = true;
        state.session.outcome = Outcome::Verified;
        sync(&window, &state);
    }
    assert_eq!(window.get_engine_tone(), Tone::Good, "connected engine");
    assert_eq!(window.get_status_tone(), Tone::Good, "verified output");
}

#[test]
fn binding_shows_the_package_version_on_the_about_page() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, _state) = bound_window(Settings::default(), None);
    assert_eq!(
        window.get_app_version(),
        env!("CARGO_PKG_VERSION"),
        "about page: expected the crate version"
    );
}

#[test]
fn changing_engine_discards_the_previous_handshake_contract() {
    i_slint_backend_testing::init_no_event_loop();
    let (_window, state) = bound_window(Settings::default(), None);
    let data = json!({"verification_required_checks":["old-check"],
        "exit_codes":{"ok":0,"failed":1,"usage":2,"publication_incomplete":3},
        "error_codes":[{"code":"USAGE","exit":2},{"code":"PUBLISH_INCOMPLETE","exit":3},
            {"code":"VERIFICATION_INCOMPLETE","exit":1}]});
    let mut desktop = state.lock().unwrap();
    desktop.session.engine_contract = Some(Arc::new(
        crate::engine::EngineContract::from_capabilities(&data).unwrap(),
    ));
    desktop.session.connected = true;
    preview_engine(&mut desktop, Some("/different/fake-bme".into()));
    assert!(
        desktop.session.engine_contract.is_none(),
        "engine change: expected previous contract cleared | received retained contract"
    );
    assert!(!desktop.session.connected);
}

#[cfg(unix)]
#[test]
fn engine_child_inherits_normalized_bme_home_overrides() {
    use std::os::unix::fs::PermissionsExt;
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake-engine");
    std::fs::write(&script, "#!/bin/sh\nprintf '{\"product\":\"biosmod-engine\",\"protocol\":\"bme/1\",\"version\":\"1\",\"command\":\"version\",\"ok\":true,\"data\":{\"config\":\"%s\",\"cache\":\"%s\",\"data\":\"%s\",\"cwd\":\"%s\"}}' \"$BME_CONFIG_HOME\" \"$BME_CACHE_HOME\" \"$BME_DATA_HOME\" \"$PWD\"\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (_window, state) = bound_window(Settings::default(), None);
    let mut desktop = state.lock().unwrap();
    desktop.engine_path = script;
    desktop.engine_home_overrides = crate::settings::home_overrides(
        dir.path(),
        [
            Some("config".into()),
            Some("cache".into()),
            Some("data".into()),
        ],
    );
    let engine = configured_engine(&desktop).unwrap();
    let reply = engine
        .run(
            &crate::engine::Request::Version,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
    for (field, subdir) in [("config", "config"), ("cache", "cache"), ("data", "data")] {
        assert_eq!(
            reply.data[field],
            dir.path().join(subdir).to_str().unwrap(),
            "child {field}: expected startup-relative directory | received {}",
            reply.data[field]
        );
    }
    assert_eq!(reply.data["cwd"], "/");
}

#[test]
fn busy_session_disables_patch_checkbox_without_changing_eligibility() {
    use i_slint_backend_testing::ElementHandle;
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    make_reviewable(&state, true);
    {
        let mut desktop = state.lock().unwrap();
        desktop.session.review = None;
        sync(&window, &desktop);
    }
    window.show().unwrap();
    let checkbox = ElementHandle::find_by_accessible_label(&window, "Correction")
        .next()
        .expect("patch checkbox");
    assert_eq!(checkbox.accessible_enabled(), Some(true));
    let _job = state
        .lock()
        .unwrap()
        .session
        .prepare(Action::Connect)
        .unwrap();
    sync(&window, &state.lock().unwrap());
    assert!(
        window.get_patches().row_data(0).unwrap().selectable,
        "eligible patch: expected eligibility retained while busy"
    );
    assert_eq!(
        checkbox.accessible_enabled(),
        Some(false),
        "busy patch checkbox: expected disabled | received enabled"
    );
    window.invoke_toggle_patch(0);
    assert!(
        !state
            .lock()
            .unwrap()
            .session
            .scan
            .as_ref()
            .unwrap()
            .report
            .patches[0]
            .selected
    );
}

#[test]
fn timers_for_independent_windows_remain_independent() {
    i_slint_backend_testing::init_no_event_loop();
    let first_calls = Rc::new(Cell::new(0));
    let second_calls = Rc::new(Cell::new(0));
    let first = slint::Timer::default();
    let second = slint::Timer::default();
    let calls = first_calls.clone();
    first.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(1),
        move || calls.set(calls.get() + 1),
    );
    let calls = second_calls.clone();
    second.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(1),
        move || calls.set(calls.get() + 1),
    );
    let first_id = register_timer(first);
    let second_id = register_timer(second);
    i_slint_backend_testing::mock_elapsed_time(Duration::from_secs(1));
    assert_eq!((first_calls.get(), second_calls.get()), (1, 1));
    stop_timer(first_id);
    i_slint_backend_testing::mock_elapsed_time(Duration::from_secs(1));
    assert_eq!(
        (first_calls.get(), second_calls.get()),
        (1, 2),
        "stopping one window's timer must leave the other active"
    );
    stop_timer(second_id);
}

#[test]
fn tools_view_shows_controlled_failure_and_paths() {
    i_slint_backend_testing::init_no_event_loop();
    let (window, state) = bound_window(Settings::default(), None);
    {
        let mut state = state.lock().unwrap();
        state.session.tool_report = Some((
            json!({"checks": [{"check":"java", "ok":false, "detail":"not installed"}], "error":{"code":"TOOL_UNAVAILABLE", "message":"missing optional tools"}}),
            Some(json!({"config":"fixture-config"})),
        ));
        sync(&window, &state);
    }
    let details = window.get_tool_details();
    assert!(details.contains("TOOL_UNAVAILABLE"));
    assert!(details.contains("not installed"));
    assert!(details.contains("fixture-config"));
}
