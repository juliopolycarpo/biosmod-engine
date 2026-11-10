//! Startup locale selection must override Slint's automatic process-locale choice.

use biosmod_gui::{i18n::Language, settings::Settings, ui::AppWindow};
use i_slint_backend_testing::ElementHandle;

#[test]
fn first_presentation_defaults_to_english_under_portuguese_process_locale() {
    if std::env::var_os("BME_LANGUAGE_TEST_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "first_presentation_defaults_to_english_under_portuguese_process_locale",
                "--nocapture",
            ])
            .env("BME_LANGUAGE_TEST_CHILD", "1")
            .env("LANG", "pt_BR.UTF-8")
            .env("LC_ALL", "pt_BR.UTF-8")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Portuguese startup: expected English before showing | received {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    i_slint_backend_testing::init_no_event_loop();
    let ui = AppWindow::new().unwrap();
    // This is the same ordering as normal and smoke startup in main.rs.
    Settings::default().language.select().unwrap();
    assert!(
        ElementHandle::find_by_accessible_label(&ui, "Settings")
            .next()
            .is_some()
    );
    Language::PtBr.select().unwrap();
    assert!(
        ElementHandle::find_by_accessible_label(&ui, "Configurações")
            .next()
            .is_some()
    );
    Language::En.select().unwrap();
    assert!(
        ElementHandle::find_by_accessible_label(&ui, "Settings")
            .next()
            .is_some()
    );
}
