//! Opt-in portal integration check on a running desktop session.
//! Run with `--ignored` and the desired SLINT_BACKEND/display environment.

use biosmod_gui::{
    desktop::{Desktop, bind},
    i18n::Language,
    settings::Settings,
    ui::{AppWindow, UiText},
};
use slint::ComponentHandle;

#[test]
#[ignore = "requires a running desktop with a native file-picker portal"]
fn portuguese_plan_picker_opens_through_the_native_portal() {
    slint::BackendSelector::new().select().unwrap();
    let window = AppWindow::new().unwrap();
    Language::PtBr.select().unwrap();
    let preferences = Settings {
        language: Language::PtBr,
        ..Settings::default()
    };
    let desktop = Desktop::new("/missing/bme".into(), preferences, None).unwrap();
    let _state = bind(&window, desktop);
    assert_eq!(
        window.global::<UiText>().get_open_plan(),
        "Abrir um plano para revisão"
    );
    assert_eq!(window.global::<UiText>().get_plan_filter(), "Plano");
    window.show().unwrap();
    window.invoke_import_plan();
    let weak = window.as_weak();
    slint::Timer::single_shot(std::time::Duration::from_secs(2), move || {
        let window = weak.upgrade().unwrap();
        assert!(
            window.get_busy(),
            "native picker: expected an active portal dialog | received status {}",
            window.get_status()
        );
        window.hide().unwrap();
        slint::quit_event_loop().unwrap();
    });
    slint::run_event_loop().unwrap();
}
