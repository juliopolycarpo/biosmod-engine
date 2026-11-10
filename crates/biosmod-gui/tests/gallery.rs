//! Render states the synthetic workflow never reaches: selection, focus, busy, failure,
//! the empty list, manual paths and long values. Set `BME_GUI_GALLERY=<dir>` and run natively
//! (`BME_GUI_NATIVE_SMOKE=1`) to write the captures; otherwise the test only builds the states.

use biosmod_gui::controller::{Action, Status};
use biosmod_gui::desktop::{localized_activity, localized_status};
use biosmod_gui::ui::{AppWindow, Fact, PatchRow, Tone, UiText};
use i_slint_backend_testing::ElementHandle;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::path::Path;

fn row(
    window: &AppWindow,
    title: &str,
    state: &str,
    tone: Tone,
    selected: bool,
    selectable: bool,
    blocker: &str,
) -> PatchRow {
    PatchRow {
        id: format!("lab::{title}@1.0.0").into(),
        title: title.into(),
        version: "1.0.0".into(),
        class: "correction".into(),
        tier: "recommended".into(),
        state: match state {
            "Defect present" => window.global::<UiText>().get_defect_present(),
            "Fixed" => window.global::<UiText>().get_fixed(),
            "Not detected" => window.global::<UiText>().get_not_detected(),
            _ => panic!("gallery state: expected a known patch state | received {state}"),
        },
        tone,
        detail: "defect present; patch applies to this exact build".into(),
        blocker: if blocker.is_empty() {
            "".into()
        } else if blocker.starts_with("Requires") {
            window
                .global::<UiText>()
                .invoke_requires_facts("board-revision".into())
        } else {
            window.global::<UiText>().get_selection_limit()
        },
        evidence: window.global::<UiText>().get_no_evidence(),
        selectable,
        selected,
    }
}

fn fact(label: &str, value: &str) -> Fact {
    Fact {
        label: label.into(),
        value: value.into(),
    }
}

fn populate(window: &AppWindow) {
    let text = window.global::<UiText>();
    window.set_image_path(
        "/home/user/firmware/a-very-long-directory-name/another-long-directory/board-image.bin"
            .into(),
    );
    window.set_source("lab".into());
    window.set_stage(1);
    window.set_can_scan(true);
    window.set_can_plan(true);
    window.set_can_recommend(true);
    window.set_can_inspect(true);
    window.set_engine_status("bme 0.1.0 · offline".into());
    window.set_engine_tone(Tone::Good);
    window.set_image_facts(ModelRc::new(VecModel::from(vec![
        fact(
            text.get_size().as_str(),
            text.invoke_bytes_size("16,777,216".into()).as_str(),
        ),
        fact(text.get_volumes().as_str(), "6"),
        fact(
            text.get_layout().as_str(),
            text.get_flash_descriptor().as_str(),
        ),
    ])));
    window.set_scan_facts(ModelRc::new(VecModel::from(vec![
        fact(
            text.get_source().as_str(),
            "community-catalog-with-a-long-alias · catalog 2026.11.0",
        ),
        fact(text.get_trust().as_str(), "unsigned-local"),
        fact(
            text.get_firmware().as_str(),
            text.get_unknown_firmware().as_str(),
        ),
        fact(text.get_boards().as_str(), "board-a, board-b, board-c"),
    ])));
    window.set_image_sha("bba72e771e75036c666ed04d87bf9631a57a380af71d039a2feaacff5077d08a".into());
    window.set_patches(ModelRc::new(VecModel::from(vec![
        row(window, "Fix the C-state wake path", "Defect present", Tone::Attention, true, true, ""),
        row(window, "Restore the fan curve table", "Defect present", Tone::Attention, false, true, ""),
        row(window, "Update microcode loader", "Fixed", Tone::Good, false, false, "Desktop selection requires a present, independently plannable correction without hold or hardware gates. Joint prerequisites require the CLI."),
        row(window, "Legacy boot option ROM", "Not detected", Tone::Quiet, false, false, "Requires physical observations: board-revision. Review with the CLI."),
    ])));
}

fn capture(window: &AppWindow, dir: &Path, name: &str) {
    let pixels = window.window().take_snapshot().unwrap();
    let file = std::fs::File::create(dir.join(format!("{name}.png"))).unwrap();
    let mut encoder = png::Encoder::new(file, pixels.width(), pixels.height());
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .unwrap()
        .write_image_data(pixels.as_bytes())
        .unwrap();
}

#[test]
fn gallery_states_build_and_capture() {
    let native = std::env::var_os("BME_GUI_NATIVE_SMOKE").is_some();
    if native {
        slint::BackendSelector::new().select().unwrap();
    } else {
        i_slint_backend_testing::init_no_event_loop();
    }
    let window = AppWindow::new().unwrap();
    let language = if std::env::var("BME_GUI_LANGUAGE").as_deref() == Ok("pt-BR") {
        biosmod_gui::i18n::Language::PtBr
    } else {
        biosmod_gui::i18n::Language::En
    };
    language.select().unwrap();
    window.set_language_index(language.index());
    if let Some(size) = std::env::var("BME_GUI_SIZE").ok().filter(|s| !s.is_empty()) {
        let (w, h) = size
            .split_once('x')
            .expect("BME_GUI_SIZE: expected WIDTHxHEIGHT");
        window.window().set_size(slint::LogicalSize::new(
            w.parse().unwrap(),
            h.parse().unwrap(),
        ));
    }
    if let Some(theme) = std::env::var("BME_GUI_THEME")
        .ok()
        .and_then(|t| t.parse::<i32>().ok())
    {
        window.set_theme_choice(theme);
        window.invoke_apply_theme();
    }
    window.show().unwrap();
    populate(&window);
    let dir = std::env::var_os("BME_GUI_GALLERY").map(std::path::PathBuf::from);
    let shot = |name: &str| {
        if let (true, Some(dir)) = (native, &dir) {
            // Let 120ms property animations finish before the snapshot.
            slint::Timer::single_shot(std::time::Duration::from_millis(250), || {
                let _ = slint::quit_event_loop();
            });
            slint::run_event_loop().unwrap();
            capture(&window, dir, name);
        }
    };
    shot("1-selected");
    window.set_page(4);
    shot("9-settings");
    window.set_page(0);
    let key = |text: slint::SharedString| {
        window
            .window()
            .dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.clone() });
        window
            .window()
            .dispatch_event(slint::platform::WindowEvent::KeyReleased { text });
    };
    key(slint::platform::Key::Tab.into());
    shot("6-focus-tab");
    for step in 2..=16 {
        key(slint::platform::Key::Tab.into());
        shot(&format!("focus-{step:02}"));
    }
    window.set_paths_open(true);
    shot("2-paths");
    window.set_paths_open(false);
    window.set_busy(true);
    window.set_operation_label(localized_activity(&window, Action::Scan));
    window.set_elapsed("12s".into());
    window.set_can_cancel(true);
    shot("3-busy");
    window.set_busy(false);
    window.set_status(localized_status(
        &window,
        Status::Failed,
        "",
        "module size: expected 604832 | received 604800",
    ));
    window.set_status_tone(Tone::Danger);
    shot("4-failed");
    window.set_status(localized_status(&window, Status::Failed, "", "module size: expected 604832 | received 604800 while rebuilding volume 3 of 6 (offset 0x1fe000, compressed section, LZMA stream, checksum mismatch in the reproduction step)"));
    shot("8-long-status");
    window.set_patches(ModelRc::new(VecModel::from(Vec::<PatchRow>::new())));
    window.set_image_facts(ModelRc::default());
    window.set_scan_facts(ModelRc::default());
    window.set_image_sha("".into());
    window.set_can_scan(false);
    window.set_stage(0);
    shot("5-empty");
    window.hide().unwrap();
}

/// The footer and status bar must stay inside the minimum window while the manual paths
/// panel is open; they used to be pushed out of view by about 70px.
#[test]
fn manual_paths_keep_footer_inside_minimum_window() {
    i_slint_backend_testing::init_no_event_loop();
    let window = AppWindow::new().unwrap();
    let language = if std::env::var("BME_GUI_LANGUAGE").as_deref() == Ok("pt-BR") {
        biosmod_gui::i18n::Language::PtBr
    } else {
        biosmod_gui::i18n::Language::En
    };
    language.select().unwrap();
    window
        .window()
        .set_size(slint::LogicalSize::new(760.0, 600.0));
    window.show().unwrap();
    populate(&window);
    window.set_paths_open(true);
    let button = ElementHandle::find_by_accessible_label(
        &window,
        if language == biosmod_gui::i18n::Language::PtBr {
            "Revisar selecionados"
        } else {
            "Review selected"
        },
    )
    .next()
    .expect("element: Review selected button | received: none");
    let bottom = button.absolute_position().y + button.size().height;
    assert!(
        bottom <= 600.0 - 44.0,
        "(footer): expected Review selected bottom <= 556 above the status bar | received: {bottom}"
    );
}

/// On a wide window the content stays in a centered column instead of stretching its rows.
#[test]
fn wide_window_centers_content_column() {
    i_slint_backend_testing::init_no_event_loop();
    let window = AppWindow::new().unwrap();
    let language = if std::env::var("BME_GUI_LANGUAGE").as_deref() == Ok("pt-BR") {
        biosmod_gui::i18n::Language::PtBr
    } else {
        biosmod_gui::i18n::Language::En
    };
    language.select().unwrap();
    window
        .window()
        .set_size(slint::LogicalSize::new(1600.0, 1000.0));
    window.show().unwrap();
    populate(&window);
    let button = ElementHandle::find_by_accessible_label(
        &window,
        if language == biosmod_gui::i18n::Language::PtBr {
            "Revisar selecionados"
        } else {
            "Review selected"
        },
    )
    .next()
    .expect("element: Review selected button | received: none");
    let right = button.absolute_position().x + button.size().width;
    let limit = (1600.0 + 1120.0) / 2.0;
    assert!(
        right <= limit + 0.5,
        "(content column): expected Review selected right edge <= {limit} | received: {right}"
    );
}

/// Navigation and workflow controls remain reachable at the minimum window width.
#[test]
fn minimum_width_keeps_navigation_and_path_controls_visible() {
    i_slint_backend_testing::init_no_event_loop();
    for (language, labels) in [
        (
            biosmod_gui::i18n::Language::En,
            [
                "Settings",
                "About",
                "Open plan",
                "Open output",
                "Enter paths",
            ],
        ),
        (
            biosmod_gui::i18n::Language::PtBr,
            [
                "Configurações",
                "Sobre",
                "Abrir plano",
                "Abrir saída",
                "Informar caminhos",
            ],
        ),
    ] {
        for width in [760.0, 1000.0, 1080.0, 1200.0, 1600.0] {
            let window = AppWindow::new().unwrap();
            language.select().unwrap();
            window
                .window()
                .set_size(slint::LogicalSize::new(width, 600.0));
            window.show().unwrap();
            populate(&window);
            for label in labels {
                let element = ElementHandle::find_by_accessible_label(&window, label)
                    .next()
                    .unwrap_or_else(|| {
                        panic!(
                            "(window width {width}): expected control {label:?} | received: none"
                        )
                    });
                let position = element.absolute_position();
                let size = element.size();
                assert!(
                    position.x >= 0.0 && position.x + size.width <= width + 0.5,
                    "(window width {width}): expected {label:?} inside 0..{width} | received: {}..{}",
                    position.x,
                    position.x + size.width
                );
            }
            window.hide().unwrap();
        }
    }
}
