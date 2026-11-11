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
    window.set_can_build(true);
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

/// Fill the flash chip page with a completed check, long paths included.
fn populate_flash(window: &AppWindow) {
    window.set_flash_supported(true);
    window.set_flash_programmer("ch341a_spi".into());
    window.set_flash_backup_path(
        "/home/user/firmware/a-very-long-directory-name/another-long-directory/bios-backup.bin"
            .into(),
    );
    window.set_flash_image_path(
        "/home/user/firmware/a-very-long-directory-name/another-long-directory/bios-backup.patched.bin"
            .into(),
    );
    window.set_flash_checked(true);
    window.set_flash_acknowledged(true);
    window.set_can_flash_write(true);
    let check = biosmod_gui::controller::FlashReport::Check(serde_json::json!({
        "image_sha256": "bba72e771e75036c666ed04d87bf9631a57a380af71d039a2feaacff5077d08a",
        "regions": [{"name": "bios", "start": 0x300000, "end": 0x1000000, "changed_bytes": 412}]
    }));
    window.set_flash_details(biosmod_gui::desktop::flash_summary(window, &check));
}

/// Fill the Tools page. `blocked` is the first-run state: Java missing, so the Ghidra install
/// waits; otherwise Ghidra can be installed and a saved flashrom has a Reset button.
fn populate_tools(window: &AppWindow, last_first: bool, blocked: bool) {
    let tool = |id: &str,
                name: &str,
                health: &str,
                version: Option<&str>,
                path: Option<&str>,
                origin: &str,
                detail: &str,
                method: &str,
                command: Option<&str>,
                automatic: bool,
                custom: bool,
                wait: Option<&str>,
                optional: bool| {
        serde_json::json!({
            "id": id, "name": name, "purpose": "", "health": health, "version": version,
            "path": path, "origin": origin, "detail": detail,
            "install": {"method": method, "command": command, "automatic": automatic, "blocked": wait},
            "custom_location": custom, "optional": optional
        })
    };
    let wait = blocked
        .then_some("Java JDK must be ready first: setup checks it before downloading anything");
    let ghidra_command = (!blocked).then_some("bme tools setup ghidra");
    let jdk = if blocked {
        tool(
            "jdk",
            "Java JDK",
            "missing",
            None,
            None,
            "PATH",
            "javac: not found",
            "package-manager",
            Some("sudo apt install openjdk-21-jdk"),
            false,
            false,
            None,
            false,
        )
    } else {
        tool(
            "jdk",
            "Java JDK",
            "ready",
            Some("25"),
            Some("/usr/bin/javac"),
            "PATH",
            "javac 25",
            "package-manager",
            Some("sudo apt install openjdk-21-jdk"),
            false,
            false,
            None,
            false,
        )
    };
    let report = serde_json::json!({"ready": false, "platform": "linux", "tools": [
        tool("ghidra", "Ghidra", "missing", None, Some("/home/user/.local/share/biosmod-engine/tools/ghidra_12.2_PUBLIC"), "managed", "support/analyzeHeadless not found in this directory", "bme", ghidra_command, !blocked, true, wait, false),
        tool("firmware-utils", "ghidra-firmware-utils", "missing", None, None, "managed", "needs Ghidra first", "bme", ghidra_command, !blocked, false, wait, false),
        tool("java", "Java runtime", "ready", Some("25"), Some("/usr/bin/java"), "PATH", "java 25", "package-manager", Some("sudo apt install openjdk-21-jdk"), false, false, None, false),
        jdk,
        tool("git", "Git", "ready", Some("2.53.0"), Some("/usr/bin/git"), "PATH", "git version 2.53.0", "package-manager", Some("sudo apt install git"), false, false, None, false),
        tool("flashrom", "flashrom", "ready", Some("1.6.0"), Some("/opt/flashrom/bin/flashrom"), "config", "flashrom answers --version", "package-manager", Some("sudo apt install flashrom"), false, true, None, false),
        tool("nasm", "NASM", "missing", None, None, "PATH", "not found in PATH", "package-manager", Some("sudo apt install nasm"), false, false, None, true),
    ]});
    let mut rows = biosmod_gui::desktop::tool_rows(window, &report);
    if last_first {
        rows.reverse();
    }
    window.set_tool_rows(ModelRc::new(VecModel::from(rows)));
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
    let requested_size = std::env::var("BME_GUI_SIZE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|size| {
            let (w, h) = size
                .split_once('x')
                .expect("BME_GUI_SIZE: expected WIDTHxHEIGHT");
            slint::LogicalSize::new(w.parse().unwrap(), h.parse().unwrap())
        });
    if let Some(theme) = std::env::var("BME_GUI_THEME")
        .ok()
        .and_then(|t| t.parse::<i32>().ok())
    {
        window.set_theme_choice(theme);
        window.invoke_apply_theme();
    }
    // Keep the initial window within the desktop while the backend initializes;
    // otherwise its larger preferred size can trigger compositor maximization.
    if let Some(size) = requested_size {
        window.window().set_size(size);
    }
    window.show().unwrap();
    // Wayland delivers its initial scale asynchronously. Process the first
    // configure event before interpreting the requested logical dimensions.
    if native {
        slint::Timer::single_shot(std::time::Duration::from_millis(100), || {
            let _ = slint::quit_event_loop();
        });
        slint::run_event_loop().unwrap();
    }
    if let Some(size) = requested_size {
        // Slint's override can differ from the compositor's scale. Use physical
        // pixels explicitly instead of letting winit convert logical dimensions.
        let scale = window.window().scale_factor();
        window.window().set_size(slint::PhysicalSize::new(
            (size.width * scale).round() as u32,
            (size.height * scale).round() as u32,
        ));
    }
    populate(&window);
    let dir = std::env::var_os("BME_GUI_GALLERY").map(std::path::PathBuf::from);
    let shot = |name: &str| {
        if let (true, Some(dir)) = (native, &dir) {
            // Let 120ms property animations finish before the snapshot.
            slint::Timer::single_shot(std::time::Duration::from_millis(250), || {
                let _ = slint::quit_event_loop();
            });
            slint::run_event_loop().unwrap();
            if let Some(size) = requested_size {
                let scale = window.window().scale_factor();
                let actual = window.window().size();
                let expected_width = (size.width * scale).round() as u32;
                let expected_height = (size.height * scale).round() as u32;
                assert_eq!(
                    (actual.width, actual.height),
                    (expected_width, expected_height),
                    "(gallery window): expected {size:?} logical pixels at scale {scale} | received {actual:?} physical pixels"
                );
            }
            capture(&window, dir, name);
        }
    };
    shot("1-selected");
    window.set_stage(2);
    let plan = serde_json::json!({"schema":"bme.plan/1", "firmware":"synthetic", "source":{"alias":"lab"}});
    let review = biosmod_gui::controller::Review::preview(plan.clone());
    window.set_plan_details(biosmod_gui::desktop::plan_summary(&window, &review));
    window.set_plan_snapshot(serde_json::to_string_pretty(&plan).unwrap().into());
    shot("10-selection-details");
    window.set_stage(1);
    window.set_page(4);
    shot("9-settings");
    populate_flash(&window);
    window.set_page(5);
    shot("11-flash-chip");
    populate_tools(&window, false, false);
    window.set_page(1);
    shot("12-tools");
    // Keep the blocked state at the requested gallery size too; CI covers both
    // the minimum window and a larger window, including scaled captures.
    populate_tools(&window, false, true);
    shot("12-tools-blocked");
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
    slint::platform::update_timers_and_animations();
    populate(&window);
    window.set_paths_open(true);
    let button = ElementHandle::find_by_accessible_label(
        &window,
        if language == biosmod_gui::i18n::Language::PtBr {
            "Gerar cópia com patches"
        } else {
            "Build patched copy"
        },
    )
    .next()
    .expect("element: Build patched copy button | received: none");
    let bottom = button.absolute_position().y + button.size().height;
    assert!(
        bottom <= 600.0 - 44.0,
        "(footer): expected Build patched copy bottom <= 556 above the status bar | received: {bottom}"
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
    slint::platform::update_timers_and_animations();
    populate(&window);
    let button = ElementHandle::find_by_accessible_label(
        &window,
        if language == biosmod_gui::i18n::Language::PtBr {
            "Gerar cópia com patches"
        } else {
            "Build patched copy"
        },
    )
    .next()
    .expect("element: Build patched copy button | received: none");
    let right = button.absolute_position().x + button.size().width;
    let limit = (1600.0 + 1120.0) / 2.0;
    assert!(
        right <= limit + 0.5,
        "(content column): expected Build patched copy right edge <= {limit} | received: {right}"
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
                "Open selection file",
                "Open output",
                "Enter paths",
            ],
        ),
        (
            biosmod_gui::i18n::Language::PtBr,
            [
                "Configurações",
                "Sobre",
                "Abrir arquivo de seleção",
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
            slint::platform::update_timers_and_animations();
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

#[test]
fn review_fields_keep_build_control_above_status_at_minimum_size() {
    i_slint_backend_testing::init_no_event_loop();
    for (language, label) in [
        (biosmod_gui::i18n::Language::En, "Build patched copy"),
        (biosmod_gui::i18n::Language::PtBr, "Gerar cópia com patches"),
    ] {
        let window = AppWindow::new().unwrap();
        language.select().unwrap();
        window
            .window()
            .set_size(slint::LogicalSize::new(760.0, 600.0));
        window.show().unwrap();
        populate(&window);
        window.set_stage(2);
        window.set_plan_details("Plan summary".into());
        window.set_plan_snapshot("{\"schema\":\"bme.plan/1\"}".into());
        let button = ElementHandle::find_by_accessible_label(&window, label)
            .next()
            .unwrap_or_else(|| panic!("review: expected {label:?} control | received none"));
        let bottom = button.absolute_position().y + button.size().height;
        assert!(
            bottom <= 556.0,
            "review ({language:?}): expected build control bottom <= 556 above status bar | received {bottom}"
        );
    }
    biosmod_gui::i18n::Language::En.select().unwrap();
}

#[test]
fn resizing_open_paths_preserves_the_minimum_window() {
    let native = std::env::var_os("BME_GUI_NATIVE_RESIZE").is_some();
    if native {
        slint::BackendSelector::new().select().unwrap();
    } else {
        i_slint_backend_testing::init_no_event_loop();
    }
    let window = AppWindow::new().unwrap();
    biosmod_gui::i18n::Language::En.select().unwrap();
    window.show().unwrap();
    if native {
        slint::Timer::single_shot(std::time::Duration::from_millis(100), || {
            let _ = slint::quit_event_loop();
        });
        slint::run_event_loop().unwrap();
    }
    populate(&window);
    window.set_paths_open(true);
    for (width, height) in [(1400, 780), (760, 600), (1200, 780), (760, 600)] {
        let scale = window.window().scale_factor();
        let expected = slint::PhysicalSize::new(
            (width as f32 * scale).round() as u32,
            (height as f32 * scale).round() as u32,
        );
        window.window().set_size(expected);
        if native {
            slint::Timer::single_shot(std::time::Duration::from_millis(250), || {
                let _ = slint::quit_event_loop();
            });
            slint::run_event_loop().unwrap();
        } else {
            slint::platform::update_timers_and_animations();
        }
        let actual = window.window().size();
        assert_eq!(
            (actual.width, actual.height),
            (expected.width, expected.height),
            "(window resize): expected {width}x{height} at scale {scale} | received {}x{} physical pixels",
            actual.width,
            actual.height
        );
        let button = ElementHandle::find_by_accessible_label(&window, "Build patched copy")
            .next()
            .expect("element: Build patched copy button | received: none");
        let bottom = button.absolute_position().y + button.size().height;
        assert!(
            bottom <= height as f32 - 44.0,
            "(footer at {width}x{height}, scale {scale}): expected bottom <= {} | received {bottom}",
            height - 44
        );
    }
}

/// Every flash chip control stays inside the minimum window, above the status bar,
/// in both languages; the page adds a navigation tab to an already full header.
#[test]
fn flash_page_fits_the_minimum_window() {
    i_slint_backend_testing::init_no_event_loop();
    for (language, labels) in [
        (
            biosmod_gui::i18n::Language::En,
            [
                "Flash chip",
                "Diagnostics",
                "Find chip",
                "Ask for administrator rights",
                "Back up chip",
                "Check the image against the chip",
                "I can recover this board if it does not start",
            ],
        ),
        (
            biosmod_gui::i18n::Language::PtBr,
            [
                "Gravar chip",
                "Diagnósticos",
                "Localizar chip",
                "Pedir direitos de administrador",
                "Fazer backup do chip",
                "Conferir a imagem com o chip",
                "Consigo recuperar esta placa se ela não iniciar",
            ],
        ),
    ] {
        let window = AppWindow::new().unwrap();
        language.select().unwrap();
        window
            .window()
            .set_size(slint::LogicalSize::new(760.0, 600.0));
        window.show().unwrap();
        slint::platform::update_timers_and_animations();
        populate(&window);
        populate_flash(&window);
        window.set_page(5);
        for label in labels {
            let elements: Vec<ElementHandle> =
                ElementHandle::find_by_accessible_label(&window, label).collect();
            assert!(
                !elements.is_empty(),
                "(flash page, {language:?}): expected control {label:?} | received: none"
            );
            for element in elements {
                let position = element.absolute_position();
                let size = element.size();
                assert!(
                    position.x >= 0.0 && position.x + size.width <= 760.5,
                    "(flash page, {language:?}): expected {label:?} inside 0..760 | received: {}..{}",
                    position.x,
                    position.x + size.width
                );
                assert!(
                    position.y + size.height <= 600.0 - 44.0 + 0.5,
                    "(flash page, {language:?}): expected {label:?} bottom <= 556 above the status bar | received: {}",
                    position.y + size.height
                );
            }
        }
        let actual = window
            .window()
            .size()
            .to_logical(window.window().scale_factor());
        assert_eq!(
            (actual.width, actual.height),
            (760.0, 600.0),
            "(flash page, {language:?}): expected the minimum window to hold the page"
        );
        window.hide().unwrap();
    }
    biosmod_gui::i18n::Language::En.select().unwrap();
}

/// Every tool card control stays inside the minimum window in both languages.
#[test]
fn tools_page_fits_the_minimum_window() {
    i_slint_backend_testing::init_no_event_loop();
    for (language, labels) in [
        (
            biosmod_gui::i18n::Language::En,
            ["Download and install", "Choose location…", "Reset"],
        ),
        (
            biosmod_gui::i18n::Language::PtBr,
            ["Baixar e instalar", "Escolher local…", "Restaurar"],
        ),
    ] {
        let window = AppWindow::new().unwrap();
        language.select().unwrap();
        window
            .window()
            .set_size(slint::LogicalSize::new(760.0, 600.0));
        window.show().unwrap();
        slint::platform::update_timers_and_animations();
        // The list only builds the cards that fit, so check the saved-location card
        // (Reset) first and the missing-Ghidra card (Install) after it.
        let mut seen = std::collections::BTreeSet::new();
        for last_first in [true, false] {
            populate_tools(&window, last_first, false);
            window.set_page(1);
            slint::platform::update_timers_and_animations();
            for label in labels {
                let visible =
                    ElementHandle::find_by_element_type_name(&window, "Button").any(|button| {
                        button
                            .accessible_label()
                            .is_some_and(|text| text.starts_with(label))
                    });
                if !visible {
                    continue;
                }
                let elements: Vec<ElementHandle> =
                    ElementHandle::find_by_element_type_name(&window, "Button")
                        .filter(|button| {
                            button
                                .accessible_label()
                                .is_some_and(|text| text.starts_with(label))
                        })
                        .collect();
                seen.insert(label);
                for element in elements {
                    let position = element.absolute_position();
                    let size = element.size();
                    assert!(
                        position.x >= 0.0 && position.x + size.width <= 760.5,
                        "(tools page, {language:?}): expected {label:?} inside 0..760 | received: {}..{}",
                        position.x,
                        position.x + size.width
                    );
                }
            }
        }
        assert_eq!(
            seen.len(),
            labels.len(),
            "(tools page, {language:?}): expected buttons {labels:?} | received {seen:?}"
        );
        window.hide().unwrap();
    }
    biosmod_gui::i18n::Language::En.select().unwrap();
}
