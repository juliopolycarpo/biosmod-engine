//! Render states the synthetic workflow never reaches: selection, focus, busy, failure,
//! the empty list, manual paths and long values. Set `BME_GUI_GALLERY=<dir>` and run natively
//! (`BME_GUI_NATIVE_SMOKE=1`) to write the captures; otherwise the test only builds the states.

use biosmod_gui::ui::{AppWindow, Fact, PatchRow, Tone};
use i_slint_backend_testing::ElementHandle;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::path::Path;

fn row(
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
        state: state.into(),
        tone,
        detail: "defect present; patch applies to this exact build".into(),
        blocker: blocker.into(),
        evidence: "No hardware observations for this patch version.".into(),
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
        fact("Size", "16,777,216 bytes"),
        fact("Volumes", "6"),
        fact("Layout", "Intel flash descriptor"),
    ])));
    window.set_scan_facts(ModelRc::new(VecModel::from(vec![
        fact(
            "Source",
            "community-catalog-with-a-long-alias · catalog 2026.11.0",
        ),
        fact("Trust", "unsigned-local"),
        fact("Firmware", "unknown or ambiguous"),
        fact("Boards", "board-a, board-b, board-c"),
    ])));
    window.set_image_sha("bba72e771e75036c666ed04d87bf9631a57a380af71d039a2feaacff5077d08a".into());
    window.set_patches(ModelRc::new(VecModel::from(vec![
        row("Fix the C-state wake path", "Defect present", Tone::Attention, true, true, ""),
        row("Restore the fan curve table", "Defect present", Tone::Attention, false, true, ""),
        row("Update microcode loader", "Fixed", Tone::Good, false, false, "Desktop selection requires a present, independently plannable correction without hold or hardware gates. Joint prerequisites require the CLI."),
        row("Legacy boot option ROM", "Not detected", Tone::Quiet, false, false, "Requires physical observations: board-revision. Review with the CLI."),
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
    if let Some(size) = std::env::var("BME_GUI_SIZE").ok().filter(|s| !s.is_empty()) {
        let (w, h) = size
            .split_once('x')
            .expect("BME_GUI_SIZE: expected WIDTHxHEIGHT");
        window.window().set_size(slint::LogicalSize::new(
            w.parse().unwrap(),
            h.parse().unwrap(),
        ));
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
    window.set_operation_label("Scanning image".into());
    window.set_elapsed("12s".into());
    window.set_can_cancel(true);
    shot("3-busy");
    window.set_busy(false);
    window.set_status(
        "The engine reported a failure: module size: expected 604832 | received 604800".into(),
    );
    window.set_status_tone(Tone::Danger);
    shot("4-failed");
    window.set_status(
        "The engine reported a failure: module size: expected 604832 | received 604800 while rebuilding volume 3 of 6 (offset 0x1fe000, compressed section, LZMA stream, checksum mismatch in the reproduction step)"
            .into(),
    );
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
    window
        .window()
        .set_size(slint::LogicalSize::new(760.0, 600.0));
    window.show().unwrap();
    populate(&window);
    window.set_paths_open(true);
    let button = ElementHandle::find_by_accessible_label(&window, "Review selected")
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
    window
        .window()
        .set_size(slint::LogicalSize::new(1600.0, 1000.0));
    window.show().unwrap();
    populate(&window);
    let button = ElementHandle::find_by_accessible_label(&window, "Review selected")
        .next()
        .expect("element: Review selected button | received: none");
    let right = button.absolute_position().x + button.size().width;
    let limit = (1600.0 + 1120.0) / 2.0;
    assert!(
        right <= limit + 0.5,
        "(content column): expected Review selected right edge <= {limit} | received: {right}"
    );
}
