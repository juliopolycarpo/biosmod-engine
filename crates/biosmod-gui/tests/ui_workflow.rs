//! Drive a real synthetic workflow through the Slint event loop and desktop callbacks.

mod common;

use biosmod_gui::controller::{Outcome, manifest_path};
use biosmod_gui::desktop::{Desktop, bind, connect};
use biosmod_gui::i18n::Language;
use biosmod_gui::settings::{PreferencesStore, Settings};
use biosmod_gui::ui::AppWindow;
use slint::{ComponentHandle, Model, Timer, TimerMode};
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant};

fn save_screenshot(window: &AppWindow, path: &Path) -> Result<(), String> {
    let pixels = window.window().take_snapshot().map_err(|e| e.to_string())?;
    let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let mut encoder = png::Encoder::new(file, pixels.width(), pixels.height());
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .map_err(|e| e.to_string())?
        .write_image_data(pixels.as_bytes())
        .map_err(|e| e.to_string())
}

/// Parse `WIDTHxHEIGHT` in logical pixels. Example: `parse_size("760x600")`.
fn parse_size(text: &str) -> slint::LogicalSize {
    let parsed = text
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)));
    let Some((width, height)) = parsed else {
        panic!("BME_GUI_SIZE: expected WIDTHxHEIGHT such as 760x600 | received {text:?}");
    };
    slint::LogicalSize::new(width, height)
}

/// Save one screenshot per non-workflow page next to the workflow captures.
fn save_pages(window: &AppWindow, path: &Path) -> Result<(), String> {
    for (page, name) in [
        (1, "sources"),
        (2, "diagnostics"),
        (4, "settings"),
        (3, "about"),
    ] {
        window.set_page(page);
        save_stage(window, Some(path), name)?;
    }
    window.set_page(0);
    Ok(())
}

#[test]
fn size_argument_requires_width_and_height() {
    let size = parse_size("760x600");
    assert_eq!((size.width, size.height), (760., 600.));
    let result = std::panic::catch_unwind(|| parse_size("760"));
    assert!(
        result.is_err(),
        "parse_size: expected a panic for a missing height"
    );
}

fn save_stage(window: &AppWindow, path: Option<&Path>, stage: &str) -> Result<(), String> {
    let Some(path) = path else { return Ok(()) };
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("screenshot: expected a UTF-8 filename")?;
    let path = path.with_file_name(format!("{stem}-{stage}.png"));
    save_screenshot(window, &path)
        .map_err(|error| format!("screenshot {}: {error}", path.display()))
}

#[test]
fn real_desktop_synthetic_workflow() {
    // Start a child with its own CLI directories: setting the environment in the
    // child before the test harness starts avoids mutating process-global state.
    if std::env::var_os("BME_GUI_UI_TEST_CHILD").is_none() {
        let root = tempfile::Builder::new()
            .prefix("bme-gui-ui-")
            .tempdir()
            .unwrap();
        let binary = common::test_engine();
        let stdout_path = root.path().join("child.stdout");
        let stderr_path = root.path().join("child.stderr");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "real_desktop_synthetic_workflow", "--nocapture"])
            .env("BME_GUI_UI_TEST_CHILD", "1")
            .env("BME_GUI_UI_TEST_ROOT", root.path())
            .env("BME_TEST_ENGINE", &binary)
            .env("BME_CONFIG_HOME", root.path().join("config"))
            .env("BME_CACHE_HOME", root.path().join("cache"))
            .env("BME_DATA_HOME", root.path().join("data"))
            .stdout(Stdio::from(std::fs::File::create(&stdout_path).unwrap()))
            .stderr(Stdio::from(std::fs::File::create(&stderr_path).unwrap()))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(25);
        let (status, timed_out) = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break (status, false);
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                break (child.wait().unwrap(), true);
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        assert!(
            status.success() && !timed_out,
            "desktop child: expected completion within 25s | received {status}, timed_out={timed_out}\nstdout:\n{}\nstderr:\n{}",
            std::fs::read_to_string(stdout_path).unwrap_or_default(),
            std::fs::read_to_string(stderr_path).unwrap_or_default()
        );
        return;
    }

    let root = PathBuf::from(std::env::var_os("BME_GUI_UI_TEST_ROOT").unwrap());
    let engine = common::test_engine();
    let image = common::setup_fixture(&engine, &root);
    let output = image.with_file_name("synthetic.patched.bin");
    if std::env::var_os("BME_GUI_NATIVE_SMOKE").is_none() {
        i_slint_backend_testing::init_integration_test_with_system_time();
    } else {
        slint::BackendSelector::new().select().unwrap();
    }
    let window = AppWindow::new().unwrap();
    let theme = std::env::var("BME_GUI_THEME")
        .ok()
        .map(|value| {
            value
                .parse::<u8>()
                .ok()
                .filter(|value| *value <= 2)
                .expect("BME_GUI_THEME: expected 0, 1, or 2")
        })
        .unwrap_or_default();
    let settings = Settings {
        language: if std::env::var("BME_GUI_LANGUAGE").as_deref() == Ok("pt-BR") {
            Language::PtBr
        } else {
            Language::En
        },
        theme,
        ..Settings::default()
    };
    let language = settings.language;
    language.select().unwrap();
    let settings_label = if language == Language::PtBr {
        "Configurações"
    } else {
        "Settings"
    };
    assert!(
        i_slint_backend_testing::ElementHandle::find_by_accessible_label(&window, settings_label)
            .next()
            .is_some(),
        "startup accessibility: expected {settings_label}"
    );
    let mut desktop = Desktop::new(engine, settings, PreferencesStore::Unavailable).unwrap();
    desktop.session.change_image(Some(image));
    desktop.session.source = "lab".into();
    let state = bind(&window, desktop);
    if let Some(size) = std::env::var("BME_GUI_SIZE").ok().filter(|s| !s.is_empty()) {
        window.window().set_size(parse_size(&size));
    }
    window.show().unwrap();
    connect(&window, &state);

    let phase = Rc::new(Cell::new(0_u8));
    let result = Rc::new(RefCell::new(None::<Result<(), String>>));
    let started = Instant::now();
    let tick_phase = phase.clone();
    let settle_until = Rc::new(Cell::new(None::<Instant>));
    let tick_settle = settle_until.clone();
    let tick_result = result.clone();
    let tick_state = state.clone();
    let weak = window.as_weak();
    let tick_output = output.clone();
    let selection_file = root.join("built selection.json");
    let replay_output = root.join("replayed selection.bin");
    let screenshot = std::env::var_os("BME_GUI_SCREENSHOT").map(PathBuf::from);
    let timer = Timer::default();
    timer.start(TimerMode::Repeated, Duration::from_millis(25), move || {
        let Some(window) = weak.upgrade() else { return };
        let state = tick_state.lock().unwrap();
        if started.elapsed() > Duration::from_secs(20) {
            *tick_result.borrow_mut() = Some(Err(format!(
                "phase {} timed out: {}",
                tick_phase.get(),
                state.session.status
            )));
            drop(state);
            let _ = slint::quit_event_loop();
            return;
        }
        if state.session.busy() || window.get_busy() {
            return;
        }
        if matches!(
            state.session.outcome,
            Outcome::Failed
                | Outcome::Interrupted
                | Outcome::PublicationIncomplete
                | Outcome::PublicationUnknown
                | Outcome::VerificationFailed
                | Outcome::VerificationIncomplete
        ) {
            *tick_result.borrow_mut() = Some(Err(format!(
                "phase {}: {}\n{}",
                tick_phase.get(),
                state.session.status,
                state.session.diagnostics
            )));
            drop(state);
            let _ = slint::quit_event_loop();
            return;
        }
        let current = tick_phase.get();
        match current {
            0 => {
                if !state.session.connected {
                    *tick_result.borrow_mut() =
                        Some(Err(format!("engine handshake: {}", state.session.status)));
                    drop(state);
                    let _ = slint::quit_event_loop();
                    return;
                }
                drop(state);
                tick_phase.set(1);
                window.invoke_inspect();
            }
            1 => {
                if state.session.inspection.is_none() {
                    *tick_result.borrow_mut() =
                        Some(Err(format!("inspection missing: {}", state.session.status)));
                    drop(state);
                    let _ = slint::quit_event_loop();
                    return;
                }
                drop(state);
                tick_phase.set(2);
                window.invoke_scan();
            }
            2 => {
                let index = state.session.scan.as_ref().and_then(|scan| {
                    scan.report
                        .patches
                        .iter()
                        .position(|p| p.id == "PA" && p.selectable())
                });
                drop(state);
                let Some(index) = index else {
                    *tick_result.borrow_mut() =
                        Some(Err("scan: expected selectable synthetic PA".into()));
                    let _ = slint::quit_event_loop();
                    return;
                };
                if window.get_patches().row_data(index).is_none() {
                    *tick_result.borrow_mut() =
                        Some(Err(format!("scan: missing displayed patch row {index}")));
                    let _ = slint::quit_event_loop();
                    return;
                }
                window.invoke_toggle_patch(index as i32);
                if !window.get_can_build()
                    || window.get_output_path().as_str() != tick_output.to_string_lossy()
                {
                    *tick_result.borrow_mut() = Some(Err(
                        "selection: expected Build enabled with the default output".into(),
                    ));
                    let _ = slint::quit_event_loop();
                    return;
                }
                tick_settle.set(Some(Instant::now() + Duration::from_millis(150)));
                tick_phase.set(3);
            }
            3 => {
                if tick_settle
                    .get()
                    .is_some_and(|deadline| Instant::now() < deadline)
                {
                    return;
                }
                drop(state);
                if let Err(error) = save_stage(&window, screenshot.as_deref(), "scan") {
                    *tick_result.borrow_mut() = Some(Err(error));
                    let _ = slint::quit_event_loop();
                    return;
                }
                tick_phase.set(4);
                window.invoke_build();
            }
            4 if state.session.outcome == Outcome::Verified => {
                drop(state);
                if !window.get_can_export_selection() {
                    *tick_result.borrow_mut() =
                        Some(Err("result: expected Export selection enabled".into()));
                    let _ = slint::quit_event_loop();
                    return;
                }
                tick_phase.set(5);
                window.invoke_export_plan_path(selection_file.to_string_lossy().as_ref().into());
            }
            5 => {
                if std::fs::read(&selection_file).ok().as_deref()
                    != state
                        .session
                        .built_plan
                        .as_ref()
                        .map(|plan| plan.bytes.as_slice())
                {
                    *tick_result.borrow_mut() = Some(Err(
                        "result export: expected the retained build document".into(),
                    ));
                    drop(state);
                    let _ = slint::quit_event_loop();
                    return;
                }
                drop(state);
                window.invoke_back_to_selection();
                window.invoke_output_edited(replay_output.to_string_lossy().as_ref().into());
                tick_phase.set(6);
                window.invoke_open_plan_path(selection_file.to_string_lossy().as_ref().into());
            }
            6 => {
                if !state.session.can_build() || state.session.imported_recipe().is_none() {
                    *tick_result.borrow_mut() = Some(Err(format!(
                        "import: expected automatic validation and Build | received {}",
                        state.session.status
                    )));
                    drop(state);
                    let _ = slint::quit_event_loop();
                    return;
                }
                drop(state);
                tick_phase.set(7);
                window.invoke_build();
            }
            _ => {
                if state.session.outcome != Outcome::Verified {
                    *tick_result.borrow_mut() = Some(Err(format!(
                        "auto-verification: expected verified | received {:?}: {}",
                        state.session.outcome, state.session.status
                    )));
                } else if window.get_result_title().as_str()
                    != if language == Language::PtBr {
                        "Verificação offline concluída"
                    } else {
                        "Offline verification complete"
                    }
                {
                    *tick_result.borrow_mut() = Some(Err(format!(
                        "localized completion: expected language {} | received {}",
                        language.identifier(),
                        window.get_result_title()
                    )));
                } else if !tick_output.is_file() || !manifest_path(&tick_output).is_file() {
                    *tick_result.borrow_mut() =
                        Some(Err("publication: expected output and manifest files".into()));
                } else if !replay_output.is_file() || !manifest_path(&replay_output).is_file() {
                    *tick_result.borrow_mut() =
                        Some(Err("replay: expected output and manifest files".into()));
                } else if std::fs::read(&replay_output).ok() != std::fs::read(&tick_output).ok() {
                    *tick_result.borrow_mut() =
                        Some(Err("replay: expected byte-identical output".into()));
                } else if let Some(path) = &screenshot {
                    *tick_result.borrow_mut() = Some(
                        save_screenshot(&window, path)
                            .and_then(|()| save_pages(&window, path))
                            .map_err(|e| format!("screenshot {}: {e}", path.display())),
                    );
                } else {
                    *tick_result.borrow_mut() = Some(Ok(()));
                }
                drop(state);
                let _ = slint::quit_event_loop();
            }
        }
    });
    slint::run_event_loop().unwrap();
    timer.stop();
    let outcome = result
        .borrow_mut()
        .take()
        .expect("event loop: expected a completion or timeout");
    outcome.unwrap_or_else(|error| panic!("desktop workflow: {error}"));
}
