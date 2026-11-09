//! Exercise focus through actual pointer and keyboard events, including stage changes.

use biosmod_gui::controller::Review;
use biosmod_gui::desktop::{Desktop, bind};
use biosmod_gui::settings::Settings;
use biosmod_gui::ui::AppWindow;
use serde_json::json;
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, Model};

fn key(window: &AppWindow, text: slint::SharedString) {
    window
        .window()
        .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
    window
        .window()
        .dispatch_event(WindowEvent::KeyReleased { text });
}

fn click(window: &AppWindow, x: f32, y: f32) {
    let position = slint::LogicalPosition::new(x, y);
    window.window().dispatch_event(WindowEvent::PointerPressed {
        position,
        button: PointerEventButton::Left,
    });
    window
        .window()
        .dispatch_event(WindowEvent::PointerReleased {
            position,
            button: PointerEventButton::Left,
        });
}

fn settle(window: &AppWindow) {
    if std::env::var_os("BME_GUI_NATIVE_SMOKE").is_some() {
        window.window().take_snapshot().unwrap();
    } else {
        // A pointer event flushes pending layout changes in the testing backend.
        window.window().dispatch_event(WindowEvent::PointerMoved {
            position: slint::LogicalPosition::new(0., 0.),
        });
    }
}

#[test]
fn keyboard_focus_survives_patch_selection_and_image_invalidation() {
    if std::env::var_os("BME_GUI_NATIVE_SMOKE").is_none() {
        i_slint_backend_testing::init_no_event_loop();
    } else {
        slint::BackendSelector::new().select().unwrap();
    }
    let mut desktop = Desktop::new("/missing/bme".into(), Settings::default(), None).unwrap();
    desktop.session.connected = true;
    desktop.session.image = Some("/tmp/input.bin".into());
    desktop.session.scan = Some(serde_json::from_value(json!({
        "alias":"lab", "trust":"local", "catalog":"fixture", "catalog_version":"1",
        "report":{"firmware":"synthetic","boards":[],"patches":[{
            "id":"PA","version":"1.0.0","title":"Correction","class":"correction",
            "tier":"optional","state":"present","plannable":true,"manual":false,"detail":"exact match"
        }]}
    })).unwrap());
    let window = AppWindow::new().unwrap();
    let state = bind(&window, desktop);
    window.show().unwrap();
    window
        .window()
        .set_size(slint::LogicalSize::new(1080., 780.));
    settle(&window);

    // Source editor, then Scan, then the first checkbox in the findings list.
    click(&window, 300., 234.);
    key(&window, Key::Tab.into());
    key(&window, Key::Tab.into());
    key(&window, " ".into());
    assert!(
        window.get_patches().row_data(0).unwrap().selected,
        "first Space: expected a selected correction"
    );
    settle(&window);
    key(&window, " ".into());
    assert!(
        !window.get_patches().row_data(0).unwrap().selected,
        "second Space: expected the focused correction to toggle off"
    );

    state.lock().unwrap().session.review = Some(Review {
        path: "/tmp/plan.json".into(),
        bytes: b"{}".to_vec(),
        document: json!({"schema":"bme.plan/1"}),
        generated: true,
    });
    // Use a real callback to synchronize the generated-review screen.
    window.invoke_output_edited("/tmp/new.bin".into());
    assert_eq!(window.get_stage(), 2);
    settle(&window);
    click(&window, 300., 194.);
    key(&window, Key::End.into());
    key(&window, "x".into());
    assert_eq!(
        window.get_stage(),
        0,
        "image edits must immediately invalidate the generated review"
    );
    assert!(!window.get_can_apply());
    settle(&window);
    key(&window, "y".into());
    assert_eq!(
        window.get_image_path(),
        "/tmp/input.binxy",
        "stage change: expected the Image editor to retain focus and receive both characters"
    );
    window.hide().unwrap();
}
