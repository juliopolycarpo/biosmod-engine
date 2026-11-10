//! Keep operation announcements useful while the visible timer continues updating.

use biosmod_gui::ui::AppWindow;
use i_slint_backend_testing::ElementHandle;

#[test]
fn operation_announcement_omits_elapsed_time_and_retains_results() {
    i_slint_backend_testing::init_no_event_loop();
    let window = AppWindow::new().unwrap();
    window.set_busy(true);
    window.set_operation_label("Inspecting image".into());
    for elapsed in ["0.1 s", "0.2 s", "12.0 s"] {
        window.set_elapsed(elapsed.into());
        assert!(
            ElementHandle::find_by_accessible_label(&window, "Inspecting image")
                .next()
                .is_some(),
            "(status, elapsed {elapsed:?}): expected announcement Inspecting image without timer"
        );
    }
    window.set_busy(false);
    for status in [
        "Operation failed: IO: missing image.bin",
        "Offline verification complete",
    ] {
        window.set_status(status.into());
        assert!(
            ElementHandle::find_by_accessible_label(&window, status)
                .next()
                .is_some(),
            "(status {status:?}): expected complete result announcement"
        );
    }
}
