//! Keep the initial client area within the supported small-desktop size.

use biosmod_gui::ui::AppWindow;
use slint::ComponentHandle;

#[test]
fn initial_window_uses_the_supported_minimum_and_can_expand() {
    i_slint_backend_testing::init_no_event_loop();
    let window = AppWindow::new().unwrap();
    window.show().unwrap();
    let size = window.window().size();
    assert_eq!(
        (size.width, size.height),
        (760, 600),
        "(initial window): expected supported 760x600 client area within a small desktop | received {size:?}"
    );
    window
        .window()
        .set_size(slint::PhysicalSize::new(1080, 780));
    assert_eq!(
        window.window().size(),
        slint::PhysicalSize::new(1080, 780),
        "(expanded window): expected user-selected 1080x780 client area"
    );
}
