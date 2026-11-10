//! Status tones must stay readable on the surfaces that carry them in every color scheme.
//!
//! In headless runs the testing backend reports a light system scheme, so the follow-system
//! case only exercises a dark desktop when run with `BME_GUI_NATIVE_SMOKE=1` in such a session.

use biosmod_gui::ui::{AppWindow, Theme};
use slint::{Brush, Color, ComponentHandle};

/// WCAG relative luminance of an sRGB color. Example: white is `1.0`, black is `0.0`.
fn luminance(color: Color) -> f64 {
    let channel = |value: u8| {
        let v = f64::from(value) / 255.0;
        if v <= 0.03928 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(color.red()) + 0.7152 * channel(color.green()) + 0.0722 * channel(color.blue())
}

/// WCAG contrast ratio between two colors. Example: black on white is `21.0`.
fn contrast(a: Color, b: Color) -> f64 {
    let (hi, lo) = (
        luminance(a).max(luminance(b)),
        luminance(a).min(luminance(b)),
    );
    (hi + 0.05) / (lo + 0.05)
}

fn solid(brush: Brush) -> Color {
    brush.color()
}

#[test]
fn contrast_of_known_pairs_matches_the_wcag_definition() {
    let (black, white) = (
        Color::from_rgb_u8(0, 0, 0),
        Color::from_rgb_u8(255, 255, 255),
    );
    assert!((contrast(black, white) - 21.0).abs() < 0.01);
    assert!((contrast(white, white) - 1.0).abs() < 0.01);
}

#[test]
fn status_tones_have_text_contrast_in_every_color_scheme() {
    if std::env::var_os("BME_GUI_NATIVE_SMOKE").is_none() {
        i_slint_backend_testing::init_no_event_loop();
    } else {
        slint::BackendSelector::new().select().unwrap();
    }
    let window = AppWindow::new().unwrap();
    biosmod_gui::i18n::Language::En.select().unwrap();
    window.show().unwrap();
    if std::env::var_os("BME_GUI_NATIVE_SMOKE").is_some() {
        // The desktop reports its color scheme asynchronously after the window appears.
        slint::Timer::single_shot(std::time::Duration::from_millis(1500), || {
            let _ = slint::quit_event_loop();
        });
        slint::run_event_loop().unwrap();
    }
    for (choice, name) in [(0, "follow system"), (1, "light"), (2, "dark")] {
        window.set_theme_choice(choice);
        window.invoke_apply_theme();
        if std::env::var_os("BME_GUI_NATIVE_SMOKE").is_some() {
            window.window().take_snapshot().unwrap();
        }
        let theme = window.global::<Theme>();
        let surface = solid(theme.get_surface());
        for (tone, color) in [
            ("success", theme.get_success()),
            ("warning", theme.get_warning()),
            ("danger", theme.get_danger()),
        ] {
            let ratio = contrast(color, surface);
            assert!(
                ratio >= 4.5,
                "{name} scheme, {tone} tone: expected contrast >= 4.5 against the surface | received {ratio:.2} ({color:?} on {surface:?})"
            );
        }
    }
    window.hide().unwrap();
}
