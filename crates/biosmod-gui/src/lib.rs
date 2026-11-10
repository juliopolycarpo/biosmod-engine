//! Desktop session and subprocess boundary. Firmware policy remains in `bme`.

pub mod controller;
pub mod desktop;
pub mod engine;
pub mod i18n;
pub mod model;
pub mod settings;
#[cfg(target_os = "linux")]
pub mod software_scale;

pub mod ui {
    slint::include_modules!();
}
