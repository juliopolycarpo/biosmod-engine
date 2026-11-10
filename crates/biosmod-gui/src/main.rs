use biosmod_gui::{
    desktop::{Desktop, bind, connect, default_engine},
    settings::{PreferencesStore, Settings, process_home_overrides, settings_path},
    ui::AppWindow,
};
use slint::ComponentHandle;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let overrides = process_home_overrides()?;
    let preferences = settings_path(
        overrides
            .iter()
            .find(|(key, _)| key == "BME_CONFIG_HOME")
            .map(|(_, value)| PathBuf::from(value)),
        std::env::var_os("XDG_CONFIG_HOME").map(Into::into),
        std::env::var_os("HOME").map(Into::into),
    );
    let (settings, warning) = match preferences.as_ref().map(|p| Settings::load(p)).transpose() {
        Ok(settings) => (settings.unwrap_or_default(), None),
        Err(error) => (Settings::default(), Some(error)),
    };
    let mut engine = settings.engine.clone().unwrap_or_else(default_engine);
    let mut image = None;
    let mut smoke = false;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--help" | "-h") => {
                println!(
                    "bme-gui [--engine /path/to/bme] [image]\n\nNative offline firmware workflow. The default engine is the packaged sibling bme.\nUse SLINT_BACKEND=winit-software for software rendering."
                );
                return Ok(());
            }
            Some("--engine") => {
                engine =
                    std::path::absolute(args.next().ok_or("--engine: expected executable path")?)?
            }
            Some("--smoke-test") => smoke = true,
            _ if image.is_none() => image = Some(std::path::absolute(PathBuf::from(arg))?),
            _ => return Err("arguments: expected [--engine /path/to/bme] [image]".into()),
        }
    }
    slint::BackendSelector::new().select()?;
    slint::set_xdg_app_id("dev.polycarpo.biosmod-engine")?;
    let ui = AppWindow::new()?;
    settings.language.select()?;
    if smoke {
        ui.show()?;
        slint::Timer::single_shot(std::time::Duration::from_millis(350), || {
            let _ = slint::quit_event_loop();
        });
        slint::run_event_loop()?;
        return Ok(());
    }
    // Leave unreadable or malformed preferences untouched for recovery.
    let store = match (preferences, &warning) {
        (Some(path), Some(_)) => PreferencesStore::Protected(path),
        (Some(path), None) => PreferencesStore::Writable(path),
        (None, _) => PreferencesStore::Unavailable,
    };
    let mut desktop = Desktop::new(engine, settings, store)?;
    desktop.session.image = image;
    if let Some(warning) = warning {
        desktop.session.diagnostics = warning;
    }
    let state = bind(&ui, desktop);
    connect(&ui, &state);
    ui.run()?;
    Ok(())
}
