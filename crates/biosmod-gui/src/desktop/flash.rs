//! The flash chip page: input callbacks and presentation of engine reports.

use super::{Desktop, Shared, sync, sync_paths};
use crate::controller::{FlashReport, FlashState};
use crate::i18n::Language;
use crate::ui::{AppWindow, UiText};
use serde_json::Value;
use slint::{ComponentHandle, SharedString};
use std::path::PathBuf;
use std::sync::Arc;

/// The report on screen and the language it was rendered in.
pub(super) type FlashPresentation = (Arc<FlashReport>, Language);

/// The window page that holds the flash chip controls.
const FLASH_PAGE: i32 = 5;

/// Connect the flash page's inputs to the session.
pub(super) fn bind(ui: &AppWindow, state: &Shared) {
    // Apply one input change, then refresh what depends on it.
    fn edit(ui: &AppWindow, shared: &Shared, change: impl FnOnce(&mut FlashState)) {
        let mut state = shared.lock().unwrap();
        if state.dialog_open || state.exporting {
            return;
        }
        state.session.edit_flash(change);
        sync(ui, &state);
    }
    let path = |value: &str| -> Option<PathBuf> {
        if value.is_empty() {
            None
        } else {
            std::path::absolute(value).ok()
        }
    };
    macro_rules! input {
        ($callback:ident, $value:ident, $change:expr) => {{
            let shared = state.clone();
            let weak = ui.as_weak();
            ui.$callback(move |$value| {
                if let Some(ui) = weak.upgrade() {
                    edit(&ui, &shared, $change);
                }
            });
        }};
    }
    input!(
        on_flash_programmer_edited,
        value,
        |flash: &mut FlashState| { flash.programmer = value.to_string() }
    );
    input!(on_flash_backup_edited, value, |flash: &mut FlashState| {
        flash.backup = path(value.as_str())
    });
    input!(on_flash_image_edited, value, |flash: &mut FlashState| {
        flash.image = path(value.as_str())
    });
    input!(on_flash_elevate_changed, value, |flash: &mut FlashState| {
        flash.elevate = value
    });
    input!(
        on_flash_whole_chip_changed,
        value,
        |flash: &mut FlashState| flash.whole_chip = value
    );
    input!(
        on_flash_acknowledged_changed,
        value,
        |flash: &mut FlashState| flash.acknowledged = value
    );
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_flash_output(move || {
        let Some(ui) = weak.upgrade() else { return };
        let mut state = shared.lock().unwrap();
        if state.session.busy() || state.dialog_open || state.exporting {
            return;
        }
        let output = state.session.output.clone();
        state.session.edit_flash(|flash| flash.image = output);
        ui.set_page(FLASH_PAGE);
        sync_paths(&ui, &state);
        sync(&ui, &state);
    });
}

/// Mirror flash state into the window; the report is re-rendered only when it or
/// the language changes, so a selection inside the text survives other updates.
pub(super) fn sync_flash(ui: &AppWindow, state: &Desktop) {
    let session = &state.session;
    let flash = &session.flash;
    ui.set_flash_supported(session.connected && flash.supported);
    ui.set_flash_elevate(flash.elevate);
    ui.set_flash_whole_chip(flash.whole_chip);
    ui.set_flash_acknowledged(flash.acknowledged);
    ui.set_flash_checked(session.flash_checked());
    ui.set_can_flash_write(session.can_flash_write());
    let mut presented = state.presented_flash.borrow_mut();
    match (&flash.report, presented.as_ref()) {
        (Some(current), Some((previous, language)))
            if Arc::ptr_eq(current, previous) && *language == state.settings.language =>
        {
            return;
        }
        (None, None) => return,
        _ => {}
    }
    match &flash.report {
        Some(report) => {
            ui.set_flash_details(flash_summary(ui, report));
            *presented = Some((report.clone(), state.settings.language));
        }
        None => {
            ui.set_flash_details(SharedString::default());
            *presented = None;
        }
    }
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}

fn hex(value: &Value) -> String {
    format!("{:#09x}", value.as_u64().unwrap_or_default())
}

/// Render a flash report in the selected language; engine details stay as written.
/// Example: `flash_summary(&window, &FlashReport::Probe(data))` lists the chips found.
pub fn flash_summary(ui: &AppWindow, report: &FlashReport) -> SharedString {
    let t = ui.global::<UiText>();
    let mut lines: Vec<String> = Vec::new();
    match report {
        FlashReport::Doctor(data) => {
            let system = &data["system"];
            let join = |fields: &[&str]| {
                fields
                    .iter()
                    .filter_map(|field| system[*field].as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let board = join(&["board_vendor", "board_name", "board_version"]);
            if !board.is_empty() {
                lines.push(t.invoke_flash_board(board.into()).into());
            }
            let firmware = join(&["bios_vendor", "bios_version", "bios_date"]);
            if !firmware.is_empty() {
                lines.push(t.invoke_flash_firmware(firmware.into()).into());
            }
            let boards = data["catalog_boards"].as_array();
            for board in boards.into_iter().flatten() {
                lines.push(
                    t.invoke_flash_catalog_board(text(&board["id"]).into())
                        .into(),
                );
            }
            if boards.is_none_or(Vec::is_empty) {
                lines.push(t.get_flash_no_catalog_board().into());
            }
            lines.push(String::new());
            lines.push(
                t.invoke_flash_checks(text(&data["programmer"]).into())
                    .into(),
            );
            for check in data["checks"].as_array().into_iter().flatten() {
                let state = match text(&check["state"]) {
                    "pass" => t.get_flash_pass(),
                    "warn" => t.get_flash_warn(),
                    "fail" => t.get_flash_fail(),
                    _ => t.get_flash_info(),
                };
                lines.push(format!(
                    "{state}  {}: {}",
                    text(&check["check"]),
                    text(&check["detail"])
                ));
            }
            lines.push(String::new());
            lines.push(
                if data["ready"] == true {
                    t.get_flash_ready()
                } else {
                    t.get_flash_not_ready()
                }
                .into(),
            );
        }
        FlashReport::Probe(data) => {
            for chip in data["chips"].as_array().into_iter().flatten() {
                lines.push(t.invoke_flash_chip(describe_chip(chip).into()).into());
            }
            lines.push(
                if data["ambiguous"] == true {
                    t.get_flash_ambiguous()
                } else {
                    t.get_flash_probe_next()
                }
                .into(),
            );
        }
        FlashReport::Backup(data) => {
            if data["chip"].is_object() {
                lines.push(
                    t.invoke_flash_chip(describe_chip(&data["chip"]).into())
                        .into(),
                );
            }
            lines.push(
                t.invoke_flash_backup_summary(
                    text(&data["output"]).into(),
                    data["size"].to_string().into(),
                    text(&data["sha256"]).into(),
                )
                .into(),
            );
            if data["partial"] == true {
                let regions: Vec<&str> = data["regions_read"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                lines.push(t.invoke_flash_partial(regions.join(", ").into()).into());
            }
            match (&data["firmware_volumes"], &data["firmware_note"]) {
                (Value::Number(count), _) => {
                    lines.push(t.invoke_flash_volumes(count.to_string().into()).into());
                    lines.push(t.get_flash_backup_next().into());
                }
                (_, Value::String(note)) => {
                    lines.push(t.invoke_flash_not_firmware(note.as_str().into()).into())
                }
                _ => {}
            }
        }
        FlashReport::Check(data) => {
            lines.push(
                t.invoke_flash_check_summary(text(&data["image_sha256"]).into())
                    .into(),
            );
            for region in data["regions"].as_array().into_iter().flatten() {
                let last = region["end"].as_u64().unwrap_or_default().saturating_sub(1);
                lines.push(
                    t.invoke_flash_region(
                        text(&region["name"]).into(),
                        hex(&region["start"]).into(),
                        format!("{last:#09x}").into(),
                        region["changed_bytes"].to_string().into(),
                    )
                    .into(),
                );
            }
            lines.push(String::new());
            lines.push(t.get_flash_check_next().into());
        }
        FlashReport::Written(data) => lines.push(
            t.invoke_flash_written_summary(text(&data["image_sha256"]).into())
                .into(),
        ),
        FlashReport::Failure(message, details) => {
            lines.push(t.invoke_flash_failure(message.as_str().into()).into());
            if let Some(log) = details.as_ref().and_then(|details| details["log"].as_str()) {
                lines.push(String::new());
                lines.push(log.to_owned());
            }
        }
    }
    lines.join("\n").into()
}

fn describe_chip(chip: &Value) -> String {
    format!(
        "{} {} · {} bytes · {}",
        text(&chip["vendor"]),
        text(&chip["name"]),
        chip["size_bytes"],
        text(&chip["bus"])
    )
}
