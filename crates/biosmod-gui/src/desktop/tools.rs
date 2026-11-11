//! The Tools page: one card per external tool, with install, choose and reset actions.

use super::{Desktop, Shared, start, sync, sync_rows};
use crate::controller::ToolChange;
use crate::engine::LocatableTool;
use crate::ui::{AppWindow, Tone, ToolRowData, UiText};
use serde_json::Value;
use slint::{ComponentHandle, SharedString};

/// Connect the card buttons to the session.
pub(super) fn bind(ui: &AppWindow, state: &Shared) {
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_tool_install(move |id| {
        if let Some(ui) = weak.upgrade()
            && id == "ghidra"
        {
            begin(&ui, &shared, ToolChange::InstallGhidra);
        }
    });
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_tool_reset(move |id| {
        if let (Some(ui), Some(tool)) = (weak.upgrade(), locatable(id.as_str())) {
            begin(&ui, &shared, ToolChange::Reset { tool });
        }
    });
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_tool_choose(move |id| {
        if let (Some(ui), Some(tool)) = (weak.upgrade(), locatable(id.as_str())) {
            choose(&ui, &shared, tool);
        }
    });
}

/// The tools `bme tools set` accepts.
///
/// Example: `locatable("flashrom")` is `Some(LocatableTool::Flashrom)`; `locatable("git")` is `None`.
fn locatable(id: &str) -> Option<LocatableTool> {
    match id {
        "ghidra" => Some(LocatableTool::Ghidra),
        "flashrom" => Some(LocatableTool::Flashrom),
        _ => None,
    }
}

/// Queue a change and run it, unless an operation or dialog is already active.
fn begin(ui: &AppWindow, shared: &Shared, change: ToolChange) {
    let action = change.action();
    {
        let mut state = shared.lock().unwrap();
        if state.session.busy() || state.dialog_open || state.exporting {
            return;
        }
        state.session.queue_tool_change(change);
    }
    start(ui, shared, action);
}

/// Ask for a Ghidra folder or a flashrom program, then save the choice.
fn choose(ui: &AppWindow, shared: &Shared, tool: LocatableTool) {
    {
        let mut state = shared.lock().unwrap();
        if state.session.busy() || state.dialog_open || state.exporting {
            return;
        }
        state.dialog_open = true;
        sync(ui, &state);
    }
    let text = ui.global::<UiText>();
    let title = match tool {
        LocatableTool::Ghidra => text.get_tool_choose_ghidra(),
        LocatableTool::Flashrom => text.get_tool_choose_flashrom(),
    }
    .to_string();
    let weak = ui.as_weak();
    let future_shared = shared.clone();
    let result = slint::spawn_local(async move {
        let dialog = rfd::AsyncFileDialog::new().set_title(&title);
        let selected = match tool {
            LocatableTool::Ghidra => dialog.pick_folder().await,
            LocatableTool::Flashrom => dialog.pick_file().await,
        };
        let Some(ui) = weak.upgrade() else { return };
        future_shared.lock().unwrap().dialog_open = false;
        match selected {
            Some(file) => begin(
                &ui,
                &future_shared,
                ToolChange::Choose {
                    tool,
                    path: file.path().to_path_buf(),
                },
            ),
            None => sync(&ui, &future_shared.lock().unwrap()),
        }
    });
    if let Err(error) = result {
        let mut state = shared.lock().unwrap();
        state.dialog_open = false;
        state.session.set_detailed_status(
            crate::controller::Status::PickerError,
            error.to_string(),
            "",
            format!("File picker unavailable: {error}."),
        );
        sync(ui, &state);
    }
}

/// Mirror the tools report into the window; rows are rebuilt only when the report or the
/// language changes.
pub(super) fn sync_tools(ui: &AppWindow, state: &Desktop) {
    let mut presented = state.presented_tools.borrow_mut();
    match (&state.session.tool_report, presented.as_ref()) {
        (Some(current), Some((previous, language)))
            if std::sync::Arc::ptr_eq(current, previous)
                && *language == state.settings.language =>
        {
            return;
        }
        (None, None) => return,
        _ => {}
    }
    let rows = state
        .session
        .tool_report
        .as_deref()
        .map(|report| tool_rows(ui, report))
        .unwrap_or_default();
    #[cfg(test)]
    if state.session.tool_report.is_some() {
        super::TOOL_RENDER_COUNT.with(|count| count.set(count.get() + 1));
    }
    sync_rows(ui.get_tool_rows(), rows, |model| ui.set_tool_rows(model));
    *presented = state
        .session
        .tool_report
        .clone()
        .map(|report| (report, state.settings.language));
}

/// Build the cards for a `tools status` report in the selected language.
///
/// Example: a `flashrom` row with health `missing` and a `sudo apt install flashrom` command
/// becomes a card with the `Missing` chip and that command; a ready row has no command.
pub fn tool_rows(ui: &AppWindow, report: &Value) -> Vec<ToolRowData> {
    let text = ui.global::<UiText>();
    let rows = report["tools"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let ghidra_ready = rows
        .iter()
        .any(|row| row["id"] == "ghidra" && row["health"] == "ready");
    rows.iter()
        .map(|row| {
            let id = row["id"].as_str().unwrap_or_default();
            let health = row["health"].as_str().unwrap_or_default();
            let ready = health == "ready";
            let (state, tone) = match health {
                "ready" => (text.get_tool_ready(), Tone::Good),
                "attention" => (text.get_tool_attention(), Tone::Attention),
                _ => (text.get_tool_missing(), Tone::Danger),
            };
            let purpose = match id {
                "ghidra" => text.get_tool_purpose_ghidra(),
                "firmware-utils" => text.get_tool_purpose_firmware_utils(),
                "java" => text.get_tool_purpose_java(),
                "jdk" => text.get_tool_purpose_jdk(),
                "git" => text.get_tool_purpose_git(),
                "flashrom" => text.get_tool_purpose_flashrom(),
                _ => row["purpose"].as_str().unwrap_or_default().into(),
            };
            let own_install = id == "ghidra" && row["install"]["method"] == "bme";
            let automatic = row["install"]["automatic"] == true;
            let can_install = own_install && automatic && !ready;
            let location = match (row["path"].as_str(), row["origin"].as_str()) {
                (Some(path), Some(origin)) => format!("{path} ({origin})"),
                (Some(path), None) => path.to_string(),
                _ => String::new(),
            };
            let custom = row["custom_location"] == true;
            ToolRowData {
                id: id.into(),
                name: row["name"].as_str().unwrap_or(id).into(),
                purpose,
                state,
                tone,
                version: row["version"].as_str().unwrap_or_default().into(),
                location: location.into(),
                detail: row["detail"].as_str().unwrap_or_default().into(),
                install_command: if can_install || (id == "firmware-utils" && !ghidra_ready) {
                    SharedString::default()
                } else {
                    row["install"]["command"]
                        .as_str()
                        .unwrap_or_default()
                        .into()
                },
                can_install,
                install_unavailable: own_install && !automatic && !ready,
                can_choose: custom,
                can_reset: custom && row["origin"] == "config",
                ready,
            }
        })
        .collect()
}
