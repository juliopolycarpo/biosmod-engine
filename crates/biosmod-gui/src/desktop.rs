//! Slint event-loop wiring. Workers never hold a strong window reference.

use crate::controller::{
    Action, Outcome, PreparationError, Review, Session, Status, manifest_path, write_new_file,
};
use crate::engine::Engine;
use crate::i18n::Language;
use crate::model::{Patch, StateTone};
use crate::settings::{PreferencesStore, Settings, process_home_overrides};
use crate::ui::{AppWindow, Fact, PatchRow, Tone, UiText};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, atomic::Ordering};
use std::time::{Duration, Instant};

pub struct Desktop {
    pub session: Session,
    pub engine_path: PathBuf,
    settings: Settings,
    preferences: PreferencesStore,
    engine_home_overrides: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    started: Instant,
    dialog_open: bool,
    exporting: bool,
    closing: bool,
    presented_review: RefCell<Option<Arc<Review>>>,
    export_writer: Arc<dyn ExportWriter>,
}
type Shared = Arc<Mutex<Desktop>>;

trait ExportWriter: Send + Sync {
    fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()>;
}

struct NewFileWriter;

impl ExportWriter for NewFileWriter {
    fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        write_new_file(path, bytes)
    }
}

impl Desktop {
    /// Build the window controller without performing engine I/O.
    /// Example: `Desktop::new(engine_path, settings, PreferencesStore::Writable(path))?`.
    pub fn new(
        engine_path: PathBuf,
        settings: Settings,
        preferences: PreferencesStore,
    ) -> std::io::Result<Self> {
        Ok(Self {
            session: Session::new()?,
            engine_path,
            settings,
            preferences,
            engine_home_overrides: process_home_overrides()?,
            started: Instant::now(),
            dialog_open: false,
            exporting: false,
            closing: false,
            presented_review: RefCell::new(None),
            export_writer: Arc::new(NewFileWriter),
        })
    }
}

/// Connect native controls to session transitions and background workers.
/// Example: `let state = bind(&window, desktop);` then call `connect(&window, &state)`.
pub fn bind(ui: &AppWindow, desktop: Desktop) -> Shared {
    bind_with_language_selector(ui, desktop, Language::select)
}

// Keep language selection replaceable so tests can exercise catalog failures
// through the same callback used by the native window.
fn bind_with_language_selector(
    ui: &AppWindow,
    desktop: Desktop,
    select_language: fn(Language) -> Result<(), slint::SelectBundledTranslationError>,
) -> Shared {
    let state = Arc::new(Mutex::new(desktop));
    ui.set_app_version(env!("CARGO_PKG_VERSION").into());
    ui.set_theme_choice(state.lock().unwrap().settings.theme.into());
    ui.set_language_index(state.lock().unwrap().settings.language.index());
    ui.invoke_apply_theme();
    macro_rules! action {
        ($callback:ident, $action:expr) => {{
            let state = state.clone();
            let weak = ui.as_weak();
            ui.$callback(move || {
                if let Some(ui) = weak.upgrade() {
                    start(&ui, &state, $action);
                }
            });
        }};
    }
    action!(on_refresh_engine, Action::Connect);
    action!(on_inspect, Action::Inspect);
    action!(on_scan, Action::Scan);
    action!(on_recommended, Action::Recommended);
    action!(on_generate_plan, Action::Plan);
    action!(on_apply_plan, Action::Apply);
    action!(on_verify, Action::Verify);
    action!(on_refresh_sources, Action::Sources);
    action!(on_show_tools, Action::Tools);
    macro_rules! edit {
        ($callback:ident, $kind:expr) => {{
            let state = state.clone();
            let weak = ui.as_weak();
            ui.$callback(move |value| {
                if let Some(ui) = weak.upgrade() {
                    change(&ui, &state, $kind, value.as_str());
                }
            });
        }};
    }
    edit!(on_image_edited, PathKind::Image);
    edit!(on_output_edited, PathKind::Output);
    edit!(on_engine_edited, PathKind::Engine);
    edit!(on_source_edited, PathKind::Source);
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_engine_committed(move |value| {
        let mut state = shared.lock().unwrap();
        let path = if value.is_empty() {
            None
        } else {
            std::path::absolute(value.as_str()).ok()
        };
        let engine = path.clone().unwrap_or_else(default_engine);
        if (state.session.busy() || state.dialog_open || state.exporting)
            && engine != state.engine_path
        {
            return;
        }
        set_engine(&mut state, path);
        if let Some(ui) = weak.upgrade() {
            sync(&ui, &state);
        }
    });
    macro_rules! picker {
        ($callback:ident, $kind:expr) => {{
            let state = state.clone();
            let weak = ui.as_weak();
            ui.$callback(move || {
                if let Some(ui) = weak.upgrade() {
                    pick(&ui, &state, $kind);
                }
            });
        }};
    }
    picker!(on_browse_image, PathKind::Image);
    picker!(on_browse_output, PathKind::Output);
    picker!(on_browse_engine, PathKind::Engine);
    picker!(on_import_plan, PathKind::Plan);
    picker!(on_open_output, PathKind::ExistingOutput);
    picker!(on_export_diagnostics, PathKind::Diagnostics);
    picker!(on_export_plan, PathKind::ExportPlan);
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_export_plan_path(move |path| {
        if let Some(ui) = weak.upgrade()
            && !path.is_empty()
            && let Ok(path) = std::path::absolute(path.as_str())
        {
            start_export_plan(&ui, &shared, path);
        }
    });
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_open_plan_path(move |path| {
        if let Some(ui) = weak.upgrade()
            && let Ok(path) = std::path::absolute(path.as_str())
        {
            start_import(&ui, &shared, path);
        }
    });
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_open_output_path(move |path| {
        let mut state = shared.lock().unwrap();
        if state.session.busy() || state.dialog_open || state.exporting || path.is_empty() {
            return;
        }
        if let Ok(path) = std::path::absolute(path.as_str()) {
            state.session.open_output(path);
        }
        if let Some(ui) = weak.upgrade() {
            sync_paths(&ui, &state);
            sync(&ui, &state);
        }
    });
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_toggle_patch(move |index| {
        let mut state = shared.lock().unwrap();
        if state.exporting || state.dialog_open {
            return;
        }
        state.session.toggle(index as usize);
        drop(state);
        if let Some(ui) = weak.upgrade() {
            sync(&ui, &shared.lock().unwrap());
        }
    });
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_cancel_operation(move || {
        let mut state = shared.lock().unwrap();
        if !state.session.busy() || state.session.publishing() {
            return;
        }
        state.session.cancel.store(true, Ordering::Relaxed);
        state.session.set_status(Status::Stopping);
        if let Some(ui) = weak.upgrade() {
            sync(&ui, &state);
        }
    });
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_theme_changed(move |choice| {
        let mut state = shared.lock().unwrap();
        state.settings.theme = choice.clamp(0, 2) as u8;
        save_settings(&mut state);
        if let Some(ui) = weak.upgrade() {
            sync(&ui, &state);
        }
    });
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_language_changed(move |choice| {
        let Some(ui) = weak.upgrade() else { return };
        let language = if choice == 1 {
            Language::PtBr
        } else {
            Language::En
        };
        let mut state = shared.lock().unwrap();
        // Keep the selector on the language actually presented when a catalog is missing.
        if let Err(error) = select_language(language) {
            ui.set_language_index(state.settings.language.index());
            state
                .session
                .set_raw_status(format!("language {}: {error}", language.identifier()));
            sync(&ui, &state);
            return;
        }
        state.settings.language = language;
        *state.presented_review.borrow_mut() = None;
        save_settings(&mut state);
        sync(&ui, &state);
    });
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.on_back_to_selection(move || {
        let mut state = shared.lock().unwrap();
        if state.session.busy() || state.exporting || state.dialog_open {
            return;
        }
        state.session.clear_results();
        state.session.set_status(Status::Back);
        if let Some(ui) = weak.upgrade() {
            sync(&ui, &state);
        }
    });
    let shared = state.clone();
    let weak = ui.as_weak();
    ui.window().on_close_requested(move || {
        let mut state = shared.lock().unwrap();
        if state.exporting {
            state.closing = true;
            state.session.set_status(Status::ClosingExport);
            if let Some(ui) = weak.upgrade() {
                sync(&ui, &state);
            }
            return slint::CloseRequestResponse::KeepWindowShown;
        }
        if state.session.publishing() {
            state.session.set_status(Status::ClosingBuild);
            if let Some(ui) = weak.upgrade() {
                sync(&ui, &state);
            }
            return slint::CloseRequestResponse::KeepWindowShown;
        }
        state.session.cancel.store(true, Ordering::Relaxed);
        if state.session.activity() == Some(Action::Import) {
            // Import only reads a user file and writes our private directory; a
            // stalled network filesystem must not keep the window open.
            return slint::CloseRequestResponse::HideWindow;
        }
        if state.session.busy() {
            state.closing = true;
            state.session.set_status(Status::ClosingStop);
            if let Some(ui) = weak.upgrade() {
                sync(&ui, &state);
            }
            return slint::CloseRequestResponse::KeepWindowShown;
        }
        slint::CloseRequestResponse::HideWindow
    });
    sync_paths(ui, &state.lock().unwrap());
    sync(ui, &state.lock().unwrap());
    state
}

/// Begin the version/capabilities handshake asynchronously.
/// Example: `connect(&window, &state)` after callbacks are bound.
pub fn connect(ui: &AppWindow, state: &Shared) {
    start(ui, state, Action::Connect);
}

fn configured_engine(state: &Desktop) -> Result<Engine, crate::engine::EngineError> {
    Engine::new(&state.engine_path, PathBuf::from("/")).map(|engine| {
        state
            .engine_home_overrides
            .iter()
            .fold(engine, |engine, (key, value)| engine.with_env(key, value))
    })
}

fn start(ui: &AppWindow, shared: &Shared, action: Action) {
    let mut state = shared.lock().unwrap();
    if state.dialog_open || state.exporting {
        return;
    }
    let engine = configured_engine(&state);
    if let Err(error) = &engine {
        let detail = error.to_string();
        state
            .session
            .set_detailed_status(Status::Failed, detail.clone(), "", detail);
        sync(ui, &state);
        return;
    }
    let job = match state.session.prepare(action) {
        Ok(job) => job,
        Err(error) => {
            state.session.set_detailed_status(
                Status::Precondition(error),
                "",
                "",
                error.to_string(),
            );
            sync(ui, &state);
            return;
        }
    };
    state.started = Instant::now();
    sync_paths(ui, &state);
    sync(ui, &state);
    drop(state);
    let timer_id = start_timer(ui, shared);
    let shared = shared.clone();
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let completion = job.run(&engine.unwrap());
        let _ = weak.upgrade_in_event_loop(move |ui| {
            stop_timer(timer_id);
            let mut state = shared.lock().unwrap();
            let accepted = state.session.finish(completion);
            if close_if_requested(&ui, &state) {
                return;
            }
            let verify = accepted
                && action == Action::Apply
                && state.session.manifest.is_some()
                && state.session.outcome == Outcome::Idle;
            sync(&ui, &state);
            drop(state);
            if verify {
                start(&ui, &shared, Action::Verify);
            }
        });
    });
}

fn start_timer(ui: &AppWindow, shared: &Shared) -> usize {
    ui.set_elapsed("0s".into());
    let timer = slint::Timer::default();
    let weak = ui.as_weak();
    let shared = shared.clone();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(1),
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_elapsed(
                    format!("{}s", shared.lock().unwrap().started.elapsed().as_secs()).into(),
                );
            }
        },
    );
    // Timer ownership stays on the UI thread until the worker completes.
    register_timer(timer)
}

thread_local! { static TIMERS: std::cell::RefCell<Vec<Option<slint::Timer>>> = const { std::cell::RefCell::new(Vec::new()) }; }
fn register_timer(timer: slint::Timer) -> usize {
    TIMERS.with(|timers| {
        let mut timers = timers.borrow_mut();
        if let Some(index) = timers.iter().position(Option::is_none) {
            timers[index] = Some(timer);
            return index;
        }
        timers.push(Some(timer));
        timers.len() - 1
    })
}
fn stop_timer(index: usize) {
    TIMERS.with(|timers| {
        timers.borrow_mut()[index].take();
    });
}

#[derive(Clone, Copy)]
enum PathKind {
    Image,
    Source,
    Output,
    Engine,
    Plan,
    ExistingOutput,
    Diagnostics,
    ExportPlan,
}

fn change(ui: &AppWindow, shared: &Shared, kind: PathKind, value: &str) {
    let path = if value.is_empty() {
        None
    } else {
        std::path::absolute(value).ok()
    };
    let mut state = shared.lock().unwrap();
    if state.session.busy() || state.exporting {
        return;
    }
    match kind {
        PathKind::Image => {
            state.session.change_image(path);
            ui.set_output_path(display_path(state.session.output.as_ref()));
        }
        PathKind::Source => {
            state.session.invalidate();
            state.session.source = value.into();
            ui.set_output_path("".into());
        }
        PathKind::Engine => {
            preview_engine(&mut state, path);
            ui.set_output_path(display_path(state.session.output.as_ref()));
        }
        PathKind::Output => {
            state.session.set_output(path);
        }
        _ => {}
    }
    sync(ui, &state);
}

fn pick(ui: &AppWindow, shared: &Shared, kind: PathKind) {
    let mut state = shared.lock().unwrap();
    if state.session.busy() || state.dialog_open || state.exporting {
        return;
    }
    state.dialog_open = true;
    sync(ui, &state);
    drop(state);
    let text = ui.global::<UiText>();
    let title = match kind {
        PathKind::Output => text.get_save_copy(),
        PathKind::ExportPlan => text.get_export_plan(),
        PathKind::Diagnostics => text.get_export_diagnostics(),
        PathKind::Plan => text.get_open_plan(),
        PathKind::Engine => text.get_choose_engine(),
        PathKind::ExistingOutput => text.get_open_output(),
        _ => text.get_open_image(),
    }
    .to_string();
    let plan_filter = text.get_plan_filter().to_string();
    let weak = ui.as_weak();
    let shared = shared.clone();
    // rfd 0.18's portal futures run their blocking portal work on an internal thread;
    // Slint's executor needs neither a Tokio runtime nor a blocking UI callback.
    let future_shared = shared.clone();
    let result = slint::spawn_local(async move {
        let dialog = rfd::AsyncFileDialog::new();
        let selected = match kind {
            PathKind::Output => {
                dialog
                    .set_title(&title)
                    .set_file_name("patched.bin")
                    .save_file()
                    .await
            }
            PathKind::ExportPlan => {
                dialog
                    .set_title(&title)
                    .set_file_name("bme-plan.json")
                    .save_file()
                    .await
            }
            PathKind::Diagnostics => {
                dialog
                    .set_title(&title)
                    .set_file_name("bme-diagnostics.txt")
                    .save_file()
                    .await
            }
            PathKind::Plan => {
                dialog
                    .set_title(&title)
                    .add_filter(&plan_filter, &["json"])
                    .pick_file()
                    .await
            }
            _ => dialog.set_title(&title).pick_file().await,
        };
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let mut state = future_shared.lock().unwrap();
        state.dialog_open = false;
        if let Some(file) = selected {
            if matches!(kind, PathKind::Plan) {
                drop(state);
                start_import(&ui, &future_shared, file.path().to_path_buf());
                return;
            }
            if matches!(kind, PathKind::ExportPlan) {
                drop(state);
                start_export_plan(&ui, &future_shared, file.path().to_path_buf());
                return;
            }
            if matches!(kind, PathKind::Diagnostics) {
                drop(state);
                start_export_diagnostics(&ui, &future_shared, file.path().to_path_buf());
                return;
            }
            apply_picked(&mut state, kind, file.path().to_path_buf());
        }
        sync_paths(&ui, &state);
        sync(&ui, &state);
    });
    if let Err(error) = result {
        let mut state = shared.lock().unwrap();
        state.dialog_open = false;
        state.session.set_detailed_status(
            Status::PickerError,
            error.to_string(),
            "",
            format!("File picker unavailable: {error}. Enter a path manually."),
        );
        sync(ui, &state);
    }
}

fn apply_picked(state: &mut Desktop, kind: PathKind, path: PathBuf) {
    match kind {
        PathKind::Image => {
            state.session.change_image(Some(path));
        }
        PathKind::Output => {
            state.session.set_output(Some(path));
        }
        PathKind::Engine => {
            set_engine(state, Some(path));
        }
        PathKind::ExistingOutput => state.session.open_output(path),
        PathKind::Plan | PathKind::ExportPlan | PathKind::Diagnostics => {}
        PathKind::Source => {}
    }
}

// Switch engines: derived data and the connection belong to the previous one.
// No path restores the packaged sibling `bme` instead of saving an empty choice.
fn set_engine(state: &mut Desktop, path: Option<PathBuf>) {
    preview_engine(state, path.clone());
    if state.settings.engine == path {
        return;
    }
    state.settings.engine = path;
    save_settings(state);
}

fn preview_engine(state: &mut Desktop, path: Option<PathBuf>) {
    let engine = path.unwrap_or_else(default_engine);
    if state.engine_path == engine {
        return;
    }
    state.session.invalidate();
    state.session.connected = false;
    state.session.engine_version = None;
    state.session.engine_contract = None;
    state.session.engine_attempted = false;
    state.engine_path = engine;
}

/// The packaged sibling engine next to this executable.
/// Example: `/opt/bme/bin/bme-gui` resolves `/opt/bme/bin/bme`.
pub fn default_engine() -> PathBuf {
    std::env::current_exe()
        .map(|exe| exe.with_file_name("bme"))
        .unwrap_or_else(|_| PathBuf::from("bme"))
}

fn save_settings(state: &mut Desktop) {
    match &state.preferences {
        PreferencesStore::Writable(path) => match state.settings.save(path) {
            Err(error) => state.session.set_notice(
                Status::PreferencesError,
                error.clone(),
                "",
                format!("Could not save preferences: {error}"),
            ),
            Ok(()) => state.session.dismiss_notice(),
        },
        PreferencesStore::Protected(path) => {
            let path = path.display().to_string();
            let fallback = format!(
                "Preferences not saved: {path} could not be read. Fix or remove that file, then restart."
            );
            state
                .session
                .set_notice(Status::PreferencesProtected, path, "", fallback)
        }
        PreferencesStore::Unavailable => state.session.set_notice(
            Status::PreferencesNoLocation,
            "",
            "",
            "Could not save preferences: no writable configuration location is available.",
        ),
    }
}

// Finish a close request that waited for background work.
fn close_if_requested(ui: &AppWindow, state: &Desktop) -> bool {
    if !state.closing {
        return false;
    }
    let _ = ui.hide();
    let _ = slint::quit_event_loop();
    true
}

#[derive(Clone, Copy)]
enum ExportKind {
    Plan,
    Diagnostics,
}

impl ExportKind {
    fn label(self) -> &'static str {
        match self {
            Self::Plan => "Plan",
            Self::Diagnostics => "Diagnostics",
        }
    }
}

enum ExportContent {
    Plan(Arc<Review>),
    Diagnostics(String),
}

fn start_export_plan(ui: &AppWindow, shared: &Shared, path: PathBuf) {
    start_export(ui, shared, path, ExportKind::Plan);
}

fn start_export_diagnostics(ui: &AppWindow, shared: &Shared, path: PathBuf) {
    start_export(ui, shared, path, ExportKind::Diagnostics);
}

fn start_export(ui: &AppWindow, shared: &Shared, path: PathBuf, kind: ExportKind) {
    let mut state = shared.lock().unwrap();
    if state.session.busy() || state.dialog_open || state.exporting {
        return;
    }
    let content = match kind {
        ExportKind::Plan => state.session.review.clone().map(ExportContent::Plan),
        ExportKind::Diagnostics => Some(ExportContent::Diagnostics(
            state.session.diagnostics.clone(),
        )),
    };
    let Some(content) = content else {
        state.session.set_status(Status::ExportNeedsPlan);
        sync(ui, &state);
        return;
    };
    let writer = state.export_writer.clone();
    state.exporting = true;
    state.session.set_detailed_status(
        match kind {
            ExportKind::Plan => Status::ExportingPlan,
            ExportKind::Diagnostics => Status::ExportingDiagnostics,
        },
        "",
        "",
        format!("Exporting {}…", kind.label().to_lowercase()),
    );
    sync(ui, &state);
    drop(state);
    let shared = shared.clone();
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let bytes = match &content {
            ExportContent::Plan(review) => review.bytes.as_slice(),
            ExportContent::Diagnostics(text) => text.as_bytes(),
        };
        let result = writer.write_new(&path, bytes);
        let _ =
            weak.upgrade_in_event_loop(move |ui| finish_export(&ui, &shared, &path, kind, result));
    });
}

fn finish_export(
    ui: &AppWindow,
    shared: &Shared,
    path: &Path,
    kind: ExportKind,
    result: std::io::Result<()>,
) {
    let mut state = shared.lock().unwrap();
    state.exporting = false;
    let label = kind.label();
    let (status, extra, fallback) = match result {
        Ok(()) => (
            match kind {
                ExportKind::Plan => Status::PlanExported,
                ExportKind::Diagnostics => Status::DiagnosticsExported,
            },
            String::new(),
            format!("{label} exported to {}", path.display()),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
            match kind {
                ExportKind::Plan => Status::PlanExists,
                ExportKind::Diagnostics => Status::DiagnosticsExist,
            },
            String::new(),
            format!(
                "{label} export {}: file already exists; choose a new path.",
                path.display()
            ),
        ),
        Err(error) => (
            match kind {
                ExportKind::Plan => Status::PlanExportError,
                ExportKind::Diagnostics => Status::DiagnosticsExportError,
            },
            error.to_string(),
            format!(
                "{label} export {}: {error}. A partial file may remain.",
                path.display()
            ),
        ),
    };
    state
        .session
        .set_detailed_status(status, path.display().to_string(), extra, fallback);
    if close_if_requested(ui, &state) {
        return;
    }
    sync(ui, &state);
}

fn start_import(ui: &AppWindow, shared: &Shared, path: PathBuf) {
    let mut state = shared.lock().unwrap();
    if state.dialog_open || state.exporting {
        return;
    }
    let job = match state.session.prepare_import(&path) {
        Ok(job) => job,
        Err(error) => {
            state.session.set_detailed_status(
                Status::Precondition(error),
                "",
                "",
                error.to_string(),
            );
            sync(ui, &state);
            return;
        }
    };
    state.started = Instant::now();
    sync(ui, &state);
    drop(state);
    let timer_id = start_timer(ui, shared);
    let shared = shared.clone();
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let completion = job.run();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            stop_timer(timer_id);
            let mut state = shared.lock().unwrap();
            state.session.finish(completion);
            if close_if_requested(&ui, &state) {
                return;
            }
            sync_paths(&ui, &state);
            sync(&ui, &state);
        });
    });
}

fn sync(ui: &AppWindow, state: &Desktop) {
    let session = &state.session;
    let t = ui.global::<UiText>();
    ui.set_engine_status(if let Some(version) = &session.engine_version {
        t.invoke_engine_ready(version.as_str().into())
    } else if session.engine_attempted {
        t.get_engine_unavailable()
    } else {
        t.get_engine_disconnected()
    });
    ui.set_status(localized_status_with_extra(
        ui,
        session.status_kind,
        &session.status,
        &session.status_detail,
        &session.status_extra,
    ));
    ui.set_status_tone(status_tone(session.outcome));
    ui.set_engine_tone(if session.connected {
        Tone::Good
    } else {
        Tone::Attention
    });
    ui.set_busy(session.busy() || state.dialog_open || state.exporting);
    let stopping =
        session.busy() && !session.publishing() && session.cancel.load(Ordering::Relaxed);
    ui.set_can_cancel(session.busy() && !session.publishing() && !stopping);
    ui.set_can_inspect(session.connected && session.image.is_some());
    ui.set_can_scan(session.connected && session.image.is_some() && !session.source.is_empty());
    ui.set_can_plan(session.scan.as_ref().is_some_and(|s| {
        s.report
            .patches
            .iter()
            .any(|p| p.selected && p.selectable())
    }));
    ui.set_can_recommend(session.connected && session.scan.is_some());
    ui.set_manifest_path(
        session
            .output
            .as_ref()
            .map(|p| manifest_path(p).to_string_lossy().as_ref().into())
            .unwrap_or_default(),
    );
    ui.set_can_apply(session.can_apply());
    ui.set_can_verify(
        session.connected
            && session.image.is_some()
            && session.output.is_some()
            && session.manifest.is_some()
            && session.review.is_some(),
    );
    let operation = if state.exporting {
        t.get_operation_export()
    } else if state.dialog_open {
        t.get_operation_pick()
    } else if stopping {
        t.get_status_stopping()
    } else {
        session
            .activity()
            .map(|action| localized_activity(ui, action))
            .unwrap_or_default()
    };
    ui.set_operation_label(operation);
    if state.exporting || state.dialog_open {
        ui.set_elapsed("".into());
    }
    sync_rows(
        ui.get_image_facts(),
        image_facts(ui, session.inspection.as_ref()),
        |m| ui.set_image_facts(m),
    );
    ui.set_image_sha(image_sha(session.inspection.as_ref()).into());
    sync_rows(
        ui.get_scan_facts(),
        session
            .scan
            .as_ref()
            .map(|scan| scan_facts(ui, scan))
            .unwrap_or_default(),
        |m| ui.set_scan_facts(m),
    );
    let patches = session
        .scan
        .as_ref()
        .map(|s| {
            let selectable = !session.busy();
            s.report
                .patches
                .iter()
                .map(|p| patch_row(ui, &s.alias, p, selectable))
                .collect()
        })
        .unwrap_or_default();
    sync_rows(ui.get_patches(), patches, |m| ui.set_patches(m));
    sync_review(ui, state);
    ui.set_result_details(
        session
            .verification_report
            .as_ref()
            .map(|report| verification_summary(ui, report))
            .unwrap_or_else(|| session.result_details.as_str().into()),
    );
    ui.set_result_title(match session.outcome {
        Outcome::Verified => t.get_status_verified(),
        Outcome::VerificationIncomplete => t.get_title_incomplete(),
        Outcome::PublicationIncomplete => t.get_title_publication(),
        Outcome::Interrupted => t.get_title_interrupted(),
        _ => t.get_title_output(),
    });
    ui.set_source_details(session.source_details.as_str().into());
    ui.set_tool_details(
        session
            .tool_report
            .as_ref()
            .map(|(data, paths)| {
                format!(
                    "{}\n\n{}\n{}",
                    crate::model::pretty(data),
                    t.get_tool_paths(),
                    paths.as_ref().map(crate::model::pretty).unwrap_or_default()
                )
                .into()
            })
            .unwrap_or_default(),
    );
    ui.set_diagnostics(session.diagnostics.as_str().into());
    ui.set_stage(
        if session.manifest.is_some()
            || matches!(
                session.outcome,
                Outcome::Verified
                    | Outcome::PublicationIncomplete
                    | Outcome::VerificationIncomplete
            )
        {
            3
        } else if session.review.is_some() {
            2
        } else if session.scan.is_some() {
            1
        } else {
            0
        },
    );
}

/// Render an operation label from its semantic action on the UI thread.
/// Example: `localized_activity(&window, Action::Scan)` names an active scan.
pub fn localized_activity(ui: &AppWindow, action: Action) -> SharedString {
    let t = ui.global::<UiText>();
    match action {
        Action::Connect => t.get_operation_connect(),
        Action::Inspect => t.get_operation_inspect(),
        Action::Scan => t.get_operation_scan(),
        Action::Plan | Action::Recommended => t.get_operation_plan(),
        Action::Apply => t.get_operation_apply(),
        Action::Verify => t.get_operation_verify(),
        Action::Sources => t.get_operation_sources(),
        Action::Tools => t.get_operation_tools(),
        Action::Import => t.get_operation_import(),
    }
}

/// Render semantic status and preserve original technical details for errors.
/// Example: `localized_status(&window, Status::Activity(Action::Scan), "", "")`.
pub fn localized_status(ui: &AppWindow, status: Status, raw: &str, detail: &str) -> SharedString {
    localized_status_with_extra(ui, status, raw, detail, "")
}

fn localized_status_with_extra(
    ui: &AppWindow,
    status: Status,
    raw: &str,
    detail: &str,
    extra: &str,
) -> SharedString {
    let t = ui.global::<UiText>();
    match status {
        Status::Start => t.get_status_start(),
        Status::Inputs => t.get_status_inputs(),
        Status::ImportedInput => t.get_status_imported_input(),
        Status::Selection => t.get_status_selection(),
        Status::Ready => t.get_status_ready(),
        Status::Inspected => t.get_status_inspected(),
        Status::Scanned => t.get_status_scanned(),
        Status::Planned => t.get_status_planned(),
        Status::Published => t.get_status_published(),
        Status::Verified => t.get_status_verified(),
        Status::Incomplete => t.get_status_incomplete(),
        Status::Sources => t.get_status_sources(),
        Status::Tools => t.get_status_tools(),
        Status::Imported => t.get_status_imported(),
        Status::Stopping => t.get_status_stopping(),
        Status::Back => t.get_status_back(),
        Status::ClosingExport => t.get_status_closing_export(),
        Status::ClosingBuild => t.get_status_closing_build(),
        Status::ClosingStop => t.get_status_closing_stop(),
        Status::ExportNeedsPlan => t.get_status_export_needs_plan(),
        Status::Activity(action) => localized_activity(ui, action),
        Status::Precondition(error) => match error {
            PreparationError::Busy => t.get_precondition_busy(),
            PreparationError::Engine => t.get_precondition_engine(),
            PreparationError::Image => t.get_precondition_image(),
            PreparationError::ImportPath => t.get_precondition_import(),
            PreparationError::Scan => t.get_precondition_scan(),
            PreparationError::Selection => t.get_precondition_selection(),
            PreparationError::Build => t.get_precondition_build(),
            PreparationError::Output => t.get_precondition_output(),
            PreparationError::Plan => t.get_precondition_plan(),
            PreparationError::Manifest => t.get_precondition_manifest(),
            PreparationError::WaitImport => t.get_precondition_wait_import(),
        },
        Status::Failed => t.invoke_status_failed(detail.into()),
        Status::PublicationUnknown => t.invoke_status_publication_unknown(detail.into()),
        Status::Raw => raw.into(),
        Status::PreferencesError => t.invoke_preferences_error(detail.into()),
        Status::PreferencesNoLocation => t.get_preferences_no_location(),
        Status::PreferencesProtected => t.invoke_preferences_protected(detail.into()),
        Status::PickerError => t.invoke_picker_error(detail.into()),
        Status::ExportingPlan => t.get_exporting_plan(),
        Status::ExportingDiagnostics => t.get_exporting_diagnostics(),
        Status::PlanExported => t.invoke_plan_exported(detail.into()),
        Status::DiagnosticsExported => t.invoke_diagnostics_exported(detail.into()),
        Status::PlanExists => t.invoke_plan_exists(detail.into()),
        Status::DiagnosticsExist => t.invoke_diagnostics_exists(detail.into()),
        Status::PlanExportError => t.invoke_plan_export_error(detail.into(), extra.into()),
        Status::DiagnosticsExportError => {
            t.invoke_diagnostics_export_error(detail.into(), extra.into())
        }
    }
}

fn sync_review(ui: &AppWindow, state: &Desktop) {
    let mut presented = state.presented_review.borrow_mut();
    let unchanged = match (&*presented, &state.session.review) {
        (Some(old), Some(new)) => Arc::ptr_eq(old, new),
        (None, None) => true,
        _ => false,
    };
    if unchanged {
        return;
    }
    ui.set_plan_details(
        state
            .session
            .review
            .as_ref()
            .map(|review| plan_summary(ui, review))
            .unwrap_or_default(),
    );
    ui.set_plan_snapshot(
        state
            .session
            .review
            .as_ref()
            .map(|review| review.snapshot.clone())
            .unwrap_or_default(),
    );
    *presented = state.session.review.clone();
}

/// Render a reviewed plan's summary in the selected language.
/// Example: `plan_summary(&window, &review)` starts with `Generated in this session` in English.
pub fn plan_summary(ui: &AppWindow, review: &Review) -> SharedString {
    let t = ui.global::<UiText>();
    let plan = &review.document;
    let value = |v: &serde_json::Value| -> SharedString { v.as_str().unwrap_or("?").into() };
    let joined = |v: &serde_json::Value| -> SharedString {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|s| !s.is_empty())
            .map(Into::into)
            .unwrap_or_else(|| t.get_none())
    };
    let header = if review.generated {
        t.get_generated_plan()
    } else {
        t.get_imported_plan()
    };
    let mut output = header;
    output.push_str("\n\n");
    output.push_str(
        t.invoke_plan_intro(
            value(&plan["firmware"]),
            value(&plan["source"]["alias"]),
            value(&plan["source"]["catalog_id"]),
            value(&plan["source"]["catalog_version"]),
            value(&plan["source"]["trust"]),
            joined(&plan["requested"]),
            joined(&plan["selected"]),
            joined(&plan["carried"]),
            value(&plan["input"]["sha256"]),
            value(&plan["output"]["sha256"]),
            value(&plan["engine"]["version"]),
            value(&plan["engine"]["codec"]),
        )
        .as_str(),
    );
    if let Some(components) = plan["components"].as_array() {
        for component in components {
            output.push_str(
                t.invoke_plan_component(
                    value(&component["name"]),
                    value(&component["ffs_guid"]),
                    component["table_offset"].to_string().into(),
                    component["file_offset"].to_string().into(),
                    joined(&component["patches"]),
                )
                .as_str(),
            );
        }
    }
    output.push_str(
        t.invoke_plan_end(
            joined(&plan["facts"]),
            plan["allow_hold"].to_string().into(),
            plan["allow_diagnostic"].to_string().into(),
            joined(&plan["notes"]),
        )
        .as_str(),
    );
    output
}

/// Present each reported verification check, its result and limits, in the selected language.
/// Example: a skipped reproduction check reads `SKIPPED  reproduction` in English.
pub fn verification_summary(ui: &AppWindow, report: &serde_json::Value) -> SharedString {
    let t = ui.global::<UiText>();
    let mut lines = vec![t.get_offline_checks().to_string(), String::new()];
    if let Some(checks) = report["checks"].as_array() {
        for check in checks {
            let name = check["check"].as_str();
            let label = match name {
                Some("input-digest") => t.get_input_digest(),
                Some("output-digest") => t.get_output_digest(),
                Some("structure") => t.get_structure(),
                Some("unchanged-outside-allowlist") => t.get_unchanged(),
                Some("changed-regions") => t.get_changed(),
                Some("patch-states") => t.get_patch_states(),
                Some("reproduced-from-catalog") => t.get_reproduced(),
                Some(other) => other.into(),
                None => t.get_unknown_check(),
            };
            lines.push(
                if check["ok"] == true {
                    t.invoke_check_passed(label)
                } else {
                    t.invoke_check_incomplete(label)
                }
                .to_string(),
            );
        }
    }
    if let Some(checks) = report["skipped"].as_array() {
        for check in checks {
            lines.push(
                t.invoke_check_skipped(
                    check["check"]
                        .as_str()
                        .map_or_else(|| t.get_unknown(), Into::into),
                    check["reason"]
                        .as_str()
                        .map_or_else(|| t.get_unknown(), Into::into),
                )
                .to_string(),
            );
        }
    }
    lines.push(format!(
        "\n{}",
        report["notice"]
            .as_str()
            .map_or_else(|| t.get_unknown(), Into::into)
    ));
    lines.join("\n").into()
}

/// Pick the status-bar tone that matches how the last operation ended.
/// Example: `status_tone(Outcome::Verified)` is `Tone::Good`; a failure is `Tone::Danger`.
pub fn status_tone(outcome: Outcome) -> Tone {
    match outcome {
        Outcome::Verified => Tone::Good,
        Outcome::Failed | Outcome::PublicationIncomplete => Tone::Danger,
        Outcome::Interrupted | Outcome::VerificationIncomplete => Tone::Attention,
        Outcome::Idle | Outcome::Running => Tone::Quiet,
    }
}

/// Present one scan row in the selected language, enabling its checkbox only while idle.
/// Example: `patch_row(&window, "lab", &patch, true).id` is `lab::PA@1.0.0`.
pub fn patch_row(ui: &AppWindow, alias: &str, patch: &Patch, idle: bool) -> PatchRow {
    let text = ui.global::<UiText>();
    let state = match patch.state.as_str() {
        "present" => text.get_defect_present(),
        "fixed" => text.get_fixed(),
        "partial" => text.get_partially_patched(),
        "likely-present" => text.get_likely_present(),
        "likely-fixed" => text.get_likely_fixed(),
        "not-detected" => text.get_not_detected(),
        "not-applicable" => text.get_not_applicable(),
        "unsupported" => text.get_unsupported(),
        _ => patch.state.as_str().into(),
    };
    // Engine detail stays in `detail`; `blocker` lists only why the desktop cannot select it.
    let mut limits = Vec::new();
    if let Some(blocked) = &patch.blocked {
        limits.push(blocked.clone());
    }
    if !patch.requires_facts.is_empty() {
        limits.push(
            text.invoke_requires_facts(patch.requires_facts.join(", ").into())
                .to_string(),
        );
    }
    if !patch.selectable() {
        limits.push(text.get_selection_limit().to_string());
    }
    PatchRow {
        id: patch.qualified(alias).into(),
        title: patch.title.as_str().into(),
        version: patch.version.as_str().into(),
        class: patch.class.as_str().into(),
        tier: patch.tier.as_str().into(),
        state,
        tone: match patch.state_tone() {
            StateTone::Attention => Tone::Attention,
            StateTone::Good => Tone::Good,
            StateTone::Quiet => Tone::Quiet,
        },
        detail: patch.detail.as_str().into(),
        blocker: limits.join("\n").into(),
        evidence: if patch.evidence.is_empty() {
            text.get_no_evidence()
        } else {
            text.invoke_scoped_evidence(patch.evidence.join(", ").into())
        },
        selectable: patch.selectable() && idle,
        selected: patch.selected,
    }
}

/// Update a Slint list in place so unchanged rows are not re-rendered.
/// Example: `sync_rows(ui.get_patches(), rows, |model| ui.set_patches(model))`.
fn sync_rows<T: Clone + PartialEq + 'static>(
    current: ModelRc<T>,
    rows: Vec<T>,
    replace: impl FnOnce(ModelRc<T>),
) {
    let Some(model) = current.as_any().downcast_ref::<VecModel<T>>() else {
        replace(ModelRc::new(VecModel::from(rows)));
        return;
    };
    if model.row_count() != rows.len() {
        model.set_vec(rows);
        return;
    }
    for (index, row) in rows.into_iter().enumerate() {
        if model.row_data(index).as_ref() != Some(&row) {
            model.set_row_data(index, row);
        }
    }
}

fn fact(label: &str, value: impl Into<SharedString>) -> Fact {
    Fact {
        label: label.into(),
        value: value.into(),
    }
}

/// Summarize an inspection for the findings header in the selected language.
/// Example: in English a 36864-byte image with two volumes reads `Size 36,864 bytes` and `Volumes 2`.
pub fn image_facts(ui: &AppWindow, inspection: Option<&serde_json::Value>) -> Vec<Fact> {
    let Some(value) = inspection else {
        return Vec::new();
    };
    let text = ui.global::<UiText>();
    vec![
        fact(
            text.get_size().as_str(),
            text.invoke_bytes_size(group_digits(&value["length"].to_string()).into()),
        ),
        fact(
            text.get_volumes().as_str(),
            value["volumes"].as_array().map_or(0, Vec::len).to_string(),
        ),
        fact(
            text.get_layout().as_str(),
            if value["descriptor_regions"].is_null() {
                text.get_bare_bios()
            } else {
                text.get_flash_descriptor()
            },
        ),
    ]
}

/// Return the inspected image digest, or an empty string before inspection.
/// Example: `image_sha(Some(&json!({"sha256": "ab"})))` is `ab`.
pub fn image_sha(inspection: Option<&serde_json::Value>) -> String {
    inspection
        .map(|v| v["sha256"].as_str().unwrap_or("unknown").to_owned())
        .unwrap_or_default()
}

/// Summarize the catalog source behind a scan in the selected language.
/// Example: alias `lab` with catalog `synthetic 1.0.0` reads `lab · synthetic 1.0.0`.
pub fn scan_facts(ui: &AppWindow, scan: &crate::model::SourceReport) -> Vec<Fact> {
    let text = ui.global::<UiText>();
    vec![
        fact(
            text.get_source().as_str(),
            format!("{} · {} {}", scan.alias, scan.catalog, scan.catalog_version),
        ),
        fact(text.get_trust().as_str(), scan.trust.as_str()),
        fact(
            text.get_firmware().as_str(),
            scan.report
                .firmware
                .as_deref()
                .map(SharedString::from)
                .unwrap_or_else(|| text.get_unknown_firmware()),
        ),
        fact(
            text.get_boards().as_str(),
            if scan.report.boards.is_empty() {
                text.get_no_boards()
            } else {
                scan.report.boards.join(", ").into()
            },
        ),
    ]
}

/// Insert thousands separators into a run of ASCII digits; other text passes through.
/// Example: `group_digits("36864")` is `36,864`.
fn group_digits(digits: &str) -> String {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return digits.to_owned();
    }
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

fn sync_paths(ui: &AppWindow, state: &Desktop) {
    ui.set_image_path(display_path(state.session.image.as_ref()));
    ui.set_output_path(display_path(state.session.output.as_ref()));
    ui.set_engine_path(state.engine_path.to_string_lossy().as_ref().into());
    ui.set_source(state.session.source.as_str().into());
}

fn display_path(path: Option<&PathBuf>) -> SharedString {
    path.map(|p| p.to_string_lossy().as_ref().into())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
