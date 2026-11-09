//! Slint event-loop wiring. Workers never hold a strong window reference.

use crate::controller::{Action, Outcome, Review, Session, manifest_path, write_new_file};
use crate::engine::Engine;
use crate::model::{Patch, StateTone};
use crate::settings::Settings;
use crate::ui::{AppWindow, Fact, PatchRow, Tone};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, atomic::Ordering};
use std::time::{Duration, Instant};

pub struct Desktop {
    pub session: Session,
    pub engine_path: PathBuf,
    settings: Settings,
    settings_path: Option<PathBuf>,
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
    /// Example: `Desktop::new(engine_path, settings, settings_path)?`.
    pub fn new(
        engine_path: PathBuf,
        settings: Settings,
        settings_path: Option<PathBuf>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            session: Session::new()?,
            engine_path,
            settings,
            settings_path,
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
    let state = Arc::new(Mutex::new(desktop));
    ui.set_theme_choice(state.lock().unwrap().settings.theme.into());
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
        state.session.status = "Stopping operation…".into();
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
    ui.on_back_to_selection(move || {
        let mut state = shared.lock().unwrap();
        if state.session.busy() || state.exporting || state.dialog_open {
            return;
        }
        state.session.clear_results();
        state.session.status = "Select corrections and generate a new plan to continue.".into();
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
            state.session.status = "Finishing file export before closing…".into();
            if let Some(ui) = weak.upgrade() {
                sync(&ui, &state);
            }
            return slint::CloseRequestResponse::KeepWindowShown;
        }
        if state.session.publishing() {
            state.session.status =
                "Building the copy. Close the window after publication finishes.".into();
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
            state.session.status = "Stopping operation before closing…".into();
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

fn start(ui: &AppWindow, shared: &Shared, action: Action) {
    let mut state = shared.lock().unwrap();
    if state.dialog_open || state.exporting {
        return;
    }
    let engine = Engine::new(&state.engine_path, PathBuf::from("/"));
    let job = engine
        .as_ref()
        .map_err(ToString::to_string)
        .and_then(|_| state.session.prepare(action));
    let job = match job {
        Ok(job) => job,
        Err(error) => {
            state.session.status = error;
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
                    .set_title("Save a new patched copy")
                    .set_file_name("patched.bin")
                    .save_file()
                    .await
            }
            PathKind::ExportPlan => {
                dialog
                    .set_title("Export reviewed plan to a new file")
                    .set_file_name("bme-plan.json")
                    .save_file()
                    .await
            }
            PathKind::Diagnostics => {
                dialog
                    .set_title("Export diagnostics to a new file")
                    .set_file_name("bme-diagnostics.txt")
                    .save_file()
                    .await
            }
            PathKind::Plan => {
                dialog
                    .set_title("Open a plan for review")
                    .add_filter("Plan", &["json"])
                    .pick_file()
                    .await
            }
            PathKind::Engine => dialog.set_title("Choose bme executable").pick_file().await,
            PathKind::ExistingOutput => {
                dialog
                    .set_title("Open a built image with its paired manifest")
                    .pick_file()
                    .await
            }
            _ => dialog.set_title("Open firmware image").pick_file().await,
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
        state.session.status = format!("File picker unavailable: {error}. Enter a path manually.");
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
    if let Some(path) = &state.settings_path
        && let Err(error) = state.settings.save(path)
    {
        state.session.status = format!("Could not save preferences: {error}");
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
        state.session.status = "Review a plan before exporting it.".into();
        sync(ui, &state);
        return;
    };
    let writer = state.export_writer.clone();
    state.exporting = true;
    state.session.status = format!("Exporting {}…", kind.label().to_lowercase());
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
    state.session.status = match result {
        Ok(()) => format!("{label} exported to {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => format!(
            "{label} export {}: file already exists; choose a new path.",
            path.display()
        ),
        Err(error) => format!(
            "{label} export {}: {error}. A partial file may remain.",
            path.display()
        ),
    };
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
            state.session.status = error;
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
    ui.set_engine_status(session.engine_status.as_str().into());
    ui.set_status(session.status.as_str().into());
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
        "Exporting file"
    } else if state.dialog_open {
        "Choosing file"
    } else if stopping {
        "Stopping operation…"
    } else {
        session.activity().map(Action::label).unwrap_or("")
    };
    ui.set_operation_label(operation.into());
    if state.exporting || state.dialog_open {
        ui.set_elapsed("".into());
    }
    sync_rows(
        ui.get_image_facts(),
        image_facts(session.inspection.as_ref()),
        |m| ui.set_image_facts(m),
    );
    ui.set_image_sha(image_sha(session.inspection.as_ref()).into());
    sync_rows(
        ui.get_scan_facts(),
        session.scan.as_ref().map(scan_facts).unwrap_or_default(),
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
                .map(|p| patch_row(&s.alias, p, selectable))
                .collect()
        })
        .unwrap_or_default();
    sync_rows(ui.get_patches(), patches, |m| ui.set_patches(m));
    sync_review(ui, state);
    ui.set_result_details(session.result_details.as_str().into());
    ui.set_result_title(
        match session.outcome {
            Outcome::Verified => "Offline verification complete",
            Outcome::VerificationIncomplete => "Verification incomplete",
            Outcome::PublicationIncomplete => "Publication incomplete: inspect remaining artifacts",
            Outcome::Interrupted => "Operation interrupted: review the outcome",
            _ => "Output & verification",
        }
        .into(),
    );
    ui.set_source_details(session.source_details.as_str().into());
    ui.set_tool_details(session.tool_details.as_str().into());
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
            .map(|r| r.text.clone())
            .unwrap_or_default(),
    );
    *presented = state.session.review.clone();
}

/// Present one scan row, enabling its checkbox only while no operation is running.
/// Example: `patch_row("lab", &patch, true).id` is `lab::PA@1.0.0`.
pub fn patch_row(alias: &str, patch: &Patch, idle: bool) -> PatchRow {
    PatchRow {
        id: patch.qualified(alias).into(),
        title: patch.title.as_str().into(),
        version: patch.version.as_str().into(),
        class: patch.class.as_str().into(),
        tier: patch.tier.as_str().into(),
        state: patch.state_label().into(),
        tone: match patch.state_tone() {
            StateTone::Attention => Tone::Attention,
            StateTone::Good => Tone::Good,
            StateTone::Quiet => Tone::Quiet,
        },
        detail: patch.detail.as_str().into(),
        blocker: patch.limits().join("\n").into(),
        evidence: if patch.evidence.is_empty() {
            "No hardware observations for this patch version.".into()
        } else {
            format!(
                "Scoped evidence: {}. See Sources & tools for image, board and scenario.",
                patch.evidence.join(", ")
            )
            .into()
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

/// Summarize an inspection for the findings header.
/// Example: a 36864-byte image with two volumes reads `Size 36,864 bytes` and `Volumes 2`.
pub fn image_facts(inspection: Option<&serde_json::Value>) -> Vec<Fact> {
    let Some(v) = inspection else {
        return Vec::new();
    };
    let layout = if v["descriptor_regions"].is_null() {
        "Bare BIOS / firmware volumes"
    } else {
        "Intel flash descriptor"
    };
    vec![
        fact("Size", group_digits(&v["length"].to_string()) + " bytes"),
        fact(
            "Volumes",
            v["volumes"].as_array().map_or(0, Vec::len).to_string(),
        ),
        fact("Layout", layout),
    ]
}

/// Return the inspected image digest, or an empty string before inspection.
/// Example: `image_sha(Some(&json!({"sha256": "ab"})))` is `ab`.
pub fn image_sha(inspection: Option<&serde_json::Value>) -> String {
    inspection
        .map(|v| v["sha256"].as_str().unwrap_or("unknown").to_owned())
        .unwrap_or_default()
}

/// Summarize the catalog source behind a scan.
/// Example: alias `lab` with catalog `synthetic 1.0.0` reads `lab · synthetic 1.0.0`.
pub fn scan_facts(scan: &crate::model::SourceReport) -> Vec<Fact> {
    let boards = if scan.report.boards.is_empty() {
        "none matched".to_owned()
    } else {
        scan.report.boards.join(", ")
    };
    vec![
        fact(
            "Source",
            format!("{} · {} {}", scan.alias, scan.catalog, scan.catalog_version),
        ),
        fact("Trust", scan.trust.as_str()),
        fact(
            "Firmware",
            scan.report
                .firmware
                .as_deref()
                .unwrap_or("unknown or ambiguous"),
        ),
        fact("Boards", boards),
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
