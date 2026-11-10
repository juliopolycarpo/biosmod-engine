//! Session transitions and reviewed-plan ownership, independent of the windowing backend.

use crate::engine::{Engine, EngineError, ErrorKind, Reply, Request, Verification};
use crate::model::{Scan, SourceReport, plan_summary, pretty, verification_summary};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tempfile::TempDir;

const PLAN_LIMIT: u64 = 16 * 1024 * 1024;
const LOG_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Connect,
    Inspect,
    Scan,
    Plan,
    Recommended,
    Apply,
    Verify,
    Sources,
    Tools,
    Import,
}

impl Action {
    /// Describe real activity without inventing percentage progress.
    /// Example: `Action::Verify.label()` is `"Verifying output"`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Connect => "Checking engine",
            Self::Inspect => "Inspecting image",
            Self::Scan => "Scanning image",
            Self::Plan | Self::Recommended => "Generating plan",
            Self::Apply => "Building patched copy",
            Self::Verify => "Verifying output",
            Self::Sources => "Reading sources",
            Self::Tools => "Checking tools",
            Self::Import => "Opening plan",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Idle,
    Running,
    Failed,
    Interrupted,
    PublicationIncomplete,
    VerificationIncomplete,
    Verified,
}

/// A GUI action cannot start until its required inputs are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparationError {
    Busy,
    Engine,
    Image,
    ImportPath,
    Scan,
    Selection,
    Build,
    Output,
    Plan,
    Manifest,
    WaitImport,
}

impl std::fmt::Display for PreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Busy => "An operation is already running.",
            Self::Engine => "Connect a compatible bme engine first.",
            Self::Image => "Choose an original image first.",
            Self::ImportPath => "Plan import requires an explicit path.",
            Self::Scan => "Scan this image and source before planning.",
            Self::Selection => "Select an eligible correction first.",
            Self::Build => "Build requires a current generated plan and a new output path.",
            Self::Output => "Choose a built output first.",
            Self::Plan => "Open or generate the matching plan first.",
            Self::Manifest => "Choose an output with its paired manifest first.",
            Self::WaitImport => "Wait for the active operation before importing a plan.",
        })
    }
}
impl std::error::Error for PreparationError {}

/// Semantic status used by the GUI to render messages without parsing diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Start,
    Inputs,
    ImportedInput,
    Selection,
    Ready,
    Inspected,
    Scanned,
    Planned,
    Published,
    Verified,
    Incomplete,
    Sources,
    Tools,
    Imported,
    Stopping,
    Back,
    ClosingExport,
    ClosingBuild,
    ClosingStop,
    ExportNeedsPlan,
    Activity(Action),
    Precondition(PreparationError),
    Failed,
    PublicationUnknown,
    Raw,
    PreferencesError,
    PreferencesNoLocation,
    PreferencesProtected,
    PickerError,
    ExportingPlan,
    ExportingDiagnostics,
    PlanExported,
    DiagnosticsExported,
    PlanExists,
    DiagnosticsExist,
    PlanExportError,
    DiagnosticsExportError,
}

impl Status {
    fn english(self) -> &'static str {
        match self {
            Self::Start => "Choose a firmware image to get started.",
            Self::Inputs => "Inputs changed. Inspect and scan to continue.",
            Self::ImportedInput => {
                "Imported plan remains read-only. Verify against the chosen original image and output."
            }
            Self::Selection => "Selection changed. Generate a new plan to review.",
            Self::Ready => "Engine ready. Choose an image to inspect.",
            Self::Inspected => "Image inspected. Scan a source for matching corrections.",
            Self::Scanned => {
                "Scan complete. Select corrections or review the engine's recommendation."
            }
            Self::Planned => "Review the resolved plan, then choose a new output and build a copy.",
            Self::Published => "Patched copy published. Independent verification is next.",
            Self::Verified => "Offline verification complete",
            Self::Incomplete => {
                "Verification incomplete. Review skipped checks and retry after addressing them."
            }
            Self::Sources => "Registered sources loaded. Firmware operations remain offline.",
            Self::Tools => "Tool diagnostics complete.",
            Self::Imported => {
                "Imported plan: review and verification only. Choose its original image and output."
            }
            Self::Stopping => "Stopping operation…",
            Self::Back => "Select corrections and generate a new plan to continue.",
            Self::ClosingExport => "Finishing file export before closing…",
            Self::ClosingBuild => "Building the copy. Close the window after publication finishes.",
            Self::ClosingStop => "Stopping operation before closing…",
            Self::ExportNeedsPlan => "Review a plan before exporting it.",
            Self::Activity(action) => action.label(),
            _ => "",
        }
    }
}

/// A status line saved while a notice temporarily replaces it.
#[derive(Debug, Clone)]
struct StatusSnapshot {
    kind: Status,
    text: String,
    detail: String,
    extra: String,
}

#[derive(Debug, Clone)]
pub struct Review {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub document: Value,
    pub generated: bool,
    pub(crate) text: slint::SharedString,
}

impl Review {
    /// Retain exact plan bytes and prepare its presentation on the worker.
    /// Example: `Review::new(path, bytes, document, false)` creates a read-only import.
    pub fn new(path: PathBuf, bytes: Vec<u8>, document: Value, generated: bool) -> Self {
        let text = format!(
            "{}\n\n{}",
            if generated {
                "Generated in this session"
            } else {
                "Read-only imported plan"
            },
            plan_summary(&document)
        );
        Self {
            path,
            bytes,
            document,
            generated,
            text: text.into(),
        }
    }
}

/// The UI owns this state. A worker receives only a prepared `Job` snapshot.
pub struct Session {
    directory: Arc<TempDir>,
    generation: u64,
    next_operation: u64,
    active: Option<(u64, u64, Action)>,
    pub cancel: Arc<AtomicBool>,
    pub image: Option<PathBuf>,
    pub source: String,
    pub output: Option<PathBuf>,
    pub manifest: Option<PathBuf>,
    pub connected: bool,
    pub engine_version: Option<String>,
    pub engine_attempted: bool,
    pub inspection: Option<Value>,
    pub scan: Option<SourceReport>,
    scan_input: Option<Value>,
    pub review: Option<Arc<Review>>,
    pub outcome: Outcome,
    pub status: String,
    pub status_kind: Status,
    pub status_detail: String,
    pub status_extra: String,
    /// The status a notice replaced, restored by `dismiss_notice`.
    noticed_status: Option<StatusSnapshot>,
    pub result_details: String,
    /// Retained verification data for presentation in the currently selected language.
    pub verification_report: Option<Value>,
    pub source_details: String,
    pub tool_report: Option<(Value, Option<Value>)>,
    pub diagnostics: String,
}

impl Session {
    /// Start an isolated session whose temporary files cannot overwrite user plans.
    /// Example: `let session = Session::new()?;`.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            directory: Arc::new(tempfile::Builder::new().prefix("bme-gui-").tempdir()?),
            generation: 0,
            next_operation: 0,
            active: None,
            cancel: Arc::new(AtomicBool::new(false)),
            image: None,
            source: "official".into(),
            output: None,
            manifest: None,
            connected: false,
            engine_version: None,
            engine_attempted: false,
            inspection: None,
            scan: None,
            scan_input: None,
            review: None,
            outcome: Outcome::Idle,
            status: Status::Start.english().into(),
            status_kind: Status::Start,
            status_detail: String::new(),
            status_extra: String::new(),
            noticed_status: None,
            result_details: String::new(),
            verification_report: None,
            source_details: String::new(),
            tool_report: None,
            diagnostics: String::new(),
        })
    }

    /// Set a semantic message while retaining an English representation for callers.
    /// Example: `session.set_status(Status::Selection)` after selection changes.
    pub fn set_status(&mut self, status: Status) {
        self.noticed_status = None;
        self.status_kind = status;
        self.status = status.english().into();
        self.status_detail.clear();
        self.status_extra.clear();
    }

    /// Display a non-translatable technical message. Example: `session.set_raw_status(error)`.
    pub fn set_raw_status(&mut self, detail: impl Into<String>) {
        self.noticed_status = None;
        self.status_kind = Status::Raw;
        self.status = detail.into();
        self.status_detail.clear();
        self.status_extra.clear();
    }

    /// Keep structured presentation values and an English fallback.
    /// Example: `session.set_detailed_status(Status::PickerError, "error", "", "error")`.
    pub fn set_detailed_status(
        &mut self,
        status: Status,
        detail: impl Into<String>,
        extra: impl Into<String>,
        fallback: impl Into<String>,
    ) {
        self.noticed_status = None;
        self.status_kind = status;
        self.status_detail = detail.into();
        self.status_extra = extra.into();
        self.status = fallback.into();
    }

    /// Show a detailed notice over the workflow status, which `dismiss_notice` brings back.
    /// Consecutive notices keep the original workflow status.
    /// Example: `session.set_notice(Status::PreferencesError, error, "", fallback)`.
    pub fn set_notice(
        &mut self,
        status: Status,
        detail: impl Into<String>,
        extra: impl Into<String>,
        fallback: impl Into<String>,
    ) {
        let replaced = self
            .noticed_status
            .take()
            .unwrap_or_else(|| StatusSnapshot {
                kind: self.status_kind,
                text: std::mem::take(&mut self.status),
                detail: std::mem::take(&mut self.status_detail),
                extra: std::mem::take(&mut self.status_extra),
            });
        self.set_detailed_status(status, detail, extra, fallback);
        self.noticed_status = Some(replaced);
    }

    /// Restore the status a notice replaced; without a notice the status stays as is.
    /// Example: call `session.dismiss_notice()` after preferences save again.
    pub fn dismiss_notice(&mut self) {
        if let Some(snapshot) = self.noticed_status.take() {
            self.status_kind = snapshot.kind;
            self.status = snapshot.text;
            self.status_detail = snapshot.detail;
            self.status_extra = snapshot.extra;
        }
    }

    /// Invalidate all derived data after an image, source, or engine change.
    /// Example: set `session.image`, then call `session.invalidate()` before another scan.
    pub fn invalidate(&mut self) {
        self.generation += 1;
        self.cancel.store(true, Ordering::Relaxed);
        self.inspection = None;
        self.scan = None;
        self.scan_input = None;
        self.review = None;
        self.output = None;
        self.manifest = None;
        self.result_details.clear();
        self.verification_report = None;
        self.outcome = Outcome::Idle;
        self.set_status(Status::Inputs);
    }

    /// Change the original image, retaining only imported artifacts for re-verification.
    /// Example: selecting an imported plan's original image never grants build permission.
    pub fn change_image(&mut self, image: Option<PathBuf>) {
        let generated = self.review.as_ref().is_some_and(|review| review.generated);
        let imported = self.review.take().filter(|review| !review.generated);
        let output = self.output.clone();
        let manifest = self.manifest.clone();
        self.invalidate();
        self.image = image;
        if imported.is_some() {
            self.review = imported;
            self.output = output;
            self.manifest = manifest;
            self.set_status(Status::ImportedInput);
        } else if !generated && manifest.is_some() {
            self.output = output;
            self.manifest = manifest;
        }
    }

    /// Return whether a worker still owns the operation slot, including a stale worker.
    /// Example: disable duplicate actions while `session.busy()`.
    pub fn busy(&self) -> bool {
        self.active.is_some()
    }

    /// Publication must finish before ordinary window closure.
    /// Example: ignore a close request while `session.publishing()`.
    pub fn publishing(&self) -> bool {
        self.active.is_some_and(|a| a.2 == Action::Apply)
    }

    /// Report the current operation for an indeterminate activity indicator.
    /// Example: `session.activity().map(Action::label)`.
    pub fn activity(&self) -> Option<Action> {
        self.active.map(|a| a.2)
    }

    /// Change one eligible selection and invalidate its previous plan immediately.
    /// Example: `session.toggle(0)` toggles the first scan row if selectable.
    pub fn toggle(&mut self, index: usize) {
        if self.busy() {
            return;
        }
        let Some(patch) = self
            .scan
            .as_mut()
            .and_then(|s| s.report.patches.get_mut(index))
        else {
            return;
        };
        if !patch.selectable() {
            return;
        }
        patch.selected = !patch.selected;
        self.clear_results();
        self.set_status(Status::Selection);
    }

    /// Drop the review, manifest, and result text after any input that makes them stale.
    /// Example: `session.clear_results()` before offering a new output path.
    pub fn clear_results(&mut self) {
        self.review = None;
        self.manifest = None;
        self.result_details.clear();
        self.verification_report = None;
        self.outcome = Outcome::Idle;
    }

    /// Whether the current generated review can be explicitly applied.
    /// Example: imported reviews always make `can_apply()` false.
    pub fn can_apply(&self) -> bool {
        self.connected
            && !self.busy()
            && self.review.as_ref().is_some_and(|r| r.generated)
            && self.output.is_some()
            && self.image.is_some()
            && self.manifest.is_none()
    }

    /// Prepare one operation with immutable paths and generation tags.
    /// Example: pass `session.prepare(Action::Scan)?` to a worker's `Job::run`.
    pub fn prepare(&mut self, action: Action) -> Result<Job, PreparationError> {
        if self.busy() {
            return Err(PreparationError::Busy);
        }
        if action != Action::Connect && !self.connected {
            return Err(PreparationError::Engine);
        }
        let image = || self.image.clone().ok_or(PreparationError::Image);
        let request = match action {
            Action::Import => return Err(PreparationError::ImportPath),
            Action::Connect => Request::Capabilities,
            Action::Inspect => Request::Inspect { image: image()? },
            Action::Scan => Request::Scan {
                image: image()?,
                source: self.source.clone(),
            },
            Action::Plan | Action::Recommended => {
                let scan = self.scan.as_ref().ok_or(PreparationError::Scan)?;
                let selection = if action == Action::Recommended {
                    vec!["recommended".into()]
                } else {
                    scan.report
                        .patches
                        .iter()
                        .filter(|p| p.selected && p.selectable())
                        .map(|p| p.qualified(&scan.alias))
                        .collect::<Vec<_>>()
                };
                if selection.is_empty() {
                    return Err(PreparationError::Selection);
                }
                Request::Plan {
                    image: image()?,
                    source: self.source.clone(),
                    selection,
                    output: self
                        .directory
                        .path()
                        .join(format!("plan-{}.json", self.next_operation)),
                }
            }
            Action::Apply => {
                if !self.can_apply() {
                    return Err(PreparationError::Build);
                }
                Request::Patch {
                    image: image()?,
                    plan: self.review.as_ref().unwrap().path.clone(),
                    output: self.output.clone().unwrap(),
                }
            }
            Action::Verify => Request::Verify {
                input: image()?,
                output: self.output.clone().ok_or(PreparationError::Output)?,
                plan: self
                    .review
                    .as_ref()
                    .ok_or(PreparationError::Plan)?
                    .path
                    .clone(),
                manifest: self.manifest.clone().ok_or(PreparationError::Manifest)?,
            },
            Action::Sources => Request::CatalogList,
            Action::Tools => Request::ToolsDoctor,
        };
        let token = self.begin(action);
        if matches!(action, Action::Plan | Action::Recommended) {
            self.review = None;
        }
        Ok(Job {
            token,
            request,
            cancel: self.cancel.clone(),
            _directory: self.directory.clone(),
            reviewed: self.review.clone(),
        })
    }

    /// Claim the single operation slot with a fresh cancel flag.
    /// Example: `let token = self.begin(Action::Scan);` before building a `Job`.
    fn begin(&mut self, action: Action) -> (u64, u64, Action) {
        self.next_operation += 1;
        let token = (self.generation, self.next_operation, action);
        self.active = Some(token);
        self.cancel = Arc::new(AtomicBool::new(false));
        self.outcome = Outcome::Running;
        self.set_status(Status::Activity(action));
        token
    }

    /// Accept only the result belonging to the active operation and current inputs.
    /// Example: an old image's scan completion returns `false` without changing its successor.
    pub fn finish(&mut self, completion: Completion) -> bool {
        if self.active != Some(completion.token) {
            return false;
        }
        self.active = None;
        if self.generation != completion.token.0 {
            return false;
        }
        let action = completion.token.2;
        let result = completion
            .result
            .and_then(|payload| self.accept(action, payload));
        if let Err(error) = result {
            self.fail(action, error);
        }
        true
    }

    fn accept(&mut self, action: Action, payload: Payload) -> Result<(), EngineError> {
        self.log(&payload.reply.diagnostics);
        let data = payload.reply.data;
        self.outcome = Outcome::Idle;
        match action {
            Action::Connect => {
                self.connected = true;
                self.engine_attempted = true;
                self.engine_version = Some(payload.reply.version.clone());
                self.set_status(Status::Ready);
            }
            Action::Inspect => {
                self.inspection = Some(data);
                self.set_status(Status::Inspected);
            }
            Action::Scan => {
                let mut scan: Scan = serde_json::from_value(data).map_err(|e| {
                    local_error(format!(
                        "scan report: expected typed source and patch fields | received {e}"
                    ))
                })?;
                if scan.sources.len() != 1 {
                    return Err(local_error("scan: expected exactly one source"));
                }
                self.scan_input = Some(scan.input);
                self.scan = scan.sources.pop();
                self.review = None;
                self.manifest = None;
                self.source_details = payload.extra.map(|v| pretty(&v)).unwrap_or_default();
                self.set_status(Status::Scanned);
            }
            Action::Plan | Action::Recommended => {
                let review = payload
                    .review
                    .ok_or_else(|| local_error("plan: expected retained review bytes"))?;
                self.validate_generated(&review.document)?;
                self.review = Some(review);
                self.manifest = None;
                self.set_status(Status::Planned);
            }
            Action::Apply => {
                data["manifest_file"]
                    .as_str()
                    .ok_or_else(|| local_error("patch: expected manifest_file display path"))?;
                self.manifest = self.output.as_ref().map(|path| manifest_path(path));
                self.result_details = pretty(&data);
                self.verification_report = None;
                self.set_status(Status::Published);
            }
            Action::Verify => {
                let verification = Verification::from_data(&data)?;
                self.outcome = if verification.complete {
                    Outcome::Verified
                } else {
                    Outcome::VerificationIncomplete
                };
                self.set_status(if verification.complete {
                    Status::Verified
                } else {
                    Status::Incomplete
                });
                self.log(&pretty(&data));
                self.result_details = verification_summary(&data);
                self.verification_report = Some(data);
            }
            Action::Sources => {
                self.source_details = pretty(&data);
                self.set_status(Status::Sources);
            }
            Action::Tools => {
                self.tool_report = Some((data, payload.extra));
                self.set_status(Status::Tools);
            }
            Action::Import => {
                self.review = payload.review;
                self.result_details.clear();
                self.verification_report = None;
                self.set_status(Status::Imported);
            }
        }
        Ok(())
    }

    fn validate_generated(&self, plan: &Value) -> Result<(), EngineError> {
        let scan = self
            .scan
            .as_ref()
            .ok_or_else(|| local_error("plan: expected current scan"))?;
        if plan["schema"] != "bme.plan/1"
            || plan["input"] != *self.scan_input.as_ref().unwrap_or(&Value::Null)
            || plan["source"]["alias"] != scan.alias
            || plan["allow_hold"] != false
            || plan["allow_diagnostic"] != false
            || plan["facts"].as_array().is_none_or(|f| !f.is_empty())
        {
            return Err(local_error(
                "plan: expected matching image/source and no hardware, hold, or diagnostic policy",
            ));
        }
        let eligible = scan
            .report
            .patches
            .iter()
            .filter(|p| p.selectable())
            .collect::<Vec<_>>();
        let requested = plan["requested"]
            .as_array()
            .ok_or_else(|| local_error("plan.requested: expected patch IDs"))?;
        let selected = plan["selected"]
            .as_array()
            .ok_or_else(|| local_error("plan.selected: expected patch IDs"))?;
        if requested.is_empty()
            || selected.is_empty()
            || requested.iter().any(|id| {
                !eligible
                    .iter()
                    .any(|p| id.as_str() == Some(p.qualified(&scan.alias).as_str()))
            })
            || selected
                .iter()
                .any(|id| !eligible.iter().any(|p| id.as_str() == Some(p.id.as_str())))
        {
            return Err(local_error(
                "plan selection: expected only scanned, independently plannable ordinary corrections from one source",
            ));
        }
        Ok(())
    }

    fn fail(&mut self, action: Action, error: EngineError) {
        if action == Action::Connect {
            self.connected = false;
            self.engine_attempted = true;
            self.engine_version = None;
        }
        self.outcome = match error.code.as_deref() {
            Some("PUBLISH_INCOMPLETE") => Outcome::PublicationIncomplete,
            Some("VERIFICATION_INCOMPLETE") => Outcome::VerificationIncomplete,
            _ if matches!(
                error.kind,
                ErrorKind::Interrupted | ErrorKind::Cancelled | ErrorKind::Timeout
            ) =>
            {
                Outcome::Interrupted
            }
            _ => Outcome::Failed,
        };
        if matches!(action, Action::Apply | Action::Plan | Action::Recommended) {
            self.review = None;
        }
        let message = error.to_string();
        let definite = matches!(
            error.kind,
            ErrorKind::Engine | ErrorKind::Configuration | ErrorKind::Launch
        );
        if action == Action::Apply && !definite {
            let fallback = format!(
                "Publication outcome unknown. Inspect output artifacts before retrying. {message}"
            );
            self.set_detailed_status(Status::PublicationUnknown, message, "", fallback);
        } else {
            self.set_detailed_status(Status::Failed, message.clone(), "", message);
        }
        self.log(&format!(
            "{}\n{}\n{}",
            error,
            error.details.as_ref().map(pretty).unwrap_or_default(),
            error.diagnostics
        ));
        self.result_details = match &error.details {
            Some(details) if self.outcome == Outcome::VerificationIncomplete => {
                verification_summary(details)
            }
            Some(details) => pretty(details),
            None => error.to_string(),
        };
        self.verification_report = if self.outcome == Outcome::VerificationIncomplete {
            error.details.clone()
        } else {
            None
        };
    }

    fn log(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        self.diagnostics.push_str(text);
        self.diagnostics.push('\n');
        if self.diagnostics.len() > LOG_LIMIT {
            let mut cut = self.diagnostics.len() - LOG_LIMIT;
            while !self.diagnostics.is_char_boundary(cut) {
                cut += 1;
            }
            self.diagnostics.drain(..cut);
        }
    }

    /// Install a copied imported review without granting permission to apply it.
    /// Example: `session.import_review(path)` preserves user files and allows verification only.
    pub fn import_review(&mut self, path: &Path) -> Result<(), String> {
        let completion = self.prepare_import(path).map_err(|e| e.to_string())?.run();
        self.finish(completion);
        if self.outcome == Outcome::Failed {
            return Err(self.status.clone());
        }
        Ok(())
    }

    /// Snapshot an import without reading the selected file on the event loop.
    /// Example: run `session.prepare_import(path)?.run()` on a worker.
    pub fn prepare_import(&mut self, path: &Path) -> Result<ImportJob, PreparationError> {
        if self.busy() {
            return Err(PreparationError::WaitImport);
        }
        let token = self.begin(Action::Import);
        Ok(ImportJob {
            path: path.into(),
            directory: self.directory.clone(),
            token,
            cancel: self.cancel.clone(),
        })
    }

    /// Choose where to build; any manifest and result text belong to the previous choice.
    /// Example: `session.set_output(Some(PathBuf::from("/tmp/new.bin")))`.
    pub fn set_output(&mut self, output: Option<PathBuf>) {
        self.output = output;
        self.manifest = None;
        self.result_details.clear();
        self.verification_report = None;
        self.outcome = Outcome::Idle;
    }

    /// Select a saved output and its conventional paired manifest for independent verification.
    /// Example: `session.open_output(PathBuf::from("/tmp/out.bin"))` uses `out.bin.manifest.json`.
    pub fn open_output(&mut self, output: PathBuf) {
        self.manifest = Some(manifest_path(&output));
        self.output = Some(output);
        self.outcome = Outcome::Idle;
        self.result_details.clear();
        self.verification_report = None;
    }

    /// Present the exact reviewed document and whether it is read-only.
    /// Example: imported reviews have a `Read-only imported plan` heading.
    pub fn review_text(&self) -> &str {
        self.review
            .as_ref()
            .map(|r| r.text.as_str())
            .unwrap_or_default()
    }
}

pub struct Job {
    token: (u64, u64, Action),
    request: Request,
    cancel: Arc<AtomicBool>,
    /// Pins the session directory until the child finishes.
    _directory: Arc<TempDir>,
    reviewed: Option<Arc<Review>>,
}
pub struct Completion {
    token: (u64, u64, Action),
    result: Result<Payload, EngineError>,
}
pub struct ImportJob {
    path: PathBuf,
    directory: Arc<TempDir>,
    token: (u64, u64, Action),
    cancel: Arc<AtomicBool>,
}

impl ImportJob {
    /// Copy and decode a regular plan file in the session's private directory.
    /// Example: `session.finish(import_job.run())` after a worker completes.
    pub fn run(self) -> Completion {
        let result = self.read();
        Completion {
            token: self.token,
            result,
        }
    }

    fn read(&self) -> Result<Payload, EngineError> {
        let bytes = read_plan(&self.path)?;
        let document: Value =
            serde_json::from_slice(&bytes).map_err(|e| local_error(format!("plan JSON: {e}")))?;
        if document["schema"] != "bme.plan/1" {
            return Err(local_error(format!(
                "plan schema: expected bme.plan/1 | received {}",
                document["schema"]
            )));
        }
        if self.cancel.load(Ordering::Relaxed) {
            let mut error = local_error("Plan import interrupted.");
            error.kind = ErrorKind::Cancelled;
            return Err(error);
        }
        let path = self
            .directory
            .path()
            .join(format!("import-{}.json", self.token.1));
        fs::write(&path, &bytes).map_err(|e| local_error(format!("plan copy: {e}")))?;
        Ok(Payload {
            reply: Reply {
                version: String::new(),
                data: Value::Null,
                diagnostics: String::new(),
            },
            extra: None,
            review: Some(Arc::new(Review::new(path, bytes, document, false))),
        })
    }
}

struct Payload {
    reply: Reply,
    extra: Option<Value>,
    review: Option<Arc<Review>>,
}

impl Job {
    /// Run blocking I/O off the UI thread, retaining the session directory until the child finishes.
    /// Example: `let completion = job.run(&engine); session.finish(completion);`.
    pub fn run(self, engine: &Engine) -> Completion {
        let result = self.execute(engine);
        Completion {
            token: self.token,
            result,
        }
    }

    fn execute(&self, engine: &Engine) -> Result<Payload, EngineError> {
        if matches!(self.token.2, Action::Apply | Action::Verify) {
            // These checks run before the engine starts, so a refusal is definite.
            let refuse = |error: EngineError| EngineError {
                kind: ErrorKind::Configuration,
                ..error
            };
            let review = self
                .reviewed
                .as_ref()
                .ok_or_else(|| refuse(local_error("review: expected retained plan")))?;
            if read_plan(&review.path).map_err(refuse)? != review.bytes {
                return Err(refuse(local_error(
                    "reviewed plan changed: expected exact reviewed bytes; generate and review again",
                )));
            }
        }
        let reply = if self.token.2 == Action::Connect {
            engine.handshake(&self.cancel)?
        } else {
            engine.run(&self.request, &self.cancel)?
        };
        let extra = match self.token.2 {
            Action::Scan => {
                let Request::Scan { source, .. } = &self.request else {
                    unreachable!("scan jobs carry a scan request");
                };
                let show = Request::CatalogShow {
                    source: source.clone(),
                };
                Some(engine.run(&show, &self.cancel)?.data)
            }
            Action::Tools => Some(engine.run(&Request::ToolsPaths, &self.cancel)?.data),
            _ => None,
        };
        let review = if let Request::Plan { output, .. } = &self.request {
            let bytes = read_plan(output)?;
            let document: Value = serde_json::from_slice(&bytes)
                .map_err(|e| local_error(format!("plan file: expected JSON | received {e}")))?;
            if document != reply.data["plan"] {
                return Err(local_error(
                    "plan file: expected the exact document returned by the engine",
                ));
            }
            Some(Arc::new(Review::new(output.clone(), bytes, document, true)))
        } else {
            None
        };
        Ok(Payload {
            reply,
            extra,
            review,
        })
    }
}

fn read_plan(path: &Path) -> Result<Vec<u8>, EngineError> {
    read_regular_file(path, PLAN_LIMIT)
        .map_err(|e| local_error(format!("plan {}: {e}", path.display())))
}

/// Read at most `limit` bytes from a regular file without blocking on a FIFO or device.
/// Example: `read_regular_file(Path::new("/tmp/plan.json"), 16 * 1024 * 1024)?`.
pub(crate) fn read_regular_file(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected at most {limit} bytes | received more"),
        ));
    }
    Ok(bytes)
}

/// Append the engine's manifest suffix without converting an OS path to UTF-8.
/// Example: `/tmp/new.bin` becomes `/tmp/new.bin.manifest.json`.
pub fn manifest_path(output: &Path) -> PathBuf {
    let mut path = output.as_os_str().to_os_string();
    path.push(".manifest.json");
    path.into()
}

/// Write bytes only to a new file, preserving any existing file.
/// Example: `write_new_file(Path::new("/tmp/new-report.txt"), b"details")?`.
pub fn write_new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(bytes)
}

fn local_error(message: impl Into<String>) -> EngineError {
    EngineError::new(ErrorKind::Protocol, message)
}

#[cfg(test)]
mod tests;
