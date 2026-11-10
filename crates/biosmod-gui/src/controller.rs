//! Session transitions and reviewed-plan ownership, independent of the windowing backend.

use crate::engine::{
    Engine, EngineContract, EngineError, ErrorKind, PatchDestination, PatchSelection, Reply,
    Request, ScannedSelection, append_diagnostics, run_pair, verification_complete,
};
use crate::model::{Scan, SourceReport, pretty};
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
    Preview,
    Export,
    Apply,
    Build,
    Verify,
    Sources,
    Tools,
    Import,
    ValidateRecipe,
}

impl Action {
    /// Describe real activity without inventing percentage progress.
    /// Example: `Action::Verify.label()` is `"Verifying output"`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Connect => "Checking engine",
            Self::Inspect => "Inspecting image",
            Self::Scan => "Scanning image",
            Self::Plan => "Generating plan",
            Self::Preview => "Previewing changes",
            Self::Export => "Exporting selection",
            Self::Apply | Self::Build => "Building patched copy",
            Self::Verify => "Verifying output",
            Self::Sources => "Reading sources",
            Self::Tools => "Checking tools",
            Self::Import => "Opening selection file",
            Self::ValidateRecipe => "Validating selection file",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Idle,
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
    RecipeMismatch,
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
            Self::Build => "Choose a new output path for the selected corrections.",
            Self::Output => "Choose a built output first.",
            Self::Plan => "Open or generate the matching plan first.",
            Self::Manifest => "Choose an output with its paired manifest first.",
            Self::WaitImport => "Wait for the active operation before importing a plan.",
            Self::RecipeMismatch => "The selection file must match the scan and use only corrections supported by the desktop.",
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
    Previewed,
    Published,
    Verified,
    Incomplete,
    Sources,
    Tools,
    Imported,
    RecipeValidated,
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
    /// English text for a status that needs no details, or `None` for one that does.
    /// Example: `Status::Ready.english()` is `Some("Engine ready. Choose an image to inspect.")`.
    fn english(self) -> Option<&'static str> {
        let text = match self {
            Self::Start => "Choose a firmware image to get started.",
            Self::Inputs => "Inputs changed. Inspect and scan to continue.",
            Self::ImportedInput => {
                "Scan the original image and matching catalog to validate the selection file."
            }
            Self::Selection => "Selection changed.",
            Self::Ready => "Engine ready. Choose an image to inspect.",
            Self::Inspected => "Image inspected. Scan a source for matching corrections.",
            Self::Scanned => "Scan complete. Select corrections or choose Recommended.",
            Self::Planned => "Review the resolved plan, then choose a new output and build a copy.",
            Self::Previewed => "Preview complete.",
            Self::Published => "Patched copy published. Independent verification is next.",
            Self::Verified => "Offline verification complete",
            Self::Incomplete => {
                "Verification incomplete. Review skipped checks and retry after addressing them."
            }
            Self::Sources => "Registered sources loaded. Firmware operations remain offline.",
            Self::Tools => "Tool diagnostics complete.",
            Self::Imported => "Selection file opened. Choose its original image and catalog.",
            Self::RecipeValidated => "Selection file validated. Choose an output and build a copy.",
            Self::Stopping => "Stopping operation…",
            Self::Back => "Select corrections and generate a new plan to continue.",
            Self::ClosingExport => "Finishing file export before closing…",
            Self::ClosingBuild => "Building the copy. Close the window after publication finishes.",
            Self::ClosingStop => "Stopping operation before closing…",
            Self::ExportNeedsPlan => "Select corrections or open a selection file to export.",
            Self::Activity(action) => action.label(),
            // These carry a detail or path; callers use set_detailed_status or set_notice.
            Self::Precondition(_)
            | Self::Failed
            | Self::PublicationUnknown
            | Self::Raw
            | Self::PreferencesError
            | Self::PreferencesNoLocation
            | Self::PreferencesProtected
            | Self::PickerError
            | Self::ExportingPlan
            | Self::ExportingDiagnostics
            | Self::PlanExported
            | Self::DiagnosticsExported
            | Self::PlanExists
            | Self::DiagnosticsExist
            | Self::PlanExportError
            | Self::DiagnosticsExportError => return None,
        };
        Some(text)
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
    pub path: Option<PathBuf>,
    pub bytes: Vec<u8>,
    pub document: Value,
    pub generated: bool,
    /// The pretty-printed document, prepared off the UI thread for every language.
    pub(crate) snapshot: slint::SharedString,
}

impl Review {
    /// Retain exact plan bytes and pretty-print the document on the worker.
    /// Example: `Review::new(path, bytes, document, false)` creates a read-only import.
    pub fn new(path: PathBuf, bytes: Vec<u8>, document: Value, generated: bool) -> Self {
        let snapshot = pretty(&document).into();
        Self {
            path: Some(path),
            bytes,
            document,
            generated,
            snapshot,
        }
    }

    fn from_document(document: Value) -> Self {
        let snapshot: slint::SharedString = pretty(&document).into();
        let bytes = snapshot.as_bytes().to_vec();
        Self {
            path: None,
            bytes,
            document,
            generated: true,
            snapshot,
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
    manifest_receipt: Option<String>,
    pub connected: bool,
    pub engine_version: Option<String>,
    pub(crate) engine_contract: Option<Arc<EngineContract>>,
    pub engine_attempted: bool,
    pub inspection: Option<Value>,
    pub scan: Option<SourceReport>,
    scan_input: Option<Value>,
    pub review: Option<Arc<Review>>,
    recipe_validated: bool,
    pub built_plan: Option<Arc<Review>>,
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
    pub tool_report: Option<Arc<(Value, Option<Value>)>>,
    pub diagnostics: String,
}

impl Session {
    /// Start an isolated session whose temporary files cannot overwrite user plans.
    /// Example: `let session = Session::new()?;`.
    pub fn new() -> std::io::Result<Self> {
        let mut session = Self {
            directory: Arc::new(tempfile::Builder::new().prefix("bme-gui-").tempdir()?),
            generation: 0,
            next_operation: 0,
            active: None,
            cancel: Arc::new(AtomicBool::new(false)),
            image: None,
            source: "official".into(),
            output: None,
            manifest: None,
            manifest_receipt: None,
            connected: false,
            engine_version: None,
            engine_contract: None,
            engine_attempted: false,
            inspection: None,
            scan: None,
            scan_input: None,
            review: None,
            recipe_validated: false,
            built_plan: None,
            outcome: Outcome::Idle,
            status: String::new(),
            status_kind: Status::Start,
            status_detail: String::new(),
            status_extra: String::new(),
            noticed_status: None,
            result_details: String::new(),
            verification_report: None,
            source_details: String::new(),
            tool_report: None,
            diagnostics: String::new(),
        };
        session.set_status(Status::Start);
        Ok(session)
    }

    /// Set a semantic message while retaining an English representation for callers.
    /// Example: `session.set_status(Status::Selection)` after selection changes.
    pub fn set_status(&mut self, status: Status) {
        let text = status.english();
        debug_assert!(
            text.is_some(),
            "set_status({status:?}): expected a status without details | use set_detailed_status"
        );
        self.noticed_status = None;
        self.status_kind = status;
        // Release builds name the variant instead of showing an empty status line.
        self.status = text.map_or_else(|| format!("{status:?}"), Into::into);
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
        self.recipe_validated = false;
        self.review = self.review.take().filter(|review| !review.generated);
        self.output = self.image.as_deref().and_then(default_patch_output);
        self.manifest = None;
        self.manifest_receipt = None;
        self.built_plan = None;
        self.result_details.clear();
        self.verification_report = None;
        self.outcome = Outcome::Idle;
        self.set_status(Status::Inputs);
    }

    /// Change the original image, retaining only imported artifacts for re-verification.
    /// Example: selecting an imported plan's original image never grants build permission.
    pub fn change_image(&mut self, image: Option<PathBuf>) {
        let keep = self.review.as_ref().is_none_or(|review| !review.generated);
        let imported = self.review.take().filter(|_| keep);
        let output = self.output.clone();
        let manifest = self
            .manifest
            .clone()
            .filter(|_| self.manifest_receipt.is_none());
        self.invalidate();
        self.image = image;
        self.output = self.image.as_deref().and_then(default_patch_output);
        if keep && manifest.is_some() {
            self.output = output;
            self.manifest = manifest;
        }
        if imported.is_some() {
            self.review = imported;
            self.set_status(Status::ImportedInput);
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
        self.active
            .is_some_and(|a| matches!(a.2, Action::Apply | Action::Build | Action::Export))
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

    /// Check whether the desktop can select every patch recommended by the current scan.
    /// Example: an empty recommendation list disables the Recommended button.
    pub fn can_recommend(&self) -> bool {
        self.connected
            && !self.busy()
            && self.scan.as_ref().is_some_and(|scan| {
                !scan.report.recommended.is_empty()
                    && scan.report.recommended.iter().all(|id| {
                        scan.report
                            .patches
                            .iter()
                            .any(|patch| &patch.id == id && patch.selectable())
                    })
            })
    }

    /// Select the exact recommendation from the current scan without starting a worker.
    /// Example: call `session.select_recommended()` from the Recommended button.
    pub fn select_recommended(&mut self) {
        if !self.can_recommend() {
            return;
        }
        let report = &mut self.scan.as_mut().expect("current scan").report;
        for patch in &mut report.patches {
            patch.selected = report.recommended.contains(&patch.id);
        }
        self.clear_results();
        self.set_status(Status::Selection);
    }

    /// Drop the review, manifest, and result text after any input that makes them stale.
    /// Example: `session.clear_results()` before offering a new output path.
    pub fn clear_results(&mut self) {
        self.review = None;
        self.recipe_validated = false;
        self.manifest = None;
        self.manifest_receipt = None;
        self.built_plan = None;
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

    /// Check whether the displayed selection can build directly to a new output.
    /// Example: selecting an eligible scan row enables Build for the default output.
    pub fn can_build(&self) -> bool {
        self.connected
            && !self.busy()
            && self.image.is_some()
            && self.output.is_some()
            && self.manifest.is_none()
            && if self.imported_recipe().is_some() {
                self.recipe_validated
            } else {
                self.scan.as_ref().is_some_and(|scan| {
                    scan.report
                        .patches
                        .iter()
                        .any(|patch| patch.selected && patch.selectable())
                })
            }
    }

    /// Return the imported selection snapshot when exact replay is active.
    /// Example: after opening a recipe, `session.imported_recipe()` exposes its retained bytes.
    pub fn imported_recipe(&self) -> Option<&Arc<Review>> {
        self.review.as_ref().filter(|review| !review.generated)
    }

    fn scanned_selection(&self) -> Result<ScannedSelection, PreparationError> {
        let scan = self.scan.as_ref().ok_or(PreparationError::Scan)?;
        let input_sha256 = self
            .scan_input
            .as_ref()
            .and_then(|input| sha256_string(&input["sha256"]))
            .ok_or(PreparationError::Scan)?;
        let ids: Vec<_> = scan
            .report
            .patches
            .iter()
            .filter(|patch| patch.selected && patch.selectable())
            .map(|patch| patch.qualified(&scan.alias))
            .collect();
        if ids.is_empty() {
            return Err(PreparationError::Selection);
        }
        Ok(ScannedSelection {
            source: self.source.clone(),
            ids,
            input_sha256: input_sha256.into(),
            source_sha256: scan.snapshot_sha256.clone(),
        })
    }

    /// Prepare one operation with immutable paths and generation tags.
    /// Example: pass `session.prepare(Action::Scan)?` to a worker's `Job::run`.
    pub fn prepare(&mut self, action: Action) -> Result<Job, PreparationError> {
        self.prepare_operation(action, None)
    }

    /// Prepare a guarded export of the IDs currently selected in the findings.
    /// Example: run `session.prepare_export("selection.json".into())?` on a worker.
    pub fn prepare_export(&mut self, output: PathBuf) -> Result<Job, PreparationError> {
        self.prepare_operation(Action::Export, Some(output))
    }

    fn prepare_operation(
        &mut self,
        action: Action,
        export_path: Option<PathBuf>,
    ) -> Result<Job, PreparationError> {
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
            Action::Plan => {
                let scan = self.scan.as_ref().ok_or(PreparationError::Scan)?;
                let selection = scan
                    .report
                    .patches
                    .iter()
                    .filter(|p| p.selected && p.selectable())
                    .map(|p| p.qualified(&scan.alias))
                    .collect::<Vec<_>>();
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
                    plan: self
                        .review
                        .as_ref()
                        .and_then(|review| review.path.clone())
                        .ok_or(PreparationError::Plan)?,
                    output: self.output.clone().unwrap(),
                }
            }
            Action::Preview => Request::Build {
                image: image()?,
                selection: PatchSelection::Scanned(self.scanned_selection()?),
                destination: PatchDestination::Preview,
            },
            Action::Export => Request::Export {
                image: image()?,
                selection: self.scanned_selection()?,
                output: export_path.ok_or(PreparationError::Output)?,
            },
            Action::ValidateRecipe => {
                let recipe = self.imported_recipe().ok_or(PreparationError::Plan)?;
                let image = image()?;
                if self.scan.is_none() {
                    return Err(PreparationError::Scan);
                }
                self.validate_generated(&recipe.document)
                    .map_err(|_| PreparationError::RecipeMismatch)?;
                Request::Build {
                    image,
                    selection: PatchSelection::Recipe(
                        recipe.path.clone().ok_or(PreparationError::Plan)?,
                    ),
                    destination: PatchDestination::Preview,
                }
            }
            Action::Build => {
                let selection = if let Some(recipe) = self.imported_recipe() {
                    PatchSelection::Recipe(recipe.path.clone().ok_or(PreparationError::Plan)?)
                } else {
                    PatchSelection::Scanned(self.scanned_selection()?)
                };
                if !self.can_build() {
                    return Err(PreparationError::Build);
                }
                Request::Build {
                    image: image()?,
                    selection,
                    destination: PatchDestination::Publish(
                        self.output.clone().expect("new output"),
                    ),
                }
            }
            Action::Verify => {
                let output = self.output.clone().ok_or(PreparationError::Output)?;
                if self.manifest.as_ref() != Some(&manifest_path(&output)) {
                    return Err(PreparationError::Manifest);
                }
                Request::VerifyResult {
                    input: image()?,
                    manifest: manifest_path(&output),
                    output,
                    recipe: self
                        .review
                        .as_ref()
                        .filter(|_| self.manifest_receipt.is_none())
                        .and_then(|review| review.path.clone()),
                }
            }
            Action::Sources => Request::CatalogList,
            Action::Tools => Request::ToolsDoctor,
        };
        let token = self.begin(action);
        if matches!(action, Action::Scan | Action::ValidateRecipe) {
            self.recipe_validated = false;
        }
        if action == Action::Plan {
            self.review = None;
        }
        Ok(Job {
            token,
            request,
            cancel: self.cancel.clone(),
            _directory: self.directory.clone(),
            reviewed: self.review.clone(),
            contract: self.engine_contract.clone(),
        })
    }

    /// Claim the single operation slot with a fresh cancel flag.
    /// Example: `let token = self.begin(Action::Scan);` before building a `Job`.
    fn begin(&mut self, action: Action) -> (u64, u64, Action) {
        self.next_operation += 1;
        let token = (self.generation, self.next_operation, action);
        self.active = Some(token);
        self.cancel = Arc::new(AtomicBool::new(false));
        self.outcome = Outcome::Idle;
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
                self.engine_contract = Some(Arc::new(EngineContract::from_capabilities(&data)?));
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
                if sha256_string(&scan.input["sha256"]).is_none()
                    || !valid_sha256(&scan.sources[0].snapshot_sha256)
                {
                    return Err(local_error(
                        "scan: expected lowercase SHA-256 digests for the input and source",
                    ));
                }
                self.scan_input = Some(scan.input);
                self.scan = scan.sources.pop();
                self.review = self.review.take().filter(|review| !review.generated);
                self.manifest = None;
                self.manifest_receipt = None;
                self.built_plan = None;
                self.source_details = payload.extra.map(|v| pretty(&v)).unwrap_or_default();
                self.set_status(Status::Scanned);
            }
            Action::Plan => {
                let review = payload
                    .review
                    .ok_or_else(|| local_error("plan: expected retained review bytes"))?;
                self.validate_generated(&review.document)?;
                self.review = Some(review);
                self.manifest = None;
                self.manifest_receipt = None;
                self.built_plan = None;
                self.set_status(Status::Planned);
            }
            Action::Preview => {
                let plan = self.validate_selection_response(&data, &payload.reply.version)?;
                if data["dry_run"] != true {
                    return Err(local_error("preview: expected a dry-run result"));
                }
                self.review = Some(Arc::new(Review::from_document(plan.clone())));
                self.set_status(Status::Previewed);
            }
            Action::Export => {
                self.validate_selection_response(&data, &payload.reply.version)?;
                let path = data["patch_file"]
                    .as_str()
                    .ok_or_else(|| local_error("export: expected a selection file path"))?;
                self.set_detailed_status(
                    Status::PlanExported,
                    path,
                    "",
                    format!("Selection exported to {path}"),
                );
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
            Action::ValidateRecipe => {
                if data["dry_run"] != true {
                    return Err(local_error("selection file: expected a dry-run result"));
                }
                self.validate_replay_response(&data["plan"], &data, &payload.reply.version)?;
                self.recipe_validated = true;
                self.set_status(Status::RecipeValidated);
            }
            Action::Build => {
                let plan = &data["manifest"]["plan"];
                let imported = self.imported_recipe().cloned();
                if imported.is_some() {
                    self.validate_replay_response(plan, &data, &payload.reply.version)?;
                } else {
                    self.validate_direct_response(plan, &data, &payload.reply.version)?;
                }
                let output = self
                    .output
                    .as_deref()
                    .ok_or_else(|| local_error("patch: expected output path"))?;
                let manifest = manifest_path(output);
                if data["manifest"]["schema"] != "bme.manifest/1"
                    || data["output"] != output.to_string_lossy().as_ref()
                    || data["manifest_file"] != manifest.to_string_lossy().as_ref()
                {
                    return Err(local_error(
                        "patch receipt: expected the connected engine, scanned selection and requested output paths",
                    ));
                }
                let digest = sha256_string(&data["manifest_sha256"]).ok_or_else(|| {
                    local_error("patch receipt: expected a lowercase manifest SHA-256")
                })?;
                self.manifest_receipt = Some(digest.into());
                self.built_plan =
                    Some(imported.unwrap_or_else(|| Arc::new(Review::from_document(plan.clone()))));
                self.manifest = Some(manifest);
                self.result_details = pretty(&data);
                self.verification_report = None;
                self.set_status(Status::Published);
            }
            Action::Verify => {
                let contract = self.engine_contract.as_deref().ok_or_else(|| {
                    local_error(
                        "verification: expected an engine contract from the active connection",
                    )
                })?;
                if let Some(expected) = &self.manifest_receipt
                    && (data["manifest_sha256"] != *expected
                        || self.engine_version.as_deref() != Some(payload.reply.version.as_str()))
                {
                    return Err(local_error(format!(
                        "verification receipt: expected manifest SHA-256 {expected} from the connected engine | received {} from version {}",
                        data["manifest_sha256"], payload.reply.version
                    )));
                }
                let complete = verification_complete(&data, contract)?;
                self.outcome = if complete {
                    Outcome::Verified
                } else {
                    Outcome::VerificationIncomplete
                };
                self.set_status(if complete {
                    Status::Verified
                } else {
                    Status::Incomplete
                });
                self.log(&pretty(&data));
                // The window renders the report itself in the selected language.
                self.result_details.clear();
                self.verification_report = Some(data);
            }
            Action::Sources => {
                self.source_details = pretty(&data);
                self.set_status(Status::Sources);
            }
            Action::Tools => {
                self.tool_report = Some(Arc::new((data, payload.extra)));
                self.set_status(Status::Tools);
            }
            Action::Import => {
                if self.manifest_receipt.take().is_some() {
                    self.manifest = None;
                    self.built_plan = None;
                }
                self.review = payload.review;
                self.recipe_validated = false;
                self.result_details.clear();
                self.verification_report = None;
                self.set_status(Status::Imported);
            }
        }
        Ok(())
    }

    fn validate_selection_response<'a>(
        &self,
        data: &'a Value,
        version: &str,
    ) -> Result<&'a Value, EngineError> {
        let plan = &data["plan"];
        self.validate_direct_response(plan, data, version)?;
        Ok(plan)
    }

    fn validate_direct_response(
        &self,
        plan: &Value,
        data: &Value,
        version: &str,
    ) -> Result<(), EngineError> {
        self.validate_generated(plan)?;
        let selection = self
            .scanned_selection()
            .map_err(|error| local_error(error.to_string()))?;
        if self.engine_version.as_deref() != Some(version)
            || plan["engine"]["version"] != version
            || data["source_snapshot_sha256"] != selection.source_sha256
            || plan["requested"] != serde_json::json!(selection.ids)
        {
            return Err(local_error(
                "patch selection: expected the connected engine and exact scanned selection",
            ));
        }
        Ok(())
    }

    fn validate_replay_response(
        &self,
        plan: &Value,
        data: &Value,
        version: &str,
    ) -> Result<(), EngineError> {
        self.validate_generated(plan)?;
        let recipe = self
            .imported_recipe()
            .ok_or_else(|| local_error("expected retained selection file"))?;
        let scan = self.scan.as_ref().expect("validated scan");
        if self.engine_version.as_deref() != Some(version)
            || plan["engine"]["version"] != version
            || data["source_snapshot_sha256"] != scan.snapshot_sha256
            || *plan != recipe.document
        {
            return Err(local_error(
                "selection file: expected exact replay against the current scan",
            ));
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
            self.engine_contract = None;
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
        if matches!(action, Action::Apply | Action::Plan) {
            self.review = None;
        }
        if matches!(action, Action::Build | Action::Preview | Action::Export)
            && error.code.as_deref() == Some("PLAN_INPUT_CHANGED")
        {
            self.scan = None;
            self.scan_input = None;
            let recipe = self.imported_recipe().cloned();
            self.clear_results();
            self.review = recipe;
            self.outcome = Outcome::Failed;
        }
        let message = error.to_string();
        let definite = matches!(
            error.kind,
            ErrorKind::Engine | ErrorKind::Configuration | ErrorKind::Launch
        );
        if matches!(action, Action::Apply | Action::Build) && !definite {
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
            Some(_) if self.outcome == Outcome::VerificationIncomplete => String::new(),
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
        self.manifest_receipt = None;
        self.built_plan = None;
        self.result_details.clear();
        self.verification_report = None;
        self.outcome = Outcome::Idle;
    }

    /// Select a saved output and its conventional paired manifest for independent verification.
    /// Example: `session.open_output(PathBuf::from("/tmp/out.bin"))` uses `out.bin.manifest.json`.
    pub fn open_output(&mut self, output: PathBuf) {
        self.manifest_receipt = None;
        self.built_plan = None;
        self.manifest = Some(manifest_path(&output));
        self.output = Some(output);
        self.outcome = Outcome::Idle;
        self.result_details.clear();
        self.verification_report = None;
    }
}

pub struct Job {
    token: (u64, u64, Action),
    request: Request,
    cancel: Arc<AtomicBool>,
    /// Pins the session directory until the child finishes.
    _directory: Arc<TempDir>,
    reviewed: Option<Arc<Review>>,
    contract: Option<Arc<EngineContract>>,
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
        if self.token.2 == Action::Apply
            || matches!(
                &self.request,
                Request::VerifyResult {
                    recipe: Some(_),
                    ..
                } | Request::Build {
                    selection: PatchSelection::Recipe(_),
                    ..
                }
            )
        {
            // These checks run before the engine starts, so a refusal is definite.
            let refuse = |error: EngineError| EngineError {
                kind: ErrorKind::Configuration,
                ..error
            };
            let review = self
                .reviewed
                .as_ref()
                .ok_or_else(|| refuse(local_error("review: expected retained plan")))?;
            let path = review
                .path
                .as_deref()
                .ok_or_else(|| refuse(local_error("expected a private recipe snapshot")))?;
            if read_plan(path).map_err(refuse)? != review.bytes {
                return Err(refuse(local_error(
                    "reviewed plan changed: expected exact reviewed bytes; generate and review again",
                )));
            }
        }
        let bound_engine;
        let engine = if self.token.2 == Action::Connect {
            engine
        } else {
            let contract = self.contract.clone().ok_or_else(|| {
                local_error("engine: expected a contract from the active connection")
            })?;
            bound_engine = engine.clone().with_contract(contract);
            &bound_engine
        };
        let (reply, extra) = match self.token.2 {
            Action::Connect => (engine.handshake(&self.cancel)?, None),
            Action::Scan => {
                let Request::Scan { source, .. } = &self.request else {
                    unreachable!("scan jobs carry a scan request");
                };
                let show = Request::CatalogShow {
                    source: source.clone(),
                };
                let (mut scan, catalog) = run_pair(
                    &self.cancel,
                    |cancel| engine.run(&self.request, cancel),
                    |cancel| engine.run(&show, cancel),
                )?;
                if scan.version != catalog.version {
                    let mut error = local_error(format!(
                        "scan: expected matching scan and catalog versions | received {} and {}",
                        scan.version, catalog.version
                    ));
                    append_diagnostics(&mut error.diagnostics, &scan.diagnostics);
                    append_diagnostics(&mut error.diagnostics, &catalog.diagnostics);
                    return Err(error);
                }
                append_diagnostics(&mut scan.diagnostics, &catalog.diagnostics);
                (scan, Some(catalog.data))
            }
            Action::Tools => {
                let mut doctor = run_doctor(engine, &self.request, &self.cancel)?;
                let paths =
                    engine
                        .run(&Request::ToolsPaths, &self.cancel)
                        .map_err(|mut error| {
                            append_diagnostics(&mut error.diagnostics, &doctor.diagnostics);
                            error
                        })?;
                if doctor.version != paths.version {
                    let mut error = local_error(format!(
                        "tools: expected matching doctor and paths versions | received {} and {}",
                        doctor.version, paths.version
                    ));
                    append_diagnostics(&mut error.diagnostics, &doctor.diagnostics);
                    append_diagnostics(&mut error.diagnostics, &paths.diagnostics);
                    return Err(error);
                }
                append_diagnostics(&mut doctor.diagnostics, &paths.diagnostics);
                (doctor, Some(paths.data))
            }
            _ => (engine.run(&self.request, &self.cancel)?, None),
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

/// Retain a controlled missing-tools doctor report without accepting malformed errors.
fn run_doctor(
    engine: &Engine,
    request: &Request,
    cancel: &AtomicBool,
) -> Result<Reply, EngineError> {
    match engine.run(request, cancel) {
        Ok(reply) => Ok(reply),
        Err(error)
            if error.kind == ErrorKind::Engine
                && error.code.as_deref() == Some("TOOL_UNAVAILABLE") =>
        {
            let details = error.details.as_ref();
            let home = details.and_then(|value| value.get("ghidra_home"));
            let checks = details.and_then(|value| value.get("checks"));
            let valid_home =
                home.is_some_and(|home| home["path"].is_string() && home["origin"].is_string());
            let valid_checks = checks.and_then(Value::as_array).is_some_and(|checks| {
                !checks.is_empty()
                    && checks.iter().all(|check| {
                        check["check"].is_string()
                            && check["ok"].is_boolean()
                            && check["detail"].is_string()
                    })
                    && checks.iter().any(|check| check["ok"] == false)
            });
            if !valid_home || !valid_checks || error.version.is_none() {
                return Err(EngineError {
                    kind: ErrorKind::Protocol,
                    message: format!(
                        "tools doctor: expected a structured failed-check report | received {}",
                        details.unwrap_or(&Value::Null)
                    ),
                    ..error
                });
            }
            let mut report = details.cloned().unwrap();
            report["error"] =
                serde_json::json!({"code":"TOOL_UNAVAILABLE", "message":error.message});
            Ok(Reply {
                version: *error.version.unwrap(),
                data: report,
                diagnostics: error.diagnostics,
            })
        }
        Err(error) => Err(error),
    }
}

fn sha256_string(value: &Value) -> Option<&str> {
    value.as_str().filter(|digest| valid_sha256(digest))
}

fn valid_sha256(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn default_patch_output(input: &Path) -> Option<PathBuf> {
    let mut name = input.file_stem()?.to_os_string();
    name.push(".patched");
    if let Some(extension) = input.extension() {
        name.push(".");
        name.push(extension);
    }
    Some(input.with_file_name(name))
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
