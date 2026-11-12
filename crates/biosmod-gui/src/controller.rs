//! Session transitions and reviewed-plan ownership, independent of the windowing backend.

use crate::engine::{
    Engine, EngineContract, EngineError, ErrorKind, LocatableTool, PatchDestination,
    PatchSelection, Reply, Request, ScannedSelection, append_diagnostics, run_pair,
    verification_complete,
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
    Preview,
    Export,
    Build,
    Verify,
    Sources,
    Tools,
    /// Save or forget a tool location.
    ToolChange,
    /// Download and install the pinned Ghidra.
    ToolInstall,
    Import,
    ValidateRecipe,
    FlashDoctor,
    FlashProbe,
    FlashBackup,
    FlashCheck,
    FlashWrite,
}

impl Action {
    /// Describe real activity without inventing percentage progress.
    /// Example: `Action::Verify.label()` is `"Verifying output"`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Connect => "Checking engine",
            Self::Inspect => "Inspecting image",
            Self::Scan => "Scanning image",
            Self::Preview => "Previewing changes",
            Self::Export => "Exporting selection",
            Self::Build => "Building patched copy",
            Self::Verify => "Verifying output",
            Self::Sources => "Reading sources",
            Self::Tools => "Checking tools",
            Self::ToolChange => "Updating tool location",
            Self::ToolInstall => "Installing Ghidra",
            Self::Import => "Opening selection file",
            Self::ValidateRecipe => "Validating selection file",
            Self::FlashDoctor => "Diagnosing the system",
            Self::FlashProbe => "Looking for the flash chip",
            Self::FlashBackup => "Backing up the flash chip",
            Self::FlashCheck => "Checking the image against the chip",
            Self::FlashWrite => "Writing the flash chip. Do not power off",
        }
    }

    /// Whether the action talks to the flash chip or diagnoses access to it.
    /// Example: `Action::FlashBackup.is_flash()` is `true`.
    pub fn is_flash(self) -> bool {
        matches!(
            self,
            Self::FlashDoctor
                | Self::FlashProbe
                | Self::FlashBackup
                | Self::FlashCheck
                | Self::FlashWrite
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Idle,
    Failed,
    Interrupted,
    PublicationIncomplete,
    PublicationUnknown,
    VerificationIncomplete,
    VerificationFailed,
    Verified,
    /// The chip was written and read back.
    ChipWritten,
    /// A chip write ended without a definite result.
    ChipWriteUnknown,
}

/// A change to the tools on the Tools page, run by `Action::ToolChange` or `Action::ToolInstall`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolChange {
    /// Use an existing Ghidra directory or flashrom executable.
    Choose { tool: LocatableTool, path: PathBuf },
    /// Forget a saved location.
    Reset { tool: LocatableTool },
    /// Download and install the pinned Ghidra.
    InstallGhidra,
}

impl ToolChange {
    /// The action that performs this change.
    ///
    /// Example: `ToolChange::InstallGhidra.action()` is `Action::ToolInstall`.
    pub fn action(&self) -> Action {
        match self {
            ToolChange::InstallGhidra => Action::ToolInstall,
            _ => Action::ToolChange,
        }
    }
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
    FlashUnsupported,
    /// The engine predates `tools status`, `tools set` and `tools unset`.
    ToolsUnsupported,
    Programmer,
    FlashBackup,
    FlashImage,
    FlashCheck,
    FlashAcknowledge,
}

impl std::fmt::Display for PreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Busy => "An operation is already running.",
            Self::Engine => "Connect a compatible bme engine first.",
            Self::Image => "Choose an original image first.",
            Self::ImportPath => "Choose a selection file to open.",
            Self::Scan => "Scan the original image and selected catalog first.",
            Self::Selection => "Select an eligible correction first.",
            Self::Build => "Choose a new output path for the selected corrections.",
            Self::Output => "Choose a built output first.",
            Self::Plan => "Open the matching selection file first.",
            Self::Manifest => "Choose an output with its paired manifest first.",
            Self::WaitImport => "Wait for the active operation before opening a selection file.",
            Self::RecipeMismatch => "The selection file must match the scan and use only corrections supported by the desktop.",
            Self::FlashUnsupported => "The connected bme engine has no flash chip commands. Use the bundled engine.",
            Self::ToolsUnsupported => "The connected bme engine cannot list or change tools. Use the bundled engine.",
            Self::Programmer => "Enter a flashrom programmer such as internal or ch341a_spi.",
            Self::FlashBackup => "Choose a backup file first.",
            Self::FlashImage => "Choose the image to write first.",
            Self::FlashCheck => "Check the image against the chip first.",
            Self::FlashAcknowledge => "Confirm that you can recover the board first.",
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
    Previewed,
    Published,
    Verified,
    VerifiedOpened,
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
    FlashDiagnosed,
    FlashProbed,
    FlashBackedUp,
    FlashChecked,
    FlashWritten,
    FlashOutcomeUnknown,
    ClosingFlash,
    FlashInputs,
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
            Self::Previewed => "Preview complete.",
            Self::Published => "Patched copy published. Independent verification is next.",
            Self::Verified => "Offline verification complete",
            Self::VerifiedOpened => "Verified against the opened manifest",
            Self::Incomplete => {
                "Verification incomplete. Review skipped checks and retry after addressing them."
            }
            Self::Sources => "Registered sources loaded. Firmware operations remain offline.",
            Self::Tools => "Tool diagnostics complete.",
            Self::Imported => "Selection file opened. Choose its original image and catalog.",
            Self::RecipeValidated => "Selection file validated. Choose an output and build a copy.",
            Self::Stopping => "Stopping operation…",
            Self::Back => "Select corrections to build a patched copy.",
            Self::ClosingExport => "Finishing file export before closing…",
            Self::ClosingBuild => "Building the copy. Close the window after publication finishes.",
            Self::ClosingStop => "Stopping operation before closing…",
            Self::ExportNeedsPlan => "Select corrections or open a selection file to export.",
            Self::FlashDiagnosed => "System diagnosis complete.",
            Self::FlashProbed => "Flash chip found.",
            Self::FlashChecked => {
                "The backup matches the chip. Review what will be written before flashing."
            }
            Self::FlashWritten => {
                "Chip written and read back. Power-cycle the board to start the new firmware."
            }
            Self::ClosingFlash => {
                "Working on the flash chip. Close the window after the operation finishes."
            }
            Self::FlashInputs => "Flash inputs changed. Check the image against the chip again.",
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
            | Self::FlashBackedUp
            | Self::FlashOutcomeUnknown
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
    pub origin: SelectionOrigin,
    pub bytes: Vec<u8>,
    pub document: Value,
    /// The pretty-printed document, prepared off the UI thread for every language.
    pub(crate) snapshot: slint::SharedString,
}

/// Provenance of the selection document shown or exported by the desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionOrigin {
    Imported(PathBuf),
    Preview,
    Build,
}

impl Review {
    /// Keep exact imported bytes and the private path used for replay.
    /// Example: `Review::imported(private_path, bytes, document)` prepares a snapshot for display.
    pub fn imported(path: PathBuf, bytes: Vec<u8>, document: Value) -> Self {
        let snapshot = pretty(&document).into();
        Self {
            origin: SelectionOrigin::Imported(path),
            bytes,
            document,
            snapshot,
        }
    }

    /// Present a dry-run document without creating a backing file.
    /// Example: `Review::preview(reply.data["plan"].clone())` renders an engine preview.
    pub fn preview(document: Value) -> Self {
        Self::from_document(document, SelectionOrigin::Preview)
    }

    fn from_document(document: Value, origin: SelectionOrigin) -> Self {
        let snapshot: slint::SharedString = pretty(&document).into();
        let bytes = snapshot.as_bytes().to_vec();
        Self {
            origin,
            bytes,
            document,
            snapshot,
        }
    }

    /// Return the private path only for an imported snapshot.
    /// Example: `review.recipe_path()` is absent for dry-run and build documents.
    pub fn recipe_path(&self) -> Option<&Path> {
        match &self.origin {
            SelectionOrigin::Imported(path) => Some(path.as_path()),
            _ => None,
        }
    }
}

/// The last flash chip result, kept as engine data for presentation in any language.
#[derive(Debug, Clone, PartialEq)]
pub enum FlashReport {
    Doctor(Value),
    Probe(Value),
    Backup(Value),
    Check(Value),
    Written(Value),
    /// A failed operation: the engine message and its structured details.
    Failure(String, Option<Value>),
}

/// The inputs a dry run approved; a write needs exactly these again.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckedWrite {
    programmer: String,
    image: PathBuf,
    backup: PathBuf,
    whole_chip: bool,
    image_sha256: String,
}

/// Flash chip inputs and results. They are independent of the patch workflow.
#[derive(Debug, Clone)]
pub struct FlashState {
    /// Whether the connected engine advertises the flash commands.
    pub supported: bool,
    pub programmer: String,
    /// Ask polkit for administrator rights before touching the chip.
    pub elevate: bool,
    pub backup: Option<PathBuf>,
    pub image: Option<PathBuf>,
    pub whole_chip: bool,
    /// The user stated they can recover a board that no longer starts.
    pub acknowledged: bool,
    pub report: Option<Arc<FlashReport>>,
    checked: Option<CheckedWrite>,
}

impl Default for FlashState {
    fn default() -> Self {
        Self {
            supported: false,
            programmer: "internal".into(),
            elevate: true,
            backup: None,
            image: None,
            whole_chip: false,
            acknowledged: false,
            report: None,
            checked: None,
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
    pub(crate) scan_input: Option<Value>,
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
    /// The `tools status` report shown on the Tools page.
    pub tool_report: Option<Arc<Value>>,
    /// The change the next `Action::ToolChange` or `Action::ToolInstall` performs.
    pending_tool_change: Option<ToolChange>,
    /// The engine advertises `tools_workflow`: it can report and change tools.
    pub tools_supported: bool,
    pub diagnostics: String,
    pub flash: FlashState,
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
            pending_tool_change: None,
            tools_supported: false,
            diagnostics: String::new(),
            flash: FlashState::default(),
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
        self.review = self
            .review
            .take()
            .filter(|review| review.recipe_path().is_some());
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
        let keep = self
            .review
            .as_ref()
            .is_none_or(|review| review.recipe_path().is_some());
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
            .is_some_and(|a| matches!(a.2, Action::Build | Action::Export))
            || self.flashing()
    }

    /// A chip operation that cannot be stopped: a backup, a check or a write, and
    /// anything running as root, which this process may not signal.
    /// Example: hide Cancel while `session.flashing()`.
    pub fn flashing(&self) -> bool {
        self.active.is_some_and(|a| match a.2 {
            Action::FlashBackup | Action::FlashCheck | Action::FlashWrite => true,
            Action::FlashProbe => self.flash.elevate,
            _ => false,
        })
    }

    /// Queue the tool change the next `prepare(change.action())` performs.
    /// Example: `session.queue_tool_change(ToolChange::InstallGhidra)`.
    pub fn queue_tool_change(&mut self, change: ToolChange) {
        self.pending_tool_change = Some(change);
    }

    /// Drop a completed write check when the queued change picks another flashrom.
    ///
    /// The write must run the flashrom its dry run checked, so a new location needs a new check.
    /// Example: queue `ToolChange::Reset { tool: LocatableTool::Flashrom }`, then prepare it.
    fn drop_check_for_flashrom_change(&mut self) {
        let flashrom = matches!(
            self.pending_tool_change,
            Some(
                ToolChange::Choose {
                    tool: LocatableTool::Flashrom,
                    ..
                } | ToolChange::Reset {
                    tool: LocatableTool::Flashrom
                }
            )
        );
        if flashrom && self.flash.checked.take().is_some() {
            self.flash.acknowledged = false;
        }
    }

    /// Change one flash input; a completed check no longer covers the new inputs.
    /// Example: `session.edit_flash(|flash| flash.programmer = "ch341a_spi".into())`.
    pub fn edit_flash(&mut self, change: impl FnOnce(&mut FlashState)) {
        if self.busy() {
            return;
        }
        let before = self.flash_inputs();
        change(&mut self.flash);
        if before != self.flash_inputs() && self.flash.checked.take().is_some() {
            self.flash.acknowledged = false;
            self.outcome = Outcome::Idle;
            self.set_status(Status::FlashInputs);
        }
    }

    fn flash_inputs(&self) -> (String, Option<PathBuf>, Option<PathBuf>, bool) {
        (
            self.flash.programmer.clone(),
            self.flash.image.clone(),
            self.flash.backup.clone(),
            self.flash.whole_chip,
        )
    }

    /// Whether a dry run approved the current flash inputs.
    /// Example: `session.flash_checked()` turns true after `Action::FlashCheck` succeeds.
    pub fn flash_checked(&self) -> bool {
        self.flash.checked.is_some()
    }

    /// Whether every guard for writing the chip holds.
    /// Example: enable the Flash button only while `session.can_flash_write()`.
    pub fn can_flash_write(&self) -> bool {
        self.connected
            && self.flash.supported
            && !self.busy()
            && self.flash.acknowledged
            && self.flash_checked()
    }

    fn flash_request(&self, action: Action) -> Result<Request, PreparationError> {
        let flash = &self.flash;
        if !flash.supported {
            return Err(PreparationError::FlashUnsupported);
        }
        let programmer = flash.programmer.trim().to_owned();
        if programmer.is_empty() {
            return Err(PreparationError::Programmer);
        }
        let elevate = flash.elevate;
        let backup = || flash.backup.clone().ok_or(PreparationError::FlashBackup);
        let image = || flash.image.clone().ok_or(PreparationError::FlashImage);
        Ok(match action {
            Action::FlashDoctor => Request::FlashDoctor { programmer },
            Action::FlashProbe => Request::FlashProbe {
                programmer,
                elevate,
            },
            Action::FlashBackup => Request::FlashBackup {
                programmer,
                output: backup()?,
                elevate,
            },
            Action::FlashCheck => Request::FlashWrite {
                programmer,
                image: image()?,
                backup: backup()?,
                whole_chip: flash.whole_chip,
                confirm: None,
                elevate,
            },
            Action::FlashWrite => {
                let checked = flash.checked.as_ref().ok_or(PreparationError::FlashCheck)?;
                if !flash.acknowledged {
                    return Err(PreparationError::FlashAcknowledge);
                }
                // The write repeats the checked inputs, not whatever the fields hold now.
                Request::FlashWrite {
                    programmer: checked.programmer.clone(),
                    image: checked.image.clone(),
                    backup: checked.backup.clone(),
                    whole_chip: checked.whole_chip,
                    confirm: Some(checked.image_sha256.clone()),
                    elevate,
                }
            }
            _ => unreachable!("flash_request({action:?}): expected a flash action"),
        })
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
        self.review
            .as_ref()
            .filter(|review| review.recipe_path().is_some())
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
                        recipe
                            .recipe_path()
                            .map(Path::to_path_buf)
                            .ok_or(PreparationError::Plan)?,
                    ),
                    destination: PatchDestination::Preview,
                }
            }
            Action::Build => {
                let selection = if let Some(recipe) = self.imported_recipe() {
                    PatchSelection::Recipe(
                        recipe
                            .recipe_path()
                            .map(Path::to_path_buf)
                            .ok_or(PreparationError::Plan)?,
                    )
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
                        .and_then(|review| review.recipe_path().map(Path::to_path_buf)),
                }
            }
            Action::Sources => Request::CatalogList,
            Action::Tools if !self.tools_supported => {
                return Err(PreparationError::ToolsUnsupported);
            }
            Action::ToolChange | Action::ToolInstall if !self.tools_supported => {
                self.pending_tool_change = None;
                return Err(PreparationError::ToolsUnsupported);
            }
            Action::Tools => Request::ToolsStatus,
            Action::ToolChange | Action::ToolInstall => {
                self.drop_check_for_flashrom_change();
                match self.pending_tool_change.take() {
                    Some(ToolChange::Choose { tool, path }) if action == Action::ToolChange => {
                        Request::ToolsSet { tool, path }
                    }
                    Some(ToolChange::Reset { tool }) if action == Action::ToolChange => {
                        Request::ToolsUnset { tool }
                    }
                    Some(ToolChange::InstallGhidra) if action == Action::ToolInstall => {
                        Request::ToolsSetupGhidra
                    }
                    _ => return Err(PreparationError::Engine),
                }
            }
            Action::FlashDoctor
            | Action::FlashProbe
            | Action::FlashBackup
            | Action::FlashCheck
            | Action::FlashWrite => self.flash_request(action)?,
        };
        let token = self.begin(action);
        if matches!(action, Action::Scan | Action::ValidateRecipe) {
            self.recipe_validated = false;
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
                self.flash.supported = data["flash_workflow"] == 1;
                self.tools_supported = data["tools_workflow"] == 1;
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
                self.review = self
                    .review
                    .take()
                    .filter(|review| review.recipe_path().is_some());
                self.manifest = None;
                self.manifest_receipt = None;
                self.built_plan = None;
                self.source_details = payload.extra.map(|v| pretty(&v)).unwrap_or_default();
                self.set_status(Status::Scanned);
            }
            Action::Preview => {
                let plan = self.validate_selection_response(&data, &payload.reply.version)?;
                if data["dry_run"] != true {
                    return Err(local_error("preview: expected a dry-run result"));
                }
                self.review = Some(Arc::new(Review::preview(plan.clone())));
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
                self.built_plan = Some(imported.unwrap_or_else(|| {
                    Arc::new(Review::from_document(plan.clone(), SelectionOrigin::Build))
                }));
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
                self.validate_verification_receipt(
                    &data["manifest_sha256"],
                    Some(payload.reply.version.as_str()),
                )?;
                let complete = verification_complete(&data, contract)?;
                self.outcome = if complete {
                    Outcome::Verified
                } else {
                    Outcome::VerificationIncomplete
                };
                self.set_status(if !complete {
                    Status::Incomplete
                } else if self.manifest_receipt.is_none() && self.manifest.is_some() {
                    Status::VerifiedOpened
                } else {
                    Status::Verified
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
                self.tool_report = Some(Arc::new(valid_tool_report(data)?));
                self.set_status(Status::Tools);
            }
            Action::ToolChange | Action::ToolInstall => {
                // The change succeeded; the refreshed report that follows it is what we show.
                let status = payload.extra.ok_or_else(|| {
                    local_error("tools: expected a status report after the change")
                })?;
                self.tool_report = Some(Arc::new(valid_tool_report(status)?));
                self.set_status(Status::Tools);
            }
            Action::FlashDoctor => {
                if !data["checks"].is_array() {
                    return Err(local_error("flash doctor: expected a checks array"));
                }
                self.flash.report = Some(Arc::new(FlashReport::Doctor(data)));
                self.set_status(Status::FlashDiagnosed);
            }
            Action::FlashProbe => {
                if data["chips"].as_array().is_none_or(Vec::is_empty) {
                    return Err(local_error("flash probe: expected one or more chips"));
                }
                self.flash.report = Some(Arc::new(FlashReport::Probe(data)));
                self.set_status(Status::FlashProbed);
            }
            Action::FlashBackup => {
                let requested = self
                    .flash
                    .backup
                    .as_deref()
                    .ok_or_else(|| local_error("flash backup: expected the requested path"))?;
                if data["output"] != requested.to_string_lossy().as_ref()
                    || sha256_string(&data["sha256"]).is_none()
                {
                    return Err(local_error(
                        "flash backup receipt: expected the requested output path and a lowercase SHA-256",
                    ));
                }
                let path = requested.display().to_string();
                self.flash.report = Some(Arc::new(FlashReport::Backup(data)));
                self.set_detailed_status(
                    Status::FlashBackedUp,
                    path.clone(),
                    "",
                    format!("Chip backed up to {path}"),
                );
            }
            Action::FlashCheck => {
                let digest = sha256_string(&data["confirm"])
                    .filter(|digest| data["image_sha256"] == *digest)
                    .ok_or_else(|| {
                        local_error("flash check: expected the image SHA-256 to confirm")
                    })?;
                if data["dry_run"] != true || data["written"] != false {
                    return Err(local_error("flash check: expected a dry run"));
                }
                let (programmer, image, backup, whole_chip) = self.flash_inputs();
                self.flash.checked = Some(CheckedWrite {
                    programmer: programmer.trim().to_owned(),
                    image: image.ok_or_else(|| local_error("flash check: expected an image"))?,
                    backup: backup.ok_or_else(|| local_error("flash check: expected a backup"))?,
                    whole_chip,
                    image_sha256: digest.to_owned(),
                });
                self.flash.acknowledged = false;
                self.flash.report = Some(Arc::new(FlashReport::Check(data)));
                self.set_status(Status::FlashChecked);
            }
            Action::FlashWrite => {
                let checked = self.flash.checked.take();
                self.flash.acknowledged = false;
                let expected = checked
                    .as_ref()
                    .map(|checked| checked.image_sha256.as_str());
                if data["written"] != true
                    || data["verified"] != true
                    || data["image_sha256"].as_str() != expected
                {
                    self.outcome = Outcome::ChipWriteUnknown;
                    return Err(local_error(format!(
                        "flash write receipt: expected a written, read-back image {} | received written={} verified={} image {}",
                        expected.unwrap_or("<none>"),
                        data["written"],
                        data["verified"],
                        data["image_sha256"]
                    )));
                }
                self.flash.report = Some(Arc::new(FlashReport::Written(data)));
                self.outcome = Outcome::ChipWritten;
                self.set_status(Status::FlashWritten);
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

    fn validate_verification_receipt(
        &self,
        digest: &Value,
        version: Option<&str>,
    ) -> Result<(), EngineError> {
        if let Some(expected) = &self.manifest_receipt
            && (digest.as_str() != Some(expected.as_str())
                || version.is_none()
                || version != self.engine_version.as_deref())
        {
            return Err(local_error(format!(
                "verification receipt: expected manifest SHA-256 {expected} from the connected engine | received {digest} from version {}",
                version.unwrap_or("<missing>")
            )));
        }
        Ok(())
    }

    fn fail(&mut self, action: Action, mut error: EngineError) {
        if action == Action::Verify
            && error.code.as_deref() == Some("VERIFICATION_INCOMPLETE")
            && let Err(receipt_error) = self.validate_verification_receipt(
                &error.details.as_ref().unwrap_or(&Value::Null)["manifest_sha256"],
                error.version.as_deref().map(String::as_str),
            )
        {
            error = receipt_error;
        }
        if action == Action::Connect {
            self.connected = false;
            self.engine_attempted = true;
            self.engine_version = None;
            self.engine_contract = None;
            self.flash.supported = false;
            self.tools_supported = false;
        }
        if action.is_flash() {
            self.fail_flash(action, error);
            return;
        }
        self.outcome = match error.code.as_deref() {
            Some("PUBLISH_INCOMPLETE") => Outcome::PublicationIncomplete,
            Some("VERIFICATION_INCOMPLETE") => Outcome::VerificationIncomplete,
            _ if action == Action::Verify && self.manifest.is_some() => Outcome::VerificationFailed,
            _ if matches!(
                error.kind,
                ErrorKind::Interrupted | ErrorKind::Cancelled | ErrorKind::Timeout
            ) =>
            {
                Outcome::Interrupted
            }
            _ => Outcome::Failed,
        };
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
        if action == Action::Build && !definite {
            self.outcome = Outcome::PublicationUnknown;
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

    /// Record a failed chip operation without touching the patch workflow's results.
    fn fail_flash(&mut self, action: Action, error: EngineError) {
        let definite = matches!(
            error.kind,
            ErrorKind::Engine | ErrorKind::Configuration | ErrorKind::Launch
        );
        let message = error.to_string();
        self.log(&format!(
            "{}\n{}\n{}",
            error,
            error.details.as_ref().map(pretty).unwrap_or_default(),
            error.diagnostics
        ));
        self.flash.report = Some(Arc::new(FlashReport::Failure(
            message.clone(),
            error.details.clone(),
        )));
        if action == Action::FlashWrite {
            // Whatever happened, the chip may have changed: the check is spent.
            self.flash.checked = None;
            self.flash.acknowledged = false;
        }
        // A refusal happens before the write; anything else may have reached the chip.
        let refused = definite && error.code.as_deref() != Some("FLASH_FAILED");
        if action == Action::FlashWrite && !refused {
            self.outcome = Outcome::ChipWriteUnknown;
            let fallback = format!(
                "The chip may hold a partial image. Keep the board powered and restore the backup. {message}"
            );
            self.set_detailed_status(Status::FlashOutcomeUnknown, message, "", fallback);
        } else {
            self.outcome = if matches!(
                error.kind,
                ErrorKind::Interrupted | ErrorKind::Cancelled | ErrorKind::Timeout
            ) {
                Outcome::Interrupted
            } else {
                Outcome::Failed
            };
            self.set_detailed_status(Status::Failed, message.clone(), "", message);
        }
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
            review: Some(Arc::new(Review::imported(path, bytes, document))),
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
        if matches!(
            &self.request,
            Request::VerifyResult {
                recipe: Some(_),
                ..
            } | Request::Build {
                selection: PatchSelection::Recipe(_),
                ..
            }
        ) {
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
                .recipe_path()
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
            let mut bound = engine.clone().with_contract(contract);
            if self.request.is_flash() {
                // Root never reads the user's configuration, so every chip command is told
                // which flashrom the user saved. Without one, the engine looks in PATH.
                let saved = saved_flashrom(&bound, &self.cancel)?;
                bound = bound.with_flashrom(saved);
            }
            bound_engine = bound;
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
            Action::ToolChange | Action::ToolInstall => {
                let mut change = engine.run(&self.request, &self.cancel)?;
                let status =
                    engine
                        .run(&Request::ToolsStatus, &self.cancel)
                        .map_err(|mut error| {
                            append_diagnostics(&mut error.diagnostics, &change.diagnostics);
                            error
                        })?;
                if change.version != status.version {
                    let mut error = local_error(format!(
                        "tools: expected matching change and status versions | received {} and {}",
                        change.version, status.version
                    ));
                    append_diagnostics(&mut error.diagnostics, &change.diagnostics);
                    append_diagnostics(&mut error.diagnostics, &status.diagnostics);
                    return Err(error);
                }
                append_diagnostics(&mut change.diagnostics, &status.diagnostics);
                (change, Some(status.data))
            }
            _ => (engine.run(&self.request, &self.cancel)?, None),
        };
        Ok(Payload {
            reply,
            extra,
            review: None,
        })
    }
}

/// The flashrom executable saved with `bme tools set`, or `None` when none is saved.
///
/// A failed lookup is an error, not `None`: an elevated command that silently skipped the
/// saved path would run whatever flashrom `PATH` offers instead.
///
/// `BME_FLASHROM` counts as a choice too: pkexec resets the environment, so the elevated
/// engine would otherwise fall back to `PATH`.
///
/// Example: a `tools paths` reply whose flashrom has origin `config` and path
/// `/opt/fr/flashrom` yields `Some("/opt/fr/flashrom")`.
fn saved_flashrom(engine: &Engine, cancel: &AtomicBool) -> Result<Option<PathBuf>, EngineError> {
    // Nothing reached the chip. A configuration error is a definite refusal, so a failed
    // write check does not claim the chip may hold a partial image.
    let reply = engine.run(&Request::ToolsPaths, cancel).map_err(|error| {
        let mut refusal = EngineError::new(
            ErrorKind::Configuration,
            format!(
                "flashrom lookup: expected the saved flashrom from `tools paths` | received {}",
                error.message
            ),
        );
        refusal.diagnostics = error.diagnostics;
        refusal
    })?;
    Ok(saved_flashrom_in(&reply.data))
}

fn saved_flashrom_in(paths: &Value) -> Option<PathBuf> {
    let flashrom = &paths["flashrom"];
    // A PATH result is what the elevated engine finds on its own; any other origin is a
    // choice that root cannot see.
    if !flashrom["origin"].is_string() || flashrom["origin"] == "PATH" {
        return None;
    }
    flashrom["path"].as_str().map(PathBuf::from)
}

/// Accept a `tools status` report that carries a list of typed tool rows.
///
/// Example: `valid_tool_report(json!({"tools": [{"id": "git", "health": "ready"}]}))` is accepted.
fn valid_tool_report(report: Value) -> Result<Value, EngineError> {
    let rows = report["tools"].as_array();
    let valid = rows.is_some_and(|rows| {
        !rows.is_empty()
            && rows.iter().all(|row| {
                row["id"].is_string()
                    && row["name"].is_string()
                    && matches!(
                        row["health"].as_str(),
                        Some("ready" | "attention" | "missing")
                    )
            })
    });
    if valid {
        Ok(report)
    } else {
        Err(local_error(format!(
            "tools status: expected tool rows with id, name and health | received {}",
            pretty(&report)
        )))
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
