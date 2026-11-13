//! `bme`: inspect firmware images, plan guarded patches, build verified copies.
//!
//! Outputs are always new files. Only the `flash` commands touch a flash chip,
//! through flashrom; `flash write` is the single command that changes one.

mod commands;
mod config;
mod flash;
mod output;
mod publish;
mod sources;
#[cfg(test)]
mod testkit;
mod toolchain;
mod transport;

use clap::{Args, Parser, Subcommand};
use output::{Out, exit};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "bme", version, about = "Biosmod Engine: scan firmware images, build patched copies and verify them.", long_about = None)]
#[command(
    after_help = "Workflow:\n  bme scan dump.bin\n  bme patch dump.bin --recommended\n  bme verify dump.bin dump.patched.bin\nChip (Linux): bme flash doctor, then `bme guide flashing`\nAgents: add --json for one machine-readable document on stdout; see `bme capabilities --json`."
)]
pub struct Cli {
    /// Emit one JSON document on stdout (including failures).
    #[arg(long, global = true)]
    json: bool,
    /// Suppress progress notes on stderr.
    #[arg(long, short, global = true)]
    quiet: bool,
    /// Forbid all network access for this invocation.
    #[arg(long, global = true)]
    offline: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Print the engine, protocol and codec versions.
    Version,
    /// Describe supported commands, formats, limits and error codes.
    Capabilities,
    /// Print a bundled JSON Schema (or list them).
    Schema { name: Option<String> },
    /// Print built-in documentation (or list topics).
    Guide { topic: Option<String> },
    /// List firmware volumes, files and the flash layout of an image.
    Inspect(InspectArgs),
    /// Decode Setup forms (UEFI IFR): questions, varstore offsets, options, defaults and conditions.
    Ifr(IfrArgs),
    /// List NVRAM variables (AMI NVAR, EDK II VSS): state, GUID, size, hash; read a Setup field against its default.
    Nvram(NvramArgs),
    /// Report known defects and patch states for an image.
    Scan(ScanArgs),
    /// Resolve a selection, dry-build it in memory and write a reviewable plan.
    #[command(hide = true)]
    Plan(PlanArgs),
    /// Save an exact patch recipe (defaults to recommended patches).
    Export(ExportArgs),
    /// Build a verified copy from patch IDs, recommendations or a saved recipe.
    Patch(PatchArgs),
    /// Independently verify an input/output pair against its manifest.
    Verify(VerifyArgs),
    /// Write one module (PE32 or DSDT) to a file.
    Extract(ExtractArgs),
    /// Put a hand-edited module back into a copy of the image.
    Replace(ReplaceArgs),
    /// Draft a patch variant for another build by unique signature matching.
    Derive(DeriveArgs),
    /// Compare two images module by module (read-only report).
    Compare(CompareArgs),
    /// Manage, validate and index catalogs.
    #[command(subcommand)]
    Catalog(CatalogCommand),
    /// Follow an investigation: inputs by digest, recorded results, draft catalog records.
    #[command(subcommand)]
    Case(CaseCommand),
    /// Check and install external analysis tools (Ghidra).
    #[command(subcommand)]
    Tools(ToolsCommand),
    /// Replay firmware modules against simulated hardware in the managed Python runtime.
    #[command(subcommand)]
    Replay(ReplayCommand),
    /// Diagnostics outside the correction catalog.
    #[command(subcommand)]
    Diag(DiagCommand),
    /// Diagnose, find, back up and write the system flash chip through flashrom (Linux).
    #[command(subcommand)]
    Flash(FlashCommand),
    /// Developer helpers.
    #[command(subcommand)]
    Dev(DevCommand),
}

#[derive(Args, Clone)]
pub struct SourceArgs {
    /// Catalog alias, catalog directory or board profile file (repeatable; default: official).
    #[arg(long = "catalog", value_name = "SOURCE")]
    pub catalogs: Vec<String>,
    /// Accept an unregistered, unsigned local catalog path.
    #[arg(long)]
    pub allow_unsigned_local: bool,
    /// Firmware build id, instead of detecting it.
    #[arg(long)]
    pub firmware: Option<String>,
}

#[derive(Args)]
pub struct InspectArgs {
    pub rom: PathBuf,
    /// List every FFS file.
    #[arg(long)]
    pub files: bool,
    /// List every checksum-valid ACPI table stored in the image (not the runtime-published set).
    #[arg(long)]
    pub acpi: bool,
}

#[derive(Args)]
pub struct IfrArgs {
    /// A firmware image or one PE, TE or raw section holding HII packages.
    #[arg(value_name = "ROM|PE")]
    pub input: PathBuf,
    /// Decode only this FFS file (images only); default: every PE with IFR.
    #[arg(long)]
    pub guid: Option<String>,
    /// String language to use (default: en-US, else the first present).
    #[arg(long, value_name = "TAG")]
    pub language: Option<String>,
}

#[derive(Args)]
pub struct NvramArgs {
    /// A firmware image (stores are found structurally) or one bare NVAR/VSS store.
    #[arg(value_name = "ROM|STORE")]
    pub input: PathBuf,
    /// Only variables with this exact name.
    #[arg(long, conflicts_with = "field")]
    pub name: Option<String>,
    /// Only variables with this vendor GUID.
    #[arg(long, conflicts_with = "field")]
    pub guid: Option<String>,
    /// Only stores whose label contains this text (`nvar@0x840000`, `StdDefaults`, `vss`).
    #[arg(long, value_name = "TEXT")]
    pub store: Option<String>,
    /// Include superseded (history), deleted and orphan records; default: active only.
    #[arg(long)]
    pub all_records: bool,
    /// Write the data of the one selected record to `--output`.
    #[arg(long, requires = "output", conflicts_with = "field")]
    pub dump: bool,
    /// New file for `--dump`.
    #[arg(short, long, value_name = "FILE", requires = "dump")]
    pub output: Option<PathBuf>,
    /// Setup question prompt: print its stored value in every record next to the IFR default.
    #[arg(long, value_name = "PROMPT")]
    pub field: Option<String>,
    /// Pick one question when a prompt names several (decimal or 0x-prefixed hex).
    #[arg(long, value_name = "ID", requires = "field")]
    pub question_id: Option<String>,
}

#[derive(Args)]
pub struct ScanArgs {
    pub rom: PathBuf,
    #[command(flatten)]
    pub source: SourceArgs,
}

#[derive(Args, Clone)]
pub struct SelectArgs {
    /// Patch ids: ID, ALIAS::ID or ALIAS::ID@VERSION; `recommended` selects plannable tier-1 corrections.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub select: Vec<String>,
    /// Assert a hardware fact confirmed on the physical board (repeatable).
    #[arg(long = "assert", value_name = "FACT")]
    pub facts: Vec<String>,
    /// Include records on hold (unknown hardware effect).
    #[arg(long)]
    pub allow_hold: bool,
    /// Include diagnostic patches.
    #[arg(long)]
    pub allow_diagnostic: bool,
}

#[derive(Args)]
pub struct PlanArgs {
    pub rom: PathBuf,
    #[command(flatten)]
    pub select: SelectArgs,
    #[command(flatten)]
    pub source: SourceArgs,
    /// Plan file to create (must not exist).
    #[arg(short, long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct DirectSelection {
    /// Patch IDs, optionally qualified as ALIAS::ID@VERSION.
    #[arg(value_name = "ID", conflicts_with_all = ["select", "recommended"])]
    pub ids: Vec<String>,
    /// Use the catalog's recommended selection.
    #[arg(long, conflicts_with = "select")]
    pub recommended: bool,
    #[command(flatten)]
    pub legacy: SelectArgs,
}

#[derive(Args, Default)]
pub struct SnapshotExpectations {
    /// Require the input SHA-256 reported by scan.
    #[arg(long)]
    pub expect_input_sha256: Option<biosmod_core::util::Digest256>,
    /// Require the catalog snapshot SHA-256 reported by scan.
    #[arg(long)]
    pub expect_source_sha256: Option<biosmod_core::util::Digest256>,
}

#[derive(Args)]
pub struct ExportArgs {
    pub rom: PathBuf,
    #[command(flatten)]
    pub selection: DirectSelection,
    #[command(flatten)]
    pub source: SourceArgs,
    #[command(flatten)]
    pub expectations: SnapshotExpectations,
    /// New recipe file.
    #[arg(short, long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct PatchArgs {
    pub rom: PathBuf,
    /// Reproduce the operation recorded in a saved recipe.
    #[arg(long = "from", alias = "plan", conflicts_with_all = [
        "ids", "recommended", "select", "catalogs", "firmware", "facts",
        "allow_hold", "allow_diagnostic", "expect_input_sha256", "expect_source_sha256",
    ])]
    pub plan: Option<PathBuf>,
    #[command(flatten)]
    pub selection: DirectSelection,
    #[command(flatten)]
    pub source: SourceArgs,
    #[command(flatten)]
    pub expectations: SnapshotExpectations,
    /// Build and validate in memory without publishing files.
    #[arg(long)]
    pub dry_run: bool,
    /// New image path (default: insert .patched before the input extension).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct VerifyArgs {
    pub input: PathBuf,
    pub output: PathBuf,
    /// Output manifest (default: <output>.manifest.json).
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// Require the manifest to embed this saved recipe.
    #[arg(long = "from", alias = "plan")]
    pub plan: Option<PathBuf>,
}

#[derive(Args)]
pub struct ExtractArgs {
    pub rom: PathBuf,
    #[arg(long)]
    pub guid: String,
    #[arg(long, value_enum, default_value = "pe32")]
    pub leaf: commands::Leaf,
    /// With --leaf acpi-table: table signature to pick, e.g. SSDT (see `inspect --acpi`).
    #[arg(long)]
    pub signature: Option<String>,
    /// With --leaf acpi-table: OEM table ID to pick, e.g. PmMgt.
    #[arg(long)]
    pub oem_table_id: Option<String>,
    /// With --leaf acpi-table: table SHA-256 to pick.
    #[arg(long)]
    pub sha256: Option<String>,
    #[arg(short, long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct ReplaceArgs {
    pub rom: PathBuf,
    #[arg(long)]
    pub guid: String,
    #[arg(long, value_enum, default_value = "pe32")]
    pub leaf: commands::Leaf,
    /// The edited module.
    #[arg(long)]
    pub input: PathBuf,
    /// Allow a different module size (files may move; XIP files never do).
    #[arg(long)]
    pub allow_resize: bool,
    #[arg(short, long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct DeriveArgs {
    #[arg(long)]
    pub patch: String,
    /// Firmware build the record was made for.
    #[arg(long)]
    pub from_firmware: String,
    #[arg(long)]
    pub component: String,
    /// The module extracted from the other build.
    #[arg(long)]
    pub module: PathBuf,
    #[command(flatten)]
    pub source: SourceArgs,
}

#[derive(Args)]
pub struct CompareArgs {
    /// The first input (reported as A).
    pub a: PathBuf,
    /// The second input (reported as B).
    pub b: PathBuf,
    /// Compare two `tools analyze` JSON exports function by function instead of images.
    #[arg(long)]
    pub functions: bool,
    /// Compare the DSDT/SSDT tables of two images, `.aml` files or `diag acpi capture` directories object by object.
    #[arg(long, conflicts_with = "functions")]
    pub acpi: bool,
    /// With --acpi: write a unified ASL diff per changed method into DIR (needs `iasl` on PATH).
    #[arg(long, value_name = "DIR", requires = "acpi")]
    pub disassemble: Option<PathBuf>,
    /// With --acpi: also list every object (path, kind, hash) of each paired table.
    #[arg(long, requires = "acpi")]
    pub objects: bool,
}

#[derive(Subcommand)]
pub enum CatalogCommand {
    /// Scaffold a device repository: an empty catalog, notes directories and a .gitignore that keeps firmware out of git.
    Init {
        /// New directory (must not exist).
        dir: PathBuf,
        /// Catalog id: 1-64 characters [A-Za-z0-9._-] starting alphanumeric; not `official`.
        #[arg(long)]
        id: String,
        /// Catalog title (default: the id).
        #[arg(long)]
        title: Option<String>,
    },
    /// Write the device repository of one board, cut from a catalog.
    ///
    /// Keeps the board's records and cuts each to the board's firmware builds:
    /// a patch stays when a build of the board has an applicable variant; a finding
    /// stays when it affects a build of the board; evidence stays when it names the
    /// board. The reply lists what was dropped.
    Split {
        /// Catalog directory, or `official` for the bundled catalog.
        source: String,
        /// Board id to keep.
        #[arg(long, value_name = "BOARD_ID")]
        board: String,
        /// New directory (must not exist).
        #[arg(short, long, value_name = "DIR")]
        output: PathBuf,
        /// Catalog id: 1-64 characters [A-Za-z0-9._-] starting alphanumeric; not `official`.
        #[arg(long)]
        id: String,
        /// Catalog title (default: the id).
        #[arg(long)]
        title: Option<String>,
    },
    /// Union two or more catalogs, or check that they agree.
    ///
    /// Records match by id. Board lists, patch variants, finding builds, code
    /// references and evidence are unioned; every other field of a shared record
    /// must be equal, and a difference is an error naming the record, field, both
    /// values and both catalogs.
    Merge {
        /// Catalog directories or `official`, at least two.
        #[arg(value_name = "SOURCE", required = true)]
        sources: Vec<String>,
        /// Write nothing; report whether the catalogs agree.
        #[arg(long, conflicts_with_all = ["output", "id", "title", "version"], required_unless_present = "output")]
        check: bool,
        /// New catalog directory (must not exist).
        #[arg(short, long, value_name = "DIR", requires = "id")]
        output: Option<PathBuf>,
        /// Catalog id: 1-64 characters [A-Za-z0-9._-] starting alphanumeric; not `official`.
        #[arg(long, requires = "output")]
        id: Option<String>,
        /// Catalog title (default: the id).
        #[arg(long, requires = "output")]
        title: Option<String>,
        /// Catalog version (default: 0.1.0).
        #[arg(long, value_name = "SEMVER", requires = "output")]
        version: Option<String>,
    },
    /// Validate a catalog directory (or board file) without registering it.
    Validate { path: PathBuf },
    /// Regenerate catalog.json's file index (lengths and hashes).
    Index {
        path: PathBuf,
        /// Only report whether the index is current.
        #[arg(long)]
        check: bool,
    },
    /// Register a local directory or HTTPS catalog under an alias.
    Add {
        alias: String,
        location: String,
        /// Minisign public key (file or base64) that must sign catalog.json.
        #[arg(long)]
        trust_key: Option<String>,
        /// Accept an unsigned local directory.
        #[arg(long)]
        allow_unsigned_local: bool,
    },
    /// List registered sources and their snapshots.
    List,
    /// Remove a registered source (cached snapshots are kept until `--purge`).
    Remove {
        alias: String,
        #[arg(long)]
        purge: bool,
    },
    /// Download and verify a new snapshot of a remote source.
    Update { alias: String },
    /// Summarize boards, firmware builds and patches of a source.
    Show {
        #[command(flatten)]
        source: SourceArgs,
    },
    /// Convert x99-bios-fixes schema-1 records into bme.patch/1 files.
    #[command(name = "import-x99fix")]
    ImportX99fix {
        /// The reference repository's patches/ directory.
        dir: PathBuf,
        /// Board-to-firmware mapping, e.g. mr9a=mnx99mr9apro-230322 (repeatable).
        #[arg(long = "map", required = true)]
        maps: Vec<String>,
        /// Reference commit the records come from.
        #[arg(long)]
        commit: String,
        #[arg(
            long,
            default_value = "https://github.com/juliopolycarpo/x99-bios-fixes"
        )]
        repository: String,
        /// Output directory (the catalog's patches/ directory).
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum CaseCommand {
    /// Scan a dump and draft a board profile and firmware build from it.
    Init(CaseInitArgs),
    /// Run a bme command and keep its JSON output and output files in the case.
    Record(CaseRecordArgs),
    /// Verify every input and artifact, and report stale results.
    Status(CaseStatusArgs),
    /// Write a catalog submission directory from the case.
    Export(CaseExportArgs),
}

#[derive(Args)]
pub struct CaseInitArgs {
    /// The firmware dump; it is hashed, never copied.
    pub dump: PathBuf,
    /// New case directory (must not exist).
    #[arg(short, long)]
    pub output: PathBuf,
    /// Board id for the draft profile (default: draft-<firmware id>).
    #[arg(long)]
    pub board_id: Option<String>,
    #[command(flatten)]
    pub source: SourceArgs,
}

#[derive(Args)]
pub struct CaseRecordArgs {
    /// The case directory.
    pub dir: PathBuf,
    /// A file the command creates besides `-o`/`--output` (repeatable).
    #[arg(long = "artifact", value_name = "PATH")]
    pub artifacts: Vec<PathBuf>,
    /// The bme command and its arguments, after `--`.
    #[arg(last = true, required = true, allow_hyphen_values = true)]
    pub argv: Vec<String>,
}

#[derive(Args)]
pub struct CaseStatusArgs {
    /// The case directory.
    pub dir: PathBuf,
    /// Where an input dump is on this machine: FILE, DIRECTORY or NAME=PATH (repeatable).
    #[arg(long = "input", value_name = "PATH")]
    pub inputs: Vec<String>,
    /// Catalog to judge staleness against (default: official).
    #[arg(long = "catalog", value_name = "SOURCE")]
    pub catalogs: Vec<String>,
    /// Accept an unregistered, unsigned local catalog path.
    #[arg(long)]
    pub allow_unsigned_local: bool,
}

#[derive(Args)]
pub struct CaseExportArgs {
    /// The case directory.
    pub dir: PathBuf,
    /// New catalog submission directory (must not exist).
    #[arg(short, long)]
    pub output: PathBuf,
}

#[derive(Subcommand)]
pub enum ToolsCommand {
    /// Read-only check of Ghidra, JDK and extension compatibility, and of the replay runtime once installed.
    Doctor {
        /// Check only one tool; `replay` also fails when its runtime is not installed.
        tool: Option<toolchain::DoctorTool>,
        /// Also start Ghidra headless on a tiny file, or execute an instruction in Unicorn.
        #[arg(long)]
        deep: bool,
    },
    /// Show every tool bme uses: version, location, and how to install what is missing.
    Status,
    /// Install pinned tools (Linux only for now).
    #[command(subcommand)]
    Setup(SetupCommand),
    /// Use an existing copy of a tool and remember it in the configuration.
    Set {
        tool: toolchain::Locatable,
        /// Ghidra installation directory, the flashrom executable, or a Python interpreter or
        /// virtual environment with the pinned replay packages.
        path: PathBuf,
    },
    /// Forget a saved tool location and go back to the default lookup.
    Unset { tool: toolchain::Locatable },
    /// Import modules into a Ghidra project and export C, assembly and JSON.
    Analyze {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(required = true)]
        modules: Vec<PathBuf>,
        /// Per-file analysis timeout in seconds.
        #[arg(long, default_value_t = 600)]
        timeout: u64,
    },
    /// Print managed tool and cache locations.
    Paths,
}

#[derive(Subcommand)]
pub enum SetupCommand {
    /// Ghidra with the ghidra-firmware-utils extension, from the pinned profile.
    Ghidra(toolchain::SetupArgs),
    /// A Python environment with hash-locked Unicorn, Capstone and pefile for `bme replay`.
    Replay(toolchain::ReplaySetupArgs),
}

#[derive(Subcommand)]
pub enum ReplayCommand {
    /// Run a Python harness against firmware modules and record the run as evidence.
    Script(ReplayScriptArgs),
    /// Replay a bme.scenario/1 file against a module and report each expectation.
    Run(ReplayRunArgs),
}

#[derive(Args)]
pub struct ReplayScriptArgs {
    /// The harness: a Python script that imports `bme_replay` and calls `bme_replay.emit`.
    pub harness: PathBuf,
    /// A firmware module the harness loads with `bme_replay.modules()` (repeatable).
    #[arg(long = "module", value_name = "PE")]
    pub modules: Vec<PathBuf>,
    /// New directory for `evidence.json` and `result.jsonl`.
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,
    /// Board id for the evidence record (default: unscoped).
    #[arg(long, default_value = commands::UNSCOPED)]
    pub board: String,
    /// Firmware build id for the evidence record (default: unscoped).
    #[arg(long, default_value = commands::UNSCOPED)]
    pub firmware: String,
    /// Seconds the harness may run.
    #[arg(long, default_value_t = 600)]
    pub timeout: u64,
    /// Arguments for the harness, after `--`.
    #[arg(last = true)]
    pub args: Vec<String>,
}

#[derive(Args)]
pub struct ReplayRunArgs {
    /// The scenario file (bme.scenario/1).
    pub scenario: PathBuf,
    /// The module the scenario names by SHA-256.
    #[arg(long, value_name = "PE")]
    pub module: PathBuf,
    /// New directory for `evidence.json` and `result.jsonl`.
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,
    /// Board id for the evidence record (default: unscoped).
    #[arg(long, default_value = commands::UNSCOPED)]
    pub board: String,
    /// Firmware build id for the evidence record (default: unscoped).
    #[arg(long, default_value = commands::UNSCOPED)]
    pub firmware: String,
    /// Seconds the scenario may run.
    #[arg(long, default_value_t = 600)]
    pub timeout: u64,
}

#[derive(Subcommand)]
pub enum DiagCommand {
    /// MR9A MRC checkpoint breadcrumbs in upper-bank CMOS.
    #[command(subcommand)]
    Breadcrumbs(BreadcrumbCommand),
    /// ACPI tables and sleep state of the running machine (Linux, root).
    #[command(subcommand)]
    Acpi(AcpiCommand),
    /// Super I/O chip registers: fan controller and logical devices (Linux, root).
    #[command(subcommand)]
    Superio(SuperioCommand),
    /// Suspend tests that return without sleeping the machine (Linux, root).
    #[command(subcommand)]
    Suspend(SuspendCommand),
    /// SMBIOS identity and memory devices from the firmware table (Linux). Root reads the
    /// full table; without root only the model-level DMI fields are available, and the
    /// output says memory devices are unavailable.
    Smbios {
        /// Also save the report, manifest and evidence record in this new directory. The
        /// raw table is never saved (it holds serial numbers).
        #[arg(short, long, value_name = "DIR")]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum SuspendCommand {
    /// Run one kernel suspend test stage (/sys/power/pm_test) and report the suspend
    /// counters. The kernel stops at the stage's checkpoint and unwinds; the machine does
    /// not sleep, but its devices and processes are frozen for several seconds. pm_test is
    /// always set back to none.
    PmTest {
        /// Checkpoint to test: freezer, devices, platform, processors or core. One per run;
        /// none (a real sleep) is refused. platform, processors and core need mem_sleep deep.
        #[arg(long, value_name = "STAGE")]
        stage: String,
        /// New directory for the test report, kernel messages, manifest and evidence record.
        #[arg(short, long, value_name = "DIR")]
        output: PathBuf,
        /// Confirm that running desktop sessions freeze and the screen may go dark for a few
        /// seconds; save your work first.
        #[arg(long, required = true)]
        i_understand_this_suspends: bool,
    },
}

#[derive(Subcommand)]
pub enum SuperioCommand {
    /// Detect the chip by ID on ports 2Eh/4Eh, refuse unknown IDs, and read its logical
    /// devices and hardware-monitor registers. Writes only access selectors and restores
    /// the logical device and bank selection. When a kernel driver owns the chip, no port
    /// is touched: the driver's hwmon files are read instead.
    Read {
        /// Port device (default /dev/port).
        #[arg(long, default_value = "/dev/port")]
        device: PathBuf,
        /// Also save the reading, manifest and evidence record in this new directory.
        #[arg(short, long, value_name = "DIR")]
        output: Option<PathBuf>,
        /// Fail instead of falling back when nct6775 is bound to the chip. Any other kernel
        /// claimant (it87, f71882fg, an unknown holder of the ports) is refused with or
        /// without this flag. By default a bound nct6775 means no port is touched and the
        /// reading is what the driver publishes in sysfs. bme never unloads a driver; the
        /// error names the `modprobe -r` step.
        #[arg(long)]
        unbound_only: bool,
    },
}

#[derive(Subcommand)]
pub enum AcpiCommand {
    /// Copy the published ACPI tables, sleep states, sleep-related kernel messages and
    /// boot, kernel and DMI identity into a new directory with a SHA-256 manifest and an
    /// evidence record (read-only; needs root).
    Capture {
        /// New directory to create; an existing one is never touched.
        #[arg(short, long, value_name = "DIR")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum BreadcrumbCommand {
    /// Decode the ten bytes E0-E9 given as hex.
    Decode { hex: Vec<String> },
    /// Read E0-E9 through ports 72h/73h on Linux (read-only; needs root).
    Read {
        #[arg(long, default_value = "/dev/port")]
        device: PathBuf,
    },
}

#[derive(Args)]
pub struct FlashTargetArgs {
    /// flashrom programmer: internal (this machine), ch341a_spi, linux_mtd:dev=0, ...
    #[arg(long, short, default_value = "internal")]
    pub programmer: String,
    /// flashrom chip definition, when probing reports several.
    #[arg(long, short)]
    pub chip: Option<String>,
    /// flashrom executable to use (default: BME_FLASHROM, `bme tools set flashrom`, then PATH).
    #[arg(long, value_name = "PATH")]
    pub flashrom: Option<PathBuf>,
}

impl FlashCommand {
    /// The `--flashrom` executable named on the command line, if any.
    ///
    /// Example: `bme flash probe --flashrom /opt/fr/flashrom` yields `/opt/fr/flashrom`.
    pub fn flashrom_override(&self) -> Option<&PathBuf> {
        match self {
            FlashCommand::Doctor { flashrom, .. } => flashrom.as_ref(),
            FlashCommand::Probe(target) | FlashCommand::Backup { target, .. } => {
                target.flashrom.as_ref()
            }
            FlashCommand::Write(args) => args.target.flashrom.as_ref(),
        }
    }
}

#[derive(Args)]
pub struct FlashWriteArgs {
    /// The image to write, built from the backup.
    pub image: PathBuf,
    /// A dump of what the chip holds now (from `flash backup`).
    #[arg(long)]
    pub backup: PathBuf,
    #[command(flatten)]
    pub target: FlashTargetArgs,
    /// Descriptor region to write (repeatable; default: bios).
    #[arg(long = "region", value_name = "NAME", conflicts_with = "whole_chip")]
    pub regions: Vec<String>,
    /// Write every byte, for chips without an Intel flash descriptor.
    #[arg(long)]
    pub whole_chip: bool,
    /// Run every check, including the chip comparison, without writing.
    #[arg(long, conflicts_with = "confirm")]
    pub dry_run: bool,
    /// The image SHA-256 printed by --dry-run; required to write.
    #[arg(long, value_name = "SHA256")]
    pub confirm: Option<biosmod_core::util::Digest256>,
}

#[derive(Subcommand)]
pub enum FlashCommand {
    /// Report what will help or block chip access on this system (read-only).
    Doctor {
        /// The flashrom programmer you plan to use.
        #[arg(long, short, default_value = "internal")]
        programmer: String,
        /// flashrom executable to use (default: BME_FLASHROM, `bme tools set flashrom`, then PATH).
        #[arg(long, value_name = "PATH")]
        flashrom: Option<PathBuf>,
    },
    /// Detect the flash chip without reading it.
    Probe(FlashTargetArgs),
    /// Read the chip twice and save the dump as a new file.
    Backup {
        #[command(flatten)]
        target: FlashTargetArgs,
        /// Read only these descriptor regions (repeatable), e.g. when the ME region is locked.
        #[arg(long = "region", value_name = "NAME")]
        regions: Vec<String>,
        /// New dump file (must not exist).
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Write an image after checking it against a backup of the chip.
    Write(FlashWriteArgs),
}

#[derive(Subcommand)]
pub enum DevCommand {
    /// Write a synthetic image and catalog (no vendor code) to try the workflow.
    Synthetic {
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Version => "version",
        Command::Capabilities => "capabilities",
        Command::Schema { .. } => "schema",
        Command::Guide { .. } => "guide",
        Command::Inspect(_) => "inspect",
        Command::Ifr(_) => "ifr",
        Command::Nvram(_) => "nvram",
        Command::Scan(_) => "scan",
        Command::Plan(_) => "plan",
        Command::Export(_) => "export",
        Command::Patch(_) => "patch",
        Command::Verify(_) => "verify",
        Command::Extract(_) => "extract",
        Command::Replace(_) => "replace",
        Command::Derive(_) => "derive",
        Command::Compare(_) => "compare",
        Command::Catalog(c) => match c {
            CatalogCommand::Init { .. } => "catalog init",
            CatalogCommand::Split { .. } => "catalog split",
            CatalogCommand::Merge { .. } => "catalog merge",
            CatalogCommand::Validate { .. } => "catalog validate",
            CatalogCommand::Index { .. } => "catalog index",
            CatalogCommand::Add { .. } => "catalog add",
            CatalogCommand::List => "catalog list",
            CatalogCommand::Remove { .. } => "catalog remove",
            CatalogCommand::Update { .. } => "catalog update",
            CatalogCommand::Show { .. } => "catalog show",
            CatalogCommand::ImportX99fix { .. } => "catalog import-x99fix",
        },
        Command::Case(c) => match c {
            CaseCommand::Init(_) => "case init",
            CaseCommand::Record(_) => "case record",
            CaseCommand::Status(_) => "case status",
            CaseCommand::Export(_) => "case export",
        },
        Command::Tools(t) => match t {
            ToolsCommand::Doctor { .. } => "tools doctor",
            ToolsCommand::Status => "tools status",
            ToolsCommand::Set { .. } => "tools set",
            ToolsCommand::Unset { .. } => "tools unset",
            ToolsCommand::Setup(SetupCommand::Ghidra(_)) => "tools setup ghidra",
            ToolsCommand::Setup(SetupCommand::Replay(_)) => "tools setup replay",
            ToolsCommand::Analyze { .. } => "tools analyze",
            ToolsCommand::Paths => "tools paths",
        },
        Command::Replay(ReplayCommand::Script(_)) => "replay script",
        Command::Replay(ReplayCommand::Run(_)) => "replay run",
        Command::Diag(DiagCommand::Breadcrumbs(_)) => "diag breadcrumbs",
        Command::Diag(DiagCommand::Acpi(AcpiCommand::Capture { .. })) => "diag acpi capture",
        Command::Diag(DiagCommand::Superio(SuperioCommand::Read { .. })) => "diag superio read",
        Command::Diag(DiagCommand::Smbios { .. }) => "diag smbios",
        Command::Diag(DiagCommand::Suspend(SuspendCommand::PmTest { .. })) => {
            "diag suspend pm-test"
        }
        Command::Flash(f) => match f {
            FlashCommand::Doctor { .. } => "flash doctor",
            FlashCommand::Probe(_) => "flash probe",
            FlashCommand::Backup { .. } => "flash backup",
            FlashCommand::Write(_) => "flash write",
        },
        Command::Dev(_) => "dev synthetic",
    }
}

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let wants_json = args.iter().skip(1).any(|a| a == "--json");
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error) => {
            use clap::error::ErrorKind;
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp
                    | ErrorKind::DisplayVersion
                    | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) {
                let _ = error.print();
                std::process::exit(
                    if error.kind() == ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand {
                        exit::USAGE
                    } else {
                        exit::OK
                    },
                );
            }
            let out = Out {
                json: wants_json,
                quiet: false,
            };
            if wants_json {
                let message = error
                    .kind()
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| "invalid arguments".into());
                let detail = error.to_string();
                let first = detail
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .trim_start_matches("error: ")
                    .to_string();
                let failure = biosmod_core::Error::new(
                    biosmod_core::Code::Usage,
                    if first.is_empty() { message } else { first },
                );
                std::process::exit(out.failure("usage", &failure));
            }
            let _ = error.print();
            std::process::exit(exit::USAGE);
        }
    };
    let out = Out {
        json: cli.json,
        quiet: cli.quiet,
    };
    let name = command_name(&cli.command);
    let code = match commands::run(cli.command, out, cli.offline) {
        Ok(reply) => out.success(name, reply),
        Err(error) => out.failure(name, &error),
    };
    std::process::exit(code);
}
