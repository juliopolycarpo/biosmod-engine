//! Command implementations. Each returns a [`Reply`] or a typed error; printing happens in `main`.

mod capture_input;
mod case;
mod catalog;
mod catalog_init;
mod catalog_share;
mod compare;
mod compare_acpi;
mod diag;
mod firmware;
mod host;
mod ifr;
mod meta;
mod nvram;
mod replay;
pub use replay::UNSCOPED;

use crate::config::{Config, Paths, io_error};
use crate::output::{Out, Reply};
use crate::sources::{self, LoadPolicy, Loaded};
use crate::{Command, DevCommand, DiagCommand, ReplayCommand, SourceArgs, ToolsCommand};
use biosmod_core::catalog::LeafKind;
use biosmod_core::firmware::Image;
use biosmod_core::ifr::ModuleDiagnostic;
use biosmod_core::{Code, Error, Result};
use std::fs;
use std::io::Read;
use std::path::Path;

/// Largest image accepted (full SPI chips are at most a few tens of MiB).
pub const MAX_IMAGE_BYTES: u64 = 64 << 20;

/// Leaf kinds as command-line values.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Leaf {
    Pe32,
    AcpiTable,
}

impl From<Leaf> for LeafKind {
    fn from(leaf: Leaf) -> LeafKind {
        match leaf {
            Leaf::Pe32 => LeafKind::Pe32,
            Leaf::AcpiTable => LeafKind::AcpiTable,
        }
    }
}

/// Shared state for one invocation.
pub struct Ctx {
    pub out: Out,
    pub offline: bool,
    pub paths: Paths,
    pub config: Config,
}

/// Dispatch a parsed command.
pub fn run(command: Command, out: Out, offline: bool) -> Result<Reply> {
    // Flash commands often run as root through sudo or pkexec, where the home
    // directory is root's: they never create configuration, and only a non-root run
    // reads `tools.flashrom` (see `flash::run`).
    let command = match command {
        Command::Flash(sub) => return crate::flash::run(out, sub),
        // Same reason: host diagnostics need root and never read configuration.
        Command::Diag(DiagCommand::Acpi(sub)) => return host::run_acpi(sub),
        Command::Diag(DiagCommand::Superio(sub)) => return host::run_superio(sub),
        Command::Diag(DiagCommand::Suspend(sub)) => return host::run_suspend(sub),
        Command::Diag(DiagCommand::Smbios { output }) => {
            return host::run_smbios(output.as_deref());
        }
        other => other,
    };
    let paths = Paths::from_env()?;
    let config = Config::load(&paths)?;
    let mut ctx = Ctx {
        out,
        offline,
        paths,
        config,
    };
    match command {
        Command::Version => Ok(meta::version()),
        Command::Capabilities => Ok(meta::capabilities()),
        Command::Schema { name } => meta::schema(name.as_deref()),
        Command::Guide { topic } => meta::guide(topic.as_deref()),
        Command::Inspect(args) => firmware::inspect(&args),
        Command::Ifr(args) => ifr::run(&args),
        Command::Nvram(args) => nvram::run(&args),
        Command::Scan(args) => firmware::scan(&ctx, &args),
        Command::Plan(args) => firmware::plan(&ctx, &args),
        Command::Export(args) => firmware::export(&ctx, &args),
        Command::Patch(args) => firmware::patch(&ctx, &args),
        Command::Verify(args) => firmware::verify(&ctx, &args),
        Command::Extract(args) => firmware::extract(&args),
        Command::Replace(args) => firmware::replace(&args),
        Command::Derive(args) => firmware::derive(&ctx, &args),
        Command::Compare(args) => compare::compare(&args),
        Command::Catalog(sub) => catalog::run(&mut ctx, sub),
        Command::Case(sub) => case::run(&ctx, sub),
        Command::Tools(sub) => tools(&ctx, sub),
        Command::Replay(ReplayCommand::Script(args)) => replay::script(&ctx, &args),
        Command::Replay(ReplayCommand::Run(args)) => replay::run(&ctx, &args),
        Command::Diag(DiagCommand::Breadcrumbs(sub)) => diag::breadcrumbs(sub),
        Command::Diag(
            DiagCommand::Acpi(_)
            | DiagCommand::Superio(_)
            | DiagCommand::Suspend(_)
            | DiagCommand::Smbios { .. },
        ) => {
            unreachable!("host diagnostics return before configuration")
        }
        Command::Dev(DevCommand::Synthetic { output }) => diag::synthetic(&output),
        Command::Flash(_) => unreachable!("flash commands return before configuration loads"),
    }
}

fn tools(ctx: &Ctx, command: ToolsCommand) -> Result<Reply> {
    use crate::toolchain;
    match command {
        ToolsCommand::Doctor { tool, deep } => toolchain::doctor(ctx, deep, tool),
        ToolsCommand::Status => toolchain::run_status(ctx),
        ToolsCommand::Set { tool, path } => toolchain::set(ctx, &toolchain::System, tool, &path),
        ToolsCommand::Unset { tool } => toolchain::unset(ctx, tool),
        ToolsCommand::Setup(crate::SetupCommand::Ghidra(args)) => toolchain::setup(ctx, &args),
        ToolsCommand::Setup(crate::SetupCommand::Replay(args)) => {
            toolchain::setup_replay(ctx, &args)
        }
        ToolsCommand::Analyze {
            project,
            output,
            modules,
            timeout,
        } => toolchain::analyze(ctx, &project, &output, &modules, timeout),
        ToolsCommand::Paths => toolchain::paths(ctx),
    }
}

/// `file GUID name: message`, the wording for a module whose IFR could not be decoded.
///
/// Example: `let line = describe_diagnostic(&diagnostic);`
pub(super) fn describe_diagnostic(diagnostic: &ModuleDiagnostic) -> String {
    let name = diagnostic
        .name
        .as_deref()
        .map(|n| format!(" {n}"))
        .unwrap_or_default();
    format!("file {}{name}: {}", diagnostic.guid, diagnostic.message)
}

/// Open a regular file for reading without blocking on a FIFO or device.
fn open_regular(path: &Path) -> Result<(fs::File, u64)> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| io_error(path, e))?;
    let meta = file.metadata().map_err(|e| io_error(path, e))?;
    if !meta.is_file() {
        return Err(Error::new(
            Code::Io,
            format!("{}: expected a regular file", path.display()),
        ));
    }
    Ok((file, meta.len()))
}

/// Read a regular file, enforcing the bound even if its metadata underreports the size.
/// Example: `read_bounded(Path::new("plan.json"), 16 * 1024 * 1024)?`.
pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let (file, length) = open_regular(path)?;
    if length > limit {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!(
                "{}: {length} bytes exceed the limit of {limit}",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(path, e))?;
    if bytes.len() as u64 > limit {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!(
                "{}: {} bytes exceed the limit of {limit}",
                path.display(),
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

/// Bytes compared per read by [`ensure_file_holds`].
const COMPARE_CHUNK: usize = 1 << 20;

/// Fail with `PLAN_INPUT_CHANGED` unless the file at `path` holds exactly `expected`.
///
/// It streams the file in 1 MiB chunks, so it needs neither a second copy of the image nor a
/// digest of it. Example: `ensure_file_holds(&rom, &planned_input)?` after a plan was built from
/// `planned_input` fails with `(expected 0x00 | received 0xff at offset 0x9000)` when the file was
/// edited meanwhile.
pub fn ensure_file_holds(path: &Path, expected: &[u8]) -> Result<()> {
    let (mut file, _) = open_regular(path)?;
    let changed = |detail: String| {
        Error::new(
            Code::PlanInputChanged,
            format!(
                "{}: changed while building; nothing was written ({detail})",
                path.display()
            ),
        )
    };
    let mut chunk = vec![0u8; COMPARE_CHUNK];
    let mut offset = 0usize;
    while offset < expected.len() {
        let wanted = chunk.len().min(expected.len() - offset);
        let read = match file.read(&mut chunk[..wanted]) {
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_error(path, e)),
        };
        if read == 0 {
            return Err(changed(format!(
                "expected {} bytes | received {offset} bytes",
                expected.len()
            )));
        }
        let held = &expected[offset..offset + read];
        if let Some(at) = chunk[..read].iter().zip(held).position(|(a, b)| a != b) {
            return Err(changed(format!(
                "expected {:#04x} | received {:#04x} at offset {:#x}",
                held[at],
                chunk[at],
                offset + at
            )));
        }
        offset += read;
    }
    let mut extra = [0u8; 1];
    loop {
        match file.read(&mut extra) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(changed(format!(
                    "expected {} bytes | received at least {} bytes",
                    expected.len(),
                    expected.len() + 1
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io_error(path, e)),
        }
    }
}

/// Read and parse a firmware image.
pub fn read_image(path: &Path) -> Result<Image> {
    let bytes = read_bounded(path, MAX_IMAGE_BYTES)?;
    Image::parse(bytes).map_err(|e| e.context(path.display()))
}

/// Load the sources named by `--catalog` (default: official) plus aliases named in qualified ids.
pub fn load_sources(ctx: &Ctx, args: &SourceArgs, select: &[String]) -> Result<Vec<Loaded>> {
    let mut names: Vec<String> = args.catalogs.clone();
    let qualified: Vec<String> = select
        .iter()
        .filter_map(|t| t.split_once("::").map(|(a, _)| a.to_string()))
        .collect();
    if names.is_empty() && (qualified.is_empty() || select.iter().any(|t| !t.contains("::"))) {
        names.push(sources::OFFICIAL.into());
    }
    let policy = LoadPolicy {
        allow_unsigned_local: args.allow_unsigned_local,
    };
    let mut loaded: Vec<Loaded> = Vec::new();
    for (index, name) in names.iter().chain(&qualified).enumerate() {
        if index >= names.len() && loaded.iter().any(|source| source.alias == *name) {
            continue;
        }
        let source = sources::load(name, &ctx.config, &ctx.paths, policy)?;
        if loaded.iter().any(|l| l.alias == source.alias) {
            return Err(Error::new(
                Code::Usage,
                format!("catalog {name}: loaded twice under alias {}", source.alias),
            ));
        }
        loaded.push(source);
    }
    Ok(loaded)
}

/// A parsed selection token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub alias: Option<String>,
    pub id: String,
    pub version: Option<semver::Version>,
}

/// Parse `ID`, `ID@VERSION`, `ALIAS::ID` or `ALIAS::ID@VERSION`.
pub fn parse_token(text: &str) -> Result<Token> {
    let (alias, rest) = match text.split_once("::") {
        Some((a, r)) => (Some(a.to_string()), r),
        None => (None, text),
    };
    let (id, version) = match rest.split_once('@') {
        Some((i, v)) => (
            i,
            Some(semver::Version::parse(v).map_err(|e| {
                Error::new(
                    Code::Usage,
                    format!("selection {text:?}: version {v:?}: {e}"),
                )
            })?),
        ),
        None => (rest, None),
    };
    if id.is_empty() || alias.as_deref() == Some("") {
        return Err(Error::new(
            Code::Usage,
            format!("selection {text:?}: expected ID, ALIAS::ID or ALIAS::ID@VERSION"),
        ));
    }
    Ok(Token {
        alias,
        id: id.to_string(),
        version,
    })
}

#[cfg(test)]
mod bounded_read_tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn actual_read_length_is_bounded_when_metadata_underreports() {
        let path = Path::new("/proc/self/cmdline");
        let metadata = fs::metadata(path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(
            metadata.len(),
            0,
            "procfs fixture must underreport its length"
        );
        let error = read_bounded(path, 1).expect_err(
            "/proc/self/cmdline: expected actual read length <= 1 despite metadata length 0",
        );
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(error.message.contains("/proc/self/cmdline"), "{error}");
        assert!(
            error.message.contains("2 bytes exceed the limit of 1"),
            "{error}"
        );
    }

    #[test]
    fn bounded_read_accepts_exact_limit_and_unlimited_u64() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("exact.bin");
        fs::write(&path, b"exact").unwrap();
        assert_eq!(read_bounded(&path, 5).unwrap(), b"exact");
        assert_eq!(read_bounded(&path, u64::MAX).unwrap(), b"exact");
        let error = read_bounded(&path, 4).unwrap_err();
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(
            error.message.contains("5 bytes exceed the limit of 4"),
            "{error}"
        );
    }
}

#[cfg(test)]
mod ensure_file_holds_tests {
    use super::*;

    /// Two chunks and a bit, so a difference can land past the first read.
    fn planned() -> Vec<u8> {
        (0..COMPARE_CHUNK * 2 + 5)
            .map(|i| (i % 251) as u8)
            .collect()
    }

    fn file_with(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rom.bin");
        fs::write(&path, bytes).unwrap();
        (directory, path)
    }

    #[test]
    fn an_identical_file_passes() {
        let bytes = planned();
        let (_directory, path) = file_with(&bytes);
        ensure_file_holds(&path, &bytes).expect("same bytes are unchanged");
        let (_empty, empty) = file_with(b"");
        ensure_file_holds(&empty, b"").expect("two empty files match");
    }

    #[test]
    fn a_flipped_byte_past_the_first_chunk_names_its_offset_and_values() {
        let bytes = planned();
        let mut edited = bytes.clone();
        let at = COMPARE_CHUNK + 2;
        edited[at] ^= 0xFF;
        let (_directory, path) = file_with(&edited);
        let error = ensure_file_holds(&path, &bytes).unwrap_err();
        assert_eq!(error.code, Code::PlanInputChanged);
        let want = format!(
            "expected {:#04x} | received {:#04x} at offset {at:#x}",
            bytes[at], edited[at]
        );
        assert!(
            error.message.contains(&want),
            "(edited input): expected {want:?} | received {}",
            error.message
        );
    }

    #[test]
    fn a_shorter_file_names_how_far_it_reached() {
        let bytes = planned();
        let (_directory, path) = file_with(&bytes[..COMPARE_CHUNK + 7]);
        let error = ensure_file_holds(&path, &bytes).unwrap_err();
        assert_eq!(error.code, Code::PlanInputChanged);
        let want = format!(
            "expected {} bytes | received {} bytes",
            bytes.len(),
            COMPARE_CHUNK + 7
        );
        assert!(
            error.message.contains(&want),
            "(truncated input): expected {want:?} | received {}",
            error.message
        );
    }

    #[test]
    fn a_longer_file_is_refused() {
        let bytes = planned();
        let mut grown = bytes.clone();
        grown.push(0);
        let (_directory, path) = file_with(&grown);
        let error = ensure_file_holds(&path, &bytes).unwrap_err();
        assert_eq!(error.code, Code::PlanInputChanged);
        let want = format!(
            "expected {} bytes | received at least {} bytes",
            bytes.len(),
            bytes.len() + 1
        );
        assert!(
            error.message.contains(&want),
            "(grown input): expected {want:?} | received {}",
            error.message
        );
    }

    #[test]
    fn a_missing_file_is_an_io_error_naming_the_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gone.bin");
        let error = ensure_file_holds(&path, b"x").unwrap_err();
        assert_eq!(error.code, Code::Io);
        assert!(
            error.message.contains("gone.bin"),
            "(missing input): expected the path in the message | received {}",
            error.message
        );
    }
}

#[cfg(test)]
mod diagnostic_wording_tests {
    use super::*;
    use biosmod_core::util::Guid;

    fn diagnostic(name: Option<&str>) -> ModuleDiagnostic {
        ModuleDiagnostic {
            guid: Guid::constant("00000000-0000-0000-0000-0000000000B1"),
            name: name.map(str::to_owned),
            code: Code::FormatInvalid,
            message: "bad package".to_owned(),
        }
    }

    #[test]
    fn describe_diagnostic_names_the_file_guid_and_the_module_when_known() {
        assert_eq!(
            describe_diagnostic(&diagnostic(Some("Setup"))),
            "file 00000000-0000-0000-0000-0000000000B1 Setup: bad package"
        );
        assert_eq!(
            describe_diagnostic(&diagnostic(None)),
            "file 00000000-0000-0000-0000-0000000000B1: bad package"
        );
    }
}
