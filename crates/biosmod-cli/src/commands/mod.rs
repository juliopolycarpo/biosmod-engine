//! Command implementations. Each returns a [`Reply`] or a typed error; printing happens in `main`.

mod catalog;
mod compare;
mod compare_acpi;
mod diag;
mod firmware;
mod host;
mod ifr;
mod meta;
mod nvram;

use crate::config::{Config, Paths, io_error};
use crate::output::{Out, Reply};
use crate::sources::{self, LoadPolicy, Loaded};
use crate::{Command, DevCommand, DiagCommand, SourceArgs, ToolsCommand};
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
        Command::Tools(sub) => tools(&ctx, sub),
        Command::Diag(DiagCommand::Breadcrumbs(sub)) => diag::breadcrumbs(sub),
        Command::Diag(DiagCommand::Acpi(_) | DiagCommand::Superio(_) | DiagCommand::Suspend(_)) => {
            unreachable!("host diagnostics return before configuration")
        }
        Command::Dev(DevCommand::Synthetic { output }) => diag::synthetic(&output),
        Command::Flash(_) => unreachable!("flash commands return before configuration loads"),
    }
}

fn tools(ctx: &Ctx, command: ToolsCommand) -> Result<Reply> {
    use crate::toolchain;
    match command {
        ToolsCommand::Doctor { deep } => toolchain::doctor(ctx, deep),
        ToolsCommand::Status => toolchain::run_status(ctx),
        ToolsCommand::Set { tool, path } => toolchain::set(ctx, &toolchain::System, tool, &path),
        ToolsCommand::Unset { tool } => toolchain::unset(ctx, tool),
        ToolsCommand::Setup(crate::SetupCommand::Ghidra(args)) => toolchain::setup(ctx, &args),
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

/// Read a regular file, enforcing the bound even if its metadata underreports the size.
/// Example: `read_bounded(Path::new("plan.json"), 16 * 1024 * 1024)?`.
pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
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
    if meta.len() > limit {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!(
                "{}: {} bytes exceed the limit of {limit}",
                path.display(),
                meta.len()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
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
