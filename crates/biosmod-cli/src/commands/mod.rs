//! Command implementations. Each returns a [`Reply`] or a typed error; printing happens in `main`.

mod catalog;
mod diag;
mod firmware;
mod meta;

use crate::config::{Config, Paths, io_error};
use crate::output::{Out, Reply};
use crate::sources::{self, LoadPolicy, Loaded};
use crate::{Command, DevCommand, DiagCommand, SourceArgs, ToolsCommand};
use biosmod_core::catalog::LeafKind;
use biosmod_core::firmware::Image;
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
        Command::Scan(args) => firmware::scan(&ctx, &args),
        Command::Plan(args) => firmware::plan(&ctx, &args),
        Command::Patch(args) => firmware::patch(&ctx, &args),
        Command::Verify(args) => firmware::verify(&ctx, &args),
        Command::Extract(args) => firmware::extract(&args),
        Command::Replace(args) => firmware::replace(&args),
        Command::Derive(args) => firmware::derive(&ctx, &args),
        Command::Catalog(sub) => catalog::run(&mut ctx, sub),
        Command::Tools(sub) => tools(&ctx, sub),
        Command::Diag(DiagCommand::Breadcrumbs(sub)) => diag::breadcrumbs(sub),
        Command::Dev(DevCommand::Synthetic { output }) => diag::synthetic(&output),
    }
}

fn tools(ctx: &Ctx, command: ToolsCommand) -> Result<Reply> {
    use crate::toolchain;
    match command {
        ToolsCommand::Doctor { deep } => toolchain::doctor(ctx, deep),
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

/// Read a file with a size bound.
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
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(path, e))?;
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
    for alias in qualified {
        if !names.contains(&alias) {
            names.push(alias);
        }
    }
    let policy = LoadPolicy {
        allow_unsigned_local: args.allow_unsigned_local,
    };
    let mut loaded: Vec<Loaded> = Vec::new();
    for name in names {
        let source = sources::load(&name, &ctx.config, &ctx.paths, policy)?;
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
