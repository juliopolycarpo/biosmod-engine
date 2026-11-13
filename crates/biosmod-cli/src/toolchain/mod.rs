//! Ghidra tooling: pinned installation, read-only doctor and headless analysis.
//!
//! Archives are verified against pinned SHA-256 digests before extraction,
//! extracted with path, symlink, size and count limits into a staging
//! directory, and only then moved into place. External programs run through
//! the [`Runner`] interface so tests can substitute a named fake.

mod archive;
mod replay;
mod runner;
mod status;
// Setup is Linux-only for now; the fakes model a Unix layout.
#[cfg(all(test, unix))]
mod tests;

pub use archive::{Limits, extract_zip};
pub use replay::package::digest as replay_package_digest;
pub use replay::script::{ScriptOutput, ScriptRun};
pub use replay::{ReplaySetupArgs, Versions};
pub use runner::{Finished, Invocation, Runner, System};
pub use status::{Locatable, TOOL_IDS, run_status, set, unset};

use crate::commands::Ctx;
use crate::config::{Config, io_error, write_atomic};
use crate::output::{Reply, display_path};
use crate::transport::{Https, Offline, Transport};
use biosmod_core::{Code, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The pinned tool profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub ghidra_version: String,
    pub ghidra_dirname: String,
    pub ghidra_url: String,
    pub ghidra_sha256: String,
    pub gradle_version: String,
    pub gradle_url: String,
    pub gradle_sha256: String,
    pub firmware_utils_repository: String,
    pub firmware_utils_commit: String,
    pub java_min: u32,
}

impl Profile {
    /// The profile this release of bme was tested with.
    pub fn pinned() -> Profile {
        Profile {
            ghidra_version: "12.2".into(),
            ghidra_dirname: "ghidra_12.2_PUBLIC".into(),
            ghidra_url: "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip".into(),
            ghidra_sha256: "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67".into(),
            gradle_version: "9.3.1".into(),
            gradle_url: "https://services.gradle.org/distributions/gradle-9.3.1-bin.zip".into(),
            gradle_sha256: "b266d5ff6b90eada6dc3b20cb090e3731302e553a27c5d3e4df1f0d76beaff06".into(),
            firmware_utils_repository: "https://github.com/al3xtjames/ghidra-firmware-utils.git".into(),
            firmware_utils_commit: "2361aa838b1aaf2575edb14d33f6bc84ec37490a".into(),
            java_min: 21,
        }
    }
}

/// Embedded Ghidra scripts and the extension patch (see tools/ghidra/NOTICE).
pub const SCRIPTS: &[(&str, &[u8])] = &[
    (
        "ExportFirmware.java",
        include_bytes!("../../../../tools/ghidra/ExportFirmware.java"),
    ),
    (
        "ExportSelectedFirmware.java",
        include_bytes!("../../../../tools/ghidra/ExportSelectedFirmware.java"),
    ),
    (
        "PeimUEFIHelper.java",
        include_bytes!("../../../../tools/ghidra/PeimUEFIHelper.java"),
    ),
    (
        "SeedFirmwareCallbacks.java",
        include_bytes!("../../../../tools/ghidra/SeedFirmwareCallbacks.java"),
    ),
    (
        "SetupFirmwareMemory.java",
        include_bytes!("../../../../tools/ghidra/SetupFirmwareMemory.java"),
    ),
    ("NOTICE", include_bytes!("../../../../tools/ghidra/NOTICE")),
    (
        "LICENSE-Apache-2.0.txt",
        include_bytes!("../../../../tools/ghidra/LICENSE-Apache-2.0.txt"),
    ),
];
const EXTENSION_PATCH: &[u8] =
    include_bytes!("../../../../tools/ghidra/ghidra-firmware-utils-12.2.patch");
const EXTENSION: &str = "ghidra-firmware-utils";
const MARKER: &str = "bme-install.json";

/// Appended to a missing extension's detail; `tools status` drops it where setup cannot run.
const SETUP_HINT: &str = " (run `bme tools setup ghidra`)";
const DOWNLOAD_LIMIT: u64 = 2 << 30;

#[derive(Debug, Clone, clap::Args)]
pub struct SetupArgs {
    /// Install directory (default: <data dir>/tools).
    #[arg(long)]
    pub prefix: Option<PathBuf>,
    /// Use a local copy of the pinned Ghidra archive (still hash-checked).
    #[arg(long)]
    pub ghidra_zip: Option<PathBuf>,
    /// Use an existing Gradle installation of the pinned version.
    #[arg(long)]
    pub gradle_home: Option<PathBuf>,
    /// Clone ghidra-firmware-utils from a local repository instead of GitHub.
    #[arg(long)]
    pub firmware_utils_src: Option<PathBuf>,
    /// Replace an installation not made by this profile.
    #[arg(long)]
    pub force: bool,
    /// Skip the final headless startup check.
    #[arg(long)]
    pub skip_check: bool,
}

/// Everything setup and doctor need from the outside world.
pub struct Env<'a> {
    pub runner: &'a dyn Runner,
    pub transport: &'a dyn Transport,
    pub offline: bool,
    pub data: PathBuf,
    pub cache: PathBuf,
    pub profile: Profile,
}

/// Where a Ghidra installation came from.
#[derive(Debug, Clone, Serialize)]
pub struct GhidraHome {
    #[serde(serialize_with = "crate::output::serialize_display_path")]
    pub path: PathBuf,
    pub origin: &'static str,
}

/// Resolve the Ghidra home: `GHIDRA_INSTALL_DIR`, then configuration, then the managed install.
pub fn ghidra_home(config: &Config, data: &Path, profile: &Profile) -> GhidraHome {
    if let Some(dir) = std::env::var_os("GHIDRA_INSTALL_DIR").filter(|v| !v.is_empty()) {
        return GhidraHome {
            path: PathBuf::from(dir),
            origin: "GHIDRA_INSTALL_DIR",
        };
    }
    if let Some(dir) = &config.tools.ghidra_home {
        return GhidraHome {
            path: dir.clone(),
            origin: "config",
        };
    }
    GhidraHome {
        path: data.join("tools").join(&profile.ghidra_dirname),
        origin: "managed",
    }
}

fn headless(home: &Path) -> PathBuf {
    let name = if cfg!(windows) {
        "analyzeHeadless.bat"
    } else {
        "analyzeHeadless"
    };
    home.join("support").join(name)
}

fn extension_dir(home: &Path) -> PathBuf {
    home.join("Ghidra").join("Extensions").join(EXTENSION)
}

/// A `key=value` property from a Java properties file.
fn property(path: &Path, key: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    text.lines().find_map(|l| {
        l.trim()
            .strip_prefix(key)?
            .trim_start()
            .strip_prefix('=')
            .map(|v| v.trim().to_string())
    })
}

/// Major version from `javac -version` / `java -version` output.
pub fn java_major(output: &str) -> Option<u32> {
    let token = output
        .split(|c: char| c.is_whitespace() || c == '"')
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
    let mut parts = token.split(['.', '-', '+', '_']);
    let first: u32 = parts.next()?.parse().ok()?;
    if first == 1 {
        parts.next()?.parse().ok()
    } else {
        Some(first)
    }
}

/// One doctor finding.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub check: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn check(name: &'static str, ok: bool, detail: impl Into<String>) -> Check {
    Check {
        check: name,
        ok,
        detail: detail.into(),
    }
}

/// Run `program -version` within `timeout` and compare its major release with `min`.
///
/// Example: `java_check(runner, "javac", 21, Duration::from_secs(60))` is ok for `javac 21.0.5`.
fn java_check(runner: &dyn Runner, program: &'static str, min: u32, timeout: Duration) -> Check {
    let name = if program == "javac" { "jdk" } else { "java" };
    let finished = match runner.run(&Invocation::new(program).arg("-version").timeout(timeout)) {
        Ok(f) => f,
        Err(e) => {
            return check(
                name,
                false,
                format!(
                    "{program}: {} (Ubuntu: apt install openjdk-{min}-jdk)",
                    e.message
                ),
            );
        }
    };
    match java_major(&format!("{}\n{}", finished.stdout, finished.stderr)) {
        Some(v) if v >= min => check(name, true, format!("{program} {v}")),
        Some(v) => check(
            name,
            false,
            format!("{program}: expected version >= {min} | received {v}"),
        ),
        None => check(
            name,
            false,
            format!("{program}: could not read a version from its output"),
        ),
    }
}

/// The Ghidra release recorded in `home`, from `Ghidra/application.properties`.
///
/// Example: `ghidra_version(Path::new("/opt/ghidra_12.2_PUBLIC"))` is `Some("12.2")`.
pub fn ghidra_version(home: &Path) -> Option<String> {
    property(
        &home.join("Ghidra/application.properties"),
        "application.version",
    )
}

/// Read-only installation checks.
pub fn inspect(env: &Env, home: &GhidraHome) -> Vec<Check> {
    let mut checks = vec![java_check(
        env.runner,
        "java",
        env.profile.java_min,
        Duration::from_secs(60),
    )];
    checks.extend(ghidra_checks(env, home));
    checks
}

/// Checks of the Ghidra directory, its version and the firmware-utils extension.
fn ghidra_checks(env: &Env, home: &GhidraHome) -> Vec<Check> {
    let mut checks = Vec::new();
    let script = headless(&home.path);
    checks.push(check(
        "ghidra",
        script.is_file(),
        format!("{} ({})", home.path.display(), home.origin),
    ));
    let version = ghidra_version(&home.path);
    let version_ok = version.as_deref() == Some(env.profile.ghidra_version.as_str());
    let detail = match &version {
        Some(v) if version_ok => v.clone(),
        Some(v) => format!(
            "expected {} | received {v}; analysis scripts are tested on {} only",
            env.profile.ghidra_version, env.profile.ghidra_version
        ),
        None => "application.properties not found".into(),
    };
    checks.push(check("ghidra-version", version_ok, detail));
    let extension = extension_dir(&home.path);
    let data_ok = extension.join("data").is_dir();
    let ext_version = property(&extension.join("extension.properties"), "version");
    let compatible = data_ok && (ext_version.is_none() || ext_version == version);
    let detail = match (data_ok, &ext_version) {
        (false, _) => format!("{}: not installed{SETUP_HINT}", extension.display()),
        (true, Some(v)) if !compatible => format!(
            "built for Ghidra {v} | installed Ghidra {}",
            version.as_deref().unwrap_or("unknown")
        ),
        (true, v) => format!(
            "{} (for Ghidra {})",
            extension.display(),
            v.as_deref().unwrap_or("unknown")
        ),
    };
    checks.push(check("firmware-utils", compatible, detail));
    checks
}

/// Start Ghidra headless and import a tiny raw file without analysis.
pub fn startup_check(runner: &dyn Runner, home: &Path) -> Check {
    // Ghidra refuses project locations below hidden directories such as `/tmp/.tmpXXXX`.
    let Ok(work) = tempfile::Builder::new().prefix("bme-probe-").tempdir() else {
        return check(
            "headless-startup",
            false,
            "could not create a temporary directory",
        );
    };
    let probe = work.path().join("probe.bin");
    if fs::write(&probe, [0x90u8; 16]).is_err() {
        return check("headless-startup", false, "could not write the probe file");
    }
    let invocation = Invocation::new(headless(home))
        .arg(work.path().join("project"))
        .arg("bmeprobe")
        .arg("-import")
        .arg(&probe)
        .args([
            "-loader",
            "BinaryLoader",
            "-processor",
            "x86:LE:32:default",
            "-noanalysis",
            "-deleteProject",
        ])
        .timeout(Duration::from_secs(600));
    let _ = fs::create_dir_all(work.path().join("project"));
    match runner.run(&invocation) {
        Ok(f) if f.success() && f.output().contains("Import succeeded") => {
            check("headless-startup", true, "imported a probe file")
        }
        Ok(f) => check(
            "headless-startup",
            false,
            format!("analyzeHeadless {}: {}", f.describe(), f.tail(400)),
        ),
        Err(e) => check("headless-startup", false, e.message),
    }
}

fn checks_reply(checks: Vec<Check>, context: Value) -> Result<Reply> {
    let mut text = String::new();
    for c in &checks {
        text += &format!(
            "  {:<5} {:<17} {}\n",
            if c.ok { "ok" } else { "FAIL" },
            c.check,
            c.detail
        );
    }
    let failed: Vec<&str> = checks.iter().filter(|c| !c.ok).map(|c| c.check).collect();
    let mut data = context;
    data["checks"] = json!(checks);
    if failed.is_empty() {
        return Ok(Reply::new(data, text));
    }
    eprint!("{text}");
    Err(Error::new(
        Code::ToolUnavailable,
        format!("tools doctor: failed checks: {}", failed.join(", ")),
    )
    .with_details(data))
}

fn env<'a>(ctx: &Ctx, runner: &'a dyn Runner, transport: &'a dyn Transport) -> Env<'a> {
    Env {
        runner,
        transport,
        offline: ctx.offline,
        data: ctx.paths.data.clone(),
        cache: ctx.paths.cache.clone(),
        profile: Profile::pinned(),
    }
}

/// Run a replay harness in the resolved replay runtime.
///
/// Example: `run_replay_script(ctx, &ScriptRun { harness, modules: &[], args: &[], timeout })`
/// fails with `ToolUnavailable` and the setup command when the runtime is not installed.
pub fn run_replay_script(ctx: &Ctx, run: &ScriptRun) -> Result<ScriptOutput> {
    let env = env(ctx, &System, &Offline);
    replay::script::run_script(&env, &replay_home_now(ctx), run)
}

/// Tools `tools doctor` can be limited to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum DoctorTool {
    /// The JDK, Ghidra and its extension.
    Ghidra,
    /// The Python runtime for `bme replay`.
    Replay,
}

/// Replay lookup from the process environment.
fn replay_home_now(ctx: &Ctx) -> replay::ReplayHome {
    replay::replay_home(
        &|key| std::env::var_os(key).filter(|v| !v.is_empty()),
        &ctx.config,
        &ctx.paths.data,
    )
}

/// `tools doctor`: Ghidra checks, plus the replay runtime once one is installed or chosen.
///
/// `only` limits the report to one tool; `doctor replay` also fails when the runtime is missing.
pub fn doctor(ctx: &Ctx, deep: bool, only: Option<DoctorTool>) -> Result<Reply> {
    let env = env(ctx, &System, &Offline);
    let mut checks = Vec::new();
    let mut context = json!({});
    if only != Some(DoctorTool::Replay) {
        let home = ghidra_home(&ctx.config, &env.data, &env.profile);
        checks.extend(inspect(&env, &home));
        if deep && checks.iter().all(|c| c.ok) {
            checks.push(startup_check(env.runner, &home.path));
        }
        context["ghidra_home"] = json!(home);
    }
    let replay = replay_home_now(ctx);
    // Without a tool named, a runtime nobody installed is not a failure of `tools doctor`.
    if only == Some(DoctorTool::Replay) || replay.python.is_file() {
        checks.extend(replay::replay_checks(&env, &replay, deep));
        context["replay"] = json!(replay);
    }
    checks_reply(checks, context)
}

/// The flashrom a chip command would run, as `tools paths` reports it to the desktop app.
///
/// Example: `flashrom_location(&|_| None, Some(Path::new("/opt/fr/flashrom")))` is
/// `{"path": "/opt/fr/flashrom", "origin": "config"}`. A relative path is made absolute.
fn flashrom_location(
    get: &dyn Fn(&str) -> Option<std::ffi::OsString>,
    configured: Option<&Path>,
) -> Option<Value> {
    crate::flash::resolve_flashrom(get, configured).map(|(path, origin)| {
        // pkexec starts root in another directory, so a relative override must not reach it.
        let path = std::path::absolute(&path).unwrap_or(path);
        json!({"path": display_path(&path), "origin": origin.label()})
    })
}

pub fn paths(ctx: &Ctx) -> Result<Reply> {
    let profile = Profile::pinned();
    let home = ghidra_home(&ctx.config, &ctx.paths.data, &profile);
    let get = |key: &str| std::env::var_os(key);
    let flashrom = flashrom_location(&get, ctx.config.tools.flashrom.as_deref());
    let replay = replay_home_now(ctx);
    let data = json!({"config": display_path(&ctx.paths.config_file()), "cache": display_path(&ctx.paths.cache), "data": display_path(&ctx.paths.data), "ghidra_home": home, "flashrom": flashrom, "replay": replay, "profile": profile});
    let text = format!(
        "config   {}\ncache    {}\ndata     {}\nghidra   {} ({})\n",
        ctx.paths.config_file().display(),
        ctx.paths.cache.display(),
        ctx.paths.data.display(),
        home.path.display(),
        home.origin
    );
    Ok(Reply::new(data, text))
}

pub fn setup(ctx: &Ctx, args: &SetupArgs) -> Result<Reply> {
    if !cfg!(target_os = "linux") {
        return Err(Error::new(
            Code::PlatformUnsupported,
            "tools setup ghidra: Linux only for now; install Ghidra 12.2 by hand and set tools.ghidra_home",
        ));
    }
    let https = Https::pinned_artifacts();
    let transport: &dyn Transport = if ctx.offline { &Offline } else { &https };
    let env = env(ctx, &System, transport);
    let installed = install(&env, args, &mut |m| ctx.out.note(m))?;
    if args.prefix.is_some() {
        let mut config = ctx.config.clone();
        config.tools.ghidra_home = Some(installed.ghidra.clone());
        config.save(&ctx.paths)?;
    }
    let text = format!(
        "Ghidra {} ready at {}\nExtension at {}\nNext: bme extract dump.bin --guid <GUID> -o module.pe && bme tools analyze --project work/project --output work/exports module.pe\n",
        env.profile.ghidra_version,
        installed.ghidra.display(),
        installed.extension.display()
    );
    Ok(Reply::new(installed, text))
}

/// `tools setup replay`: create the Python environment with the hash-locked packages.
pub fn setup_replay(ctx: &Ctx, args: &ReplaySetupArgs) -> Result<Reply> {
    let env = env(ctx, &System, &Offline);
    let installed = replay::install_replay(&env, args, &mut |m| ctx.out.note(m))?;
    let shadow = replay_home_now(ctx);
    if shadow.origin != "managed" {
        ctx.out.note(format!(
            "{} ({}) still wins over this environment; run `bme tools unset replay` or unset the variable to use it",
            shadow.python.display(),
            shadow.origin
        ));
    }
    let text = format!(
        "Replay runtime {} at {}\n{}\nCheck it with: bme tools doctor replay --deep\n",
        if installed.installed {
            "ready"
        } else {
            "already ready"
        },
        installed.python.display(),
        installed.versions.summary()
    );
    Ok(Reply::new(installed, text))
}

/// Result of a successful setup.
#[derive(Debug, Clone, Serialize)]
pub struct Installed {
    #[serde(serialize_with = "crate::output::serialize_display_path")]
    pub ghidra: PathBuf,
    #[serde(serialize_with = "crate::output::serialize_display_path")]
    pub extension: PathBuf,
    pub profile: Profile,
    pub startup_check: Option<bool>,
}

fn failed(message: impl Into<String>) -> Error {
    Error::new(Code::ToolSetupFailed, message.into())
}

/// Run the full installation.
pub fn install(env: &Env, args: &SetupArgs, note: &mut dyn FnMut(&str)) -> Result<Installed> {
    if env.offline
        && (args.ghidra_zip.is_none()
            || args.gradle_home.is_none()
            || args.firmware_utils_src.is_none())
    {
        return Err(Error::new(
            Code::SourceUnavailable,
            "--offline setup needs --ghidra-zip, --gradle-home and --firmware-utils-src (Gradle also runs with --offline)",
        ));
    }
    let java = java_check(
        env.runner,
        "javac",
        env.profile.java_min,
        Duration::from_secs(60),
    );
    if !java.ok {
        return Err(Error::new(Code::ToolUnavailable, java.detail));
    }
    let git = env.runner.run(
        &Invocation::new("git")
            .arg("--version")
            .timeout(Duration::from_secs(60)),
    );
    if !git.as_ref().is_ok_and(Finished::success) {
        return Err(Error::new(
            Code::ToolUnavailable,
            "git: not found (Ubuntu: apt install git)",
        ));
    }
    let prefix = args
        .prefix
        .clone()
        .unwrap_or_else(|| env.data.join("tools"));
    fs::create_dir_all(&prefix).map_err(|e| io_error(&prefix, e))?;
    let zip = ghidra_archive(env, args, note)?;
    let gradle = gradle_home(env, args, note)?;
    let ghidra = install_ghidra(env, &prefix, &zip, args.force, note)?;
    let source = prepare_source(env, args, note)?;
    let built = build_extension(env, &ghidra, &gradle, &source, note)?;
    let extension = install_extension(env, &ghidra, &built, args.force, note)?;
    let startup = if args.skip_check {
        None
    } else {
        note("checking headless startup");
        let result = startup_check(env.runner, &ghidra);
        if !result.ok {
            return Err(failed(format!(
                "installed, but the startup check failed: {}",
                result.detail
            )));
        }
        Some(true)
    };
    Ok(Installed {
        ghidra,
        extension,
        profile: env.profile.clone(),
        startup_check: startup,
    })
}

/// SHA-256 of a file, streamed.
pub fn file_sha256(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|e| io_error(path, e))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer).map_err(|e| io_error(path, e))?;
        if n == 0 {
            return Ok(biosmod_core::util::hex(&hasher.finalize()));
        }
        hasher.update(&buffer[..n]);
    }
}

fn verify(path: &Path, expected: &str, label: &str) -> Result<()> {
    let actual = file_sha256(path)?;
    if actual != expected {
        return Err(failed(format!(
            "{label} SHA-256: expected {expected} | received {actual} ({})",
            path.display()
        )));
    }
    Ok(())
}

/// Download `url` to `target` unless a verified copy is already cached.
fn fetch(
    env: &Env,
    url: &str,
    sha256: &str,
    target: &Path,
    note: &mut dyn FnMut(&str),
) -> Result<()> {
    if target.is_file() {
        if verify(target, sha256, url).is_ok() {
            return Ok(());
        }
        note(&format!(
            "discarding cached {} (digest mismatch)",
            target.display()
        ));
        fs::remove_file(target).map_err(|e| io_error(target, e))?;
    }
    let dir = target.parent().expect("cache file has a parent");
    fs::create_dir_all(dir).map_err(|e| io_error(dir, e))?;
    note(&format!("downloading {url}"));
    let mut staged = tempfile::Builder::new()
        .prefix(".partial-")
        .tempfile_in(dir)
        .map_err(|e| io_error(dir, e))?;
    env.transport
        .download(url, staged.as_file_mut(), DOWNLOAD_LIMIT)?;
    staged
        .as_file_mut()
        .flush()
        .map_err(|e| io_error(staged.path(), e))?;
    verify(staged.path(), sha256, url)?;
    staged
        .persist(target)
        .map_err(|e| io_error(target, e.error))?;
    Ok(())
}

fn file_name(url: &str) -> &str {
    url.rsplit('/').next().unwrap_or(url)
}

fn ghidra_archive(env: &Env, args: &SetupArgs, note: &mut dyn FnMut(&str)) -> Result<PathBuf> {
    let profile = &env.profile;
    if let Some(zip) = &args.ghidra_zip {
        verify(
            zip,
            &profile.ghidra_sha256,
            &format!("Ghidra {} archive", profile.ghidra_version),
        )?;
        return Ok(zip.clone());
    }
    let target = env
        .cache
        .join("downloads")
        .join(file_name(&profile.ghidra_url));
    fetch(
        env,
        &profile.ghidra_url,
        &profile.ghidra_sha256,
        &target,
        note,
    )?;
    Ok(target)
}

fn gradle_home(env: &Env, args: &SetupArgs, note: &mut dyn FnMut(&str)) -> Result<PathBuf> {
    let profile = &env.profile;
    let wanted = format!("Gradle {}", profile.gradle_version);
    if let Some(home) = &args.gradle_home {
        let output = env.runner.run(
            &Invocation::new(home.join("bin/gradle"))
                .arg("--version")
                .timeout(Duration::from_secs(300)),
        )?;
        if !output.output().lines().any(|l| l.trim() == wanted) {
            return Err(Error::new(
                Code::ToolUnavailable,
                format!("--gradle-home: expected {wanted} at {}", home.display()),
            ));
        }
        return Ok(home.clone());
    }
    let home = env.cache.join(format!("gradle-{}", profile.gradle_version));
    check_recovery(&home)?;
    if home.join(MARKER).is_file() && home.join("bin/gradle").is_file() {
        return Ok(home);
    }
    let zip = env
        .cache
        .join("downloads")
        .join(file_name(&profile.gradle_url));
    fetch(env, &profile.gradle_url, &profile.gradle_sha256, &zip, note)?;
    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(&env.cache)
        .map_err(|e| io_error(&env.cache, e))?;
    extract_zip(&zip, staging.path(), Limits::TOOL)?;
    let unpacked = staging
        .path()
        .join(format!("gradle-{}", profile.gradle_version));
    if !unpacked.join("bin/gradle").is_file() {
        return Err(failed(format!(
            "Gradle archive: expected gradle-{}/bin/gradle",
            profile.gradle_version
        )));
    }
    write_marker(&unpacked, profile)?;
    replace_dir(&unpacked, &home)?;
    Ok(home)
}

fn write_marker(dir: &Path, profile: &Profile) -> Result<()> {
    write_atomic(
        &dir.join(MARKER),
        &serde_json::to_vec_pretty(profile).expect("profile serializes"),
    )
}

fn marker_matches(dir: &Path, profile: &Profile) -> bool {
    fs::read(dir.join(MARKER))
        .ok()
        .and_then(|b| serde_json::from_slice::<Profile>(&b).ok())
        .is_some_and(|p| p == *profile)
}

/// Name the retained previous directory for one installation target.
///
/// Example: `ghidra_12.2_PUBLIC` uses `.bme-backup-ghidra_12.2_PUBLIC`.
fn backup_path(target: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".bme-backup-");
    name.push(target.file_name().expect("target has a filename"));
    target.with_file_name(name)
}

/// Refuse to overwrite a retained backup from an interrupted replacement.
///
/// Example: an orphan `.bme-old-123` requires inspection before setup proceeds.
fn check_recovery(target: &Path) -> Result<()> {
    let parent = target.parent().expect("target has a parent");
    let backup = backup_path(target);
    match fs::symlink_metadata(&backup) {
        Ok(_) => {
            return Err(failed(format!(
                "{}: retained backup {} requires inspection and recovery before setup",
                target.display(),
                backup.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error(&backup, e)),
    }
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_error(parent, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| io_error(parent, e))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name
            .strip_prefix(".bme-old-")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|c| c.is_ascii_digit()))
        {
            return Err(failed(format!(
                "{}: legacy backup {} requires inspection and recovery before setup",
                target.display(),
                entry.path().display()
            )));
        }
    }
    Ok(())
}

/// Replace a directory in two renames, retaining a named backup across interruption.
///
/// Example: replacing `tools/ghidra` retains `tools/.bme-backup-ghidra` until activation.
fn replace_dir(staged: &Path, target: &Path) -> Result<()> {
    check_recovery(target)?;
    let old = backup_path(target);
    let had_old = fs::symlink_metadata(target).is_ok();
    if had_old {
        fs::rename(target, &old).map_err(|e| io_error(target, e))?;
    }
    if let Err(e) = fs::rename(staged, target) {
        if had_old && let Err(restore_error) = fs::rename(&old, target) {
            return Err(failed(format!(
                "{}: activation failed ({e}); previous installation remains at {} (restore failed: {restore_error})",
                target.display(),
                old.display()
            )));
        }
        return Err(io_error(target, e));
    }
    if had_old {
        fs::remove_dir_all(&old).map_err(|e| {
            failed(format!(
                "{}: installed, but retained backup {} could not be removed: {e}",
                target.display(),
                old.display()
            ))
        })?;
    }
    Ok(())
}

fn install_ghidra(
    env: &Env,
    prefix: &Path,
    zip: &Path,
    force: bool,
    note: &mut dyn FnMut(&str),
) -> Result<PathBuf> {
    let profile = &env.profile;
    let target = prefix.join(&profile.ghidra_dirname);
    check_recovery(&target)?;
    if marker_matches(&target, profile) && headless(&target).is_file() {
        note(&format!("Ghidra already installed at {}", target.display()));
        return Ok(target);
    }
    if target.exists() && !force {
        return Err(failed(format!(
            "{}: exists but was not installed by this profile; pass --force to replace it",
            target.display()
        )));
    }
    note(&format!("unpacking Ghidra into {}", prefix.display()));
    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(prefix)
        .map_err(|e| io_error(prefix, e))?;
    extract_zip(zip, staging.path(), Limits::TOOL)?;
    let unpacked = staging.path().join(&profile.ghidra_dirname);
    if !headless(&unpacked).is_file() {
        return Err(failed(format!(
            "Ghidra archive: expected {}/support/analyzeHeadless",
            profile.ghidra_dirname
        )));
    }
    write_marker(&unpacked, profile)?;
    replace_dir(&unpacked, &target)?;
    Ok(target)
}

fn git(env: &Env, args: &[&str], cwd: Option<&Path>) -> Result<Finished> {
    let mut invocation = Invocation::new("git")
        .args(args.iter().copied())
        .timeout(Duration::from_secs(900));
    if let Some(dir) = cwd {
        invocation = invocation.arg_first("-C", dir);
    }
    env.runner.run(&invocation)
}

fn require(finished: Finished, what: &str) -> Result<Finished> {
    if finished.success() {
        return Ok(finished);
    }
    Err(failed(format!(
        "{what}: {}: {}",
        finished.describe(),
        finished.tail(600)
    )))
}

fn prepare_source(env: &Env, args: &SetupArgs, note: &mut dyn FnMut(&str)) -> Result<PathBuf> {
    let profile = &env.profile;
    let src = env.cache.join(EXTENSION);
    if let Some(local) = &args.firmware_utils_src {
        if src.exists() {
            fs::remove_dir_all(&src).map_err(|e| io_error(&src, e))?;
        }
        let from = local.to_string_lossy().into_owned();
        require(
            git(
                env,
                &["clone", "--quiet", &from, &src.to_string_lossy()],
                None,
            )?,
            "git clone (local)",
        )?;
    } else if !src.join(".git").is_dir() {
        note(&format!("cloning {}", profile.firmware_utils_repository));
        require(
            git(
                env,
                &[
                    "clone",
                    "--quiet",
                    &profile.firmware_utils_repository,
                    &src.to_string_lossy(),
                ],
                None,
            )?,
            "git clone",
        )?;
    }
    let commit = profile.firmware_utils_commit.as_str();
    let _ = git(env, &["fetch", "--quiet", "origin", commit], Some(&src));
    require(
        git(env, &["checkout", "--quiet", "--force", commit], Some(&src))?,
        &format!("ghidra-firmware-utils commit {commit}"),
    )?;
    require(git(env, &["clean", "-qfdx"], Some(&src))?, "git clean")?;
    let head = require(
        git(env, &["rev-parse", "HEAD"], Some(&src))?,
        "git rev-parse",
    )?;
    if head.stdout.trim() != commit {
        return Err(failed(format!(
            "ghidra-firmware-utils HEAD: expected {commit} | received {}",
            head.stdout.trim()
        )));
    }
    let patch =
        tempfile::NamedTempFile::new().map_err(|e| failed(format!("temporary patch file: {e}")))?;
    fs::write(patch.path(), EXTENSION_PATCH).map_err(|e| io_error(patch.path(), e))?;
    require(
        git(env, &["apply", &patch.path().to_string_lossy()], Some(&src))?,
        "applying the Ghidra 12.2 compatibility patch",
    )?;
    Ok(src)
}

fn build_extension(
    env: &Env,
    ghidra: &Path,
    gradle: &Path,
    source: &Path,
    note: &mut dyn FnMut(&str),
) -> Result<PathBuf> {
    note("building ghidra-firmware-utils");
    let mut invocation = Invocation::new(gradle.join("bin/gradle"))
        .args(["-q", "--no-daemon", "-p"])
        .arg(source)
        .arg("buildExtension")
        .env("GHIDRA_INSTALL_DIR", ghidra)
        .timeout(Duration::from_secs(3600));
    if env.offline {
        invocation = invocation.arg("--offline");
    }
    require(env.runner.run(&invocation)?, "extension build")?;
    let dist = source.join("dist");
    let mut zips: Vec<PathBuf> = fs::read_dir(&dist)
        .map_err(|e| {
            failed(format!(
                "extension build: expected {} ({e})",
                dist.display()
            ))
        })?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with("ghidra-firmware-utils.zip"))
        })
        .collect();
    zips.sort();
    zips.pop().ok_or_else(|| {
        failed(format!(
            "extension build: expected a *ghidra-firmware-utils.zip in {}",
            dist.display()
        ))
    })
}

fn install_extension(
    env: &Env,
    ghidra: &Path,
    zip: &Path,
    force: bool,
    note: &mut dyn FnMut(&str),
) -> Result<PathBuf> {
    let target = extension_dir(ghidra);
    check_recovery(&target)?;
    if target.exists() && !force && !marker_matches(&target, &env.profile) {
        return Err(failed(format!(
            "{}: exists and was not installed by this profile; pass --force to replace it",
            target.display()
        )));
    }
    let extensions = target.parent().expect("extension parent");
    fs::create_dir_all(extensions).map_err(|e| io_error(extensions, e))?;
    let staging = tempfile::Builder::new()
        .prefix(".bme-staging-")
        .tempdir_in(extensions)
        .map_err(|e| io_error(extensions, e))?;
    extract_zip(zip, staging.path(), Limits::TOOL)?;
    let unpacked = staging.path().join(EXTENSION);
    if !unpacked.join("data").is_dir() {
        return Err(failed(format!(
            "extension archive: expected {EXTENSION}/data"
        )));
    }
    write_marker(&unpacked, &env.profile)?;
    replace_dir(&unpacked, &target)?;
    note(&format!("extension installed at {}", target.display()));
    Ok(target)
}

/// Import modules and export C, assembly and JSON for each.
pub fn analyze(
    ctx: &Ctx,
    project: &Path,
    output: &Path,
    modules: &[PathBuf],
    timeout: u64,
) -> Result<Reply> {
    let profile = Profile::pinned();
    let home = ghidra_home(&ctx.config, &ctx.paths.data, &profile);
    run_analysis(
        &System,
        &home,
        project,
        output,
        modules,
        timeout,
        &mut |m| ctx.out.note(m),
    )
}

/// The analysis step, separated for tests.
pub fn run_analysis(
    runner: &dyn Runner,
    home: &GhidraHome,
    project: &Path,
    output: &Path,
    modules: &[PathBuf],
    timeout: u64,
    note: &mut dyn FnMut(&str),
) -> Result<Reply> {
    let script = headless(&home.path);
    let data = extension_dir(&home.path).join("data");
    if !script.is_file() || !data.is_dir() {
        return Err(Error::new(
            Code::ToolUnavailable,
            format!(
                "Ghidra at {} ({}): missing analyzeHeadless or the firmware-utils extension; run `bme tools doctor`",
                home.path.display(),
                home.origin
            ),
        ));
    }
    for module in modules {
        if !module.is_file() {
            return Err(Error::new(
                Code::Io,
                format!(
                    "{}: expected a module file (see `bme extract`)",
                    module.display()
                ),
            ));
        }
    }
    fs::create_dir_all(project).map_err(|e| io_error(project, e))?;
    fs::create_dir_all(output).map_err(|e| io_error(output, e))?;
    let scripts = tempfile::Builder::new()
        .prefix("bme-scripts-")
        .tempdir()
        .map_err(|e| failed(format!("script directory: {e}")))?;
    for (name, bytes) in SCRIPTS {
        fs::write(scripts.path().join(name), bytes).map_err(|e| io_error(scripts.path(), e))?;
    }
    let log = output.join("ghidra.log");
    fs::File::create(&log).map_err(|e| io_error(&log, e))?;
    let mut produced = Vec::new();
    for module in modules {
        let staging = tempfile::tempdir().map_err(|e| failed(format!("export directory: {e}")))?;
        let invocation = Invocation::new(&script)
            .arg(project)
            .arg("bme")
            .arg("-import")
            .arg(module)
            .arg("-overwrite")
            .arg("-scriptPath")
            .arg(scripts.path())
            .args([
                "-preScript",
                "SetupFirmwareMemory.java",
                "-postScript",
                "PeimUEFIHelper.java",
            ])
            .arg(&data)
            .arg("-postScript")
            .arg("ExportFirmware.java")
            .arg(staging.path())
            .arg("-analysisTimeoutPerFile")
            .arg(timeout.to_string())
            .append_log(&log)
            .timeout(Duration::from_secs(timeout.saturating_add(900)));
        note(&format!("running Ghidra headless (log: {})", log.display()));
        let finished = runner.run(&invocation)?;
        if !finished.success() {
            return Err(Error::new(
                Code::ToolFailed,
                format!(
                    "analyzeHeadless {}; see {}: {}",
                    finished.describe(),
                    log.display(),
                    finished.tail(400)
                ),
            ));
        }
        if !staging.path().join(".bme-export-complete").is_file() {
            return Err(Error::new(
                Code::ToolFailed,
                format!(
                    "{}: expected Ghidra export completion; see {}",
                    module.display(),
                    log.display()
                ),
            ));
        }
        let name = module
            .file_name()
            .ok_or_else(|| failed(format!("{}: expected a module filename", module.display())))?
            .to_string_lossy();
        let name = name.strip_suffix(".pe").unwrap_or(&name);
        for ext in ["c", "asm", "json"] {
            let filename = format!("{name}.{ext}");
            let source = staging.path().join(&filename);
            if !source.is_file() {
                return Err(Error::new(
                    Code::ToolFailed,
                    format!(
                        "{}: expected Ghidra export {filename}; see {}",
                        module.display(),
                        log.display()
                    ),
                ));
            }
            fs::copy(&source, output.join(&filename)).map_err(|e| io_error(&source, e))?;
            produced.push(filename);
        }
    }
    produced.sort();
    let text = format!(
        "Exported {} files to {} (C output is approximate; check .asm bytes before patching)\n",
        produced.len(),
        output.display()
    );
    Ok(Reply::new(
        json!({"output": display_path(output), "files": produced, "log": display_path(&log)}),
        text,
    ))
}
