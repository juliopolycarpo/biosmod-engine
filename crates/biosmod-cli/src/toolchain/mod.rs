//! Ghidra tooling: pinned installation, read-only doctor and headless analysis.
//!
//! Archives are verified against pinned SHA-256 digests before extraction,
//! extracted with path, symlink, size and count limits into a staging
//! directory, and only then moved into place. External programs run through
//! the [`Runner`] interface so tests can substitute a named fake.

mod archive;
mod runner;
// Setup is Linux-only for now; the fakes model a Unix layout.
#[cfg(all(test, unix))]
mod tests;

pub use archive::{Limits, extract_zip};
pub use runner::{Finished, Invocation, Runner, System};

use crate::commands::Ctx;
use crate::config::{Config, io_error, write_atomic};
use crate::output::Reply;
use crate::transport::{Https, Offline, Transport};
use biosmod_core::{Code, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
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

fn short(duration: u64) -> Duration {
    Duration::from_secs(duration)
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

fn java_check(runner: &dyn Runner, program: &'static str, min: u32) -> Check {
    let name = if program == "javac" { "jdk" } else { "java" };
    let finished = match runner.run(&Invocation::new(program).arg("-version").timeout(short(60))) {
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

/// Read-only installation checks.
pub fn inspect(env: &Env, home: &GhidraHome) -> Vec<Check> {
    let mut checks = vec![java_check(env.runner, "java", env.profile.java_min)];
    let script = headless(&home.path);
    checks.push(check(
        "ghidra",
        script.is_file(),
        format!("{} ({})", home.path.display(), home.origin),
    ));
    let version = property(
        &home.path.join("Ghidra/application.properties"),
        "application.version",
    );
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
        (false, _) => format!(
            "{}: not installed (run `bme tools setup ghidra`)",
            extension.display()
        ),
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
        .timeout(short(600));
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

fn checks_reply(checks: Vec<Check>, home: &GhidraHome) -> Result<Reply> {
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
    if failed.is_empty() {
        return Ok(Reply::new(
            json!({"ghidra_home": home, "checks": checks}),
            text,
        ));
    }
    eprint!("{text}");
    Err(Error::new(
        Code::ToolUnavailable,
        format!("tools doctor: failed checks: {}", failed.join(", ")),
    )
    .with_details(json!({"ghidra_home": home, "checks": checks})))
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

pub fn doctor(ctx: &Ctx, deep: bool) -> Result<Reply> {
    let env = env(ctx, &System, &Offline);
    let home = ghidra_home(&ctx.config, &env.data, &env.profile);
    let mut checks = inspect(&env, &home);
    if deep && checks.iter().all(|c| c.ok) {
        checks.push(startup_check(env.runner, &home.path));
    }
    checks_reply(checks, &home)
}

pub fn paths(ctx: &Ctx) -> Result<Reply> {
    let profile = Profile::pinned();
    let home = ghidra_home(&ctx.config, &ctx.paths.data, &profile);
    let data = json!({"config": ctx.paths.config_file(), "cache": ctx.paths.cache, "data": ctx.paths.data, "ghidra_home": home, "profile": profile});
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

/// Result of a successful setup.
#[derive(Debug, Clone, Serialize)]
pub struct Installed {
    pub ghidra: PathBuf,
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
    let java = java_check(env.runner, "javac", env.profile.java_min);
    if !java.ok {
        return Err(Error::new(Code::ToolUnavailable, java.detail));
    }
    let git = env
        .runner
        .run(&Invocation::new("git").arg("--version").timeout(short(60)));
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
                .timeout(short(300)),
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

/// Move `staged` to `target`, replacing an existing directory only after the new one is complete.
fn replace_dir(staged: &Path, target: &Path) -> Result<()> {
    let parent = target.parent().expect("target has a parent");
    let old = parent.join(format!(".bme-old-{}", std::process::id()));
    let had_old = target.exists();
    if had_old {
        fs::rename(target, &old).map_err(|e| io_error(target, e))?;
    }
    if let Err(e) = fs::rename(staged, target) {
        if had_old {
            let _ = fs::rename(&old, target);
        }
        return Err(io_error(target, e));
    }
    if had_old {
        let _ = fs::remove_dir_all(&old);
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
        .timeout(short(900));
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
        .timeout(short(3600));
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
    let invocation = Invocation::new(&script)
        .arg(project)
        .arg("bme")
        .arg("-import")
        .args(modules.iter().map(|m| m.as_os_str()))
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
        .arg(output)
        .arg("-analysisTimeoutPerFile")
        .arg(timeout.to_string())
        .log(&log)
        .timeout(short(
            timeout
                .saturating_mul(modules.len() as u64)
                .saturating_add(900),
        ));
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
    let mut produced: Vec<String> = fs::read_dir(output)
        .map_err(|e| io_error(output, e))?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "ghidra.log")
        .collect();
    produced.sort();
    let text = format!(
        "Exported {} files to {} (C output is approximate; check .asm bytes before patching)\n",
        produced.len(),
        output.display()
    );
    Ok(Reply::new(
        json!({"output": output, "files": produced, "log": log}),
        text,
    ))
}
