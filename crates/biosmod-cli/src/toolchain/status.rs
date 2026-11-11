//! `tools status`, `tools set` and `tools unset`: one row per external tool bme runs.
//!
//! The status view never fails because a tool is missing; `tools doctor` keeps that
//! job. Each row says what was found, where it came from and how to install it, so
//! the command line and the desktop app can show the same facts.

use super::{Env, GhidraHome, Runner, ghidra_checks, ghidra_version, java_check};
use crate::commands::Ctx;
use crate::flash::{FLASHROM_OVERRIDE, SBIN_DIRECTORIES, parse_version, resolve_flashrom_in};
use crate::output::{Reply, table};
use crate::toolchain::{Invocation, System};
use biosmod_core::{Code, Error, Result};
use serde::Serialize;
use serde_json::json;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How healthy one tool is for the work bme asks of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    /// Found and usable.
    Ready,
    /// Found, but untested or incompatible: bme may still run it.
    Attention,
    /// Not found, or the chosen location is unusable.
    Missing,
}

impl Health {
    /// The word printed in the status table.
    pub fn word(self) -> &'static str {
        match self {
            Health::Ready => "ready",
            Health::Attention => "attention",
            Health::Missing => "missing",
        }
    }
}

/// How a missing tool gets installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Install {
    /// `bme` when bme downloads and verifies the tool, `package-manager` when you run the command.
    pub method: &'static str,
    /// The command that installs the tool, when one is known for this system.
    pub command: Option<String>,
    /// Whether bme can run the installation itself on this system.
    pub automatic: bool,
}

/// What `tools status` knows about one tool.
#[derive(Debug, Clone, Serialize)]
pub struct ToolRow {
    pub id: &'static str,
    pub name: &'static str,
    pub purpose: &'static str,
    pub health: Health,
    pub version: Option<String>,
    pub path: Option<String>,
    /// Where the path came from: an environment variable, `config`, `managed` or `PATH`.
    pub origin: &'static str,
    pub detail: String,
    pub install: Install,
    /// Whether `tools set` can point this tool at another location.
    pub custom_location: bool,
}

/// Tools whose location the user can choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Locatable {
    /// The Ghidra installation directory.
    Ghidra,
    /// The flashrom executable.
    Flashrom,
}

impl Locatable {
    fn name(self) -> &'static str {
        match self {
            Locatable::Ghidra => "ghidra",
            Locatable::Flashrom => "flashrom",
        }
    }
}

/// Packages that system tools come from.
#[derive(Debug, Clone, Copy)]
enum Package {
    Flashrom,
    Git,
    Jdk(u32),
}

/// The package-manager command for `package`, from the text of `/etc/os-release`.
///
/// Example: for Ubuntu, `package_command(text, Package::Flashrom)` is `sudo apt install flashrom`.
fn package_command(os_release: &str, package: Package) -> Option<String> {
    let mut families: Vec<String> = Vec::new();
    for line in os_release.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key == "ID" || key == "ID_LIKE" {
            families.extend(
                value
                    .trim_matches('"')
                    .split_whitespace()
                    .map(str::to_string),
            );
        }
    }
    let is = |names: &[&str]| families.iter().any(|f| names.contains(&f.as_str()));
    let (manager, name) = if is(&["debian", "ubuntu"]) {
        (
            "sudo apt install",
            match package {
                Package::Flashrom => "flashrom".to_string(),
                Package::Git => "git".to_string(),
                Package::Jdk(n) => format!("openjdk-{n}-jdk"),
            },
        )
    } else if is(&["fedora", "rhel", "centos"]) {
        (
            "sudo dnf install",
            match package {
                Package::Flashrom => "flashrom".to_string(),
                Package::Git => "git".to_string(),
                Package::Jdk(n) => format!("java-{n}-openjdk-devel"),
            },
        )
    } else if is(&["arch"]) {
        (
            "sudo pacman -S",
            match package {
                Package::Flashrom => "flashrom".to_string(),
                Package::Git => "git".to_string(),
                Package::Jdk(n) => format!("jdk{n}-openjdk"),
            },
        )
    } else {
        return None;
    };
    Some(format!("{manager} {name}"))
}

fn first_on_path(get: &dyn Fn(&str) -> Option<OsString>, name: &str) -> Option<PathBuf> {
    let path = get("PATH")?;
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    std::env::split_paths(&path)
        .map(|directory| directory.join(&file))
        .find(|candidate| candidate.is_file())
}

fn lossy(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Everything `tools status` reads besides the filesystem.
pub struct Probe<'a> {
    pub env: &'a Env<'a>,
    pub ghidra: &'a GhidraHome,
    /// Process environment lookup.
    pub get: &'a dyn Fn(&str) -> Option<OsString>,
    /// `tools.flashrom` from the configuration.
    pub flashrom: Option<&'a Path>,
    /// Directories searched for flashrom after `PATH`.
    pub sbin: &'a [&'a str],
    /// Contents of `/etc/os-release`, when the system has one.
    pub os_release: Option<&'a str>,
}

/// Inspect every tool. Never fails: problems become rows.
///
/// Example: `status(&probe)` returns rows for ghidra, firmware-utils, java, jdk, git and flashrom.
pub fn status(probe: &Probe) -> Vec<ToolRow> {
    let mut rows = ghidra_rows(probe);
    rows.extend(java_rows(probe));
    rows.push(git_row(probe));
    rows.push(flashrom_row(probe));
    rows
}

fn system_install(probe: &Probe, package: Package) -> Install {
    Install {
        method: "package-manager",
        command: probe
            .os_release
            .and_then(|text| package_command(text, package)),
        automatic: false,
    }
}

fn ghidra_install() -> Install {
    Install {
        method: "bme",
        command: Some("bme tools setup ghidra".into()),
        automatic: cfg!(target_os = "linux"),
    }
}

fn ghidra_rows(probe: &Probe) -> Vec<ToolRow> {
    let home = probe.ghidra;
    let checks = ghidra_checks(probe.env, home);
    let by_name = |name: &str| checks.iter().find(|c| c.check == name);
    let found = by_name("ghidra").is_some_and(|c| c.ok);
    let compatible = by_name("ghidra-version").is_some_and(|c| c.ok);
    let extension = by_name("firmware-utils");
    let version = found.then(|| ghidra_version(&home.path)).flatten();
    let (health, detail) = match (found, compatible) {
        (true, true) => (
            Health::Ready,
            "Ghidra and its pinned version are present".into(),
        ),
        (true, false) => (
            Health::Attention,
            by_name("ghidra-version")
                .map(|c| c.detail.clone())
                .unwrap_or_default(),
        ),
        (false, _) => (
            Health::Missing,
            "support/analyzeHeadless not found in this directory".into(),
        ),
    };
    let ghidra = ToolRow {
        id: "ghidra",
        name: "Ghidra",
        purpose: "analyzes extracted firmware modules",
        health,
        version,
        path: Some(lossy(&home.path)),
        origin: home.origin,
        detail,
        install: ghidra_install(),
        custom_location: true,
    };
    let extension_ok = found && extension.is_some_and(|c| c.ok);
    let firmware_utils = ToolRow {
        id: "firmware-utils",
        name: "ghidra-firmware-utils",
        purpose: "teaches Ghidra the UEFI firmware formats",
        health: if extension_ok {
            Health::Ready
        } else {
            Health::Missing
        },
        version: extension_ok.then(|| {
            probe
                .env
                .profile
                .firmware_utils_commit
                .chars()
                .take(12)
                .collect()
        }),
        path: found.then(|| lossy(&super::extension_dir(&home.path))),
        origin: home.origin,
        detail: match (found, extension) {
            (false, _) => "needs Ghidra first".into(),
            (true, Some(c)) => c.detail.clone(),
            (true, None) => String::new(),
        },
        install: ghidra_install(),
        custom_location: false,
    };
    vec![ghidra, firmware_utils]
}

fn java_rows(probe: &Probe) -> Vec<ToolRow> {
    let min = probe.env.profile.java_min;
    [
        ("java", "Java runtime", "runs Ghidra", "java"),
        (
            "jdk",
            "Java JDK",
            "builds the Ghidra extension during setup",
            "javac",
        ),
    ]
    .into_iter()
    .map(|(id, name, purpose, program)| {
        let check = java_check(probe.env.runner, program, min);
        let version = (check.ok)
            .then(|| check.detail.rsplit(' ').next().map(str::to_string))
            .flatten();
        let path = first_on_path(probe.get, program).map(|p| lossy(&p));
        let health = if check.ok {
            Health::Ready
        } else if version.is_none() && check.detail.contains("received") {
            Health::Attention
        } else {
            Health::Missing
        };
        ToolRow {
            id,
            name,
            purpose,
            health,
            version,
            path,
            origin: "PATH",
            detail: check.detail,
            install: system_install(probe, Package::Jdk(min)),
            custom_location: false,
        }
    })
    .collect()
}

fn git_row(probe: &Probe) -> ToolRow {
    let finished = probe.env.runner.run(
        &Invocation::new("git")
            .arg("--version")
            .timeout(Duration::from_secs(60)),
    );
    let (health, version, detail) = match finished {
        Ok(f) if f.success() => {
            let line = f.stdout.trim().to_string();
            let version = line.strip_prefix("git version ").map(str::to_string);
            (Health::Ready, version, line)
        }
        Ok(f) => (Health::Missing, None, format!("git: {}", f.describe())),
        Err(e) => (Health::Missing, None, format!("git: {}", e.message)),
    };
    ToolRow {
        id: "git",
        name: "Git",
        purpose: "fetches the Ghidra extension source during setup",
        health,
        version,
        path: first_on_path(probe.get, "git").map(|p| lossy(&p)),
        origin: "PATH",
        detail,
        install: system_install(probe, Package::Git),
        custom_location: false,
    }
}

fn flashrom_row(probe: &Probe) -> ToolRow {
    let install = system_install(probe, Package::Flashrom);
    let Some((path, origin)) = resolve_flashrom_in(probe.get, probe.flashrom, probe.sbin) else {
        return ToolRow {
            id: "flashrom",
            name: "flashrom",
            purpose: "reads and writes the SPI flash chip",
            health: Health::Missing,
            version: None,
            path: None,
            origin: "none",
            detail: "not found in PATH or the sbin directories".into(),
            install,
            custom_location: true,
        };
    };
    let finished = probe.env.runner.run(
        &Invocation::new(&path)
            .arg("--version")
            .timeout(Duration::from_secs(60)),
    );
    let (health, version, detail) = match finished {
        Ok(f) => match parse_version(&f.output()) {
            Some(v) => (Health::Ready, Some(v), "flashrom answers --version".into()),
            None => (
                Health::Attention,
                None,
                format!(
                    "{}: expected a `flashrom v<version>` banner | received {}",
                    path.display(),
                    f.tail(120)
                ),
            ),
        },
        Err(e) => (Health::Missing, None, e.message),
    };
    ToolRow {
        id: "flashrom",
        name: "flashrom",
        purpose: "reads and writes the SPI flash chip",
        health,
        version,
        path: Some(lossy(&path)),
        origin: origin.label(),
        detail,
        install,
        custom_location: true,
    }
}

/// Render rows as a table followed by one next step per tool that needs attention.
pub fn render(rows: &[ToolRow]) -> String {
    let mut cells = vec![vec![
        "TOOL".to_string(),
        "STATUS".into(),
        "VERSION".into(),
        "LOCATION".into(),
    ]];
    for row in rows {
        cells.push(vec![
            row.id.to_string(),
            row.health.word().to_string(),
            row.version.clone().unwrap_or_else(|| "-".into()),
            match &row.path {
                Some(path) => format!("{path} ({})", row.origin),
                None => "-".into(),
            },
        ]);
    }
    let mut text = table(&cells);
    let pending: Vec<&ToolRow> = rows.iter().filter(|r| r.health != Health::Ready).collect();
    if pending.is_empty() {
        text += "\nEvery tool is ready.\n";
        return text;
    }
    text += "\nNext steps\n";
    for row in pending {
        text += &format!("  {}: {}\n", row.id, row.detail);
        if let Some(command) = &row.install.command {
            text += &format!("    install:  {command}\n");
        } else {
            text += "    install:  use your package manager\n";
        }
        if row.custom_location {
            text += &format!(
                "    or use an existing copy:  bme tools set {} <path>\n",
                row.id
            );
        }
    }
    text
}

/// `tools status`.
pub fn run_status(ctx: &Ctx) -> Result<Reply> {
    let env = super::env(ctx, &System, &crate::transport::Offline);
    let home = super::ghidra_home(&ctx.config, &env.data, &env.profile);
    let get = |key: &str| std::env::var_os(key).filter(|v| !v.is_empty());
    let os_release = std::fs::read_to_string("/etc/os-release").ok();
    let rows = status(&Probe {
        env: &env,
        ghidra: &home,
        get: &get,
        flashrom: ctx.config.tools.flashrom.as_deref(),
        sbin: &SBIN_DIRECTORIES,
        os_release: os_release.as_deref(),
    });
    let ready = rows.iter().all(|r| r.health == Health::Ready);
    let text = render(&rows);
    Ok(Reply::new(
        json!({"ready": ready, "platform": std::env::consts::OS, "tools": rows}),
        text,
    ))
}

/// Check that `path` is a usable location for `tool` and return the version found there.
fn validate(runner: &dyn Runner, tool: Locatable, path: &Path) -> Result<String> {
    match tool {
        Locatable::Ghidra => {
            let script = super::headless(path);
            if !script.is_file() {
                return Err(Error::new(
                    Code::Usage,
                    format!(
                        "ghidra home {}: expected an installation containing support/analyzeHeadless | received {} not found",
                        path.display(),
                        script.display()
                    ),
                ));
            }
            Ok(ghidra_version(path).unwrap_or_else(|| "unknown version".into()))
        }
        Locatable::Flashrom => {
            if !path.is_file() {
                return Err(Error::new(
                    Code::Usage,
                    format!(
                        "flashrom {}: expected an executable file | received none",
                        path.display()
                    ),
                ));
            }
            let finished = runner
                .run(
                    &Invocation::new(path)
                        .arg("--version")
                        .timeout(Duration::from_secs(60)),
                )
                .map_err(|e| {
                    Error::new(
                        Code::Usage,
                        format!(
                            "flashrom {}: expected a runnable executable | received {}",
                            path.display(),
                            e.message
                        ),
                    )
                })?;
            parse_version(&finished.output()).ok_or_else(|| {
                Error::new(
                    Code::Usage,
                    format!(
                        "flashrom {}: expected a `flashrom v<version>` banner | received {}",
                        path.display(),
                        finished.tail(120)
                    ),
                )
            })
        }
    }
}

/// The environment variable that overrides `tool`, when it is set.
fn overriding_variable(tool: Locatable) -> Option<&'static str> {
    let name = match tool {
        Locatable::Ghidra => "GHIDRA_INSTALL_DIR",
        Locatable::Flashrom => FLASHROM_OVERRIDE,
    };
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(|_| name)
}

/// `tools set <tool> <path>`: validate a location and save it in the configuration.
///
/// Example: `bme tools set flashrom /opt/flashrom/bin/flashrom` makes later `bme flash` runs use it.
pub fn set(ctx: &Ctx, runner: &dyn Runner, tool: Locatable, path: &Path) -> Result<Reply> {
    let absolute = std::path::absolute(path).map_err(|e| crate::config::io_error(path, e))?;
    let version = validate(runner, tool, &absolute)?;
    let mut config = ctx.config.clone();
    let previous = match tool {
        Locatable::Ghidra => config.tools.ghidra_home.replace(absolute.clone()),
        Locatable::Flashrom => config.tools.flashrom.replace(absolute.clone()),
    };
    config.save(&ctx.paths)?;
    let shadow = overriding_variable(tool);
    if let Some(variable) = shadow {
        ctx.out.note(format!(
            "{variable} is set and still wins over this setting in this shell"
        ));
    }
    Ok(Reply::new(
        json!({
            "tool": tool.name(),
            "path": lossy(&absolute),
            "version": version,
            "previous": previous.as_deref().map(lossy),
            "overridden_by": shadow,
        }),
        format!(
            "{} set to {} ({version})\n",
            tool.name(),
            absolute.display()
        ),
    ))
}

/// `tools unset <tool>`: drop the saved location and fall back to the default lookup.
///
/// Example: `bme tools unset flashrom` goes back to `BME_FLASHROM`, then `PATH`.
pub fn unset(ctx: &Ctx, tool: Locatable) -> Result<Reply> {
    let mut config = ctx.config.clone();
    let previous = match tool {
        Locatable::Ghidra => config.tools.ghidra_home.take(),
        Locatable::Flashrom => config.tools.flashrom.take(),
    };
    if previous.is_some() {
        config.save(&ctx.paths)?;
    }
    let text = match &previous {
        Some(path) => format!(
            "{} no longer uses {}; run `bme tools status` to see what it finds now\n",
            tool.name(),
            path.display()
        ),
        None => format!("{} had no saved location\n", tool.name()),
    };
    Ok(Reply::new(
        json!({"tool": tool.name(), "previous": previous.as_deref().map(lossy)}),
        text,
    ))
}

#[cfg(all(test, unix))]
mod tests;
