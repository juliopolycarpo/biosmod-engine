//! The managed replay runtime: a Python environment with hash-locked Unicorn, Capstone
//! and pefile.
//!
//! bme ships no emulator code. Setup asks the user's `python3` to create a virtual
//! environment under the data directory and has pip install the pinned wheels from
//! `tools/replay/requirements.lock` with `--require-hashes --only-binary :all:`. Every
//! program runs through the [`Runner`] interface, so tests substitute a named fake.
//! Nothing here installs implicitly: a command that needs the runtime and cannot find it
//! fails with [`missing_runtime`], which names the setup command.

use super::{Check, Env, Finished, Invocation, Runner, check, check_recovery, failed, replace_dir};
use crate::config::{Config, io_error, write_atomic};
use biosmod_core::{Code, Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The pinned packages, in lock order. `tools/replay/lock.py` generates the lock from the
/// same list, and a test keeps both in step.
pub const PACKAGES: [(&str, &str); 3] = [
    ("unicorn", "2.1.4"),
    ("capstone", "5.0.9"),
    ("pefile", "2024.8.26"),
];
/// Oldest Python that creates the environment and runs the pinned packages.
pub const PYTHON_MIN: (u32, u32) = (3, 10);
/// The hash-locked requirements pip installs.
pub const LOCK: &str = include_str!("../../../../tools/replay/requirements.lock");
/// The command every missing-runtime error names.
pub const SETUP_COMMAND: &str = "bme tools setup replay";
/// Environment variable that points bme at another interpreter or environment.
pub const OVERRIDE: &str = "BME_REPLAY_PYTHON";
/// File inside the environment that records what setup installed.
const MARKER: &str = "bme-replay.json";
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// Prints the interpreter and pinned package versions as one JSON line.
const VERSIONS_SCRIPT: &str = r#"
import json, sys
from importlib.metadata import PackageNotFoundError, version
packages = {}
for name in ("unicorn", "capstone", "pefile"):
    try:
        packages[name] = version(name)
    except PackageNotFoundError:
        packages[name] = None
print(json.dumps({"python": ".".join(map(str, sys.version_info[:3])), "packages": packages}))
"#;

/// Imports all three packages and executes one instruction.
const SELFTEST_SCRIPT: &str = r#"
import capstone, pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EAX
uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(0x1000, 0x1000)
uc.mem_write(0x1000, b"\x40")  # inc eax
uc.emu_start(0x1000, 0x1001)
assert uc.reg_read(UC_X86_REG_EAX) == 1, "inc eax did not run"
print("selftest ok")
"#;

/// What the base interpreter offers for creating an environment.
const BASE_SCRIPT: &str = r#"
import importlib.util, json, sys
print(json.dumps({"python": ".".join(map(str, sys.version_info[:3])),
                  "venv": all(importlib.util.find_spec(m) for m in ("venv", "ensurepip"))}))
"#;

/// Where the replay interpreter came from.
#[derive(Debug, Clone, Serialize)]
pub struct ReplayHome {
    #[serde(serialize_with = "crate::output::serialize_display_path")]
    pub python: PathBuf,
    /// `BME_REPLAY_PYTHON`, `config` or `managed`.
    pub origin: &'static str,
}

/// Resolve the interpreter: `BME_REPLAY_PYTHON`, then configuration, then the managed environment.
///
/// Example: with nothing set, the result is `<data>/replay/venv/bin/python` from `managed`.
pub fn replay_home(
    get: &dyn Fn(&str) -> Option<OsString>,
    config: &Config,
    data: &Path,
) -> ReplayHome {
    if let Some(path) = get(OVERRIDE).filter(|v| !v.is_empty()) {
        return ReplayHome {
            python: interpreter(Path::new(&path)),
            origin: OVERRIDE,
        };
    }
    if let Some(path) = &config.tools.replay_python {
        return ReplayHome {
            python: interpreter(path),
            origin: "config",
        };
    }
    ReplayHome {
        python: venv_python(&managed_venv(data)),
        origin: "managed",
    }
}

/// The environment bme creates.
pub fn managed_venv(data: &Path) -> PathBuf {
    data.join("replay").join("venv")
}

/// The interpreter inside a virtual environment.
///
/// Example: `venv_python(Path::new("/d/venv"))` is `/d/venv/bin/python` (`Scripts\python.exe` on Windows).
pub fn venv_python(venv: &Path) -> PathBuf {
    if cfg!(windows) {
        venv.join("Scripts").join("python.exe")
    } else {
        venv.join("bin").join("python")
    }
}

/// Accept an interpreter or a virtual environment directory.
///
/// Example: `interpreter(Path::new("/opt/venv"))` is `/opt/venv/bin/python` when `/opt/venv` is a directory.
pub fn interpreter(path: &Path) -> PathBuf {
    if path.is_dir() {
        venv_python(path)
    } else {
        path.to_path_buf()
    }
}

/// Interpreter and package versions found in one environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Versions {
    pub python: String,
    /// Installed version per pinned package; `None` when the package is absent.
    pub packages: BTreeMap<String, Option<String>>,
}

impl Versions {
    /// Whether the interpreter is at least [`PYTHON_MIN`].
    pub fn python_ok(&self) -> bool {
        parse_python(&self.python).is_some_and(|(major, minor)| (major, minor) >= PYTHON_MIN)
    }

    /// One `name: expected X | received Y` line per package that is not the pinned version.
    ///
    /// Example: a missing unicorn gives `unicorn: expected 2.1.4 | received none`.
    pub fn mismatches(&self) -> Vec<String> {
        PACKAGES
            .iter()
            .filter_map(|(name, pinned)| {
                let found = self.packages.get(*name).and_then(|v| v.as_deref());
                (found != Some(*pinned)).then(|| {
                    format!(
                        "{name}: expected {pinned} | received {}",
                        found.unwrap_or("none")
                    )
                })
            })
            .collect()
    }

    /// `unicorn 2.1.4, capstone 5.0.9, pefile 2024.8.26`.
    pub fn summary(&self) -> String {
        PACKAGES
            .iter()
            .map(|(name, _)| {
                format!(
                    "{name} {}",
                    self.packages
                        .get(*name)
                        .and_then(|v| v.as_deref())
                        .unwrap_or("none")
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Major and minor of a `3.14.4` style version.
///
/// Example: `parse_python("3.14.4")` is `Some((3, 14))`.
pub fn parse_python(text: &str) -> Option<(u32, u32)> {
    let mut parts = text.trim().split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// The error for a command that needs the runtime and cannot use it.
///
/// Example: `missing_runtime("python not found")` has code `TOOL_UNAVAILABLE` and a message
/// ending in "run `bme tools setup replay`".
pub fn missing_runtime(reason: impl AsRef<str>) -> Error {
    Error::new(
        Code::ToolUnavailable,
        format!(
            "replay runtime: {} (run `{SETUP_COMMAND}`)",
            reason.as_ref()
        ),
    )
}

/// The JSON object a probe script printed, from the last line that looks like one.
fn json_line(finished: &Finished) -> Option<serde_json::Value> {
    finished
        .stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .and_then(|line| serde_json::from_str(line).ok())
}

fn run_script(
    runner: &dyn Runner,
    python: &Path,
    script: &str,
    timeout: Duration,
) -> std::result::Result<Finished, String> {
    // `-I` keeps the working directory and user site out of the probe.
    let finished = runner
        .run(
            &Invocation::new(python)
                .args(["-I", "-c", script])
                .timeout(timeout),
        )
        .map_err(|e| e.message)?;
    if finished.success() {
        Ok(finished)
    } else {
        Err(format!(
            "{}: {}: {}",
            python.display(),
            finished.describe(),
            finished.tail(300)
        ))
    }
}

/// Ask `python` for its version and the pinned packages' versions in one run.
///
/// Example: `probe_versions(&System, Path::new("/d/venv/bin/python"), timeout)` is
/// `Ok(Versions { python: "3.14.4", .. })`; a missing interpreter is `Err("... No such file")`.
pub fn probe_versions(
    runner: &dyn Runner,
    python: &Path,
    timeout: Duration,
) -> std::result::Result<Versions, String> {
    let finished = run_script(runner, python, VERSIONS_SCRIPT, timeout)?;
    let value = json_line(&finished).ok_or_else(|| {
        format!(
            "{}: expected a JSON version line | received {}",
            python.display(),
            finished.tail(120)
        )
    })?;
    let text = |v: &serde_json::Value| v.as_str().map(str::to_string);
    let python_version = text(&value["python"]).ok_or_else(|| {
        format!(
            "{}: expected a python version | received {value}",
            python.display()
        )
    })?;
    let packages = PACKAGES
        .iter()
        .map(|(name, _)| (name.to_string(), text(&value["packages"][*name])))
        .collect();
    Ok(Versions {
        python: python_version,
        packages,
    })
}

/// Import all three packages and execute one instruction.
///
/// Example: `selftest(&System, python)` is `Ok(())` for a working runtime.
pub fn selftest(runner: &dyn Runner, python: &Path) -> std::result::Result<(), String> {
    run_script(runner, python, SELFTEST_SCRIPT, Duration::from_secs(120)).and_then(|f| {
        f.stdout
            .contains("selftest ok")
            .then_some(())
            .ok_or_else(|| {
                format!(
                    "{}: expected `selftest ok` | received {}",
                    python.display(),
                    f.tail(120)
                )
            })
    })
}

/// Doctor findings for the replay runtime. `deep` also runs [`selftest`].
///
/// Example: a complete environment yields `replay-python`, `replay-packages` and, when
/// `deep`, `replay-emulation`, all ok.
pub fn replay_checks(env: &Env, home: &ReplayHome, deep: bool) -> Vec<Check> {
    let location = format!("{} ({})", home.python.display(), home.origin);
    let versions = match probe_versions(env.runner, &home.python, PROBE_TIMEOUT) {
        Ok(v) => v,
        Err(e) => {
            return vec![check("replay-python", false, missing_runtime(e).message)];
        }
    };
    let (min_major, min_minor) = PYTHON_MIN;
    let python_ok = versions.python_ok();
    let mut checks = vec![check(
        "replay-python",
        python_ok,
        if python_ok {
            format!("{location}, Python {}", versions.python)
        } else {
            format!(
                "{location}: expected Python >= {min_major}.{min_minor} | received {}",
                versions.python
            )
        },
    )];
    let mismatches = versions.mismatches();
    let packages_ok = mismatches.is_empty();
    checks.push(check(
        "replay-packages",
        packages_ok,
        if packages_ok {
            versions.summary()
        } else {
            missing_runtime(mismatches.join("; ")).message
        },
    ));
    if deep && python_ok && packages_ok {
        checks.push(match selftest(env.runner, &home.python) {
            Ok(()) => check("replay-emulation", true, "executed one instruction"),
            Err(e) => check("replay-emulation", false, e),
        });
    }
    checks
}

/// Why `program` cannot create an environment, or `None` when it can.
///
/// Example: `python3 3.9.2` gives `expected Python >= 3.10 | received 3.9.2`.
pub fn base_python_issue(runner: &dyn Runner, program: &Path, timeout: Duration) -> Option<String> {
    let finished = match run_script(runner, program, BASE_SCRIPT, timeout) {
        Ok(f) => f,
        Err(e) => return Some(format!("{e} (Ubuntu: apt install python3 python3-venv)")),
    };
    let Some(value) = json_line(&finished) else {
        return Some(format!(
            "{}: expected a JSON version line | received {}",
            program.display(),
            finished.tail(120)
        ));
    };
    let version = value["python"].as_str().unwrap_or("unknown");
    if !parse_python(version).is_some_and(|v| v >= PYTHON_MIN) {
        return Some(format!(
            "{}: expected Python >= {}.{} | received {version}",
            program.display(),
            PYTHON_MIN.0,
            PYTHON_MIN.1
        ));
    }
    (value["venv"] != true).then(|| {
        format!(
            "{}: the venv or ensurepip module is missing (Ubuntu: apt install python3-venv)",
            program.display()
        )
    })
}

/// What setup recorded inside the environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayMarker {
    packages: BTreeMap<String, String>,
    lock_sha256: String,
}

impl ReplayMarker {
    fn current() -> ReplayMarker {
        ReplayMarker {
            packages: PACKAGES
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            lock_sha256: biosmod_core::util::hex(&Sha256::digest(LOCK.as_bytes())),
        }
    }
}

/// Whether `venv` carries this release's marker, so setup made it and may replace it.
///
/// Example: a directory copied in by hand has no marker and needs `--force` to be replaced.
pub fn marker_current(venv: &Path) -> bool {
    fs::read(venv.join(MARKER))
        .ok()
        .and_then(|b| serde_json::from_slice::<ReplayMarker>(&b).ok())
        .is_some_and(|m| m == ReplayMarker::current())
}

/// A managed environment directory that setup did not create and will not replace without `--force`.
pub fn leftover_venv(venv: &Path) -> Option<PathBuf> {
    (venv.exists() && !marker_current(venv)).then(|| venv.to_path_buf())
}

#[derive(Debug, Clone, clap::Args)]
pub struct ReplaySetupArgs {
    /// Python 3.10 or newer that creates the environment (default: python3 on PATH).
    #[arg(long)]
    pub python: Option<PathBuf>,
    /// Install the pinned wheels from this local directory instead of PyPI.
    #[arg(long)]
    pub wheelhouse: Option<PathBuf>,
    /// Replace an environment not made by this release.
    #[arg(long)]
    pub force: bool,
}

/// Result of a successful setup.
#[derive(Debug, Clone, Serialize)]
pub struct ReplayInstalled {
    #[serde(serialize_with = "crate::output::serialize_display_path")]
    pub python: PathBuf,
    pub versions: Versions,
    /// False when an environment from this release was already healthy.
    pub installed: bool,
}

fn require_success(finished: Finished, what: &str) -> Result<Finished> {
    if finished.success() {
        return Ok(finished);
    }
    Err(failed(format!(
        "{what}: {}: {}",
        finished.describe(),
        finished.tail(800)
    )))
}

/// Create the managed environment and install the hash-locked packages into it.
///
/// Example: `install_replay(&env, &args, &mut |m| eprintln!("{m}"))` leaves
/// `<data>/replay/venv` ready and returns its interpreter.
pub fn install_replay(
    env: &Env,
    args: &ReplaySetupArgs,
    note: &mut dyn FnMut(&str),
) -> Result<ReplayInstalled> {
    if env.offline && args.wheelhouse.is_none() {
        return Err(Error::new(
            Code::SourceUnavailable,
            "--offline setup needs --wheelhouse with the pinned wheels (see tools/replay/requirements.lock)",
        ));
    }
    if let Some(dir) = &args.wheelhouse
        && !dir.is_dir()
    {
        return Err(Error::new(
            Code::Usage,
            format!(
                "--wheelhouse {}: expected a directory of wheels | received none",
                dir.display()
            ),
        ));
    }
    let base = args
        .python
        .clone()
        .unwrap_or_else(|| PathBuf::from(if cfg!(windows) { "python" } else { "python3" }));
    let venv = managed_venv(&env.data);
    check_recovery(&venv)?;
    let current = venv_python(&venv);
    if marker_current(&venv)
        && let Ok(versions) = probe_versions(env.runner, &current, PROBE_TIMEOUT)
        && versions.python_ok()
        && versions.mismatches().is_empty()
        && selftest(env.runner, &current).is_ok()
    {
        note(&format!(
            "replay runtime already installed at {}",
            current.display()
        ));
        return Ok(ReplayInstalled {
            python: current,
            versions,
            installed: false,
        });
    }
    if venv.exists() && !args.force && !marker_current(&venv) {
        return Err(failed(format!(
            "{}: exists but was not installed by this release; pass --force to replace it",
            venv.display()
        )));
    }
    if let Some(issue) = base_python_issue(env.runner, &base, PROBE_TIMEOUT) {
        return Err(Error::new(Code::ToolUnavailable, issue));
    }
    let parent = venv.parent().expect("managed venv has a parent");
    fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(parent)
        .map_err(|e| io_error(parent, e))?;
    let staged = staging.path().join("venv");
    note(&format!("creating {}", venv.display()));
    let created = env.runner.run(
        // `-I` and the staging cwd keep a `venv.py` in the caller's directory from running.
        &Invocation::new(&base)
            .args(["-I", "-m", "venv"])
            .arg(&staged)
            .cwd(staging.path())
            .timeout(Duration::from_secs(300)),
    )?;
    if !created.success() && created.output().contains("ensurepip") {
        return Err(Error::new(
            Code::ToolUnavailable,
            format!(
                "{}: venv cannot bootstrap pip (Ubuntu: apt install python3-venv): {}",
                base.display(),
                created.tail(300)
            ),
        ));
    }
    require_success(created, "python -m venv")?;
    let lock = staging.path().join("requirements.lock");
    fs::write(&lock, LOCK).map_err(|e| io_error(&lock, e))?;
    note("installing the pinned wheels with hash checking");
    // `--isolated` ignores pip configuration and PIP_* variables, so the lock decides what
    // is installed and a user index cannot add a source for it.
    let mut pip = Invocation::new(venv_python(&staged))
        .args(["-I", "-m", "pip", "install", "--isolated", "--no-input"])
        .cwd(staging.path())
        .args([
            "--disable-pip-version-check",
            "--require-hashes",
            "--no-deps",
            "--only-binary",
            ":all:",
        ])
        .arg("-r")
        .arg(&lock)
        .timeout(Duration::from_secs(1800));
    if let Some(wheels) = &args.wheelhouse {
        pip = pip.args(["--no-index", "--find-links"]).arg(wheels);
    }
    require_success(env.runner.run(&pip)?, "pip install")?;
    write_atomic(
        &staged.join(MARKER),
        &serde_json::to_vec_pretty(&ReplayMarker::current()).expect("marker serializes"),
    )?;
    replace_dir(&staged, &venv)?;
    let versions = probe_versions(env.runner, &current, PROBE_TIMEOUT)
        .map_err(|e| failed(format!("installed, but the version check failed: {e}")))?;
    let mismatches = versions.mismatches();
    if !mismatches.is_empty() {
        return Err(failed(format!(
            "installed, but the packages differ from the lock: {}",
            mismatches.join("; ")
        )));
    }
    note("checking that Unicorn executes an instruction");
    selftest(env.runner, &current)
        .map_err(|e| failed(format!("installed, but the selftest failed: {e}")))?;
    Ok(ReplayInstalled {
        python: current,
        versions,
        installed: true,
    })
}

/// Validate a location for `tools set replay`: it must be an interpreter or environment with the
/// pinned packages. Returns the interpreter and the versions found.
///
/// Example: `/opt/venv` holding unicorn 2.0.1 fails with `unicorn: expected 2.1.4 | received 2.0.1`.
pub fn validate_location(runner: &dyn Runner, path: &Path) -> Result<(PathBuf, Versions)> {
    let python = interpreter(path);
    let usage = |detail: String| {
        Error::new(
            Code::Usage,
            format!("replay runtime {}: {detail}", path.display()),
        )
    };
    if !python.is_file() {
        return Err(usage(format!(
            "expected a Python interpreter or virtual environment | received {} not found",
            python.display()
        )));
    }
    let versions = probe_versions(runner, &python, PROBE_TIMEOUT)
        .map_err(|e| usage(format!("expected a runnable interpreter | received {e}")))?;
    if !versions.python_ok() {
        return Err(usage(format!(
            "expected Python >= {}.{} | received {}",
            PYTHON_MIN.0, PYTHON_MIN.1, versions.python
        )));
    }
    let mismatches = versions.mismatches();
    if !mismatches.is_empty() {
        return Err(usage(format!(
            "expected the pinned packages | received {}",
            mismatches.join("; ")
        )));
    }
    Ok((python, versions))
}

#[cfg(all(test, unix))]
mod tests;
