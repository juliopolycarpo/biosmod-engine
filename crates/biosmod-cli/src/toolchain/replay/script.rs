//! Run a harness in the replay runtime and collect the JSON documents it emits.
//!
//! The runner keeps only the last 64 KiB of stdout and has no stdin, so results travel through
//! a file: the child appends one JSON document per line to the path in `BME_REPLAY_RESULT`
//! (`bme_replay.emit`). Everything goes through [`Runner`], so tests answer with a named fake.

use super::{PROBE_TIMEOUT, ReplayHome, Versions, missing_runtime, package, probe_versions};
use crate::config::io_error;
use crate::toolchain::{Env, Invocation};
use biosmod_core::{Code, Error, Result};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Environment variable naming the file `bme_replay.emit` appends to.
pub const RESULT_ENV: &str = "BME_REPLAY_RESULT";

/// Runs `bme_replay.__main__.main` from the managed package directory. `-I` keeps the working
/// directory, `PYTHONPATH` and the user site out of the interpreter, so the path argument is
/// the only way `bme_replay` is found; `-B` (`-I` ignores `PYTHONDONTWRITEBYTECODE`) keeps
/// bytecode out of the package directory.
const LAUNCHER: &str = r#"
import sys
sys.path.insert(0, sys.argv[1])
from bme_replay.__main__ import main
main(sys.argv[2:])
"#;

/// What to run.
pub struct ScriptRun<'a> {
    pub harness: &'a Path,
    pub modules: &'a [PathBuf],
    /// Arguments after `--`, passed to the harness as `sys.argv[1:]`.
    pub args: &'a [String],
    pub timeout: Duration,
}

/// What a finished harness left behind.
#[derive(Debug)]
pub struct ScriptOutput {
    /// Emitted documents, in order.
    pub documents: Vec<serde_json::Value>,
    /// The emitted lines exactly as written, for hashing.
    pub raw: String,
    /// Interpreter and package versions that ran it.
    pub versions: Versions,
}

/// Confirm the runtime exists and carries the pinned packages; returns what it found.
///
/// Example: a missing interpreter fails with `ToolUnavailable` and a message ending in
/// "(run `bme tools setup replay`)".
pub fn ready(env: &Env, home: &ReplayHome) -> Result<Versions> {
    if !home.python.is_file() {
        return Err(missing_runtime(format!(
            "{} ({}): expected a Python interpreter | received none",
            home.python.display(),
            home.origin
        )));
    }
    let versions =
        probe_versions(env.runner, &home.python, PROBE_TIMEOUT).map_err(missing_runtime)?;
    if !versions.python_ok() {
        return Err(missing_runtime(format!(
            "{}: expected Python >= 3.10 | received {}",
            home.python.display(),
            versions.python
        )));
    }
    let mismatches = versions.mismatches();
    if !mismatches.is_empty() {
        return Err(missing_runtime(format!(
            "{}: expected the pinned packages | received {}",
            home.python.display(),
            mismatches.join("; ")
        )));
    }
    Ok(versions)
}

/// Run a harness and return what it emitted.
///
/// Example: `run_script(&env, &home, &ScriptRun { harness, modules: &[], args: &[], timeout })`
/// yields one document per `bme_replay.emit` call.
pub fn run_script(env: &Env, home: &ReplayHome, run: &ScriptRun) -> Result<ScriptOutput> {
    let versions = ready(env, home)?;
    let package_dir = package::ensure(&env.data)?;
    let mut args: Vec<OsString> = vec![package_dir.into_os_string(), run.harness.into()];
    for module in run.modules {
        args.push("--module".into());
        args.push(module.into());
    }
    if !run.args.is_empty() {
        args.push("--".into());
        args.extend(run.args.iter().map(OsString::from));
    }
    run_main(env, home, run.timeout, args, versions, run.harness)
}

/// Start the launcher with `main_args` and read the result file back.
pub(super) fn run_main(
    env: &Env,
    home: &ReplayHome,
    timeout: Duration,
    main_args: Vec<OsString>,
    versions: Versions,
    what: &Path,
) -> Result<ScriptOutput> {
    let scratch = tempfile::tempdir().map_err(|e| io_error(&std::env::temp_dir(), e))?;
    let result = scratch.path().join("result.jsonl");
    let invocation = Invocation::new(&home.python)
        .args(["-I", "-B", "-c", LAUNCHER])
        .args(main_args)
        .env(RESULT_ENV, &result)
        .timeout(timeout);
    let finished = env.runner.run(&invocation)?;
    if !finished.success() {
        return Err(Error::new(
            Code::ToolFailed,
            format!(
                "replay {}: expected exit status 0 | received {}: {}",
                what.display(),
                finished.describe(),
                finished.tail(2000)
            ),
        ));
    }
    let raw = match fs::read_to_string(&result) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(io_error(&result, e)),
    };
    let documents = parse_documents(&raw, what)?;
    Ok(ScriptOutput {
        documents,
        raw,
        versions,
    })
}

/// Parse the result file: one JSON document per non-empty line.
///
/// Example: `{"a":1}\n{"b":2}\n` is two documents; `oops` fails naming line 1.
pub fn parse_documents(raw: &str, what: &Path) -> Result<Vec<serde_json::Value>> {
    raw.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|e| {
                Error::new(
                    Code::ToolFailed,
                    format!(
                        "replay {} result line {}: expected one JSON document | received {e}",
                        what.display(),
                        index + 1
                    ),
                )
            })
        })
        .collect()
}

#[cfg(all(test, unix))]
mod tests;
