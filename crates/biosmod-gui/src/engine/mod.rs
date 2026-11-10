//! A subprocess client for the `bme/1` protocol. No firmware policy lives here.

use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const MAX_JSON: usize = 64 * 1024 * 1024;
const MAX_DIAGNOSTICS: usize = 256 * 1024;
/// Concrete patch IDs bound to the input and catalog displayed by a scan.
#[derive(Debug, Clone)]
pub struct ScannedSelection {
    pub source: String,
    pub ids: Vec<String>,
    pub input_sha256: String,
    pub source_sha256: String,
}

/// The selection to build or preview.
#[derive(Debug, Clone)]
pub enum PatchSelection {
    Scanned(ScannedSelection),
    Recipe(PathBuf),
}

/// How to return the result of preparing a patched copy.
#[derive(Debug, Clone)]
pub enum PatchDestination {
    Preview,
    Publish(PathBuf),
}

/// Operations supported by this client. Paths remain OS strings until passed to `bme`.
#[derive(Debug, Clone)]
pub enum Request {
    Version,
    Capabilities,
    Inspect {
        image: PathBuf,
    },
    Scan {
        image: PathBuf,
        source: String,
    },
    CatalogList,
    CatalogShow {
        source: String,
    },
    Plan {
        image: PathBuf,
        source: String,
        selection: Vec<String>,
        output: PathBuf,
    },
    Patch {
        image: PathBuf,
        plan: PathBuf,
        output: PathBuf,
    },
    Verify {
        input: PathBuf,
        output: PathBuf,
        plan: PathBuf,
    },
    Build {
        image: PathBuf,
        selection: PatchSelection,
        destination: PatchDestination,
    },
    Export {
        image: PathBuf,
        selection: ScannedSelection,
        output: PathBuf,
    },
    VerifyResult {
        input: PathBuf,
        output: PathBuf,
        manifest: PathBuf,
        recipe: Option<PathBuf>,
    },
    ToolsDoctor,
    ToolsPaths,
}

impl Request {
    fn name(&self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Capabilities => "capabilities",
            Self::Inspect { .. } => "inspect",
            Self::Scan { .. } => "scan",
            Self::CatalogList => "catalog list",
            Self::CatalogShow { .. } => "catalog show",
            Self::Plan { .. } => "plan",
            Self::Patch { .. } | Self::Build { .. } => "patch",
            Self::Export { .. } => "export",
            Self::Verify { .. } | Self::VerifyResult { .. } => "verify",
            Self::ToolsDoctor => "tools doctor",
            Self::ToolsPaths => "tools paths",
        }
    }

    fn publishes(&self) -> bool {
        matches!(
            self,
            Self::Patch { .. }
                | Self::Build {
                    destination: PatchDestination::Publish(_),
                    ..
                }
                | Self::Export { .. }
        )
    }

    fn args(&self, cwd: &Path) -> Result<Vec<OsString>, EngineError> {
        let mut args: Vec<OsString> = self.name().split(' ').map(Into::into).collect();
        let path = |p: &Path| -> OsString {
            if p.is_absolute() {
                p.as_os_str().to_owned()
            } else {
                cwd.join(p).into_os_string()
            }
        };
        let option = |name: &str, value: &OsStr| -> OsString {
            let mut arg = OsString::from(name);
            arg.push(value);
            arg
        };
        let mut selected_ids = None;
        match self {
            Self::Inspect { image } => args.push(path(image)),
            Self::Scan { image, source } => {
                args.push(path(image));
                args.push(option("--catalog=", OsStr::new(source)));
            }
            Self::CatalogShow { source } => args.push(option("--catalog=", OsStr::new(source))),
            Self::Plan {
                image,
                source,
                selection,
                output,
            } => {
                if selection.is_empty() || selection.iter().any(|s| s.is_empty() || s.contains(','))
                {
                    return Err(EngineError::new(
                        ErrorKind::Configuration,
                        "selection: expected one or more nonempty patch IDs without commas",
                    ));
                }
                args.push(path(image));
                args.push(option("--catalog=", OsStr::new(source)));
                args.push(option("--select=", OsStr::new(&selection.join(","))));
                args.push(option("--output=", &path(output)));
            }
            Self::Patch {
                image,
                plan,
                output,
            } => {
                args.push(path(image));
                args.push(option("--plan=", &path(plan)));
                args.push(option("--output=", &path(output)));
            }
            Self::Verify {
                input,
                output,
                plan,
            } => {
                args.extend([path(input), path(output)]);
                args.push(option("--plan=", &path(plan)));
            }
            Self::Build {
                image,
                selection,
                destination,
            } => {
                args.push(path(image));
                match selection {
                    PatchSelection::Scanned(selection) => selected_ids = Some(selection),
                    PatchSelection::Recipe(recipe) => args.push(option("--from=", &path(recipe))),
                }
                match destination {
                    PatchDestination::Preview => args.push("--dry-run".into()),
                    PatchDestination::Publish(output) => {
                        args.push(option("--output=", &path(output)))
                    }
                }
            }
            Self::Export {
                image,
                selection,
                output,
            } => {
                args.push(path(image));
                args.push(option("--output=", &path(output)));
                selected_ids = Some(selection);
            }
            Self::VerifyResult {
                input,
                output,
                manifest,
                recipe,
            } => {
                args.extend([path(input), path(output)]);
                args.push(option("--manifest=", &path(manifest)));
                if let Some(recipe) = recipe {
                    args.push(option("--from=", &path(recipe)));
                }
            }
            _ => {}
        }
        args.extend([OsString::from("--json"), OsString::from("--offline")]);
        if let Some(selection) = selected_ids {
            if selection.ids.is_empty() || selection.ids.iter().any(String::is_empty) {
                return Err(EngineError::new(
                    ErrorKind::Configuration,
                    "selection: expected one or more nonempty patch IDs",
                ));
            }
            args.push(option("--catalog=", OsStr::new(&selection.source)));
            args.push(option(
                "--expect-input-sha256=",
                OsStr::new(&selection.input_sha256),
            ));
            args.push(option(
                "--expect-source-sha256=",
                OsStr::new(&selection.source_sha256),
            ));
            args.push("--".into());
            args.extend(selection.ids.iter().map(OsString::from));
        }
        Ok(args)
    }
}

/// Categories distinguish an engine rejection from transport and process failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Configuration,
    Launch,
    Io,
    Protocol,
    OutputLimit,
    Engine,
    Timeout,
    Cancelled,
    Interrupted,
}

/// A failed operation, including the structured engine error and bounded diagnostics when available.
#[derive(Debug, Clone)]
pub struct EngineError {
    pub kind: ErrorKind,
    pub message: String,
    /// Engine version from a validated controlled-error envelope, when present.
    pub version: Option<Box<String>>,
    pub code: Option<String>,
    pub details: Option<Value>,
    pub diagnostics: String,
}

impl EngineError {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            version: None,
            code: None,
            details: None,
            diagnostics: String::new(),
        }
    }
    fn diagnostics(mut self, diagnostics: &str) -> Self {
        self.diagnostics = diagnostics.to_owned();
        self
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.code {
            Some(code) => write!(f, "{code}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}
impl std::error::Error for EngineError {}

/// A validated successful response.
#[derive(Debug, Clone)]
pub struct Reply {
    pub version: String,
    pub data: Value,
    pub diagnostics: String,
}

#[derive(Deserialize)]
struct Envelope {
    product: String,
    protocol: String,
    version: String,
    command: String,
    ok: bool,
    #[serde(default)]
    data: Field<Value>,
    #[serde(default)]
    error: Field<EngineFailure>,
}

// Missing fields and explicit null are different in the protocol envelope.
enum Field<T> {
    Missing,
    Present(T),
}

// Deriving Default would unnecessarily require T: Default.
#[allow(clippy::derivable_impls)]
impl<T> Default for Field<T> {
    fn default() -> Self {
        Self::Missing
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Field<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::Present)
    }
}
#[derive(Deserialize)]
struct EngineFailure {
    code: String,
    message: String,
    #[serde(default)]
    details: Option<Value>,
}

/// Decode a bootstrap response; until capabilities arrive only zero/nonzero status is known.
///
/// Example: `decode("version", 0, br#"{"product":"biosmod-engine","protocol":"bme/1","version":"1","command":"version","ok":true,"data":{}}"#, "")` returns a reply.
#[cfg(test)]
fn decode(
    expected: &str,
    exit: i32,
    bytes: &[u8],
    diagnostics: &str,
) -> Result<Reply, EngineError> {
    decode_with_contract(expected, exit, bytes, diagnostics, None)
}

fn decode_with_contract(
    expected: &str,
    exit: i32,
    bytes: &[u8],
    diagnostics: &str,
    contract: Option<&EngineContract>,
) -> Result<Reply, EngineError> {
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|e| {
        EngineError::new(
            ErrorKind::Protocol,
            format!("engine response: expected one complete bme/1 JSON envelope | received {e}"),
        )
        .diagnostics(diagnostics)
    })?;
    let bad =
        |message: String| EngineError::new(ErrorKind::Protocol, message).diagnostics(diagnostics);
    if envelope.product != "biosmod-engine"
        || envelope.protocol != "bme/1"
        || envelope.version.is_empty()
    {
        return Err(bad(format!(
            "engine identity: expected biosmod-engine / bme/1 / nonempty version | received {} / {} / {:?}",
            envelope.product, envelope.protocol, envelope.version
        )));
    }
    let usage = envelope.command == "usage"
        && !envelope.ok
        && matches!(&envelope.error, Field::Present(error) if error.code == "USAGE");
    if envelope.command != expected && !usage {
        return Err(bad(format!(
            "engine command: expected {expected} | received {}",
            envelope.command
        )));
    }
    let success_exit = contract.map_or(0, |contract| contract.ok_exit);
    if envelope.ok && exit == success_exit && matches!(envelope.error, Field::Missing) {
        return match envelope.data {
            Field::Present(data) => Ok(Reply {
                version: envelope.version,
                data,
                diagnostics: diagnostics.to_owned(),
            }),
            Field::Missing => Err(bad("engine response: expected data for success".into())),
        };
    }
    if !envelope.ok
        && matches!(envelope.data, Field::Missing)
        && let Field::Present(error) = envelope.error
    {
        let expected_exit = contract.and_then(|contract| contract.error_exits.get(&error.code));
        let valid_exit = match contract {
            Some(_) => expected_exit == Some(&exit),
            None => exit != success_exit,
        };
        if !valid_exit
            || error.code.is_empty()
            || !error
                .code
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c == b'_')
            || error.message.is_empty()
        {
            return Err(bad(format!(
                "engine error {:?}: expected uppercase advertised code, nonempty message and exit {:?} | received exit {exit}",
                error.code, expected_exit
            )));
        }
        return Err(EngineError {
            kind: ErrorKind::Engine,
            message: error.message,
            version: Some(Box::new(envelope.version)),
            code: Some(error.code),
            details: error.details,
            diagnostics: diagnostics.to_owned(),
        });
    }
    Err(bad(format!(
        "engine result: expected success with exit 0 or a matching controlled error | received ok={} exit={exit}",
        envelope.ok
    )))
}

/// The verification and exit-code contract advertised by a connected engine.
#[derive(Debug, Clone)]
pub struct EngineContract {
    required_checks: Vec<String>,
    ok_exit: i32,
    error_exits: HashMap<String, i32>,
}

impl EngineContract {
    /// Validate the advertised exit codes and required verification checks.
    /// Example: `EngineContract::from_capabilities(&reply.data)` binds a session to its engine.
    pub fn from_capabilities(data: &Value) -> Result<Self, EngineError> {
        let invalid = |field: &str, value: &Value| {
            EngineError::new(
                ErrorKind::Protocol,
                format!("engine capability {field}: expected a valid contract | received {value}"),
            )
        };
        let checks = &data["verification_required_checks"];
        let mut seen = HashSet::new();
        let required_checks = checks
            .as_array()
            .filter(|checks| !checks.is_empty())
            .ok_or_else(|| invalid("verification_required_checks", checks))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|name| !name.is_empty() && seen.insert((*name).to_owned()))
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("verification_required_checks", value))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let exits = &data["exit_codes"];
        let exit_value = |name: &str| -> Result<i32, EngineError> {
            exits
                .get(name)
                .and_then(Value::as_i64)
                .and_then(|value| i32::try_from(value).ok())
                .filter(|value| (0..=255).contains(value))
                .ok_or_else(|| invalid("exit_codes", exits))
        };
        let ok_exit = exit_value("ok")?;
        let failed = exit_value("failed")?;
        let usage = exit_value("usage")?;
        let incomplete = exit_value("publication_incomplete")?;
        if ok_exit != 0
            || [failed, usage, incomplete].contains(&ok_exit)
            || HashSet::from([failed, usage, incomplete]).len() != 3
        {
            return Err(invalid("exit_codes", exits));
        }
        let errors = &data["error_codes"];
        let mut error_exits = HashMap::new();
        for entry in errors
            .as_array()
            .filter(|errors| !errors.is_empty())
            .ok_or_else(|| invalid("error_codes", errors))?
        {
            let code = entry
                .get("code")
                .and_then(Value::as_str)
                .filter(|code| {
                    !code.is_empty() && code.bytes().all(|c| c.is_ascii_uppercase() || c == b'_')
                })
                .ok_or_else(|| invalid("error_codes", entry))?;
            let exit = entry
                .get("exit")
                .and_then(Value::as_i64)
                .and_then(|value| i32::try_from(value).ok())
                .filter(|exit| [failed, usage, incomplete].contains(exit))
                .ok_or_else(|| invalid("error_codes", entry))?;
            if error_exits.insert(code.to_owned(), exit).is_some() {
                return Err(invalid("error_codes", entry));
            }
        }
        if error_exits.get("USAGE") != Some(&usage)
            || error_exits.get("PUBLISH_INCOMPLETE") != Some(&incomplete)
            || error_exits.get("VERIFICATION_INCOMPLETE") != Some(&failed)
        {
            return Err(invalid("error_codes", errors));
        }
        Ok(Self {
            required_checks,
            ok_exit,
            error_exits,
        })
    }
}

/// Check a verification report against the connected engine's required checks.
/// Example: `verification_complete(&report, &contract)` rejects a missing check.
pub(crate) fn verification_complete(
    data: &Value,
    contract: &EngineContract,
) -> Result<bool, EngineError> {
    let invalid = |field: &str, expected: &str| {
        let value = data.get(field).unwrap_or(&Value::Null);
        let summary = match value {
            Value::String(value) if value.len() > 128 => format!("string ({} bytes)", value.len()),
            Value::Array(value) => format!("array ({} entries)", value.len()),
            Value::Object(value) => format!("object ({} fields)", value.len()),
            _ => value.to_string(),
        };
        EngineError::new(
            ErrorKind::Protocol,
            format!("verification {field}: expected {expected} | received {summary}"),
        )
    };
    let declared = data
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("complete", "a boolean"))?;
    let checks = data
        .get("checks")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("checks", "an array"))?;
    let skipped = data
        .get("skipped")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("skipped", "an array"))?;
    data.get("notice")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("notice", "a string"))?;
    let mut seen = HashSet::new();
    let valid_checks = checks.iter().all(|check| {
        check
            .get("check")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty() && seen.insert(name))
            && check.get("ok").and_then(Value::as_bool) == Some(true)
    });
    let required = contract.required_checks.iter().all(|name| {
        checks
            .iter()
            .filter(|check| check.get("check").and_then(Value::as_str) == Some(name))
            .count()
            == 1
    });
    Ok(declared && skipped.is_empty() && valid_checks && required)
}

/// An engine executable with a fixed, intentional working directory.
#[derive(Debug, Clone)]
pub struct Engine {
    executable: PathBuf,
    cwd: PathBuf,
    env: Vec<(OsString, OsString)>,
    timeout: Duration,
    contract: Option<Arc<EngineContract>>,
}

impl Engine {
    /// Set up an engine using absolute paths, independent of the opened image's directory.
    ///
    /// Example: `Engine::new("/usr/bin/bme", "/tmp")` configures a sibling engine.
    pub fn new(
        executable: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
    ) -> Result<Self, EngineError> {
        let executable = executable.into();
        let cwd = cwd.into();
        if !executable.is_absolute() || !cwd.is_absolute() {
            return Err(EngineError::new(
                ErrorKind::Configuration,
                format!(
                    "engine paths: expected absolute executable and working directory | received {} and {}",
                    executable.display(),
                    cwd.display()
                ),
            ));
        }
        Ok(Self {
            executable,
            cwd,
            env: Vec::new(),
            timeout: Duration::from_secs(120),
            contract: None,
        })
    }
    /// Override one child environment variable, for example isolated `BME_CONFIG_HOME` in tests.
    ///
    /// Example: `engine.with_env("BME_CONFIG_HOME", "/tmp/config")`.
    pub fn with_env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }
    /// Set the read-only operation timeout; publication is intentionally not interrupted.
    ///
    /// Example: `engine.with_timeout(std::time::Duration::from_secs(30))`.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    /// Bind subsequent requests to the contract obtained during connection.
    /// Example: `engine.with_contract(contract)` validates advertised exit codes.
    pub fn with_contract(mut self, contract: Arc<EngineContract>) -> Self {
        self.contract = Some(contract);
        self
    }
    /// Verify protocol identity, command groups and document versions before enabling operations.
    ///
    /// Example: `engine.handshake(&std::sync::atomic::AtomicBool::new(false))`.
    pub fn handshake(&self, cancel: &AtomicBool) -> Result<Reply, EngineError> {
        let (version, mut capabilities) = run_pair(
            cancel,
            |pair_cancel| self.run(&Request::Version, pair_cancel),
            |pair_cancel| self.run(&Request::Capabilities, pair_cancel),
        )?;
        let validation = validate_handshake(&version, &capabilities);
        let mut diagnostics = version.diagnostics;
        if diagnostics.is_empty() {
            std::mem::swap(&mut diagnostics, &mut capabilities.diagnostics);
        } else {
            append_diagnostics(&mut diagnostics, &capabilities.diagnostics);
        }
        match validation {
            Ok(()) => {
                capabilities.diagnostics = diagnostics;
                Ok(capabilities)
            }
            Err(mut error) => {
                append_diagnostics(&mut error.diagnostics, &diagnostics);
                Err(error)
            }
        }
    }
    /// Run one command, draining both output streams while waiting for it to exit.
    /// Non-handshake commands require the contract from a successful handshake.
    ///
    /// Example: `engine.run(&Request::Version, &std::sync::atomic::AtomicBool::new(false))`.
    pub fn run(&self, request: &Request, cancel: &AtomicBool) -> Result<Reply, EngineError> {
        if self.contract.is_none() && !matches!(request, Request::Version | Request::Capabilities) {
            return Err(EngineError::new(
                ErrorKind::Configuration,
                format!(
                    "engine {}: expected a validated connection contract | received none",
                    request.name()
                ),
            ));
        }
        let args = request.args(&self.cwd)?;
        let mut command = Command::new(&self.executable);
        command
            .args(args)
            .current_dir(&self.cwd)
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn().map_err(|e| {
            EngineError::new(
                ErrorKind::Launch,
                format!(
                    "engine {}: expected executable process | received {e}",
                    self.executable.display()
                ),
            )
        })?;
        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        #[cfg(unix)]
        if let Err(error) = nonblocking(&stdout).and_then(|()| nonblocking(&stderr)) {
            if request.publishes() {
                // Publication may already have started. Drain both pipes and wait for it
                // rather than treating a local setup failure as safe to interrupt.
                let out =
                    thread::spawn(move || drain_pipe(stdout, MAX_JSON, &AtomicBool::new(false)));
                let err = thread::spawn(move || {
                    drain_pipe(stderr, MAX_DIAGNOSTICS, &AtomicBool::new(false))
                });
                let _ = child.wait();
                let _ = out.join();
                let _ = err.join();
            } else {
                terminate_group(&mut child);
            }
            return Err(EngineError::new(
                ErrorKind::Io,
                format!("engine pipes: expected nonblocking reads | received {error}"),
            ));
        }
        let stop_readers = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel();
        let out_stop = stop_readers.clone();
        let out_sender = sender.clone();
        let out = thread::spawn(move || {
            let _ = out_sender.send((true, drain_pipe(stdout, MAX_JSON, &out_stop)));
        });
        let err_stop = stop_readers.clone();
        let err = thread::spawn(move || {
            let _ = sender.send((false, drain_pipe(stderr, MAX_DIAGNOSTICS, &err_stop)));
        });
        let started = Instant::now();
        let mut stdout = None;
        let mut stderr = None;
        let mut reaped_status = None;
        let mut stopped = None;
        let mut leader_done = false;
        let mut process_error = None;
        loop {
            while let Ok((is_stdout, result)) = receiver.try_recv() {
                if is_stdout {
                    stdout = Some(result);
                } else {
                    stderr = Some(result);
                }
            }
            if !leader_done {
                match leader_exited(&mut child, &mut reaped_status) {
                    Ok(exited) => leader_done = exited,
                    Err(error) => {
                        process_error = Some(error);
                        break;
                    }
                }
            }
            if leader_done && stdout.is_some() && stderr.is_some() {
                break;
            }
            if !request.publishes()
                && (cancel.load(Ordering::Relaxed) || started.elapsed() >= self.timeout)
            {
                stopped = Some(if cancel.load(Ordering::Relaxed) {
                    ErrorKind::Cancelled
                } else {
                    ErrorKind::Timeout
                });
                break;
            }
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok((true, result)) => stdout = Some(result),
                Ok((false, result)) => stderr = Some(result),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected)
                    if stdout.is_some() && stderr.is_some() =>
                {
                    // Both pipes closed before the process exited; keep checking
                    // its deadline without spinning on the disconnected channel.
                    thread::sleep(Duration::from_millis(10));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    process_error =
                        Some(io::Error::other("engine reader stopped without a result"));
                    break;
                }
            }
        }
        if stopped.is_some() || process_error.is_some() {
            if request.publishes() {
                // A supervision error cannot make it safe to interrupt publication.
                let _ = child.wait();
            } else {
                terminate_group(&mut child);
            }
            stop_readers.store(true, Ordering::Relaxed);
            // Unix readers are nonblocking and observe the stop flag even when a descendant
            // outside the group retains a pipe. No reader thread outlives this operation.
            #[cfg(unix)]
            {
                let _ = out.join();
                let _ = err.join();
            }
            for (is_stdout, result) in receiver.try_iter() {
                if !is_stdout {
                    stderr = Some(result);
                }
            }
            let diagnostics = stderr
                .and_then(Result::ok)
                .map(|stderr| stderr.text())
                .unwrap_or_default();
            let kind = stopped.unwrap_or(ErrorKind::Io);
            return Err(EngineError::new(
                kind,
                match kind {
                    ErrorKind::Cancelled => "engine operation cancelled".to_owned(),
                    ErrorKind::Timeout => "engine operation timed out".to_owned(),
                    _ => format!("engine process: {}", process_error.expect("process error")),
                },
            )
            .diagnostics(&diagnostics));
        }
        let status = match reaped_status {
            Some(status) => Ok(status),
            None => child.wait(),
        };
        let _ = out.join();
        let _ = err.join();
        let stdout = stdout
            .expect("stdout finished")
            .map_err(|e| EngineError::new(ErrorKind::Io, format!("engine stdout: {e}")))?;
        let stderr = stderr
            .expect("stderr finished")
            .map_err(|e| EngineError::new(ErrorKind::Io, format!("engine stderr: {e}")))?;
        let diagnostics = stderr.text();
        let status = status.map_err(|e| {
            EngineError::new(ErrorKind::Io, format!("engine process: {e}"))
                .diagnostics(&diagnostics)
        })?;
        let code = status.code().ok_or_else(|| {
            EngineError::new(
                ErrorKind::Interrupted,
                format!("engine process interrupted: {status}"),
            )
            .diagnostics(&diagnostics)
        })?;
        if stdout.overflow {
            return Err(EngineError::new(
                ErrorKind::OutputLimit,
                format!("engine response: expected at most {MAX_JSON} bytes | received more"),
            )
            .diagnostics(&diagnostics));
        }
        decode_with_contract(
            request.name(),
            code,
            &stdout.bytes,
            &diagnostics,
            self.contract.as_deref(),
        )
    }
}

/// Run two independent read-only requests and stop the peer after either fails.
/// Example: `run_pair(&cancel, |c| engine.run(&a, c), |c| engine.run(&b, c))`.
pub(crate) fn run_pair<F, G>(
    cancel: &AtomicBool,
    first: F,
    second: G,
) -> Result<(Reply, Reply), EngineError>
where
    F: FnOnce(&AtomicBool) -> Result<Reply, EngineError> + Send,
    G: FnOnce(&AtomicBool) -> Result<Reply, EngineError> + Send,
{
    if cancel.load(Ordering::Relaxed) {
        return Err(EngineError::new(
            ErrorKind::Cancelled,
            "engine operation cancelled",
        ));
    }
    let pair_cancel = AtomicBool::new(false);
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::channel();
        let first_sender = sender.clone();
        let pair_cancel_ref = &pair_cancel;
        scope.spawn(move || pair_worker(first, pair_cancel_ref, first_sender, 0));
        let pair_cancel_ref = &pair_cancel;
        let second_sender = sender.clone();
        scope.spawn(move || pair_worker(second, pair_cancel_ref, second_sender, 1));
        drop(sender);
        let mut results = [None, None];
        while results.iter().any(Option::is_none) {
            if cancel.load(Ordering::Relaxed) {
                pair_cancel.store(true, Ordering::Relaxed);
            }
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok((index, result)) => {
                    if result.is_err() {
                        pair_cancel.store(true, Ordering::Relaxed);
                    }
                    results[index] = Some(result);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(EngineError::new(
                        ErrorKind::Io,
                        "engine pair stopped without both results",
                    ));
                }
            }
        }
        let [first, second] = results.map(Option::unwrap);
        if cancel.load(Ordering::Relaxed) {
            let mut error = EngineError::new(ErrorKind::Cancelled, "engine operation cancelled");
            for result in [&first, &second] {
                let diagnostics = match result {
                    Ok(reply) => &reply.diagnostics,
                    Err(error) => &error.diagnostics,
                };
                append_diagnostics(&mut error.diagnostics, diagnostics);
            }
            return Err(error);
        }
        match (first, second) {
            (Ok(first), Ok(second)) => Ok((first, second)),
            (Err(first), Err(mut second))
                if first.kind == ErrorKind::Cancelled && second.kind != ErrorKind::Cancelled =>
            {
                append_diagnostics(&mut second.diagnostics, &first.diagnostics);
                Err(second)
            }
            (Err(mut first), Err(second)) => {
                append_diagnostics(&mut first.diagnostics, &second.diagnostics);
                Err(first)
            }
            (Err(mut error), Ok(peer)) | (Ok(peer), Err(mut error)) => {
                append_diagnostics(&mut error.diagnostics, &peer.diagnostics);
                Err(error)
            }
        }
    })
}

/// Retain both streams' diagnostics when independent requests complete.
/// Example: appending `"paths"` to `"doctor"` yields `"doctor\npaths"`.
pub(crate) fn append_diagnostics(destination: &mut String, extra: &str) {
    if !extra.is_empty() {
        if !destination.is_empty() {
            destination.push('\n');
        }
        destination.push_str(extra);
    }
}

/// Execute one paired request and always report its result to the coordinator.
fn pair_worker<F>(
    operation: F,
    cancel: &AtomicBool,
    sender: mpsc::Sender<(usize, Result<Reply, EngineError>)>,
    index: usize,
) where
    F: FnOnce(&AtomicBool) -> Result<Reply, EngineError>,
{
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(cancel)))
        .unwrap_or_else(|_| {
            Err(EngineError::new(
                ErrorKind::Io,
                "engine pair worker panicked",
            ))
        });
    let _ = sender.send((index, result));
}

struct Drained {
    bytes: Vec<u8>,
    overflow: bool,
}
impl Drained {
    /// Render captured stderr, marking truncation.
    fn text(&self) -> String {
        let mut text = String::from_utf8_lossy(&self.bytes).into_owned();
        if self.overflow {
            text.push_str("\n[diagnostics truncated]");
        }
        text
    }
}
#[cfg(test)]
fn drain(reader: impl Read, limit: usize) -> io::Result<Drained> {
    drain_until(reader, limit, &AtomicBool::new(false), |_| Ok(()))
}

#[cfg(unix)]
fn drain_pipe(
    reader: impl Read + std::os::fd::AsRawFd,
    limit: usize,
    stop: &AtomicBool,
) -> io::Result<Drained> {
    drain_until(reader, limit, stop, |reader| {
        let mut descriptor = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor names a live child pipe for the duration of this call.
        let result = unsafe { libc::poll(&mut descriptor, 1, 10) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(())
    })
}

#[cfg(not(unix))]
fn drain_pipe(reader: impl Read, limit: usize, stop: &AtomicBool) -> io::Result<Drained> {
    drain_until(reader, limit, stop, |_| {
        thread::sleep(Duration::from_millis(10));
        Ok(())
    })
}

fn drain_until<R: Read>(
    mut reader: R,
    limit: usize,
    stop: &AtomicBool,
    mut wait: impl FnMut(&R) -> io::Result<()>,
) -> io::Result<Drained> {
    let mut bytes = Vec::new();
    let mut overflow = false;
    let mut buf = [0; 16384];
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let count = match reader.read(&mut buf) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait(&reader)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        if count == 0 {
            break;
        }
        let keep = count.min(limit.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buf[..keep]);
        overflow |= keep < count;
    }
    Ok(Drained { bytes, overflow })
}

#[cfg(unix)]
fn nonblocking(pipe: &impl std::os::fd::AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: fd belongs to a live pipe and fcntl does not take ownership.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL only changes the status flags of this live pipe.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn leader_exited(
    child: &mut std::process::Child,
    _: &mut Option<std::process::ExitStatus>,
) -> io::Result<bool> {
    // WNOWAIT preserves the leader PID until the pipes close or the group is killed.
    // This prevents reuse of the process-group ID while we supervise descendants.
    // SAFETY: zeroed siginfo_t is a valid output buffer for waitid.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: child.id() names our live child, and info points to writable storage.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: waitid initialized info; an empty result has si_pid == 0.
    Ok(unsafe { info.si_pid() } != 0)
}

#[cfg(not(target_os = "linux"))]
fn leader_exited(
    child: &mut std::process::Child,
    status: &mut Option<std::process::ExitStatus>,
) -> io::Result<bool> {
    *status = child.try_wait()?;
    Ok(status.is_some())
}

fn terminate_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: each child is started in its own process group, whose ID is its PID.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn validate_handshake(version: &Reply, capabilities: &Reply) -> Result<(), EngineError> {
    let fail = |message: String| EngineError::new(ErrorKind::Protocol, message);
    for field in ["desktop_workflow", "direct_patch_workflow"] {
        let revision = &capabilities.data[field];
        if revision.as_u64() != Some(1) {
            return Err(fail(format!(
                "engine capability {field}: expected revision 1 | received {revision}; use the matching bundled bme"
            )));
        }
    }
    let version_protocol = version.data.get("protocol").and_then(Value::as_str);
    let capabilities_protocol = capabilities.data.get("protocol").and_then(Value::as_str);
    let version_engine = version.data.get("engine").and_then(Value::as_str);
    let capabilities_engine = capabilities.data.get("engine").and_then(Value::as_str);
    if version_protocol != Some("bme/1")
        || capabilities_protocol != Some("bme/1")
        || version_engine != Some(version.version.as_str())
        || capabilities_engine != version_engine
        || capabilities.version != version.version
    {
        return Err(fail(format!(
            "engine handshake: expected matching engine versions and bme/1 protocol | received version {} ({:?}, {:?}) and capabilities {} ({:?}, {:?})",
            version.version,
            version_engine,
            version_protocol,
            capabilities.version,
            capabilities_engine,
            capabilities_protocol
        )));
    }
    let commands = capabilities
        .data
        .get("commands")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("engine capabilities: expected commands array".into()))?;
    for required in [
        "inspect",
        "scan",
        "export",
        "patch",
        "patch --dry-run",
        "verify",
        "catalog validate|index|show|import-x99fix",
        "catalog add|list|remove",
        "tools doctor|paths",
    ] {
        if !commands
            .iter()
            .any(|v| v.get("name").and_then(Value::as_str) == Some(required))
        {
            return Err(fail(format!(
                "engine capabilities: expected command group {required}"
            )));
        }
    }
    let docs = capabilities
        .data
        .get("documents")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("engine capabilities: expected documents array".into()))?;
    for (name, schema) in [
        ("plan", "bme.plan/1"),
        ("manifest", "bme.manifest/1"),
        ("catalog", "bme.catalog/1"),
        ("patch", "bme.patch/1"),
    ] {
        if !docs.iter().any(|v| {
            v.get("name").and_then(Value::as_str) == Some(name)
                && v.get("schema").and_then(Value::as_str) == Some(schema)
        }) {
            return Err(fail(format!(
                "engine capabilities: expected document {name} {schema}"
            )));
        }
    }
    EngineContract::from_capabilities(&capabilities.data)?;
    Ok(())
}

#[cfg(test)]
mod tests;
