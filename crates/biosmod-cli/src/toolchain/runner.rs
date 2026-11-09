//! External program execution with timeouts and bounded captured output.

use biosmod_core::{Code, Error, Result};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Captured output kept per stream.
const TAIL: u64 = 64 << 10;

/// A program to run.
#[derive(Debug, Clone)]
pub struct Invocation {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub env: Vec<(String, OsString)>,
    pub timeout: Duration,
    /// Send stdout and stderr to this file instead of a temporary capture.
    pub log: Option<PathBuf>,
}

impl Invocation {
    pub fn new(program: impl AsRef<Path>) -> Invocation {
        Invocation {
            program: program.as_ref().to_path_buf(),
            args: Vec::new(),
            env: Vec::new(),
            timeout: Duration::from_secs(300),
            log: None,
        }
    }

    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Invocation {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    pub fn args<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(mut self, args: I) -> Invocation {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    /// Insert `flag value` before the existing arguments (used for `git -C dir`).
    pub fn arg_first(mut self, flag: &str, value: &Path) -> Invocation {
        self.args.splice(
            0..0,
            [OsString::from(flag), value.as_os_str().to_os_string()],
        );
        self
    }

    pub fn env(mut self, key: &str, value: impl AsRef<OsStr>) -> Invocation {
        self.env.push((key.into(), value.as_ref().to_os_string()));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Invocation {
        self.timeout = timeout;
        self
    }

    pub fn log(mut self, path: &Path) -> Invocation {
        self.log = Some(path.to_path_buf());
        self
    }

    /// Arguments as lossy strings (for test fakes).
    #[cfg(test)]
    pub fn words(&self) -> Vec<String> {
        self.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }
}

/// How a program ended.
#[derive(Debug, Clone, Default)]
pub struct Finished {
    pub status: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
}

impl Finished {
    pub fn success(&self) -> bool {
        self.status == Some(0) && !self.timed_out
    }

    pub fn output(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }

    pub fn describe(&self) -> String {
        match (self.timed_out, self.status) {
            (true, _) => "timed out".into(),
            (false, Some(code)) => format!("exit status {code}"),
            (false, None) => "killed by a signal".into(),
        }
    }

    /// The last `chars` characters of combined output.
    pub fn tail(&self, chars: usize) -> String {
        let all = self.output();
        let trimmed = all.trim();
        let start = trimmed
            .char_indices()
            .rev()
            .nth(chars)
            .map_or(0, |(i, _)| i);
        trimmed[start..].to_string()
    }
}

/// Runs external programs.
pub trait Runner {
    fn run(&self, invocation: &Invocation) -> Result<Finished>;
}

/// The real process runner.
pub struct System;

fn tail_of(file: &mut fs::File) -> String {
    let len = file.seek(SeekFrom::End(0)).unwrap_or(0);
    let _ = file.seek(SeekFrom::Start(len.saturating_sub(TAIL)));
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Kill the whole process group led by `pid` (Unix); elsewhere only the child is killed.
fn kill_group(pid: u32) {
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-s", "KILL", "--", &format!("-{pid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    #[cfg(not(unix))]
    let _ = pid;
}

impl Runner for System {
    fn run(&self, invocation: &Invocation) -> Result<Finished> {
        let name = invocation.program.display().to_string();
        let io = |e: std::io::Error| Error::new(Code::ToolUnavailable, format!("{name}: {e}"));
        let (mut out, mut err) = match &invocation.log {
            Some(path) => {
                let file = fs::File::create(path).map_err(io)?;
                (file.try_clone().map_err(io)?, file)
            }
            None => (
                tempfile::tempfile().map_err(io)?,
                tempfile::tempfile().map_err(io)?,
            ),
        };
        let mut command = Command::new(&invocation.program);
        command
            .args(&invocation.args)
            .stdin(Stdio::null())
            .stdout(out.try_clone().map_err(io)?)
            .stderr(err.try_clone().map_err(io)?);
        for (key, value) in &invocation.env {
            command.env(key, value);
        }
        // Own process group, so a timeout also stops what a launcher script started (Ghidra's JVM).
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let mut child = command.spawn().map_err(io)?;
        let deadline = Instant::now() + invocation.timeout;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(io)? {
                break Some(status);
            }
            if Instant::now() >= deadline {
                kill_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let stdout = tail_of(&mut out);
        let stderr = if invocation.log.is_some() {
            String::new()
        } else {
            tail_of(&mut err)
        };
        Ok(Finished {
            status: status.and_then(|s| s.code()),
            timed_out: status.is_none(),
            stdout,
            stderr,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn captures_output_status_and_timeouts() {
        let done = System
            .run(&Invocation::new("sh").args(["-c", "echo out; echo err >&2; exit 3"]))
            .unwrap();
        assert_eq!(
            (done.status, done.stdout.trim(), done.stderr.trim()),
            (Some(3), "out", "err")
        );
        let slow = System
            .run(
                &Invocation::new("sh")
                    .args(["-c", "sleep 5"])
                    .timeout(Duration::from_millis(200)),
            )
            .unwrap();
        assert!(slow.timed_out && !slow.success());
        let missing = System
            .run(&Invocation::new("/nonexistent/bme-test"))
            .unwrap_err();
        assert_eq!(missing.code, Code::ToolUnavailable);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn timeout_kills_grandchildren() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = format!("sleep 30 & echo $! > {}; wait", pidfile.display());
        let done = System
            .run(
                &Invocation::new("sh")
                    .args(["-c", &script])
                    .timeout(Duration::from_millis(300)),
            )
            .unwrap();
        assert!(done.timed_out);
        let pid = fs::read_to_string(&pidfile).unwrap().trim().to_string();
        let gone = (0..40).any(|_| {
            let state = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            let dead =
                state.is_empty() || state.split(") ").nth(1).is_some_and(|s| s.starts_with('Z'));
            if !dead {
                std::thread::sleep(Duration::from_millis(50));
            }
            dead
        });
        assert!(
            gone,
            "(grandchild {pid}): expected killed with its group | still running"
        );
    }
}
