//! Helpers for running the `bme` binary in an isolated environment.

#![allow(dead_code)]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One isolated user: private config, cache and data directories.
pub struct Sandbox {
    pub dir: tempfile::TempDir,
}

/// Result of one invocation.
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    /// Parse stdout as the single JSON envelope.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "(stdout): expected one JSON document | {e}\n{}\nstderr: {}",
                self.stdout, self.stderr
            )
        })
    }

    /// The error code of a failed envelope.
    pub fn error_code(&self) -> String {
        let doc = self.json();
        assert_eq!(
            doc["ok"], false,
            "(envelope ok): expected false | received {doc}"
        );
        doc["error"]["code"].as_str().unwrap().to_string()
    }
}

impl Sandbox {
    pub fn new() -> Sandbox {
        Sandbox {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Run `bme` with arguments.
    pub fn run<I: IntoIterator<Item = S>, S: AsRef<std::ffi::OsStr>>(&self, args: I) -> Run {
        self.run_with_env(args, &[])
    }

    /// Run `bme` with arguments and extra environment variables.
    pub fn run_with_env<I: IntoIterator<Item = S>, S: AsRef<std::ffi::OsStr>>(
        &self,
        args: I,
        variables: &[(&str, &Path)],
    ) -> Run {
        let output = Command::new(env!("CARGO_BIN_EXE_bme"))
            .args(args)
            .env_remove("BME_FLASHROM")
            .env_remove("BME_REPLAY_PYTHON")
            .envs(variables.iter().copied())
            .env("BME_CONFIG_HOME", self.path("config"))
            .env("BME_CACHE_HOME", self.path("cache"))
            .env("BME_DATA_HOME", self.path("data"))
            .env_remove("GHIDRA_INSTALL_DIR")
            .output()
            .unwrap();
        Run {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8(output.stdout).unwrap(),
            stderr: String::from_utf8(output.stderr).unwrap(),
        }
    }

    /// Write the synthetic image and catalog; returns (image, catalog dir).
    pub fn synthetic(&self) -> (PathBuf, PathBuf) {
        let run = self.run(["dev", "synthetic", "-o", self.path("syn").to_str().unwrap()]);
        assert_eq!(run.code, 0, "{}", run.stderr);
        (self.path("syn/synthetic.bin"), self.path("syn/catalog"))
    }
}

/// Path argument helper.
pub fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Write a directory shaped like a `bme diag acpi capture`: each `(name, bytes)` under
/// `acpi/tables/`, a `bme.host-capture/1` manifest listing them with their SHA-256, and
/// `evidence.json` last. `name` may hold a subdirectory such as `dynamic/SSDT3`.
///
/// Example: `write_capture_directory(&dir, &[("DSDT", dsdt_bytes)]);`
pub fn write_capture_directory(dir: &Path, tables: &[(&str, Vec<u8>)]) {
    let mut listed = Vec::new();
    for (name, bytes) in tables {
        let relative = format!("acpi/tables/{name}");
        let target = dir.join(&relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, bytes).unwrap();
        listed.push(serde_json::json!({
            "path": relative,
            "bytes": bytes.len(),
            "sha256": biosmod_core::util::sha256_hex(bytes),
        }));
    }
    let manifest = serde_json::json!({
        "schema": "bme.host-capture/1",
        "command": "diag acpi capture",
        "files": listed,
        "skipped": [],
    });
    std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
    std::fs::write(dir.join("evidence.json"), "{}").unwrap();
}
