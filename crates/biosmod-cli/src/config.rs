//! Per-user configuration (TOML) and directory layout.
//!
//! Locations follow the XDG base directories on Linux and can be overridden
//! with `BME_CONFIG_HOME`, `BME_CACHE_HOME` and `BME_DATA_HOME` (used by tests
//! and portable setups).

use biosmod_core::{Code, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const APP: &str = "biosmod-engine";

/// Resolved per-user directories.
#[derive(Debug, Clone, Serialize)]
pub struct Paths {
    pub config: PathBuf,
    pub cache: PathBuf,
    pub data: PathBuf,
}

impl Paths {
    /// Resolve from the process environment for the current platform.
    pub fn from_env() -> Result<Paths> {
        Paths::resolve(
            &|key| std::env::var_os(key).filter(|v| !v.is_empty()),
            std::env::consts::OS,
        )
    }

    /// Resolve with `BME_*_HOME`, then `XDG_*_HOME`, then the platform default.
    ///
    /// Example: `Paths::resolve(&|k| (k == "HOME").then(|| "/home/u".into()), "linux")`
    /// gives `/home/u/.config/biosmod-engine` for configuration.
    pub fn resolve(get: &dyn Fn(&str) -> Option<OsString>, os: &str) -> Result<Paths> {
        let base = |var: &str| {
            get(var)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        };
        let default = |kind: usize| -> Option<PathBuf> {
            match os {
                "windows" => {
                    let roaming = base("APPDATA")?.join(APP);
                    let local = base("LOCALAPPDATA")?.join(APP);
                    Some([roaming, local.join("cache"), local.join("data")][kind].clone())
                }
                "macos" => {
                    let library = base("HOME")?.join("Library");
                    let support = library.join("Application Support").join(APP);
                    Some(
                        [
                            support.clone(),
                            library.join("Caches").join(APP),
                            support.join("data"),
                        ][kind]
                            .clone(),
                    )
                }
                _ => Some(
                    base("HOME")?
                        .join([".config", ".cache", ".local/share"][kind])
                        .join(APP),
                ),
            }
        };
        let pick = |kind: usize, own: &str, xdg: &str| -> Result<PathBuf> {
            if let Some(dir) = base(own) {
                return Ok(dir);
            }
            if let Some(dir) = base(xdg).filter(|dir| dir.is_absolute()) {
                return Ok(dir.join(APP));
            }
            default(kind).ok_or_else(|| {
                Error::new(
                    Code::Io,
                    format!("{own}: no home directory found for {os}; set {own} explicitly"),
                )
            })
        };
        Ok(Paths {
            config: pick(0, "BME_CONFIG_HOME", "XDG_CONFIG_HOME")?,
            cache: pick(1, "BME_CACHE_HOME", "XDG_CACHE_HOME")?,
            data: pick(2, "BME_DATA_HOME", "XDG_DATA_HOME")?,
        })
    }

    pub fn config_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Local,
    Remote,
}

/// One registered catalog source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    pub kind: SourceKind,
    /// Absolute directory (local) or HTTPS URL of `catalog.json` (remote).
    pub location: String,
    /// Minisign public key (base64), when the source is signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_key: Option<String>,
    /// Explicit user policy accepting an unsigned local source.
    #[serde(default)]
    pub allow_unsigned: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolsConfig {
    /// Ghidra installation directory to use instead of the managed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ghidra_home: Option<PathBuf>,
}

/// The configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub sources: BTreeMap<String, SourceConfig>,
    #[serde(default)]
    pub tools: ToolsConfig,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            version: 1,
            sources: BTreeMap::new(),
            tools: ToolsConfig::default(),
        }
    }
}

impl Config {
    /// Load the configuration, or defaults when the file does not exist.
    pub fn load(paths: &Paths) -> Result<Config> {
        let file = paths.config_file();
        let text = match fs::read_to_string(&file) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => return Err(io_error(&file, e)),
        };
        let config: Config = toml::from_str(&text)
            .map_err(|e| Error::new(Code::Usage, format!("{}: {e}", file.display())))?;
        if config.version != 1 {
            return Err(Error::new(
                Code::Usage,
                format!("{}: version {}: expected 1", file.display(), config.version),
            ));
        }
        Ok(config)
    }

    /// Save atomically (temporary file in the same directory, then rename).
    pub fn save(&self, paths: &Paths) -> Result<()> {
        let text = toml::to_string_pretty(self)
            .map_err(|e| Error::new(Code::Internal, format!("config serialization: {e}")))?;
        write_atomic(&paths.config_file(), text.as_bytes())
    }
}

/// `Io` error naming the path.
pub fn io_error(path: &Path, error: std::io::Error) -> Error {
    Error::new(Code::Io, format!("{}: {error}", path.display()))
}

/// Create `path`, failing if it exists, and write `bytes` to it.
///
/// Example: `write_new(Path::new("plan.json"), b"{}")?;`
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|e| io_error(path, e))
}

/// Replace `path` atomically with `bytes`, creating parent directories.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| io_error(parent, e))?;
    temp.write_all(bytes)
        .and_then(|()| temp.as_file().sync_all())
        .map_err(|e| io_error(temp.path(), e))?;
    temp.persist(path).map_err(|e| io_error(path, e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_new_creates_the_file_and_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        write_new(&path, b"first").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");
        let error = write_new(&path, b"second").unwrap_err();
        assert_eq!(
            error.code,
            Code::Io,
            "expected Io for an existing file: {error:?}"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            b"first",
            "existing file untouched"
        );
    }

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |key| {
            vars.iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn relative_and_empty_xdg_paths_use_platform_defaults() {
        let paths = Paths::resolve(
            &env(&[
                ("HOME", "/home/user"),
                ("XDG_CONFIG_HOME", "relative"),
                ("XDG_CACHE_HOME", ""),
                ("XDG_DATA_HOME", "also-relative"),
            ]),
            "linux",
        )
        .unwrap();
        assert_eq!(
            paths.config,
            PathBuf::from("/home/user/.config/biosmod-engine"),
            "relative XDG_CONFIG_HOME must use HOME"
        );
        assert_eq!(
            paths.cache,
            PathBuf::from("/home/user/.cache/biosmod-engine"),
            "empty XDG_CACHE_HOME must use HOME"
        );
        assert_eq!(
            paths.data,
            PathBuf::from("/home/user/.local/share/biosmod-engine"),
            "relative XDG_DATA_HOME must use HOME"
        );
    }

    #[test]
    fn empty_explicit_home_uses_xdg_directory() {
        let paths = Paths::resolve(
            &env(&[
                ("HOME", "/home/user"),
                ("BME_CONFIG_HOME", ""),
                ("XDG_CONFIG_HOME", "/xdg"),
            ]),
            "linux",
        )
        .unwrap();
        assert_eq!(
            paths.config,
            PathBuf::from("/xdg/biosmod-engine"),
            "empty BME_CONFIG_HOME: expected XDG directory | received {:?}",
            paths.config
        );
    }

    #[test]
    fn platform_defaults_and_overrides() {
        let linux = Paths::resolve(&env(&[("HOME", "/home/u")]), "linux").unwrap();
        assert_eq!(
            linux.config,
            PathBuf::from("/home/u/.config/biosmod-engine")
        );
        assert_eq!(
            linux.data,
            PathBuf::from("/home/u/.local/share/biosmod-engine")
        );
        let mac = Paths::resolve(&env(&[("HOME", "/Users/u")]), "macos").unwrap();
        assert_eq!(
            mac.cache,
            PathBuf::from("/Users/u/Library/Caches/biosmod-engine")
        );
        let windows = Paths::resolve(
            &env(&[("APPDATA", "C:/R"), ("LOCALAPPDATA", "C:/L")]),
            "windows",
        )
        .unwrap();
        assert_eq!(
            (windows.config, windows.cache),
            (
                PathBuf::from("C:/R/biosmod-engine"),
                PathBuf::from("C:/L/biosmod-engine/cache")
            )
        );
        let overridden = Paths::resolve(
            &env(&[
                ("HOME", "/h"),
                ("XDG_CACHE_HOME", "/x"),
                ("BME_DATA_HOME", "/d"),
            ]),
            "linux",
        )
        .unwrap();
        assert_eq!(
            (overridden.cache, overridden.data),
            (PathBuf::from("/x/biosmod-engine"), PathBuf::from("/d"))
        );
        let error = Paths::resolve(&env(&[]), "linux").unwrap_err();
        assert!(
            error.message.contains("set BME_CONFIG_HOME explicitly"),
            "{error}"
        );
    }

    #[test]
    fn config_round_trips_and_rejects_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: dir.path().into(),
            cache: dir.path().into(),
            data: dir.path().into(),
        };
        assert!(Config::load(&paths).unwrap().sources.is_empty());
        let mut config = Config::default();
        config.tools.ghidra_home = Some("/opt/ghidra".into());
        config.save(&paths).unwrap();
        assert_eq!(
            Config::load(&paths).unwrap().tools.ghidra_home,
            Some(PathBuf::from("/opt/ghidra"))
        );
        std::fs::write(
            paths.config_file(),
            "version = 1\ntrust_everything = true\n",
        )
        .unwrap();
        assert_eq!(Config::load(&paths).unwrap_err().code, Code::Usage);
    }
}
