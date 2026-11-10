//! Presentation settings are separate from engine configuration and source trust.

use crate::controller::read_regular_file;
use crate::i18n::Language;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub language: Language,
    #[serde(default)]
    pub theme: u8,
    #[serde(default)]
    pub engine: Option<PathBuf>,
}

impl Settings {
    /// Read a bounded settings file, returning defaults when it has not been created.
    /// Example: `Settings::load(Path::new("/tmp/gui.json"))?`.
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = match read_regular_file(path, 64 * 1024) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(format!("settings {}: {error}", path.display())),
        };
        let settings: Self =
            serde_json::from_slice(&bytes).map_err(|e| format!("settings: {e}"))?;
        if settings.theme > 2 {
            return Err(format!(
                "theme: expected 0 (system), 1 (light), or 2 (dark) | received {}",
                settings.theme
            ));
        }
        Ok(settings)
    }

    /// Atomically save presentation preferences and engine choice, without storing image paths.
    /// Example: `settings.save(Path::new("/tmp/bme/gui.json"))?`.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let directory = path
            .parent()
            .ok_or("settings path: expected a parent directory")?;
        std::fs::create_dir_all(directory).map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let mut temp = tempfile::NamedTempFile::new_in(directory).map_err(|e| e.to_string())?;
        temp.write_all(&bytes).map_err(|e| e.to_string())?;
        temp.persist(path).map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Where the desktop may persist preference changes for this session.
/// Example: `PreferencesStore::Protected(path)` keeps a malformed `gui.json` untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreferencesStore {
    /// Save changes to this file.
    Writable(PathBuf),
    /// The file exists but could not be loaded, so it stays as found for manual recovery.
    Protected(PathBuf),
    /// Neither `XDG_CONFIG_HOME` nor `HOME` names a configuration directory.
    Unavailable,
}

/// Resolve presentation configuration using XDG, falling back to the home directory.
/// Example: `settings_path(Some("/tmp/config".into()), None)` resolves `/tmp/config/biosmod-engine/gui.json`.
pub fn settings_path(xdg: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    xdg.filter(|p| p.is_absolute())
        .or_else(|| home.map(|h| h.join(".config")))
        .map(|p| p.join("biosmod-engine/gui.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn presentation_round_trip_and_invalid_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/gui.json");
        assert_eq!(Settings::load(&path).unwrap().theme, 0);
        let settings = Settings {
            language: Language::PtBr,
            theme: 2,
            engine: Some("/tmp/engine path".into()),
        };
        settings.save(&path).unwrap();
        let restored = Settings::load(&path).unwrap();
        assert_eq!(restored.theme, 2);
        assert_eq!(restored.language, Language::PtBr);
        assert_eq!(restored.engine, settings.engine);
        std::fs::write(&path, br#"{"theme":9}"#).unwrap();
        assert!(Settings::load(&path).unwrap_err().contains("received 9"));
        assert_eq!(
            settings_path(Some("/tmp/c".into()), None),
            Some("/tmp/c/biosmod-engine/gui.json".into())
        );
        assert_eq!(
            settings_path(Some("relative".into()), Some("/home/test".into())),
            Some("/home/test/.config/biosmod-engine/gui.json".into())
        );
        assert_eq!(settings_path(None, None), None);
    }

    #[test]
    fn language_defaults_preserve_other_preferences() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gui.json");
        for language in [
            None,
            Some(serde_json::json!("unknown")),
            Some(serde_json::json!(false)),
            Some(serde_json::json!(null)),
        ] {
            let mut value = serde_json::json!({"theme": 1, "engine": "/tmp/custom-bme"});
            if let Some(language) = language {
                value["language"] = language;
            }
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let settings = Settings::load(&path).unwrap();
            assert_eq!(
                settings.language,
                Language::En,
                "language: expected English fallback | received {value}"
            );
            assert_eq!(settings.theme, 1);
            assert_eq!(settings.engine, Some("/tmp/custom-bme".into()));
        }
    }

    #[test]
    fn settings_save_failure_leaves_original_file() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, b"original").unwrap();
        assert!(Settings::default().save(&blocker.join("gui.json")).is_err());
        assert_eq!(std::fs::read(&blocker).unwrap(), b"original");
        assert_eq!(
            settings_path(Some("".into()), Some("/home/test".into())),
            Some("/home/test/.config/biosmod-engine/gui.json".into())
        );
        std::fs::write(&blocker, b"{bad-json").unwrap();
        assert!(Settings::load(&blocker).unwrap_err().contains("settings:"));
        assert_eq!(std::fs::read(&blocker).unwrap(), b"{bad-json");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_settings_are_refused_without_blocking_startup() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("gui.json");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: name is terminated and names a file in this private test directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(Settings::load(&fifo));
        });
        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("settings FIFO: expected an immediate refusal | received a blocked open");
        let error = result.unwrap_err();
        assert!(error.contains("regular file"), "{error}");
    }
}
