//! Presentation settings are separate from engine configuration and source trust.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub theme: u8,
    #[serde(default)]
    pub engine: Option<PathBuf>,
}

impl Settings {
    /// Read a bounded settings file, returning defaults when it has not been created.
    /// Example: `Settings::load(Path::new("/tmp/gui.json"))?`.
    pub fn load(path: &Path) -> Result<Self, String> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(format!("settings {}: {error}", path.display())),
        };
        let mut bytes = Vec::new();
        file.take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 64 * 1024 {
            return Err("settings: expected at most 64 KiB".into());
        }
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

    /// Atomically save theme and explicit engine choice, without storing image paths.
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
            theme: 2,
            engine: Some("/tmp/engine path".into()),
        };
        settings.save(&path).unwrap();
        let restored = Settings::load(&path).unwrap();
        assert_eq!(restored.theme, 2);
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
}
