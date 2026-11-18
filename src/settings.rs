//! Persistent user preferences and the shared save-folder handle.
//!
//! Settings live in a small JSON file under the platform config directory.
//! The file is written atomically so an interrupted save cannot leave a
//! truncated preference behind.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::paths;

/// Visual palette used by the window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeKind {
    #[default]
    Dark,
    Light,
}

impl ThemeKind {
    pub fn toggled(self) -> Self {
        match self {
            Self::Dark => Self::Light,
            Self::Light => Self::Dark,
        }
    }
}

/// Persisted preferences. Missing fields fall back to the defaults, so a
/// future version can add settings without rejecting an older file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeKind,
    /// `None` means the platform Downloads directory.
    pub save_dir: Option<PathBuf>,
}

impl Settings {
    /// Load the user settings and, on failure, a message suitable for the
    /// activity log. A missing file is not an error.
    pub fn load() -> (Self, Option<String>) {
        Self::load_from(&paths::settings_file())
    }

    pub fn load_from(path: &Path) -> (Self, Option<String>) {
        match std::fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str(&raw) {
                Ok(settings) => (settings, None),
                Err(error) => (
                    Self::default(),
                    Some(format!(
                        "settings at {} are invalid ({error}); using defaults",
                        path.display()
                    )),
                ),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (Self::default(), None),
            Err(error) => (
                Self::default(),
                Some(format!(
                    "cannot read settings at {} ({error}); using defaults",
                    path.display()
                )),
            ),
        }
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&paths::settings_file())
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        write_json(path, self).context("save settings")
    }
}

/// The folder incoming files go to. Shared with the running receiver so a
/// preference change applies to the next transfer without a restart.
#[derive(Debug, Clone)]
pub struct SaveDir {
    path: Arc<Mutex<PathBuf>>,
}

impl SaveDir {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: Arc::new(Mutex::new(path)),
        }
    }

    pub fn get(&self) -> PathBuf {
        self.path.lock().expect("save folder lock").clone()
    }

    pub fn set(&self, path: PathBuf) {
        *self.path.lock().expect("save folder lock") = path;
    }
}

/// Write JSON through a uniquely named sibling and rename it into place.
/// Used by both settings and the trust store.
pub(crate) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    crate::security::create_private_dir(parent)
        .with_context(|| format!("create config directory {}", parent.display()))?;

    let bytes = serde_json::to_vec_pretty(value).context("serialize config")?;
    let temporary = parent.join(format!(".kalo-{}.tmp", Uuid::new_v4().simple()));
    let write = (|| -> Result<()> {
        let mut file = std::fs::File::create(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        crate::security::restrict_file_permissions(&temporary)?;
        file.write_all(&bytes)
            .with_context(|| format!("write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temporary.display()))?;
        drop(file);
        std::fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
        Ok(())
    })();
    if write.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    write
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kalo-test-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_settings_use_defaults_without_a_warning() {
        let dir = temp_dir();
        let (settings, warning) = Settings::load_from(&dir.join("settings.json"));
        assert_eq!(settings, Settings::default());
        assert!(warning.is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn invalid_settings_fall_back_and_warn() {
        let dir = temp_dir();
        let path = dir.join("settings.json");
        std::fs::write(&path, "{not json").unwrap();

        let (settings, warning) = Settings::load_from(&path);
        assert_eq!(settings, Settings::default());
        assert!(warning.unwrap().contains("invalid"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn settings_round_trip() {
        let dir = temp_dir();
        let path = dir.join("nested").join("settings.json");
        let settings = Settings {
            theme: ThemeKind::Light,
            save_dir: Some(dir.join("Received")),
        };
        settings.save_to(&path).unwrap();

        let (loaded, warning) = Settings::load_from(&path);
        assert!(warning.is_none());
        assert_eq!(loaded, settings);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn theme_toggle_round_trips() {
        assert_eq!(ThemeKind::Dark.toggled(), ThemeKind::Light);
        assert_eq!(ThemeKind::Light.toggled(), ThemeKind::Dark);
    }

    #[test]
    fn save_dir_is_shared_between_handles() {
        let first = SaveDir::new(PathBuf::from("/tmp/one"));
        let second = first.clone();
        second.set(PathBuf::from("/tmp/two"));
        assert_eq!(first.get(), PathBuf::from("/tmp/two"));
    }
}
