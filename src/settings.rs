//! Persistent user preferences and the shared save-folder handle.
//!
//! Settings live in a small JSON file under the platform config directory.
//! The file is written atomically so an interrupted save cannot leave a
//! truncated preference behind.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::paths;

/// Keyring service and account names for the shared encryption passphrase.
const KEYRING_SERVICE: &str = "Kalo";
const KEYRING_ACCOUNT: &str = "encryption-passphrase";

/// Where the passphrase is kept. The real implementation uses the platform
/// credential store; tests substitute an in-memory store.
pub trait SecretStore {
    fn get(&self) -> Result<Option<String>>;
    fn set(&self, secret: Option<&str>) -> Result<()>;
}

/// Platform keyring: Secret Service on Linux, Credential Manager on Windows,
/// and Keychain on macOS.
pub struct KeyringStore;

impl SecretStore for KeyringStore {
    fn get(&self) -> Result<Option<String>> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
            .map_err(|error| anyhow!("open the system keyring: {error}"))?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(anyhow!("read the system keyring: {error}")),
        }
    }

    fn set(&self, secret: Option<&str>) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
            .map_err(|error| anyhow!("open the system keyring: {error}"))?;
        match secret {
            Some(secret) => entry
                .set_password(secret)
                .map_err(|error| anyhow!("write the system keyring: {error}")),
            None => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(error) => Err(anyhow!("clear the system keyring: {error}")),
            },
        }
    }
}

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
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeKind,
    /// `None` means the platform Downloads directory.
    pub save_dir: Option<PathBuf>,
    /// Encrypt outgoing files for Kalo receivers sharing the passphrase.
    pub encrypt_sends: bool,
    /// Shared passphrase. It is kept in the system keyring when available,
    /// falls back to the private settings file, and is also used to decrypt
    /// incoming Kalo containers even when outgoing encryption is off.
    pub encryption_passphrase: String,
}

/// Never include the passphrase in debug output. Settings can end up in a
/// failed assertion or a diagnostic log, and the secret must not follow.
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let passphrase = if self.encryption_passphrase.is_empty() {
            "<unset>"
        } else {
            "<set>"
        };
        f.debug_struct("Settings")
            .field("theme", &self.theme)
            .field("save_dir", &self.save_dir)
            .field("encrypt_sends", &self.encrypt_sends)
            .field("encryption_passphrase", &passphrase)
            .finish()
    }
}

impl Settings {
    /// Load the user settings, the passphrase from the system keyring when
    /// available, and a message suitable for the activity log. A missing file
    /// is not an error.
    pub fn load() -> (Self, Option<String>) {
        Self::load_with_store(&paths::settings_file(), &KeyringStore)
    }

    /// File-only load. Tests and the migration path use this; application
    /// code should call [`Settings::load`] so the keyring is consulted.
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

    /// Load through a credential store. A passphrase left in an older
    /// settings file is moved into the keyring and removed from disk; when
    /// the keyring is unavailable the file keeps it and a warning is
    /// returned.
    pub fn load_with_store(path: &Path, store: &dyn SecretStore) -> (Self, Option<String>) {
        let (mut settings, file_warning) = Self::load_from(path);
        let mut notes = Vec::new();
        if let Some(warning) = file_warning {
            notes.push(warning);
        }
        if settings.encryption_passphrase.is_empty() {
            match store.get() {
                Ok(Some(secret)) => settings.encryption_passphrase = secret,
                Ok(None) => {}
                Err(error) => notes.push(format!(
                    "cannot read the passphrase from the system keyring: {error:#}"
                )),
            }
        } else if let Err(error) = store.set(Some(&settings.encryption_passphrase)) {
            notes.push(format!(
                "cannot move the passphrase to the system keyring ({error:#}); it remains in \
                 the private settings file"
            ));
        } else {
            let mut persisted = settings.clone();
            persisted.encryption_passphrase.clear();
            match Self::save_to(&persisted, path) {
                Ok(()) => notes.push("moved the saved passphrase to the system keyring".into()),
                Err(error) => notes.push(format!(
                    "moved the passphrase to the system keyring but could not remove it from \
                     {} ({error:#})",
                    path.display()
                )),
            }
        }
        let warning = (!notes.is_empty()).then(|| notes.join("; "));
        (settings, warning)
    }

    /// Save preferences and keep the passphrase in the system keyring. If the
    /// keyring is unavailable, fall back to the private settings file and
    /// return a warning instead of silently losing the secret.
    pub fn save(&self) -> Result<Option<String>> {
        self.save_with_store(&paths::settings_file(), &KeyringStore)
    }

    pub fn save_with_store(&self, path: &Path, store: &dyn SecretStore) -> Result<Option<String>> {
        let secret =
            (!self.encryption_passphrase.is_empty()).then_some(self.encryption_passphrase.as_str());
        match store.set(secret) {
            Ok(()) => {
                let mut persisted = self.clone();
                persisted.encryption_passphrase.clear();
                Self::save_to(&persisted, path)?;
                Ok(None)
            }
            Err(error) => {
                // Never drop a configured passphrase just because the keyring
                // is unavailable. The settings file is owner-only on Unix.
                Self::save_to(self, path)?;
                Ok(Some(format!(
                    "cannot use the system keyring ({error:#}); the passphrase was saved in the \
                     private settings file instead"
                )))
            }
        }
    }

    /// File-only save. Used by the fallback path and by tests.
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
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
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
            encrypt_sends: true,
            encryption_passphrase: "a long shared passphrase".into(),
        };
        settings.save_to(&path).unwrap();

        let (loaded, warning) = Settings::load_from(&path);
        assert!(warning.is_none());
        assert_eq!(loaded, settings);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn settings_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let path = dir.join("settings.json");
        write_json(&path, &Settings::default()).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn debug_output_redacts_the_passphrase() {
        let settings = Settings {
            encrypt_sends: true,
            encryption_passphrase: "a very secret shared passphrase".into(),
            ..Settings::default()
        };
        let debug = format!("{settings:?}");
        assert!(!debug.contains("very secret"));
        assert!(debug.contains("<set>"));
    }

    #[derive(Default)]
    struct MemoryStore {
        secret: Mutex<Option<String>>,
        fail: bool,
    }

    impl SecretStore for MemoryStore {
        fn get(&self) -> Result<Option<String>> {
            if self.fail {
                return Err(anyhow!("keyring unavailable"));
            }
            Ok(self.secret.lock().unwrap().clone())
        }

        fn set(&self, secret: Option<&str>) -> Result<()> {
            if self.fail {
                return Err(anyhow!("keyring unavailable"));
            }
            *self.secret.lock().unwrap() = secret.map(str::to_string);
            Ok(())
        }
    }

    #[test]
    fn keyring_save_keeps_the_secret_out_of_the_file() {
        let dir = temp_dir();
        let path = dir.join("settings.json");
        let store = MemoryStore::default();
        let settings = Settings {
            encrypt_sends: true,
            encryption_passphrase: "a long shared passphrase".into(),
            ..Settings::default()
        };

        let warning = settings.save_with_store(&path, &store).unwrap();
        assert!(warning.is_none());
        assert_eq!(
            store.secret.lock().unwrap().as_deref(),
            Some("a long shared passphrase")
        );
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("a long shared passphrase"));
        assert!(raw.contains("encrypt_sends"));

        let (loaded, warning) = Settings::load_with_store(&path, &store);
        assert!(warning.is_none());
        assert_eq!(loaded.encryption_passphrase, "a long shared passphrase");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn legacy_file_passphrase_is_migrated_to_the_keyring() {
        let dir = temp_dir();
        let path = dir.join("settings.json");
        let legacy = Settings {
            encrypt_sends: true,
            encryption_passphrase: "an older shared passphrase".into(),
            ..Settings::default()
        };
        legacy.save_to(&path).unwrap();
        let store = MemoryStore::default();

        let (loaded, warning) = Settings::load_with_store(&path, &store);
        assert!(warning.unwrap().contains("moved the saved passphrase"));
        assert_eq!(loaded.encryption_passphrase, "an older shared passphrase");
        assert_eq!(
            store.secret.lock().unwrap().as_deref(),
            Some("an older shared passphrase")
        );
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("an older shared passphrase"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keyring_failure_falls_back_to_the_private_file() {
        let dir = temp_dir();
        let path = dir.join("settings.json");
        let store = MemoryStore {
            fail: true,
            ..MemoryStore::default()
        };
        let settings = Settings {
            encrypt_sends: true,
            encryption_passphrase: "a fallback shared passphrase".into(),
            ..Settings::default()
        };

        let warning = settings.save_with_store(&path, &store).unwrap();
        assert!(warning.unwrap().contains("system keyring"));
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("a fallback shared passphrase"));
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
