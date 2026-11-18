//! Platform-aware filesystem locations.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Directory for Kalo's settings and trust store.
#[cfg(target_os = "linux")]
pub fn config_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("kalo")
}

/// macOS keeps user configuration in Application Support, not in `~/.config`.
#[cfg(target_os = "macos")]
pub fn config_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join("Library")
        .join("Application Support")
        .join("Kalo")
}

#[cfg(windows)]
pub fn config_dir() -> PathBuf {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{
        FOLDERID_RoamingAppData, KNOWN_FOLDER_FLAG, SHGetKnownFolderPath,
    };

    let known = unsafe {
        SHGetKnownFolderPath(&FOLDERID_RoamingAppData, KNOWN_FOLDER_FLAG(0), None)
            .ok()
            .and_then(|ptr| {
                let path = ptr.to_string().ok();
                CoTaskMemFree(Some(ptr.0 as *const core::ffi::c_void));
                path
            })
    };
    known
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Kalo")
}

pub fn settings_file() -> PathBuf {
    config_dir().join("settings.json")
}

pub fn trust_file() -> PathBuf {
    config_dir().join("trust.json")
}

/// Open a folder in the platform file manager, creating it first so the
/// default Downloads folder works on a fresh account.
pub fn open_folder(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("create folder {}", path.display()))?;
    #[cfg(target_os = "linux")]
    let mut command = std::process::Command::new("xdg-open");
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(windows)]
    let mut command = std::process::Command::new("explorer");
    command
        .arg(path)
        .spawn()
        .with_context(|| format!("open {}", path.display()))?;
    Ok(())
}

/// The user's Downloads directory.
///
/// Linux uses the XDG user directory (falling back to `$HOME/Downloads`).
/// macOS uses the conventional `~/Downloads`. Windows asks the shell for the
/// real Known Folder, so redirected or localized Downloads folders are
/// honored.
#[cfg(target_os = "linux")]
pub fn downloads_dir() -> PathBuf {
    if let Ok(out) = std::process::Command::new("xdg-user-dir")
        .arg("DOWNLOAD")
        .output()
        && out.status.success()
    {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() && std::path::Path::new(&s).is_dir() {
            return PathBuf::from(s);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join("Downloads")
}

#[cfg(target_os = "macos")]
pub fn downloads_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join("Downloads")
}

#[cfg(windows)]
pub fn downloads_dir() -> PathBuf {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_Downloads, KNOWN_FOLDER_FLAG, SHGetKnownFolderPath};

    // SHGetKnownFolderPath allocates the returned string with the COM task
    // allocator; copy it before freeing.
    let known = unsafe {
        SHGetKnownFolderPath(&FOLDERID_Downloads, KNOWN_FOLDER_FLAG(0), None)
            .ok()
            .and_then(|ptr| {
                let path = ptr.to_string().ok();
                CoTaskMemFree(Some(ptr.0 as *const core::ffi::c_void));
                path
            })
    };
    if let Some(path) = known.map(PathBuf::from).filter(|path| path.is_dir()) {
        return path;
    }
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Downloads")
}
