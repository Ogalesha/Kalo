//! Platform-aware filesystem locations.

use std::path::PathBuf;

/// The user's Downloads directory.
///
/// Linux uses the XDG user directory (falling back to `$HOME/Downloads`).
/// Windows asks the shell for the real Known Folder, so redirected or
/// localized Downloads folders are honored.
#[cfg(not(windows))]
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
