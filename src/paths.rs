//! XDG-aware filesystem locations.

use std::path::PathBuf;

/// The user's Downloads directory (XDG), falling back to `$HOME/Downloads`.
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
