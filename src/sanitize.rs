//! Filename safety helpers for untrusted (remote-provided) file names.

use std::path::{Path, PathBuf};

/// Sanitize an untrusted filename (e.g. the OPP `Name` header): strip path
/// separators and control characters, avoid dotfiles / `.` / `..`, cap length.
pub fn filename(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .filter(|c| *c != '/' && *c != '\\' && !c.is_control())
        .collect();
    let trimmed = cleaned.trim().trim_start_matches('.');
    let mut name = trimmed.to_string();
    if name.is_empty() {
        name = "received-file".to_string();
    }
    // Cap length (most filesystems allow 255 bytes per component).
    while name.len() > 200 {
        name.pop();
    }
    if name.is_empty() {
        name = "received-file".to_string();
    }
    name
}

/// Find a non-colliding path in `dir` for `name`: `name (1).ext` style.
pub fn unique_in_dir(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let stem = Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = Path::new(name).extension().and_then(|s| s.to_str());
    for i in 1..u32::MAX {
        let name2 = match ext {
            Some(e) => format!("{stem} ({i}).{e}"),
            None => format!("{stem} ({i})"),
        };
        let candidate = dir.join(&name2);
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(format!("{stem}-{}", uuid::Uuid::new_v4().simple()))
}

/// Move a file, atomically when possible (rename), copy+delete otherwise.
pub fn move_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            std::fs::copy(src, dst)?;
            std::fs::remove_file(src)?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_strips_separators_and_control_chars() {
        assert_eq!(filename("../../etc/passwd"), "etcpasswd");
        assert_eq!(filename("a/b\\c"), "abc");
        assert_eq!(filename("bad\u{0}name"), "badname");
    }

    #[test]
    fn filename_is_never_dotfile_or_empty() {
        assert_eq!(filename(".hidden"), "hidden");
        assert_eq!(filename("..."), "received-file");
        assert_eq!(filename("   "), "received-file");
        assert_eq!(filename(""), "received-file");
    }

    #[test]
    fn filename_caps_length() {
        let long = "x".repeat(500);
        assert_eq!(filename(&long).len(), 200);
    }

    #[test]
    fn unique_in_dir_numbers_collisions() {
        let dir = std::env::temp_dir().join(format!("kalo-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_in_dir(&dir, "a.txt"), dir.join("a.txt"));
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        assert_eq!(unique_in_dir(&dir, "a.txt"), dir.join("a (1).txt"));
        std::fs::write(dir.join("a (1).txt"), b"x").unwrap();
        assert_eq!(unique_in_dir(&dir, "a.txt"), dir.join("a (2).txt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn move_file_renames_within_same_directory() {
        let dir = std::env::temp_dir().join(format!("kalo-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        std::fs::write(&src, b"hello").unwrap();
        let dst = dir.join("dst.bin");
        move_file(&src, &dst).unwrap();
        assert!(!src.exists());
        assert_eq!(std::fs::read(&dst).unwrap(), b"hello");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
