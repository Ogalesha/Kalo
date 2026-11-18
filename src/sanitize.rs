//! Filename safety helpers for untrusted (remote-provided) file names.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// Device names Windows resolves even when an extension is present. Writing a
/// received file called `CON` would target the console device instead of a
/// regular file, so such names get a safe prefix.
const WINDOWS_RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Sanitize an untrusted filename (e.g. the OPP `Name` header): strip path
/// separators and control characters, replace characters that are special on
/// Windows (including `:`, which would create an NTFS alternate data stream),
/// avoid dotfiles / `.` / `..`, trailing dots and spaces, reserved device
/// names, and cap the length.
pub fn filename(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .filter(|c| *c != '/' && *c != '\\' && !c.is_control())
        .map(|c| {
            if matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned
        .trim()
        .trim_start_matches('.')
        .trim_end_matches(['.', ' ']);
    let mut name = trimmed.to_string();
    if name.is_empty() {
        name = "received-file".to_string();
    }
    if is_windows_reserved(&name) {
        name.insert(0, '_');
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

fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    WINDOWS_RESERVED
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
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

/// Move a file without replacing an existing destination.
///
/// On the same filesystem a hard link is atomic and fails with `AlreadyExists`
/// instead of overwriting. When hard links are unavailable (typically
/// cross-device), copy into a freshly created destination and only then
/// remove the source. A failed copy removes its partial destination.
pub fn move_file(src: &Path, dst: &Path) -> io::Result<()> {
    match std::fs::hard_link(src, dst) {
        Ok(()) => {
            if let Err(e) = std::fs::remove_file(src) {
                let _ = std::fs::remove_file(dst);
                return Err(e);
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(e),
        Err(e) if link_fallback(&e) => copy_no_replace(src, dst),
        Err(e) => Err(e),
    }
}

/// Errors that mean "hard links are not usable here" rather than "this move
/// is invalid". The copy path still uses `create_new`, so it cannot overwrite.
fn link_fallback(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::CrossesDevices
            | io::ErrorKind::Unsupported
            | io::ErrorKind::PermissionDenied
    )
}

fn copy_no_replace(src: &Path, dst: &Path) -> io::Result<()> {
    let mut input = File::open(src)?;
    let mut output = OpenOptions::new().write(true).create_new(true).open(dst)?;
    if let Err(e) = io::copy(&mut input, &mut output).and_then(|_| output.sync_all()) {
        let _ = std::fs::remove_file(dst);
        return Err(e);
    }
    if let Err(e) = std::fs::remove_file(src) {
        let _ = std::fs::remove_file(dst);
        return Err(e);
    }
    Ok(())
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
    fn filename_never_creates_windows_streams_or_devices() {
        // A colon would create an NTFS alternate data stream on Windows.
        assert_eq!(filename("report.txt:hidden.exe"), "report.txt_hidden.exe");
        assert_eq!(filename("CON"), "_CON");
        assert_eq!(filename("con.txt"), "_con.txt");
        assert_eq!(filename("LPT1.log"), "_LPT1.log");
        // Trailing dots and spaces disappear on Windows; remove them here so
        // the name shown in the UI matches the name on disk everywhere.
        assert_eq!(filename("notes. "), "notes");
        assert_eq!(filename("aux. . ."), "_aux");
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

    #[test]
    fn move_file_refuses_to_overwrite_existing_destination() {
        let dir = std::env::temp_dir().join(format!("kalo-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        let dst = dir.join("dst.bin");
        std::fs::write(&src, b"new").unwrap();
        std::fs::write(&dst, b"keep").unwrap();

        let err = move_file(&src, &dst).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&src).unwrap(), b"new");
        assert_eq!(std::fs::read(&dst).unwrap(), b"keep");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
