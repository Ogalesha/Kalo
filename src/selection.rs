//! Build a send queue from files, multiple files, or folders.
//!
//! OPP has no folder concept, so a folder selection is flattened: every
//! regular file below it is queued individually and sent one after another.
//! Symbolic links are never followed, hidden entries are skipped, and the
//! result is sorted so the queue is deterministic. The cap lives in
//! [`crate::security::MAX_SEND_FILES`] and is reported as an error instead of
//! silently truncating a large selection.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::security::MAX_SEND_FILES;

/// Folder nesting deeper than this is treated as a mistake (or a cycle that
/// somehow avoided the symlink guard) and skipped with a note.
const MAX_DEPTH: usize = 32;

/// Result of expanding a UI or CLI selection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    /// Regular files, sorted by path.
    pub files: Vec<PathBuf>,
    /// Sum of the sizes observed while collecting.
    pub total_bytes: u64,
    /// Non-fatal things the user should know (skipped links, unreadable
    /// subfolders, the file cap).
    pub notes: Vec<String>,
    /// Number of top-level folders that were expanded.
    pub folders: usize,
}

impl Selection {
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

/// Expand a mixed selection of files and folders.
pub fn collect(paths: &[PathBuf]) -> Result<Selection> {
    if paths.is_empty() {
        bail!("choose at least one file or folder");
    }

    let mut found: BTreeMap<PathBuf, u64> = BTreeMap::new();
    let mut notes = Vec::new();
    let mut folders = 0;

    for path in paths {
        let metadata =
            fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            notes.push(format!(
                "{} is a symbolic link and was skipped",
                path.display()
            ));
            continue;
        }
        if file_type.is_dir() {
            folders += 1;
            let before = found.len();
            walk_folder(path, &mut found, &mut notes)?;
            if found.len() == before {
                notes.push(format!("{} contains no sendable files", path.display()));
            }
        } else if file_type.is_file() {
            found.insert(path.clone(), metadata.len());
        } else {
            notes.push(format!("{} is not a regular file", path.display()));
        }
        if found.len() > MAX_SEND_FILES {
            bail!(
                "the selection contains more than {MAX_SEND_FILES} files; \
                 choose a smaller folder or fewer files"
            );
        }
    }

    if found.is_empty() {
        bail!("nothing to send — the selection has no regular files");
    }

    let total_bytes = found
        .values()
        .fold(0u64, |total, size| total.saturating_add(*size));
    Ok(Selection {
        files: found.into_keys().collect(),
        total_bytes,
        notes,
        folders,
    })
}

/// Iterative folder walk. Unreadable subfolders are notes, not failures: the
/// rest of the selection is still usable.
fn walk_folder(
    root: &Path,
    found: &mut BTreeMap<PathBuf, u64>,
    notes: &mut Vec<String>,
) -> Result<()> {
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut unreadable = 0usize;
    let mut skipped_links = 0usize;
    let mut skipped_special = 0usize;

    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            notes.push(format!(
                "{} is nested too deeply and was skipped",
                dir.display()
            ));
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                unreadable += 1;
                notes.push(format!("cannot read {}: {error}", dir.display()));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    unreadable += 1;
                    notes.push(format!(
                        "cannot read an entry in {}: {error}",
                        dir.display()
                    ));
                    continue;
                }
            };
            let name = entry.file_name();
            // Hidden files and folders are intentionally left out of folder
            // sends; a single hidden file can still be picked explicitly.
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => {
                    skipped_special += 1;
                    continue;
                }
            };
            if file_type.is_symlink() {
                skipped_links += 1;
                continue;
            }
            if file_type.is_dir() {
                stack.push((path, depth + 1));
            } else if file_type.is_file() {
                let size = entry.metadata().map(|meta| meta.len()).unwrap_or(0);
                found.insert(path, size);
                if found.len() > MAX_SEND_FILES {
                    bail!(
                        "the selection contains more than {MAX_SEND_FILES} files; \
                         choose a smaller folder or fewer files"
                    );
                }
            } else {
                skipped_special += 1;
            }
        }
    }

    if skipped_links > 0 {
        notes.push(format!(
            "skipped {skipped_links} symbolic link(s) while expanding folders"
        ));
    }
    if skipped_special > 0 {
        notes.push(format!(
            "skipped {skipped_special} non-regular entry/entries while expanding folders"
        ));
    }
    if unreadable > 0 {
        notes.push(format!("{unreadable} folder(s) could not be read"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kalo-sel-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_single_file_is_a_selection() {
        let dir = temp_dir();
        let file = dir.join("one.txt");
        fs::write(&file, b"hello").unwrap();
        let selection = collect(std::slice::from_ref(&file)).unwrap();
        assert_eq!(selection.files, vec![file]);
        assert_eq!(selection.total_bytes, 5);
        assert_eq!(selection.folders, 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn folders_are_flattened_sorted_and_hide_dotfiles() {
        let dir = temp_dir();
        let nested = dir.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(dir.join("b.txt"), b"bb").unwrap();
        fs::write(dir.join("a.txt"), b"a").unwrap();
        fs::write(dir.join(".hidden"), b"nope").unwrap();
        fs::write(nested.join("c.txt"), b"ccc").unwrap();

        let selection = collect(std::slice::from_ref(&dir)).unwrap();
        assert_eq!(selection.file_count(), 3);
        assert_eq!(selection.total_bytes, 6);
        assert!(selection.files[0].ends_with("a.txt"));
        assert!(selection.files[1].ends_with("b.txt"));
        assert!(selection.files[2].ends_with("nested/c.txt"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_selection_is_an_error() {
        let dir = temp_dir();
        assert!(collect(std::slice::from_ref(&dir)).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_followed() {
        use std::os::unix::fs::symlink;
        let dir = temp_dir();
        let outside = dir.join("outside.txt");
        fs::write(&outside, b"secret").unwrap();
        let folder = dir.join("folder");
        fs::create_dir_all(&folder).unwrap();
        symlink(&outside, folder.join("link.txt")).unwrap();
        fs::write(folder.join("real.txt"), b"ok").unwrap();

        let selection = collect(std::slice::from_ref(&folder)).unwrap();
        assert_eq!(selection.file_count(), 1);
        assert!(selection.files[0].ends_with("real.txt"));
        assert!(
            selection
                .notes
                .iter()
                .any(|note| note.contains("symbolic link"))
        );

        let direct = collect(&[folder.join("link.txt")]);
        assert!(direct.is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn duplicate_paths_are_collapsed() {
        let dir = temp_dir();
        let file = dir.join("same.txt");
        fs::write(&file, b"x").unwrap();
        let selection = collect(&[file.clone(), file.clone()]).unwrap();
        assert_eq!(selection.file_count(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }
}
