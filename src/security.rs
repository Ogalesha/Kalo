//! File-safety policy shared by the sender and the receiver.
//!
//! Kalo only ever moves files. It never executes, opens or otherwise acts on
//! the content of a transfer, and every file that leaves or enters the app is
//! checked against a SHA-256 malware blocklist. The blocklist is cached under
//! the Kalo config directory and refreshed in the background from a public
//! feed; refresh failures never block a transfer.
//!
//! Hashing is streaming and uses one small buffer so checking a large file
//! does not raise memory use. The cached hash list is kept as sorted
//! `[u8; 32]` values (about 5 MB for the full feed) and looked up with a binary
//! search instead of a hash map or a database.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Once, OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::paths;

/// More files than this in one folder selection is almost certainly a mistake
/// (and would take hours over OPP). The UI reports the cap instead of silently
/// truncating.
pub const MAX_SEND_FILES: usize = 500;

/// Bounded incoming concurrency: four simultaneous OPP pushes already saturate
/// a Bluetooth link, while an unbounded number of connections would let a
/// remote peer exhaust file descriptors and memory.
pub const MAX_CONCURRENT_INCOMING: usize = 4;

/// OPP length headers are 32-bit, so a single object cannot exceed 4 GiB.
pub const MAX_FILE_BYTES: u64 = u32::MAX as u64;

/// The public feed is about 7 MB; 64 MB leaves room for growth without
/// allowing a compromised or misconfigured endpoint to exhaust memory.
const MAX_BLOCKLIST_BYTES: u64 = 64 * 1024 * 1024;
const BLOCKLIST_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const BLOCKLIST_RECHECK: Duration = Duration::from_secs(6 * 60 * 60);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
const FREE_SPACE_MARGIN: u64 = 16 * 1024 * 1024;
const HASH_BUFFER: usize = 64 * 1024;

/// Public SHA-256 feeds from the MIT-licensed romainmarcoux/malicious-hash
/// project. Two files keep each response comfortably below typical proxy
/// limits and are merged locally.
const FEEDS: [&str; 2] = [
    "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-ab.txt",
];

/// Baseline shipped with the binary so the very first launch (and an offline
/// machine) still blocks known malware hashes.
const BUNDLED: &str = include_str!("../assets/malware-sha256.txt");

/// Result of scanning a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scan {
    pub digest: [u8; 32],
    pub blocked: bool,
}

/// Incremental SHA-256 helper for receivers that already stream bytes to disk
/// (the Windows OBEX parser). Reusing the write path avoids a second read.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug)]
pub struct Hasher {
    inner: Sha256,
    bytes: u64,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl Hasher {
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
            bytes: 0,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
        self.bytes += bytes.len() as u64;
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn finish(self) -> [u8; 32] {
        self.inner.finalize().into()
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Stream a file through SHA-256. Only one small buffer is allocated.
pub fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file =
        File::open(path).with_context(|| format!("open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_BUFFER];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {} for hashing", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

/// Validate a user-selected path and scan it before it is sent.
///
/// Symlinks and special files are rejected: a symlink could point outside the
/// folder the user picked, and OPP itself only accepts regular files. The
/// returned length is the size that was scanned.
pub fn check_send_file(path: &Path) -> Result<u64> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "{} is a symbolic link; Kalo only sends regular files",
            path.display()
        );
    }
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if metadata.len() > MAX_FILE_BYTES {
        bail!("{} is larger than the 4 GB OPP limit", path.display());
    }
    let scan = scan_file(path)?;
    if scan.blocked {
        bail!(
            "{} matches a known malicious SHA-256 hash and was blocked",
            path.display()
        );
    }
    Ok(metadata.len())
}

/// Scan a staged incoming file. The caller decides what to do with a blocked
/// result (Kalo deletes the staged copy instead of saving it).
pub fn scan_received_file(path: &Path) -> Result<Scan> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("received object is not a regular file");
    }
    scan_file(path)
}

fn scan_file(path: &Path) -> Result<Scan> {
    let digest = sha256_file(path)?;
    Ok(Scan {
        digest,
        blocked: is_blocked(digest),
    })
}

/// True when the digest is in the active blocklist. Never performs I/O.
pub fn is_blocked(digest: [u8; 32]) -> bool {
    match blocklist().read() {
        Ok(list) => list.contains(&digest),
        Err(poisoned) => poisoned.into_inner().contains(&digest),
    }
}

/// Human-readable digest, used in logs and tests.
pub fn digest_hex(digest: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Parse a text feed. `bytes` is consumed and dropped after parsing so the
/// temporary download buffer does not stay resident.
fn parse_hashes(bytes: &[u8], out: &mut Vec<[u8; 32]>) {
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = line.strip_prefix(b"\xef\xbb\xbf").unwrap_or(line);
        if line.len() != 64 {
            continue;
        }
        let mut digest = [0u8; 32];
        let mut ok = true;
        for (index, chunk) in line.as_chunks::<2>().0.iter().enumerate() {
            match (hex_value(chunk[0]), hex_value(chunk[1])) {
                (Some(high), Some(low)) => digest[index] = (high << 4) | low,
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            out.push(digest);
        }
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn bundled_hashes() -> Vec<[u8; 32]> {
    let mut hashes = Vec::new();
    parse_hashes(BUNDLED.as_bytes(), &mut hashes);
    hashes
}

fn sort_and_dedup(hashes: &mut Vec<[u8; 32]>) {
    hashes.sort_unstable();
    hashes.dedup();
}

#[derive(Debug, Default)]
struct Blocklist {
    hashes: Vec<[u8; 32]>,
    cached: bool,
}

impl Blocklist {
    fn contains(&self, digest: &[u8; 32]) -> bool {
        self.hashes.binary_search(digest).is_ok()
    }
}

static BLOCKLIST: OnceLock<RwLock<Blocklist>> = OnceLock::new();
static INIT: Once = Once::new();

fn blocklist() -> &'static RwLock<Blocklist> {
    BLOCKLIST.get_or_init(|| RwLock::new(Blocklist::default()))
}

fn cache_file() -> PathBuf {
    paths::config_dir().join("malware-sha256.txt")
}

/// Load the cached feed (if any) and start the low-frequency refresher.
///
/// The cached list is read synchronously because receive decisions should not
/// wait for a network round-trip. The refresh itself runs on a sleepy
/// background thread and never blocks or fails a transfer.
pub fn init() {
    INIT.call_once(|| {
        // Trust decisions and the hash cache live here; keep the directory
        // private before either file is written.
        if let Err(error) = create_private_dir(&paths::config_dir()) {
            eprintln!("warning: cannot secure the Kalo config directory: {error:#}");
        }
        let mut baseline = bundled_hashes();
        let mut cached = false;
        match fs::read(cache_file()) {
            Ok(bytes) => {
                parse_hashes(&bytes, &mut baseline);
                cached = true;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => eprintln!("warning: cannot read malware hash cache: {error}"),
        }
        sort_and_dedup(&mut baseline);
        if let Ok(mut list) = blocklist().write() {
            list.hashes = baseline;
            list.cached = cached;
        }
        std::thread::Builder::new()
            .name("kalo-blocklist".into())
            .spawn(|| {
                loop {
                    if cache_is_stale()
                        && let Err(error) = refresh()
                    {
                        eprintln!("warning: malware hash refresh failed: {error:#}");
                    }
                    std::thread::sleep(BLOCKLIST_RECHECK);
                }
            })
            .ok();
    });
}

fn cache_is_stale() -> bool {
    let Ok(metadata) = fs::metadata(cache_file()) else {
        return true;
    };
    metadata
        .modified()
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_none_or(|age| age >= BLOCKLIST_MAX_AGE)
}

/// Download and merge both public feeds, then atomically replace the cache.
///
/// Returns the number of unique hashes in the new list. Network and parse
/// failures leave the previous list active.
pub fn refresh() -> Result<usize> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(DOWNLOAD_TIMEOUT))
        .user_agent(concat!("Kalo/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent();

    let mut hashes = bundled_hashes();
    for url in FEEDS {
        let mut response = agent
            .get(url)
            .call()
            .with_context(|| format!("download malware hash feed {url}"))?;
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_BLOCKLIST_BYTES)
            .read_to_vec()
            .with_context(|| format!("read malware hash feed {url}"))?;
        parse_hashes(&bytes, &mut hashes);
    }
    sort_and_dedup(&mut hashes);
    if hashes.len() <= bundled_hashes().len() {
        bail!("public malware hash feeds returned no usable hashes");
    }

    let path = cache_file();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    create_private_dir(parent)?;
    let temporary = parent.join(format!(
        ".kalo-hashes-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let write = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        let mut text = String::with_capacity(hashes.len() * 65);
        for digest in &hashes {
            text.push_str(&digest_hex(*digest));
            text.push('\n');
        }
        file.write_all(text.as_bytes())
            .with_context(|| format!("write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temporary.display()))?;
        drop(file);
        restrict_file_permissions(&temporary)?;
        fs::rename(&temporary, &path).with_context(|| format!("replace {}", path.display()))?;
        Ok(())
    })();
    if write.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write?;

    let count = hashes.len();
    if let Ok(mut list) = blocklist().write() {
        list.hashes = hashes;
        list.cached = true;
    }
    Ok(count)
}

/// Create a directory that only the current user can access.
pub fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    restrict_dir_permissions(path)
}

#[cfg(unix)]
pub fn restrict_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restrict permissions on {}", path.display()))
}

#[cfg(not(unix))]
pub fn restrict_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Config and cache files contain trust decisions and blocklist data; keep
/// them private to the account that owns them.
#[cfg(unix)]
pub fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restrict permissions on {}", path.display()))
}

#[cfg(not(unix))]
pub fn restrict_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Applied to every file moved into the save folder. Received content is
/// never executable and, on Windows, carries Mark-of-the-Web so the shell
/// treats it like a file downloaded from the internet.
pub fn harden_received_file(path: &Path) -> Result<()> {
    restrict_file_permissions(path)?;
    #[cfg(windows)]
    {
        let mut ads = path.as_os_str().to_owned();
        ads.push(":Zone.Identifier");
        let zone = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=about:blank\r\n";
        if let Err(error) = fs::write(PathBuf::from(ads), zone) {
            // A filesystem without alternate data streams (some network
            // shares) must not turn a successful transfer into a failure.
            eprintln!(
                "warning: cannot write Mark-of-the-Web for {}: {error}",
                path.display()
            );
        }
    }
    Ok(())
}

/// Free bytes available to the current user at `path`, looking at the nearest
/// existing ancestor so a not-yet-created save folder works.
pub fn available_space(path: &Path) -> Result<u64> {
    let existing = path
        .ancestors()
        .find(|candidate| candidate.exists())
        .unwrap_or_else(|| Path::new("."));
    platform_available_space(existing)
}

#[cfg(unix)]
fn platform_available_space(path: &Path) -> Result<u64> {
    let stat = rustix::fs::statvfs(path)
        .with_context(|| format!("read free space for {}", path.display()))?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

#[cfg(windows)]
fn platform_available_space(path: &Path) -> Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows::core::PCWSTR;

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut available = 0u64;
    unsafe {
        GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), Some(&mut available), None, None)
            .with_context(|| format!("read free space for {}", path.display()))?;
    }
    Ok(available)
}

/// Refuse a transfer that cannot possibly fit, before any bytes are written.
/// Unknown sizes still require a small working margin.
pub fn ensure_free_space(path: &Path, needed: Option<u64>) -> Result<()> {
    let required = needed.unwrap_or(0).saturating_add(FREE_SPACE_MARGIN);
    let available = available_space(path)?;
    if available < required {
        bail!(
            "not enough free space for this transfer (need {}, have {})",
            crate::events::format_bytes(required),
            crate::events::format_bytes(available)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kalo-test-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parses_plain_and_crlf_hashes_and_ignores_noise() {
        let a = "a".repeat(64);
        let b = "B".repeat(64);
        let text = format!("# comment\n{a}\r\n{b}\nnot-a-hash\n{}\n", "c".repeat(63));
        let mut hashes = Vec::new();
        parse_hashes(text.as_bytes(), &mut hashes);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], [0xaa; 32]);
        assert_eq!(hashes[1], [0xbb; 32]);
    }

    #[test]
    fn bundled_baseline_is_sorted_and_contains_eicar() {
        let mut hashes = bundled_hashes();
        assert!(hashes.len() >= 10);
        sort_and_dedup(&mut hashes);
        assert!(hashes.windows(2).all(|pair| pair[0] < pair[1]));
        let eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        assert!(hashes.iter().any(|hash| digest_hex(*hash) == eicar));
    }

    #[test]
    fn streamed_hash_matches_incremental_hash() {
        let dir = temp_dir();
        let path = dir.join("sample.bin");
        fs::write(&path, b"kalo security test").unwrap();
        let digest = sha256_file(&path).unwrap();
        let mut hasher = Hasher::new();
        hasher.update(b"kalo ");
        hasher.update(b"security test");
        assert_eq!(hasher.bytes(), 18);
        assert_eq!(hasher.finish(), digest);
        assert_eq!(
            digest_hex(digest),
            "000192294b8617e8de3fa7bf5af8b75f651db37db59847caa703a1536af10dac".to_string()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn check_send_file_rejects_directories_and_short_files() {
        let dir = temp_dir();
        assert!(check_send_file(&dir).is_err());
        let path = dir.join("ok.txt");
        fs::write(&path, b"hello").unwrap();
        assert_eq!(check_send_file(&path).unwrap(), 5);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn check_send_file_rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = temp_dir();
        let target = dir.join("target.txt");
        let link = dir.join("link.txt");
        fs::write(&target, b"secret").unwrap();
        symlink(&target, &link).unwrap();
        let error = check_send_file(&link).unwrap_err().to_string();
        assert!(error.contains("symbolic link"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn received_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let path = dir.join("received.bin");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        harden_received_file(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn free_space_is_reported() {
        let dir = temp_dir();
        assert!(available_space(&dir).unwrap() > 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn blocklist_lookup_uses_binary_search() {
        let list = Blocklist {
            hashes: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            ..Blocklist::default()
        };
        assert!(list.contains(&[2u8; 32]));
        assert!(!list.contains(&[4u8; 32]));
    }

    #[test]
    fn received_eicar_file_is_blocked_before_saving() {
        let dir = temp_dir();
        let path = dir.join("eicar.com");
        fs::write(
            &path,
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();

        let mut hashes = bundled_hashes();
        sort_and_dedup(&mut hashes);
        if let Ok(mut list) = blocklist().write() {
            list.hashes = hashes;
        }

        let scan = scan_received_file(&path).unwrap();
        assert!(scan.blocked);
        fs::remove_dir_all(&dir).unwrap();
    }
}
