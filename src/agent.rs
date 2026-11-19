//! OBEX agent: receives incoming OPP pushes into a staging directory under
//! obexd's root, then moves finished files into the user's save folder.
//!
//! New senders are authorized by the trust store or approved in the desktop
//! UI; the CLI receiver accepts remembered senders only.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use tokio::time::MissedTickBehavior;
use uuid::Uuid;
use zbus::Connection;
use zbus::fdo;
use zbus::interface;
use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::crypto::{self, Encryption};
use crate::events::{Event, EventSink, TransferStatus};
use crate::paths;
use crate::receiver::ReceiverHandle;
use crate::sanitize;
use crate::security;
use crate::settings::{SaveDir, Settings};
use crate::trust::{Authorizer, TrustStore};

/// Root path for agent objects. Every registration exports a unique child
/// path so a late `Release` from an old registration can never affect the
/// current one.
pub const AGENT_PATH: &str = "/org/kalo/obex/agent";

/// How long transient D-Bus failures are tolerated before a pending transfer
/// is treated as gone. A real transfer object usually reappears immediately;
/// an obexd restart can take a few seconds.
const TRANSIENT_ERROR_GRACE: Duration = Duration::from_secs(10);
/// Incoming transfers that make no progress for this long are finalized as
/// interrupted (keeping a partial file) instead of waiting forever.
const INCOMING_STALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// A queued incoming transfer that never starts is likely stranded.
const INCOMING_QUEUED_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// A suspended transfer is a deliberate pause, so it gets more room.
const INCOMING_SUSPENDED_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Status values Kalo does not know cannot be watched forever.
const INCOMING_UNKNOWN_TIMEOUT: Duration = Duration::from_secs(60);

/// Receiver supervision cadence.
const REGISTRATION_RETRY: Duration = Duration::from_secs(15);
const SESSION_BUS_RETRY: Duration = Duration::from_secs(5);
const PENDING_POLL_INTERVAL: Duration = Duration::from_millis(500);
const STAGING_SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// One in-flight incoming transfer.
#[derive(Debug, Clone)]
pub struct PendingTransfer {
    /// Stable identity for poll bookkeeping: obexd reuses transfer object
    /// paths, so entries must never be matched or removed by path.
    pub id: String,
    /// Sanitized filename, for logs and events.
    pub name: String,
    /// Remote device address, for logs and events.
    pub sender: String,
    /// Friendly sender name, resolved from BlueZ when available. Used only to
    /// choose the per-sender save folder; the address remains the identity.
    pub sender_label: String,
    /// Size announced by the sender, when present.
    pub size: Option<u64>,
    pub path: String,
    /// The staging destination this entry authorized (obexd writes here).
    pub dest: PathBuf,
    pub staging_dir: PathBuf,
    pub started: Instant,
    /// First transient poll failure for this entry, if any.
    pub last_error_at: Option<Instant>,
    /// Last time the byte counter changed (or the entry was created).
    pub last_progress_at: Instant,
    pub last_transferred: u64,
    /// Last observed `Transfer1.Status` (raw) and when it changed. The
    /// per-status stall policy uses these clocks.
    pub last_status: Option<String>,
    pub status_since: Instant,
    /// Pairing protocol object: never shown as a file and never saved.
    pub control: bool,
}

/// Shared registry of in-flight incoming transfers.
pub type PendingTransfers = Arc<Mutex<Vec<PendingTransfer>>>;

pub fn new_pending() -> PendingTransfers {
    Arc::new(Mutex::new(Vec::new()))
}

/// Watch `org.bluez.obex` owner changes on the session bus. obexd restarting
/// silently invalidates our registration, so the supervisor must treat any
/// change as a lost slot and re-register.
pub async fn obexd_owner_changes(
    conn: &Connection,
) -> Result<zbus::proxy::OwnerChangedStream<'static>> {
    let proxy = zbus::Proxy::new(
        conn,
        "org.bluez.obex",
        "/org/bluez/obex",
        "org.freedesktop.DBus.Peer",
    )
    .await
    .context("obexd owner watcher")?;
    Ok(proxy.receive_owner_changed().await?)
}

#[proxy(
    default_service = "org.bluez.obex",
    interface = "org.bluez.obex.Transfer1"
)]
trait TransferProps {
    #[zbus(property)]
    fn status(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn size(&self) -> zbus::Result<u64>;
    #[zbus(property)]
    fn transferred(&self) -> zbus::Result<u64>;
    #[zbus(property)]
    fn filename(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn session(&self) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    default_service = "org.bluez.obex",
    interface = "org.bluez.obex.Session1"
)]
trait SessionProps {
    #[zbus(property)]
    fn destination(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn root(&self) -> zbus::Result<String>;
}

#[proxy(
    default_service = "org.bluez.obex",
    default_path = "/org/bluez/obex",
    interface = "org.bluez.obex.AgentManager1"
)]
trait AgentManager {
    fn register_agent(&self, agent: OwnedObjectPath) -> zbus::Result<()>;
    fn unregister_agent(&self, agent: OwnedObjectPath) -> zbus::Result<()>;
}

fn opath(s: &str) -> zbus::Result<OwnedObjectPath> {
    Ok(ObjectPath::try_from(s)?.to_owned().into())
}

/// Service object implementing `org.bluez.obex.Agent1`.
pub struct AgentService {
    conn: Connection,
    pending: PendingTransfers,
    events: EventSink,
    handle: ReceiverHandle,
    registration: u64,
    authorizer: Authorizer,
    save_dir: SaveDir,
    pairing: Option<crate::identity::PairingManager>,
}

#[interface(name = "org.bluez.obex.Agent1")]
impl AgentService {
    async fn release(&self) {
        self.handle.release(
            self.registration,
            "released by obexd; will retry registration",
        );
    }

    async fn cancel(&self) {
        self.events
            .send(Event::Log("OBEX agent request canceled".into()));
    }

    async fn authorize_push(&self, transfer: OwnedObjectPath) -> fdo::Result<String> {
        match self.authorize(&transfer).await {
            Ok(dest) => Ok(dest.to_string_lossy().into_owned()),
            Err(e) => {
                self.events
                    .send(Event::Log(format!("rejected incoming push: {e}")));
                Err(fdo::Error::Failed(format!("kalo agent: {e}")))
            }
        }
    }
}

impl AgentService {
    async fn authorize(&self, transfer: &OwnedObjectPath) -> Result<PathBuf> {
        let t = TransferPropsProxy::builder(&self.conn)
            .path(transfer.as_str())?
            .build()
            .await
            .context("Transfer1 proxy")?;

        let proposed_name = t.name().await.unwrap_or_default();
        let proposed_file = t.filename().await.unwrap_or_default();
        let base = if !proposed_name.trim().is_empty() {
            proposed_name
        } else {
            Path::new(&proposed_file)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        let safe_name = sanitize::filename(&base);
        let control = crate::identity::looks_like_pairing_name(&base);

        let session = t.session().await.context("Transfer1.Session")?;
        let session_props = SessionPropsProxy::builder(&self.conn)
            .path(session.as_str())?
            .build()
            .await
            .context("Session1 proxy")?;
        let sender = session_props
            .destination()
            .await
            .unwrap_or_else(|_| "unknown".into());
        if sender.trim().is_empty() || sender == "unknown" {
            bail!("cannot identify the sender");
        }
        // Resolve a friendly alias for the per-sender save folder. Failure is
        // not fatal: the normalized address is still a safe folder name.
        let sender_label = crate::bluez::device_alias(&self.conn, &sender)
            .await
            .unwrap_or_else(|| sender.clone());
        let root = session_props
            .root()
            .await
            .unwrap_or_else(|_| obexd_root_fallback());
        let size = t.size().await.ok();

        let id = Uuid::new_v4().simple().to_string();
        if control {
            // Pairing control objects are authenticated by SPAKE2 and the
            // identity signatures, never saved, and never trusted on their
            // own. They bypass the file prompt so two devices can pair, but
            // they still respect the concurrency and size caps below.
            if self.pairing.is_none() {
                bail!("this Kalo installation cannot process pairing objects");
            }
            if !crate::trust::is_stable_key(&sender) {
                bail!("pairing requires a stable Bluetooth address");
            }
            if size.is_some_and(|size| size > crate::identity::MAX_PAIR_BYTES) {
                bail!("the pairing object is larger than the protocol allows");
            }
        }
        if let Err(error) = self.accept_capacity(size) {
            let reason = format!("{error:#}");
            self.events.send(Event::IncomingFailed {
                id: id.clone(),
                sender: sender.clone(),
                name: safe_name.clone(),
                error: reason.clone(),
                staged_at: None,
            });
            bail!("{reason}");
        }
        if !control
            && let Err(reason) = self
                .authorizer
                .authorize(&id, &sender, &sender, &safe_name, size)
                .await
        {
            self.events.send(Event::IncomingFailed {
                id,
                sender,
                name: safe_name,
                error: reason,
                staged_at: None,
            });
            bail!("incoming push was not authorized");
        }

        // Stage inside obexd's root (it may refuse to write outside it). The
        // directory is private to this account: incoming content must never be
        // readable by other local users while it waits for its scan.
        let staging_dir = PathBuf::from(&root).join(format!("kalo-{id}"));
        security::create_private_dir(&staging_dir)
            .with_context(|| format!("create staging dir {staging_dir:?}"))?;
        // obexd may stage on a different filesystem than the save folder, so
        // check that filesystem too before the sender starts writing.
        if let Err(error) = security::ensure_free_space(&staging_dir, size) {
            cleanup_staging(&staging_dir);
            let reason = format!("not enough free space in the staging area: {error:#}");
            self.events.send(Event::IncomingFailed {
                id: id.clone(),
                sender: sender.clone(),
                name: safe_name.clone(),
                error: reason.clone(),
                staged_at: None,
            });
            bail!("{reason}");
        }
        let dest = staging_dir.join(&safe_name);

        self.pending
            .lock()
            .expect("pending lock")
            .push(PendingTransfer {
                id: id.clone(),
                name: safe_name.clone(),
                sender: sender.clone(),
                sender_label,
                size,
                path: transfer.to_string(),
                dest: dest.clone(),
                staging_dir,
                started: Instant::now(),
                last_error_at: None,
                last_progress_at: Instant::now(),
                last_transferred: 0,
                last_status: None,
                status_since: Instant::now(),
                control,
            });

        if control {
            self.events.send(Event::Log(format!(
                "pairing object from {sender}; processing it without saving"
            )));
        } else {
            self.events.send(Event::IncomingStarted {
                id,
                sender,
                name: safe_name,
                size,
            });
        }
        Ok(dest)
    }

    /// Refuse work this machine cannot safely accept: an object beyond the
    /// OPP cap, more than the bounded number of simultaneous pushes, or a
    /// transfer that cannot fit on disk.
    fn accept_capacity(&self, size: Option<u64>) -> Result<()> {
        security::check_announced_size(size)?;
        let active = self.pending.lock().expect("pending lock").len();
        if active >= security::MAX_CONCURRENT_INCOMING {
            bail!(
                "too many simultaneous incoming transfers (limit {})",
                security::MAX_CONCURRENT_INCOMING
            );
        }
        security::ensure_free_space(&self.save_dir.get(), size)
    }
}

/// obexd's default root (`-r`), used only if `Session1.Root` cannot be read.
fn obexd_root_fallback() -> String {
    staging_root().to_string_lossy().into_owned()
}

/// Default cache root obexd stages files under. A custom `obexd -r` root is
/// only discoverable from a live session, so the sweep covers the default
/// location only.
fn staging_root() -> PathBuf {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    cache.join("obexd")
}

fn cleanup_staging(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Staging dirs older than this were left by a process that is no longer
/// receiving (matches the incoming stall timeout). Any recent write to a
/// staged file also keeps the directory fresh.
const STAGING_STALE_AGE: Duration = INCOMING_STALL_TIMEOUT;

/// Recover files staged by a crashed/interrupted Kalo run into Downloads and
/// remove the now-empty `kalo-*` directories.
///
/// The supervisor runs this after registration and periodically afterwards.
fn sweep_staging(
    save_dir: &SaveDir,
    events: &EventSink,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) {
    let downloads = save_dir.get();
    let recovered = sweep_stale_staging(
        &staging_root(),
        &downloads,
        STAGING_STALE_AGE,
        events,
        encryption,
        pairing,
    );
    if recovered > 0 {
        events.send(Event::Log(format!(
            "recovered {recovered} file(s) from an interrupted transfer"
        )));
    }
}

/// Recover every regular file from stale `kalo-*` staging dirs, then delete
/// the dir only when nothing is left. Never deletes a file.
fn sweep_stale_staging(
    root: &Path,
    downloads: &Path,
    min_age: Duration,
    events: &EventSink,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut recovered = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("kalo-") {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let stale = newest_mtime(&entry.path())
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age >= min_age);
        if !stale {
            continue;
        }
        recovered += recover_staging_dir(&entry.path(), downloads, events, encryption, pairing);
    }
    recovered
}

/// Newest modification time of a directory or any file directly inside it.
/// Directory mtimes do not change when an existing file is written, so the
/// files themselves must be considered when deciding whether a transfer is
/// still active.
fn newest_mtime(dir: &Path) -> Option<std::time::SystemTime> {
    let mut newest = std::fs::metadata(dir).and_then(|m| m.modified()).ok();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(modified) = entry.metadata().and_then(|m| m.modified()) {
                newest = match newest {
                    Some(current) if current >= modified => Some(current),
                    _ => Some(modified),
                };
            }
        }
    }
    newest
}

fn recover_staging_dir(
    dir: &Path,
    downloads: &Path,
    events: &EventSink,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut recovered = 0;
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let file_label = file_name.to_string_lossy();
        if file_label.starts_with(crypto::DECRYPT_TEMP_PREFIX) {
            let _ = std::fs::remove_file(entry.path());
            events.send(Event::Log(format!(
                "removed a stale decrypted temporary file at {:?}",
                entry.path()
            )));
            continue;
        }
        if crate::identity::looks_like_pairing_name(&file_label) {
            let _ = std::fs::remove_file(entry.path());
            events.send(Event::Log(format!(
                "removed a stale pairing object at {:?}",
                entry.path()
            )));
            continue;
        }
        match crypto::container_kind(&entry.path()) {
            Ok(Some(kind)) => {
                recovered += recover_encrypted_staged(
                    &entry.path(),
                    dir,
                    downloads,
                    events,
                    encryption,
                    kind,
                    pairing,
                );
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                events.send(Event::Log(format!(
                    "left a stale staged file with unreadable headers at {:?}: {error:#}",
                    entry.path()
                )));
                continue;
            }
        }
        match security::scan_received_file(&entry.path()) {
            Ok(scan) if scan.blocked => {
                let _ = std::fs::remove_file(entry.path());
                events.send(Event::Log(format!(
                    "deleted a stale staged file that matches the malware hash list (SHA-256 {})",
                    security::digest_hex(scan.digest)
                )));
                continue;
            }
            Ok(_) => {}
            Err(error) => {
                // Keep the file staged: it was never verified, so it must not
                // be presented as a successfully received file.
                events.send(Event::Log(format!(
                    "left a stale staged file unscanned at {:?}: {error:#}",
                    entry.path()
                )));
                continue;
            }
        }
        let recovered_dir = sanitize::sender_dir(downloads, "Recovered");
        if let Err(e) = std::fs::create_dir_all(&recovered_dir) {
            events.send(Event::Log(format!(
                "cannot recover staged files into {downloads:?}: {e}"
            )));
            break;
        }
        let name = sanitize::filename(&entry.file_name().to_string_lossy());
        let mut dest = sanitize::unique_in_dir(&recovered_dir, &name);
        loop {
            match sanitize::move_file(&entry.path(), &dest) {
                Ok(()) => {
                    if let Err(error) = security::harden_received_file(&dest) {
                        events.send(Event::Log(format!(
                            "warning: cannot harden {}: {error:#}",
                            dest.display()
                        )));
                    }
                    recovered += 1;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    dest = sanitize::unique_in_dir(&recovered_dir, &name);
                }
                Err(e) => {
                    events.send(Event::Log(format!(
                        "recover staged file {:?} failed: {e}",
                        entry.path()
                    )));
                    break;
                }
            }
        }
    }
    // Leave the directory in place if any file could not be recovered.
    if std::fs::read_dir(dir)
        .map(|mut it| it.next().is_none())
        .unwrap_or(false)
    {
        let _ = std::fs::remove_dir(dir);
    }
    recovered
}

/// Recover one stale encrypted container into Downloads. The container is
/// only deleted after the plaintext has been moved; transient save failures
/// keep it for the next sweep.
fn recover_encrypted_staged(
    container: &Path,
    staging_dir: &Path,
    downloads: &Path,
    events: &EventSink,
    encryption: &Encryption,
    kind: crypto::ContainerKind,
    pairing: Option<&crate::identity::PairingManager>,
) -> usize {
    let mut out_of_space = false;
    let gate = |size: u64| match security::ensure_free_space(staging_dir, Some(size)) {
        Ok(()) => Ok(()),
        Err(error) => {
            out_of_space = true;
            Err(error.context("make room for the decrypted file in staging"))
        }
    };

    let decrypted: crypto::Decrypted = match kind {
        crypto::ContainerKind::Passphrase => {
            let Some(decryptor) = encryption.decryptor() else {
                let _ = std::fs::remove_file(container);
                events.send(Event::Log(format!(
                    "deleted a stale encrypted container at {:?}: no passphrase is configured",
                    container
                )));
                return 0;
            };
            match decryptor.decrypt_to_gated(container, staging_dir, gate) {
                Ok(decrypted) => decrypted,
                Err(error) if out_of_space => {
                    events.send(Event::Log(format!(
                        "cannot recover a stale encrypted file yet: {error:#}"
                    )));
                    return 0;
                }
                Err(error) => {
                    let _ = std::fs::remove_file(container);
                    events.send(Event::Log(format!(
                        "deleted a stale encrypted container that could not be decrypted: {error:#}"
                    )));
                    return 0;
                }
            }
        }
        crypto::ContainerKind::Peer => {
            let Some(pairing) = pairing else {
                events.send(Event::Log(format!(
                    "kept a stale paired-device container at {:?}: pairing is unavailable",
                    container
                )));
                return 0;
            };
            let selected = crypto::peer_key_id(container)
                .ok()
                .flatten()
                .and_then(|key_id| pairing.trust().peer_by_key_id(&key_id))
                .and_then(|(address, _)| {
                    pairing
                        .trust()
                        .incoming_chain(&address)
                        .zip(pairing.trust().peer_public(&address))
                        .map(|(chain, public)| (address, chain, public))
                });
            let Some((address, chain, public)) = selected else {
                let _ = std::fs::remove_file(container);
                events.send(Event::Log(format!(
                    "deleted a stale paired-device container at {:?}: the sending device is \
                     no longer paired",
                    container
                )));
                return 0;
            };
            let decryptor = match crypto::PeerDecryptor::new(chain.key, chain.step, public) {
                Ok(decryptor) => decryptor,
                Err(error) => {
                    let _ = std::fs::remove_file(container);
                    events.send(Event::Log(format!(
                        "deleted a stale paired-device container with an invalid pinned \
                         identity: {error:#}"
                    )));
                    return 0;
                }
            };
            match decryptor.decrypt_to_gated(container, staging_dir, gate) {
                Ok(decrypted) => {
                    if let Err(error) = pairing.trust().commit_incoming(
                        &address,
                        decrypted.step,
                        decrypted.next_key,
                    ) {
                        let _ = std::fs::remove_file(&decrypted.path);
                        let _ = std::fs::remove_file(container);
                        events.send(Event::Log(format!(
                            "deleted a stale paired-device container because its key chain \
                             could not be saved: {error:#}"
                        )));
                        return 0;
                    }
                    crypto::Decrypted {
                        path: decrypted.path,
                        name: decrypted.name,
                        size: decrypted.size,
                    }
                }
                Err(error) if out_of_space => {
                    events.send(Event::Log(format!(
                        "cannot recover a stale paired-device file yet: {error:#}"
                    )));
                    return 0;
                }
                Err(error) => {
                    let _ = std::fs::remove_file(container);
                    events.send(Event::Log(format!(
                        "deleted a stale paired-device container that could not be decrypted: \
                         {error:#}"
                    )));
                    return 0;
                }
            }
        }
    };
    let name = sanitize::filename(&decrypted.name);
    let discard = |path: &Path, container: &Path| {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(container);
    };

    match security::scan_received_file(&decrypted.path) {
        Ok(scan) if scan.blocked => {
            discard(&decrypted.path, container);
            events.send(Event::Log(format!(
                "deleted a stale decrypted file that matches the malware hash list (SHA-256 {})",
                security::digest_hex(scan.digest)
            )));
            return 0;
        }
        Ok(_) => {}
        Err(error) => {
            discard(&decrypted.path, container);
            events.send(Event::Log(format!(
                "deleted a stale decrypted file that could not be verified: {error:#}"
            )));
            return 0;
        }
    }
    let recovered_dir = sanitize::sender_dir(downloads, "Recovered");
    if let Err(error) = std::fs::create_dir_all(&recovered_dir)
        .with_context(|| format!("create recovered folder {recovered_dir:?}"))
        .and_then(|()| security::ensure_free_space(&recovered_dir, Some(decrypted.size)))
    {
        let _ = std::fs::remove_file(&decrypted.path);
        events.send(Event::Log(format!(
            "cannot recover an encrypted file into {recovered_dir:?}: {error:#}"
        )));
        return 0;
    }

    let mut dest = sanitize::unique_in_dir(&recovered_dir, &name);
    loop {
        match sanitize::move_file(&decrypted.path, &dest) {
            Ok(()) => {
                if let Err(error) = security::harden_received_file(&dest) {
                    events.send(Event::Log(format!(
                        "warning: cannot harden {}: {error:#}",
                        dest.display()
                    )));
                }
                let _ = std::fs::remove_file(container);
                events.send(Event::Log(format!(
                    "recovered an encrypted file from an interrupted transfer as {:?}",
                    dest
                )));
                return 1;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                dest = sanitize::unique_in_dir(&recovered_dir, &name);
            }
            Err(error) => {
                let _ = std::fs::remove_file(&decrypted.path);
                events.send(Event::Log(format!(
                    "cannot recover an encrypted file into Downloads: {error}"
                )));
                return 0;
            }
        }
    }
}

/// Guard against obexd reusing transfer object paths: only touch the
/// transfer this entry authorized (`Transfer1.Filename` must equal the
/// authorized staging destination). Returns `true` when the object now
/// belongs to some other transfer.
async fn stale_transfer(t: &TransferPropsProxy<'_>, dest: &Path) -> bool {
    match t.filename().await {
        Ok(filename) => Path::new(&filename) != dest,
        Err(_) => false, // object likely gone; let the caller recover from `dest`
    }
}

fn fail(
    events: &EventSink,
    p: &PendingTransfer,
    error: impl Into<String>,
    staged_at: Option<PathBuf>,
) {
    events.send(Event::IncomingFailed {
        id: p.id.clone(),
        sender: p.sender.clone(),
        name: p.name.clone(),
        error: error.into(),
        staged_at,
    });
}

fn stale_failure(events: &EventSink, p: &PendingTransfer) {
    fail(
        events,
        p,
        format!(
            "stale transfer object (path reused by another transfer); staged file kept at {}",
            p.staging_dir.display()
        ),
        Some(p.staging_dir.clone()),
    );
}

/// First transient poll failure for this entry. Returns the age of the
/// failure and whether it was just recorded.
fn note_transient_error(pending: &PendingTransfers, id: &str) -> Option<(Duration, bool)> {
    let mut list = pending.lock().expect("pending lock");
    let p = list.iter_mut().find(|p| p.id == id)?;
    let now = Instant::now();
    let first = p.last_error_at.is_none();
    let since = *p.last_error_at.get_or_insert(now);
    Some((now.duration_since(since), first))
}

fn clear_transient_error(pending: &PendingTransfers, id: &str) {
    if let Some(p) = pending
        .lock()
        .expect("pending lock")
        .iter_mut()
        .find(|p| p.id == id)
    {
        p.last_error_at = None;
    }
}

/// Record inbound progress and return how long the byte counter has been
/// unchanged. This is the active-transfer stall clock.
fn record_progress(pending: &PendingTransfers, id: &str, transferred: u64) -> Duration {
    let mut list = pending.lock().expect("pending lock");
    let Some(p) = list.iter_mut().find(|p| p.id == id) else {
        return Duration::ZERO;
    };
    let now = Instant::now();
    if transferred != p.last_transferred {
        p.last_transferred = transferred;
        p.last_progress_at = now;
    }
    now.duration_since(p.last_progress_at)
}

/// Record a status change and return how long the transfer has been in the
/// current status. Queued/suspended/unknown policies use this clock.
fn record_status(pending: &PendingTransfers, id: &str, status: &TransferStatus) -> Duration {
    let mut list = pending.lock().expect("pending lock");
    let Some(p) = list.iter_mut().find(|p| p.id == id) else {
        return Duration::ZERO;
    };
    let now = Instant::now();
    let raw = status.to_string();
    if p.last_status.as_deref() != Some(raw.as_str()) {
        p.last_status = Some(raw);
        p.status_since = now;
    }
    now.duration_since(p.status_since)
}

/// Delete staged bytes that already violate the size policy. obexd can write
/// more than the sender announced (or more than the OPP cap) before the
/// transfer completes, so every poll checks the file itself.
fn reject_oversized_staged(p: &PendingTransfer, events: &EventSink) -> bool {
    let Ok(metadata) = std::fs::metadata(&p.dest) else {
        return false;
    };
    let Some(reason) = security::oversized_reason(metadata.len(), p.size) else {
        return false;
    };
    let _ = std::fs::remove_file(&p.dest);
    fail(
        events,
        p,
        format!("{reason}; the oversized file was deleted"),
        None,
    );
    cleanup_staging(&p.staging_dir);
    true
}

/// True when a D-Bus error means the object really is gone rather than a
/// transient bus failure.
fn is_object_gone(e: &zbus::Error) -> bool {
    match e {
        zbus::Error::MethodError(name, _, _) => {
            let name = name.as_str();
            name.ends_with("UnknownObject")
                || name.ends_with("UnknownInterface")
                || name.ends_with("UnknownMethod")
                || name.ends_with("NameHasNoOwner")
        }
        _ => false,
    }
}

/// Decide whether a transient poll failure should be recovered immediately,
/// retried, or has outlived the grace period.
fn transient_should_recover(
    pending: &PendingTransfers,
    p: &PendingTransfer,
    events: &EventSink,
    error: &str,
    gone: bool,
) -> bool {
    if gone {
        return true;
    }
    match note_transient_error(pending, &p.id) {
        Some((age, first)) if age < TRANSIENT_ERROR_GRACE => {
            if first {
                events.send(Event::Log(format!(
                    "{}: waiting for transfer object ({error})",
                    p.name
                )));
            }
            false
        }
        _ => true,
    }
}

/// A transfer object vanished. If obexd already wrote a staged file, keep it
/// and report a partial/recovered transfer; otherwise report failure.
fn handle_object_gone(
    p: &PendingTransfer,
    downloads: &Path,
    events: &EventSink,
    reason: impl Into<String>,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) {
    if p.dest.exists() {
        events.send(Event::Log(format!(
            "{}: transfer object disappeared; recovering staged file",
            p.dest.display()
        )));
        if let Err(e) = finalize_transfer(p, downloads, events, true, encryption, pairing) {
            fail(
                events,
                p,
                format!("recover staged file: {e}"),
                Some(p.staging_dir.clone()),
            );
        }
    } else {
        fail(events, p, reason, None);
        cleanup_staging(&p.staging_dir);
    }
}

/// obexd reported a terminal failure. Anything it already wrote is the only
/// copy of the received bytes, so it must be kept and moved to Downloads
/// (marked partial) instead of deleting the staging directory.
fn recover_failed_transfer(
    p: &PendingTransfer,
    downloads: &Path,
    events: &EventSink,
    error: &str,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) {
    if p.dest.exists() {
        events.send(Event::Log(format!(
            "{}: {error}; keeping the staged partial file",
            p.dest.display()
        )));
        if let Err(e) = finalize_transfer(p, downloads, events, true, encryption, pairing) {
            fail(
                events,
                p,
                format!("keep partial file: {e}"),
                Some(p.staging_dir.clone()),
            );
        }
    } else {
        fail(events, p, error, None);
        cleanup_staging(&p.staging_dir);
    }
}

/// Per-status incoming stall policy (pure, unit-tested). A single timeout
/// would either kill legitimate long transfers or leave unknown statuses
/// hanging forever.
fn incoming_stall_reason(
    status: &TransferStatus,
    status_since: Duration,
    progress_since: Duration,
) -> Option<String> {
    match status {
        TransferStatus::Complete | TransferStatus::Error => None,
        TransferStatus::Queued if status_since > INCOMING_QUEUED_TIMEOUT => Some(format!(
            "incoming transfer stayed queued for more than {}s",
            INCOMING_QUEUED_TIMEOUT.as_secs()
        )),
        TransferStatus::Active if progress_since > INCOMING_STALL_TIMEOUT => Some(format!(
            "incoming transfer made no progress for more than {}s",
            INCOMING_STALL_TIMEOUT.as_secs()
        )),
        TransferStatus::Suspended if status_since > INCOMING_SUSPENDED_TIMEOUT => Some(format!(
            "incoming transfer stayed suspended for more than {}s",
            INCOMING_SUSPENDED_TIMEOUT.as_secs()
        )),
        TransferStatus::Unknown(raw) if status_since > INCOMING_UNKNOWN_TIMEOUT => Some(format!(
            "incoming transfer stuck in unknown status '{raw}' for more than {}s",
            INCOMING_UNKNOWN_TIMEOUT.as_secs()
        )),
        _ => None,
    }
}

/// Poll pending incoming transfers; completion is detected by polling
/// (simple and runtime-agnostic for the spike).
pub async fn poll_pending(
    conn: &Connection,
    pending: &PendingTransfers,
    save_dir: &SaveDir,
    events: &EventSink,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) {
    let list = pending.lock().expect("pending lock").clone();
    if list.is_empty() {
        return;
    }
    // Snapshot once per poll: a preference change takes effect on the next
    // poll rather than splitting one completion across two folders.
    let downloads = save_dir.get();
    // Entries are finished by `id`, never by object path (obexd reuses paths).
    let mut finished: Vec<String> = Vec::new();

    for p in &list {
        // A peer can lie about (or omit) the OBEX length header. Check what
        // obexd actually wrote before doing any more D-Bus work.
        if reject_oversized_staged(p, events) {
            finished.push(p.id.clone());
            continue;
        }
        // With no announced size the upfront check only reserved a small
        // margin; keep watching the staging filesystem while it grows.
        if p.size.is_none()
            && let Err(error) = security::ensure_free_space(&p.staging_dir, None)
        {
            recover_failed_transfer(
                p,
                &downloads,
                events,
                &format!("not enough free disk space for the incoming file: {error:#}"),
                encryption,
                pairing,
            );
            finished.push(p.id.clone());
            continue;
        }
        let proxy = match TransferPropsProxy::builder(conn).path(p.path.as_str()) {
            Ok(builder) => match builder.build().await {
                Ok(proxy) => proxy,
                Err(e) => {
                    if !transient_should_recover(
                        pending,
                        p,
                        events,
                        &format!("proxy: {e}"),
                        is_object_gone(&e),
                    ) {
                        continue;
                    }
                    handle_object_gone(
                        p,
                        &downloads,
                        events,
                        format!("transfer object unavailable: {e}"),
                        encryption,
                        pairing,
                    );
                    finished.push(p.id.clone());
                    continue;
                }
            },
            Err(e) => {
                if !transient_should_recover(
                    pending,
                    p,
                    events,
                    &format!("proxy path: {e}"),
                    is_object_gone(&e),
                ) {
                    continue;
                }
                handle_object_gone(
                    p,
                    &downloads,
                    events,
                    format!("transfer object unavailable: {e}"),
                    encryption,
                    pairing,
                );
                finished.push(p.id.clone());
                continue;
            }
        };

        let status = match proxy.status().await {
            Ok(raw) => {
                clear_transient_error(pending, &p.id);
                TransferStatus::parse(&raw)
            }
            Err(e) => {
                if !transient_should_recover(
                    pending,
                    p,
                    events,
                    &format!("status: {e}"),
                    is_object_gone(&e),
                ) {
                    continue;
                }
                handle_object_gone(
                    p,
                    &downloads,
                    events,
                    format!("transfer object disappeared before completion: {e}"),
                    encryption,
                    pairing,
                );
                finished.push(p.id.clone());
                continue;
            }
        };

        match &status {
            TransferStatus::Complete => {
                if stale_transfer(&proxy, &p.dest).await {
                    stale_failure(events, p);
                    finished.push(p.id.clone());
                    continue; // keep the staging dir: it may hold the old file
                }
                if let Err(e) = finalize_transfer(p, &downloads, events, false, encryption, pairing)
                {
                    // Keep the staged source: a failed move must not destroy
                    // the only copy of the received file.
                    fail(
                        events,
                        p,
                        format!("save failed: {e}"),
                        Some(p.staging_dir.clone()),
                    );
                }
                finished.push(p.id.clone());
            }
            TransferStatus::Error => {
                if stale_transfer(&proxy, &p.dest).await {
                    stale_failure(events, p);
                    finished.push(p.id.clone());
                    continue; // keep the staging dir
                }
                recover_failed_transfer(
                    p,
                    &downloads,
                    events,
                    "transfer reported error",
                    encryption,
                    pairing,
                );
                finished.push(p.id.clone());
            }
            TransferStatus::Unknown(raw) if raw.eq_ignore_ascii_case("cancelled") => {
                if stale_transfer(&proxy, &p.dest).await {
                    stale_failure(events, p);
                    finished.push(p.id.clone());
                    continue; // keep the staging dir
                }
                recover_failed_transfer(
                    p,
                    &downloads,
                    events,
                    "transfer was canceled",
                    encryption,
                    pairing,
                );
                finished.push(p.id.clone());
            }
            _ => {
                let status_since = record_status(pending, &p.id, &status);
                let transferred = proxy.transferred().await.ok();
                let idle =
                    record_progress(pending, &p.id, transferred.unwrap_or(p.last_transferred));
                if let Some(reason) = incoming_stall_reason(&status, status_since, idle) {
                    handle_object_gone(p, &downloads, events, reason, encryption, pairing);
                    finished.push(p.id.clone());
                    continue;
                }
                events.send(Event::IncomingProgress {
                    id: p.id.clone(),
                    name: p.name.clone(),
                    transferred,
                    size: p.size,
                });
            }
        }
    }

    if !finished.is_empty() {
        pending
            .lock()
            .expect("pending lock")
            .retain(|x| !finished.contains(&x.id));
    }
}

/// Move the authorized staging file into `~/Downloads`, report stats, and
/// remove the staging directory only on success.
fn finalize_transfer(
    p: &PendingTransfer,
    downloads: &Path,
    events: &EventSink,
    interrupted: bool,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) -> Result<()> {
    finish_transfer(p, downloads, events, interrupted, encryption, pairing)?;
    cleanup_staging(&p.staging_dir);
    Ok(())
}

fn finish_transfer(
    p: &PendingTransfer,
    downloads: &Path,
    events: &EventSink,
    interrupted: bool,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) -> Result<()> {
    if p.control {
        return finish_pairing_transfer(p, events, encryption, pairing);
    }
    let target_dir = sanitize::sender_dir(downloads, &p.sender_label);
    std::fs::create_dir_all(&target_dir)
        .with_context(|| format!("create sender folder {target_dir:?}"))?;
    let bytes = std::fs::metadata(&p.dest)
        .with_context(|| format!("read staged file {:?}", p.dest))?
        .len();
    // Final gate: a fast sender can finish between two polls, so re-check the
    // completed object before it enters the save folder.
    if let Some(reason) = security::oversized_reason(bytes, p.size) {
        let _ = std::fs::remove_file(&p.dest);
        events.send(Event::IncomingFailed {
            id: p.id.clone(),
            sender: p.sender.clone(),
            name: p.name.clone(),
            error: format!("{reason}; the oversized file was deleted"),
            staged_at: None,
        });
        return Ok(());
    }
    if let Some(kind) = crypto::container_kind(&p.dest)? {
        return finish_encrypted_transfer(
            p,
            downloads,
            events,
            interrupted,
            bytes,
            encryption,
            pairing,
            kind,
        );
    }
    let base = p
        .dest
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "received-file".into());
    let name = sanitize::filename(&base);

    // Verify the finished object before it enters the user's save folder. A
    // blocked file is deleted from staging and never shown as saved; a scan
    // failure keeps the private staged copy for manual recovery instead of
    // pretending the file is safe.
    let scan = security::scan_received_file(&p.dest)?;
    if scan.blocked {
        let _ = std::fs::remove_file(&p.dest);
        events.send(Event::IncomingFailed {
            id: p.id.clone(),
            sender: p.sender.clone(),
            name: p.name.clone(),
            error: format!(
                "blocked by the malware hash list (SHA-256 {}); the received file was deleted",
                security::digest_hex(scan.digest)
            ),
            staged_at: None,
        });
        return Ok(());
    }
    security::ensure_free_space(&target_dir, Some(bytes))?;

    // Retry the numbered name if another writer wins the race between
    // `unique_in_dir` and the no-overwrite move.
    let mut final_path = sanitize::unique_in_dir(&target_dir, &name);
    loop {
        match sanitize::move_file(&p.dest, &final_path) {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                final_path = sanitize::unique_in_dir(&target_dir, &name);
            }
            Err(e) => return Err(e).context("move into the sender folder"),
        }
    }
    if let Err(error) = security::harden_received_file(&final_path) {
        events.send(Event::Log(format!(
            "warning: cannot harden {}: {error:#}",
            final_path.display()
        )));
    }

    let partial = match p.size {
        Some(expected) => bytes != expected,
        None => interrupted,
    };
    let elapsed_secs = p.started.elapsed().as_secs_f64();
    let mbps = if elapsed_secs > 0.0 {
        bytes as f64 / (1024.0 * 1024.0) / elapsed_secs
    } else {
        0.0
    };
    events.send(Event::IncomingDone {
        id: p.id.clone(),
        sender: p.sender.clone(),
        name: p.name.clone(),
        saved_to: final_path,
        bytes,
        elapsed_secs,
        mbps,
        partial,
    });
    Ok(())
}

/// Finish a pairing control object: process it, delete it, and optionally
/// send the next protocol object back over a fresh OPP session.
fn finish_pairing_transfer(
    p: &PendingTransfer,
    events: &EventSink,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) -> Result<()> {
    let Some(pairing) = pairing else {
        let _ = std::fs::remove_file(&p.dest);
        cleanup_staging(&p.staging_dir);
        events.send(Event::Pairing {
            address: p.sender.clone(),
            name: p.sender.clone(),
            ok: false,
            message: "pairing is unavailable on this installation".into(),
        });
        return Ok(());
    };
    let Some(passphrase) = encryption.passphrase() else {
        let _ = std::fs::remove_file(&p.dest);
        cleanup_staging(&p.staging_dir);
        events.send(Event::Pairing {
            address: p.sender.clone(),
            name: p.sender.clone(),
            ok: false,
            message: "set a shared passphrase before pairing".into(),
        });
        return Ok(());
    };
    let result = pairing.handle_file(&p.sender, &p.dest, &passphrase);
    let _ = std::fs::remove_file(&p.dest);
    cleanup_staging(&p.staging_dir);
    match result {
        Ok(outcome) => {
            events.send(Event::Log(format!(
                "pairing object from {}: {}",
                p.sender, outcome.message
            )));
            if let Some(reply) = outcome.reply {
                let peer = p.sender.clone();
                let events = events.clone();
                tokio::spawn(async move {
                    if let Err(error) = crate::platform::send_control(&peer, &reply, &events).await
                    {
                        events.send(Event::Log(format!(
                            "could not deliver a pairing reply to {peer}: {error:#}"
                        )));
                    }
                });
            }
        }
        Err(error) => {
            events.send(Event::Pairing {
                address: p.sender.clone(),
                name: p.sender.clone(),
                ok: false,
                message: format!("{error:#}"),
            });
        }
    }
    Ok(())
}

/// Decrypt a completed Kalo container, scan the plaintext and save it under
/// its authenticated original name. Repeated hashing is intentional: the
/// malware list must see the bytes the user will actually open, not the
/// ciphertext.
#[allow(clippy::too_many_arguments)]
fn finish_encrypted_transfer(
    p: &PendingTransfer,
    downloads: &Path,
    events: &EventSink,
    interrupted: bool,
    container_bytes: u64,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
    kind: crypto::ContainerKind,
) -> Result<()> {
    let target_dir = sanitize::sender_dir(downloads, &p.sender_label);
    std::fs::create_dir_all(&target_dir)
        .with_context(|| format!("create sender folder {target_dir:?}"))?;
    if interrupted {
        let _ = std::fs::remove_file(&p.dest);
        events.send(Event::IncomingFailed {
            id: p.id.clone(),
            sender: p.sender.clone(),
            name: p.name.clone(),
            error: "the encrypted transfer did not complete; the partial container was deleted"
                .into(),
            staged_at: None,
        });
        return Ok(());
    }

    let mut out_of_space = false;
    let gate = |size: u64| match security::ensure_free_space(&p.staging_dir, Some(size)) {
        Ok(()) => Ok(()),
        Err(error) => {
            out_of_space = true;
            Err(error.context("make room for the decrypted file in staging"))
        }
    };

    let decrypted: crypto::Decrypted = match kind {
        crypto::ContainerKind::Passphrase => {
            let Some(decryptor) = encryption.decryptor() else {
                let _ = std::fs::remove_file(&p.dest);
                events.send(Event::IncomingFailed {
                    id: p.id.clone(),
                    sender: p.sender.clone(),
                    name: p.name.clone(),
                    error: "received an encrypted Kalo file but no encryption passphrase is \
                            configured; the container was deleted"
                        .into(),
                    staged_at: None,
                });
                return Ok(());
            };
            match decryptor.decrypt_to_gated(&p.dest, &p.staging_dir, gate) {
                Ok(decrypted) => decrypted,
                // A full disk is not a bad container: keep it for the
                // recovery sweep instead of destroying the only copy.
                Err(error) if out_of_space => return Err(error),
                Err(error) => {
                    let _ = std::fs::remove_file(&p.dest);
                    events.send(Event::IncomingFailed {
                        id: p.id.clone(),
                        sender: p.sender.clone(),
                        name: p.name.clone(),
                        error: format!(
                            "cannot decrypt the incoming file (wrong passphrase or corrupted \
                             container): {error:#}; the container was deleted"
                        ),
                        staged_at: None,
                    });
                    return Ok(());
                }
            }
        }
        crypto::ContainerKind::Peer => {
            let Some(pairing) = pairing else {
                let _ = std::fs::remove_file(&p.dest);
                events.send(Event::IncomingFailed {
                    id: p.id.clone(),
                    sender: p.sender.clone(),
                    name: p.name.clone(),
                    error: "received a paired-device container but pairing is unavailable; \
                            the container was deleted"
                        .into(),
                    staged_at: None,
                });
                return Ok(());
            };
            // Prefer the sender address, then fall back to the pinned key id.
            // The key id is covered by the signature, so it only selects a
            // pinned peer; it never authenticates one by itself.
            let selected = pairing
                .trust()
                .incoming_chain(&p.sender)
                .zip(pairing.trust().peer_public(&p.sender))
                .map(|(chain, public)| (p.sender.clone(), chain, public))
                .or_else(|| {
                    crypto::peer_key_id(&p.dest)
                        .ok()
                        .flatten()
                        .and_then(|key_id| pairing.trust().peer_by_key_id(&key_id))
                        .and_then(|(address, _)| {
                            pairing
                                .trust()
                                .incoming_chain(&address)
                                .zip(pairing.trust().peer_public(&address))
                                .map(|(chain, public)| (address, chain, public))
                        })
                });
            let Some((address, chain, public)) = selected else {
                let _ = std::fs::remove_file(&p.dest);
                events.send(Event::IncomingFailed {
                    id: p.id.clone(),
                    sender: p.sender.clone(),
                    name: p.name.clone(),
                    error: "received a paired-device container from a device that is not \
                            paired with this Kalo installation; the container was deleted"
                        .into(),
                    staged_at: None,
                });
                return Ok(());
            };
            let decryptor = match crypto::PeerDecryptor::new(chain.key, chain.step, public) {
                Ok(decryptor) => decryptor,
                Err(error) => {
                    let _ = std::fs::remove_file(&p.dest);
                    events.send(Event::IncomingFailed {
                        id: p.id.clone(),
                        sender: p.sender.clone(),
                        name: p.name.clone(),
                        error: format!(
                            "cannot use the pinned identity for {address}: {error:#}; \
                             the container was deleted"
                        ),
                        staged_at: None,
                    });
                    return Ok(());
                }
            };
            match decryptor.decrypt_to_gated(&p.dest, &p.staging_dir, gate) {
                Ok(decrypted) => {
                    // Burn the ratchet step before any further processing.
                    // A replay of this container must fail even if the file is
                    // later rejected by the malware scan.
                    if let Err(error) = pairing.trust().commit_incoming(
                        &address,
                        decrypted.step,
                        decrypted.next_key,
                    ) {
                        let _ = std::fs::remove_file(&decrypted.path);
                        let _ = std::fs::remove_file(&p.dest);
                        events.send(Event::IncomingFailed {
                            id: p.id.clone(),
                            sender: p.sender.clone(),
                            name: p.name.clone(),
                            error: format!(
                                "the incoming paired-device key chain could not be saved: \
                                 {error:#}; the container was deleted"
                            ),
                            staged_at: None,
                        });
                        return Ok(());
                    }
                    crypto::Decrypted {
                        path: decrypted.path,
                        name: decrypted.name,
                        size: decrypted.size,
                    }
                }
                Err(error) if out_of_space => return Err(error),
                Err(error) => {
                    let _ = std::fs::remove_file(&p.dest);
                    events.send(Event::IncomingFailed {
                        id: p.id.clone(),
                        sender: p.sender.clone(),
                        name: p.name.clone(),
                        error: format!(
                            "cannot decrypt the paired-device container (wrong identity, \
                             replayed or corrupted file): {error:#}; the container was deleted"
                        ),
                        staged_at: None,
                    });
                    return Ok(());
                }
            }
        }
    };
    let name = sanitize::filename(&decrypted.name);
    if name != decrypted.name {
        events.send(Event::Log(format!(
            "renamed encrypted file {:?} to {:?}",
            decrypted.name, name
        )));
    }

    let scan = match security::scan_received_file(&decrypted.path) {
        Ok(scan) => scan,
        Err(error) => {
            let _ = std::fs::remove_file(&decrypted.path);
            let _ = std::fs::remove_file(&p.dest);
            events.send(Event::IncomingFailed {
                id: p.id.clone(),
                sender: p.sender.clone(),
                name: p.name.clone(),
                error: format!(
                    "cannot verify the decrypted file: {error:#}; both the decrypted copy and \
                     the container were deleted"
                ),
                staged_at: None,
            });
            return Ok(());
        }
    };
    if scan.blocked {
        let _ = std::fs::remove_file(&decrypted.path);
        let _ = std::fs::remove_file(&p.dest);
        events.send(Event::IncomingFailed {
            id: p.id.clone(),
            sender: p.sender.clone(),
            name: p.name.clone(),
            error: format!(
                "the decrypted file matches a known malicious SHA-256 hash ({}); it was deleted",
                security::digest_hex(scan.digest)
            ),
            staged_at: None,
        });
        return Ok(());
    }
    if let Err(error) = security::ensure_free_space(&target_dir, Some(decrypted.size)) {
        // Keep the container for a later sweep, but never leave plaintext in
        // staging where the recovery walk could mistake it for a normal file.
        let _ = std::fs::remove_file(&decrypted.path);
        return Err(error).context("make room for the decrypted file");
    }

    let mut final_path = sanitize::unique_in_dir(&target_dir, &name);
    loop {
        match sanitize::move_file(&decrypted.path, &final_path) {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                final_path = sanitize::unique_in_dir(&target_dir, &name);
            }
            Err(error) => {
                let _ = std::fs::remove_file(&decrypted.path);
                return Err(error).context("move decrypted file into the sender folder");
            }
        }
    }
    if let Err(error) = security::harden_received_file(&final_path) {
        events.send(Event::Log(format!(
            "warning: cannot harden {}: {error:#}",
            final_path.display()
        )));
    }
    let _ = std::fs::remove_file(&p.dest);

    let elapsed_secs = p.started.elapsed().as_secs_f64();
    let mbps = if elapsed_secs > 0.0 {
        decrypted.size as f64 / (1024.0 * 1024.0) / elapsed_secs
    } else {
        0.0
    };
    events.send(Event::Log(format!(
        "decrypted {name} from an encrypted container ({} on the wire, {} plaintext)",
        crate::events::format_bytes(container_bytes),
        crate::events::format_bytes(decrypted.size)
    )));
    events.send(Event::IncomingDone {
        id: p.id.clone(),
        sender: p.sender.clone(),
        name,
        saved_to: final_path,
        bytes: decrypted.size,
        elapsed_secs,
        mbps,
        partial: false,
    });
    Ok(())
}

fn registration_path(id: u64) -> String {
    format!("{AGENT_PATH}/{id}")
}

async fn export_agent(conn: &Connection, path: &str, service: AgentService) -> Result<()> {
    conn.object_server()
        .at(path, service)
        .await
        .context("export OBEX agent object")?;
    Ok(())
}

/// Export a uniquely-pathed agent object and register it with obexd. Returns
/// the object path so the supervisor can remove it once replaced.
async fn register_receiver(
    conn: &Connection,
    handle: ReceiverHandle,
    pending: PendingTransfers,
    events: EventSink,
    authorizer: Authorizer,
    save_dir: SaveDir,
    pairing: Option<crate::identity::PairingManager>,
) -> Result<String> {
    let registration = handle.begin_registration();
    let path = registration_path(registration);

    let service = AgentService {
        conn: conn.clone(),
        pending,
        events: events.clone(),
        handle: handle.clone(),
        registration,
        authorizer,
        save_dir,
        pairing,
    };
    export_agent(conn, &path, service).await?;

    let manager = match AgentManagerProxy::new(conn).await {
        Ok(manager) => manager,
        Err(e) => {
            let _ = conn
                .object_server()
                .remove::<AgentService, _>(path.as_str())
                .await;
            return Err(e.into());
        }
    };
    let agent_path = match opath(&path) {
        Ok(path) => path,
        Err(e) => {
            let _ = conn
                .object_server()
                .remove::<AgentService, _>(path.as_str())
                .await;
            return Err(e.into());
        }
    };
    if let Err(e) = manager.register_agent(agent_path.clone()).await {
        let _ = conn
            .object_server()
            .remove::<AgentService, _>(path.as_str())
            .await;
        return Err(e.into());
    }

    let became_active = handle.mark_active(registration);
    if !became_active && !handle.is_active() {
        // A Release (or an obexd restart) invalidated this registration
        // before the reply arrived. Undo it and let the supervisor retry.
        let _ = manager.unregister_agent(agent_path).await;
        let _ = conn
            .object_server()
            .remove::<AgentService, _>(path.as_str())
            .await;
        return Err(anyhow!("agent registration was invalidated during startup"));
    }
    Ok(path)
}

fn is_already_exists(e: &anyhow::Error) -> bool {
    if let Some(zbus::Error::MethodError(name, _, _)) = e.downcast_ref::<zbus::Error>() {
        return name.as_str().ends_with("AlreadyExists");
    }
    e.to_string().contains("AlreadyExists")
}

/// User-facing registration error text, shared by the CLI and the UI retry.
pub fn registration_error(e: &anyhow::Error) -> String {
    if is_already_exists(e) {
        "the OBEX agent slot is taken (Blueman TransferService is active?). Disable \
         Blueman's Transfer plugin or stop blueman-applet; Kalo will retry."
            .to_string()
    } else {
        format!("OBEX agent registration failed: {e}")
    }
}

/// Supervisor shared by the UI and `kalo receive`: connects to the session
/// bus, registers the agent, retries lost registrations and replaces the
/// connection when the bus goes away.
pub async fn run_receiver(
    handle: ReceiverHandle,
    pending: PendingTransfers,
    save_dir: SaveDir,
    events: EventSink,
    authorizer: Authorizer,
    encryption: Encryption,
    pairing: Option<crate::identity::PairingManager>,
) -> ! {
    loop {
        match Connection::session().await {
            Ok(conn) => {
                if let Err(e) = receiver_session(
                    &conn,
                    &handle,
                    &pending,
                    &save_dir,
                    &events,
                    &authorizer,
                    &encryption,
                    pairing.as_ref(),
                )
                .await
                {
                    let reason = format!("session bus connection lost: {e}; reconnecting");
                    handle.mark_lost(&reason);
                    events.send(Event::Log(reason));
                }
            }
            Err(e) => {
                let reason = format!("D-Bus session error: {e}; retrying");
                handle.mark_lost(&reason);
            }
        }
        tokio::time::sleep(SESSION_BUS_RETRY).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn receiver_session(
    conn: &Connection,
    handle: &ReceiverHandle,
    pending: &PendingTransfers,
    save_dir: &SaveDir,
    events: &EventSink,
    authorizer: &Authorizer,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) -> Result<()> {
    let mut owner_changes = match obexd_owner_changes(conn).await {
        Ok(changes) => Some(changes),
        Err(e) => {
            events.send(Event::Log(format!("obexd owner watch unavailable: {e}")));
            None
        }
    };

    let mut last_registration_error: Option<String> = None;
    let mut current_path = match register_receiver(
        conn,
        handle.clone(),
        pending.clone(),
        events.clone(),
        authorizer.clone(),
        save_dir.clone(),
        pairing.cloned(),
    )
    .await
    {
        Ok(path) => {
            sweep_staging(save_dir, events, encryption, pairing);
            Some(path)
        }
        Err(e) => {
            let reason = registration_error(&e);
            handle.mark_lost(&reason);
            events.send(Event::Log(format!(
                "receiver registration failed: {reason}"
            )));
            last_registration_error = Some(reason);
            None
        }
    };
    // Poll while any agent object exists: in-flight transfers may still
    // finish even after obexd released the registration.
    let mut exported = current_path.is_some();

    let mut retry = tokio::time::interval(REGISTRATION_RETRY);
    retry.set_missed_tick_behavior(MissedTickBehavior::Delay);
    retry.tick().await; // consume the immediate first tick
    let mut poll = tokio::time::interval(PENDING_POLL_INTERVAL);
    poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
    poll.tick().await;
    let mut sweep = tokio::time::interval(STAGING_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);
    sweep.tick().await;

    loop {
        if conn.is_closed() {
            bail!("session bus connection closed");
        }
        tokio::select! {
            change = async {
                match owner_changes.as_mut() {
                    Some(changes) => changes.next().await,
                    None => std::future::pending().await,
                }
            } => {
                match change {
                    Some(_) => {
                        events.send(Event::Log(
                            "obexd restarted; re-registering the receiver".into(),
                        ));
                        handle.mark_lost("obexd restarted; will retry registration");
                        last_registration_error = None;
                        // Retry now instead of waiting for the next tick.
                        retry.reset();
                    }
                    None => {
                        owner_changes = None;
                        events.send(Event::Log(
                            "obexd owner watch ended; using registration retries".into(),
                        ));
                    }
                }
            }
            _ = poll.tick(), if exported => {
                poll_pending(conn, pending, save_dir, events, encryption, pairing).await;
                if conn.is_closed() {
                    bail!("session bus connection closed");
                }
            }
            _ = retry.tick(), if !handle.is_active() => {
                match register_receiver(
                    conn,
                    handle.clone(),
                    pending.clone(),
                    events.clone(),
                    authorizer.clone(),
                    save_dir.clone(),
                    pairing.cloned(),
                )
                .await
                {
                    Ok(path) => {
                        if let Some(old) = current_path.replace(path) {
                            let _ = conn
                                .object_server()
                                .remove::<AgentService, _>(old.as_str())
                                .await;
                        }
                        exported = true;
                        last_registration_error = None;
                        sweep_staging(save_dir, events, encryption, pairing);
                    }
                    Err(e) => {
                        let reason = registration_error(&e);
                        handle.mark_lost(&reason);
                        // Log only when the reason changes: retries are
                        // frequent and the status event already carries it.
                        if last_registration_error.as_deref() != Some(reason.as_str()) {
                            events.send(Event::Log(format!(
                                "receiver registration retry failed: {reason}"
                            )));
                            last_registration_error = Some(reason);
                        }
                    }
                }
            }
            _ = sweep.tick(), if handle.is_active() => {
                sweep_staging(save_dir, events, encryption, pairing);
            }
        }
    }
}

/// CLI: grab and immediately release the OBEX agent slot (non-destructive).
pub async fn agent_check() -> Result<()> {
    let conn = Connection::session().await?;
    let events = EventSink::new(64);
    let mut rx = events.subscribe();
    let handle = ReceiverHandle::new(events.clone());
    let authorizer = Authorizer::new(TrustStore::in_memory(), events.clone(), false);
    let check_save = SaveDir::new(paths::default_save_dir());
    let path = register_receiver(
        &conn,
        handle,
        new_pending(),
        events.clone(),
        authorizer,
        check_save,
        None,
    )
    .await?;
    let manager = AgentManagerProxy::new(&conn).await?;
    manager.unregister_agent(opath(&path)?).await?;
    let _ = conn
        .object_server()
        .remove::<AgentService, _>(path.as_str())
        .await;
    while let Ok(event) = rx.try_recv() {
        println!("{event:?}");
    }
    println!("agent-check OK: the slot was free and is free again.");
    Ok(())
}

/// CLI: run the receiver in the foreground. Trusted senders only; approve
/// new senders from the desktop UI.
pub async fn receive() -> Result<()> {
    let events = EventSink::new(1024);
    let mut rx = events.subscribe();
    let handle = ReceiverHandle::new(events.clone());
    let pending = new_pending();
    let (settings, settings_warning) = Settings::load();
    if let Some(warning) = settings_warning {
        eprintln!("warning: {warning}");
    }
    let save_dir = SaveDir::new(
        settings
            .save_dir
            .clone()
            .unwrap_or_else(paths::default_save_dir),
    );
    let encryption = Encryption::new(
        settings.encrypt_sends,
        settings.encryption_passphrase.clone(),
    );
    let (trust, trust_warning) = TrustStore::load();
    if let Some(warning) = trust_warning {
        eprintln!("warning: {warning}");
    }
    let authorizer = Authorizer::new(trust.clone(), events.clone(), false);

    println!(
        "listening… (Ctrl-C to stop); new senders are rejected in the CLI — approve \
         them in the Kalo window"
    );
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => println!("{event:?}"),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(dropped)) => {
                    eprintln!("warning: event stream lagged; dropped {dropped} events");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let identity = match crate::identity::DeviceIdentity::load_or_create() {
        Ok(identity) => Some(crate::identity::PairingManager::new(
            identity,
            trust.clone(),
            events.clone(),
        )),
        Err(error) => {
            eprintln!("warning: paired-device encryption is unavailable: {error:#}");
            None
        }
    };
    run_receiver(
        handle, pending, save_dir, events, authorizer, encryption, identity,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::ReceiverStatus;
    use tokio::sync::broadcast;

    fn event_sink() -> (EventSink, broadcast::Receiver<Event>) {
        let sink = EventSink::new(64);
        let rx = sink.subscribe();
        (sink, rx)
    }

    fn no_encryption() -> Encryption {
        Encryption::new(false, String::new())
    }

    fn pending_transfer(dest: PathBuf, size: Option<u64>) -> PendingTransfer {
        let staging_dir = dest.parent().unwrap().to_path_buf();
        PendingTransfer {
            id: "id-1".into(),
            name: "photo.jpg".into(),
            sender: "AA:BB".into(),
            sender_label: "Pixel 8".into(),
            size,
            path: "/org/bluez/obex/session/transfer1".into(),
            dest,
            staging_dir,
            started: Instant::now(),
            last_error_at: None,
            last_progress_at: Instant::now(),
            last_transferred: 0,
            last_status: None,
            status_since: Instant::now(),
            control: false,
        }
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kalo-test-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn save_failure_preserves_staged_file() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let dest = staging.join("photo.jpg");
        std::fs::write(&dest, b"hello").unwrap();

        // Make the Downloads path invalid by putting a regular file in the
        // way. `create_dir_all` must fail and the staged file must survive.
        let blocker = dir.join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let downloads = blocker.join("Downloads");
        let (events, mut rx) = event_sink();
        let p = pending_transfer(dest.clone(), Some(5));

        assert!(finalize_transfer(&p, &downloads, &events, false, &no_encryption(), None).is_err());
        assert!(dest.exists(), "staged source must be kept on save failure");
        let _ = rx.try_recv();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn successful_save_cleans_staging_and_reports_size() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let dest = staging.join("photo.jpg");
        std::fs::write(&dest, b"hello").unwrap();
        let downloads = dir.join("Downloads");
        let (events, mut rx) = event_sink();
        let p = pending_transfer(dest.clone(), Some(5));

        finalize_transfer(&p, &downloads, &events, false, &no_encryption(), None).unwrap();
        assert!(!dest.exists());
        assert!(!staging.exists());
        let event = rx.try_recv().unwrap();
        match event {
            Event::IncomingDone {
                name,
                bytes,
                partial,
                ..
            } => {
                assert_eq!(name, "photo.jpg");
                assert_eq!(bytes, 5);
                assert!(!partial);
            }
            other => panic!("unexpected event: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn oversized_staged_file_is_deleted() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let dest = staging.join("photo.jpg");
        std::fs::write(&dest, b"hello").unwrap();
        let (events, mut rx) = event_sink();
        let p = pending_transfer(dest.clone(), Some(4));

        assert!(reject_oversized_staged(&p, &events));
        assert!(!dest.exists(), "oversized staged bytes must be deleted");
        assert!(!staging.exists(), "empty staging dir must be removed");
        match rx.try_recv().unwrap() {
            Event::IncomingFailed {
                error, staged_at, ..
            } => {
                assert!(error.contains("announced"), "unexpected error: {error}");
                assert!(error.contains("deleted"), "unexpected error: {error}");
                assert_eq!(staged_at, None);
            }
            other => panic!("unexpected event: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn staged_size_at_or_below_the_announcement_is_kept() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let dest = staging.join("photo.jpg");
        std::fs::write(&dest, b"hello").unwrap();
        let (events, _rx) = event_sink();

        assert!(!reject_oversized_staged(
            &pending_transfer(dest.clone(), Some(5)),
            &events
        ));
        assert!(dest.exists());
        assert!(!reject_oversized_staged(
            &pending_transfer(dest.clone(), None),
            &events
        ));
        assert!(dest.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn finalize_deletes_an_oversized_completed_file() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let dest = staging.join("photo.jpg");
        std::fs::write(&dest, b"hello").unwrap();
        let downloads = dir.join("Downloads");
        let (events, mut rx) = event_sink();
        let p = pending_transfer(dest.clone(), Some(4));

        // A sender can finish between two polls; finalization is the last
        // gate before the save folder.
        finalize_transfer(&p, &downloads, &events, false, &no_encryption(), None).unwrap();

        assert!(!dest.exists());
        assert!(!staging.exists());
        assert!(
            !sanitize::sender_dir(&downloads, "Pixel 8")
                .join("photo.jpg")
                .exists()
        );
        match rx.try_recv().unwrap() {
            Event::IncomingFailed { error, .. } => {
                assert!(error.contains("announced"), "unexpected error: {error}");
                assert!(error.contains("deleted"), "unexpected error: {error}");
            }
            other => panic!("unexpected event: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn size_mismatch_is_reported_as_partial() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let dest = staging.join("photo.jpg");
        std::fs::write(&dest, b"hello").unwrap();
        let downloads = dir.join("Downloads");
        let (events, mut rx) = event_sink();
        let p = pending_transfer(dest, Some(10));

        finalize_transfer(&p, &downloads, &events, false, &no_encryption(), None).unwrap();
        match rx.try_recv().unwrap() {
            Event::IncomingDone { partial, bytes, .. } => {
                assert_eq!(bytes, 5);
                assert!(partial, "short file must be marked partial");
            }
            other => panic!("unexpected event: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn interrupted_unknown_size_is_partial() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let dest = staging.join("photo.jpg");
        std::fs::write(&dest, b"hello").unwrap();
        let downloads = dir.join("Downloads");
        let (events, mut rx) = event_sink();
        let p = pending_transfer(dest, None);

        finalize_transfer(&p, &downloads, &events, true, &no_encryption(), None).unwrap();
        match rx.try_recv().unwrap() {
            Event::IncomingDone { partial, .. } => assert!(partial),
            other => panic!("unexpected event: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn error_keeps_partial_staged_file() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let dest = staging.join("photo.jpg");
        std::fs::write(&dest, b"hello").unwrap();
        let downloads = dir.join("Downloads");
        let (events, mut rx) = event_sink();
        let p = pending_transfer(dest, Some(10));

        // SM-01 regression: an obexd error after some bytes were written must
        // move the partial file to Downloads instead of deleting it.
        recover_failed_transfer(
            &p,
            &downloads,
            &events,
            "transfer reported error",
            &no_encryption(),
            None,
        );

        match rx
            .try_recv()
            .into_iter()
            .chain(std::iter::from_fn(|| rx.try_recv().ok()))
            .find(|event| !matches!(event, Event::Log(_)))
            .expect("completion event")
        {
            Event::IncomingDone { partial, bytes, .. } => {
                assert!(partial);
                assert_eq!(bytes, 5);
            }
            other => panic!("unexpected event: {other:?}"),
        }
        assert!(
            sanitize::sender_dir(&downloads, "Pixel 8")
                .join("photo.jpg")
                .exists()
        );
        assert!(!staging.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn canceled_transfer_with_nothing_staged_reports_failure() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let downloads = dir.join("Downloads");
        let (events, mut rx) = event_sink();
        let p = pending_transfer(staging.join("photo.jpg"), Some(10));

        recover_failed_transfer(
            &p,
            &downloads,
            &events,
            "transfer was canceled",
            &no_encryption(),
            None,
        );
        match rx.try_recv().unwrap() {
            Event::IncomingFailed { error, .. } => {
                assert_eq!(error, "transfer was canceled");
            }
            other => panic!("unexpected event: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn failure_uses_filename_and_keeps_staging_path() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let p = pending_transfer(staging.join("photo.jpg"), Some(5));
        let (events, mut rx) = event_sink();

        fail(&events, &p, "boom", Some(staging.clone()));
        match rx.try_recv().unwrap() {
            Event::IncomingFailed {
                name,
                staged_at,
                error,
                ..
            } => {
                assert_eq!(name, "photo.jpg");
                assert_eq!(error, "boom");
                assert_eq!(staged_at, Some(staging));
            }
            other => panic!("unexpected event: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn transient_error_grace_is_tracked_and_cleared() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let p = pending_transfer(staging.join("photo.jpg"), Some(5));
        let pending = new_pending();
        pending.lock().unwrap().push(p.clone());
        let (events, _rx) = event_sink();

        assert!(!transient_should_recover(
            &pending, &p, &events, "timeout", false
        ));
        let (_, first) = note_transient_error(&pending, &p.id).unwrap();
        assert!(!first, "second observation must not log again");
        clear_transient_error(&pending, &p.id);
        assert!(note_transient_error(&pending, &p.id).unwrap().1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unknown_object_recovers_without_grace() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let p = pending_transfer(staging.join("photo.jpg"), Some(5));
        let pending = new_pending();
        pending.lock().unwrap().push(p.clone());
        let (events, _rx) = event_sink();

        assert!(transient_should_recover(
            &pending,
            &p,
            &events,
            "unknown object",
            true
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stale_release_from_previous_registration_is_ignored() {
        let (events, mut rx) = event_sink();
        let handle = ReceiverHandle::new(events);
        let first = handle.begin_registration();
        assert!(handle.mark_active(first));
        assert!(matches!(
            rx.try_recv().unwrap(),
            Event::ReceiverState(ReceiverStatus::Active)
        ));

        // A new registration starts before obexd's late Release for the old
        // object arrives: the stale Release must not turn the receiver off.
        let second = handle.begin_registration();
        assert!(handle.is_active());
        handle.release(first, "stale release");
        assert!(handle.is_active());
        assert!(rx.try_recv().is_err());

        handle.release(second, "released by obexd");
        assert!(!handle.is_active());
        match rx.try_recv().unwrap() {
            Event::ReceiverState(ReceiverStatus::Off(reason)) => {
                assert_eq!(reason, "released by obexd");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn repeated_off_status_is_not_reemitted() {
        let (events, mut rx) = event_sink();
        let handle = ReceiverHandle::new(events);
        handle.mark_lost("bus down");
        assert!(matches!(
            rx.try_recv().unwrap(),
            Event::ReceiverState(ReceiverStatus::Off(reason)) if reason == "bus down"
        ));
        handle.mark_lost("bus down");
        assert!(rx.try_recv().is_err());
        handle.mark_lost("other reason");
        assert!(matches!(
            rx.try_recv().unwrap(),
            Event::ReceiverState(ReceiverStatus::Off(reason)) if reason == "other reason"
        ));
    }

    #[test]
    fn stale_staging_is_recovered_without_overwriting() {
        let dir = temp_dir();
        let root = dir.join("obexd");
        let staging = root.join("kalo-dead");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("photo.jpg"), b"recovered").unwrap();

        let downloads = dir.join("Downloads");
        let recovered_dir = downloads.join("Recovered");
        std::fs::create_dir_all(&recovered_dir).unwrap();
        std::fs::write(recovered_dir.join("photo.jpg"), b"keep").unwrap();

        let (events, _rx) = event_sink();
        let recovered = sweep_stale_staging(
            &root,
            &downloads,
            Duration::ZERO,
            &events,
            &no_encryption(),
            None,
        );

        assert_eq!(recovered, 1);
        assert!(!staging.exists(), "empty staging dir must be removed");
        // The pre-existing file is never replaced.
        assert_eq!(
            std::fs::read(recovered_dir.join("photo.jpg")).unwrap(),
            b"keep"
        );
        assert_eq!(
            std::fs::read(recovered_dir.join("photo_1.jpg")).unwrap(),
            b"recovered"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn staging_sweep_ignores_foreign_and_fresh_dirs() {
        let dir = temp_dir();
        let root = dir.join("obexd");
        let foreign = root.join("blueman-staging");
        let fresh = root.join("kalo-fresh");
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::write(foreign.join("a.bin"), b"x").unwrap();
        std::fs::write(fresh.join("b.bin"), b"y").unwrap();
        let downloads = dir.join("Downloads");
        let (events, _rx) = event_sink();

        // A recent directory may belong to another live receiver.
        assert_eq!(
            sweep_stale_staging(
                &root,
                &downloads,
                Duration::from_secs(3600),
                &events,
                &no_encryption(),
                None,
            ),
            0
        );
        assert!(fresh.join("b.bin").exists());

        // Old enough: only Kalo's own staging is recovered.
        assert_eq!(
            sweep_stale_staging(
                &root,
                &downloads,
                Duration::ZERO,
                &events,
                &no_encryption(),
                None
            ),
            1
        );
        assert!(!fresh.exists());
        assert!(foreign.join("a.bin").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn newest_mtime_considers_writes_to_existing_files() {
        let dir = temp_dir();
        let file = dir.join("part.bin");
        std::fs::write(&file, b"x").unwrap();
        // Writing an existing file does not update the directory mtime.
        std::thread::sleep(Duration::from_millis(10));
        std::fs::write(&file, b"xx").unwrap();

        let file_mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
        assert_eq!(newest_mtime(&dir), Some(file_mtime));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn progress_clock_advances_only_on_change() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let p = pending_transfer(staging.join("photo.jpg"), Some(5));
        let pending = new_pending();
        pending.lock().unwrap().push(p.clone());

        // Backdate the clock instead of sleeping: deterministic and fast.
        {
            let mut list = pending.lock().unwrap();
            let entry = list.iter_mut().find(|e| e.id == p.id).unwrap();
            entry.last_progress_at = Instant::now() - Duration::from_secs(5);
        }

        // No byte change: the idle clock keeps running.
        let unchanged = record_progress(&pending, &p.id, 0);
        assert!(
            unchanged >= Duration::from_secs(5),
            "unchanged counter must not reset the clock, got {unchanged:?}"
        );

        // Byte change: the clock resets to (nearly) zero.
        let after_change = record_progress(&pending, &p.id, 5);
        assert!(
            after_change < Duration::from_secs(1),
            "progress must reset the clock, got {after_change:?}"
        );

        // The counter is still 5, so the fresh clock keeps running.
        let unchanged_again = record_progress(&pending, &p.id, 5);
        assert!(unchanged_again >= after_change);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn status_clock_advances_only_on_change() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let p = pending_transfer(staging.join("photo.jpg"), Some(5));
        let pending = new_pending();
        pending.lock().unwrap().push(p.clone());

        {
            let mut list = pending.lock().unwrap();
            let entry = list.iter_mut().find(|e| e.id == p.id).unwrap();
            entry.status_since = Instant::now() - Duration::from_secs(9);
            entry.last_status = Some("active".into());
        }

        let same = record_status(&pending, &p.id, &TransferStatus::Active);
        assert!(same >= Duration::from_secs(9), "got {same:?}");

        let changed = record_status(&pending, &p.id, &TransferStatus::Queued);
        assert!(changed < Duration::from_secs(1), "got {changed:?}");
        assert_eq!(
            pending.lock().unwrap()[0].last_status.as_deref(),
            Some("queued")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn incoming_stall_policy_is_per_status() {
        let zero = Duration::ZERO;
        assert!(incoming_stall_reason(&TransferStatus::Complete, zero, zero).is_none());
        assert!(incoming_stall_reason(&TransferStatus::Error, zero, zero).is_none());

        assert!(
            incoming_stall_reason(&TransferStatus::Queued, Duration::from_secs(301), zero)
                .is_some()
        );
        assert!(
            incoming_stall_reason(&TransferStatus::Queued, Duration::from_secs(299), zero)
                .is_none()
        );
        assert!(
            incoming_stall_reason(&TransferStatus::Active, zero, Duration::from_secs(1801))
                .is_some()
        );
        assert!(
            incoming_stall_reason(&TransferStatus::Active, zero, Duration::from_secs(1799))
                .is_none()
        );
        assert!(
            incoming_stall_reason(&TransferStatus::Suspended, Duration::from_secs(601), zero)
                .is_some()
        );
        assert!(
            incoming_stall_reason(
                &TransferStatus::Unknown("weird".into()),
                Duration::from_secs(61),
                zero
            )
            .is_some()
        );
        assert!(
            incoming_stall_reason(
                &TransferStatus::Unknown("cancelled".into()),
                Duration::from_secs(61),
                zero
            )
            .is_some()
        );
    }
}
