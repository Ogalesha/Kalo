//! OBEX agent: receives incoming OPP pushes into a staging directory under
//! obexd's root, then moves finished files into `~/Downloads`.
//!
//! SPIKE NOTE: authorization is accept-all; the trust store arrives in Phase 1.

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

use crate::events::{Event, EventSink, ReceiverStatus, TransferStatus};
use crate::paths;
use crate::sanitize;

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
}

/// Shared registry of in-flight incoming transfers.
pub type PendingTransfers = Arc<Mutex<Vec<PendingTransfer>>>;

/// Single source of truth for the OBEX agent slot. Both the D-Bus service and
/// the supervisor read and update it, so the UI never has to reconcile
/// separate "active" flags with status events. Status changes are published
/// while the state lock is held, which keeps a stale `Active` from racing
/// ahead of an immediately following `Release`.
#[derive(Debug, Clone)]
pub struct ReceiverHandle {
    inner: Arc<Mutex<ReceiverInner>>,
    events: EventSink,
}

#[derive(Debug)]
struct ReceiverInner {
    status: ReceiverStatus,
    /// Registration id currently allowed to speak for the receiver.
    current: Option<u64>,
    next: u64,
}

impl ReceiverHandle {
    pub fn new(events: EventSink) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ReceiverInner {
                status: ReceiverStatus::Starting,
                current: None,
                next: 1,
            })),
            events,
        }
    }

    pub fn status(&self) -> ReceiverStatus {
        self.inner.lock().expect("receiver lock").status.clone()
    }

    pub fn is_active(&self) -> bool {
        self.status() == ReceiverStatus::Active
    }

    /// Allocate the id for a registration attempt and make it the only one
    /// whose `Release` is honored.
    fn begin_registration(&self) -> u64 {
        let mut inner = self.inner.lock().expect("receiver lock");
        let id = inner.next;
        inner.next += 1;
        inner.current = Some(id);
        id
    }

    /// Mark a registration active. Returns whether this changed the state.
    /// A registration invalidated by a release/restart in the meantime is
    /// left alone.
    fn mark_active(&self, id: u64) -> bool {
        let mut inner = self.inner.lock().expect("receiver lock");
        if inner.current != Some(id) || inner.status == ReceiverStatus::Active {
            return false;
        }
        self.set_status(&mut inner, ReceiverStatus::Active);
        true
    }

    /// A `Release` for `id`. Stale releases from earlier registrations are
    /// ignored; only the current registration can turn the receiver off.
    fn release(&self, id: u64, reason: &str) {
        let mut inner = self.inner.lock().expect("receiver lock");
        if inner.current != Some(id) {
            return;
        }
        inner.current = None;
        let next = ReceiverStatus::Off(reason.to_string());
        self.set_status(&mut inner, next);
    }

    /// Any reason the current registration is no longer valid (obexd restart,
    /// session-bus failure, registration error).
    fn mark_lost(&self, reason: &str) {
        let mut inner = self.inner.lock().expect("receiver lock");
        inner.current = None;
        let next = ReceiverStatus::Off(reason.to_string());
        self.set_status(&mut inner, next);
    }

    /// Caller holds the state lock, so the published order always matches
    /// the stored state.
    fn set_status(&self, inner: &mut ReceiverInner, next: ReceiverStatus) {
        if inner.status == next {
            return;
        }
        inner.status = next.clone();
        self.events.send(Event::ReceiverState(next));
    }
}

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
    /// SPIKE: accept every push. Trust checks arrive in Phase 1.
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
        let root = session_props
            .root()
            .await
            .unwrap_or_else(|_| obexd_root_fallback());
        let size = t.size().await.ok();

        // Stage inside obexd's root (it may refuse to write outside it).
        let id = Uuid::new_v4().simple().to_string();
        let staging_dir = PathBuf::from(&root).join(format!("kalo-{id}"));
        std::fs::create_dir_all(&staging_dir)
            .with_context(|| format!("create staging dir {staging_dir:?}"))?;
        let dest = staging_dir.join(&safe_name);

        self.pending
            .lock()
            .expect("pending lock")
            .push(PendingTransfer {
                id: id.clone(),
                name: safe_name.clone(),
                sender: sender.clone(),
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
            });

        self.events.send(Event::IncomingStarted {
            id,
            sender,
            name: safe_name,
            size,
        });
        Ok(dest)
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
fn sweep_staging(downloads: &Path, events: &EventSink) {
    let recovered = sweep_stale_staging(&staging_root(), downloads, STAGING_STALE_AGE, events);
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
        recovered += recover_staging_dir(&entry.path(), downloads, events);
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

fn recover_staging_dir(dir: &Path, downloads: &Path, events: &EventSink) -> usize {
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
        if let Err(e) = std::fs::create_dir_all(downloads) {
            events.send(Event::Log(format!(
                "cannot recover staged files into {downloads:?}: {e}"
            )));
            break;
        }
        let name = sanitize::filename(&entry.file_name().to_string_lossy());
        let mut dest = sanitize::unique_in_dir(downloads, &name);
        loop {
            match sanitize::move_file(&entry.path(), &dest) {
                Ok(()) => {
                    recovered += 1;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    dest = sanitize::unique_in_dir(downloads, &name);
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
) {
    if p.dest.exists() {
        events.send(Event::Log(format!(
            "{}: transfer object disappeared; recovering staged file",
            p.dest.display()
        )));
        if let Err(e) = finalize_transfer(p, downloads, events, true) {
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
fn recover_failed_transfer(p: &PendingTransfer, downloads: &Path, events: &EventSink, error: &str) {
    if p.dest.exists() {
        events.send(Event::Log(format!(
            "{}: {error}; keeping the staged partial file",
            p.dest.display()
        )));
        if let Err(e) = finalize_transfer(p, downloads, events, true) {
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
    downloads: &Path,
    events: &EventSink,
) {
    let list = pending.lock().expect("pending lock").clone();
    if list.is_empty() {
        return;
    }
    // Entries are finished by `id`, never by object path (obexd reuses paths).
    let mut finished: Vec<String> = Vec::new();

    for p in &list {
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
                        downloads,
                        events,
                        format!("transfer object unavailable: {e}"),
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
                    downloads,
                    events,
                    format!("transfer object unavailable: {e}"),
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
                    downloads,
                    events,
                    format!("transfer object disappeared before completion: {e}"),
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
                if let Err(e) = finalize_transfer(p, downloads, events, false) {
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
                recover_failed_transfer(p, downloads, events, "transfer reported error");
                finished.push(p.id.clone());
            }
            TransferStatus::Unknown(raw) if raw.eq_ignore_ascii_case("cancelled") => {
                if stale_transfer(&proxy, &p.dest).await {
                    stale_failure(events, p);
                    finished.push(p.id.clone());
                    continue; // keep the staging dir
                }
                recover_failed_transfer(p, downloads, events, "transfer was canceled");
                finished.push(p.id.clone());
            }
            _ => {
                let status_since = record_status(pending, &p.id, &status);
                let transferred = proxy.transferred().await.ok();
                let idle =
                    record_progress(pending, &p.id, transferred.unwrap_or(p.last_transferred));
                if let Some(reason) = incoming_stall_reason(&status, status_since, idle) {
                    handle_object_gone(p, downloads, events, reason);
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
) -> Result<()> {
    finish_transfer(p, downloads, events, interrupted)?;
    cleanup_staging(&p.staging_dir);
    Ok(())
}

fn finish_transfer(
    p: &PendingTransfer,
    downloads: &Path,
    events: &EventSink,
    interrupted: bool,
) -> Result<()> {
    std::fs::create_dir_all(downloads)
        .with_context(|| format!("create Downloads dir {downloads:?}"))?;
    let bytes = std::fs::metadata(&p.dest)
        .with_context(|| format!("read staged file {:?}", p.dest))?
        .len();
    let base = p
        .dest
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "received-file".into());
    let name = sanitize::filename(&base);

    // Retry the numbered name if another writer wins the race between
    // `unique_in_dir` and the no-overwrite move.
    let mut final_path = sanitize::unique_in_dir(downloads, &name);
    loop {
        match sanitize::move_file(&p.dest, &final_path) {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                final_path = sanitize::unique_in_dir(downloads, &name);
            }
            Err(e) => return Err(e).context("move into Downloads"),
        }
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

fn registration_path(id: u64) -> String {
    format!("{AGENT_PATH}/{id}")
}

async fn export_agent(
    conn: &Connection,
    path: &str,
    pending: PendingTransfers,
    events: EventSink,
    handle: ReceiverHandle,
    registration: u64,
) -> Result<()> {
    let service = AgentService {
        conn: conn.clone(),
        pending,
        events,
        handle,
        registration,
    };
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
) -> Result<String> {
    let registration = handle.begin_registration();
    let path = registration_path(registration);

    export_agent(
        conn,
        &path,
        pending,
        events.clone(),
        handle.clone(),
        registration,
    )
    .await?;

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
    downloads: PathBuf,
    events: EventSink,
) -> ! {
    loop {
        match Connection::session().await {
            Ok(conn) => {
                if let Err(e) =
                    receiver_session(&conn, &handle, &pending, &downloads, &events).await
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

async fn receiver_session(
    conn: &Connection,
    handle: &ReceiverHandle,
    pending: &PendingTransfers,
    downloads: &Path,
    events: &EventSink,
) -> Result<()> {
    let mut owner_changes = match obexd_owner_changes(conn).await {
        Ok(changes) => Some(changes),
        Err(e) => {
            events.send(Event::Log(format!("obexd owner watch unavailable: {e}")));
            None
        }
    };

    let mut last_registration_error: Option<String> = None;
    let mut current_path =
        match register_receiver(conn, handle.clone(), pending.clone(), events.clone()).await {
            Ok(path) => {
                sweep_staging(downloads, events);
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
                poll_pending(conn, pending, downloads, events).await;
                if conn.is_closed() {
                    bail!("session bus connection closed");
                }
            }
            _ = retry.tick(), if !handle.is_active() => {
                match register_receiver(conn, handle.clone(), pending.clone(), events.clone()).await {
                    Ok(path) => {
                        if let Some(old) = current_path.replace(path) {
                            let _ = conn
                                .object_server()
                                .remove::<AgentService, _>(old.as_str())
                                .await;
                        }
                        exported = true;
                        last_registration_error = None;
                        sweep_staging(downloads, events);
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
                sweep_staging(downloads, events);
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
    let path = register_receiver(&conn, handle, new_pending(), events.clone()).await?;
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

/// CLI: run the receiver in the foreground (SPIKE: accepts everything).
pub async fn receive() -> Result<()> {
    let events = EventSink::new(1024);
    let mut rx = events.subscribe();
    let handle = ReceiverHandle::new(events.clone());
    let pending = new_pending();
    let downloads = paths::downloads_dir();

    println!("listening… (Ctrl-C to stop)");
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

    run_receiver(handle, pending, downloads, events).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    fn event_sink() -> (EventSink, broadcast::Receiver<Event>) {
        let sink = EventSink::new(64);
        let rx = sink.subscribe();
        (sink, rx)
    }

    fn pending_transfer(dest: PathBuf, size: Option<u64>) -> PendingTransfer {
        let staging_dir = dest.parent().unwrap().to_path_buf();
        PendingTransfer {
            id: "id-1".into(),
            name: "photo.jpg".into(),
            sender: "AA:BB".into(),
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

        assert!(finalize_transfer(&p, &downloads, &events, false).is_err());
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

        finalize_transfer(&p, &downloads, &events, false).unwrap();
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
    fn size_mismatch_is_reported_as_partial() {
        let dir = temp_dir();
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        let dest = staging.join("photo.jpg");
        std::fs::write(&dest, b"hello").unwrap();
        let downloads = dir.join("Downloads");
        let (events, mut rx) = event_sink();
        let p = pending_transfer(dest, Some(10));

        finalize_transfer(&p, &downloads, &events, false).unwrap();
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

        finalize_transfer(&p, &downloads, &events, true).unwrap();
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
        recover_failed_transfer(&p, &downloads, &events, "transfer reported error");

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
        assert!(downloads.join("photo.jpg").exists());
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

        recover_failed_transfer(&p, &downloads, &events, "transfer was canceled");
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
        std::fs::create_dir_all(&downloads).unwrap();
        std::fs::write(downloads.join("photo.jpg"), b"keep").unwrap();

        let (events, _rx) = event_sink();
        let recovered = sweep_stale_staging(&root, &downloads, Duration::ZERO, &events);

        assert_eq!(recovered, 1);
        assert!(!staging.exists(), "empty staging dir must be removed");
        // The pre-existing file is never replaced.
        assert_eq!(std::fs::read(downloads.join("photo.jpg")).unwrap(), b"keep");
        assert_eq!(
            std::fs::read(downloads.join("photo (1).jpg")).unwrap(),
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
            sweep_stale_staging(&root, &downloads, Duration::from_secs(3600), &events),
            0
        );
        assert!(fresh.join("b.bin").exists());

        // Old enough: only Kalo's own staging is recovered.
        assert_eq!(
            sweep_stale_staging(&root, &downloads, Duration::ZERO, &events),
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
