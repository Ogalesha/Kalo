//! OBEX agent: receives incoming OPP pushes into a staging directory under
//! obexd's root, then moves finished files into `~/Downloads`.
//!
//! SPIKE NOTE: authorization is accept-all; the trust store arrives in Phase 1.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;
use zbus::Connection;
use zbus::fdo;
use zbus::interface;
use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::events::{Event, ReceiverStatus, TransferStatus};
use crate::paths;
use crate::sanitize;

pub const AGENT_PATH: &str = "/org/kalo/obex/agent";

/// How long transient D-Bus failures are tolerated before a pending transfer
/// is treated as gone. A real transfer object usually reappears immediately;
/// an obexd restart can take a few seconds.
const TRANSIENT_ERROR_GRACE: Duration = Duration::from_secs(10);
/// Incoming transfers that make no progress for this long are finalized as
/// interrupted (keeping a partial file) instead of waiting forever.
const INCOMING_STALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);

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
}

/// Shared registry of in-flight incoming transfers.
pub type PendingTransfers = Arc<Mutex<Vec<PendingTransfer>>>;

/// Whether the OBEX agent is currently registered with obexd. Shared between
/// the D-Bus service and the UI pump so `Release` can trigger a retry.
pub type ReceiverActive = Arc<AtomicBool>;

pub fn new_pending() -> PendingTransfers {
    Arc::new(Mutex::new(Vec::new()))
}

pub fn new_active() -> ReceiverActive {
    Arc::new(AtomicBool::new(false))
}

/// Apply an obexd `Release`: this process no longer owns the agent slot, so
/// the pump retries registration and reports the receiver as off.
fn mark_released(active: &ReceiverActive, tx: &UnboundedSender<Event>) {
    mark_registration_lost(active, tx, "released by obexd; will retry registration");
}

/// A registration is no longer valid (released, or obexd restarted). The pump
/// retries registration while the receiver is reported off.
pub fn mark_registration_lost(active: &ReceiverActive, tx: &UnboundedSender<Event>, reason: &str) {
    active.store(false, Ordering::Relaxed);
    let _ = tx.send(Event::ReceiverState(ReceiverStatus::Off(
        reason.to_string(),
    )));
}

/// Watch `org.bluez.obex` owner changes on the session bus. obexd restarting
/// silently invalidates our registration, so the pump must treat any change
/// as a lost slot and re-register.
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
    tx: UnboundedSender<Event>,
    active: ReceiverActive,
}

#[interface(name = "org.bluez.obex.Agent1")]
impl AgentService {
    async fn release(&self) {
        mark_released(&self.active, &self.tx);
    }

    async fn cancel(&self) {
        let _ = self
            .tx
            .send(Event::Log("OBEX agent request canceled".into()));
    }

    async fn authorize_push(&self, transfer: OwnedObjectPath) -> fdo::Result<String> {
        match self.authorize(&transfer).await {
            Ok(dest) => Ok(dest.to_string_lossy().into_owned()),
            Err(e) => {
                let _ = self
                    .tx
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
            });

        let _ = self.tx.send(Event::IncomingStarted {
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
/// only discoverable from a live session, so the startup sweep covers the
/// default location only.
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

/// One-shot startup cleanup: recover files staged by a crashed/interrupted
/// Kalo run into Downloads, then remove the now-empty `kalo-*` directories.
///
/// Call only after this process owns the OBEX agent slot, so a live receiver
/// cannot be writing into these directories.
pub fn sweep_stale_staging_once(tx: &UnboundedSender<Event>) {
    static SWEPT: Once = Once::new();
    SWEPT.call_once(|| {
        let recovered = sweep_stale_staging(
            &staging_root(),
            &paths::downloads_dir(),
            STAGING_STALE_AGE,
            tx,
        );
        if recovered > 0 {
            let _ = tx.send(Event::Log(format!(
                "recovered {recovered} file(s) from an interrupted transfer"
            )));
        }
    });
}

/// Recover every regular file from stale `kalo-*` staging dirs, then delete
/// the dir only when nothing is left. Never deletes a file.
fn sweep_stale_staging(
    root: &Path,
    downloads: &Path,
    min_age: Duration,
    tx: &UnboundedSender<Event>,
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
        recovered += recover_staging_dir(&entry.path(), downloads, tx);
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

fn recover_staging_dir(dir: &Path, downloads: &Path, tx: &UnboundedSender<Event>) -> usize {
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
            let _ = tx.send(Event::Log(format!(
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
                    let _ = tx.send(Event::Log(format!(
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
    tx: &UnboundedSender<Event>,
    p: &PendingTransfer,
    error: impl Into<String>,
    staged_at: Option<PathBuf>,
) {
    let _ = tx.send(Event::IncomingFailed {
        id: p.id.clone(),
        sender: p.sender.clone(),
        name: p.name.clone(),
        error: error.into(),
        staged_at,
    });
}

fn stale_failure(tx: &UnboundedSender<Event>, p: &PendingTransfer) {
    fail(
        tx,
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
/// unchanged. This is also the incoming stall clock.
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
    tx: &UnboundedSender<Event>,
    error: &str,
    gone: bool,
) -> bool {
    if gone {
        return true;
    }
    match note_transient_error(pending, &p.id) {
        Some((age, first)) if age < TRANSIENT_ERROR_GRACE => {
            if first {
                let _ = tx.send(Event::Log(format!(
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
    tx: &UnboundedSender<Event>,
    reason: impl Into<String>,
) {
    if p.dest.exists() {
        let _ = tx.send(Event::Log(format!(
            "{}: transfer object disappeared; recovering staged file",
            p.dest.display()
        )));
        if let Err(e) = finalize_transfer(p, downloads, tx, true) {
            fail(
                tx,
                p,
                format!("recover staged file: {e}"),
                Some(p.staging_dir.clone()),
            );
        }
    } else {
        fail(tx, p, reason, None);
        cleanup_staging(&p.staging_dir);
    }
}

/// Poll pending incoming transfers; completion is detected by polling
/// (simple and runtime-agnostic for the spike).
pub async fn poll_pending(
    conn: &Connection,
    pending: &PendingTransfers,
    downloads: &Path,
    tx: &UnboundedSender<Event>,
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
                        tx,
                        &format!("proxy: {e}"),
                        is_object_gone(&e),
                    ) {
                        continue;
                    }
                    handle_object_gone(
                        p,
                        downloads,
                        tx,
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
                    tx,
                    &format!("proxy path: {e}"),
                    is_object_gone(&e),
                ) {
                    continue;
                }
                handle_object_gone(
                    p,
                    downloads,
                    tx,
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
                    tx,
                    &format!("status: {e}"),
                    is_object_gone(&e),
                ) {
                    continue;
                }
                handle_object_gone(
                    p,
                    downloads,
                    tx,
                    format!("transfer object disappeared before completion: {e}"),
                );
                finished.push(p.id.clone());
                continue;
            }
        };

        match status {
            TransferStatus::Complete => {
                if stale_transfer(&proxy, &p.dest).await {
                    stale_failure(tx, p);
                    finished.push(p.id.clone());
                    continue; // keep the staging dir: it may hold the old file
                }
                if let Err(e) = finalize_transfer(p, downloads, tx, false) {
                    // Keep the staged source: a failed move must not destroy
                    // the only copy of the received file.
                    fail(
                        tx,
                        p,
                        format!("save failed: {e}"),
                        Some(p.staging_dir.clone()),
                    );
                }
                finished.push(p.id.clone());
            }
            TransferStatus::Error => {
                if stale_transfer(&proxy, &p.dest).await {
                    stale_failure(tx, p);
                    finished.push(p.id.clone());
                    continue; // keep the staging dir
                }
                fail(tx, p, "transfer reported error", None);
                cleanup_staging(&p.staging_dir);
                finished.push(p.id.clone());
            }
            _ => {
                let transferred = proxy.transferred().await.ok();
                let idle =
                    record_progress(pending, &p.id, transferred.unwrap_or(p.last_transferred));
                if idle > INCOMING_STALL_TIMEOUT {
                    handle_object_gone(
                        p,
                        downloads,
                        tx,
                        format!(
                            "incoming transfer stalled for more than {}s",
                            INCOMING_STALL_TIMEOUT.as_secs()
                        ),
                    );
                    finished.push(p.id.clone());
                    continue;
                }
                let _ = tx.send(Event::IncomingProgress {
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
    tx: &UnboundedSender<Event>,
    interrupted: bool,
) -> Result<()> {
    finish_transfer(p, downloads, tx, interrupted)?;
    cleanup_staging(&p.staging_dir);
    Ok(())
}

fn finish_transfer(
    p: &PendingTransfer,
    downloads: &Path,
    tx: &UnboundedSender<Event>,
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
    let _ = tx.send(Event::IncomingDone {
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

/// Export the agent object on the connection. Kept separate from
/// registration so a failed registration can be retried without re-exporting.
pub async fn export_agent(
    conn: &Connection,
    pending: PendingTransfers,
    tx: UnboundedSender<Event>,
    active: ReceiverActive,
) -> Result<()> {
    let service = AgentService {
        conn: conn.clone(),
        pending,
        tx,
        active,
    };
    conn.object_server()
        .at(AGENT_PATH, service)
        .await
        .context("export OBEX agent object")?;
    Ok(())
}

/// Register the already-exported agent with obexd.
pub async fn register_agent(
    conn: &Connection,
    active: ReceiverActive,
    tx: &UnboundedSender<Event>,
) -> Result<()> {
    let manager = AgentManagerProxy::new(conn).await?;
    manager.register_agent(opath(AGENT_PATH)?).await?;
    active.store(true, Ordering::Relaxed);
    let _ = tx.send(Event::ReceiverState(ReceiverStatus::Active));
    Ok(())
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

/// Export and register the agent (CLI entry point).
pub async fn start(
    conn: &Connection,
    pending: PendingTransfers,
    tx: UnboundedSender<Event>,
) -> Result<()> {
    let active = new_active();
    export_agent(conn, pending, tx.clone(), active.clone()).await?;
    match register_agent(conn, active, &tx).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let msg = registration_error(&e);
            let _ = tx.send(Event::ReceiverState(ReceiverStatus::Off(msg.clone())));
            Err(anyhow!(msg))
        }
    }
}

/// CLI: grab and immediately release the OBEX agent slot (non-destructive).
pub async fn agent_check() -> Result<()> {
    let conn = Connection::session().await?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    start(&conn, new_pending(), tx).await?;
    let manager = AgentManagerProxy::new(&conn).await?;
    manager.unregister_agent(opath(AGENT_PATH)?).await?;
    while let Ok(event) = rx.try_recv() {
        println!("{event:?}");
    }
    println!("agent-check OK: the slot was free and is free again.");
    Ok(())
}

/// CLI: run the receiver in the foreground (SPIKE: accepts everything).
pub async fn receive() -> Result<()> {
    let conn = Connection::session().await?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let pending = new_pending();
    let downloads = paths::downloads_dir();
    start(&conn, pending.clone(), tx.clone()).await?;
    sweep_stale_staging_once(&tx);

    println!("listening… (Ctrl-C to stop)");
    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(event) => println!("{event:?}"),
                    None => break,
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                poll_pending(&conn, &pending, &downloads, &tx).await;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let p = pending_transfer(dest.clone(), Some(5));

        assert!(finalize_transfer(&p, &downloads, &tx, false).is_err());
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
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let p = pending_transfer(dest.clone(), Some(5));

        finalize_transfer(&p, &downloads, &tx, false).unwrap();
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
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let p = pending_transfer(dest, Some(10));

        finalize_transfer(&p, &downloads, &tx, false).unwrap();
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
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let p = pending_transfer(dest, None);

        finalize_transfer(&p, &downloads, &tx, true).unwrap();
        match rx.try_recv().unwrap() {
            Event::IncomingDone { partial, .. } => assert!(partial),
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
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        fail(&tx, &p, "boom", Some(staging.clone()));
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
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        assert!(!transient_should_recover(
            &pending, &p, &tx, "timeout", false
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
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        assert!(transient_should_recover(
            &pending,
            &p,
            &tx,
            "unknown object",
            true
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn release_clears_active_and_reports_receiver_off() {
        let active = new_active();
        active.store(true, Ordering::Relaxed);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        mark_released(&active, &tx);

        assert!(!active.load(Ordering::Relaxed));
        match rx.try_recv().unwrap() {
            Event::ReceiverState(ReceiverStatus::Off(reason)) => {
                assert!(reason.contains("retry"), "reason: {reason}");
            }
            other => panic!("unexpected event: {other:?}"),
        }
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

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let recovered = sweep_stale_staging(&root, &downloads, Duration::ZERO, &tx);

        assert_eq!(recovered, 1);
        assert!(!staging.exists(), "empty staging dir must be removed");
        // C1: the pre-existing file is never replaced.
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
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        // A recent directory may belong to another live receiver.
        assert_eq!(
            sweep_stale_staging(&root, &downloads, Duration::from_secs(3600), &tx),
            0
        );
        assert!(fresh.join("b.bin").exists());

        // Old enough: only Kalo's own staging is recovered.
        assert_eq!(
            sweep_stale_staging(&root, &downloads, Duration::ZERO, &tx),
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
}
