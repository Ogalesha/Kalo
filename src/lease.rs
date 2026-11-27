//! Linux receive-window lease.
//!
//! obexd accepts exactly one OBEX agent. Blueman's `TransferService` normally
//! owns it, so Kalo cannot register until Blueman yields. This module opens a
//! short, explicit window: it snapshots Blueman's plugin state, asks the applet
//! to unload `TransferService`, lets the receiver register, and restores
//! Blueman when the window closes or expires. Restore writes the user's plugin
//! list back first, then verifies that a running applet really has the plugin
//! loaded again; an unreadable applet keeps the marker for a retry. An empty
//! list relies on Blueman's autoload: it does not unload a plugin that is
//! already loaded, so the exact original list can be restored after the plugin
//! is back.
//!
//! Crash safety is layered. Before Blueman is touched, a guard process is
//! started with its stdin connected to Kalo. If Kalo dies, the pipe closes and
//! the guard restores Blueman. A marker file records the same restore data for
//! the case where both processes die, and is consumed on the next Kalo start.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;
use zbus::Connection;

use crate::blueman;
use crate::events::{Event, EventSink, LeaseStatus};
use crate::paths;
use crate::receiver::ReceiverHandle;
use crate::settings;

/// User-approved duration of one receive window.
pub const RECEIVE_WINDOW: Duration = Duration::from_secs(10 * 60);
/// How long Blueman's plugin unload and Kalo's registration may take.
const ARM_TIMEOUT: Duration = Duration::from_secs(20);
/// Delay before retrying a failed Blueman restore.
const RESTORE_RETRY: Duration = Duration::from_secs(5);
/// How long Blueman may take to load the plugin. The applet can block on
/// BlueZ for a minute or more, so this is deliberately generous.
const RESTORE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long Blueman may take to persist a plugin-list change.
const PLUGIN_LIST_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the plugin must stay loaded before a restore is considered
/// complete.
const RESTORE_SETTLE: Duration = Duration::from_secs(3);
/// How many load/settle/verify rounds a single restore may attempt.
const RESTORE_ATTEMPTS: usize = 2;
/// Poll interval while checking that the plugin stays loaded.
const STABLE_POLL: Duration = Duration::from_millis(200);
const MARKER_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseCommand {
    Arm,
    Release,
}

/// One supervisor decision, produced outside `tokio::select!` so the caller
/// can await the D-Bus handoff without holding other branch borrows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseAction {
    Arm,
    Release { reason: String },
}

#[derive(Clone)]
pub struct LeaseHandle {
    inner: Arc<Mutex<LeaseInner>>,
    tx: mpsc::UnboundedSender<LeaseCommand>,
    events: EventSink,
}

pub struct LeaseControl {
    rx: mpsc::UnboundedReceiver<LeaseCommand>,
    handle: LeaseHandle,
}

struct LeaseInner {
    status: LeaseStatus,
    yielded: Option<Yielded>,
    lock: Option<LeaseLock>,
    /// Why the window never opened. Kept across restore retries so the user
    /// still sees the original cause after a delayed recovery.
    arm_failure: Option<String>,
}

/// The state needed to put Blueman back exactly as it was.
struct Yielded {
    token: String,
    original_plugin_list: String,
    created_unix: u64,
    guard: Option<Guard>,
}

/// The guard is a child process. Closing its stdin without sending `done`
/// means "Kalo died; restore Blueman now".
struct Guard {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl Guard {
    fn finish(mut self) {
        if let Some(mut stdin) = self.stdin.take() {
            let _ = stdin.write_all(b"done\n");
            let _ = stdin.flush();
        }
        let _ = self.child.wait();
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Dropping the pipe is the crash signal. The guard reads the marker and
        // restores Blueman; it never depends on this process still running.
        let _ = self.stdin.take();
    }
}

/// Advisory lock held for the whole receive window. The kernel releases it
/// when the owning process dies, so another Kalo can tell a live window (lock
/// busy) from a stale marker (lock free). Without it, a second instance could
/// "recover" a marker while the first instance is still receiving.
struct LeaseLock {
    _file: fs::File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaseMarker {
    version: u32,
    token: String,
    phase: MarkerPhase,
    original_plugin_list: String,
    created_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MarkerPhase {
    /// The marker exists, but Blueman may not be disabled yet.
    Disabling,
    /// Blueman's plugin was successfully unloaded.
    Disabled,
}

impl LeaseHandle {
    pub fn new(events: EventSink) -> (Self, LeaseControl) {
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = Self {
            inner: Arc::new(Mutex::new(LeaseInner {
                status: LeaseStatus::Idle,
                yielded: None,
                lock: None,
                arm_failure: None,
            })),
            tx,
            events,
        };
        let control = LeaseControl {
            rx,
            handle: handle.clone(),
        };
        (handle, control)
    }

    pub fn status(&self) -> LeaseStatus {
        self.inner.lock().expect("lease lock").status.clone()
    }

    /// Ask the receiver supervisor to open a window. The supervisor owns all
    /// D-Bus work; this method only records the intent and queues a command.
    pub fn request_arm(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().expect("lease lock");
        match inner.status {
            LeaseStatus::Idle | LeaseStatus::Error(_) => {
                inner.arm_failure = None;
                self.set_status_locked(
                    &mut inner,
                    LeaseStatus::Arming {
                        deadline: Instant::now() + ARM_TIMEOUT,
                    },
                );
                drop(inner);
                if self.tx.send(LeaseCommand::Arm).is_err() {
                    self.mark_error("the receiver supervisor is not running");
                    return Err("the receiver supervisor is not running".into());
                }
                Ok(())
            }
            _ => Err("a receive window is already open".into()),
        }
    }

    /// Stop the window after the current transfer, or immediately when idle.
    pub fn request_release(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().expect("lease lock");
        match inner.status {
            LeaseStatus::Arming { .. } | LeaseStatus::Armed { .. } => {
                self.set_status_locked(
                    &mut inner,
                    LeaseStatus::Stopping {
                        reason: "stopped manually".into(),
                    },
                );
                drop(inner);
                if self.tx.send(LeaseCommand::Release).is_err() {
                    self.mark_error("the receiver supervisor is not running");
                    return Err("the receiver supervisor is not running".into());
                }
                Ok(())
            }
            LeaseStatus::Stopping { .. } | LeaseStatus::Restoring { .. } => Ok(()),
            _ => Err("no receive window is open".into()),
        }
    }

    /// The handoff can take most of the arm timeout, so the registration
    /// deadline is refreshed once Blueman has actually yielded. Only the
    /// deadline changes; no redundant UI event is published. Returns false if
    /// the window was cancelled meanwhile.
    pub(crate) fn refresh_arm_deadline(&self, deadline: Instant) -> bool {
        let mut inner = self.inner.lock().expect("lease lock");
        if let LeaseStatus::Arming {
            deadline: current, ..
        } = &mut inner.status
        {
            *current = deadline;
            true
        } else {
            false
        }
    }

    pub(crate) fn mark_armed_if_arming(&self, expires_at: Instant) -> bool {
        let mut inner = self.inner.lock().expect("lease lock");
        if !matches!(inner.status, LeaseStatus::Arming { .. }) {
            return false;
        }
        self.set_status_locked(&mut inner, LeaseStatus::Armed { expires_at });
        true
    }

    /// Record why the window never opened and start closing it. Returns false
    /// when the window was cancelled meanwhile: a user's Stop must win over a
    /// late timeout.
    pub(crate) fn fail_arm(&self, reason: &str) -> bool {
        let mut inner = self.inner.lock().expect("lease lock");
        if !matches!(inner.status, LeaseStatus::Arming { .. }) {
            return false;
        }
        inner.arm_failure = Some(reason.to_string());
        self.set_status_locked(
            &mut inner,
            LeaseStatus::Stopping {
                reason: reason.to_string(),
            },
        );
        true
    }

    /// Remember a failure discovered outside [`fail_arm`] (for example an
    /// error returned by the D-Bus handoff). The next successful `end` turns
    /// it into an error status instead of silently going idle. Returns false
    /// when the user cancelled meanwhile, so a late failure does not replace
    /// their cleaner "stopped" outcome.
    pub(crate) fn mark_arm_failure_if_arming(&self, message: &str) -> bool {
        let mut inner = self.inner.lock().expect("lease lock");
        if !matches!(inner.status, LeaseStatus::Arming { .. }) {
            return false;
        }
        inner.arm_failure = Some(message.to_string());
        true
    }

    fn take_arm_failure(&self) -> Option<String> {
        self.inner.lock().expect("lease lock").arm_failure.take()
    }

    pub(crate) fn mark_stopping(&self, reason: impl Into<String>) {
        let mut inner = self.inner.lock().expect("lease lock");
        self.set_status_locked(
            &mut inner,
            LeaseStatus::Stopping {
                reason: reason.into(),
            },
        );
    }

    pub(crate) fn mark_restoring(&self) {
        let mut inner = self.inner.lock().expect("lease lock");
        let next = LeaseStatus::Restoring {
            retry_at: Instant::now() + RESTORE_RETRY,
        };
        if matches!(inner.status, LeaseStatus::Restoring { .. }) {
            // Keep resetting the retry timer without spamming the log.
            inner.status = next;
        } else {
            self.set_status_locked(&mut inner, next);
        }
    }

    pub(crate) fn mark_idle(&self) {
        let mut inner = self.inner.lock().expect("lease lock");
        inner.arm_failure = None;
        inner.lock = None;
        self.set_status_locked(&mut inner, LeaseStatus::Idle);
    }

    /// True while the window is being closed and Blueman is getting its slot
    /// back. Kalo's periodic registration must stay parked meanwhile: winning
    /// the slot during the restore would leave Blueman's loaded plugin
    /// agentless.
    pub(crate) fn is_closing(&self) -> bool {
        matches!(
            self.status(),
            LeaseStatus::Stopping { .. } | LeaseStatus::Restoring { .. }
        )
    }

    pub(crate) fn mark_error(&self, message: impl Into<String>) {
        let mut inner = self.inner.lock().expect("lease lock");
        inner.arm_failure = None;
        inner.lock = None;
        self.set_status_locked(&mut inner, LeaseStatus::Error(message.into()));
    }

    fn set_status_locked(&self, inner: &mut LeaseInner, next: LeaseStatus) {
        if inner.status == next {
            return;
        }
        inner.status = next.clone();
        self.events.send(Event::LeaseState(next));
    }

    fn has_yielded(&self) -> bool {
        self.inner.lock().expect("lease lock").yielded.is_some()
    }

    /// Take the cross-process window lock. Busy means another live Kalo owns
    /// the receive window, so this one must not touch Blueman or the marker.
    fn acquire_window_lock(&self) -> Result<()> {
        let lock = acquire_lease_lock()?
            .ok_or_else(|| anyhow!("another Kalo window is already using the receive slot"))?;
        self.inner.lock().expect("lease lock").lock = Some(lock);
        Ok(())
    }

    /// Record the exact Blueman state before the plugin is unloaded. The
    /// marker is written first, so a crash at any later point is recoverable.
    fn install_yielded(&self, yielded: Yielded) -> Result<()> {
        let marker = LeaseMarker {
            version: MARKER_VERSION,
            token: yielded.token.clone(),
            phase: MarkerPhase::Disabling,
            original_plugin_list: yielded.original_plugin_list.clone(),
            created_unix: yielded.created_unix,
        };
        write_marker_at(&marker_path(), &marker)
            .context("write the receive-window recovery marker")?;
        self.inner.lock().expect("lease lock").yielded = Some(yielded);
        Ok(())
    }

    fn attach_guard(&self, guard: Guard) {
        let mut inner = self.inner.lock().expect("lease lock");
        if let Some(yielded) = inner.yielded.as_mut() {
            yielded.guard = Some(guard);
        }
    }

    /// Update the marker after Blueman actually unloaded the plugin. Failure
    /// is not fatal: the existing `Disabling` marker already carries the
    /// original state and is sufficient for recovery.
    fn mark_marker_disabled(&self) -> Result<()> {
        let marker = {
            let inner = self.inner.lock().expect("lease lock");
            let Some(yielded) = inner.yielded.as_ref() else {
                bail!("no Blueman state was recorded");
            };
            LeaseMarker {
                version: MARKER_VERSION,
                token: yielded.token.clone(),
                phase: MarkerPhase::Disabled,
                original_plugin_list: yielded.original_plugin_list.clone(),
                created_unix: yielded.created_unix,
            }
        };
        write_marker_at(&marker_path(), &marker).context("update the receive-window marker")
    }

    /// Recovery data for the current yield, usable even if the marker file was
    /// removed externally.
    fn yielded_marker(&self) -> Option<LeaseMarker> {
        self.inner
            .lock()
            .expect("lease lock")
            .yielded
            .as_ref()
            .map(|yielded| LeaseMarker {
                version: MARKER_VERSION,
                token: yielded.token.clone(),
                phase: MarkerPhase::Disabled,
                original_plugin_list: yielded.original_plugin_list.clone(),
                created_unix: yielded.created_unix,
            })
    }

    /// Blueman is back; stop the guard and forget the saved state.
    fn complete_yielded(&self) {
        let yielded = {
            let mut inner = self.inner.lock().expect("lease lock");
            inner.yielded.take()
        };
        if let Some(yielded) = yielded {
            let _ = remove_marker_if_token(&yielded.token);
            if let Some(guard) = yielded.guard {
                guard.finish();
            }
        }
    }
}

impl LeaseControl {
    /// Cancel-safe command receive used by the receiver supervisor's select.
    pub async fn recv(&mut self) -> Option<LeaseCommand> {
        self.rx.recv().await
    }

    pub fn handle(&self) -> &LeaseHandle {
        &self.handle
    }
}

/// Advance the lease state machine. Returns a command to process outside the
/// `select!` loop, where awaiting D-Bus is safe.
pub fn tick(
    lease: &LeaseHandle,
    receiver: &ReceiverHandle,
    pending_empty: bool,
    now: Instant,
) -> Option<LeaseAction> {
    match lease.status() {
        LeaseStatus::Arming { deadline } => {
            if receiver.is_active() {
                // If the user pressed Stop meanwhile the state is no longer
                // Arming and this is a no-op.
                lease.mark_armed_if_arming(now + RECEIVE_WINDOW);
                None
            } else if now >= deadline {
                let reason = "the receiver did not start in time";
                lease.fail_arm(reason).then(|| LeaseAction::Release {
                    reason: reason.into(),
                })
            } else {
                None
            }
        }
        LeaseStatus::Armed { expires_at } if now >= expires_at => {
            let reason = "the 10-minute receive window expired";
            lease.mark_stopping(reason);
            pending_empty.then(|| LeaseAction::Release {
                reason: reason.into(),
            })
        }
        LeaseStatus::Stopping { reason } if pending_empty => Some(LeaseAction::Release { reason }),
        LeaseStatus::Restoring { retry_at } if now >= retry_at => Some(LeaseAction::Release {
            reason: "retrying to restore Blueman".into(),
        }),
        // The window failed, but Kalo later took the slot anyway (for example
        // after Blueman quit). The stale error must not block the normal UI.
        LeaseStatus::Error(_) if receiver.is_active() => {
            lease.mark_idle();
            None
        }
        _ => None,
    }
}

/// Snapshot Blueman's state, unload its transfer plugin, and wake the receiver
/// so it can claim the agent slot. Must not be called while a previous marker
/// is still pending; the caller recovers it first.
pub async fn begin(
    conn: &Connection,
    lease: &LeaseHandle,
    receiver: &ReceiverHandle,
    events: &EventSink,
) -> Result<()> {
    // One live window per user session. The lock is released by `end` (or by
    // the kernel if this process dies).
    lease.acquire_window_lock()?;
    if lease.has_yielded() && !marker_exists()? {
        // The marker disappeared while this process still knows Blueman is
        // paused. Re-create it so recovery has the same source of truth.
        lease.mark_marker_disabled()?;
    }
    if lease.has_yielded() || marker_exists()? {
        recover_stale_marker_locked(events).await?;
        lease.complete_yielded();
    }

    if receiver.is_active() {
        lease.mark_armed_if_arming(Instant::now() + RECEIVE_WINDOW);
        return Ok(());
    }

    match blueman::transfer_service_loaded(conn).await {
        Ok(Some(true)) => {
            let original = blueman::plugin_list_snapshot()
                .context("snapshot Blueman's plugin list before pausing it")?;
            let token = Uuid::new_v4().simple().to_string();
            lease.install_yielded(Yielded {
                token: token.clone(),
                original_plugin_list: original,
                created_unix: unix_now(),
                guard: None,
            })?;
            // The marker is in place before the guard starts, so a crash in
            // either order still leaves a recoverable state.
            match spawn_guard(&token) {
                Ok(guard) => lease.attach_guard(guard),
                Err(error) => {
                    events.send(Event::Log(format!(
                        "receive-window guard unavailable ({error:#}); a crash will be \
                         recovered on the next Kalo start"
                    )));
                }
            }

            if let Err(error) = async {
                blueman::set_transfer_service(conn, false).await?;
                blueman::wait_for_transfer_service(conn, false, ARM_TIMEOUT).await?;
                // Do not open the window while Blueman still has a queued
                // disable write; it could land after the restore.
                blueman::wait_for_transfer_list_disabled(PLUGIN_LIST_TIMEOUT).await
            }
            .await
            {
                let restore = restore_after_failed_arm(conn, lease, events).await;
                return Err(match restore {
                    Ok(()) => error,
                    Err(restore_error) => {
                        anyhow!("{error:#}; restoring Blueman also failed: {restore_error:#}")
                    }
                });
            }

            if let Err(error) = lease.mark_marker_disabled() {
                events.send(Event::Log(format!(
                    "warning: could not update the receive-window marker: {error:#}"
                )));
            }
            events.send(Event::Log(
                "Blueman paused; Kalo is taking over incoming transfers.".into(),
            ));
        }
        Ok(Some(false)) => {
            events.send(Event::Log(
                "Blueman's transfer service is already paused.".into(),
            ));
        }
        Ok(None) => {
            events.send(Event::Log(
                "Blueman is not running; trying to claim the OBEX slot directly.".into(),
            ));
        }
        Err(error) => {
            events.send(Event::Log(format!(
                "Could not inspect Blueman; trying to claim the OBEX slot directly: {error:#}"
            )));
        }
    }

    // The handoff may have consumed most of the original arm timeout. If the
    // user cancelled meanwhile, `end` owns the cleanup instead.
    lease.refresh_arm_deadline(Instant::now() + ARM_TIMEOUT);
    receiver.wake();
    Ok(())
}

/// Unregister Kalo's agent first, then give Blueman its plugin back. The
/// marker and guard are kept if the restore fails, so retrying is safe.
pub async fn end(
    conn: &Connection,
    lease: &LeaseHandle,
    receiver: &ReceiverHandle,
    registration: &mut Option<crate::agent::Registration>,
    events: &EventSink,
    reason: &str,
) -> Result<()> {
    let marker = lease.yielded_marker();
    if marker.is_some() {
        lease.mark_restoring();
    }

    if let Some(registration) = registration.take() {
        crate::agent::release_registration(conn, &registration, receiver, reason).await;
    } else if receiver.is_active() {
        receiver.mark_lost(reason);
    }

    if let Some(marker) = marker {
        restore_marker(&marker, Some(conn), events).await?;
        lease.complete_yielded();
        events.send(Event::Log("Blueman's transfer service restored.".into()));
    }

    // A failed arm must not look like a clean close once restore succeeds.
    if let Some(message) = lease.take_arm_failure() {
        lease.mark_error(message);
    } else {
        lease.mark_idle();
    }
    Ok(())
}

async fn restore_after_failed_arm(
    conn: &Connection,
    lease: &LeaseHandle,
    events: &EventSink,
) -> Result<()> {
    let Some(marker) = lease.yielded_marker() else {
        return Ok(());
    };
    restore_marker(&marker, Some(conn), events).await?;
    lease.complete_yielded();
    Ok(())
}

/// Restore a marker left by a crash. Idempotent and safe to run at startup.
/// A busy lock means another live Kalo owns the window, so its marker is left
/// alone. Returns true when a marker was actually restored.
pub async fn recover_stale_marker(events: &EventSink) -> Result<bool> {
    let Some(_lock) = acquire_lease_lock()? else {
        return Ok(false);
    };
    recover_stale_marker_locked(events).await
}

/// Like [`recover_stale_marker`], but the caller already holds the window
/// lock (used by `begin`).
async fn recover_stale_marker_locked(events: &EventSink) -> Result<bool> {
    let Some(marker) = read_marker_at(&marker_path())? else {
        return Ok(false);
    };
    events.send(Event::Log(format!(
        "found a receive-window marker from {} ago; restoring Blueman",
        age_label(marker.created_unix)
    )));
    let conn = Connection::session().await.ok();
    restore_marker(&marker, conn.as_ref(), events).await?;
    remove_marker_if_token(&marker.token)?;
    events.send(Event::Log(
        "Blueman's transfer service restored after an interrupted receive window.".into(),
    ));
    Ok(true)
}

/// Runtime state of the Blueman applet as observed during a restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreApplet {
    Running,
    Absent,
    Unknown,
}

/// What a restore must do after the user's plugin list is written back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestorePlan {
    /// The list alone describes the desired state: it explicitly disables the
    /// plugin, or there is no applet to talk to (Blueman's autoload will apply
    /// the list when it next starts).
    RestoreOnly,
    /// The list does not disable the plugin, so a running applet must be asked
    /// to load it again. After the plugin is back, the user's exact list is
    /// restored; an empty list does not unload an already-loaded plugin.
    EnsureLoaded,
    /// The applet state could not be read. Keep the marker and retry instead
    /// of silently leaving the plugin unloaded.
    Retry,
}

fn restore_plan(original_plugin_list: &str, applet: RestoreApplet) -> RestorePlan {
    if blueman::list_disables_transfer(original_plugin_list) {
        return RestorePlan::RestoreOnly;
    }
    match applet {
        RestoreApplet::Running => RestorePlan::EnsureLoaded,
        RestoreApplet::Absent => RestorePlan::RestoreOnly,
        RestoreApplet::Unknown => RestorePlan::Retry,
    }
}

/// True when the plugin stayed loaded for the whole `duration`. `None` (the
/// applet went away) is treated as stable: Blueman's autoload applies the
/// restored list when it next starts.
async fn wait_for_stable_transfer_service(conn: &Connection, duration: Duration) -> Result<bool> {
    let deadline = Instant::now() + duration;
    loop {
        match blueman::transfer_service_loaded(conn).await? {
            Some(true) | None => {}
            Some(false) => return Ok(false),
        }
        if Instant::now() >= deadline {
            return Ok(true);
        }
        tokio::time::sleep(STABLE_POLL).await;
    }
}

async fn restore_marker(
    marker: &LeaseMarker,
    conn: Option<&Connection>,
    events: &EventSink,
) -> Result<()> {
    let explicit_disable = blueman::list_disables_transfer(&marker.original_plugin_list);

    // Put the user's persisted list back first. An empty list is the normal
    // "no overrides" value and relies on Blueman's autoload; it does not
    // unload a plugin that is already loaded. An explicit `!TransferService`
    // entry does unload it, which is the state the user asked for.
    blueman::restore_plugin_list(&marker.original_plugin_list)?;

    if explicit_disable {
        return Ok(());
    }

    let applet = match conn {
        Some(conn) => match blueman::transfer_service_loaded(conn).await {
            Ok(Some(_)) => RestoreApplet::Running,
            Ok(None) => RestoreApplet::Absent,
            Err(error) => {
                events.send(Event::Log(format!(
                    "warning: could not inspect Blueman while restoring it: {error:#}"
                )));
                RestoreApplet::Unknown
            }
        },
        None => RestoreApplet::Unknown,
    };

    match restore_plan(&marker.original_plugin_list, applet) {
        RestorePlan::RestoreOnly => Ok(()),
        RestorePlan::Retry => bail!(
            "could not determine whether Blueman's transfer service needs restoring; \
             keeping the recovery marker for a retry"
        ),
        RestorePlan::EnsureLoaded => {
            let conn = conn.context("no session-bus connection to restore Blueman")?;
            for attempt in 0..RESTORE_ATTEMPTS {
                blueman::set_transfer_service(conn, true).await?;
                // Make sure the queued handoff write has been superseded in
                // GSettings before trusting the plugin's loaded state. A slow
                // applet is not fatal here: the load wait below and the final
                // verification still decide the outcome.
                if let Err(error) =
                    blueman::wait_for_transfer_list_enabled(PLUGIN_LIST_TIMEOUT).await
                {
                    events.send(Event::Log(format!(
                        "warning: Blueman's plugin list did not settle in time: {error:#}"
                    )));
                }
                blueman::wait_for_transfer_service(conn, true, RESTORE_TIMEOUT).await?;
                // Put the user's exact list back. An empty list means "no
                // overrides" and does not unload the plugin that is already
                // loaded, so this leaves no explicit entry behind.
                blueman::restore_plugin_list(&marker.original_plugin_list)?;
                // Blueman applies GSettings changes asynchronously. Keep
                // checking for a whole settle window so a late write cannot
                // undo the restore after it has already returned.
                if wait_for_stable_transfer_service(conn, RESTORE_SETTLE).await? {
                    return Ok(());
                }
                if attempt + 1 < RESTORE_ATTEMPTS {
                    events.send(Event::Log(
                        "Blueman unloaded its transfer service during restore; retrying".into(),
                    ));
                }
            }
            bail!(
                "Blueman kept unloading its transfer service while it was being restored; \
                 keeping the recovery marker for a retry"
            )
        }
    }
}

/// Hidden `kalo lease-guard` subcommand. Reads one line from Kalo: `done`
/// means the parent already restored Blueman; EOF or anything else means the
/// parent died while the window was open.
pub async fn guard(token: &str) -> Result<()> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read the lease-guard pipe")?;
    if line.trim() == "done" {
        return Ok(());
    }

    let events = EventSink::new(16);
    let mut last_error = None;
    for attempt in 0..6 {
        // Re-read every attempt: a newer Kalo may have replaced the marker
        // with a different receive window while this guard was waiting.
        let Some(marker) = read_marker_at(&marker_path())? else {
            return Ok(());
        };
        if marker.token != token {
            return Ok(());
        }
        // Serialize with a new Kalo that may be recovering the same marker.
        let Some(_lock) = acquire_lease_lock()? else {
            if attempt < 5 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            return Ok(());
        };
        let conn = Connection::session().await.ok();
        match restore_marker(&marker, conn.as_ref(), &events).await {
            Ok(()) => {
                remove_marker_if_token(&marker.token)?;
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
        if attempt < 5 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("could not restore Blueman")))
}

fn spawn_guard(token: &str) -> Result<Guard> {
    let exe = std::env::current_exe().context("locate the Kalo executable")?;
    let mut child = Command::new(exe)
        .arg("lease-guard")
        .arg("--token")
        .arg(token)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start the receive-window guard")?;
    let stdin = child.stdin.take();
    Ok(Guard { child, stdin })
}

fn lease_lock_path() -> PathBuf {
    paths::config_dir().join("receive-lease.lock")
}

/// Open and non-blockingly lock the window file. `Ok(None)` means another
/// process owns the lock.
fn acquire_lease_lock() -> Result<Option<LeaseLock>> {
    acquire_lease_lock_at(&lease_lock_path())
}

fn acquire_lease_lock_at(path: &Path) -> Result<Option<LeaseLock>> {
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    crate::security::create_private_dir(parent)
        .with_context(|| format!("create config directory {}", parent.display()))?;

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    crate::security::restrict_file_permissions(path)?;
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Some(LeaseLock { _file: file })),
        Err(error)
            if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN =>
        {
            Ok(None)
        }
        Err(error) => Err(error).context("lock the receive-window state"),
    }
}

fn marker_path() -> std::path::PathBuf {
    paths::config_dir().join("receive-lease.json")
}

fn marker_exists() -> Result<bool> {
    match fs::metadata(marker_path()) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect the receive-window marker"),
    }
}

fn read_marker_at(path: &Path) -> Result<Option<LeaseMarker>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read the receive-window marker"),
    };
    let marker: LeaseMarker =
        serde_json::from_slice(&bytes).context("parse the receive-window marker")?;
    if marker.version != MARKER_VERSION {
        bail!(
            "unsupported receive-window marker version {} (expected {MARKER_VERSION})",
            marker.version
        );
    }
    Ok(Some(marker))
}

fn write_marker_at(path: &Path, marker: &LeaseMarker) -> Result<()> {
    settings::write_json(path, marker)
}

fn remove_marker_at(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove the receive-window marker"),
    }
}

/// Remove the marker only when it still belongs to `token`. This keeps a
/// late guard from deleting a newer receive window's recovery data.
fn remove_marker_if_token(token: &str) -> Result<()> {
    remove_marker_if_token_at(&marker_path(), token)
}

fn remove_marker_if_token_at(path: &Path, token: &str) -> Result<()> {
    match read_marker_at(path)? {
        Some(marker) if marker.token == token => remove_marker_at(path),
        _ => Ok(()),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn age_label(created_unix: u64) -> String {
    let now = unix_now();
    let seconds = now.saturating_sub(created_unix);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else {
        format!("{}h", seconds / 3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("kalo-lease-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn marker_round_trips_with_the_original_plugin_list() {
        let dir = temp_dir();
        let path = dir.join("receive-lease.json");
        let marker = LeaseMarker {
            version: MARKER_VERSION,
            token: "abc".into(),
            phase: MarkerPhase::Disabled,
            original_plugin_list: "@as []".into(),
            created_unix: 123,
        };
        write_marker_at(&path, &marker).unwrap();
        let loaded = read_marker_at(&path).unwrap().unwrap();
        assert_eq!(loaded.token, "abc");
        assert_eq!(loaded.phase, MarkerPhase::Disabled);
        assert_eq!(loaded.original_plugin_list, "@as []");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn arming_moves_to_armed_only_while_arming() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events);
        assert_eq!(lease.status(), LeaseStatus::Idle);
        lease.request_arm().unwrap();
        assert!(matches!(lease.status(), LeaseStatus::Arming { .. }));
        let expires = Instant::now() + RECEIVE_WINDOW;
        assert!(lease.mark_armed_if_arming(expires));
        assert_eq!(
            lease.status(),
            LeaseStatus::Armed {
                expires_at: expires
            }
        );
    }

    #[test]
    fn release_request_waits_for_an_open_window() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events);
        lease.request_arm().unwrap();
        lease.request_release().unwrap();
        assert!(matches!(lease.status(), LeaseStatus::Stopping { .. }));
    }

    #[test]
    fn idle_lease_publishes_nothing_when_released() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events);
        assert!(lease.request_release().is_err());
        assert_eq!(lease.status(), LeaseStatus::Idle);
    }

    #[test]
    fn tick_closes_an_expired_window_only_when_idle() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events.clone());
        let receiver = ReceiverHandle::new(events);
        lease.request_arm().unwrap();
        let now = Instant::now();
        assert!(lease.mark_armed_if_arming(now - Duration::from_secs(1)));
        assert!(tick(&lease, &receiver, false, now).is_none());
        assert!(matches!(lease.status(), LeaseStatus::Stopping { .. }));
        assert!(matches!(
            tick(&lease, &receiver, true, now),
            Some(LeaseAction::Release { .. })
        ));
    }

    #[test]
    fn tick_arms_when_the_receiver_becomes_active() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events.clone());
        let receiver = ReceiverHandle::new(events);
        lease.request_arm().unwrap();
        let registration = receiver.begin_registration();
        receiver.mark_active(registration);
        assert!(tick(&lease, &receiver, true, Instant::now()).is_none());
        assert!(matches!(lease.status(), LeaseStatus::Armed { .. }));
    }

    #[test]
    fn cancelling_while_arming_beats_a_late_activation() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events.clone());
        let receiver = ReceiverHandle::new(events);
        lease.request_arm().unwrap();
        lease.request_release().unwrap();
        let registration = receiver.begin_registration();
        receiver.mark_active(registration);
        assert!(!lease.mark_armed_if_arming(Instant::now() + RECEIVE_WINDOW));
        assert!(matches!(lease.status(), LeaseStatus::Stopping { .. }));
    }

    #[test]
    fn cancelling_while_arming_beats_a_late_timeout() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events.clone());
        let receiver = ReceiverHandle::new(events);
        lease.request_arm().unwrap();
        let deadline = match lease.status() {
            LeaseStatus::Arming { deadline } => deadline,
            other => panic!("unexpected status {other:?}"),
        };
        lease.request_release().unwrap();
        assert!(tick(&lease, &receiver, true, deadline + Duration::from_secs(1)).is_some());
        assert!(matches!(lease.status(), LeaseStatus::Stopping { .. }));
        assert!(lease.take_arm_failure().is_none());
    }

    #[test]
    fn closing_states_park_the_receiver_until_blueman_is_back() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events);
        assert!(!lease.is_closing());
        lease.request_arm().unwrap();
        assert!(!lease.is_closing());
        lease.request_release().unwrap();
        assert!(lease.is_closing());
        lease.mark_restoring();
        assert!(lease.is_closing());
        lease.mark_idle();
        assert!(!lease.is_closing());
    }

    #[test]
    fn a_late_handoff_failure_does_not_replace_a_user_cancel() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events);
        lease.request_arm().unwrap();
        lease.request_release().unwrap();
        assert!(!lease.mark_arm_failure_if_arming("Blueman would not pause"));
        assert!(lease.take_arm_failure().is_none());
        assert!(matches!(lease.status(), LeaseStatus::Stopping { .. }));
    }

    #[test]
    fn arming_timeout_records_the_failure_for_the_ui() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events.clone());
        let receiver = ReceiverHandle::new(events);
        lease.request_arm().unwrap();
        let deadline = match lease.status() {
            LeaseStatus::Arming { deadline } => deadline,
            other => panic!("unexpected status {other:?}"),
        };
        let action = tick(&lease, &receiver, true, deadline + Duration::from_secs(1));
        assert!(matches!(action, Some(LeaseAction::Release { .. })));
        assert_eq!(
            lease.take_arm_failure().as_deref(),
            Some("the receiver did not start in time")
        );
    }

    #[test]
    fn refreshing_the_deadline_does_not_restart_a_cancelled_window() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events);
        lease.request_arm().unwrap();
        let refreshed = Instant::now() + Duration::from_secs(60);
        assert!(lease.refresh_arm_deadline(refreshed));
        assert_eq!(
            lease.status(),
            LeaseStatus::Arming {
                deadline: refreshed
            }
        );
        lease.request_release().unwrap();
        assert!(!lease.refresh_arm_deadline(Instant::now() + Duration::from_secs(120)));
        assert!(matches!(lease.status(), LeaseStatus::Stopping { .. }));
    }

    #[test]
    fn failed_arm_survives_a_restore_retry() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events);
        lease.request_arm().unwrap();
        assert!(lease.mark_arm_failure_if_arming("the receiver did not start in time"));
        lease.mark_restoring();
        let later = Instant::now() + RESTORE_RETRY + Duration::from_secs(1);
        assert!(matches!(
            tick(&lease, &ReceiverHandle::new(EventSink::new(4)), true, later),
            Some(LeaseAction::Release { .. })
        ));
        assert_eq!(
            lease.take_arm_failure().as_deref(),
            Some("the receiver did not start in time")
        );
    }

    #[test]
    fn a_stale_error_clears_when_the_receiver_is_active_again() {
        let events = EventSink::new(16);
        let (lease, _control) = LeaseHandle::new(events.clone());
        let receiver = ReceiverHandle::new(events);
        lease.mark_error("the handoff failed");
        let registration = receiver.begin_registration();
        receiver.mark_active(registration);
        assert!(tick(&lease, &receiver, true, Instant::now()).is_none());
        assert_eq!(lease.status(), LeaseStatus::Idle);
    }

    #[test]
    fn window_lock_is_exclusive_and_released_on_drop() {
        let dir = temp_dir();
        let path = dir.join("receive-lease.lock");
        let first = acquire_lease_lock_at(&path).unwrap().unwrap();
        assert!(acquire_lease_lock_at(&path).unwrap().is_none());
        drop(first);
        assert!(acquire_lease_lock_at(&path).unwrap().is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn marker_removal_only_accepts_the_matching_token() {
        let dir = temp_dir();
        let path = dir.join("receive-lease.json");
        let marker = LeaseMarker {
            version: MARKER_VERSION,
            token: "ours".into(),
            phase: MarkerPhase::Disabled,
            original_plugin_list: "@as []".into(),
            created_unix: 1,
        };
        write_marker_at(&path, &marker).unwrap();
        remove_marker_if_token_at(&path, "someone-else").unwrap();
        assert!(read_marker_at(&path).unwrap().is_some());
        remove_marker_if_token_at(&path, "ours").unwrap();
        assert!(read_marker_at(&path).unwrap().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unknown_marker_version_is_rejected() {
        let dir = temp_dir();
        let path = dir.join("receive-lease.json");
        let marker = LeaseMarker {
            version: MARKER_VERSION + 1,
            token: "future".into(),
            phase: MarkerPhase::Disabled,
            original_plugin_list: "@as []".into(),
            created_unix: 1,
        };
        write_marker_at(&path, &marker).unwrap();
        assert!(read_marker_at(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_empty_plugin_list_still_requires_loading_the_transfer_service() {
        assert_eq!(
            restore_plan("@as []", RestoreApplet::Running),
            RestorePlan::EnsureLoaded
        );
    }

    #[test]
    fn an_explicit_disable_is_restored_without_loading_the_plugin() {
        assert_eq!(
            restore_plan("['!TransferService']", RestoreApplet::Running),
            RestorePlan::RestoreOnly
        );
        assert_eq!(
            restore_plan("['!TransferService']", RestoreApplet::Unknown),
            RestorePlan::RestoreOnly
        );
    }

    #[test]
    fn an_explicitly_enabled_plugin_is_loaded_when_missing() {
        assert_eq!(
            restore_plan("['TransferService']", RestoreApplet::Running),
            RestorePlan::EnsureLoaded
        );
    }

    #[test]
    fn an_unknown_applet_state_keeps_the_marker_for_a_retry() {
        assert_eq!(
            restore_plan("@as []", RestoreApplet::Unknown),
            RestorePlan::Retry
        );
    }

    #[test]
    fn an_absent_applet_relies_on_autoload() {
        assert_eq!(
            restore_plan("@as []", RestoreApplet::Absent),
            RestorePlan::RestoreOnly
        );
    }
}
