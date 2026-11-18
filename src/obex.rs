//! OPP client over the session-bus obexd API (`org.bluez.obex`).
//!
//! Outgoing transfer: `Client1.CreateSession(target="opp")` →
//! `ObjectPush1.SendFile` → watch `Transfer1` status/progress.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use tokio::time::MissedTickBehavior;
use zbus::Connection;
use zbus::proxy;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::events::{Event, EventSink, TransferStatus};
use crate::transfer::{Cancel, SendSummary};

/// How often the transfer status is re-read as a safety net: D-Bus
/// property-change signals are not replayed to late subscribers, so the
/// loop must never rely on them alone.
const STATUS_TICK: Duration = Duration::from_secs(2);

/// How long a transfer may sit in each non-terminal state without observable
/// progress before it is considered stalled. These are deliberately
/// conservative; `suspended` is a legitimate state and gets the longest
/// deadline. The user can still cancel explicitly.
const QUEUED_TIMEOUT: Duration = Duration::from_secs(30);
const ACTIVE_STALL_TIMEOUT: Duration = Duration::from_secs(120);
const SUSPENDED_TIMEOUT: Duration = Duration::from_secs(600);
const UNKNOWN_TIMEOUT: Duration = Duration::from_secs(60);
const STATUS_ERROR_LIMIT: u32 = 3;
const CANCEL_TIMEOUT: Duration = Duration::from_secs(2);
/// `CreateSession`/`SendFile` must not leave the UI stuck forever when the
/// device is out of range or obexd is unresponsive.
const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(30);
/// After a cancel request, give an in-flight preflight call a moment to
/// return so the session/transfer object it created can be cleaned up.
const CANCEL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[proxy(
    default_service = "org.bluez.obex",
    default_path = "/org/bluez/obex",
    interface = "org.bluez.obex.Client1"
)]
trait Client {
    fn create_session(
        &self,
        destination: &str,
        args: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<OwnedObjectPath>;
    fn remove_session(&self, session: OwnedObjectPath) -> zbus::Result<()>;
}

#[proxy(
    default_service = "org.bluez.obex",
    interface = "org.bluez.obex.ObjectPush1"
)]
trait ObjectPush {
    fn send_file(
        &self,
        sourcefile: &str,
    ) -> zbus::Result<(OwnedObjectPath, HashMap<String, OwnedValue>)>;
}

#[proxy(
    default_service = "org.bluez.obex",
    interface = "org.bluez.obex.Transfer1"
)]
trait Transfer {
    #[zbus(property)]
    fn status(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn transferred(&self) -> zbus::Result<u64>;
    fn cancel(&self) -> zbus::Result<()>;
}

/// Send one file to `mac` via OPP, streaming progress into `events`.
///
/// `send_id` is echoed in every progress event so the UI can discard progress
/// from a previous or concurrent send. `cancel` is shared by the whole batch;
/// when it fires, the OBEX transfer is cancelled and the session torn down.
pub async fn send(
    mac: &str,
    file: &Path,
    events: &EventSink,
    send_id: u64,
    cancel: &Cancel,
) -> Result<SendSummary> {
    let file = file.canonicalize().context("file not found")?;
    let conn = Connection::session().await?;
    let client = ClientProxy::new(&conn).await?;

    events.send(Event::Log(format!("opening OPP session to {mac}…")));
    let mut args: HashMap<&str, Value<'_>> = HashMap::new();
    args.insert("Target", Value::new("opp"));

    let create = client.create_session(mac, args);
    tokio::pin!(create);
    let session = match preflight_outcome(PREFLIGHT_TIMEOUT, cancel, create.as_mut()).await {
        Preflight::Ready(result) => result
            .context("CreateSession failed (is the device paired, in range and reachable?)")?,
        Preflight::Canceled => {
            // The bus call cannot be interrupted; wait briefly for its reply
            // so a session it creates is removed instead of leaking.
            if let Ok(Ok(session)) =
                tokio::time::timeout(CANCEL_CLEANUP_TIMEOUT, create.as_mut()).await
            {
                let _ = client.remove_session(session).await;
            }
            events.send(Event::Log(
                "send canceled while opening the OPP session".into(),
            ));
            bail!("send canceled");
        }
        Preflight::TimedOut => bail!(
            "CreateSession did not answer within {}s; is the device paired and in range?",
            PREFLIGHT_TIMEOUT.as_secs()
        ),
    };

    // From here on the session must always be torn down, including on
    // early failures (send_file, proxy setup, stream errors).
    let outcome = push_to_session(&conn, &session, &file, events, send_id, cancel).await;
    if let Err(e) = client.remove_session(session).await {
        events.send(Event::Log(format!("remove OPP session failed: {e}")));
    }

    let (bytes, elapsed_secs) = outcome?;
    Ok(SendSummary::new(mac, bytes, elapsed_secs))
}

/// Push the file into an existing OPP session and wait until the transfer
/// reaches a terminal status. Returns `(bytes, elapsed_secs)`.
async fn push_to_session(
    conn: &Connection,
    session: &OwnedObjectPath,
    file: &Path,
    events: &EventSink,
    send_id: u64,
    cancel: &Cancel,
) -> Result<(u64, f64)> {
    let started = Instant::now();
    let push = ObjectPushProxy::builder(conn)
        .path(session.as_str())?
        .build()
        .await?;

    let source = file.to_string_lossy();
    let send_file = push.send_file(source.as_ref());
    tokio::pin!(send_file);
    let (transfer, props) =
        match preflight_outcome(PREFLIGHT_TIMEOUT, cancel, send_file.as_mut()).await {
            Preflight::Ready(result) => result.context("SendFile failed")?,
            Preflight::Canceled => {
                // Cancel a transfer object that appears while we are backing
                // out, so the peer does not keep receiving a canceled file.
                if let Ok(Ok((transfer, _))) =
                    tokio::time::timeout(CANCEL_CLEANUP_TIMEOUT, send_file.as_mut()).await
                    && let Ok(builder) = TransferProxy::builder(conn).path(transfer.as_str())
                    && let Ok(proxy) = builder.build().await
                {
                    let _ = tokio::time::timeout(CANCEL_TIMEOUT, proxy.cancel()).await;
                }
                events.send(Event::Log(
                    "send canceled before the transfer started".into(),
                ));
                bail!("send canceled");
            }
            Preflight::TimedOut => bail!(
                "SendFile did not answer within {}s; is the device paired and in range?",
                PREFLIGHT_TIMEOUT.as_secs()
            ),
        };
    // `Size` is optional in the BlueZ API (absent when unknown). Fall back to
    // the local file size so the UI can still render a meaningful fraction.
    let size = props
        .get("Size")
        .and_then(|v| v.downcast_ref::<u64>().ok())
        .or_else(|| std::fs::metadata(file).ok().map(|m| m.len()));

    let transfer_proxy = TransferProxy::builder(conn)
        .path(transfer.as_str())?
        .build()
        .await?;

    // Property-change signals are not replayed to late subscribers: read the
    // current status once so an already-terminal transfer cannot hang the
    // loop below.
    let mut status = TransferStatus::parse(
        &transfer_proxy
            .status()
            .await
            .context("transfer status unavailable")?,
    );

    let mut status_stream = transfer_proxy.receive_status_changed().await;
    let mut transferred_stream = transfer_proxy.receive_transferred_changed().await;
    let mut status_since = Instant::now();
    let mut last_progress_at = Instant::now();
    let mut last_transferred = 0u64;
    let mut status_errors = 0u32;
    // A re-created `sleep` restarts on every signal and can be starved by a
    // busy status stream; a fixed interval is the reliable watchdog.
    let mut tick = tokio::time::interval(STATUS_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await; // consume the immediate first tick

    while !status.is_terminal() {
        tokio::select! {
            Some(change) = status_stream.next() => {
                match change.get().await {
                    Ok(raw) => {
                        status_errors = 0;
                        let next = TransferStatus::parse(&raw);
                        if next != status {
                            status = next;
                            status_since = Instant::now();
                        }
                        let transferred = transfer_proxy.transferred().await.unwrap_or(last_transferred);
                        if transferred != last_transferred {
                            last_transferred = transferred;
                            last_progress_at = Instant::now();
                        }
                        events.send(Event::SendProgress {
                            send_id,
                            transferred,
                            size,
                            status: status.clone(),
                        });
                    }
                    Err(e) => {
                        events.send(Event::Log(format!("transfer status signal failed: {e}")));
                    }
                }
            }
            Some(change) = transferred_stream.next() => {
                let transferred = match change.get().await {
                    Ok(transferred) => transferred,
                    Err(_) => last_transferred,
                };
                if transferred != last_transferred {
                    last_transferred = transferred;
                    last_progress_at = Instant::now();
                }
                events.send(Event::SendProgress {
                    send_id,
                    transferred,
                    size,
                    status: status.clone(),
                });
            }
            // Safety net for missed property-change signals and a place to
            // enforce the stall watchdog.
            _ = tick.tick() => {
                match transfer_proxy.status().await {
                    Ok(raw) => {
                        status_errors = 0;
                        let next = TransferStatus::parse(&raw);
                        if next != status {
                            status = next;
                            status_since = Instant::now();
                        }
                        let transferred = transfer_proxy
                            .transferred()
                            .await
                            .unwrap_or(last_transferred);
                        if transferred != last_transferred {
                            last_transferred = transferred;
                            last_progress_at = Instant::now();
                        }
                        if status.is_terminal() {
                            events.send(Event::SendProgress {
                                send_id,
                                transferred,
                                size,
                                status: status.clone(),
                            });
                        }
                    }
                    Err(e) => {
                        status_errors += 1;
                        if status_errors >= STATUS_ERROR_LIMIT {
                            bail!("transfer status unavailable after {status_errors} attempts: {e}");
                        }
                        events.send(Event::Log(format!(
                            "transfer status read failed ({status_errors}/{STATUS_ERROR_LIMIT}): {e}"
                        )));
                    }
                }

                if let Some(reason) = stall_reason(
                    &status,
                    status_since.elapsed(),
                    last_progress_at.elapsed(),
                ) {
                    events.send(Event::Log(reason.clone()));
                    bail!(reason);
                }
            }
            _ = cancel.wait() => {
                let _ = tokio::time::timeout(CANCEL_TIMEOUT, transfer_proxy.cancel()).await;
                events.send(Event::Log("send canceled".into()));
                bail!("send canceled");
            }
        }
    }

    let elapsed_secs = started.elapsed().as_secs_f64();
    let transferred = transfer_proxy
        .transferred()
        .await
        .unwrap_or(last_transferred);
    // A completed transfer has sent the whole file. Prefer the known size so
    // a transient final property read cannot report a 0-byte success.
    let bytes = transferred.max(size.unwrap_or(0));
    if status == TransferStatus::Error {
        bail!("transfer failed (status=error)");
    }
    Ok((bytes, elapsed_secs))
}

/// Outcome of a preflight D-Bus call that must observe cancellation and a
/// deadline (SM-02).
enum Preflight<T> {
    Ready(zbus::Result<T>),
    Canceled,
    TimedOut,
}

async fn preflight_outcome<T, F>(
    deadline: Duration,
    cancel: &Cancel,
    call: Pin<&mut F>,
) -> Preflight<T>
where
    F: Future<Output = zbus::Result<T>>,
{
    tokio::select! {
        result = call => Preflight::Ready(result),
        _ = cancel.wait() => Preflight::Canceled,
        _ = tokio::time::sleep(deadline) => Preflight::TimedOut,
    }
}

/// Pure stall policy (unit-tested). `status_since` is the time spent in the
/// current status; `progress_since` is the time since `Transferred` last
/// changed.
fn stall_reason(
    status: &TransferStatus,
    status_since: Duration,
    progress_since: Duration,
) -> Option<String> {
    match status {
        TransferStatus::Complete | TransferStatus::Error => None,
        TransferStatus::Queued if status_since > QUEUED_TIMEOUT => Some(format!(
            "transfer stayed queued for more than {}s",
            QUEUED_TIMEOUT.as_secs()
        )),
        TransferStatus::Active if progress_since > ACTIVE_STALL_TIMEOUT => Some(format!(
            "transfer made no progress for more than {}s",
            ACTIVE_STALL_TIMEOUT.as_secs()
        )),
        TransferStatus::Suspended if status_since > SUSPENDED_TIMEOUT => Some(format!(
            "transfer stayed suspended for more than {}s",
            SUSPENDED_TIMEOUT.as_secs()
        )),
        TransferStatus::Unknown(raw) if status_since > UNKNOWN_TIMEOUT => Some(format!(
            "transfer stuck in unknown status '{raw}' for more than {}s",
            UNKNOWN_TIMEOUT.as_secs()
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::send_progress_line;

    #[test]
    fn terminal_status_values() {
        assert!(TransferStatus::parse("complete").is_terminal());
        assert!(TransferStatus::parse("error").is_terminal());
        for status in ["queued", "active", "suspended", "", "cancelled"] {
            assert!(!TransferStatus::parse(status).is_terminal(), "{status}");
        }
    }

    #[test]
    fn stall_policy_is_conservative() {
        let ok = Duration::from_secs(0);
        assert!(stall_reason(&TransferStatus::Complete, ok, ok).is_none());
        assert!(stall_reason(&TransferStatus::Error, ok, ok).is_none());
        assert!(stall_reason(&TransferStatus::Queued, Duration::from_secs(31), ok).is_some());
        assert!(stall_reason(&TransferStatus::Queued, Duration::from_secs(29), ok).is_none());
        assert!(
            stall_reason(
                &TransferStatus::Active,
                Duration::from_secs(1),
                Duration::from_secs(121)
            )
            .is_some()
        );
        assert!(
            stall_reason(
                &TransferStatus::Active,
                Duration::from_secs(1),
                Duration::from_secs(119)
            )
            .is_none()
        );
        assert!(stall_reason(&TransferStatus::Suspended, Duration::from_secs(601), ok).is_some());
        assert!(
            stall_reason(
                &TransferStatus::Unknown("weird".into()),
                Duration::from_secs(61),
                ok
            )
            .is_some()
        );
    }

    #[test]
    fn summary_line_is_shared_by_ui_and_cli() {
        let summary = SendSummary {
            mac: "AA:BB".into(),
            bytes: 1024,
            elapsed_secs: 2.0,
            mbps: 0.5,
        };
        assert_eq!(
            summary.line(),
            "sent 1024 bytes to AA:BB in 2.0s (0.50 MB/s)"
        );
    }

    #[test]
    fn progress_line_is_shared_by_ui_and_cli() {
        assert_eq!(
            send_progress_line(1, Some(2), &TransferStatus::Active),
            "send active: 1/2 bytes"
        );
    }

    #[tokio::test]
    async fn cancel_interrupts_a_pending_preflight_call() {
        let (cancel_tx, cancel) = Cancel::new();
        let call = std::future::pending::<zbus::Result<()>>();
        tokio::pin!(call);
        cancel_tx.cancel();

        match preflight_outcome(Duration::from_secs(60), &cancel, call.as_mut()).await {
            Preflight::Canceled => {}
            _ => panic!("cancel must win over a pending preflight call"),
        }
    }

    #[tokio::test]
    async fn preflight_calls_have_a_bounded_deadline() {
        let (_handle, cancel) = Cancel::new();
        let call = std::future::pending::<zbus::Result<()>>();
        tokio::pin!(call);

        match preflight_outcome(Duration::from_millis(10), &cancel, call.as_mut()).await {
            Preflight::TimedOut => {}
            _ => panic!("preflight must time out instead of hanging forever"),
        }
    }
}
