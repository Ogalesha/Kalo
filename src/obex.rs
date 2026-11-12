//! OPP client over the session-bus obexd API (`org.bluez.obex`).
//!
//! Outgoing transfer: `Client1.CreateSession(target="opp")` →
//! `ObjectPush1.SendFile` → watch `Transfer1` status/progress.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::StreamExt;
use tokio::sync::mpsc::UnboundedSender;
use zbus::proxy;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::Connection;

use crate::events::Event;

/// How often the transfer status is re-read as a safety net: D-Bus
/// property-change signals are not replayed to late subscribers, so the
/// loop must never rely on them alone.
const STATUS_TICK: Duration = Duration::from_secs(2);

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
}

/// Summary of a completed outgoing transfer.
#[derive(Debug, Clone)]
pub struct SendSummary {
    pub mac: String,
    pub bytes: u64,
    pub elapsed_secs: f64,
    pub mbps: f64,
}

/// Send one file to `mac` via OPP, streaming progress into `events`.
pub async fn send(mac: &str, file: &Path, events: &UnboundedSender<Event>) -> Result<SendSummary> {
    let file = file.canonicalize().context("file not found")?;
    let conn = Connection::session().await?;
    let client = ClientProxy::new(&conn).await?;

    events
        .send(Event::Log(format!("opening OPP session to {mac}…")))
        .ok();
    let mut args: HashMap<&str, Value<'_>> = HashMap::new();
    args.insert("Target", Value::new("opp"));
    let session = client
        .create_session(mac, args)
        .await
        .context("CreateSession failed (is the device paired, in range and reachable?)")?;

    // From here on the session must always be torn down, including on
    // early failures (send_file, proxy setup, stream errors).
    let outcome = push_to_session(&conn, &session, &file, events).await;
    let _ = client.remove_session(session).await;

    let (bytes, elapsed_secs) = outcome?;
    Ok(SendSummary {
        mac: mac.to_string(),
        bytes,
        elapsed_secs,
        mbps: mbps(bytes, elapsed_secs),
    })
}

/// Push the file into an existing OPP session and wait until the transfer
/// reaches a terminal status. Returns `(bytes, elapsed_secs)`.
async fn push_to_session(
    conn: &Connection,
    session: &OwnedObjectPath,
    file: &Path,
    events: &UnboundedSender<Event>,
) -> Result<(u64, f64)> {
    let started = Instant::now();
    let push = ObjectPushProxy::builder(conn)
        .path(session.as_str())?
        .build()
        .await?;

    let (transfer, props) = push.send_file(file.to_string_lossy().as_ref()).await?;
    let size = props.get("Size").and_then(|v| v.downcast_ref::<u64>().ok());

    let transfer_proxy = TransferProxy::builder(conn)
        .path(transfer.as_str())?
        .build()
        .await?;

    // Property-change signals are not replayed to late subscribers: read the
    // current status once so an already-terminal transfer cannot hang the
    // loop below.
    let mut status = transfer_proxy
        .status()
        .await
        .context("transfer status unavailable")?;

    let mut status_stream = transfer_proxy.receive_status_changed().await;
    let mut transferred_stream = transfer_proxy.receive_transferred_changed().await;

    while !is_terminal(&status) {
        tokio::select! {
            Some(change) = status_stream.next() => {
                status = change.get().await.unwrap_or_default();
                let transferred = transfer_proxy.transferred().await.unwrap_or(0);
                events
                    .send(Event::SendProgress {
                        transferred,
                        size,
                        status: status.clone(),
                    })
                    .ok();
            }
            Some(change) = transferred_stream.next() => {
                let transferred = change.get().await.unwrap_or(0);
                events
                    .send(Event::SendProgress {
                        transferred,
                        size,
                        status: status.clone(),
                    })
                    .ok();
            }
            // Safety net for missed property-change signals: re-read the
            // status periodically so the loop cannot hang forever.
            _ = tokio::time::sleep(STATUS_TICK) => {
                status = transfer_proxy
                    .status()
                    .await
                    .context("transfer object disappeared")?;
            }
        }
    }

    let elapsed_secs = started.elapsed().as_secs_f64();
    let bytes = transfer_proxy.transferred().await.unwrap_or(0);
    if status == "error" {
        anyhow::bail!("transfer failed (status=error)");
    }
    Ok((bytes, elapsed_secs))
}

/// Terminal `org.bluez.obex.Transfer1.Status` values (pure, unit-tested).
fn is_terminal(status: &str) -> bool {
    status == "complete" || status == "error"
}

fn mbps(bytes: u64, elapsed_secs: f64) -> f64 {
    if elapsed_secs > 0.0 {
        bytes as f64 / (1024.0 * 1024.0) / elapsed_secs
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_status_values() {
        assert!(is_terminal("complete"));
        assert!(is_terminal("error"));
        assert!(!is_terminal("queued"));
        assert!(!is_terminal("active"));
        assert!(!is_terminal("suspended"));
        assert!(!is_terminal(""));
    }
}
