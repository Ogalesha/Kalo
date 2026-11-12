//! OPP client over the session-bus obexd API (`org.bluez.obex`).
//!
//! Outgoing transfer: `Client1.CreateSession(target="opp")` →
//! `ObjectPush1.SendFile` → watch `Transfer1` status/progress.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use tokio::sync::mpsc::UnboundedSender;
use zbus::proxy;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::events::Event;

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
    let conn = zbus::Connection::session().await?;
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

    let push = ObjectPushProxy::builder(&conn)
        .path(session.as_str())?
        .build()
        .await?;

    let started = Instant::now();
    let (transfer, props) = push.send_file(file.to_string_lossy().as_ref()).await?;
    let size = props.get("Size").and_then(|v| v.downcast_ref::<u64>().ok());

    let transfer_proxy = TransferProxy::builder(&conn)
        .path(transfer.as_str())?
        .build()
        .await?;
    let mut status_stream = transfer_proxy.receive_status_changed().await;
    let mut transferred_stream = transfer_proxy.receive_transferred_changed().await;

    let status = loop {
        tokio::select! {
            Some(change) = status_stream.next() => {
                let s = change.get().await.unwrap_or_default();
                events
                    .send(Event::SendProgress {
                        transferred: transfer_proxy.transferred().await.unwrap_or(0),
                        size,
                        status: s.clone(),
                    })
                    .ok();
                if s == "complete" || s == "error" {
                    break s;
                }
            }
            Some(change) = transferred_stream.next() => {
                let transferred = change.get().await.unwrap_or(0);
                events
                    .send(Event::SendProgress {
                        transferred,
                        size,
                        status: "active".to_string(),
                    })
                    .ok();
            }
        }
    };

    let elapsed_secs = started.elapsed().as_secs_f64();
    let bytes = transfer_proxy.transferred().await.unwrap_or(0);
    let mbps = if elapsed_secs > 0.0 {
        bytes as f64 / (1024.0 * 1024.0) / elapsed_secs
    } else {
        0.0
    };

    let _ = client.remove_session(session).await;

    if status == "error" {
        anyhow::bail!("transfer failed (status=error)");
    }
    Ok(SendSummary {
        mac: mac.to_string(),
        bytes,
        elapsed_secs,
        mbps,
    })
}
