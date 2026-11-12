//! OBEX agent: receives incoming OPP pushes into a staging directory under
//! obexd's root, then moves finished files into `~/Downloads`.
//!
//! SPIKE NOTE: authorization is accept-all; the trust store arrives in Phase 1.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;
use zbus::fdo;
use zbus::interface;
use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};
use zbus::Connection;

use crate::events::Event;
use crate::paths;
use crate::sanitize;

pub const AGENT_PATH: &str = "/org/kalo/obex/agent";

/// One in-flight incoming transfer.
#[derive(Debug, Clone)]
pub struct PendingTransfer {
    pub path: String,
    pub staging_dir: PathBuf,
    pub started: Instant,
}

/// Shared registry of in-flight incoming transfers.
pub type PendingTransfers = Arc<Mutex<Vec<PendingTransfer>>>;

pub fn new_pending() -> PendingTransfers {
    Arc::new(Mutex::new(Vec::new()))
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
}

#[interface(name = "org.bluez.obex.Agent1")]
impl AgentService {
    async fn release(&self) {
        let _ = self.tx.send(Event::Log("OBEX agent released by obexd".into()));
    }

    async fn cancel(&self) {
        let _ = self.tx.send(Event::Log("OBEX agent request canceled".into()));
    }

    async fn authorize_push(&self, transfer: OwnedObjectPath) -> fdo::Result<String> {
        match self.authorize(&transfer).await {
            Ok(dest) => Ok(dest.to_string_lossy().into_owned()),
            Err(e) => {
                let _ = self.tx.send(Event::Log(format!("rejected incoming push: {e}")));
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
        let staging_dir = PathBuf::from(&root).join(format!("kalo-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&staging_dir)
            .with_context(|| format!("create staging dir {staging_dir:?}"))?;
        let dest = staging_dir.join(&safe_name);

        self.pending
            .lock()
            .expect("pending lock")
            .push(PendingTransfer {
                path: transfer.to_string(),
                staging_dir: staging_dir.clone(),
                started: Instant::now(),
            });

        let _ = self.tx.send(Event::IncomingStarted {
            sender,
            name: safe_name,
            size,
            path: transfer.to_string(),
        });
        Ok(dest)
    }
}

/// obexd's default root (`-r`), used only if `Session1.Root` cannot be read.
fn obexd_root_fallback() -> String {
    std::env::var("XDG_CACHE_HOME")
        .or_else(|_| std::env::var("HOME").map(|h| format!("{h}/.cache")))
        .unwrap_or_else(|_| "/tmp".into())
}

fn cleanup_staging(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
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
    let mut finished: Vec<String> = Vec::new();

    for p in &list {
        let proxy = match TransferPropsProxy::builder(conn).path(p.path.as_str()) {
            Ok(b) => match b.build().await {
                Ok(t) => t,
                Err(e) => {
                    let _ = tx.send(Event::IncomingFailed {
                        name: p.path.clone(),
                        error: format!("proxy: {e}"),
                    });
                    cleanup_staging(&p.staging_dir);
                    finished.push(p.path.clone());
                    continue;
                }
            },
            Err(e) => {
                let _ = tx.send(Event::IncomingFailed {
                    name: p.path.clone(),
                    error: format!("proxy path: {e}"),
                });
                cleanup_staging(&p.staging_dir);
                finished.push(p.path.clone());
                continue;
            }
        };

        match proxy.status().await {
            Ok(status) => match status.as_str() {
                "complete" => {
                    if let Err(e) = finish_transfer(p, &proxy, downloads, tx).await {
                        let _ = tx.send(Event::IncomingFailed {
                            name: p.path.clone(),
                            error: e.to_string(),
                        });
                    }
                    cleanup_staging(&p.staging_dir);
                    finished.push(p.path.clone());
                }
                "error" => {
                    let _ = tx.send(Event::IncomingFailed {
                        name: p.path.clone(),
                        error: "transfer reported error".into(),
                    });
                    cleanup_staging(&p.staging_dir);
                    finished.push(p.path.clone());
                }
                _ => {
                    let transferred = proxy.transferred().await.ok();
                    let _ = tx.send(Event::IncomingProgress {
                        path: p.path.clone(),
                        transferred,
                    });
                }
            },
            Err(e) => {
                let _ = tx.send(Event::IncomingFailed {
                    name: p.path.clone(),
                    error: format!("status: {e}"),
                });
                cleanup_staging(&p.staging_dir);
                finished.push(p.path.clone());
            }
        }
    }

    if !finished.is_empty() {
        pending
            .lock()
            .expect("pending lock")
            .retain(|x| !finished.contains(&x.path));
    }
}

async fn finish_transfer(
    p: &PendingTransfer,
    t: &TransferPropsProxy<'_>,
    downloads: &Path,
    tx: &UnboundedSender<Event>,
) -> Result<()> {
    let filename = t.filename().await.context("final filename")?;
    let bytes = std::fs::metadata(&filename).map(|m| m.len()).unwrap_or(0);
    let base = Path::new(&filename)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "received-file".into());
    let final_path = sanitize::unique_in_dir(downloads, &sanitize::filename(&base));
    sanitize::move_file(Path::new(&filename), &final_path).context("move into Downloads")?;

    let elapsed_secs = p.started.elapsed().as_secs_f64();
    let mbps = if elapsed_secs > 0.0 {
        bytes as f64 / (1024.0 * 1024.0) / elapsed_secs
    } else {
        0.0
    };
    let _ = tx.send(Event::IncomingDone {
        saved_to: final_path,
        bytes,
        elapsed_secs,
        mbps,
    });
    Ok(())
}

/// Export the agent object and register it with obexd.
pub async fn start(
    conn: &Connection,
    pending: PendingTransfers,
    tx: UnboundedSender<Event>,
) -> Result<()> {
    let service = AgentService {
        conn: conn.clone(),
        pending: pending.clone(),
        tx: tx.clone(),
    };
    conn.object_server()
        .at(AGENT_PATH, service)
        .await
        .context("export OBEX agent object")?;

    let manager = AgentManagerProxy::new(conn).await?;
    match manager.register_agent(opath(AGENT_PATH)?).await {
        Ok(()) => {
            let _ = tx.send(Event::ReceiverState(
                "receiver active — incoming files land in ~/Downloads".into(),
            ));
            Ok(())
        }
        Err(e) => {
            let msg = if format!("{e}").contains("AlreadyExists") {
                "the OBEX agent slot is taken (Blueman TransferService is active?). Disable \
                 Blueman's Transfer plugin or stop blueman-applet, then restart Kalo."
                    .to_string()
            } else {
                format!("OBEX agent registration failed: {e}")
            };
            let _ = tx.send(Event::ReceiverState(format!("receiver OFF — {msg}")));
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
