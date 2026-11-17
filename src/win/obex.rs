//! Outgoing OPP transfer over WinRT RFCOMM, using the native OBEX engine.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use obex_protocol::client::Client;
use obex_protocol::header::Header;
use tokio::sync::oneshot;
use windows::Networking::Sockets::StreamSocket;

use super::rfcomm::RfcommStream;
use super::{ComGuard, format_mac, parse_mac, run_blocking};
use crate::events::{Event, EventSink, TransferStatus};

/// OBEX Object Push service class: `F9EC7BC4-953C-11D2-984E-525400DC9E09`.
const OPP_TARGET: [u8; 16] = [
    0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2, 0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09,
];
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
const CONNECT_STALL_TIMEOUT: Duration = Duration::from_secs(60);
const ACTIVE_STALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(15);

/// Summary of a completed outgoing transfer.
#[derive(Debug, Clone)]
pub struct SendSummary {
    pub mac: String,
    pub bytes: u64,
    pub elapsed_secs: f64,
    pub mbps: f64,
}

impl SendSummary {
    pub fn line(&self) -> String {
        format!(
            "sent {} bytes to {} in {:.1}s ({:.2} MB/s)",
            self.bytes, self.mac, self.elapsed_secs, self.mbps
        )
    }
}

/// Send one file to `mac` via OPP, streaming progress into `events`.
///
/// The WinRT connection is blocking work on a worker thread, while a tiny
/// watcher forwards cancellation by closing the socket so a stalled read or
/// write is interrupted instead of waiting for the OS timeout.
pub async fn send(
    mac: &str,
    file: &Path,
    events: &EventSink,
    send_id: u64,
    cancel: Option<oneshot::Receiver<()>>,
) -> Result<SendSummary> {
    let file = file.canonicalize().context("file not found")?;
    let metadata = std::fs::metadata(&file).context("read the file")?;
    if !metadata.is_file() {
        bail!("not a regular file: {}", file.display());
    }
    let size = metadata.len();
    if size > u32::MAX as u64 {
        bail!("files larger than 4 GB are not supported by OPP");
    }
    let name = file
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "kalo-file".to_string());
    let address = parse_mac(mac)?;
    let target = format_mac(address);

    let canceled = Arc::new(AtomicBool::new(false));
    let socket_slot: Arc<Mutex<Option<StreamSocket>>> = Arc::new(Mutex::new(None));
    if let Some(cancel) = cancel {
        let canceled = canceled.clone();
        let socket_slot = socket_slot.clone();
        tokio::spawn(async move {
            if cancel.await.is_ok() {
                canceled.store(true, Ordering::SeqCst);
                // Closing from this worker still counts as a WinRT call, so
                // make sure the thread has a COM apartment before calling it.
                let _com = ComGuard::new().ok();
                if let Some(socket) = socket_slot.lock().expect("send socket lock").as_ref() {
                    let _ = socket.Close();
                }
            }
        });
    }

    let worker = SendJob {
        address,
        target: target.clone(),
        file,
        name,
        size,
        events: events.clone(),
        send_id,
        canceled,
        socket_slot,
    };
    run_blocking(move || worker.run()).await
}

struct SendJob {
    address: u64,
    target: String,
    file: PathBuf,
    name: String,
    size: u64,
    events: EventSink,
    send_id: u64,
    canceled: Arc<AtomicBool>,
    socket_slot: Arc<Mutex<Option<StreamSocket>>>,
}

impl SendJob {
    fn run(self) -> Result<SendSummary> {
        let _com = ComGuard::new()?;
        let started = Instant::now();
        self.events.send(Event::Log(format!(
            "opening OPP session to {}…",
            self.target
        )));
        self.events.send(Event::SendProgress {
            send_id: self.send_id,
            transferred: 0,
            size: Some(self.size),
            status: TransferStatus::Queued,
        });

        if self.canceled.load(Ordering::SeqCst) {
            bail!("send canceled");
        }
        let stream = RfcommStream::connect(self.address)
            .with_context(|| format!("connect to {} over RFCOMM", self.target))?;
        *self.socket_slot.lock().expect("send socket lock") = Some(stream.socket().clone());
        if self.canceled.load(Ordering::SeqCst) {
            bail!("send canceled");
        }

        let connected = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let transferred = Arc::new(AtomicU64::new(0));
        let last_progress = Arc::new(Mutex::new(Instant::now()));
        spawn_watchdog(
            stream.socket().clone(),
            last_progress.clone(),
            connected.clone(),
            done.clone(),
            self.events.clone(),
        );

        self.events.send(Event::SendProgress {
            send_id: self.send_id,
            transferred: 0,
            size: Some(self.size),
            status: TransferStatus::Active,
        });

        let file = match File::open(&self.file) {
            Ok(file) => file,
            Err(error) => {
                done.store(true, Ordering::SeqCst);
                return Err(error).context("open the file");
            }
        };
        let reader = ProgressReader {
            inner: file,
            size: self.size,
            transferred: transferred.clone(),
            last_progress: last_progress.clone(),
            last_emit: Instant::now(),
            events: self.events.clone(),
            send_id: self.send_id,
            canceled: self.canceled.clone(),
        };

        let mut client = Client::new(stream);
        let outcome = client
            .connect([Header::Target(OPP_TARGET.to_vec())])
            .map_err(|error| anyhow!("OBEX connect failed: {error}"))
            .and_then(|_| {
                connected.store(true, Ordering::SeqCst);
                *last_progress.lock().expect("send progress lock") = Instant::now();
                client
                    .put_from(
                        [
                            Header::Name(self.name.clone()),
                            Header::Length(self.size as u32),
                        ],
                        reader,
                    )
                    .map_err(|error| anyhow!("OBEX put failed: {error}"))
            });
        let _ = client.disconnect();
        done.store(true, Ordering::SeqCst);

        let elapsed_secs = started.elapsed().as_secs_f64();
        match outcome {
            Ok(_) => {
                self.events.send(Event::SendProgress {
                    send_id: self.send_id,
                    transferred: self.size,
                    size: Some(self.size),
                    status: TransferStatus::Complete,
                });
                Ok(SendSummary {
                    mac: self.target,
                    bytes: self.size,
                    elapsed_secs,
                    mbps: mbps(self.size, elapsed_secs),
                })
            }
            Err(error) => {
                let sent = transferred.load(Ordering::SeqCst);
                self.events.send(Event::SendProgress {
                    send_id: self.send_id,
                    transferred: sent,
                    size: Some(self.size),
                    status: TransferStatus::Error,
                });
                Err(error)
            }
        }
    }
}

fn spawn_watchdog(
    socket: StreamSocket,
    last_progress: Arc<Mutex<Instant>>,
    connected: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    events: EventSink,
) {
    std::thread::spawn(move || {
        let _com = ComGuard::new().ok();
        loop {
            std::thread::sleep(WATCHDOG_INTERVAL);
            if done.load(Ordering::SeqCst) {
                return;
            }
            let limit = if connected.load(Ordering::SeqCst) {
                ACTIVE_STALL_TIMEOUT
            } else {
                CONNECT_STALL_TIMEOUT
            };
            let idle = last_progress.lock().expect("send progress lock").elapsed();
            if idle >= limit {
                events.send(Event::Log(format!(
                    "send stalled for more than {}s; closing the connection",
                    limit.as_secs()
                )));
                let _ = socket.Close();
                return;
            }
        }
    });
}

/// File reader that reports progress and observes cancellation.
struct ProgressReader {
    inner: File,
    size: u64,
    transferred: Arc<AtomicU64>,
    last_progress: Arc<Mutex<Instant>>,
    last_emit: Instant,
    events: EventSink,
    send_id: u64,
    canceled: Arc<AtomicBool>,
}

impl Read for ProgressReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.canceled.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "send canceled"));
        }
        let read = self.inner.read(buf)?;
        if read == 0 {
            let sent = self.transferred.load(Ordering::SeqCst);
            if sent < self.size {
                return Err(io::Error::other(format!(
                    "file ended after {sent} of {} bytes",
                    self.size
                )));
            }
            return Ok(0);
        }
        let total = self.transferred.fetch_add(read as u64, Ordering::SeqCst) + read as u64;
        *self.last_progress.lock().expect("send progress lock") = Instant::now();
        if self.last_emit.elapsed() >= PROGRESS_INTERVAL {
            self.last_emit = Instant::now();
            self.events.send(Event::SendProgress {
                send_id: self.send_id,
                transferred: total,
                size: Some(self.size),
                status: TransferStatus::Active,
            });
        }
        Ok(read)
    }
}

fn mbps(bytes: u64, elapsed_secs: f64) -> f64 {
    if elapsed_secs > 0.0 {
        bytes as f64 / (1024.0 * 1024.0) / elapsed_secs
    } else {
        0.0
    }
}
