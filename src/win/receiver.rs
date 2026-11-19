//! Incoming OPP receiver: advertise the Windows OBEX Object Push service and
//! stream pushes into a staging directory before moving them to the save
//! folder. New senders are approved in the desktop UI or rejected.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use obex_protocol::Error as ObexError;
use obex_protocol::header::Header;
use obex_protocol::opcode::Opcode;
use obex_protocol::packet::{ConnectParameters, Response};
use obex_protocol::response::ResponseCode;
use obex_protocol::transport::PacketStream;
use uuid::Uuid;
use windows::Devices::Bluetooth::BluetoothDevice;
use windows::Devices::Bluetooth::Rfcomm::{RfcommServiceId, RfcommServiceProvider};
use windows::Foundation::TypedEventHandler;
use windows::Networking::HostName;
use windows::Networking::Sockets::{
    StreamSocket, StreamSocketListener, StreamSocketListenerConnectionReceivedEventArgs,
};

use super::rfcomm::RfcommStream;
use super::{ComGuard, format_mac, hstring, run_blocking};
use crate::crypto::{self, Encryption};
use crate::events::{Event, EventSink};
use crate::receiver::ReceiverHandle;
use crate::sanitize;
use crate::security;
use crate::settings::{SaveDir, Settings};
use crate::trust::{Authorizer, TrustStore};

/// The Windows backend has no shared transfer registry; the UI follows the
/// event stream. A non-unit marker keeps the platform facade signature
/// identical without pretending there is state to share.
#[derive(Debug, Clone)]
pub struct PendingTransfers;

pub fn new_pending() -> PendingTransfers {
    PendingTransfers
}

const START_RETRY: Duration = Duration::from_secs(15);
const SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);
const STAGING_STALE_AGE: Duration = Duration::from_secs(30 * 60);
const INCOMING_STALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(30);
/// Re-check free space every 64 MiB while a sender writes, so a long or
/// unknown-size transfer cannot fill the disk between the upfront check and
/// completion.
const SPACE_RECHECK_BYTES: u64 = 64 * 1024 * 1024;

/// Foreground receiver used by `kalo receive`.
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
            .unwrap_or_else(crate::paths::default_save_dir),
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
    let pairing = match crate::identity::DeviceIdentity::load_or_create() {
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

    run_receiver(
        handle, pending, save_dir, events, authorizer, encryption, pairing,
    )
    .await
}

/// Supervise the advertised RFCOMM OPP service. Advertising failures (radio
/// off, another receiver owning the service) retry without ending the app.
pub async fn run_receiver(
    handle: ReceiverHandle,
    _pending: PendingTransfers,
    save_dir: SaveDir,
    events: EventSink,
    authorizer: Authorizer,
    encryption: Encryption,
    pairing: Option<crate::identity::PairingManager>,
) -> ! {
    loop {
        sweep_staging(&save_dir.get(), &events, &encryption, pairing.as_ref());
        let start_save_dir = save_dir.clone();
        let start_events = events.clone();
        let start_authorizer = authorizer.clone();
        let start_encryption = encryption.clone();
        let start_pairing = pairing.clone();
        let started = run_blocking(move || {
            start_advertising(
                start_save_dir,
                start_events,
                start_authorizer,
                start_encryption,
                start_pairing,
            )
        })
        .await;
        match started {
            Ok(service) => {
                let registration = handle.begin_registration();
                handle.mark_active(registration);
                events.send(Event::Log(
                    "receiver ready — Windows OBEX Object Push service advertised".into(),
                ));
                // Keep the advertising thread parked. Dropping the handle
                // stops the advertisement and releases the WinRT objects.
                let _service = service;
                loop {
                    tokio::time::sleep(SWEEP_INTERVAL).await;
                    sweep_staging(&save_dir.get(), &events, &encryption, pairing.as_ref());
                    if !handle.is_active() {
                        break;
                    }
                }
                handle.release(registration, "receiver stopped; will retry");
            }
            Err(error) => {
                let reason = format!("{error:#}");
                handle.mark_lost(&reason);
                events.send(Event::Log(format!("receiver start failed: {reason}")));
                tokio::time::sleep(START_RETRY).await;
            }
        }
    }
}

/// Check that the OPP service can be advertised, then release it.
pub async fn agent_check() -> Result<()> {
    run_blocking(|| {
        let _com = ComGuard::new()?;
        let service_id = RfcommServiceId::ObexObjectPush()?;
        let provider = RfcommServiceProvider::CreateAsync(&service_id)?
            .join()
            .context("create the OBEX Object Push service provider")?;
        let listener = StreamSocketListener::new()?;
        provider
            .StartAdvertising(&listener)
            .context("advertise the OBEX Object Push service")?;
        provider.StopAdvertising()?;
        println!("receiver-check OK: the OPP service was free and is free again.");
        Ok(())
    })
    .await
}

type ConnectionHandler =
    TypedEventHandler<StreamSocketListener, StreamSocketListenerConnectionReceivedEventArgs>;

/// Handle to the thread that owns the advertised service.
///
/// The WinRT objects are created, advertised and released on one dedicated
/// thread so their COM apartment always owns their lifetime. Dropping the
/// handle stops the advertisement.
struct ReceiverService {
    shutdown: std::sync::mpsc::Sender<()>,
}

impl Drop for ReceiverService {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
    }
}

struct ConnectionContext {
    save_dir: SaveDir,
    events: EventSink,
    authorizer: Authorizer,
    encryption: Encryption,
    pairing: Option<crate::identity::PairingManager>,
    /// Bounded number of simultaneous incoming connections.
    active: Arc<AtomicUsize>,
}

/// Releases one concurrency slot when the connection worker ends.
struct IncomingSlot {
    active: Arc<AtomicUsize>,
}

impl IncomingSlot {
    fn acquire(active: Arc<AtomicUsize>) -> Option<Self> {
        active
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < security::MAX_CONCURRENT_INCOMING).then_some(count + 1)
            })
            .ok()
            .map(|_| Self { active })
    }
}

impl Drop for IncomingSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn start_advertising(
    save_dir: SaveDir,
    events: EventSink,
    authorizer: Authorizer,
    encryption: Encryption,
    pairing: Option<crate::identity::PairingManager>,
) -> Result<ReceiverService> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<std::result::Result<(), String>>();
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();

    std::thread::spawn(move || {
        let _com = match ComGuard::new() {
            Ok(com) => com,
            Err(error) => {
                let _ = ready_tx.send(Err(format!("{error:#}")));
                return;
            }
        };
        let (provider, listener, _handler) =
            match advertise(save_dir, events, authorizer, encryption, pairing) {
                Ok(parts) => parts,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!("{error:#}")));
                    return;
                }
            };
        if let Err(error) = provider.StartAdvertising(&listener) {
            let _ = ready_tx.send(Err(format!(
                "advertise the OBEX Object Push service: {error}"
            )));
            return;
        }
        let _ = ready_tx.send(Ok(()));
        // Stay parked so teardown happens on the thread that created the
        // WinRT objects and holds the COM apartment.
        let _ = shutdown_rx.recv();
        let _ = provider.StopAdvertising();
    });

    match ready_rx.recv() {
        Ok(Ok(())) => Ok(ReceiverService {
            shutdown: shutdown_tx,
        }),
        Ok(Err(error)) => bail!("{error}"),
        Err(_) => bail!("the receiver thread stopped before advertising the service"),
    }
}

fn advertise(
    save_dir: SaveDir,
    events: EventSink,
    authorizer: Authorizer,
    encryption: Encryption,
    pairing: Option<crate::identity::PairingManager>,
) -> Result<(
    RfcommServiceProvider,
    StreamSocketListener,
    ConnectionHandler,
)> {
    let service_id = RfcommServiceId::ObexObjectPush()?;
    let provider = RfcommServiceProvider::CreateAsync(&service_id)?
        .join()
        .context("create the OBEX Object Push service provider")?;
    let listener = StreamSocketListener::new()?;

    let context = Arc::new(ConnectionContext {
        save_dir,
        events,
        authorizer,
        encryption,
        pairing,
        active: Arc::new(AtomicUsize::new(0)),
    });
    let handler: ConnectionHandler = TypedEventHandler::new(
        move |_sender: windows::core::Ref<'_, StreamSocketListener>,
              args: windows::core::Ref<'_, StreamSocketListenerConnectionReceivedEventArgs>| {
            let socket = args.ok()?.Socket()?;
            let context = context.clone();
            std::thread::spawn(move || {
                let _com = match ComGuard::new() {
                    Ok(com) => com,
                    Err(error) => {
                        context.events.send(Event::Log(format!(
                            "incoming worker COM setup failed: {error:#}"
                        )));
                        return;
                    }
                };
                handle_connection(socket, context);
            });
            Ok(())
        },
    );
    listener.ConnectionReceived(&handler)?;
    Ok((provider, listener, handler))
}

/// Serve one accepted RFCOMM connection until it disconnects or fails.
fn handle_connection(socket: StreamSocket, context: Arc<ConnectionContext>) {
    let Some(_slot) = IncomingSlot::acquire(context.active.clone()) else {
        context.events.send(Event::Log(format!(
            "rejected incoming connection: {} transfers are already active",
            security::MAX_CONCURRENT_INCOMING
        )));
        return;
    };
    let sender = remote_sender(&socket);
    if sender.stable {
        context.events.send(Event::Log(format!(
            "incoming OBEX connection from {} ({})",
            sender.name, sender.address
        )));
    } else {
        context.events.send(Event::Log(format!(
            "incoming OBEX connection from {} (Bluetooth address unavailable)",
            sender.name
        )));
    }

    let watchdog_socket = socket.clone();
    let last_activity = Arc::new(Mutex::new(Instant::now()));
    let done = Arc::new(AtomicBool::new(false));
    spawn_watchdog(
        watchdog_socket,
        last_activity.clone(),
        done.clone(),
        context.events.clone(),
    );

    let transport = match RfcommStream::from_socket(socket) {
        Ok(transport) => transport,
        Err(error) => {
            context.events.send(Event::Log(format!(
                "incoming socket setup failed: {error:#}"
            )));
            done.store(true, Ordering::SeqCst);
            return;
        }
    };
    let mut stream = PacketStream::new(transport);
    let mut incoming: Option<Incoming> = None;

    loop {
        let request = match stream.read_request() {
            Ok(request) => request,
            Err(ObexError::Disconnected) => break,
            Err(error) => {
                if let Some(transfer) = incoming.take() {
                    fail_keep(
                        transfer,
                        &context.events,
                        format!("connection lost: {error}"),
                    );
                } else {
                    context
                        .events
                        .send(Event::Log(format!("incoming OBEX read failed: {error}")));
                }
                break;
            }
        };
        *last_activity.lock().expect("incoming activity lock") = Instant::now();

        match request.opcode {
            Opcode::Connect => {
                let max = request
                    .connect
                    .map(|parameters| parameters.max_packet_length)
                    .unwrap_or(255);
                let mut response = Response::new(ResponseCode::Success);
                response.connect = Some(ConnectParameters::new(max.max(255)));
                if let Err(error) = stream.write_response(&response) {
                    context.events.send(Event::Log(format!(
                        "incoming CONNECT reply failed: {error}"
                    )));
                    break;
                }
            }
            Opcode::Put => {
                let mut name = None;
                let mut size = None;
                let mut body = Vec::new();
                let mut last_chunk = request.is_final;
                for header in request.headers {
                    match header {
                        Header::Name(value) => name = Some(value),
                        Header::Length(value) => size = Some(value as u64),
                        Header::Body(value) => body = value,
                        Header::EndOfBody(value) => {
                            body = value;
                            last_chunk = true;
                        }
                        _ => {}
                    }
                }

                if incoming.is_none() {
                    let safe_name = sanitize::filename(name.as_deref().unwrap_or(""));
                    let control = crate::identity::looks_like_pairing_name(
                        name.as_deref().unwrap_or_default(),
                    );
                    if !sender.stable && sender.name == "unknown device" {
                        context.events.send(Event::Log(
                            "rejected incoming push: the sender could not be identified".into(),
                        ));
                        let _ = stream.write_response(&Response::new(ResponseCode::Forbidden));
                        break;
                    }
                    let id = Uuid::new_v4().simple().to_string();
                    // Reject impossible transfers before prompting the user:
                    // an oversized object or a full disk cannot be accepted
                    // even when the sender is trusted.
                    let capacity = security::check_announced_size(size)
                        .and_then(|()| {
                            if control
                                && size.is_some_and(|size| size > crate::identity::MAX_PAIR_BYTES)
                            {
                                bail!("the pairing object is larger than the protocol allows");
                            }
                            Ok(())
                        })
                        .and_then(|()| security::ensure_free_space(&context.save_dir.get(), size));
                    if let Err(error) = capacity {
                        let reason = format!("{error:#}");
                        context.events.send(Event::IncomingFailed {
                            id: id.clone(),
                            sender: sender.name.clone(),
                            name: safe_name.clone(),
                            error: reason.clone(),
                            staged_at: None,
                        });
                        context.events.send(Event::Log(format!(
                            "incoming push from {} rejected: {reason}",
                            sender.name
                        )));
                        let _ = stream.write_response(&Response::new(ResponseCode::Forbidden));
                        break;
                    }
                    if control && context.pairing.is_none() {
                        context.events.send(Event::Log(
                            "rejected pairing object: pairing is unavailable".into(),
                        ));
                        let _ = stream.write_response(&Response::new(ResponseCode::Forbidden));
                        break;
                    }
                    if control && !sender.stable {
                        context.events.send(Event::Log(
                            "rejected pairing object: the sender has no stable Bluetooth address"
                                .into(),
                        ));
                        let _ = stream.write_response(&Response::new(ResponseCode::Forbidden));
                        break;
                    }
                    if !control
                        && let Err(reason) = context.authorizer.authorize_blocking(
                            &id,
                            &sender.address,
                            &sender.name,
                            &safe_name,
                            size,
                        )
                    {
                        context.events.send(Event::IncomingFailed {
                            id,
                            sender: sender.name.clone(),
                            name: safe_name,
                            error: reason.clone(),
                            staged_at: None,
                        });
                        context.events.send(Event::Log(format!(
                            "incoming push from {} rejected: {reason}",
                            sender.name
                        )));
                        let _ = stream.write_response(&Response::new(ResponseCode::Forbidden));
                        break;
                    }
                    match start_transfer(&context, &sender, id, safe_name, size, control) {
                        Ok(transfer) => incoming = Some(transfer),
                        Err(error) => {
                            context.events.send(Event::Log(format!(
                                "cannot start incoming transfer: {error:#}"
                            )));
                            let _ = stream
                                .write_response(&Response::new(ResponseCode::InternalServerError));
                            break;
                        }
                    }
                }
                let transfer = incoming.as_mut().expect("incoming was created");
                if let Err(error) = transfer.write(&body, &context.events) {
                    let transfer = incoming.take().expect("incoming exists");
                    fail_keep(transfer, &context.events, format!("{error:#}"));
                    let _ =
                        stream.write_response(&Response::new(ResponseCode::InternalServerError));
                    break;
                }

                if last_chunk {
                    let transfer = incoming.take().expect("incoming exists");
                    match finish_transfer(
                        transfer,
                        &context.save_dir.get(),
                        &context.events,
                        &context.encryption,
                        context.pairing.as_ref(),
                    ) {
                        Ok(SaveOutcome::Saved) => {
                            if let Err(error) =
                                stream.write_response(&Response::new(ResponseCode::Success))
                            {
                                context.events.send(Event::Log(format!(
                                    "incoming final reply failed: {error}"
                                )));
                                break;
                            }
                        }
                        Ok(SaveOutcome::Blocked | SaveOutcome::Rejected) => {
                            let _ = stream.write_response(&Response::new(ResponseCode::Forbidden));
                            break;
                        }
                        Err(error) => {
                            context
                                .events
                                .send(Event::Log(format!("cannot save incoming file: {error:#}")));
                            let _ = stream
                                .write_response(&Response::new(ResponseCode::InternalServerError));
                            break;
                        }
                    }
                } else if let Err(error) =
                    stream.write_response(&Response::new(ResponseCode::Continue))
                {
                    context.events.send(Event::Log(format!(
                        "incoming continue reply failed: {error}"
                    )));
                    break;
                }
            }
            Opcode::Abort => {
                if let Some(transfer) = incoming.take() {
                    fail_keep(transfer, &context.events, "aborted by sender".into());
                }
                let _ = stream.write_response(&Response::new(ResponseCode::Success));
                break;
            }
            Opcode::Disconnect => {
                let _ = stream.write_response(&Response::new(ResponseCode::Success));
                break;
            }
            _ => {
                let _ = stream.write_response(&Response::new(ResponseCode::NotImplemented));
            }
        }
    }

    if let Some(transfer) = incoming.take() {
        fail_keep(
            transfer,
            &context.events,
            "connection closed mid-transfer".into(),
        );
    }
    done.store(true, Ordering::SeqCst);
}

/// The remote device as far as the receiver can identify it. `stable` means
/// the Bluetooth address was resolved; display-name-only identities are
/// accepted for one transfer but never persisted.
#[derive(Debug, Clone)]
struct SenderIdentity {
    /// Trust-store key (`AA:BB:...` or `name:<display name>`).
    address: String,
    /// Human-readable name for logs and prompts.
    name: String,
    stable: bool,
}

struct Incoming {
    id: String,
    name: String,
    sender: String,
    /// Trust-store key for the sender (`AA:BB:...` or `name:...`).
    address: String,
    /// Pairing protocol object: never saved and never shown as a file.
    control: bool,
    size: Option<u64>,
    dest: PathBuf,
    staging_dir: PathBuf,
    file: Option<File>,
    bytes: u64,
    started: Instant,
    last_emit: Instant,
    /// Next byte count at which free space is checked again.
    next_space_check: u64,
    /// Hashes while bytes are written, avoiding a second read at the end.
    hasher: security::Hasher,
}

impl Incoming {
    fn write(&mut self, body: &[u8], events: &EventSink) -> Result<()> {
        if body.is_empty() {
            return Ok(());
        }
        let next = self.bytes.saturating_add(body.len() as u64);
        if let Some(reason) = security::oversized_reason(next, self.size) {
            bail!("{reason}");
        }
        if next >= self.next_space_check {
            let remaining = self.size.map(|size| size.saturating_sub(next));
            security::ensure_free_space(&self.staging_dir, remaining)
                .context("not enough free space to finish receiving")?;
            self.next_space_check = next.saturating_add(SPACE_RECHECK_BYTES);
        }
        self.file
            .as_mut()
            .context("staging file is closed")?
            .write_all(body)
            .with_context(|| format!("write staged file {:?}", self.dest))?;
        self.hasher.update(body);
        self.bytes = next;
        if self.last_emit.elapsed() >= PROGRESS_INTERVAL {
            self.last_emit = Instant::now();
            events.send(Event::IncomingProgress {
                id: self.id.clone(),
                name: self.name.clone(),
                transferred: Some(self.bytes),
                size: self.size,
            });
        }
        Ok(())
    }

    fn close(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.sync_all();
        }
    }
}

fn start_transfer(
    context: &ConnectionContext,
    sender: &SenderIdentity,
    id: String,
    safe_name: String,
    size: Option<u64>,
    control: bool,
) -> Result<Incoming> {
    // Refuse before writing: an announced transfer that cannot fit must not
    // consume the little free space that is left.
    security::check_announced_size(size)?;
    security::ensure_free_space(&context.save_dir.get(), size)?;
    let staging_dir = staging_root().join(format!("kalo-{id}"));
    security::create_private_dir(&staging_dir)
        .with_context(|| format!("create staging directory {staging_dir:?}"))?;
    if let Err(error) = security::ensure_free_space(&staging_dir, size) {
        let _ = std::fs::remove_dir_all(&staging_dir);
        return Err(error).context("not enough free space in the staging area");
    }
    let dest = staging_dir.join(&safe_name);
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&dest)
        .with_context(|| format!("create staged file {dest:?}"))?;

    if control {
        context.events.send(Event::Log(format!(
            "pairing object from {}; processing it without saving",
            sender.name
        )));
    } else {
        context.events.send(Event::IncomingStarted {
            id: id.clone(),
            sender: sender.name.clone(),
            name: safe_name.clone(),
            size,
        });
    }
    Ok(Incoming {
        id,
        name: safe_name,
        sender: sender.name.clone(),
        address: sender.address.clone(),
        control,
        size,
        dest,
        staging_dir,
        file: Some(file),
        bytes: 0,
        started: Instant::now(),
        last_emit: Instant::now(),
        next_space_check: SPACE_RECHECK_BYTES,
        hasher: security::Hasher::new(),
    })
}

/// Outcome of a completed receive. A blocked file is deleted, not saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaveOutcome {
    Saved,
    Blocked,
    Rejected,
}

/// Move a completed file into Downloads and report the transfer.
fn finish_transfer(
    mut transfer: Incoming,
    downloads: &Path,
    events: &EventSink,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) -> Result<SaveOutcome> {
    transfer.close();
    // The incremental hash must cover exactly the bytes written to disk.
    if transfer.hasher.bytes() != transfer.bytes {
        bail!(
            "incoming file integrity check failed: hashed {} bytes but wrote {}",
            transfer.hasher.bytes(),
            transfer.bytes
        );
    }
    if transfer.control {
        return finish_pairing_transfer(transfer, events, encryption, pairing);
    }
    if let Some(kind) = crypto::container_kind(&transfer.dest)? {
        return finish_encrypted_transfer(transfer, downloads, events, encryption, pairing, kind);
    }
    let digest = std::mem::take(&mut transfer.hasher).finish();
    if security::is_blocked(digest) {
        let _ = std::fs::remove_file(&transfer.dest);
        events.send(Event::IncomingFailed {
            id: transfer.id.clone(),
            sender: transfer.sender.clone(),
            name: transfer.name.clone(),
            error: format!(
                "blocked by the malware hash list (SHA-256 {}); the received file was deleted",
                security::digest_hex(digest)
            ),
            staged_at: None,
        });
        let _ = std::fs::remove_dir_all(&transfer.staging_dir);
        return Ok(SaveOutcome::Blocked);
    }
    let target_dir = sanitize::sender_dir(downloads, &transfer.sender);
    let persisted = (|| -> Result<(PathBuf, u64)> {
        std::fs::create_dir_all(&target_dir)
            .with_context(|| format!("create sender directory {target_dir:?}"))?;
        let bytes = std::fs::metadata(&transfer.dest)
            .with_context(|| format!("read staged file {:?}", transfer.dest))?
            .len();
        security::ensure_free_space(&target_dir, Some(bytes))?;
        let name = sanitize::filename(
            transfer
                .dest
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| transfer.name.clone())
                .as_str(),
        );

        let mut final_path = sanitize::unique_in_dir(&target_dir, &name);
        loop {
            match sanitize::move_file(&transfer.dest, &final_path) {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    final_path = sanitize::unique_in_dir(&target_dir, &name);
                }
                Err(error) => return Err(error).context("move into the sender folder"),
            }
        }
        Ok((final_path, bytes))
    })();

    let (final_path, bytes) = match persisted {
        Ok(persisted) => persisted,
        Err(error) => {
            // The receiver already announced this transfer; report the failure
            // and leave the staged file for recovery instead of silently
            // dropping it from the UI.
            events.send(Event::IncomingFailed {
                id: transfer.id,
                sender: transfer.sender,
                name: transfer.name,
                error: format!("{error:#}"),
                staged_at: Some(transfer.dest),
            });
            return Err(error);
        }
    };

    let partial = transfer.size.is_some_and(|size| size != bytes);
    let elapsed_secs = transfer.started.elapsed().as_secs_f64();
    let mbps = if elapsed_secs > 0.0 {
        bytes as f64 / (1024.0 * 1024.0) / elapsed_secs
    } else {
        0.0
    };
    if let Err(error) = security::harden_received_file(&final_path) {
        events.send(Event::Log(format!(
            "warning: cannot harden {}: {error:#}",
            final_path.display()
        )));
    }
    events.send(Event::IncomingDone {
        id: transfer.id,
        sender: transfer.sender,
        name: transfer.name,
        saved_to: final_path,
        bytes,
        elapsed_secs,
        mbps,
        partial,
    });
    let _ = std::fs::remove_dir_all(&transfer.staging_dir);
    Ok(SaveOutcome::Saved)
}

/// Process a pairing control object, delete it, and deliver the next object
/// over a fresh OPP connection from a worker thread.
fn finish_pairing_transfer(
    transfer: Incoming,
    events: &EventSink,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) -> Result<SaveOutcome> {
    let result = match (pairing, encryption.passphrase()) {
        (Some(pairing), Some(passphrase)) => {
            pairing.handle_file(&transfer.address, &transfer.dest, &passphrase)
        }
        (None, _) => Err(anyhow::anyhow!(
            "pairing is unavailable on this installation"
        )),
        (_, None) => Err(anyhow::anyhow!("set a shared passphrase before pairing")),
    };
    let _ = std::fs::remove_file(&transfer.dest);
    let _ = std::fs::remove_dir_all(&transfer.staging_dir);
    match result {
        Ok(outcome) => {
            events.send(Event::Log(format!(
                "pairing object from {}: {}",
                transfer.sender, outcome.message
            )));
            if let Some(reply) = outcome.reply {
                let peer = transfer.address.clone();
                let events = events.clone();
                std::thread::spawn(move || {
                    let file = match crate::identity::PairingFile::new(&reply) {
                        Ok(file) => file,
                        Err(error) => {
                            events.send(Event::Log(format!(
                                "could not stage a pairing reply: {error:#}"
                            )));
                            return;
                        }
                    };
                    if let Err(error) = super::obex::send_blocking(&peer, file.path(), &events) {
                        events.send(Event::Log(format!(
                            "could not deliver a pairing reply to {peer}: {error:#}"
                        )));
                    }
                });
            }
        }
        Err(error) => {
            events.send(Event::Pairing {
                address: transfer.address.clone(),
                name: transfer.sender.clone(),
                ok: false,
                message: format!("{error:#}"),
            });
        }
    }
    Ok(SaveOutcome::Saved)
}

/// Decrypt a completed Kalo container, scan the plaintext and save it under
/// its authenticated original name.
fn finish_encrypted_transfer(
    transfer: Incoming,
    downloads: &Path,
    events: &EventSink,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
    kind: crypto::ContainerKind,
) -> Result<SaveOutcome> {
    let mut out_of_space = false;
    let gate = |size: u64| match security::ensure_free_space(&transfer.staging_dir, Some(size)) {
        Ok(()) => Ok(()),
        Err(error) => {
            out_of_space = true;
            Err(error.context("make room for the decrypted file in staging"))
        }
    };

    let decrypted: crypto::Decrypted = match kind {
        crypto::ContainerKind::Passphrase => {
            let Some(decryptor) = encryption.decryptor() else {
                let _ = std::fs::remove_file(&transfer.dest);
                let _ = std::fs::remove_dir_all(&transfer.staging_dir);
                events.send(Event::IncomingFailed {
                    id: transfer.id,
                    sender: transfer.sender,
                    name: transfer.name,
                    error: "received an encrypted Kalo file but no encryption passphrase is \
                            configured; the container was deleted"
                        .into(),
                    staged_at: None,
                });
                return Ok(SaveOutcome::Rejected);
            };
            match decryptor.decrypt_to_gated(&transfer.dest, &transfer.staging_dir, gate) {
                Ok(decrypted) => decrypted,
                // Keep the container when the disk is full; the recovery sweep
                // can retry once space is available.
                Err(error) if out_of_space => {
                    events.send(Event::IncomingFailed {
                        id: transfer.id,
                        sender: transfer.sender,
                        name: transfer.name,
                        error: format!("{error:#}"),
                        staged_at: Some(transfer.dest),
                    });
                    return Err(error);
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&transfer.dest);
                    let _ = std::fs::remove_dir_all(&transfer.staging_dir);
                    events.send(Event::IncomingFailed {
                        id: transfer.id,
                        sender: transfer.sender,
                        name: transfer.name,
                        error: format!(
                            "cannot decrypt the incoming file (wrong passphrase or corrupted \
                             container): {error:#}; the container was deleted"
                        ),
                        staged_at: None,
                    });
                    return Ok(SaveOutcome::Rejected);
                }
            }
        }
        crypto::ContainerKind::Peer => {
            let Some(pairing) = pairing else {
                let _ = std::fs::remove_file(&transfer.dest);
                let _ = std::fs::remove_dir_all(&transfer.staging_dir);
                events.send(Event::IncomingFailed {
                    id: transfer.id,
                    sender: transfer.sender,
                    name: transfer.name,
                    error: "received a paired-device container but pairing is unavailable; \
                            the container was deleted"
                        .into(),
                    staged_at: None,
                });
                return Ok(SaveOutcome::Rejected);
            };
            let selected = pairing
                .trust()
                .incoming_chain(&transfer.address)
                .zip(pairing.trust().peer_public(&transfer.address))
                .map(|(chain, public)| (transfer.address.clone(), chain, public))
                .or_else(|| {
                    crypto::peer_key_id(&transfer.dest)
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
                let _ = std::fs::remove_file(&transfer.dest);
                let _ = std::fs::remove_dir_all(&transfer.staging_dir);
                events.send(Event::IncomingFailed {
                    id: transfer.id,
                    sender: transfer.sender,
                    name: transfer.name,
                    error: "received a paired-device container from a device that is not \
                            paired with this Kalo installation; the container was deleted"
                        .into(),
                    staged_at: None,
                });
                return Ok(SaveOutcome::Rejected);
            };
            let decryptor = match crypto::PeerDecryptor::new(chain.key, chain.step, public) {
                Ok(decryptor) => decryptor,
                Err(error) => {
                    let _ = std::fs::remove_file(&transfer.dest);
                    let _ = std::fs::remove_dir_all(&transfer.staging_dir);
                    events.send(Event::IncomingFailed {
                        id: transfer.id,
                        sender: transfer.sender,
                        name: transfer.name,
                        error: format!(
                            "cannot use the pinned identity for {address}: {error:#}; \
                             the container was deleted"
                        ),
                        staged_at: None,
                    });
                    return Ok(SaveOutcome::Rejected);
                }
            };
            match decryptor.decrypt_to_gated(&transfer.dest, &transfer.staging_dir, gate) {
                Ok(decrypted) => {
                    if let Err(error) = pairing.trust().commit_incoming(
                        &address,
                        decrypted.step,
                        decrypted.next_key,
                    ) {
                        let _ = std::fs::remove_file(&decrypted.path);
                        let _ = std::fs::remove_file(&transfer.dest);
                        let _ = std::fs::remove_dir_all(&transfer.staging_dir);
                        events.send(Event::IncomingFailed {
                            id: transfer.id,
                            sender: transfer.sender,
                            name: transfer.name,
                            error: format!(
                                "the incoming paired-device key chain could not be saved: \
                                 {error:#}; the container was deleted"
                            ),
                            staged_at: None,
                        });
                        return Ok(SaveOutcome::Rejected);
                    }
                    crypto::Decrypted {
                        path: decrypted.path,
                        name: decrypted.name,
                        size: decrypted.size,
                    }
                }
                Err(error) if out_of_space => {
                    events.send(Event::IncomingFailed {
                        id: transfer.id,
                        sender: transfer.sender,
                        name: transfer.name,
                        error: format!("{error:#}"),
                        staged_at: Some(transfer.dest),
                    });
                    return Err(error);
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&transfer.dest);
                    let _ = std::fs::remove_dir_all(&transfer.staging_dir);
                    events.send(Event::IncomingFailed {
                        id: transfer.id,
                        sender: transfer.sender,
                        name: transfer.name,
                        error: format!(
                            "cannot decrypt the paired-device container (wrong identity, \
                             replayed or corrupted file): {error:#}; the container was deleted"
                        ),
                        staged_at: None,
                    });
                    return Ok(SaveOutcome::Rejected);
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
            let _ = std::fs::remove_file(&transfer.dest);
            let _ = std::fs::remove_dir_all(&transfer.staging_dir);
            events.send(Event::IncomingFailed {
                id: transfer.id,
                sender: transfer.sender,
                name: transfer.name,
                error: format!(
                    "cannot verify the decrypted file: {error:#}; both the decrypted copy and \
                     the container were deleted"
                ),
                staged_at: None,
            });
            return Ok(SaveOutcome::Rejected);
        }
    };
    if scan.blocked {
        let _ = std::fs::remove_file(&decrypted.path);
        let _ = std::fs::remove_file(&transfer.dest);
        let _ = std::fs::remove_dir_all(&transfer.staging_dir);
        events.send(Event::IncomingFailed {
            id: transfer.id,
            sender: transfer.sender,
            name: transfer.name,
            error: format!(
                "the decrypted file matches a known malicious SHA-256 hash ({}); it was deleted",
                security::digest_hex(scan.digest)
            ),
            staged_at: None,
        });
        return Ok(SaveOutcome::Blocked);
    }

    let target_dir = sanitize::sender_dir(downloads, &transfer.sender);
    let persisted = (|| -> Result<(PathBuf, u64)> {
        std::fs::create_dir_all(&target_dir)
            .with_context(|| format!("create sender directory {target_dir:?}"))?;
        security::ensure_free_space(&target_dir, Some(decrypted.size))?;
        let mut final_path = sanitize::unique_in_dir(&target_dir, &name);
        loop {
            match sanitize::move_file(&decrypted.path, &final_path) {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    final_path = sanitize::unique_in_dir(&target_dir, &name);
                }
                Err(error) => {
                    return Err(error).context("move decrypted file into the sender folder");
                }
            }
        }
        Ok((final_path, decrypted.size))
    })();

    let (final_path, bytes) = match persisted {
        Ok(persisted) => persisted,
        Err(error) => {
            // Keep the ciphertext container for the recovery sweep, but never
            // leave a plaintext copy where the plain-file walk could pick it
            // up as an ordinary transfer.
            let _ = std::fs::remove_file(&decrypted.path);
            events.send(Event::IncomingFailed {
                id: transfer.id,
                sender: transfer.sender,
                name: transfer.name,
                error: format!("{error:#}"),
                staged_at: Some(transfer.dest),
            });
            return Err(error);
        }
    };

    if let Err(error) = security::harden_received_file(&final_path) {
        events.send(Event::Log(format!(
            "warning: cannot harden {}: {error:#}",
            final_path.display()
        )));
    }
    let container_bytes = transfer.bytes;
    let elapsed_secs = transfer.started.elapsed().as_secs_f64();
    let mbps = if elapsed_secs > 0.0 {
        bytes as f64 / (1024.0 * 1024.0) / elapsed_secs
    } else {
        0.0
    };
    events.send(Event::Log(format!(
        "decrypted {name} from an encrypted container ({} on the wire, {} plaintext)",
        crate::events::format_bytes(container_bytes),
        crate::events::format_bytes(bytes)
    )));
    events.send(Event::IncomingDone {
        id: transfer.id,
        sender: transfer.sender,
        name,
        saved_to: final_path,
        bytes,
        elapsed_secs,
        mbps,
        partial: false,
    });
    let _ = std::fs::remove_dir_all(&transfer.staging_dir);
    Ok(SaveOutcome::Saved)
}

/// Keep a usable partial file in staging and tell the UI where it is.
fn fail_keep(mut transfer: Incoming, events: &EventSink, error: String) {
    transfer.close();
    // A partial encrypted container can never be decrypted; keeping it only
    // leaves unreadable bytes and plaintext-free clutter behind.
    if matches!(crypto::container_kind(&transfer.dest), Ok(Some(_))) {
        let _ = std::fs::remove_dir_all(&transfer.staging_dir);
        events.send(Event::IncomingFailed {
            id: transfer.id,
            sender: transfer.sender,
            name: transfer.name,
            error: format!("{error}; the partial encrypted container was deleted"),
            staged_at: None,
        });
        return;
    }
    events.send(Event::IncomingFailed {
        id: transfer.id,
        sender: transfer.sender,
        name: transfer.name,
        error,
        staged_at: Some(transfer.dest),
    });
}

fn spawn_watchdog(
    socket: StreamSocket,
    last_activity: Arc<Mutex<Instant>>,
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
            let idle = last_activity
                .lock()
                .expect("incoming activity lock")
                .elapsed();
            if idle >= INCOMING_STALL_TIMEOUT {
                events.send(Event::Log(format!(
                    "incoming transfer stalled for more than {}s; closing the connection",
                    INCOMING_STALL_TIMEOUT.as_secs()
                )));
                let _ = socket.Close();
                return;
            }
        }
    });
}

fn remote_sender(socket: &StreamSocket) -> SenderIdentity {
    let host = socket
        .Information()
        .ok()
        .and_then(|info| info.RemoteAddress().ok());
    let name = host
        .as_ref()
        .and_then(remote_name)
        .unwrap_or_else(|| "unknown device".into());
    let address = host.and_then(|host| {
        BluetoothDevice::FromHostNameAsync(&host)
            .ok()?
            .join()
            .ok()?
            .BluetoothAddress()
            .ok()
    });
    match address {
        Some(address) => SenderIdentity {
            address: format_mac(address),
            name,
            stable: true,
        },
        None => SenderIdentity {
            address: format!("name:{name}"),
            name,
            stable: false,
        },
    }
}

fn remote_name(host: &HostName) -> Option<String> {
    for name in [host.DisplayName().ok(), host.RawName().ok()]
        .into_iter()
        .flatten()
    {
        let name = hstring(name);
        if !name.trim().is_empty() {
            return Some(name);
        }
    }
    None
}

fn staging_root() -> PathBuf {
    std::env::temp_dir().join("kalo").join("staging")
}

/// Recover files left behind by an interrupted Kalo run.
fn sweep_staging(
    downloads: &Path,
    events: &EventSink,
    encryption: &Encryption,
    pairing: Option<&crate::identity::PairingManager>,
) {
    let root = staging_root();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    let mut recovered = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("kalo-") || !entry.path().is_dir() {
            continue;
        }
        let stale = newest_mtime(&entry.path())
            .and_then(|time| time.elapsed().ok())
            .is_some_and(|age| age >= STAGING_STALE_AGE);
        if !stale {
            continue;
        }
        recovered += recover_staging_dir(&entry.path(), downloads, events, encryption, pairing);
    }
    if recovered > 0 {
        events.send(Event::Log(format!(
            "recovered {recovered} file(s) from an interrupted transfer"
        )));
    }
}

fn newest_mtime(dir: &Path) -> Option<SystemTime> {
    let mut newest = std::fs::metadata(dir).and_then(|meta| meta.modified()).ok();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(modified) = entry.metadata().and_then(|meta| meta.modified()) {
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
        if !entry
            .file_type()
            .map(|kind| kind.is_file())
            .unwrap_or(false)
        {
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
                // Never present an unverified file as recovered.
                events.send(Event::Log(format!(
                    "left a stale staged file unscanned at {:?}: {error:#}",
                    entry.path()
                )));
                continue;
            }
        }
        let recovered_dir = sanitize::sender_dir(downloads, "Recovered");
        if let Err(error) = std::fs::create_dir_all(&recovered_dir) {
            events.send(Event::Log(format!(
                "cannot recover staged files into {downloads:?}: {error}"
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
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    dest = sanitize::unique_in_dir(&recovered_dir, &name);
                }
                Err(error) => {
                    events.send(Event::Log(format!(
                        "recover staged file {:?} failed: {error}",
                        entry.path()
                    )));
                    break;
                }
            }
        }
    }
    if std::fs::read_dir(dir)
        .map(|mut entries| entries.next().is_none())
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
