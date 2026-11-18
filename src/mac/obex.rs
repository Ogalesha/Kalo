//! Outgoing OPP transfers through IOBluetooth.
//!
//! `OBEXFileTransferServices` is callback driven: every operation completes on
//! the run loop of the thread that started it. The whole transfer therefore
//! runs on a blocking worker that pumps its own run loop, while progress and
//! completion are shared through a small mutex-protected state object. No
//! other Bluetooth profile is ever opened: only the Object Push service
//! (UUID 0x1105) is queried and used.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use objc2::rc::{Retained, autoreleasepool};
use objc2::runtime::AnyObject;
use objc2::{AnyThread, DefinedClass, define_class, msg_send};
use objc2_core_foundation::CFString;
use objc2_foundation::{NSArray, NSDictionary, NSNumber, NSObject, NSObjectProtocol, NSString};
use objc2_io_bluetooth::{
    IOBluetoothDevice, IOBluetoothOBEXSession, IOBluetoothSDPServiceRecord, IOBluetoothSDPUUID,
    OBEXError, OBEXErrorCodes, OBEXFileTransferServices, kFTSProgressBytesTotalKey,
    kFTSProgressBytesTransferredKey,
};

use super::{as_any, pump_run_loop};
use crate::events::{Event, EventSink, TransferStatus};
use crate::transfer::{Cancel, SendSummary};

const OPP_SERVICE_UUID: u16 = 0x1105;
const SDP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(90);
/// No progress callback for this long means the link silently died; abort
/// instead of holding the session until the OS timeout.
const STALL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const POLL: Duration = Duration::from_millis(100);
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
const ABORT_GRACE: Duration = Duration::from_secs(2);
const DISCONNECT_GRACE: Duration = Duration::from_secs(1);

/// State shared between the transfer loop and the Objective-C delegate.
#[derive(Debug)]
struct ObexState {
    connected: bool,
    connection_error: Option<OBEXError>,
    done: bool,
    transfer_error: Option<OBEXError>,
    aborted: bool,
    disconnected: bool,
    transferred: u64,
    total: Option<u64>,
    last_activity: Instant,
    last_emit: Instant,
}

impl Default for ObexState {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            connected: false,
            connection_error: None,
            done: false,
            transfer_error: None,
            aborted: false,
            disconnected: false,
            transferred: 0,
            total: None,
            last_activity: now,
            last_emit: now,
        }
    }
}

struct DelegateIvars {
    state: Arc<Mutex<ObexState>>,
    events: EventSink,
    send_id: u64,
    expected_size: u64,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements and the delegate holds
    // its state in `Arc`s; it is only alive while the transfer loop runs.
    #[unsafe(super(NSObject))]
    #[name = "KaloObexDelegate"]
    #[ivars = DelegateIvars]
    struct ObexDelegate;

    impl ObexDelegate {
        #[unsafe(method(fileTransferServicesConnectionComplete:error:))]
        fn connection_complete(
            &self,
            _services: Option<&OBEXFileTransferServices>,
            error: OBEXError,
        ) {
            let mut state = self.ivars().state.lock().expect("obex state lock");
            state.last_activity = Instant::now();
            if error == OBEXErrorCodes::Success.0 {
                state.connected = true;
            } else {
                state.connection_error = Some(error);
                state.done = true;
            }
        }

        #[unsafe(method(fileTransferServicesDisconnectionComplete:error:))]
        fn disconnection_complete(
            &self,
            _services: Option<&OBEXFileTransferServices>,
            error: OBEXError,
        ) {
            let mut state = self.ivars().state.lock().expect("obex state lock");
            state.last_activity = Instant::now();
            state.disconnected = true;
            // An unexpected drop must not leave the send loop waiting forever.
            if !state.done && error != OBEXErrorCodes::Success.0 {
                state.transfer_error = Some(error);
                state.done = true;
            }
        }

        #[unsafe(method(fileTransferServicesAbortComplete:error:))]
        fn abort_complete(
            &self,
            _services: Option<&OBEXFileTransferServices>,
            _error: OBEXError,
        ) {
            let mut state = self.ivars().state.lock().expect("obex state lock");
            state.aborted = true;
            state.last_activity = Instant::now();
        }

        #[unsafe(method(fileTransferServicesFilePreparationComplete:error:))]
        fn preparation_complete(
            &self,
            _services: Option<&OBEXFileTransferServices>,
            error: OBEXError,
        ) {
            if error != OBEXErrorCodes::Success.0 {
                let mut state = self.ivars().state.lock().expect("obex state lock");
                state.transfer_error = Some(error);
                state.done = true;
            }
        }

        #[unsafe(method(fileTransferServicesSendFileProgress:transferProgress:))]
        fn send_progress(
            &self,
            _services: Option<&OBEXFileTransferServices>,
            progress: Option<&NSDictionary>,
        ) {
            let Some(progress) = progress else {
                return;
            };
            let transferred = unsafe { kFTSProgressBytesTransferredKey }
                .and_then(|key| dict_u64(progress, key));
            let total =
                unsafe { kFTSProgressBytesTotalKey }.and_then(|key| dict_u64(progress, key));

            let emission = {
                let mut state = self.ivars().state.lock().expect("obex state lock");
                let now = Instant::now();
                state.last_activity = now;
                if let Some(transferred) = transferred {
                    state.transferred = transferred;
                }
                if let Some(total) = total {
                    state.total = Some(total);
                }
                let should_emit = now.duration_since(state.last_emit) >= PROGRESS_INTERVAL;
                if should_emit {
                    state.last_emit = now;
                }
                should_emit.then_some((state.transferred, state.total))
            };

            if let Some((transferred, total)) = emission {
                self.ivars().events.send(Event::SendProgress {
                    send_id: self.ivars().send_id,
                    transferred,
                    size: total.or(Some(self.ivars().expected_size)),
                    status: TransferStatus::Active,
                });
            }
        }

        #[unsafe(method(fileTransferServicesSendFileComplete:error:))]
        fn send_complete(
            &self,
            _services: Option<&OBEXFileTransferServices>,
            error: OBEXError,
        ) {
            let mut state = self.ivars().state.lock().expect("obex state lock");
            state.last_activity = Instant::now();
            if error == OBEXErrorCodes::Success.0 {
                state.transferred = self.ivars().expected_size;
            } else {
                state.transfer_error = Some(error);
            }
            state.done = true;
        }
    }

    unsafe impl NSObjectProtocol for ObexDelegate {}
);

impl ObexDelegate {
    fn new(
        state: Arc<Mutex<ObexState>>,
        events: EventSink,
        send_id: u64,
        size: u64,
    ) -> Retained<Self> {
        let this = Self::alloc().set_ivars(DelegateIvars {
            state,
            events,
            send_id,
            expected_size: size,
        });
        unsafe { msg_send![super(this), init] }
    }
}

/// Read an integer from a progress dictionary. The documented keys are
/// CFStrings toll-free bridged with NSString, which is what NSDictionary uses.
fn dict_u64(dict: &NSDictionary, key: &CFString) -> Option<u64> {
    // SAFETY: CFString and NSString are toll-free bridged; both wrappers are
    // zero-sized views over the same object pointer.
    let key: &NSString = unsafe { &*(key as *const CFString as *const NSString) };
    let key: &AnyObject = unsafe { &*(key as *const NSString as *const AnyObject) };
    let value = dict.objectForKey(key)?;
    // SAFETY: the progress dictionary stores NSNumber values for these keys.
    let number: &NSNumber = unsafe { &*(Retained::as_ptr(&value) as *const NSNumber) };
    Some(number.as_u64())
}

/// Send one file to `mac` through the Object Push profile.
pub async fn send(
    mac: &str,
    file: &Path,
    events: &EventSink,
    send_id: u64,
    cancel: &Cancel,
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

    let mac = mac.trim().to_uppercase();
    let mac_for_worker = mac.clone();
    let events_for_worker = events.clone();
    let cancel_for_worker = cancel.clone();
    let file_for_worker = file.clone();
    let started = Instant::now();

    events.send(Event::SendProgress {
        send_id,
        transferred: 0,
        size: Some(size),
        status: TransferStatus::Queued,
    });

    let bytes = tokio::task::spawn_blocking(move || {
        send_blocking(
            &mac_for_worker,
            &file_for_worker,
            &events_for_worker,
            send_id,
            size,
            &cancel_for_worker,
        )
    })
    .await
    .context("macOS transfer task failed")??;

    Ok(SendSummary::new(
        &mac,
        bytes,
        started.elapsed().as_secs_f64(),
    ))
}

fn send_blocking(
    mac: &str,
    file: &Path,
    events: &EventSink,
    send_id: u64,
    size: u64,
    cancel: &Cancel,
) -> Result<u64> {
    autoreleasepool(|_| {
        let address = NSString::from_str(mac);
        let device = unsafe { IOBluetoothDevice::deviceWithAddressString(Some(&address)) }
            .with_context(|| {
                format!("device {mac} is not known to macOS — pair it first with `kalo pair {mac}`")
            })?;

        events.send(Event::Log(format!("looking up the OPP service on {mac}…")));
        let record = find_opp_service(&device, cancel)?;
        let mut channel = 0u8;
        let status = unsafe { record.getRFCOMMChannelID(&mut channel) };
        if status != 0 {
            bail!("the remote OPP service did not report an RFCOMM channel (IOKit error {status})");
        }

        let session =
            unsafe { IOBluetoothOBEXSession::withDevice_channelID(Some(&device), channel) }
                .context("could not create the Bluetooth OBEX session")?;
        let services = unsafe { OBEXFileTransferServices::withOBEXSession(Some(&session)) }
            .context("could not create the OBEX file transfer service")?;

        let state = Arc::new(Mutex::new(ObexState::default()));
        let delegate = ObexDelegate::new(state.clone(), events.clone(), send_id, size);
        unsafe { services.setDelegate(Some(as_any(&*delegate))) };

        let outcome = run_transfer(&services, &state, file, size, events, send_id, cancel);

        // Always close the transport, even after a failed or canceled
        // transfer. Ignore the result: the error that got us here is the one
        // worth reporting.
        unsafe {
            let _ = services.disconnect();
        }
        wait_for_disconnect(&state);
        unsafe { services.setDelegate(None) };
        drop(delegate);

        outcome
    })
}

fn find_opp_service(
    device: &IOBluetoothDevice,
    cancel: &Cancel,
) -> Result<Retained<IOBluetoothSDPServiceRecord>> {
    let uuid = unsafe { IOBluetoothSDPUUID::uuid16(OPP_SERVICE_UUID) }
        .context("could not create the OPP service UUID")?;
    let uuid_for_query: Retained<AnyObject> = unsafe { Retained::cast_unchecked(uuid.clone()) };
    let uuids = NSArray::from_retained_slice(&[uuid_for_query]);
    let status = unsafe { device.performSDPQuery_uuids(None, Some(&uuids)) };
    if status != 0 {
        // Cached services may still contain OPP; only fail if the poll below
        // also comes up empty.
        eprintln!("warning: SDP query returned IOKit error {status}; trying cached services");
    }

    let deadline = Instant::now() + SDP_TIMEOUT;
    loop {
        if let Some(record) = unsafe { device.getServiceRecordForUUID(Some(&uuid)) } {
            return Ok(record);
        }
        if cancel.is_cancelled() {
            bail!("send canceled");
        }
        if Instant::now() >= deadline {
            bail!(
                "the other device did not report an Object Push service; \
                 make sure it is in range and accepts Bluetooth file transfers"
            );
        }
        pump_run_loop(POLL);
    }
}

fn run_transfer(
    services: &OBEXFileTransferServices,
    state: &Arc<Mutex<ObexState>>,
    file: &Path,
    size: u64,
    events: &EventSink,
    send_id: u64,
    cancel: &Cancel,
) -> Result<u64> {
    let connect = unsafe { services.connectToObjectPushService() };
    if connect != OBEXErrorCodes::Success.0 {
        return Err(obex_failure(
            "connecting to the remote OPP service",
            connect,
        ));
    }
    wait_for_connection(state, services, cancel)?;

    events.send(Event::Log(
        "OPP session connected; sending the file…".into(),
    ));
    events.send(Event::SendProgress {
        send_id,
        transferred: 0,
        size: Some(size),
        status: TransferStatus::Active,
    });

    let path = file.to_string_lossy();
    let path = NSString::from_str(&path);
    let started = unsafe { services.sendFile(Some(&path)) };
    if started != OBEXErrorCodes::Success.0 {
        return Err(obex_failure("starting the file transfer", started));
    }

    wait_for_transfer(state, services, cancel)?;
    Ok(size)
}

fn wait_for_connection(
    state: &Arc<Mutex<ObexState>>,
    services: &OBEXFileTransferServices,
    cancel: &Cancel,
) -> Result<()> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        {
            let state = state.lock().expect("obex state lock");
            if let Some(error) = state.connection_error {
                return Err(obex_failure("connecting to the remote OPP service", error));
            }
            if state.connected {
                return Ok(());
            }
        }
        if cancel.is_cancelled() {
            unsafe {
                let _ = services.abort();
            }
            bail!("send canceled");
        }
        if Instant::now() >= deadline {
            unsafe {
                let _ = services.abort();
            }
            bail!(
                "connection to the remote OPP service timed out; \
                 make sure the device is paired, in range and accepting transfers"
            );
        }
        pump_run_loop(POLL);
    }
}

fn wait_for_transfer(
    state: &Arc<Mutex<ObexState>>,
    services: &OBEXFileTransferServices,
    cancel: &Cancel,
) -> Result<()> {
    loop {
        {
            let state = state.lock().expect("obex state lock");
            if let Some(error) = state.transfer_error {
                return Err(obex_failure("sending the file", error));
            }
            if state.done {
                return Ok(());
            }
            if state.last_activity.elapsed() >= STALL_TIMEOUT {
                drop(state);
                unsafe {
                    let _ = services.abort();
                }
                bail!("the transfer stalled and was aborted");
            }
        }
        if cancel.is_cancelled() {
            abort_transfer(services, state);
            bail!("send canceled");
        }
        pump_run_loop(POLL);
    }
}

fn abort_transfer(services: &OBEXFileTransferServices, state: &Arc<Mutex<ObexState>>) {
    unsafe {
        let _ = services.abort();
    }
    let deadline = Instant::now() + ABORT_GRACE;
    while Instant::now() < deadline {
        if state.lock().expect("obex state lock").aborted {
            break;
        }
        pump_run_loop(Duration::from_millis(50));
    }
}

fn wait_for_disconnect(state: &Arc<Mutex<ObexState>>) {
    let deadline = Instant::now() + DISCONNECT_GRACE;
    while Instant::now() < deadline {
        if state.lock().expect("obex state lock").disconnected {
            break;
        }
        pump_run_loop(Duration::from_millis(50));
    }
}

fn obex_failure(action: &str, code: OBEXError) -> anyhow::Error {
    let reason = match OBEXErrorCodes(code) {
        OBEXErrorCodes::Success => "success".to_string(),
        OBEXErrorCodes::TimeoutError | OBEXErrorCodes::SessionTimeoutError => "timed out".into(),
        OBEXErrorCodes::CancelledError => "cancelled".into(),
        OBEXErrorCodes::ForbiddenError => {
            "the other device declined or forbids the transfer".into()
        }
        OBEXErrorCodes::UnauthorizedError => "the other device rejected authorization".into(),
        OBEXErrorCodes::NotAcceptableError => "the other device did not accept the file".into(),
        OBEXErrorCodes::SessionBusyError => "the remote OPP service is busy".into(),
        OBEXErrorCodes::SessionNoTransportError | OBEXErrorCodes::SessionTransportDiedError => {
            "the Bluetooth link dropped".into()
        }
        OBEXErrorCodes::SessionNotConnectedError => "the OPP session is not connected".into(),
        OBEXErrorCodes::NotImplementedError => {
            "the other device does not implement Object Push".into()
        }
        other => format!("OBEX error {}", other.0),
    };
    anyhow!("{action} failed: {reason}")
}
