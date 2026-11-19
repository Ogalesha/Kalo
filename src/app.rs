//! Iced UI for the Kalo spike: devices, send with progress, receiver state, log.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::SinkExt;
use iced::widget::{
    button, column, container, image as image_widget, progress_bar, row, rule, scrollable, space,
    text, text_input,
};
use iced::{Alignment, Color, ContentFit, Element, Font, Length, Padding, Subscription, Task};
use tokio::sync::broadcast;

use crate::crypto::{Encryption, MIN_PASSPHRASE_CHARS};
use crate::events::{
    Event, EventSink, ReceiverStatus, format_bytes, send_progress_summary, transfer_fraction,
};
use crate::paths;
use crate::platform::{self, DeviceInfo, PendingTransfers, ReceiverHandle, new_pending};
use crate::selection::Selection;
use crate::settings::{SaveDir, Settings, ThemeKind};
use crate::transfer::{Cancel, CancelHandle, batch_position};
use crate::trust::{Authorizer, IncomingPolicy, TrustStore};

/// Shared handles for the event-pump subscription. iced 0.14 builds
/// subscriptions from plain `fn` builders, so the state must be static.
static EVENT_BUS: OnceLock<EventBus> = OnceLock::new();

struct EventBus {
    sink: EventSink,
    receiver: ReceiverHandle,
    pending: PendingTransfers,
    save_dir: SaveDir,
    authorizer: Authorizer,
    encryption: Encryption,
    /// Screenshot mode: never touch Bluetooth or the user's config.
    demo: bool,
}

impl EventBus {
    /// Spawn the shared receiver supervisor exactly once. The subscription can
    /// be re-created by iced, but the supervisor (and its event sink) must not
    /// be duplicated.
    fn ensure_receiver_started(&self) {
        static STARTED: AtomicBool = AtomicBool::new(false);
        if self.demo || STARTED.swap(true, Ordering::SeqCst) {
            return;
        }
        tokio::spawn(platform::run_receiver(
            self.receiver.clone(),
            self.pending.clone(),
            self.save_dir.clone(),
            self.sink.clone(),
            self.authorizer.clone(),
            self.encryption.clone(),
        ));
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    DevicesLoaded {
        request_id: u64,
        result: Result<Vec<DeviceInfo>, String>,
    },
    RefreshDevices,
    PickDevice(String),
    PickFiles,
    PickFolder,
    /// Raw paths chosen in a file dialog. The folder walk runs off the UI
    /// thread before the selection is accepted.
    FilesPicked(Option<Vec<PathBuf>>),
    SelectionCollected(Result<Selection, String>),
    SendClicked,
    CancelSend,
    SendFinished {
        send_id: u64,
        result: Result<String, String>,
    },
    ToggleTheme,
    ToggleEncryption,
    EncryptionPassphraseChanged(String),
    SaveEncryptionPassphrase,
    ClearEncryptionPassphrase,
    PickSaveFolder,
    SaveFolderPicked(Option<PathBuf>),
    OpenPath(PathBuf),
    AuthorizationResponse {
        id: String,
        allow: bool,
        remember: bool,
    },
    RemoveTrustedSender(String),
    SetIncomingPolicy(IncomingPolicy),
    ToggleTrustList,
    PollTray,
    TrayShow,
    TrayQuit,
    WindowCloseRequested(iced::window::Id),
    Event(Event),
}

#[derive(Debug, Clone)]
struct IncomingUi {
    id: String,
    sender: String,
    name: String,
    transferred: u64,
    size: Option<u64>,
}

#[derive(Debug, Clone)]
struct SendProgressUi {
    /// `None` when the peer did not announce a size: the bar would otherwise
    /// sit at 0% for the whole transfer.
    fraction: Option<f32>,
    detail: String,
}

#[derive(Debug, Clone)]
struct SendResultUi {
    ok: bool,
    message: String,
}

#[derive(Debug, Clone)]
struct AuthPromptUi {
    id: String,
    sender: String,
    address: String,
    name: String,
    size: Option<u64>,
    stable: bool,
}

#[derive(Debug, Clone)]
struct SavedUi {
    name: String,
    path: PathBuf,
    partial: bool,
}

/// Everything that belongs to the one in-flight outgoing transfer. Keeping
/// it in one struct makes invalid combinations (sending without an id or a
/// cancel handle) unrepresentable.
#[derive(Debug)]
struct ActiveSend {
    id: u64,
    target: String,
    cancel: Option<CancelHandle>,
    cancel_requested: bool,
    progress: Option<SendProgressUi>,
    /// 1-based position in the batch and the batch size.
    index: usize,
    total: usize,
    /// File currently being sent, for the batch header.
    current: String,
}

struct App {
    tx: EventSink,
    devices: Vec<DeviceInfo>,
    devices_request_id: u64,
    devices_loaded: bool,
    devices_loading: bool,
    devices_error: Option<String>,
    /// Selected device address (stable across list refreshes; an index would
    /// go stale because `list_known_devices` re-sorts on every refresh).
    selected: Option<String>,
    selection: Option<Selection>,
    picking_selection: bool,
    log: Vec<String>,
    /// The active send, if any.
    active_send: Option<ActiveSend>,
    next_send_id: u64,
    send_result: Option<SendResultUi>,
    incoming: Vec<IncomingUi>,
    receiver_state: ReceiverStatus,
    settings: Settings,
    trust: TrustStore,
    authorizer: Authorizer,
    save_dir: SaveDir,
    encryption: Encryption,
    /// New passphrase typed in the settings row. The saved secret stays in
    /// the shared handle and never returns to the text field.
    passphrase_draft: String,
    picking_folder: bool,
    pending_authorizations: Vec<AuthPromptUi>,
    last_saved: Option<SavedUi>,
    show_trust: bool,
    demo: bool,
    tray_ready: bool,
}

impl App {
    fn log(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > 300 {
            self.log.drain(0..100);
        }
    }

    fn is_sending(&self) -> bool {
        self.active_send.is_some()
    }

    fn persist_settings(&mut self) {
        if self.demo {
            return;
        }
        if let Err(error) = self.settings.save() {
            self.log(format!("Couldn't save settings: {error:#}"));
        }
    }
}

struct Startup {
    devices: Vec<DeviceInfo>,
    selected: Option<String>,
    devices_loaded: bool,
    devices_loading: bool,
    log: Vec<String>,
    incoming: Vec<IncomingUi>,
    receiver_state: ReceiverStatus,
}

fn demo_enabled() -> bool {
    cfg!(debug_assertions) && std::env::var_os("KALO_DEMO").is_some()
}

fn demo_settings() -> Settings {
    let theme = match std::env::var("KALO_DEMO_THEME").as_deref() {
        Ok("light") => ThemeKind::Light,
        _ => ThemeKind::Dark,
    };
    Settings {
        theme,
        save_dir: Some(PathBuf::from("/home/you/Downloads")),
        encrypt_sends: false,
        encryption_passphrase: String::new(),
    }
}

fn startup(bus: &EventBus, demo: bool, mut log: Vec<String>) -> Startup {
    if demo {
        log.extend([
            "Sent design-review.pdf to Studio laptop · 4.2 MB in 1.4s (3.0 MB/s)".to_string(),
            "Saved sunset.jpg from Pixel 8 → Downloads/sunset.jpg · 2.4 MB in 0.9s (2.7 MB/s)"
                .to_string(),
            "Incoming from Kitchen speaker: voice-memo.opus — waiting for approval".to_string(),
        ]);
        return Startup {
            devices: vec![
                DeviceInfo {
                    address: "AA:BB:CC:11:22:33".into(),
                    alias: "Pixel 8".into(),
                    paired: true,
                    trusted: true,
                    connected: true,
                },
                DeviceInfo {
                    address: "AA:BB:CC:44:55:66".into(),
                    alias: "Studio laptop".into(),
                    paired: true,
                    trusted: true,
                    connected: false,
                },
                DeviceInfo {
                    address: "AA:BB:CC:77:88:99".into(),
                    alias: "Kitchen speaker".into(),
                    paired: false,
                    trusted: false,
                    connected: false,
                },
            ],
            selected: Some("AA:BB:CC:11:22:33".into()),
            devices_loaded: true,
            devices_loading: false,
            log,
            incoming: vec![IncomingUi {
                id: "demo-incoming".into(),
                sender: "Pixel 8".into(),
                name: "weekend-photo.jpg".into(),
                transferred: 1_800_000,
                size: Some(3_400_000),
            }],
            receiver_state: ReceiverStatus::Active,
        };
    }

    Startup {
        devices: Vec::new(),
        selected: None,
        devices_loaded: false,
        devices_loading: true,
        log,
        incoming: Vec::new(),
        receiver_state: bus.receiver.status(),
    }
}

pub fn run() -> iced::Result {
    let sink = EventSink::new(2048);
    let demo = demo_enabled();
    let tray_ready = if demo { false } else { crate::tray::start() };
    let (settings, settings_note) = if demo {
        (demo_settings(), None)
    } else {
        Settings::load()
    };
    let (trust, trust_note) = if demo {
        (TrustStore::demo(), None)
    } else {
        TrustStore::load()
    };
    let save_dir = SaveDir::new(
        settings
            .save_dir
            .clone()
            .unwrap_or_else(paths::downloads_dir),
    );
    let encryption = Encryption::new(
        settings.encrypt_sends,
        settings.encryption_passphrase.clone(),
    );
    let authorizer = Authorizer::new(trust.clone(), sink.clone(), true);
    let receiver = ReceiverHandle::new(sink.clone());
    if EVENT_BUS
        .set(EventBus {
            sink: sink.clone(),
            receiver: receiver.clone(),
            pending: new_pending(),
            save_dir: save_dir.clone(),
            authorizer: authorizer.clone(),
            encryption: encryption.clone(),
            demo,
        })
        .is_err()
    {
        panic!("kalo event bus is initialized exactly once");
    }

    iced::application(
        move || {
            let bus = EVENT_BUS.get().expect("event bus must be initialized");
            let initial_request_id = 1;
            let mut log = Vec::new();
            if let Some(note) = settings_note.clone() {
                log.push(note);
            }
            if let Some(note) = trust_note.clone() {
                log.push(note);
            }
            if settings.encrypt_sends && !encryption.enabled() {
                log.push(
                    "Outgoing encryption is off because the saved passphrase is missing or too \
                     short; set a valid passphrase to enable it."
                        .to_string(),
                );
            }
            let start = startup(bus, demo, log);
            let app = App {
                tx: bus.sink.clone(),
                devices: start.devices,
                devices_request_id: initial_request_id,
                devices_loaded: start.devices_loaded,
                devices_loading: start.devices_loading,
                devices_error: None,
                selected: start.selected,
                selection: demo.then(|| Selection {
                    files: vec![PathBuf::from("/home/you/Documents/design-review.pdf")],
                    total_bytes: 4_200_000,
                    notes: Vec::new(),
                    folders: 0,
                }),
                picking_selection: false,
                log: start.log,
                active_send: None,
                next_send_id: 1,
                send_result: None,
                incoming: start.incoming,
                receiver_state: start.receiver_state,
                settings: settings.clone(),
                trust: trust.clone(),
                authorizer: authorizer.clone(),
                save_dir: save_dir.clone(),
                encryption: encryption.clone(),
                passphrase_draft: String::new(),
                picking_folder: false,
                pending_authorizations: if demo {
                    vec![AuthPromptUi {
                        id: "demo-authorization".into(),
                        sender: "Kitchen speaker".into(),
                        address: "AA:BB:CC:77:88:99".into(),
                        name: "voice-memo.opus".into(),
                        size: Some(1_200_000),
                        stable: true,
                    }]
                } else {
                    Vec::new()
                },
                last_saved: None,
                show_trust: false,
                demo,
                tray_ready,
            };
            let task = if demo {
                Task::none()
            } else {
                Task::perform(platform::list_known_devices(), move |result| {
                    Message::DevicesLoaded {
                        request_id: initial_request_id,
                        result: result.map_err(|e| e.to_string()),
                    }
                })
            };
            (app, task)
        },
        update,
        view,
    )
    .title("Kalo")
    .theme(|app: &App| ui::theme(app.settings.theme))
    .window(iced::window::Settings {
        size: iced::Size::new(980.0, 710.0),
        position: iced::window::Position::Centered,
        icon: window_icon(),
        ..Default::default()
    })
    .exit_on_close_request(!tray_ready)
    .subscription(subscription)
    .run()
}

fn window_icon() -> Option<iced::window::Icon> {
    let image = image::load_from_memory(include_bytes!(
        "../packaging/common/icons/hicolor/256x256/apps/kalo.png"
    ))
    .ok()?
    .to_rgba8();
    let (width, height) = image.dimensions();
    iced::window::icon::from_rgba(image.into_vec(), width, height).ok()
}

fn update(app: &mut App, message: Message) -> Task<Message> {
    match message {
        Message::DevicesLoaded { request_id, result } => {
            if request_id != app.devices_request_id {
                return Task::none();
            }
            app.devices_loaded = true;
            app.devices_loading = false;
            match result {
                Ok(devices) => {
                    app.devices = devices;
                    app.devices_error = None;
                }
                Err(e) => {
                    app.devices_error = Some(e.clone());
                    app.log(format!("Couldn't load devices: {e}"));
                }
            }
            Task::none()
        }
        Message::RefreshDevices => {
            if app.devices_loading {
                return Task::none();
            }
            app.devices_loading = true;
            app.devices_request_id += 1;
            let request_id = app.devices_request_id;
            Task::perform(platform::list_known_devices(), move |result| {
                Message::DevicesLoaded {
                    request_id,
                    result: result.map_err(|e| e.to_string()),
                }
            })
        }
        Message::PickDevice(address) => {
            if app.is_sending() {
                app.log("cannot change the target during a send");
                return Task::none();
            }
            app.selected = Some(address);
            app.send_result = None;
            Task::none()
        }
        Message::PickFiles => {
            if app.is_sending() || app.picking_selection {
                return Task::none();
            }
            app.picking_selection = true;
            Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .set_title("Choose files to send")
                        .pick_files()
                        .await
                        .map(|handles| {
                            handles
                                .into_iter()
                                .map(|handle| handle.path().to_path_buf())
                                .collect()
                        })
                },
                Message::FilesPicked,
            )
        }
        Message::PickFolder => {
            if app.is_sending() || app.picking_selection {
                return Task::none();
            }
            app.picking_selection = true;
            Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .set_title("Choose a folder to send")
                        .pick_folder()
                        .await
                        .map(|handle| vec![handle.path().to_path_buf()])
                },
                Message::FilesPicked,
            )
        }
        Message::FilesPicked(paths) => {
            app.picking_selection = false;
            if app.is_sending() {
                app.log("ignored a selection that finished during a send");
                return Task::none();
            }
            // Cancel leaves the previous selection intact.
            let Some(paths) = paths else {
                return Task::none();
            };
            Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || crate::selection::collect(&paths))
                        .await
                        .map_err(|error| format!("selection task failed: {error}"))?
                        .map_err(|error| format!("{error:#}"))
                },
                Message::SelectionCollected,
            )
        }
        Message::SelectionCollected(result) => {
            match result {
                Ok(selection) => {
                    for note in &selection.notes {
                        app.log(note.clone());
                    }
                    app.log(format!(
                        "{} ready to send ({})",
                        selection_summary(&selection),
                        format_bytes(selection.total_bytes)
                    ));
                    app.selection = Some(selection);
                    app.send_result = None;
                }
                Err(error) => app.log(format!("Couldn't prepare the selection: {error}")),
            }
            Task::none()
        }
        Message::SendClicked => {
            if let Some(send_id) = app.active_send.as_ref().map(|send| send.id) {
                app.log(format!("send already in progress (id {send_id})"));
                return Task::none();
            }
            if app.picking_selection {
                app.log("finish choosing files before starting a send");
                return Task::none();
            }
            let Some(device) = resolve_target(&app.devices, app.selected.as_deref()) else {
                app.log("select a device first");
                return Task::none();
            };
            let Some(selection) = app.selection.clone() else {
                app.log("choose files or a folder first");
                return Task::none();
            };
            let mac = device.address.clone();
            let target = format!("{} ({})", device_name(device), device.address);
            let result_target = device_name(device).to_string();
            let files = selection.files;
            let total = files.len();
            let first_name = files
                .first()
                .map(|file| file_name(file))
                .unwrap_or_default();
            let send_id = app.next_send_id;
            app.next_send_id += 1;
            let (cancel_handle, cancel) = Cancel::new();

            app.active_send = Some(ActiveSend {
                id: send_id,
                target,
                cancel: Some(cancel_handle),
                cancel_requested: false,
                progress: None,
                index: 1,
                total,
                current: first_name,
            });
            app.send_result = None;

            let tx = app.tx.clone();
            let encryption = app.encryption.clone();
            Task::perform(
                async move {
                    platform::send(&mac, &files, &tx, send_id, cancel, &encryption)
                        .await
                        .map(|summary| {
                            if summary.files == 1 {
                                let name = files
                                    .first()
                                    .map(|file| file_name(file))
                                    .unwrap_or_else(|| "file".to_string());
                                format!(
                                    "Sent {name} to {result_target} · {} in {:.1}s ({:.1} MB/s)",
                                    format_bytes(summary.bytes),
                                    summary.elapsed_secs,
                                    summary.mbps
                                )
                            } else {
                                format!(
                                    "Sent {} files ({}) to {result_target} · {:.1}s ({:.1} MB/s)",
                                    summary.files,
                                    format_bytes(summary.bytes),
                                    summary.elapsed_secs,
                                    summary.mbps
                                )
                            }
                        })
                },
                move |result| Message::SendFinished {
                    send_id,
                    result: result.map_err(|e| e.to_string()),
                },
            )
        }
        Message::CancelSend => {
            let line = if let Some(active) = app.active_send.as_mut() {
                if active.cancel_requested {
                    "cancel already requested".to_string()
                } else {
                    match active.cancel.take() {
                        Some(cancel) => {
                            if cancel.cancel() {
                                active.cancel_requested = true;
                                "canceling send…".to_string()
                            } else {
                                "send already finished".to_string()
                            }
                        }
                        None => "no send to cancel".to_string(),
                    }
                }
            } else {
                "no send to cancel".to_string()
            };
            app.log(line);
            Task::none()
        }
        Message::SendFinished { send_id, result } => {
            if app.active_send.as_ref().map(|send| send.id) != Some(send_id) {
                return Task::none();
            }
            let active = app.active_send.take().expect("active send was checked");
            let canceled = active.cancel_requested;
            let target = active.target;

            let (ok, message) = match result {
                Ok(summary) => (true, summary),
                Err(e) if canceled => (false, format!("Send canceled: {e}")),
                Err(e) => (false, format!("Sending to {target} failed: {e}")),
            };
            app.log(message.clone());
            app.send_result = Some(SendResultUi { ok, message });
            Task::none()
        }
        Message::ToggleTheme => {
            app.settings.theme = app.settings.theme.toggled();
            let label = match app.settings.theme {
                ThemeKind::Dark => "Dark",
                ThemeKind::Light => "Light",
            };
            app.persist_settings();
            app.log(format!("{label} theme enabled"));
            Task::none()
        }
        Message::ToggleEncryption => {
            let enable = !app.encryption.enabled();
            if enable && !app.encryption.has_strong_passphrase() {
                app.log(format!(
                    "Set a shared passphrase of at least {MIN_PASSPHRASE_CHARS} characters \
                     before enabling encryption."
                ));
                return Task::none();
            }
            app.encryption.set_enabled(enable);
            app.settings.encrypt_sends = enable;
            app.persist_settings();
            app.log(if enable {
                "Outgoing encryption on: Kalo receivers with the same passphrase can open these files."
                    .to_string()
            } else {
                "Outgoing encryption off: files are sent as standard OPP objects.".to_string()
            });
            Task::none()
        }
        Message::EncryptionPassphraseChanged(passphrase) => {
            app.passphrase_draft = passphrase;
            Task::none()
        }
        Message::SaveEncryptionPassphrase => {
            let passphrase = std::mem::take(&mut app.passphrase_draft);
            if passphrase.is_empty() {
                app.log("Type a shared passphrase first, or use Clear to remove the saved one.");
                return Task::none();
            }
            if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
                app.passphrase_draft = passphrase;
                app.log(format!(
                    "The encryption passphrase must be at least {MIN_PASSPHRASE_CHARS} characters."
                ));
                return Task::none();
            }
            app.encryption.set_passphrase(passphrase.clone());
            app.settings.encryption_passphrase = passphrase;
            app.settings.encrypt_sends = app.encryption.enabled();
            app.persist_settings();
            app.log(
                "Encryption passphrase saved. Incoming Kalo containers are decrypted automatically.",
            );
            Task::none()
        }
        Message::ClearEncryptionPassphrase => {
            app.passphrase_draft.clear();
            app.encryption.set_passphrase(String::new());
            app.encryption.set_enabled(false);
            app.settings.encryption_passphrase.clear();
            app.settings.encrypt_sends = false;
            app.persist_settings();
            app.log("Encryption passphrase cleared; outgoing encryption is off.");
            Task::none()
        }
        Message::PickSaveFolder => {
            if app.picking_folder {
                return Task::none();
            }
            app.picking_folder = true;
            let current = app.save_dir.get();
            Task::perform(
                async move {
                    let mut dialog = rfd::AsyncFileDialog::new()
                        .set_title("Choose where incoming files are saved");
                    if current.is_dir() {
                        dialog = dialog.set_directory(current);
                    }
                    dialog
                        .pick_folder()
                        .await
                        .map(|handle| handle.path().to_path_buf())
                },
                Message::SaveFolderPicked,
            )
        }
        Message::SaveFolderPicked(folder) => {
            app.picking_folder = false;
            if let Some(folder) = folder {
                app.save_dir.set(folder.clone());
                app.settings.save_dir = Some(folder.clone());
                app.persist_settings();
                app.last_saved = None;
                app.log(format!("Incoming files now save to {}", folder.display()));
            }
            Task::none()
        }
        Message::OpenPath(path) => {
            if let Err(error) = paths::open_folder(&path) {
                app.log(format!("Couldn't open {}: {error:#}", path.display()));
            }
            Task::none()
        }
        Message::AuthorizationResponse {
            id,
            allow,
            remember,
        } => {
            let sender = app
                .pending_authorizations
                .iter()
                .find(|prompt| prompt.id == id)
                .map(|prompt| prompt.sender.clone())
                .unwrap_or_else(|| "the sender".to_string());
            if app.authorizer.respond(&id, allow, remember) {
                app.log(format!(
                    "{} incoming file from {sender}",
                    if allow { "Allowed" } else { "Declined" }
                ));
            } else {
                app.log("that approval request is no longer pending");
            }
            app.pending_authorizations.retain(|prompt| prompt.id != id);
            Task::none()
        }
        Message::RemoveTrustedSender(address) => {
            match app.trust.remove(&address) {
                Ok(()) => app.log(format!("Removed {address} from trusted senders")),
                Err(error) => app.log(format!("Couldn't update trusted senders: {error:#}")),
            }
            Task::none()
        }
        Message::SetIncomingPolicy(policy) => {
            if app.trust.policy() == policy {
                return Task::none();
            }
            match app.trust.set_policy(policy) {
                Ok(()) => app.log(match policy {
                    IncomingPolicy::Ask => "New senders will be approved in Kalo",
                    IncomingPolicy::TrustedOnly => {
                        "New senders will be blocked; only trusted senders can send"
                    }
                }),
                Err(error) => app.log(format!("Couldn't save the incoming policy: {error:#}")),
            }
            Task::none()
        }
        Message::ToggleTrustList => {
            app.show_trust = !app.show_trust;
            Task::none()
        }
        Message::PollTray => {
            let tasks: Vec<Task<Message>> = crate::tray::poll()
                .into_iter()
                .map(|action| match action {
                    crate::tray::TrayAction::Show => Task::done(Message::TrayShow),
                    crate::tray::TrayAction::Quit => Task::done(Message::TrayQuit),
                })
                .collect();
            Task::batch(tasks)
        }
        Message::TrayShow => show_window(),
        Message::TrayQuit => iced::exit(),
        Message::WindowCloseRequested(id) => {
            if app.tray_ready {
                iced::window::set_mode(id, iced::window::Mode::Hidden)
            } else {
                iced::exit()
            }
        }
        Message::Event(event) => handle_event(app, event),
    }
}

fn handle_event(app: &mut App, event: Event) -> Task<Message> {
    match event {
        Event::Log(line) => app.log(line),
        Event::SendFileStarted {
            send_id,
            index,
            total,
            name,
        } => {
            let Some(active) = app.active_send.as_mut().filter(|send| send.id == send_id) else {
                return Task::none();
            };
            active.index = index;
            active.total = total;
            active.current = name;
            // A new file gets a fresh bar; keeping the previous file's
            // fraction would look like the next file already made progress.
            active.progress = None;
        }
        Event::SendProgress {
            send_id,
            transferred,
            size,
            status,
        } => {
            let Some(active) = app.active_send.as_mut().filter(|send| send.id == send_id) else {
                return Task::none();
            };
            let fraction = size
                .filter(|s| *s > 0)
                .map(|s| (transferred as f32 / s as f32).clamp(0.0, 1.0));
            active.progress = Some(SendProgressUi {
                fraction,
                detail: send_progress_summary(transferred, size, &status),
            });
        }
        Event::IncomingAuthorization {
            id,
            sender,
            address,
            name,
            size,
            stable,
        } => {
            let sender = sender_name(&app.devices, &address, &sender);
            let size_note = size
                .map(|size| format!(" ({})", format_bytes(size)))
                .unwrap_or_default();
            app.log(format!(
                "Incoming from {sender}{size_note}: waiting for approval"
            ));
            let prompt = AuthPromptUi {
                id: id.clone(),
                sender,
                address,
                name,
                size,
                stable,
            };
            if let Some(existing) = app
                .pending_authorizations
                .iter_mut()
                .find(|prompt| prompt.id == id)
            {
                *existing = prompt;
            } else {
                app.pending_authorizations.push(prompt);
            }
        }
        Event::IncomingStarted {
            id,
            sender,
            name,
            size,
        } => {
            let size_note = size
                .map(|s| format!(" ({})", format_bytes(s)))
                .unwrap_or_default();
            app.log(format!("Incoming from {sender}: {name}{size_note}"));
            let entry = IncomingUi {
                id: id.clone(),
                sender,
                name,
                transferred: 0,
                size,
            };
            if let Some(existing) = app.incoming.iter_mut().find(|item| item.id == id) {
                *existing = entry;
            } else {
                app.incoming.push(entry);
            }
        }
        Event::IncomingProgress {
            id,
            name,
            transferred,
            size,
        } => {
            if let Some(item) = app.incoming.iter_mut().find(|item| item.id == id) {
                item.name = name;
                item.transferred = transferred.unwrap_or(item.transferred);
                item.size = size.or(item.size);
            } else {
                app.incoming.push(IncomingUi {
                    id,
                    sender: String::new(),
                    name,
                    transferred: transferred.unwrap_or(0),
                    size,
                });
            }
        }
        Event::IncomingDone {
            id,
            sender,
            name,
            saved_to,
            bytes,
            elapsed_secs,
            mbps,
            partial,
        } => {
            app.incoming.retain(|item| item.id != id);
            app.pending_authorizations.retain(|prompt| prompt.id != id);
            app.last_saved = Some(SavedUi {
                name: name.clone(),
                path: saved_to.clone(),
                partial,
            });
            if partial {
                app.log(format!(
                    "Recovered partial {name} from {sender} → {} · {} in {elapsed_secs:.1}s ({mbps:.1} MB/s)",
                    saved_to.display(),
                    format_bytes(bytes)
                ));
            } else {
                app.log(format!(
                    "Saved {name} from {sender} → {} · {} in {elapsed_secs:.1}s ({mbps:.1} MB/s)",
                    saved_to.display(),
                    format_bytes(bytes)
                ));
            }
        }
        Event::IncomingFailed {
            id,
            sender,
            name,
            error,
            staged_at,
        } => {
            app.incoming.retain(|item| item.id != id);
            app.pending_authorizations.retain(|prompt| prompt.id != id);
            app.log(format!("Incoming failed from {sender} ({name}): {error}"));
            if let Some(path) = staged_at {
                app.log(format!("  staged file kept at {}", path.display()));
            }
        }
        Event::ReceiverState(state) => {
            let line = match &state {
                ReceiverStatus::Starting => "Receiver starting…".to_string(),
                ReceiverStatus::Active => {
                    "Receiver ready. Incoming files save to your save folder.".to_string()
                }
                ReceiverStatus::Off(reason) => format!("Receiver unavailable: {reason}"),
            };
            app.receiver_state = state;
            app.log(line);
        }
    }
    Task::none()
}

fn show_window() -> Task<Message> {
    iced::window::latest().and_then(|id| {
        Task::batch([
            iced::window::set_mode(id, iced::window::Mode::Windowed),
            iced::window::gain_focus(id),
        ])
    })
}

fn subscription(app: &App) -> Subscription<Message> {
    let close_requests = iced::window::close_requests().map(Message::WindowCloseRequested);
    if app.demo {
        return close_requests;
    }
    let events = Subscription::run(|| {
        iced::stream::channel(
            100,
            |mut out: futures::channel::mpsc::Sender<Message>| async move {
                let Some(bus) = EVENT_BUS.get() else {
                    return;
                };
                // A broadcast subscription can be re-created without
                // consuming the bus, unlike the old one-shot receiver.
                let mut events = bus.sink.subscribe();
                let initial = bus.receiver.status();
                if out
                    .send(Message::Event(Event::ReceiverState(initial)))
                    .await
                    .is_err()
                {
                    return;
                }
                bus.ensure_receiver_started();

                loop {
                    match events.recv().await {
                        Ok(event) => {
                            if out.send(Message::Event(event)).await.is_err() {
                                return;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(dropped)) => {
                            let note = Event::Log(format!(
                                "UI event stream lagged: {dropped} events dropped; state may be stale"
                            ));
                            if out.send(Message::Event(note)).await.is_err() {
                                return;
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    }
                }
            },
        )
    });
    Subscription::batch([
        events,
        close_requests,
        iced::time::every(Duration::from_millis(300)).map(|_| Message::PollTray),
    ])
}

fn view(app: &App) -> Element<'_, Message> {
    let p = ui::palette(app.settings.theme);
    let is_sending = app.is_sending();
    let target = resolve_target(&app.devices, app.selected.as_deref());

    let theme_button = button(
        text(match app.settings.theme {
            ThemeKind::Dark => "☀ Light",
            ThemeKind::Light => "☾ Dark",
        })
        .size(11.5)
        .font(ui::MEDIUM),
    )
    .padding([6, 11])
    .style(ui::secondary_button)
    .on_press(Message::ToggleTheme);

    let header = row![
        row![
            brand_mark(p),
            column![
                text("Kalo").size(22).font(ui::BOLD).color(p.text),
                text("Bluetooth file transfer")
                    .size(11.5)
                    .color(p.text_muted),
            ]
            .spacing(0),
        ]
        .spacing(11)
        .align_y(Alignment::Center),
        space().width(Length::Fill),
        theme_button,
        receiver_summary(&app.receiver_state, &app.save_dir.get(), p),
    ]
    .spacing(10)
    .width(Length::Fill)
    .align_y(Alignment::Center);

    let hero = container(
        row![
            column![
                text("Send files over Bluetooth.")
                    .size(30)
                    .font(ui::BOLD)
                    .color(p.text),
                text(
                    "Choose a compatible device, pick a file, and send it directly. \
                     No cloud upload or account required."
                )
                .size(13)
                .color(p.text_secondary),
                row![
                    chip("Direct Bluetooth", p),
                    chip("No sign-in", p),
                    chip("You choose the folder", p),
                ]
                .spacing(8),
            ]
            .spacing(9)
            .width(Length::Fill),
            transfer_orb(p),
        ]
        .spacing(24)
        .align_y(Alignment::Center),
    )
    .padding([19, 24])
    .width(Length::Fill)
    .style(ui::hero);

    let device_rows: Vec<Element<'_, Message>> = app
        .devices
        .iter()
        .map(|device| {
            let selected = app
                .selected
                .as_deref()
                .is_some_and(|address| address.eq_ignore_ascii_case(&device.address));
            device_button(device, selected, !is_sending, p)
        })
        .collect();

    let device_list: Element<'_, Message> = if app.devices.is_empty() {
        device_empty_state(app.devices_loaded, app.devices_error.as_deref(), p)
    } else {
        scrollable(column(device_rows).spacing(8).width(Length::Fill))
            .height(Length::Fill)
            .into()
    };

    let mut device_section = column![
        row![
            step_label("1", "Choose a device", p),
            space().width(Length::Fill),
            button(
                text(if app.devices_loading {
                    "Refreshing…"
                } else {
                    "Refresh list"
                })
                .size(11.5)
                .font(ui::MEDIUM),
            )
            .padding([5, 10])
            .style(ui::secondary_button)
            .on_press_maybe((!app.devices_loading).then_some(Message::RefreshDevices)),
        ]
        .width(Length::Fill)
        .align_y(Alignment::Center),
    ]
    .spacing(9)
    .height(Length::Fill);
    if let Some(error) = app.devices_error.as_deref()
        && !app.devices.is_empty()
    {
        device_section = device_section.push(
            text(format!("Couldn't refresh: {error}"))
                .size(11.5)
                .color(p.danger_text),
        );
    }
    device_section = device_section.push(device_list);

    let (file_title, file_detail) = match app.selection.as_ref() {
        Some(selection) if selection.file_count() == 1 => {
            let path = &selection.files[0];
            let detail = path
                .parent()
                .map(folder_label)
                .filter(|folder| !folder.is_empty())
                .map(|folder| format!("{folder} · {}", format_bytes(selection.total_bytes)))
                .unwrap_or_else(|| format_bytes(selection.total_bytes));
            (file_name(path), detail)
        }
        Some(selection) => {
            let folder = selection
                .files
                .first()
                .and_then(|file| file.parent())
                .map(folder_label)
                .filter(|folder| !folder.is_empty());
            let detail = match folder {
                Some(folder) => format!(
                    "{} files from {folder} · {}",
                    selection.file_count(),
                    format_bytes(selection.total_bytes)
                ),
                None => format!(
                    "{} files · {}",
                    selection.file_count(),
                    format_bytes(selection.total_bytes)
                ),
            };
            (format!("{} files selected", selection.file_count()), detail)
        }
        None => (
            "No files selected".to_string(),
            "Pick one file, several files, or a whole folder.".to_string(),
        ),
    };
    let has_selection = app.selection.is_some();
    let file_info = column![
        text(file_title)
            .size(13.5)
            .font(if has_selection {
                ui::SEMIBOLD
            } else {
                Font::DEFAULT
            })
            .color(if has_selection {
                p.text
            } else {
                p.text_secondary
            }),
        text(file_detail).size(11).color(p.text_muted),
    ]
    .spacing(2)
    .width(Length::Fill);

    let choosing = app.picking_selection;
    let file_zone = container(
        row![
            container(text("↥").size(18).font(ui::BOLD).color(p.accent_text))
                .width(38)
                .height(38)
                .center(38)
                .style(ui::icon_tile),
            file_info,
            column![
                button(
                    text(if choosing { "Choosing…" } else { "Files…" })
                        .size(12)
                        .font(ui::MEDIUM)
                )
                .padding([5, 10])
                .style(ui::secondary_button)
                .on_press_maybe((!is_sending && !choosing).then_some(Message::PickFiles)),
                button(text("Folder…").size(12).font(ui::MEDIUM))
                    .padding([5, 10])
                    .style(ui::secondary_button)
                    .on_press_maybe((!is_sending && !choosing).then_some(Message::PickFolder)),
            ]
            .spacing(4),
        ]
        .spacing(12)
        .align_y(Alignment::Center),
    )
    .padding([11, 12])
    .width(Length::Fill)
    .style(ui::inset);

    let file_section =
        column![step_label("2", "Choose files or a folder", p), file_zone,].spacing(9);

    let send_panel = container(
        column![
            column![
                text("Send files").size(20).font(ui::SEMIBOLD).color(p.text),
                text("Select a Bluetooth device, then send files or a folder.")
                    .size(12)
                    .color(p.text_secondary),
            ]
            .spacing(3),
            device_section,
            rule::horizontal(1).style(ui::divider),
            file_section,
            send_action(app, target),
        ]
        .spacing(15)
        .height(Length::Fill),
    )
    .padding(20)
    .width(Length::FillPortion(3))
    .height(Length::Fill)
    .style(ui::panel);

    let mut incoming_header = row![
        text("Incoming files")
            .size(19)
            .font(ui::SEMIBOLD)
            .color(p.text),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    if !app.incoming.is_empty() {
        incoming_header = incoming_header.push(
            text(format!("{} active", app.incoming.len()))
                .size(10.5)
                .font(ui::BOLD)
                .color(p.accent_text),
        );
    }
    incoming_header = incoming_header.push(space().width(Length::Fill)).push(
        button(
            text(if app.show_trust {
                "Hide senders"
            } else {
                "Senders"
            })
            .size(10.5)
            .font(ui::MEDIUM),
        )
        .padding([5, 9])
        .style(ui::policy_button(app.show_trust))
        .on_press(Message::ToggleTrustList),
    );

    let mut incoming_body = column![].spacing(9).width(Length::Fill);
    for prompt in &app.pending_authorizations {
        incoming_body = incoming_body.push(auth_prompt(prompt, p));
    }
    if let ReceiverStatus::Off(reason) = &app.receiver_state {
        incoming_body = incoming_body.push(receiver_notice(reason, p));
    }
    if app.incoming.is_empty() {
        if !matches!(app.receiver_state, ReceiverStatus::Off(_)) {
            incoming_body =
                incoming_body.push(incoming_empty(&app.receiver_state, &app.save_dir.get(), p));
        }
    } else {
        let height = (app.incoming.len() as f32 * 58.0).clamp(58.0, 150.0);
        incoming_body = incoming_body.push(
            scrollable(
                column(
                    app.incoming
                        .iter()
                        .map(|item| incoming_row(item, p))
                        .collect::<Vec<Element<'_, Message>>>(),
                )
                .spacing(8)
                .width(Length::Fill),
            )
            .height(Length::Fixed(height)),
        );
    }
    if let Some(saved) = &app.last_saved {
        incoming_body = incoming_body.push(saved_banner(saved, p));
    }
    incoming_body = incoming_body.push(save_folder_row(&app.save_dir.get(), app.picking_folder, p));
    incoming_body = incoming_body.push(encryption_row(&app.encryption, &app.passphrase_draft, p));
    if app.show_trust {
        incoming_body = incoming_body.push(trust_panel(
            app.trust.entries(),
            app.trust.policy(),
            &app.devices,
            p,
        ));
    }

    let activity: Element<'_, Message> = if app.log.is_empty() {
        container(
            column![
                text("No transfer activity yet")
                    .size(13)
                    .font(ui::MEDIUM)
                    .color(p.text),
                text("Transfer updates, receiver status, and errors appear here.")
                    .size(11.5)
                    .color(p.text_secondary),
            ]
            .spacing(3),
        )
        .padding(13)
        .width(Length::Fill)
        .style(ui::inset)
        .into()
    } else {
        let rows: Vec<Element<'_, Message>> = app
            .log
            .iter()
            .rev()
            .map(|line| {
                row![
                    container(space())
                        .width(5)
                        .height(5)
                        .style(ui::dot(p.accent)),
                    text(line.clone())
                        .size(11.5)
                        .line_height(1.4)
                        .color(p.text_secondary)
                        .width(Length::Fill),
                ]
                .spacing(9)
                .align_y(Alignment::Start)
                .into()
            })
            .collect();
        scrollable(column(rows).spacing(9).width(Length::Fill))
            .height(Length::Fill)
            .into()
    };

    let activity_block = column![
        row![
            text("Transfer activity")
                .size(19)
                .font(ui::SEMIBOLD)
                .color(p.text),
            space().width(Length::Fill),
            text(format!("{} entries", app.log.len()))
                .size(10.5)
                .color(p.text_muted),
        ]
        .align_y(Alignment::Center),
        activity,
    ]
    .spacing(10)
    .height(Length::Fill);

    let incoming_card = container(
        column![incoming_header, incoming_body]
            .spacing(10)
            .width(Length::Fill),
    )
    .padding(18)
    .width(Length::Fill)
    .style(ui::panel);

    let activity_card = container(activity_block)
        .padding(18)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(ui::panel);

    let right_panel = column![incoming_card, activity_card]
        .spacing(16)
        .width(Length::FillPortion(2))
        .height(Length::Fill);

    let body = row![send_panel, right_panel]
        .spacing(16)
        .width(Length::Fill)
        .height(Length::Fill);

    container(
        column![header, hero, body]
            .spacing(16)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .padding(Padding::from([22, 26]))
    .width(Length::Fill)
    .height(Length::Fill)
    .style(ui::canvas)
    .into()
}

fn brand_mark<'a>(_p: &ui::Palette) -> Element<'a, Message> {
    // The in-app mark is the shipped 256 px icon, so the window, tray, desktop
    // entry and app all show the same artwork. The gradient tile behind it
    // keeps the white "K" readable in the light theme.
    static MARK: OnceLock<image_widget::Handle> = OnceLock::new();
    let mark = MARK
        .get_or_init(|| {
            image_widget::Handle::from_bytes(
                include_bytes!("../packaging/common/icons/hicolor/256x256/apps/kalo.png")
                    .as_slice(),
            )
        })
        .clone();
    container(
        image_widget(mark)
            .width(Length::Fixed(26.0))
            .height(Length::Fixed(26.0))
            .content_fit(ContentFit::Contain),
    )
    .width(40)
    .height(40)
    .center(40)
    .style(ui::brand)
    .into()
}

fn chip<'a>(label: &'a str, p: &ui::Palette) -> Element<'a, Message> {
    container(
        text(label)
            .size(10.5)
            .font(ui::MEDIUM)
            .color(p.text_secondary),
    )
    .padding([4, 9])
    .style(ui::chip)
    .into()
}

fn step_label<'a>(step: &'a str, label: &'a str, p: &ui::Palette) -> Element<'a, Message> {
    row![
        container(text(step).size(10).font(ui::BOLD).color(p.on_accent))
            .width(20)
            .height(20)
            .center(20)
            .style(ui::step_badge),
        text(label)
            .size(12.5)
            .font(ui::SEMIBOLD)
            .color(p.text_secondary),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

/// A quiet orbit graphic for the hero: rings read as "nearby devices" without
/// adding another moving part to the interface.
fn transfer_orb<'a>(p: &ui::Palette) -> Element<'a, Message> {
    container(
        container(
            container(text("⇄").size(25).font(ui::BOLD).color(p.accent_text))
                .width(54)
                .height(54)
                .center(54)
                .style(ui::orb_core),
        )
        .width(76)
        .height(76)
        .center(76)
        .style(ui::orb_ring),
    )
    .width(96)
    .height(96)
    .center(96)
    .style(ui::orb_outer)
    .into()
}

fn receiver_summary(
    state: &ReceiverStatus,
    save_dir: &Path,
    p: &ui::Palette,
) -> Element<'static, Message> {
    let (label, detail, dot, tint, text_color) = match state {
        ReceiverStatus::Starting => (
            "Starting Bluetooth receiver",
            "Incoming files will be ready shortly".to_string(),
            p.warning,
            p.warning_tint,
            p.warning_text,
        ),
        ReceiverStatus::Active => (
            "Ready to receive",
            format!("Files save to {}", folder_label(save_dir)),
            p.success,
            p.success_tint,
            p.success_text,
        ),
        ReceiverStatus::Off(_) => (
            "Receiving unavailable",
            "Incoming files are unavailable".to_string(),
            p.danger,
            p.danger_tint,
            p.danger_text,
        ),
    };
    let detail_color = if matches!(state, ReceiverStatus::Off(_)) {
        p.danger_text
    } else {
        p.text_muted
    };

    container(
        column![
            row![
                container(space()).width(7).height(7).style(ui::dot(dot)),
                text(label).size(11.5).font(ui::SEMIBOLD).color(text_color),
            ]
            .spacing(7)
            .align_y(Alignment::Center),
            text(detail).size(10.5).color(detail_color),
        ]
        .spacing(2),
    )
    .padding([7, 12])
    .style(ui::pill(tint))
    .into()
}

fn device_button<'a>(
    device: &'a DeviceInfo,
    selected: bool,
    enabled: bool,
    p: &ui::Palette,
) -> Element<'a, Message> {
    let mut meta = row![
        text(&device.address)
            .size(11)
            .font(ui::MONO)
            .color(p.text_muted),
    ]
    .spacing(6)
    .align_y(Alignment::Center);
    if device.connected {
        meta = meta.push(badge("Connected", p.success_tint, p.success_text));
    }
    if !device.paired {
        meta = meta.push(badge("Not paired", p.warning_tint, p.warning_text));
    }

    let avatar = container(
        text(device_initial(device))
            .size(14)
            .font(ui::BOLD)
            .color(if selected { p.on_accent } else { p.accent_text }),
    )
    .width(34)
    .height(34)
    .center(34)
    .style(ui::avatar(selected));

    let trailing: Element<'_, Message> = if selected {
        container(text("✓").size(11).font(ui::BOLD).color(p.on_accent))
            .width(21)
            .height(21)
            .center(21)
            .style(ui::fill(p.accent, 999.0))
            .into()
    } else {
        text("Select").size(11).color(p.text_muted).into()
    };

    let content = row![
        avatar,
        column![
            text(device_name(device))
                .size(13.5)
                .font(ui::SEMIBOLD)
                .color(if enabled { p.text } else { p.text_secondary }),
            meta,
        ]
        .spacing(2)
        .width(Length::Fill),
        trailing,
    ]
    .spacing(11)
    .align_y(Alignment::Center)
    .width(Length::Fill);

    button(content)
        .width(Length::Fill)
        .padding([8, 10])
        .style(ui::device_row(selected))
        .on_press_maybe(enabled.then(|| Message::PickDevice(device.address.clone())))
        .into()
}

fn device_initial(device: &DeviceInfo) -> String {
    device_name(device)
        .chars()
        .next()
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "B".to_string())
}

fn badge(label: &str, background: Color, text_color: Color) -> Element<'_, Message> {
    container(text(label).size(10).font(ui::SEMIBOLD).color(text_color))
        .padding([1, 6])
        .style(ui::fill(background, 999.0))
        .into()
}

fn device_empty_state<'a>(
    loaded: bool,
    error: Option<&'a str>,
    p: &ui::Palette,
) -> Element<'a, Message> {
    let content: Element<'_, Message> = if !loaded {
        column![
            text("Loading Bluetooth devices…")
                .size(13)
                .font(ui::MEDIUM)
                .color(p.text),
            text("This usually takes a moment.")
                .size(11.5)
                .color(p.text_secondary),
        ]
        .spacing(4)
        .into()
    } else if let Some(error) = error {
        column![
            text("Couldn't load Bluetooth devices")
                .size(13)
                .font(ui::MEDIUM)
                .color(p.danger_text),
            text(error).size(11.5).color(p.text_secondary),
            text("Choose Refresh list to try again.")
                .size(11)
                .color(p.text_muted),
        ]
        .spacing(3)
        .into()
    } else {
        column![
            text("No known Bluetooth devices")
                .size(13)
                .font(ui::MEDIUM)
                .color(p.text),
            text("Pair a device in your system's Bluetooth settings, then refresh this list.")
                .size(11.5)
                .color(p.text_secondary),
        ]
        .spacing(4)
        .into()
    };

    container(content)
        .padding(14)
        .width(Length::Fill)
        .style(ui::inset)
        .into()
}

fn receiver_notice<'a>(reason: &'a str, p: &ui::Palette) -> Element<'a, Message> {
    container(
        column![
            text("Receiving unavailable")
                .size(12)
                .font(ui::SEMIBOLD)
                .color(p.danger_text),
            text(reason).size(11).color(p.text_secondary),
            text(
                "Kalo will retry automatically. If this continues, check Bluetooth services \
                 or other transfer apps."
            )
            .size(11)
            .color(p.text_muted),
        ]
        .spacing(3),
    )
    .padding(12)
    .width(Length::Fill)
    .style(ui::notice)
    .into()
}

fn incoming_empty<'a>(
    state: &ReceiverStatus,
    save_dir: &Path,
    p: &ui::Palette,
) -> Element<'a, Message> {
    let detail = match state {
        ReceiverStatus::Starting => "The receiver is starting. Incoming files will appear here.",
        _ => "Incoming transfers appear here.",
    };
    let save_note = format!("Saving to {}", folder_label(save_dir));

    container(
        row![
            container(text("↓").size(16).font(ui::BOLD).color(p.text_muted))
                .width(34)
                .height(34)
                .center(34)
                .style(ui::icon_tile_muted),
            column![
                text("No incoming transfers")
                    .size(12.5)
                    .font(ui::MEDIUM)
                    .color(p.text),
                text(detail).size(11).color(p.text_secondary),
                text(save_note).size(10.5).color(p.text_muted),
            ]
            .spacing(2)
            .width(Length::Fill),
        ]
        .spacing(11)
        .align_y(Alignment::Center),
    )
    .padding(12)
    .width(Length::Fill)
    .style(ui::inset)
    .into()
}

fn incoming_row<'a>(item: &'a IncomingUi, p: &ui::Palette) -> Element<'a, Message> {
    let fraction = transfer_fraction(item.transferred, item.size);
    let percent = fraction.map(|fraction| format!("{:.0}%", fraction * 100.0));
    let from = if item.sender.is_empty() {
        "Incoming file".to_string()
    } else {
        format!("From {}", item.sender)
    };
    let amount = match item.size {
        Some(size) if size > 0 => format!(
            "{} of {}",
            format_bytes(item.transferred),
            format_bytes(size)
        ),
        _ => format!("{} received", format_bytes(item.transferred)),
    };
    let name = if item.name.is_empty() {
        "Unnamed file"
    } else {
        item.name.as_str()
    };

    let mut title = row![
        text(name)
            .size(13)
            .font(ui::MEDIUM)
            .color(p.text)
            .width(Length::Fill),
    ]
    .spacing(10)
    .align_y(Alignment::Center);
    if let Some(percent) = percent {
        title = title.push(
            text(percent)
                .size(11.5)
                .font(ui::SEMIBOLD)
                .color(p.accent_text),
        );
    }

    let mut content = column![
        title,
        text(format!("{from} · {amount}"))
            .size(11)
            .color(p.text_secondary)
            .width(Length::Fill),
    ]
    .spacing(4);
    if let Some(fraction) = fraction {
        content = content.push(
            progress_bar(0.0..=1.0, fraction)
                .girth(Length::Fixed(5.0))
                .style(ui::progress),
        );
    }

    container(
        row![
            container(text("↓").size(14).font(ui::BOLD).color(p.accent_text))
                .width(32)
                .height(32)
                .center(32)
                .style(ui::icon_tile),
            content.width(Length::Fill),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    )
    .padding(10)
    .width(Length::Fill)
    .style(ui::inset)
    .into()
}

fn auth_prompt(prompt: &AuthPromptUi, p: &ui::Palette) -> Element<'static, Message> {
    let id = prompt.id.clone();
    let size = prompt
        .size
        .map(|size| format!(" · {}", format_bytes(size)))
        .unwrap_or_default();
    let meta = if prompt.stable {
        if prompt.sender.eq_ignore_ascii_case(&prompt.address) {
            format!("Bluetooth device {}{size}", prompt.address)
        } else {
            format!("{} · {}{size}", prompt.sender, prompt.address)
        }
    } else {
        format!("{} · Bluetooth address unavailable{size}", prompt.sender)
    };

    let allow = button(text("Allow once").size(10.5).font(ui::MEDIUM))
        .padding([5, 8])
        .style(ui::primary_button)
        .on_press(Message::AuthorizationResponse {
            id: id.clone(),
            allow: true,
            remember: false,
        });
    let decline = button(text("Decline").size(10.5).font(ui::MEDIUM))
        .padding([5, 8])
        .style(ui::secondary_button)
        .on_press(Message::AuthorizationResponse {
            id: id.clone(),
            allow: false,
            remember: false,
        });
    let mut actions = row![allow, decline].spacing(6);
    if prompt.stable {
        actions = actions
            .push(
                button(text("Always allow").size(10.5).font(ui::MEDIUM))
                    .padding([5, 8])
                    .style(ui::secondary_button)
                    .on_press(Message::AuthorizationResponse {
                        id: id.clone(),
                        allow: true,
                        remember: true,
                    }),
            )
            .push(
                button(text("Block").size(10.5).font(ui::MEDIUM))
                    .padding([5, 8])
                    .style(ui::danger_button)
                    .on_press(Message::AuthorizationResponse {
                        id,
                        allow: false,
                        remember: true,
                    }),
            );
    }

    container(
        column![
            row![
                container(text("?").size(14).font(ui::BOLD).color(p.warning_text))
                    .width(30)
                    .height(30)
                    .center(30)
                    .style(ui::warning_tile),
                column![
                    text(format!("Approve {}?", prompt.name))
                        .size(12.5)
                        .font(ui::SEMIBOLD)
                        .color(p.text),
                    text(meta).size(10.5).color(p.text_muted),
                ]
                .spacing(2)
                .width(Length::Fill),
            ]
            .spacing(9)
            .align_y(Alignment::Center),
            actions,
        ]
        .spacing(9),
    )
    .padding(11)
    .width(Length::Fill)
    .style(ui::prompt)
    .into()
}

fn saved_banner(saved: &SavedUi, p: &ui::Palette) -> Element<'static, Message> {
    let folder = saved
        .path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| saved.path.clone());
    let title = if saved.partial {
        format!("Partial file kept: {}", saved.name)
    } else {
        format!("Saved {}", saved.name)
    };
    let detail = match saved.path.parent() {
        Some(parent) => folder_label(parent),
        None => folder.display().to_string(),
    };

    container(
        row![
            container(text("✓").size(12).font(ui::BOLD).color(p.success_text))
                .width(26)
                .height(26)
                .center(26)
                .style(ui::success_tile),
            column![
                text(title)
                    .size(11.5)
                    .font(ui::MEDIUM)
                    .color(p.success_text),
                text(detail).size(10).color(p.text_muted),
            ]
            .spacing(1)
            .width(Length::Fill),
            button(text("Open folder").size(10.5).font(ui::MEDIUM))
                .padding([5, 9])
                .style(ui::secondary_button)
                .on_press(Message::OpenPath(folder)),
        ]
        .spacing(9)
        .align_y(Alignment::Center),
    )
    .padding([7, 9])
    .width(Length::Fill)
    .style(ui::success_panel)
    .into()
}

fn save_folder_row<'a>(save_dir: &Path, picking: bool, p: &ui::Palette) -> Element<'a, Message> {
    container(
        row![
            text("Save to").size(10.5).color(p.text_muted),
            text(short_path(save_dir))
                .size(10.5)
                .font(ui::MONO)
                .color(p.text_secondary)
                .width(Length::Fill),
            button(
                text(if picking { "Choosing…" } else { "Change…" })
                    .size(10.5)
                    .font(ui::MEDIUM)
            )
            .padding([4, 8])
            .style(ui::secondary_button)
            .on_press_maybe((!picking).then_some(Message::PickSaveFolder)),
            button(text("Open").size(10.5).font(ui::MEDIUM))
                .padding([4, 8])
                .style(ui::secondary_button)
                .on_press(Message::OpenPath(save_dir.to_path_buf())),
        ]
        .spacing(7)
        .align_y(Alignment::Center),
    )
    .padding([6, 9])
    .width(Length::Fill)
    .style(ui::inset)
    .into()
}

fn encryption_row<'a>(
    encryption: &Encryption,
    draft: &'a str,
    p: &ui::Palette,
) -> Element<'a, Message> {
    let enabled = encryption.enabled();
    let configured = encryption.is_configured();
    let field = text_input(
        if configured {
            "Replace the shared passphrase…"
        } else {
            "Shared passphrase (12+ characters)"
        },
        draft,
    )
    .secure(true)
    .on_input(Message::EncryptionPassphraseChanged)
    .on_submit(Message::SaveEncryptionPassphrase)
    .padding([5, 8])
    .size(10.5)
    .width(Length::Fill)
    .style(ui::text_field);

    let mut actions = row![
        text("Outgoing encryption")
            .size(9.5)
            .color(p.text_muted)
            .width(Length::Fill),
        button(
            text(if enabled { "On" } else { "Off" })
                .size(10)
                .font(ui::MEDIUM)
        )
        .padding([3, 8])
        .style(ui::policy_button(enabled))
        .on_press(Message::ToggleEncryption),
        button(text("Save").size(10).font(ui::MEDIUM))
            .padding([3, 8])
            .style(ui::secondary_button)
            .on_press(Message::SaveEncryptionPassphrase),
    ]
    .spacing(6)
    .align_y(Alignment::Center);
    if configured {
        actions = actions.push(
            button(text("Clear").size(10).font(ui::MEDIUM))
                .padding([3, 8])
                .style(ui::secondary_button)
                .on_press(Message::ClearEncryptionPassphrase),
        );
    }

    container(
        column![
            row![
                text("File encryption")
                    .size(10.5)
                    .font(ui::SEMIBOLD)
                    .color(p.text),
                text(if configured {
                    "passphrase set"
                } else {
                    "no passphrase"
                })
                .size(9.5)
                .color(if configured {
                    p.success_text
                } else {
                    p.text_muted
                }),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
            field,
            actions,
            text(
                "Kalo-to-Kalo only: both devices need the same passphrase. Standard OPP \
                 receivers cannot open encrypted files."
            )
            .size(9.5)
            .color(p.text_muted),
        ]
        .spacing(6),
    )
    .padding([7, 9])
    .width(Length::Fill)
    .style(ui::inset)
    .into()
}

fn trust_panel(
    entries: Vec<(String, crate::trust::TrustEntry)>,
    policy: IncomingPolicy,
    devices: &[DeviceInfo],
    p: &ui::Palette,
) -> Element<'static, Message> {
    let mut list = column![].spacing(5);
    if entries.is_empty() {
        list = list.push(
            text("No trusted or blocked senders yet.")
                .size(10.5)
                .color(p.text_muted),
        );
    }
    for (address, entry) in entries {
        let (label, tint, color) = match entry.decision {
            crate::trust::TrustDecision::Allow => ("Allowed", p.success_tint, p.success_text),
            crate::trust::TrustDecision::Block => ("Blocked", p.danger_tint, p.danger_text),
        };
        let name = sender_name(devices, &address, &entry.name);
        let mut details = column![text(name.clone()).size(11).font(ui::MEDIUM).color(p.text)]
            .spacing(1)
            .width(Length::Fill);
        if !name.eq_ignore_ascii_case(&address) {
            details = details.push(
                text(address.clone())
                    .size(10)
                    .font(ui::MONO)
                    .color(p.text_muted),
            );
        }
        list = list.push(
            row![
                details,
                badge(label, tint, color),
                button(text("Remove").size(10).font(ui::MEDIUM))
                    .padding([3, 7])
                    .style(ui::secondary_button)
                    .on_press(Message::RemoveTrustedSender(address)),
            ]
            .spacing(7)
            .align_y(Alignment::Center),
        );
    }

    container(
        column![
            row![
                text("Incoming senders")
                    .size(11)
                    .font(ui::SEMIBOLD)
                    .color(p.text),
                space().width(Length::Fill),
                button(text("Ask").size(10).font(ui::MEDIUM))
                    .padding([3, 8])
                    .style(ui::policy_button(policy == IncomingPolicy::Ask))
                    .on_press(Message::SetIncomingPolicy(IncomingPolicy::Ask)),
                button(text("Trusted only").size(10).font(ui::MEDIUM))
                    .padding([3, 8])
                    .style(ui::policy_button(policy == IncomingPolicy::TrustedOnly))
                    .on_press(Message::SetIncomingPolicy(IncomingPolicy::TrustedOnly)),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
            text(
                "New senders can be approved in Kalo. Block and allow decisions are remembered \
                 by Bluetooth address."
            )
            .size(10)
            .color(p.text_muted),
            list,
        ]
        .spacing(7),
    )
    .padding(10)
    .width(Length::Fill)
    .style(ui::inset)
    .into()
}

fn folder_label(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| path.display().to_string())
}

/// Keep long save folders readable in the compact footer row.
fn short_path(path: &Path) -> String {
    let text = path.display().to_string();
    let mut parts: Vec<String> = path
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    if text.chars().count() <= 42 || parts.len() <= 2 {
        return text;
    }
    let tail = parts.split_off(parts.len() - 2);
    format!("…/{}/{}", tail[0], tail[1])
}

fn send_action<'a>(app: &'a App, target: Option<&'a DeviceInfo>) -> Element<'a, Message> {
    let p = ui::palette(app.settings.theme);
    if let Some(active) = &app.active_send {
        let progress = active.progress.as_ref();
        let fraction = progress.and_then(|progress| progress.fraction);
        let detail = progress
            .map(|progress| progress.detail.clone())
            .unwrap_or_else(|| "Starting…".to_string());
        let mut top = row![
            text(format!("Sending to {}", active.target))
                .size(13.5)
                .font(ui::SEMIBOLD)
                .color(p.text)
                .width(Length::Fill),
        ]
        .spacing(10)
        .align_y(Alignment::Center);
        if let Some(fraction) = fraction {
            top = top.push(
                text(format!("{:.0}%", fraction * 100.0))
                    .size(12.5)
                    .font(ui::BOLD)
                    .color(p.accent_text),
            );
        }

        let cancel = button(
            text(if active.cancel_requested {
                "Canceling…"
            } else {
                "Cancel"
            })
            .size(11.5)
            .font(ui::MEDIUM),
        )
        .padding([6, 11])
        .style(ui::secondary_button)
        .on_press_maybe((!active.cancel_requested).then_some(Message::CancelSend));

        let bottom = row![
            text(detail)
                .size(11.5)
                .color(p.text_secondary)
                .width(Length::Fill),
            cancel,
        ]
        .spacing(12)
        .align_y(Alignment::Center);

        let current = text(batch_position(active.index, active.total, &active.current))
            .size(11.5)
            .color(p.text_secondary);
        let mut block = column![top, current].spacing(8);
        if let Some(fraction) = fraction {
            block = block.push(
                progress_bar(0.0..=1.0, fraction)
                    .girth(Length::Fixed(6.0))
                    .style(ui::progress),
            );
        }
        return container(block.push(bottom))
            .padding(13)
            .width(Length::Fill)
            .style(ui::active_transfer)
            .into();
    }

    let selected = app
        .selection
        .as_ref()
        .map(Selection::file_count)
        .unwrap_or(0);
    let can_send = target.is_some() && selected > 0 && !app.picking_selection;
    let guidance = match (target.is_some(), selected) {
        (false, 0) => "Select a device and choose files.".to_string(),
        (false, _) => "Select a device to send this selection.".to_string(),
        (true, 0) => "Choose files or a folder to send.".to_string(),
        (true, 1) => "Ready to send 1 file.".to_string(),
        (true, count) => format!("Ready to send {count} files."),
    };
    let send_label = target
        .map(|device| {
            if selected > 1 {
                format!("Send {selected} files to {}", device_name(device))
            } else {
                format!("Send to {}", device_name(device))
            }
        })
        .unwrap_or_else(|| "Send files".to_string());

    let mut block = column![
        container(text(guidance).size(11.5).color(p.text_muted))
            .width(Length::Fill)
            .height(Length::Fixed(18.0))
            .align_y(Alignment::Center),
        button(
            row![
                text(send_label).size(14).font(ui::SEMIBOLD),
                space().width(Length::Fill),
                text("→").size(16).font(ui::BOLD),
            ]
            .align_y(Alignment::Center)
        )
        .width(Length::Fill)
        .padding([11, 15])
        .style(ui::primary_button)
        .on_press_maybe(can_send.then_some(Message::SendClicked)),
    ]
    .spacing(8);
    if let Some(result) = &app.send_result {
        let color = if result.ok {
            p.success_text
        } else {
            p.danger_text
        };
        block = block.push(
            row![
                container(space()).width(7).height(7).style(ui::dot(color)),
                text(&result.message)
                    .size(11.5)
                    .color(color)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        );
    }
    block.into()
}

fn device_name(device: &DeviceInfo) -> &str {
    if device.alias.is_empty() {
        &device.address
    } else {
        &device.alias
    }
}

/// Prefer the friendly name from the loaded device list. Linux authorization
/// events carry only the Bluetooth address, so this keeps prompts and the
/// trust list readable without another backend lookup.
fn sender_name(devices: &[DeviceInfo], address: &str, fallback: &str) -> String {
    devices
        .iter()
        .find(|device| !address.is_empty() && device.address.eq_ignore_ascii_case(address))
        .map(|device| device_name(device).to_string())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn selection_summary(selection: &Selection) -> String {
    match selection.file_count() {
        1 => file_name(&selection.files[0]),
        count => format!("{count} files"),
    }
}

/// Resolve the selected device by address (pure helper, unit-tested):
/// stale selections that no longer match any listed device resolve to
/// `None` instead of pointing at the wrong entry.
fn resolve_target<'a>(devices: &'a [DeviceInfo], selected: Option<&str>) -> Option<&'a DeviceInfo> {
    let address = selected?;
    devices
        .iter()
        .find(|d| d.address.eq_ignore_ascii_case(address))
}

/// Visual system for Kalo. Two palettes share one layout and one set of
/// semantic colors, so a theme switch never changes meaning.
mod ui {
    use std::f32::consts::FRAC_PI_4;

    use iced::font::Weight;
    use iced::gradient;
    use iced::theme::Base;
    use iced::widget::{button, container, progress_bar, rule, text_input};
    use iced::{Background, Border, Color, Font, Shadow, Theme, Vector};

    use crate::settings::ThemeKind;

    /// Every color the interface uses. Style functions receive the active
    /// iced theme, look up the matching palette, and build from these fields.
    pub struct Palette {
        pub canvas: Color,
        pub surface: Color,
        pub surface_alt: Color,
        pub border: Color,
        pub border_strong: Color,
        pub text: Color,
        pub text_secondary: Color,
        pub text_muted: Color,
        pub accent: Color,
        pub accent_blue: Color,
        pub accent_hover: Color,
        pub accent_pressed: Color,
        pub accent_blue_hover: Color,
        pub accent_blue_pressed: Color,
        pub accent_text: Color,
        pub accent_tint: Color,
        pub accent_dim: Color,
        pub on_accent: Color,
        pub row_hover: Color,
        pub row_pressed: Color,
        pub track: Color,
        pub chip: Color,
        pub disabled_bg: Color,
        pub disabled_text: Color,
        pub success: Color,
        pub success_tint: Color,
        pub success_text: Color,
        pub warning: Color,
        pub warning_tint: Color,
        pub warning_text: Color,
        pub danger: Color,
        pub danger_tint: Color,
        pub danger_text: Color,
        pub hero_from: Color,
        pub hero_to: Color,
        pub hero_shadow: Color,
        pub panel_shadow: Color,
        pub notice_border: Color,
        pub brand_shadow: Color,
        pub orb_shadow: Color,
    }

    pub const DARK: Palette = Palette {
        canvas: Color::from_rgb8(0x07, 0x0A, 0x0F),
        surface: Color::from_rgb8(0x0D, 0x12, 0x19),
        surface_alt: Color::from_rgb8(0x11, 0x18, 0x23),
        border: Color::from_rgb8(0x1D, 0x27, 0x35),
        border_strong: Color::from_rgb8(0x2B, 0x3B, 0x4F),
        text: Color::from_rgb8(0xF3, 0xF7, 0xFB),
        text_secondary: Color::from_rgb8(0xA6, 0xB3, 0xC4),
        text_muted: Color::from_rgb8(0x76, 0x85, 0x9A),
        accent: Color::from_rgb8(0x5E, 0xEA, 0xD4),
        accent_blue: Color::from_rgb8(0x60, 0xA5, 0xFA),
        accent_hover: Color::from_rgb8(0x7F, 0xF3, 0xE1),
        accent_pressed: Color::from_rgb8(0x2D, 0xD4, 0xBF),
        accent_blue_hover: Color::from_rgb8(0x8B, 0xC5, 0xFF),
        accent_blue_pressed: Color::from_rgb8(0x38, 0x7B, 0xD9),
        accent_text: Color::from_rgb8(0x7D, 0xF0, 0xDC),
        accent_tint: Color::from_rgb8(0x0D, 0x26, 0x24),
        accent_dim: Color::from_rgb8(0x1C, 0x4A, 0x46),
        on_accent: Color::from_rgb8(0x04, 0x12, 0x0F),
        row_hover: Color::from_rgb8(0x14, 0x1D, 0x29),
        row_pressed: Color::from_rgb8(0x19, 0x24, 0x32),
        track: Color::from_rgb8(0x1A, 0x25, 0x33),
        chip: Color::from_rgb8(0x14, 0x1C, 0x26),
        disabled_bg: Color::from_rgb8(0x16, 0x1E, 0x29),
        disabled_text: Color::from_rgb8(0x64, 0x73, 0x87),
        success: Color::from_rgb8(0x34, 0xD3, 0x99),
        success_tint: Color::from_rgb8(0x0D, 0x28, 0x1F),
        success_text: Color::from_rgb8(0x6E, 0xE7, 0xB7),
        warning: Color::from_rgb8(0xFB, 0xBF, 0x24),
        warning_tint: Color::from_rgb8(0x2A, 0x23, 0x14),
        warning_text: Color::from_rgb8(0xFD, 0xE6, 0x8A),
        danger: Color::from_rgb8(0xFB, 0x71, 0x85),
        danger_tint: Color::from_rgb8(0x2C, 0x15, 0x1B),
        danger_text: Color::from_rgb8(0xFD, 0xA4, 0xAF),
        hero_from: Color::from_rgb8(0x0E, 0x20, 0x26),
        hero_to: Color::from_rgb8(0x0C, 0x12, 0x1B),
        hero_shadow: Color::from_rgba8(0x00, 0x00, 0x00, 0.35),
        panel_shadow: Color::from_rgba8(0x00, 0x00, 0x00, 0.28),
        notice_border: Color::from_rgb8(0x4A, 0x26, 0x30),
        brand_shadow: Color::from_rgba8(0x5E, 0xEA, 0xD4, 0.22),
        orb_shadow: Color::from_rgba8(0x5E, 0xEA, 0xD4, 0.18),
    };

    pub const LIGHT: Palette = Palette {
        canvas: Color::from_rgb8(0xF4, 0xF7, 0xFB),
        surface: Color::from_rgb8(0xFF, 0xFF, 0xFF),
        surface_alt: Color::from_rgb8(0xF7, 0xFA, 0xFD),
        border: Color::from_rgb8(0xE1, 0xE8, 0xF0),
        border_strong: Color::from_rgb8(0xC6, 0xD2, 0xE1),
        text: Color::from_rgb8(0x0B, 0x15, 0x24),
        text_secondary: Color::from_rgb8(0x4A, 0x5B, 0x70),
        text_muted: Color::from_rgb8(0x60, 0x71, 0x87),
        accent: Color::from_rgb8(0x0F, 0x8F, 0x7C),
        accent_blue: Color::from_rgb8(0x25, 0x63, 0xC9),
        accent_hover: Color::from_rgb8(0x12, 0xA5, 0x8F),
        accent_pressed: Color::from_rgb8(0x0A, 0x74, 0x65),
        accent_blue_hover: Color::from_rgb8(0x3B, 0x7B, 0xE0),
        accent_blue_pressed: Color::from_rgb8(0x1D, 0x4F, 0xA8),
        accent_text: Color::from_rgb8(0x0B, 0x6F, 0x60),
        accent_tint: Color::from_rgb8(0xE6, 0xF7, 0xF3),
        accent_dim: Color::from_rgb8(0xB9, 0xE5, 0xDD),
        on_accent: Color::from_rgb8(0xFF, 0xFF, 0xFF),
        row_hover: Color::from_rgb8(0xF0, 0xF5, 0xFA),
        row_pressed: Color::from_rgb8(0xE8, 0xEF, 0xF7),
        track: Color::from_rgb8(0xE4, 0xEB, 0xF3),
        chip: Color::from_rgb8(0xEE, 0xF3, 0xF9),
        disabled_bg: Color::from_rgb8(0xED, 0xF1, 0xF6),
        disabled_text: Color::from_rgb8(0x9A, 0xA8, 0xB8),
        success: Color::from_rgb8(0x0E, 0x9F, 0x6E),
        success_tint: Color::from_rgb8(0xE7, 0xF8, 0xF0),
        success_text: Color::from_rgb8(0x08, 0x7A, 0x51),
        warning: Color::from_rgb8(0xB7, 0x79, 0x1F),
        warning_tint: Color::from_rgb8(0xFF, 0xF6, 0xE0),
        warning_text: Color::from_rgb8(0x8A, 0x5A, 0x00),
        danger: Color::from_rgb8(0xD1, 0x43, 0x5B),
        danger_tint: Color::from_rgb8(0xFD, 0xEB, 0xEE),
        danger_text: Color::from_rgb8(0xA6, 0x1E, 0x36),
        hero_from: Color::from_rgb8(0xEA, 0xF7, 0xF4),
        hero_to: Color::from_rgb8(0xEE, 0xF4, 0xFF),
        hero_shadow: Color::from_rgba8(0x0F, 0x17, 0x2A, 0.10),
        panel_shadow: Color::from_rgba8(0x0F, 0x17, 0x2A, 0.08),
        notice_border: Color::from_rgb8(0xF3, 0xC6, 0xCE),
        brand_shadow: Color::from_rgba8(0x0F, 0x8F, 0x7C, 0.25),
        orb_shadow: Color::from_rgba8(0x0F, 0x8F, 0x7C, 0.15),
    };

    const DARK_NAME: &str = "Kalo Midnight";
    const LIGHT_NAME: &str = "Kalo Daylight";

    pub fn palette(kind: ThemeKind) -> &'static Palette {
        match kind {
            ThemeKind::Dark => &DARK,
            ThemeKind::Light => &LIGHT,
        }
    }

    fn palette_for(theme: &Theme) -> &'static Palette {
        if theme.name() == LIGHT_NAME {
            &LIGHT
        } else {
            &DARK
        }
    }

    pub const SEMIBOLD: Font = Font {
        family: iced::font::Family::SansSerif,
        weight: Weight::Semibold,
        stretch: iced::font::Stretch::Normal,
        style: iced::font::Style::Normal,
    };
    pub const BOLD: Font = Font {
        family: iced::font::Family::SansSerif,
        weight: Weight::Bold,
        stretch: iced::font::Stretch::Normal,
        style: iced::font::Style::Normal,
    };
    pub const MEDIUM: Font = Font {
        family: iced::font::Family::SansSerif,
        weight: Weight::Medium,
        stretch: iced::font::Stretch::Normal,
        style: iced::font::Style::Normal,
    };
    pub const MONO: Font = Font {
        family: iced::font::Family::Monospace,
        weight: Weight::Normal,
        stretch: iced::font::Stretch::Normal,
        style: iced::font::Style::Normal,
    };

    /// The custom iced theme used for built-in widget details such as
    /// scrollbars, so they belong to the same surface as the app.
    pub fn theme(kind: ThemeKind) -> Theme {
        let palette = palette(kind);
        Theme::custom(
            match kind {
                ThemeKind::Dark => DARK_NAME,
                ThemeKind::Light => LIGHT_NAME,
            },
            iced::theme::Palette {
                background: palette.canvas,
                text: palette.text,
                primary: palette.accent,
                success: palette.success,
                warning: palette.warning,
                danger: palette.danger,
            },
        )
    }

    fn gradient_background(from: Color, to: Color) -> Background {
        Background::Gradient(
            gradient::Linear::new(FRAC_PI_4)
                .add_stop(0.0, from)
                .add_stop(1.0, to)
                .into(),
        )
    }

    pub fn canvas(theme: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(palette_for(theme).canvas)),
            ..container::Style::default()
        }
    }

    pub fn hero(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(gradient_background(p.hero_from, p.hero_to)),
            border: Border {
                color: p.border,
                width: 1.0,
                radius: 20.0.into(),
            },
            shadow: Shadow {
                color: p.hero_shadow,
                offset: Vector::new(0.0, 8.0),
                blur_radius: 24.0,
            },
            ..container::Style::default()
        }
    }

    pub fn panel(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.surface)),
            border: Border {
                color: p.border,
                width: 1.0,
                radius: 18.0.into(),
            },
            shadow: Shadow {
                color: p.panel_shadow,
                offset: Vector::new(0.0, 6.0),
                blur_radius: 18.0,
            },
            ..container::Style::default()
        }
    }

    pub fn inset(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.surface_alt)),
            border: Border {
                color: p.border,
                width: 1.0,
                radius: 12.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn active_transfer(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.accent_tint)),
            border: Border {
                color: p.accent_dim,
                width: 1.0,
                radius: 12.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn notice(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.danger_tint)),
            border: Border {
                color: p.notice_border,
                width: 1.0,
                radius: 12.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn brand(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(gradient_background(p.accent, p.accent_blue)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 12.0.into(),
            },
            shadow: Shadow {
                color: p.brand_shadow,
                offset: Vector::new(0.0, 4.0),
                blur_radius: 16.0,
            },
            ..container::Style::default()
        }
    }

    pub fn step_badge(theme: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(palette_for(theme).accent)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 7.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn avatar(selected: bool) -> impl Fn(&Theme) -> container::Style {
        move |theme| {
            let p = palette_for(theme);
            container::Style {
                background: Some(Background::Color(if selected {
                    p.accent
                } else {
                    p.accent_tint
                })),
                border: Border {
                    color: if selected { p.accent } else { p.accent_dim },
                    width: 1.0,
                    radius: 10.0.into(),
                },
                ..container::Style::default()
            }
        }
    }

    pub fn icon_tile(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.accent_tint)),
            border: Border {
                color: p.accent_dim,
                width: 1.0,
                radius: 10.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn icon_tile_muted(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.chip)),
            border: Border {
                color: p.border,
                width: 1.0,
                radius: 10.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn warning_tile(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.warning_tint)),
            border: Border {
                color: p.warning,
                width: 1.0,
                radius: 9.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn success_tile(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.success_tint)),
            border: Border {
                color: p.success,
                width: 1.0,
                radius: 999.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn prompt(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.warning_tint)),
            border: Border {
                color: p.warning,
                width: 1.0,
                radius: 11.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn success_panel(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.success_tint)),
            border: Border {
                color: p.success,
                width: 1.0,
                radius: 10.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn text_field(theme: &Theme, status: text_input::Status) -> text_input::Style {
        let p = palette_for(theme);
        let border = match status {
            text_input::Status::Focused { .. } => p.accent,
            text_input::Status::Hovered => p.border_strong,
            _ => p.border,
        };
        text_input::Style {
            background: Background::Color(p.surface_alt),
            border: Border {
                color: border,
                width: 1.0,
                radius: 7.0.into(),
            },
            icon: p.text_muted,
            placeholder: p.text_muted,
            value: p.text,
            selection: p.accent_dim,
        }
    }

    pub fn policy_button(active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
        move |theme, status| {
            let p = palette_for(theme);
            let hovered = matches!(status, button::Status::Hovered);
            let pressed = matches!(status, button::Status::Pressed);
            let (background, text_color, border_color) = if active {
                (p.accent_tint, p.accent_text, p.accent)
            } else if pressed {
                (p.row_pressed, p.text, p.border_strong)
            } else if hovered {
                (p.row_hover, p.text, p.border_strong)
            } else {
                (p.surface_alt, p.text_secondary, p.border)
            };
            button::Style {
                background: Some(Background::Color(background)),
                text_color,
                border: Border {
                    color: border_color,
                    width: 1.0,
                    radius: 8.0.into(),
                },
                ..button::Style::default()
            }
        }
    }

    pub fn danger_button(theme: &Theme, status: button::Status) -> button::Style {
        let p = palette_for(theme);
        let (background, text_color, border_color) = match status {
            button::Status::Active => (p.danger_tint, p.danger_text, p.danger),
            button::Status::Hovered => (p.row_hover, p.danger_text, p.danger),
            button::Status::Pressed => (p.row_pressed, p.danger_text, p.danger),
            button::Status::Disabled => (p.disabled_bg, p.disabled_text, p.border),
        };
        button::Style {
            background: Some(Background::Color(background)),
            text_color,
            border: Border {
                color: border_color,
                width: 1.0,
                radius: 9.0.into(),
            },
            ..button::Style::default()
        }
    }

    fn accent_ring(theme: &Theme, alpha: f32) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(Color {
                a: 0.03,
                ..p.accent
            })),
            border: Border {
                color: Color {
                    a: alpha,
                    ..p.accent
                },
                width: 1.0,
                radius: 999.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn orb_outer(theme: &Theme) -> container::Style {
        accent_ring(theme, 0.12)
    }

    pub fn orb_ring(theme: &Theme) -> container::Style {
        accent_ring(theme, 0.24)
    }

    pub fn orb_core(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.accent_tint)),
            border: Border {
                color: p.accent_dim,
                width: 1.0,
                radius: 999.0.into(),
            },
            shadow: Shadow {
                color: p.orb_shadow,
                offset: Vector::new(0.0, 0.0),
                blur_radius: 22.0,
            },
            ..container::Style::default()
        }
    }

    /// A flat tinted surface: used for badges, status pills and chips.
    pub fn fill(background: Color, radius: f32) -> impl Fn(&Theme) -> container::Style {
        move |_| container::Style {
            background: Some(Background::Color(background)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: radius.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn dot(color: Color) -> impl Fn(&Theme) -> container::Style {
        fill(color, 999.0)
    }

    pub fn pill(background: Color) -> impl Fn(&Theme) -> container::Style {
        fill(background, 999.0)
    }

    pub fn chip(theme: &Theme) -> container::Style {
        let p = palette_for(theme);
        container::Style {
            background: Some(Background::Color(p.chip)),
            border: Border {
                color: p.border,
                width: 1.0,
                radius: 999.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn divider(theme: &Theme) -> rule::Style {
        rule::Style {
            color: palette_for(theme).border,
            radius: 0.0.into(),
            fill_mode: rule::FillMode::Full,
            snap: true,
        }
    }

    pub fn progress(theme: &Theme) -> progress_bar::Style {
        let p = palette_for(theme);
        progress_bar::Style {
            background: Background::Color(p.track),
            bar: gradient_background(p.accent, p.accent_blue),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 6.0.into(),
            },
        }
    }

    pub fn primary_button(theme: &Theme, status: button::Status) -> button::Style {
        let p = palette_for(theme);
        let (background, text_color) = match status {
            button::Status::Active => (gradient_background(p.accent, p.accent_blue), p.on_accent),
            button::Status::Hovered => (
                gradient_background(p.accent_hover, p.accent_blue_hover),
                p.on_accent,
            ),
            button::Status::Pressed => (
                gradient_background(p.accent_pressed, p.accent_blue_pressed),
                p.on_accent,
            ),
            button::Status::Disabled => (Background::Color(p.disabled_bg), p.disabled_text),
        };

        button::Style {
            background: Some(background),
            text_color,
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 11.0.into(),
            },
            shadow: Shadow {
                color: Color::from_rgba8(0x00, 0x00, 0x00, 0.25),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 8.0,
            },
            ..button::Style::default()
        }
    }

    pub fn secondary_button(theme: &Theme, status: button::Status) -> button::Style {
        let p = palette_for(theme);
        let (background, text_color, border_color) = match status {
            button::Status::Active => (p.surface_alt, p.text_secondary, p.border_strong),
            button::Status::Hovered => (p.row_hover, p.text, p.border_strong),
            button::Status::Pressed => (p.row_pressed, p.text, p.border_strong),
            button::Status::Disabled => (p.disabled_bg, p.disabled_text, p.border),
        };

        button::Style {
            background: Some(Background::Color(background)),
            text_color,
            border: Border {
                color: border_color,
                width: 1.0,
                radius: 9.0.into(),
            },
            ..button::Style::default()
        }
    }

    pub fn device_row(selected: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
        move |theme, status| {
            let p = palette_for(theme);
            let hovered = matches!(status, button::Status::Hovered);
            let pressed = matches!(status, button::Status::Pressed);
            let background = if selected {
                p.accent_tint
            } else if pressed {
                p.row_pressed
            } else if hovered {
                p.row_hover
            } else {
                p.surface_alt
            };
            let border_color = if selected {
                p.accent
            } else if hovered || pressed {
                p.border_strong
            } else {
                p.border
            };

            button::Style {
                background: Some(Background::Color(background)),
                text_color: p.text,
                border: Border {
                    color: border_color,
                    width: 1.0,
                    radius: 12.0.into(),
                },
                ..button::Style::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(address: &str, alias: &str) -> DeviceInfo {
        DeviceInfo {
            address: address.into(),
            alias: alias.into(),
            paired: true,
            trusted: false,
            connected: false,
        }
    }

    fn app() -> App {
        let sink = EventSink::new(64);
        let trust = TrustStore::in_memory();
        App {
            tx: sink.clone(),
            devices: vec![device("AA:BB", "phone")],
            devices_request_id: 1,
            devices_loaded: true,
            devices_loading: false,
            devices_error: None,
            selected: Some("AA:BB".into()),
            selection: Some(Selection {
                files: vec![PathBuf::from("/tmp/kalo-test-file")],
                total_bytes: 16,
                notes: Vec::new(),
                folders: 0,
            }),
            picking_selection: false,
            log: Vec::new(),
            active_send: None,
            next_send_id: 1,
            send_result: None,
            incoming: Vec::new(),
            receiver_state: ReceiverStatus::Starting,
            settings: Settings::default(),
            authorizer: Authorizer::new(trust.clone(), sink, true),
            trust,
            save_dir: SaveDir::new(PathBuf::from("/tmp/kalo-downloads")),
            encryption: Encryption::new(false, String::new()),
            passphrase_draft: String::new(),
            picking_folder: false,
            pending_authorizations: Vec::new(),
            last_saved: None,
            show_trust: false,
            demo: true,
            tray_ready: false,
        }
    }

    fn active_send(id: u64) -> ActiveSend {
        ActiveSend {
            id,
            target: "phone (AA:BB)".into(),
            cancel: None,
            cancel_requested: false,
            progress: None,
            index: 1,
            total: 1,
            current: "kalo-test-file".into(),
        }
    }

    fn active_id(app: &App) -> Option<u64> {
        app.active_send.as_ref().map(|send| send.id)
    }

    #[test]
    fn resolve_target_matches_selected_address() {
        let devices = vec![device("AA:BB", "phone"), device("CC:DD", "laptop")];
        assert_eq!(
            resolve_target(&devices, Some("CC:DD")).unwrap().alias,
            "laptop"
        );
    }

    #[test]
    fn resolve_target_is_case_insensitive() {
        let devices = vec![device("AA:BB", "phone")];
        assert!(resolve_target(&devices, Some("aa:bb")).is_some());
    }

    #[test]
    fn resolve_target_is_none_for_stale_selection() {
        // After a refresh the selected device may no longer be listed: it
        // must not resolve (a stale index used to point at another device).
        let devices = vec![device("CC:DD", "laptop")];
        assert!(resolve_target(&devices, Some("AA:BB")).is_none());
        assert!(resolve_target(&devices, None).is_none());
    }

    #[test]
    fn second_send_click_is_ignored() {
        let mut app = app();
        let _ = update(&mut app, Message::SendClicked);
        assert_eq!(active_id(&app), Some(1));
        assert_eq!(app.next_send_id, 2);

        let _ = update(&mut app, Message::SendClicked);
        assert_eq!(active_id(&app), Some(1));
        assert_eq!(app.next_send_id, 2);
        assert!(
            app.log
                .iter()
                .any(|line| line.contains("already in progress"))
        );
    }

    #[test]
    fn send_waits_for_the_file_picker_to_finish() {
        let mut app = app();
        app.picking_selection = true;
        let _ = update(&mut app, Message::SendClicked);
        assert!(app.active_send.is_none());
        assert!(
            app.log
                .iter()
                .any(|line| line.contains("finish choosing files"))
        );
    }

    #[test]
    fn cancel_is_available_before_progress_arrives() {
        let mut app = app();
        let (cancel_handle, cancel) = Cancel::new();
        app.active_send = Some(ActiveSend {
            cancel: Some(cancel_handle),
            ..active_send(1)
        });

        let _ = update(&mut app, Message::CancelSend);
        assert!(cancel.is_cancelled());
        assert!(
            app.active_send
                .as_ref()
                .is_some_and(|send| send.cancel_requested)
        );

        let _ = update(&mut app, Message::CancelSend);
        assert!(
            app.log
                .iter()
                .any(|line| line.contains("already requested"))
        );
    }

    #[test]
    fn refresh_is_ignored_while_a_load_is_in_flight() {
        let mut app = app();
        let _ = update(&mut app, Message::RefreshDevices);
        assert!(app.devices_loading);
        let request_id = app.devices_request_id;

        let _ = update(&mut app, Message::RefreshDevices);
        assert_eq!(app.devices_request_id, request_id);

        let _ = update(
            &mut app,
            Message::DevicesLoaded {
                request_id,
                result: Ok(vec![]),
            },
        );
        assert!(!app.devices_loading);
    }

    #[test]
    fn stale_finished_message_does_not_clear_active_send() {
        let mut app = app();
        app.active_send = Some(active_send(2));
        let _ = update(
            &mut app,
            Message::SendFinished {
                send_id: 1,
                result: Ok("old".into()),
            },
        );
        assert_eq!(active_id(&app), Some(2));

        let _ = update(
            &mut app,
            Message::SendFinished {
                send_id: 2,
                result: Ok("new".into()),
            },
        );
        assert!(app.active_send.is_none());
        assert!(app.log.iter().any(|line| line.contains("new")));
    }

    #[test]
    fn stale_send_progress_is_ignored() {
        let mut app = app();
        app.active_send = Some(active_send(2));
        let _ = handle_event(
            &mut app,
            Event::SendProgress {
                send_id: 1,
                transferred: 3,
                size: Some(10),
                status: crate::events::TransferStatus::Active,
            },
        );
        assert!(
            app.active_send
                .as_ref()
                .is_some_and(|send| send.progress.is_none())
        );

        let _ = handle_event(
            &mut app,
            Event::SendProgress {
                send_id: 2,
                transferred: 3,
                size: Some(10),
                status: crate::events::TransferStatus::Active,
            },
        );
        assert!(
            app.active_send
                .as_ref()
                .is_some_and(|send| send.progress.is_some())
        );
    }

    #[test]
    fn batch_start_resets_progress_and_updates_position() {
        let mut app = app();
        app.active_send = Some(active_send(1));
        let _ = handle_event(
            &mut app,
            Event::SendProgress {
                send_id: 1,
                transferred: 5,
                size: Some(10),
                status: crate::events::TransferStatus::Active,
            },
        );
        let _ = handle_event(
            &mut app,
            Event::SendFileStarted {
                send_id: 1,
                index: 2,
                total: 3,
                name: "second.pdf".into(),
            },
        );
        let active = app.active_send.as_ref().expect("active send");
        assert!(active.progress.is_none());
        assert_eq!(active.index, 2);
        assert_eq!(active.total, 3);
        assert_eq!(active.current, "second.pdf");
    }

    #[test]
    fn selection_summary_names_single_files_and_counts_batches() {
        let one = Selection {
            files: vec![PathBuf::from("/tmp/report.pdf")],
            total_bytes: 10,
            notes: Vec::new(),
            folders: 0,
        };
        assert_eq!(selection_summary(&one), "report.pdf");
        let many = Selection {
            files: vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")],
            total_bytes: 20,
            notes: Vec::new(),
            folders: 0,
        };
        assert_eq!(selection_summary(&many), "2 files");
    }

    #[test]
    fn picker_cancel_preserves_existing_selection() {
        let mut app = app();
        let previous = app.selection.clone();
        app.picking_selection = true;
        let _ = update(&mut app, Message::FilesPicked(None));
        assert_eq!(app.selection, previous);
        assert!(!app.picking_selection);
    }

    #[test]
    fn stale_device_refresh_is_ignored() {
        let mut app = app();
        app.devices_request_id = 2;
        app.devices = vec![device("OLD", "old")];
        let _ = update(
            &mut app,
            Message::DevicesLoaded {
                request_id: 1,
                result: Ok(vec![device("STALE", "stale")]),
            },
        );
        assert_eq!(app.devices[0].address, "OLD");

        let _ = update(
            &mut app,
            Message::DevicesLoaded {
                request_id: 2,
                result: Ok(vec![device("NEW", "new")]),
            },
        );
        assert_eq!(app.devices[0].address, "NEW");
    }

    #[test]
    fn concurrent_incoming_progress_is_isolated() {
        let mut app = app();
        let _ = handle_event(
            &mut app,
            Event::IncomingStarted {
                id: "a".into(),
                sender: "AA".into(),
                name: "a.jpg".into(),
                size: Some(10),
            },
        );
        let _ = handle_event(
            &mut app,
            Event::IncomingStarted {
                id: "b".into(),
                sender: "BB".into(),
                name: "b.jpg".into(),
                size: Some(20),
            },
        );
        let _ = handle_event(
            &mut app,
            Event::IncomingProgress {
                id: "a".into(),
                name: "a.jpg".into(),
                transferred: Some(5),
                size: Some(10),
            },
        );
        let _ = handle_event(
            &mut app,
            Event::IncomingDone {
                id: "a".into(),
                sender: "AA".into(),
                name: "a.jpg".into(),
                saved_to: PathBuf::from("/tmp/a.jpg"),
                bytes: 10,
                elapsed_secs: 1.0,
                mbps: 1.0,
                partial: false,
            },
        );
        assert_eq!(app.incoming.len(), 1);
        assert_eq!(app.incoming[0].id, "b");
    }

    #[test]
    fn finished_send_sets_inline_result_until_the_next_choice() {
        let mut app = app();
        app.active_send = Some(active_send(1));
        let _ = update(
            &mut app,
            Message::SendFinished {
                send_id: 1,
                result: Ok("Sent file to phone.".into()),
            },
        );
        let result = app.send_result.as_ref().expect("send result");
        assert!(result.ok);
        assert_eq!(result.message, "Sent file to phone.");
        assert!(app.log.iter().any(|line| line == "Sent file to phone."));

        let _ = update(
            &mut app,
            Message::SelectionCollected(Ok(Selection {
                files: vec![PathBuf::from("/tmp/next")],
                total_bytes: 4,
                notes: Vec::new(),
                folders: 0,
            })),
        );
        assert!(app.send_result.is_none());

        app.send_result = Some(SendResultUi {
            ok: true,
            message: "old".into(),
        });
        let _ = update(&mut app, Message::PickDevice("AA:BB".into()));
        assert!(app.send_result.is_none());
    }

    #[test]
    fn send_progress_without_size_stays_indeterminate() {
        let mut app = app();
        app.active_send = Some(active_send(1));
        let _ = handle_event(
            &mut app,
            Event::SendProgress {
                send_id: 1,
                transferred: 5,
                size: None,
                status: crate::events::TransferStatus::Active,
            },
        );
        let progress = app
            .active_send
            .as_ref()
            .and_then(|send| send.progress.as_ref())
            .expect("progress");
        assert!(progress.fraction.is_none());
        assert_eq!(progress.detail, "5 B sent");
    }

    #[test]
    fn device_errors_are_surfaced_and_cleared_by_a_good_refresh() {
        let mut app = app();
        let _ = update(
            &mut app,
            Message::DevicesLoaded {
                request_id: 1,
                result: Err("bus down".into()),
            },
        );
        assert_eq!(app.devices_error.as_deref(), Some("bus down"));
        assert!(app.devices_loaded);

        let _ = update(
            &mut app,
            Message::DevicesLoaded {
                request_id: 1,
                result: Ok(vec![]),
            },
        );
        assert!(app.devices_error.is_none());
    }

    #[test]
    fn device_name_and_file_name_have_honest_fallbacks() {
        assert_eq!(device_name(&device("AA:BB", "phone")), "phone");
        assert_eq!(device_name(&device("AA:BB", "")), "AA:BB");
        assert_eq!(
            file_name(Path::new("/tmp/report.pdf")),
            "report.pdf".to_string()
        );
        assert_eq!(file_name(Path::new("/")), "/".to_string());
    }

    #[test]
    fn sender_names_prefer_known_devices() {
        let devices = vec![device("AA:BB:CC:11:22:33", "Pixel 8")];
        assert_eq!(
            sender_name(&devices, "aa:bb:cc:11:22:33", "AA:BB:CC:11:22:33"),
            "Pixel 8"
        );
        assert_eq!(sender_name(&[], "AA:BB", "AA:BB"), "AA:BB");
        assert_eq!(sender_name(&devices, "", "Some sender"), "Some sender");
    }

    #[test]
    fn theme_toggle_and_save_folder_update_locally() {
        let mut app = app();
        assert_eq!(app.settings.theme, ThemeKind::Dark);

        let _ = update(&mut app, Message::ToggleTheme);
        assert_eq!(app.settings.theme, ThemeKind::Light);
        let _ = update(&mut app, Message::ToggleTheme);
        assert_eq!(app.settings.theme, ThemeKind::Dark);

        let folder = PathBuf::from("/tmp/kalo-received");
        let _ = update(&mut app, Message::SaveFolderPicked(Some(folder.clone())));
        assert_eq!(app.save_dir.get(), folder);
        assert_eq!(app.settings.save_dir, Some(folder));
        assert!(app.log.iter().any(|line| line.contains("now save to")));
    }

    #[test]
    fn authorization_prompt_is_shown_and_dismissed() {
        let mut app = app();
        let _ = handle_event(
            &mut app,
            Event::IncomingAuthorization {
                id: "auth-1".into(),
                sender: "Pixel 8".into(),
                address: "AA:BB:CC:DD:EE:FF".into(),
                name: "photo.jpg".into(),
                size: Some(10),
                stable: true,
            },
        );
        assert_eq!(app.pending_authorizations.len(), 1);
        assert_eq!(app.pending_authorizations[0].sender, "Pixel 8");
        assert!(
            app.log
                .iter()
                .any(|line| line.contains("waiting for approval"))
        );

        let _ = update(
            &mut app,
            Message::AuthorizationResponse {
                id: "auth-1".into(),
                allow: false,
                remember: false,
            },
        );
        assert!(app.pending_authorizations.is_empty());
    }

    #[test]
    fn completed_incoming_transfer_offers_the_saved_folder() {
        let mut app = app();
        let path = PathBuf::from("/tmp/kalo-received/photo.jpg");
        let _ = handle_event(
            &mut app,
            Event::IncomingDone {
                id: "in-1".into(),
                sender: "Pixel 8".into(),
                name: "photo.jpg".into(),
                saved_to: path.clone(),
                bytes: 10,
                elapsed_secs: 1.0,
                mbps: 1.0,
                partial: false,
            },
        );
        let saved = app.last_saved.as_ref().expect("saved banner");
        assert_eq!(saved.name, "photo.jpg");
        assert_eq!(saved.path, path);
        assert!(!saved.partial);
    }

    #[test]
    fn removing_a_trusted_sender_updates_the_store() {
        let mut app = app();
        app.trust
            .remember(
                "AA:BB:CC:DD:EE:FF",
                "Pixel 8",
                crate::trust::TrustDecision::Allow,
            )
            .unwrap();
        assert_eq!(app.trust.entries().len(), 1);

        let _ = update(
            &mut app,
            Message::RemoveTrustedSender("aa:bb:cc:dd:ee:ff".into()),
        );
        assert!(app.trust.entries().is_empty());
    }

    #[test]
    fn long_save_folders_are_shortened_for_the_footer() {
        assert_eq!(
            short_path(Path::new("/home/you/Downloads")),
            "/home/you/Downloads"
        );
        let long = short_path(Path::new(
            "/home/you/a-very-long-folder-name/received files",
        ));
        assert!(long.starts_with("…/"));
        assert!(long.ends_with("received files"));
    }
}
