//! Iced UI for the Kalo spike: devices, send with progress, receiver state, log.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::SinkExt;
use iced::widget::{button, column, container, progress_bar, row, rule, scrollable, space, text};
use iced::{Alignment, Color, Element, Font, Length, Padding, Subscription, Task};
use tokio::sync::broadcast;
use tokio::sync::oneshot;

use crate::events::{
    Event, EventSink, ReceiverStatus, format_bytes, send_progress_summary, transfer_fraction,
};
use crate::paths;
use crate::platform::{self, DeviceInfo, PendingTransfers, ReceiverHandle, new_pending};

/// Shared handles for the event-pump subscription. iced 0.14 builds
/// subscriptions from plain `fn` builders, so the state must be static.
static EVENT_BUS: OnceLock<EventBus> = OnceLock::new();

struct EventBus {
    sink: EventSink,
    receiver: ReceiverHandle,
    pending: PendingTransfers,
    downloads: PathBuf,
}

impl EventBus {
    /// Spawn the shared receiver supervisor exactly once. The subscription can
    /// be re-created by iced, but the supervisor (and its event sink) must not
    /// be duplicated.
    fn ensure_receiver_started(&self) {
        static STARTED: AtomicBool = AtomicBool::new(false);
        if STARTED.swap(true, Ordering::SeqCst) {
            return;
        }
        tokio::spawn(platform::run_receiver(
            self.receiver.clone(),
            self.pending.clone(),
            self.downloads.clone(),
            self.sink.clone(),
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
    PickFile,
    FilePicked(Option<PathBuf>),
    SendClicked,
    CancelSend,
    SendFinished {
        send_id: u64,
        result: Result<String, String>,
    },
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

/// Everything that belongs to the one in-flight outgoing transfer. Keeping
/// it in one struct makes invalid combinations (sending without an id or a
/// cancel handle) unrepresentable.
#[derive(Debug)]
struct ActiveSend {
    id: u64,
    target: String,
    cancel: Option<oneshot::Sender<()>>,
    cancel_requested: bool,
    progress: Option<SendProgressUi>,
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
    file: Option<PathBuf>,
    picking_file: bool,
    log: Vec<String>,
    /// The active send, if any.
    active_send: Option<ActiveSend>,
    next_send_id: u64,
    send_result: Option<SendResultUi>,
    incoming: Vec<IncomingUi>,
    receiver_state: ReceiverStatus,
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
}

pub fn run() -> iced::Result {
    let sink = EventSink::new(2048);
    if EVENT_BUS
        .set(EventBus {
            sink: sink.clone(),
            receiver: ReceiverHandle::new(sink),
            pending: new_pending(),
            downloads: paths::downloads_dir(),
        })
        .is_err()
    {
        panic!("kalo event bus is initialized exactly once");
    }

    iced::application(
        || {
            let bus = EVENT_BUS.get().expect("event bus must be initialized");
            let initial_request_id = 1;
            let app = App {
                tx: bus.sink.clone(),
                devices: Vec::new(),
                devices_request_id: initial_request_id,
                devices_loaded: false,
                devices_loading: true,
                devices_error: None,
                selected: None,
                file: None,
                picking_file: false,
                log: Vec::new(),
                active_send: None,
                next_send_id: 1,
                send_result: None,
                incoming: Vec::new(),
                receiver_state: bus.receiver.status(),
            };
            let task = Task::perform(platform::list_known_devices(), move |result| {
                Message::DevicesLoaded {
                    request_id: initial_request_id,
                    result: result.map_err(|e| e.to_string()),
                }
            });
            (app, task)
        },
        update,
        view,
    )
    .title("Kalo")
    .theme(|_: &App| ui::theme())
    .window_size((980.0, 710.0))
    .centered()
    .subscription(subscription)
    .run()
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
        Message::PickFile => {
            if app.is_sending() || app.picking_file {
                return Task::none();
            }
            app.picking_file = true;
            Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .set_title("Choose a file to send")
                        .pick_file()
                        .await
                        .map(|handle| handle.path().to_path_buf())
                },
                Message::FilePicked,
            )
        }
        Message::FilePicked(file) => {
            app.picking_file = false;
            if app.is_sending() {
                app.log("ignored a file selection that finished during a send");
                return Task::none();
            }
            // Cancel leaves the previous selection intact.
            if let Some(file) = file {
                app.file = Some(file);
                app.send_result = None;
            }
            Task::none()
        }
        Message::SendClicked => {
            if let Some(send_id) = app.active_send.as_ref().map(|send| send.id) {
                app.log(format!("send already in progress (id {send_id})"));
                return Task::none();
            }
            if app.picking_file {
                app.log("finish choosing a file before starting a send");
                return Task::none();
            }
            let Some(device) = resolve_target(&app.devices, app.selected.as_deref()) else {
                app.log("select a device first");
                return Task::none();
            };
            let Some(file) = app.file.clone() else {
                app.log("pick a file first");
                return Task::none();
            };
            let mac = device.address.clone();
            let target = format!("{} ({})", device_name(device), device.address);
            let result_target = device_name(device).to_string();
            let result_file = file_name(&file);
            let send_id = app.next_send_id;
            app.next_send_id += 1;
            let (cancel_tx, cancel_rx) = oneshot::channel();

            app.active_send = Some(ActiveSend {
                id: send_id,
                target,
                cancel: Some(cancel_tx),
                cancel_requested: false,
                progress: None,
            });
            app.send_result = None;

            let tx = app.tx.clone();
            Task::perform(
                async move {
                    platform::send(&mac, &file, &tx, send_id, Some(cancel_rx))
                        .await
                        .map(|summary| {
                            format!(
                                "Sent {result_file} to {result_target} · {} in {:.1}s ({:.1} MB/s)",
                                format_bytes(summary.bytes),
                                summary.elapsed_secs,
                                summary.mbps
                            )
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
                        Some(cancel) => match cancel.send(()) {
                            Ok(()) => {
                                active.cancel_requested = true;
                                "canceling send…".to_string()
                            }
                            Err(_) => "send already finished".to_string(),
                        },
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
        Message::Event(event) => handle_event(app, event),
    }
}

fn handle_event(app: &mut App, event: Event) -> Task<Message> {
    match event {
        Event::Log(line) => app.log(line),
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
            app.log(format!("Incoming failed from {sender} ({name}): {error}"));
            if let Some(path) = staged_at {
                app.log(format!("  staged file kept at {}", path.display()));
            }
        }
        Event::ReceiverState(state) => {
            let line = match &state {
                ReceiverStatus::Starting => "Receiver starting…".to_string(),
                ReceiverStatus::Active => {
                    "Receiver ready. Incoming files save to Downloads.".to_string()
                }
                ReceiverStatus::Off(reason) => format!("Receiver unavailable: {reason}"),
            };
            app.receiver_state = state;
            app.log(line);
        }
    }
    Task::none()
}

fn subscription(_app: &App) -> Subscription<Message> {
    Subscription::run(|| {
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
    })
}

fn view(app: &App) -> Element<'_, Message> {
    let is_sending = app.is_sending();
    let target = resolve_target(&app.devices, app.selected.as_deref());

    let header = row![
        row![
            brand_mark(),
            column![
                text("Kalo").size(22).font(ui::BOLD).color(ui::TEXT),
                text("Bluetooth file transfer")
                    .size(11.5)
                    .color(ui::TEXT_MUTED),
            ]
            .spacing(0),
        ]
        .spacing(11)
        .align_y(Alignment::Center),
        space().width(Length::Fill),
        receiver_summary(&app.receiver_state),
    ]
    .width(Length::Fill)
    .align_y(Alignment::Center);

    let hero = container(
        row![
            column![
                text("Pass a file. No cables.")
                    .size(30)
                    .font(ui::BOLD)
                    .color(ui::TEXT),
                text("Send directly to the devices around you. Nothing goes through the cloud.")
                    .size(13)
                    .color(ui::TEXT_SECONDARY),
                row![
                    chip("Local transfer"),
                    chip("No sign-in"),
                    chip("Saves to Downloads"),
                ]
                .spacing(8),
            ]
            .spacing(9)
            .width(Length::Fill),
            transfer_orb(),
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
            device_button(device, selected, !is_sending)
        })
        .collect();

    let device_list: Element<'_, Message> = if app.devices.is_empty() {
        device_empty_state(app.devices_loaded, app.devices_error.as_deref())
    } else {
        scrollable(column(device_rows).spacing(8).width(Length::Fill))
            .height(Length::Fill)
            .into()
    };

    let mut device_section = column![
        row![
            step_label("1", "Choose a device"),
            space().width(Length::Fill),
            button(
                text(if app.devices_loading {
                    "Refreshing…"
                } else {
                    "Refresh"
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
                .color(ui::DANGER_TEXT),
        );
    }
    device_section = device_section.push(device_list);

    let file_title = app
        .file
        .as_deref()
        .map(file_name)
        .unwrap_or_else(|| "No file chosen".to_string());
    let mut file_info = column![
        text(file_title)
            .size(13.5)
            .font(if app.file.is_some() {
                ui::SEMIBOLD
            } else {
                Font::DEFAULT
            })
            .color(if app.file.is_some() {
                ui::TEXT
            } else {
                ui::TEXT_SECONDARY
            }),
    ]
    .spacing(2)
    .width(Length::Fill);
    if let Some(path) = app.file.as_deref() {
        file_info = file_info.push(
            text(path.display().to_string())
                .size(11)
                .color(ui::TEXT_MUTED),
        );
    }

    let file_button_label = if app.picking_file {
        "Choosing…"
    } else if app.file.is_some() {
        "Change…"
    } else {
        "Choose file…"
    };
    let file_zone = container(
        row![
            container(text("↥").size(18).font(ui::BOLD).color(ui::ACCENT_TEXT))
                .width(38)
                .height(38)
                .center(38)
                .style(ui::icon_tile),
            file_info,
            button(text(file_button_label).size(12).font(ui::MEDIUM))
                .padding([7, 11])
                .style(ui::secondary_button)
                .on_press_maybe((!is_sending && !app.picking_file).then_some(Message::PickFile)),
        ]
        .spacing(12)
        .align_y(Alignment::Center),
    )
    .padding([11, 12])
    .width(Length::Fill)
    .style(ui::inset);

    let file_section = column![step_label("2", "Pick a file"), file_zone,].spacing(9);

    let send_panel = container(
        column![
            column![
                text("Send a file")
                    .size(20)
                    .font(ui::SEMIBOLD)
                    .color(ui::TEXT),
                text("Choose a device and a file, then send.")
                    .size(12)
                    .color(ui::TEXT_SECONDARY),
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

    let mut incoming_header = row![text("Incoming").size(19).font(ui::SEMIBOLD).color(ui::TEXT),]
        .spacing(8)
        .align_y(Alignment::Center);
    if !app.incoming.is_empty() {
        incoming_header = incoming_header.push(space().width(Length::Fill)).push(
            text(format!("{} active", app.incoming.len()))
                .size(10.5)
                .font(ui::BOLD)
                .color(ui::ACCENT_TEXT),
        );
    }

    let mut incoming_body = column![].spacing(9).width(Length::Fill);
    if let ReceiverStatus::Off(reason) = &app.receiver_state {
        incoming_body = incoming_body.push(receiver_notice(reason));
    }
    if app.incoming.is_empty() {
        if !matches!(app.receiver_state, ReceiverStatus::Off(_)) {
            incoming_body = incoming_body.push(incoming_empty(&app.receiver_state));
        }
    } else {
        incoming_body = incoming_body.push(
            scrollable(
                column(
                    app.incoming
                        .iter()
                        .map(incoming_row)
                        .collect::<Vec<Element<'_, Message>>>(),
                )
                .spacing(8)
                .width(Length::Fill),
            )
            .height(Length::Fixed(150.0)),
        );
    }

    let activity: Element<'_, Message> = if app.log.is_empty() {
        container(
            column![
                text("No activity yet")
                    .size(13)
                    .font(ui::MEDIUM)
                    .color(ui::TEXT),
                text("Sent and received files will be listed here.")
                    .size(11.5)
                    .color(ui::TEXT_SECONDARY),
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
                        .style(ui::dot(ui::ACCENT)),
                    text(line.clone())
                        .size(11.5)
                        .line_height(1.4)
                        .color(ui::TEXT_SECONDARY)
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
            text("Activity").size(19).font(ui::SEMIBOLD).color(ui::TEXT),
            space().width(Length::Fill),
            text(format!("{} entries", app.log.len()))
                .size(10.5)
                .color(ui::TEXT_MUTED),
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

fn brand_mark<'a>() -> Element<'a, Message> {
    container(text("K").size(19).font(ui::BOLD).color(ui::ON_ACCENT))
        .width(40)
        .height(40)
        .center(40)
        .style(ui::brand)
        .into()
}

fn chip<'a>(label: &'a str) -> Element<'a, Message> {
    container(
        text(label)
            .size(10.5)
            .font(ui::MEDIUM)
            .color(ui::TEXT_SECONDARY),
    )
    .padding([4, 9])
    .style(ui::chip)
    .into()
}

fn step_label<'a>(step: &'a str, label: &'a str) -> Element<'a, Message> {
    row![
        container(text(step).size(10).font(ui::BOLD).color(ui::ON_ACCENT))
            .width(20)
            .height(20)
            .center(20)
            .style(ui::step_badge),
        text(label)
            .size(12.5)
            .font(ui::SEMIBOLD)
            .color(ui::TEXT_SECONDARY),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

/// A quiet orbit graphic for the hero: rings read as "nearby devices" without
/// adding another moving part to the interface.
fn transfer_orb<'a>() -> Element<'a, Message> {
    container(
        container(
            container(text("⇄").size(25).font(ui::BOLD).color(ui::ACCENT_TEXT))
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

fn receiver_summary(state: &ReceiverStatus) -> Element<'_, Message> {
    let (label, detail, dot, tint, text_color) = match state {
        ReceiverStatus::Starting => (
            "Starting receiver",
            "Incoming files will be ready shortly",
            ui::WARNING,
            ui::WARNING_TINT,
            ui::WARNING_TEXT,
        ),
        ReceiverStatus::Active => (
            "Receiver on",
            "Files save to Downloads",
            ui::SUCCESS,
            ui::SUCCESS_TINT,
            ui::SUCCESS_TEXT,
        ),
        ReceiverStatus::Off(_) => (
            "Receiver off",
            "Incoming files are unavailable",
            ui::DANGER,
            ui::DANGER_TINT,
            ui::DANGER_TEXT,
        ),
    };
    let detail_color = if matches!(state, ReceiverStatus::Off(_)) {
        ui::DANGER_TEXT
    } else {
        ui::TEXT_MUTED
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

fn device_button(device: &DeviceInfo, selected: bool, enabled: bool) -> Element<'_, Message> {
    let mut meta = row![
        text(&device.address)
            .size(11)
            .font(ui::MONO)
            .color(ui::TEXT_MUTED),
    ]
    .spacing(6)
    .align_y(Alignment::Center);
    if device.connected {
        meta = meta.push(badge("Connected", ui::SUCCESS_TINT, ui::SUCCESS_TEXT));
    }
    if !device.paired {
        meta = meta.push(badge("Not paired", ui::WARNING_TINT, ui::WARNING_TEXT));
    }

    let avatar = container(text(device_initial(device)).size(14).font(ui::BOLD).color(
        if selected {
            ui::ON_ACCENT
        } else {
            ui::ACCENT_TEXT
        },
    ))
    .width(34)
    .height(34)
    .center(34)
    .style(ui::avatar(selected));

    let trailing: Element<'_, Message> = if selected {
        container(text("✓").size(11).font(ui::BOLD).color(ui::ON_ACCENT))
            .width(21)
            .height(21)
            .center(21)
            .style(ui::fill(ui::ACCENT, 999.0))
            .into()
    } else {
        text("Select").size(11).color(ui::TEXT_MUTED).into()
    };

    let content = row![
        avatar,
        column![
            text(device_name(device))
                .size(13.5)
                .font(ui::SEMIBOLD)
                .color(if enabled {
                    ui::TEXT
                } else {
                    ui::TEXT_SECONDARY
                }),
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

fn device_empty_state(loaded: bool, error: Option<&str>) -> Element<'_, Message> {
    let content: Element<'_, Message> = if !loaded {
        column![
            text("Looking for paired devices…")
                .size(13)
                .font(ui::MEDIUM)
                .color(ui::TEXT),
            text("This usually takes a moment.")
                .size(11.5)
                .color(ui::TEXT_SECONDARY),
        ]
        .spacing(4)
        .into()
    } else if let Some(error) = error {
        column![
            text("Couldn't load paired devices")
                .size(13)
                .font(ui::MEDIUM)
                .color(ui::DANGER_TEXT),
            text(error).size(11.5).color(ui::TEXT_SECONDARY),
            text("Choose Refresh to try again.")
                .size(11)
                .color(ui::TEXT_MUTED),
        ]
        .spacing(3)
        .into()
    } else {
        column![
            text("No paired devices")
                .size(13)
                .font(ui::MEDIUM)
                .color(ui::TEXT),
            text("Pair one in your Bluetooth settings, then choose Refresh.")
                .size(11.5)
                .color(ui::TEXT_SECONDARY),
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

fn receiver_notice(reason: &str) -> Element<'_, Message> {
    container(
        column![
            text("Incoming files are unavailable")
                .size(12)
                .font(ui::SEMIBOLD)
                .color(ui::DANGER_TEXT),
            text(reason).size(11).color(ui::TEXT_SECONDARY),
            text("Kalo retries automatically. Restart it if this persists.")
                .size(11)
                .color(ui::TEXT_MUTED),
        ]
        .spacing(3),
    )
    .padding(12)
    .width(Length::Fill)
    .style(ui::notice)
    .into()
}

fn incoming_empty(state: &ReceiverStatus) -> Element<'_, Message> {
    let detail = match state {
        ReceiverStatus::Starting => "The receiver is starting. Incoming files will appear here.",
        _ => "Files sent to this computer appear here.",
    };

    container(
        row![
            container(text("↓").size(16).font(ui::BOLD).color(ui::TEXT_MUTED))
                .width(34)
                .height(34)
                .center(34)
                .style(ui::icon_tile_muted),
            column![
                text("Nothing incoming")
                    .size(12.5)
                    .font(ui::MEDIUM)
                    .color(ui::TEXT),
                text(detail).size(11).color(ui::TEXT_SECONDARY),
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

fn incoming_row(item: &IncomingUi) -> Element<'_, Message> {
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
            .color(ui::TEXT)
            .width(Length::Fill),
    ]
    .spacing(10)
    .align_y(Alignment::Center);
    if let Some(percent) = percent {
        title = title.push(
            text(percent)
                .size(11.5)
                .font(ui::SEMIBOLD)
                .color(ui::ACCENT_TEXT),
        );
    }

    let mut content = column![
        title,
        text(format!("{from} · {amount}"))
            .size(11)
            .color(ui::TEXT_SECONDARY)
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
            container(text("↓").size(14).font(ui::BOLD).color(ui::ACCENT_TEXT))
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

fn send_action<'a>(app: &'a App, target: Option<&'a DeviceInfo>) -> Element<'a, Message> {
    if let Some(active) = &app.active_send {
        let progress = active.progress.as_ref();
        let fraction = progress.and_then(|progress| progress.fraction);
        let detail = progress
            .map(|progress| progress.detail.clone())
            .unwrap_or_else(|| "Preparing transfer…".to_string());
        let mut top = row![
            text(format!("Sending to {}", active.target))
                .size(13.5)
                .font(ui::SEMIBOLD)
                .color(ui::TEXT)
                .width(Length::Fill),
        ]
        .spacing(10)
        .align_y(Alignment::Center);
        if let Some(fraction) = fraction {
            top = top.push(
                text(format!("{:.0}%", fraction * 100.0))
                    .size(12.5)
                    .font(ui::BOLD)
                    .color(ui::ACCENT_TEXT),
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
                .color(ui::TEXT_SECONDARY)
                .width(Length::Fill),
            cancel,
        ]
        .spacing(12)
        .align_y(Alignment::Center);

        let mut block = column![top].spacing(8);
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

    let can_send = target.is_some() && app.file.is_some() && !app.picking_file;
    let guidance = match (target.is_some(), app.file.is_some()) {
        (false, false) => "Select a device and choose a file.",
        (false, true) => "Select a device to send this file.",
        (true, false) => "Choose a file to send.",
        (true, true) => "Ready when you are.",
    };
    let send_label = target
        .map(|device| format!("Send to {}", device_name(device)))
        .unwrap_or_else(|| "Send file".to_string());

    let mut block = column![
        container(text(guidance).size(11.5).color(ui::TEXT_MUTED)).height(Length::Fixed(17.0)),
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
            ui::SUCCESS_TEXT
        } else {
            ui::DANGER_TEXT
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

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
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

/// Visual system for Kalo's midnight surface. A single dark palette keeps
/// contrast and state meaning predictable while giving the product a distinct
/// identity.
mod ui {
    use std::f32::consts::FRAC_PI_4;

    use iced::font::Weight;
    use iced::gradient;
    use iced::widget::{button, container, progress_bar, rule};
    use iced::{Background, Border, Color, Font, Shadow, Theme, Vector};

    pub const CANVAS: Color = Color::from_rgb8(0x07, 0x0A, 0x0F);
    pub const SURFACE: Color = Color::from_rgb8(0x0D, 0x12, 0x19);
    pub const SURFACE_ALT: Color = Color::from_rgb8(0x11, 0x18, 0x23);
    pub const BORDER: Color = Color::from_rgb8(0x1D, 0x27, 0x35);
    pub const BORDER_STRONG: Color = Color::from_rgb8(0x2B, 0x3B, 0x4F);
    pub const TEXT: Color = Color::from_rgb8(0xF3, 0xF7, 0xFB);
    pub const TEXT_SECONDARY: Color = Color::from_rgb8(0xA6, 0xB3, 0xC4);
    pub const TEXT_MUTED: Color = Color::from_rgb8(0x76, 0x85, 0x9A);
    pub const ACCENT: Color = Color::from_rgb8(0x5E, 0xEA, 0xD4);
    pub const ACCENT_BLUE: Color = Color::from_rgb8(0x60, 0xA5, 0xFA);
    pub const ACCENT_HOVER: Color = Color::from_rgb8(0x7F, 0xF3, 0xE1);
    pub const ACCENT_PRESSED: Color = Color::from_rgb8(0x2D, 0xD4, 0xBF);
    pub const ACCENT_TEXT: Color = Color::from_rgb8(0x7D, 0xF0, 0xDC);
    pub const ACCENT_TINT: Color = Color::from_rgb8(0x0D, 0x26, 0x24);
    pub const ACCENT_DIM: Color = Color::from_rgb8(0x1C, 0x4A, 0x46);
    pub const ON_ACCENT: Color = Color::from_rgb8(0x04, 0x12, 0x0F);
    pub const ROW_HOVER: Color = Color::from_rgb8(0x14, 0x1D, 0x29);
    pub const ROW_PRESSED: Color = Color::from_rgb8(0x19, 0x24, 0x32);
    pub const TRACK: Color = Color::from_rgb8(0x1A, 0x25, 0x33);
    pub const CHIP: Color = Color::from_rgb8(0x14, 0x1C, 0x26);
    pub const DISABLED_BG: Color = Color::from_rgb8(0x16, 0x1E, 0x29);
    pub const DISABLED_TEXT: Color = Color::from_rgb8(0x64, 0x73, 0x87);
    pub const SUCCESS: Color = Color::from_rgb8(0x34, 0xD3, 0x99);
    pub const SUCCESS_TINT: Color = Color::from_rgb8(0x0D, 0x28, 0x1F);
    pub const SUCCESS_TEXT: Color = Color::from_rgb8(0x6E, 0xE7, 0xB7);
    pub const WARNING: Color = Color::from_rgb8(0xFB, 0xBF, 0x24);
    pub const WARNING_TINT: Color = Color::from_rgb8(0x2A, 0x23, 0x14);
    pub const WARNING_TEXT: Color = Color::from_rgb8(0xFD, 0xE6, 0x8A);
    pub const DANGER: Color = Color::from_rgb8(0xFB, 0x71, 0x85);
    pub const DANGER_TINT: Color = Color::from_rgb8(0x2C, 0x15, 0x1B);
    pub const DANGER_TEXT: Color = Color::from_rgb8(0xFD, 0xA4, 0xAF);

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
    pub fn theme() -> Theme {
        Theme::custom(
            "Kalo Midnight",
            iced::theme::Palette {
                background: CANVAS,
                text: TEXT,
                primary: ACCENT,
                success: SUCCESS,
                warning: WARNING,
                danger: DANGER,
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

    pub fn canvas(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(CANVAS)),
            ..container::Style::default()
        }
    }

    pub fn hero(_: &Theme) -> container::Style {
        container::Style {
            background: Some(gradient_background(
                Color::from_rgb8(0x0E, 0x20, 0x26),
                Color::from_rgb8(0x0C, 0x12, 0x1B),
            )),
            border: Border {
                color: BORDER,
                width: 1.0,
                radius: 20.0.into(),
            },
            shadow: Shadow {
                color: Color::from_rgba8(0x00, 0x00, 0x00, 0.35),
                offset: Vector::new(0.0, 8.0),
                blur_radius: 24.0,
            },
            ..container::Style::default()
        }
    }

    pub fn panel(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(SURFACE)),
            border: Border {
                color: BORDER,
                width: 1.0,
                radius: 18.0.into(),
            },
            shadow: Shadow {
                color: Color::from_rgba8(0x00, 0x00, 0x00, 0.28),
                offset: Vector::new(0.0, 6.0),
                blur_radius: 18.0,
            },
            ..container::Style::default()
        }
    }

    pub fn inset(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(SURFACE_ALT)),
            border: Border {
                color: BORDER,
                width: 1.0,
                radius: 12.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn active_transfer(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(ACCENT_TINT)),
            border: Border {
                color: ACCENT_DIM,
                width: 1.0,
                radius: 12.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn notice(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(DANGER_TINT)),
            border: Border {
                color: Color::from_rgb8(0x4A, 0x26, 0x30),
                width: 1.0,
                radius: 12.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn brand(_: &Theme) -> container::Style {
        container::Style {
            background: Some(gradient_background(ACCENT, ACCENT_BLUE)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 12.0.into(),
            },
            shadow: Shadow {
                color: Color::from_rgba8(0x5E, 0xEA, 0xD4, 0.22),
                offset: Vector::new(0.0, 4.0),
                blur_radius: 16.0,
            },
            ..container::Style::default()
        }
    }

    pub fn step_badge(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(ACCENT)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 7.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn avatar(selected: bool) -> impl Fn(&Theme) -> container::Style {
        move |_| container::Style {
            background: Some(Background::Color(if selected {
                ACCENT
            } else {
                ACCENT_TINT
            })),
            border: Border {
                color: if selected { ACCENT } else { ACCENT_DIM },
                width: 1.0,
                radius: 10.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn icon_tile(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(ACCENT_TINT)),
            border: Border {
                color: ACCENT_DIM,
                width: 1.0,
                radius: 10.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn icon_tile_muted(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(CHIP)),
            border: Border {
                color: BORDER,
                width: 1.0,
                radius: 10.0.into(),
            },
            ..container::Style::default()
        }
    }

    fn accent_ring(alpha: f32) -> container::Style {
        container::Style {
            background: Some(Background::Color(Color::from_rgba8(0x5E, 0xEA, 0xD4, 0.03))),
            border: Border {
                color: Color::from_rgba8(0x5E, 0xEA, 0xD4, alpha),
                width: 1.0,
                radius: 999.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn orb_outer(_: &Theme) -> container::Style {
        accent_ring(0.12)
    }

    pub fn orb_ring(_: &Theme) -> container::Style {
        accent_ring(0.24)
    }

    pub fn orb_core(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(ACCENT_TINT)),
            border: Border {
                color: ACCENT_DIM,
                width: 1.0,
                radius: 999.0.into(),
            },
            shadow: Shadow {
                color: Color::from_rgba8(0x5E, 0xEA, 0xD4, 0.18),
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

    pub fn chip(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(CHIP)),
            border: Border {
                color: BORDER,
                width: 1.0,
                radius: 999.0.into(),
            },
            ..container::Style::default()
        }
    }

    pub fn divider(_: &Theme) -> rule::Style {
        rule::Style {
            color: BORDER,
            radius: 0.0.into(),
            fill_mode: rule::FillMode::Full,
            snap: true,
        }
    }

    pub fn progress(_: &Theme) -> progress_bar::Style {
        progress_bar::Style {
            background: Background::Color(TRACK),
            bar: gradient_background(ACCENT, ACCENT_BLUE),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 6.0.into(),
            },
        }
    }

    pub fn primary_button(_: &Theme, status: button::Status) -> button::Style {
        let (background, text_color) = match status {
            button::Status::Active => (gradient_background(ACCENT, ACCENT_BLUE), ON_ACCENT),
            button::Status::Hovered => (
                gradient_background(ACCENT_HOVER, Color::from_rgb8(0x8B, 0xC5, 0xFF)),
                ON_ACCENT,
            ),
            button::Status::Pressed => (
                gradient_background(ACCENT_PRESSED, Color::from_rgb8(0x38, 0x7B, 0xD9)),
                ON_ACCENT,
            ),
            button::Status::Disabled => (Background::Color(DISABLED_BG), DISABLED_TEXT),
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

    pub fn secondary_button(_: &Theme, status: button::Status) -> button::Style {
        let (background, text_color, border_color) = match status {
            button::Status::Active => (SURFACE_ALT, TEXT_SECONDARY, BORDER_STRONG),
            button::Status::Hovered => (ROW_HOVER, TEXT, BORDER_STRONG),
            button::Status::Pressed => (ROW_PRESSED, TEXT, BORDER_STRONG),
            button::Status::Disabled => (DISABLED_BG, DISABLED_TEXT, BORDER),
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
        move |_, status| {
            let hovered = matches!(status, button::Status::Hovered);
            let pressed = matches!(status, button::Status::Pressed);
            let background = if selected {
                ACCENT_TINT
            } else if pressed {
                ROW_PRESSED
            } else if hovered {
                ROW_HOVER
            } else {
                SURFACE_ALT
            };
            let border_color = if selected {
                ACCENT
            } else if hovered || pressed {
                BORDER_STRONG
            } else {
                BORDER
            };

            button::Style {
                background: Some(Background::Color(background)),
                text_color: TEXT,
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
        App {
            tx: EventSink::new(64),
            devices: vec![device("AA:BB", "phone")],
            devices_request_id: 1,
            devices_loaded: true,
            devices_loading: false,
            devices_error: None,
            selected: Some("AA:BB".into()),
            file: Some(PathBuf::from("/tmp/kalo-test-file")),
            picking_file: false,
            log: Vec::new(),
            active_send: None,
            next_send_id: 1,
            send_result: None,
            incoming: Vec::new(),
            receiver_state: ReceiverStatus::Starting,
        }
    }

    fn active_send(id: u64) -> ActiveSend {
        ActiveSend {
            id,
            target: "phone (AA:BB)".into(),
            cancel: None,
            cancel_requested: false,
            progress: None,
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
        app.picking_file = true;
        let _ = update(&mut app, Message::SendClicked);
        assert!(app.active_send.is_none());
        assert!(
            app.log
                .iter()
                .any(|line| line.contains("finish choosing a file"))
        );
    }

    #[test]
    fn cancel_is_available_before_progress_arrives() {
        let mut app = app();
        let (cancel_tx, mut cancel_rx) = oneshot::channel();
        app.active_send = Some(ActiveSend {
            cancel: Some(cancel_tx),
            ..active_send(1)
        });

        let _ = update(&mut app, Message::CancelSend);
        assert!(matches!(cancel_rx.try_recv(), Ok(())));
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
    fn picker_cancel_preserves_existing_file() {
        let mut app = app();
        let previous = app.file.clone();
        app.picking_file = true;
        let _ = update(&mut app, Message::FilePicked(None));
        assert_eq!(app.file, previous);
        assert!(!app.picking_file);
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
            Message::FilePicked(Some(PathBuf::from("/tmp/next"))),
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
}
