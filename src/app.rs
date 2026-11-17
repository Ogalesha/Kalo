//! Iced UI for the Kalo spike: devices, send with progress, receiver state, log.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::SinkExt;
use iced::widget::{button, column, container, progress_bar, row, rule, scrollable, space, text};
use iced::{Alignment, Color, Element, Font, Length, Padding, Subscription, Task, Theme};
use tokio::sync::broadcast;
use tokio::sync::oneshot;

use crate::agent::{self, PendingTransfers, ReceiverHandle, new_pending};
use crate::bluez::{self, DeviceInfo};
use crate::events::{
    Event, EventSink, ReceiverStatus, format_bytes, send_progress_summary, transfer_fraction,
};
use crate::obex;
use crate::paths;

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
        tokio::spawn(agent::run_receiver(
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
            let task = Task::perform(bluez::list_known_devices(), move |result| {
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
    .theme(|_: &App| Theme::Light)
    .window_size((880.0, 640.0))
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
            Task::perform(bluez::list_known_devices(), move |result| {
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
                    obex::send(&mac, &file, &tx, send_id, Some(cancel_rx))
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
        column![
            text("Kalo").size(26).font(ui::BOLD).color(ui::TEXT),
            text("Bluetooth file transfer")
                .size(12.5)
                .color(ui::TEXT_SECONDARY),
        ]
        .spacing(1),
        space().width(Length::Fill),
        receiver_summary(&app.receiver_state),
    ]
    .width(Length::Fill)
    .align_y(Alignment::Center);

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
            text("Device")
                .size(12)
                .font(ui::MEDIUM)
                .color(ui::TEXT_MUTED),
            space().width(Length::Fill),
            button(
                text(if app.devices_loading {
                    "Refreshing…"
                } else {
                    "Refresh"
                })
                .size(12)
                .font(ui::MEDIUM),
            )
            .padding([5, 10])
            .style(ui::secondary_button)
            .on_press_maybe((!app.devices_loading).then_some(Message::RefreshDevices)),
        ]
        .width(Length::Fill)
        .align_y(Alignment::Center),
    ]
    .spacing(8)
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
            .size(14)
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
                .size(11.5)
                .color(ui::TEXT_MUTED),
        );
    }

    let file_button_label = if app.picking_file {
        "Choosing…"
    } else if app.file.is_some() {
        "Change file…"
    } else {
        "Choose file…"
    };
    let file_section = column![
        text("File").size(12).font(ui::MEDIUM).color(ui::TEXT_MUTED),
        row![
            file_info,
            button(text(file_button_label).size(12.5).font(ui::MEDIUM))
                .padding([8, 12])
                .style(ui::secondary_button)
                .on_press_maybe((!is_sending && !app.picking_file).then_some(Message::PickFile)),
        ]
        .spacing(12)
        .align_y(Alignment::Center),
    ]
    .spacing(6);

    let send_panel = container(
        column![
            column![
                text("Send a file")
                    .size(18)
                    .font(ui::SEMIBOLD)
                    .color(ui::TEXT),
                text("Pick a paired device, then choose a file.")
                    .size(12.5)
                    .color(ui::TEXT_SECONDARY),
            ]
            .spacing(3),
            device_section,
            rule::horizontal(1).style(ui::divider),
            file_section,
            send_action(app, target),
        ]
        .spacing(16)
        .height(Length::Fill),
    )
    .padding(22)
    .width(Length::FillPortion(3))
    .height(Length::Fill)
    .style(ui::panel);

    let mut incoming_header = row![text("Incoming").size(18).font(ui::SEMIBOLD).color(ui::TEXT),]
        .spacing(8)
        .align_y(Alignment::Center);
    if !app.incoming.is_empty() {
        incoming_header = incoming_header.push(
            text(format!("{} in progress", app.incoming.len()))
                .size(11.5)
                .font(ui::MEDIUM)
                .color(ui::ACCENT_TEXT),
        );
    }

    let mut incoming_body = column![].spacing(10).width(Length::Fill);
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
                .spacing(14)
                .width(Length::Fill),
            )
            .height(Length::Fixed(160.0)),
        );
    }

    let activity: Element<'_, Message> = if app.log.is_empty() {
        column![
            text("No activity yet")
                .size(13)
                .font(ui::MEDIUM)
                .color(ui::TEXT),
            text("Sent and received files will be listed here.")
                .size(12)
                .color(ui::TEXT_SECONDARY),
        ]
        .spacing(3)
        .into()
    } else {
        let rows: Vec<Element<'_, Message>> = app
            .log
            .iter()
            .rev()
            .map(|line| {
                text(line.clone())
                    .size(12)
                    .line_height(1.35)
                    .color(ui::TEXT_SECONDARY)
                    .width(Length::Fill)
                    .into()
            })
            .collect();
        scrollable(column(rows).spacing(8).width(Length::Fill))
            .height(Length::Fill)
            .into()
    };

    let activity_block = column![
        text("Activity").size(18).font(ui::SEMIBOLD).color(ui::TEXT),
        activity,
    ]
    .spacing(10)
    .height(Length::Fill);

    let right_panel = container(
        column![
            column![incoming_header, incoming_body].spacing(10),
            rule::horizontal(1).style(ui::divider),
            activity_block,
        ]
        .spacing(16)
        .height(Length::Fill),
    )
    .padding(22)
    .width(Length::FillPortion(2))
    .height(Length::Fill)
    .style(ui::panel);

    let body = row![send_panel, right_panel]
        .spacing(20)
        .width(Length::Fill)
        .height(Length::Fill);

    container(
        column![header, body]
            .spacing(20)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .padding(Padding::from([24, 28]))
    .width(Length::Fill)
    .height(Length::Fill)
    .style(ui::canvas)
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
        ui::TEXT_SECONDARY
    };

    column![
        container(
            row![
                container(space()).width(7).height(7).style(ui::dot(dot)),
                text(label).size(12).font(ui::MEDIUM).color(text_color),
            ]
            .spacing(7)
            .align_y(Alignment::Center),
        )
        .padding([5, 10])
        .style(ui::pill(tint)),
        text(detail).size(11).color(detail_color),
    ]
    .spacing(4)
    .align_x(Alignment::End)
    .into()
}

fn device_button(device: &DeviceInfo, selected: bool, enabled: bool) -> Element<'_, Message> {
    let mut meta = row![
        text(&device.address)
            .size(11.5)
            .font(ui::MONO)
            .color(ui::TEXT_MUTED),
    ]
    .spacing(7)
    .align_y(Alignment::Center);
    if device.connected {
        meta = meta.push(badge("Connected", ui::SUCCESS_TINT, ui::SUCCESS_TEXT));
    }
    if !device.paired {
        meta = meta.push(badge("Not paired", ui::WARNING_TINT, ui::WARNING_TEXT));
    }

    let trailing = if selected {
        text("Selected")
            .size(11.5)
            .font(ui::SEMIBOLD)
            .color(ui::ACCENT_TEXT)
    } else {
        text("Select").size(11.5).color(ui::TEXT_MUTED)
    };

    let content = row![
        column![
            text(device_name(device))
                .size(14)
                .font(ui::SEMIBOLD)
                .color(if enabled {
                    ui::TEXT
                } else {
                    ui::TEXT_SECONDARY
                }),
            meta,
        ]
        .spacing(3)
        .width(Length::Fill),
        trailing,
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .width(Length::Fill);

    button(content)
        .width(Length::Fill)
        .padding([9, 11])
        .style(ui::device_row(selected))
        .on_press_maybe(enabled.then(|| Message::PickDevice(device.address.clone())))
        .into()
}

fn badge(label: &str, background: Color, text_color: Color) -> Element<'_, Message> {
    container(text(label).size(11).font(ui::SEMIBOLD).color(text_color))
        .padding([1, 7])
        .style(ui::fill(background, 999.0))
        .into()
}

fn device_empty_state(loaded: bool, error: Option<&str>) -> Element<'_, Message> {
    if !loaded {
        column![
            text("Looking for paired devices…")
                .size(13.5)
                .font(ui::MEDIUM)
                .color(ui::TEXT),
            text("This usually takes a moment.")
                .size(12)
                .color(ui::TEXT_SECONDARY),
        ]
        .spacing(4)
        .into()
    } else if let Some(error) = error {
        column![
            text("Couldn't load paired devices")
                .size(13.5)
                .font(ui::MEDIUM)
                .color(ui::DANGER_TEXT),
            text(error).size(11.5).color(ui::TEXT_SECONDARY),
            text("Choose Refresh to try again.")
                .size(11.5)
                .color(ui::TEXT_MUTED),
        ]
        .spacing(3)
        .into()
    } else {
        column![
            text("No paired devices")
                .size(13.5)
                .font(ui::MEDIUM)
                .color(ui::TEXT),
            text("Pair one in your Bluetooth settings, then choose Refresh.")
                .size(12)
                .color(ui::TEXT_SECONDARY),
        ]
        .spacing(4)
        .into()
    }
}

fn receiver_notice(reason: &str) -> Element<'_, Message> {
    container(
        column![
            text("Incoming files are unavailable")
                .size(12.5)
                .font(ui::SEMIBOLD)
                .color(ui::DANGER_TEXT),
            text(reason).size(11.5).color(ui::TEXT_SECONDARY),
            text("Kalo retries automatically. Restart it if this persists.")
                .size(11.5)
                .color(ui::TEXT_SECONDARY),
        ]
        .spacing(3),
    )
    .padding(11)
    .width(Length::Fill)
    .style(ui::fill(ui::DANGER_TINT, 10.0))
    .into()
}

fn incoming_empty(state: &ReceiverStatus) -> Element<'_, Message> {
    let detail = match state {
        ReceiverStatus::Starting => "The receiver is starting. Incoming files will appear here.",
        _ => "Files sent to this computer appear here.",
    };

    column![
        text("Nothing incoming")
            .size(13.5)
            .font(ui::MEDIUM)
            .color(ui::TEXT),
        text(detail).size(12).color(ui::TEXT_SECONDARY),
    ]
    .spacing(3)
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
            .size(14)
            .font(ui::MEDIUM)
            .color(ui::TEXT)
            .width(Length::Fill),
    ]
    .spacing(10)
    .align_y(Alignment::Center);
    if let Some(percent) = percent {
        title = title.push(
            text(percent)
                .size(12)
                .font(ui::SEMIBOLD)
                .color(ui::ACCENT_TEXT),
        );
    }

    let mut content = column![
        title,
        text(format!("{from} · {amount}"))
            .size(12)
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
    content.into()
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
                .size(14)
                .font(ui::SEMIBOLD)
                .color(ui::TEXT)
                .width(Length::Fill),
        ]
        .spacing(10)
        .align_y(Alignment::Center);
        if let Some(fraction) = fraction {
            top = top.push(
                text(format!("{:.0}%", fraction * 100.0))
                    .size(13)
                    .font(ui::SEMIBOLD)
                    .color(ui::ACCENT_TEXT),
            );
        }

        let cancel = button(
            text(if active.cancel_requested {
                "Canceling…"
            } else {
                "Cancel"
            })
            .size(12.5)
            .font(ui::MEDIUM),
        )
        .padding([7, 12])
        .style(ui::secondary_button)
        .on_press_maybe((!active.cancel_requested).then_some(Message::CancelSend));

        let bottom = row![
            text(detail)
                .size(12)
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
        return block.push(bottom).into();
    }

    let can_send = target.is_some() && app.file.is_some() && !app.picking_file;
    let guidance = match (target.is_some(), app.file.is_some()) {
        (false, false) => "Select a device and choose a file.",
        (false, true) => "Select a device to send this file.",
        (true, false) => "Choose a file to send.",
        (true, true) => "",
    };
    let send_label = target
        .map(|device| format!("Send to {}", device_name(device)))
        .unwrap_or_else(|| "Send file".to_string());

    let mut block = column![
        container(text(guidance).size(12).color(ui::TEXT_MUTED)).height(Length::Fixed(18.0)),
        button(text(send_label).size(14.5).font(ui::SEMIBOLD))
            .width(Length::Fill)
            .padding([11, 16])
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
                    .size(12)
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

/// Visual system for the Operate surface. Colors are fixed to a light theme
/// so contrast and state meaning stay predictable on every desktop.
mod ui {
    use iced::font::Weight;
    use iced::widget::{button, container, progress_bar, rule};
    use iced::{Background, Border, Color, Font, Shadow, Theme, Vector};

    pub const CANVAS: Color = Color::from_rgb8(0xF3, 0xF5, 0xF7);
    pub const SURFACE: Color = Color::WHITE;
    pub const BORDER: Color = Color::from_rgb8(0xE1, 0xE7, 0xED);
    pub const BORDER_STRONG: Color = Color::from_rgb8(0xC9, 0xD3, 0xDD);
    pub const TEXT: Color = Color::from_rgb8(0x18, 0x22, 0x2D);
    pub const TEXT_SECONDARY: Color = Color::from_rgb8(0x55, 0x61, 0x6E);
    pub const TEXT_MUTED: Color = Color::from_rgb8(0x66, 0x72, 0x7F);
    pub const ACCENT: Color = Color::from_rgb8(0x1D, 0x4E, 0xD8);
    pub const ACCENT_HOVER: Color = Color::from_rgb8(0x1E, 0x40, 0xAF);
    pub const ACCENT_PRESSED: Color = Color::from_rgb8(0x1E, 0x3A, 0x8A);
    pub const ACCENT_TEXT: Color = Color::from_rgb8(0x1E, 0x40, 0xAF);
    pub const ACCENT_TINT: Color = Color::from_rgb8(0xEE, 0xF4, 0xFF);
    pub const ROW_HOVER: Color = Color::from_rgb8(0xF7, 0xF9, 0xFB);
    pub const ROW_PRESSED: Color = Color::from_rgb8(0xEF, 0xF3, 0xF7);
    pub const TRACK: Color = Color::from_rgb8(0xE6, 0xEC, 0xF2);
    pub const DISABLED_BG: Color = Color::from_rgb8(0xEC, 0xF0, 0xF4);
    pub const DISABLED_TEXT: Color = Color::from_rgb8(0x5B, 0x6B, 0x7C);
    pub const SUCCESS: Color = Color::from_rgb8(0x16, 0xA3, 0x4A);
    pub const SUCCESS_TINT: Color = Color::from_rgb8(0xEC, 0xFD, 0xF3);
    pub const SUCCESS_TEXT: Color = Color::from_rgb8(0x16, 0x65, 0x34);
    pub const WARNING: Color = Color::from_rgb8(0xD9, 0x77, 0x06);
    pub const WARNING_TINT: Color = Color::from_rgb8(0xFF, 0xF7, 0xED);
    pub const WARNING_TEXT: Color = Color::from_rgb8(0x92, 0x40, 0x0E);
    pub const DANGER: Color = Color::from_rgb8(0xDC, 0x26, 0x26);
    pub const DANGER_TINT: Color = Color::from_rgb8(0xFE, 0xF2, 0xF2);
    pub const DANGER_TEXT: Color = Color::from_rgb8(0x99, 0x1B, 0x1B);

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

    pub fn canvas(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(CANVAS)),
            ..container::Style::default()
        }
    }

    pub fn panel(_: &Theme) -> container::Style {
        container::Style {
            background: Some(Background::Color(SURFACE)),
            border: Border {
                color: BORDER,
                width: 1.0,
                radius: 14.0.into(),
            },
            shadow: Shadow {
                color: Color::from_rgba8(0x0F, 0x17, 0x2A, 0.04),
                offset: Vector::new(0.0, 1.0),
                blur_radius: 4.0,
            },
            ..container::Style::default()
        }
    }

    /// A flat tinted surface: used for badges, status pills and notices.
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
            bar: Background::Color(ACCENT),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 6.0.into(),
            },
        }
    }

    pub fn primary_button(_: &Theme, status: button::Status) -> button::Style {
        let (background, text_color) = match status {
            button::Status::Active => (ACCENT, Color::WHITE),
            button::Status::Hovered => (ACCENT_HOVER, Color::WHITE),
            button::Status::Pressed => (ACCENT_PRESSED, Color::WHITE),
            button::Status::Disabled => (DISABLED_BG, DISABLED_TEXT),
        };

        button::Style {
            background: Some(Background::Color(background)),
            text_color,
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 10.0.into(),
            },
            ..button::Style::default()
        }
    }

    pub fn secondary_button(_: &Theme, status: button::Status) -> button::Style {
        let (background, text_color, border_color) = match status {
            button::Status::Active => (SURFACE, TEXT_SECONDARY, BORDER_STRONG),
            button::Status::Hovered => (ROW_HOVER, TEXT, BORDER_STRONG),
            button::Status::Pressed => (ROW_PRESSED, TEXT, BORDER_STRONG),
            button::Status::Disabled => (SURFACE, DISABLED_TEXT, BORDER),
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
                SURFACE
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
                    radius: 10.0.into(),
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
