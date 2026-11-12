//! Iced UI for the Kalo spike: devices, send with progress, receiver state, log.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use iced::widget::{button, column, container, progress_bar, row, scrollable, space, text};
use iced::{Element, Length, Subscription, Task};
use futures_util::SinkExt;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use zbus::Connection;

use crate::agent::{self, new_pending, PendingTransfers};
use crate::bluez::{self, DeviceInfo};
use crate::events::Event;
use crate::obex;
use crate::paths;

/// Shared handles for the event-pump subscription. iced 0.14 builds
/// subscriptions from plain `fn` builders, so the state must be static.
static EVENT_BUS: OnceLock<EventBus> = OnceLock::new();

struct EventBus {
    tx: UnboundedSender<Event>,
    rx_slot: Arc<Mutex<Option<UnboundedReceiver<Event>>>>,
    pending: PendingTransfers,
    downloads: PathBuf,
}

#[derive(Debug, Clone)]
pub enum Message {
    DevicesLoaded(Result<Vec<DeviceInfo>, String>),
    RefreshDevices,
    PickDevice(String),
    PickFile,
    FilePicked(Option<PathBuf>),
    SendClicked,
    SendFinished(Result<String, String>),
    Event(Event),
}

struct App {
    tx: UnboundedSender<Event>,
    devices: Vec<DeviceInfo>,
    /// Selected device address (stable across list refreshes; an index would
    /// go stale because `list_known_devices` re-sorts on every refresh).
    selected: Option<String>,
    file: Option<PathBuf>,
    log: Vec<String>,
    sending: bool,
    send_progress: Option<(f32, String)>,
    incoming_progress: Option<String>,
    receiver_state: String,
}

impl App {
    fn log(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > 300 {
            self.log.drain(0..100);
        }
    }
}

pub fn run() -> iced::Result {
    let (tx, rx) = unbounded_channel();
    let _ = EVENT_BUS.set(EventBus {
        tx: tx.clone(),
        rx_slot: Arc::new(Mutex::new(Some(rx))),
        pending: new_pending(),
        downloads: paths::downloads_dir(),
    });

    iced::application(
        || {
            let bus = EVENT_BUS.get().expect("event bus must be initialized");
            let app = App {
                tx: bus.tx.clone(),
                devices: Vec::new(),
                selected: None,
                file: None,
                log: vec!["Kalo spike ready.".to_string()],
                sending: false,
                send_progress: None,
                incoming_progress: None,
                receiver_state: "starting…".to_string(),
            };
            let task = Task::perform(bluez::list_known_devices(), |result| {
                Message::DevicesLoaded(result.map_err(|e| e.to_string()))
            });
            (app, task)
        },
        update,
        view,
    )
    .title("Kalo")
    .window_size((880.0, 640.0))
    .centered()
    .subscription(subscription)
    .run()
}

fn update(app: &mut App, message: Message) -> Task<Message> {
    match message {
        Message::DevicesLoaded(Ok(devices)) => {
            app.devices = devices;
            Task::none()
        }
        Message::DevicesLoaded(Err(e)) => {
            app.log(format!("devices: {e}"));
            Task::none()
        }
        Message::RefreshDevices => Task::perform(bluez::list_known_devices(), |result| {
            Message::DevicesLoaded(result.map_err(|e| e.to_string()))
        }),
        Message::PickDevice(address) => {
            app.selected = Some(address);
            Task::none()
        }
        Message::PickFile => Task::perform(
            async {
                rfd::AsyncFileDialog::new()
                    .set_title("Choose a file to send")
                    .pick_file()
                    .await
                    .map(|handle| handle.path().to_path_buf())
            },
            Message::FilePicked,
        ),
        Message::FilePicked(file) => {
            app.file = file;
            Task::none()
        }
        Message::SendClicked => {
            let Some(device) = resolve_target(&app.devices, app.selected.as_deref()) else {
                app.log("select a device first");
                return Task::none();
            };
            let Some(file) = app.file.clone() else {
                app.log("pick a file first");
                return Task::none();
            };
            let mac = device.address.clone();
            app.sending = true;
            app.send_progress = None;
            let tx = app.tx.clone();
            Task::perform(
                async move {
                    obex::send(&mac, &file, &tx).await.map(|summary| {
                        format!(
                            "sent {} bytes to {} in {:.1}s ({:.2} MB/s)",
                            summary.bytes, summary.mac, summary.elapsed_secs, summary.mbps
                        )
                    })
                },
                |result| Message::SendFinished(result.map_err(|e| e.to_string())),
            )
        }
        Message::SendFinished(Ok(summary)) => {
            app.sending = false;
            app.send_progress = None;
            app.log(format!("✔ {summary}"));
            Task::none()
        }
        Message::SendFinished(Err(e)) => {
            app.sending = false;
            app.send_progress = None;
            app.log(format!("✖ send failed: {e}"));
            Task::none()
        }
        Message::Event(event) => handle_event(app, event),
    }
}

fn handle_event(app: &mut App, event: Event) -> Task<Message> {
    match event {
        Event::Log(line) => app.log(line),
        Event::SendProgress {
            transferred,
            size,
            status,
        } => {
            let fraction = size
                .filter(|s| *s > 0)
                .map(|s| (transferred as f32 / s as f32).clamp(0.0, 1.0))
                .unwrap_or(0.0);
            let line = match size {
                Some(s) => format!("send {status}: {transferred}/{s} bytes"),
                None => format!("send {status}: {transferred} bytes"),
            };
            app.send_progress = Some((fraction, line));
        }
        Event::IncomingStarted {
            sender,
            name,
            size,
            ..
        } => {
            let size_note = size
                .map(|s| format!(" ({s} bytes)"))
                .unwrap_or_default();
            app.log(format!("⇣ incoming from {sender}: {name}{size_note}"));
            app.incoming_progress = None;
        }
        Event::IncomingProgress { transferred, .. } => {
            let transferred = transferred.unwrap_or(0);
            app.incoming_progress = Some(format!("receiving… {transferred} bytes"));
        }
        Event::IncomingDone {
            saved_to,
            bytes,
            elapsed_secs,
            mbps,
        } => {
            app.log(format!(
                "⇣ saved {saved_to:?} — {bytes} bytes in {elapsed_secs:.1}s ({mbps:.2} MB/s)"
            ));
            app.incoming_progress = None;
        }
        Event::IncomingFailed { name, error } => {
            app.log(format!("✖ incoming failed ({name}): {error}"));
            app.incoming_progress = None;
        }
        Event::ReceiverState(state) => {
            app.receiver_state = state.clone();
            app.log(format!("receiver: {state}"));
        }
    }
    Task::none()
}

fn subscription(_app: &App) -> Subscription<Message> {
    Subscription::run(|| {
        iced::stream::channel(100, |mut out: futures::channel::mpsc::Sender<Message>| async move {
            let Some(bus) = EVENT_BUS.get() else {
                return;
            };
            let Some(mut rx) = bus.rx_slot.lock().expect("rx slot").take() else {
                // The channel was already consumed (subscription re-created):
                // surface it instead of dying silently.
                let _ = out
                    .send(Message::Event(Event::ReceiverState(
                        "event pump restarted but its channel was already consumed — restart Kalo"
                            .into(),
                    )))
                    .await;
                return;
            };
            let conn = match Connection::session().await {
                Ok(conn) => conn,
                Err(e) => {
                    let _ = out
                        .send(Message::Event(Event::ReceiverState(format!(
                            "D-Bus session error: {e}"
                        ))))
                        .await;
                    return;
                }
            };
            // The receiver registers itself and reports state via events. On
            // failure (e.g. the OBEX agent slot is taken by Blueman) the pump
            // goes passive: it still forwards events, but stops polling
            // incoming transfers that will never arrive.
            let receiver_active =
                agent::start(&conn, bus.pending.clone(), bus.tx.clone()).await.is_ok();

            loop {
                tokio::select! {
                    event = rx.recv() => {
                        match event {
                            Some(event) => {
                                let _ = out.send(Message::Event(event)).await;
                            }
                            None => break,
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(500)), if receiver_active => {
                        agent::poll_pending(&conn, &bus.pending, &bus.downloads, &bus.tx).await;
                    }
                }
            }
        })
    })
}

fn view(app: &App) -> Element<'_, Message> {
    let device_rows: Vec<Element<'_, Message>> = app
        .devices
        .iter()
        .map(|device| {
            let marker = if app.selected.as_deref() == Some(device.address.as_str()) {
                "▶ "
            } else {
                "  "
            };
            let label = format!(
                "{marker}{} — {} [paired:{} trusted:{} connected:{}]",
                device.alias, device.address, device.paired, device.trusted, device.connected
            );
            button(text(label))
                .width(Length::Fill)
                .on_press(Message::PickDevice(device.address.clone()))
                .into()
        })
        .collect();

    let devices_box = if device_rows.is_empty() {
        scrollable(text("no devices known to BlueZ yet — pair one first").size(12))
            .height(Length::FillPortion(3))
    } else {
        scrollable(column(device_rows).spacing(4)).height(Length::FillPortion(3))
    };

    let target = resolve_target(&app.devices, app.selected.as_deref())
        .map(|d| format!("target: {} ({})", d.alias, d.address))
        .unwrap_or_else(|| "target: —".to_string());
    let file = app
        .file
        .as_ref()
        .map(|p| format!("file: {}", p.display()))
        .unwrap_or_else(|| "file: —".to_string());
    let can_send = resolve_target(&app.devices, app.selected.as_deref()).is_some()
        && app.file.is_some()
        && !app.sending;

    let mut send_box = column![
        text(target).size(13),
        text(file).size(13),
        row![
            button("Choose file…")
                .on_press_maybe((!app.sending).then_some(Message::PickFile)),
            button("Send via Bluetooth")
                .on_press_maybe(can_send.then_some(Message::SendClicked)),
            button("Refresh devices").on_press(Message::RefreshDevices),
        ]
        .spacing(10),
    ]
    .spacing(6);

    if let Some((fraction, line)) = app.send_progress.as_ref().filter(|_| app.sending) {
        send_box = send_box
            .push(text(line.clone()).size(12))
            .push(progress_bar(0.0..=1.0, *fraction));
    }

    let mut log_rows: Vec<Element<'_, Message>> =
        app.log.iter().map(|line| text(line.clone()).size(12).into()).collect();
    if let Some(line) = app.incoming_progress.as_ref() {
        log_rows.push(text(line.clone()).size(12).into());
    }

    let content = column![
        row![
            text("Kalo").size(26),
            space(),
            text(app.receiver_state.clone()).size(12),
        ],
        text("Devices").size(16),
        devices_box,
        send_box,
        text("Log").size(16),
        scrollable(column(log_rows).spacing(2)).height(Length::FillPortion(2)),
    ]
    .spacing(10)
    .width(Length::Fill)
    .height(Length::Fill);

    container(content).padding(16).into()
}

/// Resolve the selected device by address (pure helper, unit-tested):
/// stale selections that no longer match any listed device resolve to
/// `None` instead of pointing at the wrong entry.
fn resolve_target<'a>(
    devices: &'a [DeviceInfo],
    selected: Option<&str>,
) -> Option<&'a DeviceInfo> {
    let address = selected?;
    devices
        .iter()
        .find(|d| d.address.eq_ignore_ascii_case(address))
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
}
