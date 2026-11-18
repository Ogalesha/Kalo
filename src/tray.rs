//! Status-area (system tray) icon on Linux.
//!
//! Kalo keeps running in the panel when the window is closed, like other
//! background transfer apps. The tray uses the freedesktop StatusNotifierItem
//! protocol, so it works in horizontal and vertical panels that implement it
//! (KDE Plasma, Cinnamon, XFCE, and GNOME with the AppIndicator extension).

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, Receiver, Sender};
#[cfg(target_os = "linux")]
use std::sync::{Mutex, OnceLock};
#[cfg(target_os = "linux")]
use std::time::Duration;

/// A command chosen from the tray icon.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    Show,
    Quit,
}

#[cfg(target_os = "linux")]
static ACTIONS: OnceLock<Mutex<Receiver<TrayAction>>> = OnceLock::new();
#[cfg(target_os = "linux")]
static STARTED: AtomicBool = AtomicBool::new(false);

/// Start the tray icon once. Returns whether a status-area host accepted it.
///
/// The call is bounded so a desktop without a StatusNotifierWatcher cannot
/// delay startup; in that case Kalo falls back to normal window-close behavior.
#[cfg(target_os = "linux")]
pub fn start() -> bool {
    if STARTED.swap(true, Ordering::SeqCst) {
        return ACTIONS.get().is_some();
    }

    let (tx, rx) = mpsc::channel();
    let _ = ACTIONS.set(Mutex::new(rx));
    let (ready_tx, ready_rx) = mpsc::channel();

    std::thread::spawn(move || {
        use ksni::blocking::TrayMethods;

        match (KaloTray { tx }).spawn() {
            Ok(_handle) => {
                let _ = ready_tx.send(true);
                // The handle must stay alive for as long as the panel item.
                loop {
                    std::thread::park();
                }
            }
            Err(error) => {
                eprintln!("Kalo tray icon unavailable: {error}");
                let _ = ready_tx.send(false);
            }
        }
    });

    ready_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
pub fn start() -> bool {
    false
}

/// Drain actions queued by tray clicks and menu entries.
pub fn poll() -> Vec<TrayAction> {
    #[cfg(target_os = "linux")]
    {
        let Some(actions) = ACTIONS.get() else {
            return Vec::new();
        };
        actions
            .lock()
            .expect("tray actions lock")
            .try_iter()
            .collect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct KaloTray {
    tx: Sender<TrayAction>,
}

#[cfg(target_os = "linux")]
impl ksni::Tray for KaloTray {
    fn id(&self) -> String {
        "org.kalo.Kalo".into()
    }

    fn title(&self) -> String {
        "Kalo".into()
    }

    fn icon_name(&self) -> String {
        "kalo".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![tray_icon()]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            icon_name: "kalo".into(),
            icon_pixmap: vec![tray_icon()],
            title: "Kalo".into(),
            description: "Bluetooth file transfer · receiver ready".into(),
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.send(TrayAction::Show);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;

        vec![
            StandardItem {
                label: "Open Kalo".into(),
                icon_name: "kalo".into(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.tx.send(TrayAction::Show);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit Kalo".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.tx.send(TrayAction::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

#[cfg(target_os = "linux")]
fn tray_icon() -> ksni::Icon {
    let image = image::load_from_memory(include_bytes!(
        "../packaging/common/icons/hicolor/64x64/apps/kalo.png"
    ))
    .expect("bundled tray icon is a valid PNG")
    .to_rgba8();
    let (width, height) = image.dimensions();
    let mut data = image.into_vec();
    // StatusNotifierItem expects ARGB32 in network byte order.
    let (pixels, _) = data.as_chunks_mut::<4>();
    for pixel in pixels {
        pixel.rotate_right(1);
    }
    ksni::Icon {
        width: width as i32,
        height: height as i32,
        data,
    }
}
