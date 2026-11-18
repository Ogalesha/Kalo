//! Platform facade.
//!
//! The UI and CLI talk to one set of names. Linux maps them onto BlueZ/obexd,
//! Windows onto WinRT RFCOMM plus the native OBEX implementation, and macOS
//! onto IOBluetooth. Keeping the facade small makes the shared event contract
//! the only thing backends must agree on.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Result, bail};

use crate::events::{Event, EventSink};
use crate::security;
use crate::transfer::{BatchSummary, Cancel};

#[cfg(target_os = "linux")]
pub use crate::agent::{PendingTransfers, agent_check, new_pending, receive, run_receiver};
#[cfg(target_os = "linux")]
pub use crate::bluez::{
    DeviceInfo, connectable, list_adapters, list_devices, list_known_devices, pair,
};
#[cfg(target_os = "linux")]
use crate::obex::send as send_one;

#[cfg(windows)]
use crate::win::send as send_one;
#[cfg(windows)]
pub use crate::win::{
    DeviceInfo, PendingTransfers, agent_check, connectable, list_adapters, list_devices,
    list_known_devices, new_pending, pair, receive, run_receiver,
};

#[cfg(target_os = "macos")]
use crate::mac::send as send_one;
#[cfg(target_os = "macos")]
pub use crate::mac::{
    DeviceInfo, PendingTransfers, agent_check, connectable, list_adapters, list_devices,
    list_known_devices, new_pending, pair, receive, run_receiver,
};

pub use crate::receiver::ReceiverHandle;

/// Send one file or a whole selection to `mac`.
///
/// Every file is validated and hashed before the first byte moves, so a
/// blocked or unreadable file stops the batch while the receiver still has
/// nothing to undo. Files are then sent sequentially over one OPP session per
/// file (the profile has no multi-object session), sharing one cancellation
/// signal. The first failure stops the queue; the caller reports which files
/// completed.
pub async fn send(
    mac: &str,
    files: &[PathBuf],
    events: &EventSink,
    send_id: u64,
    cancel: Cancel,
) -> Result<BatchSummary> {
    if files.is_empty() {
        bail!("no files to send");
    }
    if let Some(error) = files
        .iter()
        .find_map(|file| security::check_send_file(file).err())
    {
        return Err(error);
    }
    if cancel.is_cancelled() {
        bail!("send canceled");
    }

    let started = Instant::now();
    let total = files.len();
    let mut bytes = 0u64;
    for (position, file) in files.iter().enumerate() {
        if cancel.is_cancelled() {
            bail!("send canceled");
        }
        let name = file
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| file.display().to_string());
        events.send(Event::SendFileStarted {
            send_id,
            index: position + 1,
            total,
            name,
        });
        let summary = send_one(mac, file, events, send_id, &cancel).await?;
        events.send(Event::Log(summary.line()));
        bytes += summary.bytes;
    }

    Ok(BatchSummary::new(
        mac,
        total,
        bytes,
        started.elapsed().as_secs_f64(),
    ))
}
