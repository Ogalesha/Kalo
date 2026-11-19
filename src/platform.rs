//! Platform facade.
//!
//! The UI and CLI talk to one set of names. Linux maps them onto BlueZ/obexd,
//! Windows onto WinRT RFCOMM plus the native OBEX implementation, and macOS
//! onto IOBluetooth. Keeping the facade small makes the shared event contract
//! the only thing backends must agree on.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};

use crate::crypto::{Encryption, TempContainer};
use crate::events::{Event, EventSink, format_bytes};
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
    encryption: &Encryption,
) -> Result<BatchSummary> {
    if files.is_empty() {
        bail!("no files to send");
    }
    let mut sizes = Vec::with_capacity(files.len());
    for file in files {
        sizes.push(security::check_send_file(file)?);
    }
    // Derive the batch key once, then validate every container size before
    // anything moves. Argon2id is deliberately expensive, so keep it off the
    // async runtime thread; a failure here still stops the batch before the
    // receiver has anything to undo.
    let encryption = encryption.clone();
    let encryptor = tokio::task::spawn_blocking(move || encryption.encryptor())
        .await
        .context("encryption setup task failed")??
        .map(Arc::new);
    if let Some(encryptor) = &encryptor {
        for (file, size) in files.iter().zip(&sizes) {
            let name = file
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| file.display().to_string());
            encryptor
                .container_len(*size, &name)
                .with_context(|| format!("cannot encrypt {}", file.display()))?;
        }
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
            name: name.clone(),
        });

        let container = match &encryptor {
            Some(encryptor) => {
                events.send(Event::Log(format!(
                    "encrypting {name} for Kalo-to-Kalo delivery…"
                )));
                let container = TempContainer::new()?;
                let source = file.clone();
                let target = container.path().to_path_buf();
                let metadata_name = name.clone();
                let encryptor = encryptor.clone();
                let encrypted = tokio::task::spawn_blocking(move || {
                    encryptor.encrypt_file(&source, &target, &metadata_name)
                })
                .await
                .context("encryption task failed")??;
                if cancel.is_cancelled() {
                    bail!("send canceled");
                }
                events.send(Event::Log(format!(
                    "encrypted {name} ({} container); the receiver needs the same passphrase",
                    format_bytes(encrypted)
                )));
                Some(container)
            }
            None => None,
        };
        let send_path = container
            .as_ref()
            .map(|container| container.path())
            .unwrap_or(file);
        let summary = send_one(mac, send_path, events, send_id, &cancel).await?;
        events.send(Event::Log(summary.line()));
        // Report the user's plaintext size in the batch summary; the backend
        // line above still shows the actual ciphertext bytes on the wire.
        bytes += if encryptor.is_some() {
            sizes[position]
        } else {
            summary.bytes
        };
        // Drop the plaintext-equivalent temp container before the next file.
        drop(container);
    }

    Ok(BatchSummary::new(
        mac,
        total,
        bytes,
        started.elapsed().as_secs_f64(),
    ))
}
