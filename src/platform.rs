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

/// Send a small Kalo control object (pairing request, response or
/// confirmation) as a normal OPP push. Control objects are temporary and
/// always removed after the attempt.
pub async fn send_control(mac: &str, bytes: &[u8], events: &EventSink) -> Result<()> {
    let file = crate::identity::PairingFile::new(bytes)?;
    let (_handle, cancel) = Cancel::new();
    send_one(mac, file.path(), events, u64::MAX, &cancel).await?;
    Ok(())
}

/// Send one file or a whole selection to `mac`.
///
/// Every file is validated and hashed before the first byte moves, so a
/// blocked or unreadable file stops the batch while the receiver still has
/// nothing to undo. Files are then sent sequentially over one OPP session per
/// file (the profile has no multi-object session), sharing one cancellation
/// signal. The first failure stops the queue; the caller reports which files
/// completed.
#[allow(clippy::too_many_arguments)]
pub async fn send(
    mac: &str,
    files: &[PathBuf],
    events: &EventSink,
    send_id: u64,
    cancel: Cancel,
    encryption: &Encryption,
    trust: &crate::trust::TrustStore,
    pairing: Option<&crate::identity::PairingManager>,
) -> Result<BatchSummary> {
    if files.is_empty() {
        bail!("no files to send");
    }
    let mut sizes = Vec::with_capacity(files.len());
    for file in files {
        sizes.push(security::check_send_file(file)?);
    }

    // A paired device always uses the authenticated per-device container.
    // Never downgrade a paired sender to the shared passphrase or plaintext:
    // that would silently weaken a channel the user explicitly paired.
    // Fail closed on the pinned key, not on both directions being intact: a
    // damaged incoming chain must not turn a paired send into a plaintext or
    // shared-passphrase one that the peer would reject (or an impersonator
    // could read).
    let peer = if trust.is_pinned(mac) {
        let pairing = pairing.context(
            "this device is paired, but the local pairing identity is unavailable; \
             refusing to send without per-device encryption",
        )?;
        let chain = trust
            .outgoing_chain(mac)
            .context("the paired device has no outgoing key chain; pair it again")?;
        Some((pairing.identity().signing_key(), chain.key, chain.step))
    } else {
        None
    };

    // Derive the batch key once, then validate every container size before
    // anything moves. Argon2id is deliberately expensive, so keep it off the
    // async runtime thread; a failure here still stops the batch before the
    // receiver has anything to undo.
    let encryption = encryption.clone();
    let passphrase_encryptor = if peer.is_none() {
        tokio::task::spawn_blocking(move || encryption.encryptor())
            .await
            .context("encryption setup task failed")??
            .map(Arc::new)
    } else {
        None
    };
    if let Some((signing, chain, step)) = &peer {
        let encryptor = crate::crypto::PeerEncryptor::new(*chain, *step, signing.clone());
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
    } else if let Some(encryptor) = &passphrase_encryptor {
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

    let mut peer = peer;
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

        let container = if let Some((signing, chain, step)) = &peer {
            events.send(Event::Log(format!(
                "encrypting {name} with the paired-device key…"
            )));
            let container = TempContainer::new()?;
            let source = file.clone();
            let target = container.path().to_path_buf();
            let metadata_name = name.clone();
            let encryptor = crate::crypto::PeerEncryptor::new(*chain, *step, signing.clone());
            let encrypted = tokio::task::spawn_blocking(move || {
                encryptor.encrypt_file(&source, &target, &metadata_name)
            })
            .await
            .context("encryption task failed")??;
            if cancel.is_cancelled() {
                // The sender burned this step even though nothing left the
                // machine; persist it so a later file cannot reuse it.
                let (next, next_step) =
                    crate::crypto::PeerEncryptor::new(*chain, *step, signing.clone()).next_state();
                let _ = trust.commit_outgoing(mac, *step, next);
                let _ = next_step;
                bail!("send canceled");
            }
            events.send(Event::Log(format!(
                "encrypted {name} ({} paired-device container)",
                format_bytes(encrypted)
            )));
            Some(container)
        } else if let Some(encryptor) = &passphrase_encryptor {
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
        } else {
            None
        };

        let send_path = container
            .as_ref()
            .map(|container| container.path())
            .unwrap_or(file);
        let send_result = send_one(mac, send_path, events, send_id, &cancel).await;

        let summary = match send_result {
            Ok(summary) => summary,
            Err(error) => {
                if let Some((signing, chain, step)) = &peer {
                    let (next, _) =
                        crate::crypto::PeerEncryptor::new(*chain, *step, signing.clone())
                            .next_state();
                    let _ = trust.commit_outgoing(mac, *step, next);
                }
                return Err(error);
            }
        };

        if let Some((signing, chain, step)) = &peer {
            let (next, next_step) =
                crate::crypto::PeerEncryptor::new(*chain, *step, signing.clone()).next_state();
            trust
                .commit_outgoing(mac, *step, next)
                .context("the outgoing paired-device key chain could not be saved")?;
            peer = Some((signing.clone(), next, next_step));
        }

        events.send(Event::Log(summary.line()));
        // Report the user's plaintext size in the batch summary; the backend
        // line above still shows the actual ciphertext bytes on the wire.
        bytes += if peer.is_some() || passphrase_encryptor.is_some() {
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
