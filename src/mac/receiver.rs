//! macOS receiver status.
//!
//! IOBluetooth exposes senders and the OBEX client API, but no public API for
//! hosting an Object Push server. macOS ships that receiver as "Bluetooth
//! Sharing" in System Settings → General → Sharing, which saves incoming
//! files itself. Kalo therefore reports the receiver as off with instructions
//! instead of advertising a service it cannot serve.
//!
//! This is also the safer default: Kalo never opens an inbound RFCOMM listener
//! on macOS, so no remote peer can reach the app through this backend.

use std::time::Duration;

use anyhow::{Result, bail};

use crate::events::EventSink;
use crate::receiver::ReceiverHandle;
use crate::settings::SaveDir;
use crate::trust::Authorizer;

/// The macOS backend has no receiver registry; the marker keeps the shared
/// platform facade signature identical without pretending there is state.
#[derive(Debug, Clone)]
pub struct PendingTransfers;

pub fn new_pending() -> PendingTransfers {
    PendingTransfers
}

const REASON: &str = "macOS has no public OPP receiver API — enable Bluetooth Sharing \
                       in System Settings → General → Sharing to receive files";

/// The UI starts the receiver once; on macOS it only publishes the reason and
/// then stays parked. `!` matches the other backends' supervisor signature.
pub async fn run_receiver(
    handle: ReceiverHandle,
    _pending: PendingTransfers,
    _save_dir: SaveDir,
    events: EventSink,
    _authorizer: Authorizer,
) -> ! {
    handle.mark_lost(REASON);
    events.send(crate::events::Event::Log(REASON.to_string()));
    loop {
        tokio::time::sleep(Duration::from_secs(6 * 60 * 60)).await;
    }
}

/// CLI `kalo receive`: returning a clear error beats pretending to listen.
pub async fn receive() -> Result<()> {
    bail!("{REASON}. The Kalo window explains this and keeps sending available.")
}

/// CLI `kalo receiver-check`: no local OPP service exists to check.
pub async fn agent_check() -> Result<()> {
    bail!("{REASON}")
}
