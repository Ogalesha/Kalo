//! Events produced by background D-Bus work, consumed by the UI (or the CLI).

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum Event {
    /// Generic log line.
    Log(String),
    /// Progress of an outgoing OPP transfer.
    SendProgress {
        transferred: u64,
        size: Option<u64>,
        status: String,
    },
    /// An incoming OPP push was authorized (spike: accept-all).
    IncomingStarted {
        sender: String,
        name: String,
        size: Option<u64>,
        /// Transfer path, kept for future progress correlation (Phase 1).
        #[allow(dead_code)]
        path: String,
    },
    /// Progress of an incoming transfer (polled).
    IncomingProgress {
        /// Transfer path, kept for future progress correlation (Phase 1).
        #[allow(dead_code)]
        path: String,
        transferred: Option<u64>,
    },
    /// Incoming transfer completed and was moved into Downloads.
    IncomingDone {
        saved_to: PathBuf,
        bytes: u64,
        elapsed_secs: f64,
        mbps: f64,
    },
    /// Incoming transfer failed or was rejected.
    IncomingFailed { name: String, error: String },
    /// State of the receiver (OBEX agent).
    ReceiverState(String),
}
