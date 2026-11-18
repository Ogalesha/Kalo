//! Events produced by background D-Bus work, consumed by the UI (or the CLI).

use std::fmt;
use std::path::PathBuf;

use tokio::sync::broadcast;

/// `org.bluez.obex.Transfer1.Status` as a closed set plus a forward-compatible
/// escape hatch. BlueZ documents exactly five values; anything else is kept
/// verbatim so it can be displayed and handled without guessing.
///
/// The Windows backend only emits the subset its native OBEX engine can
/// report; the full vocabulary remains available to the shared renderers.
#[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferStatus {
    Queued,
    Active,
    Suspended,
    Complete,
    Error,
    Unknown(String),
}

#[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
impl TransferStatus {
    pub fn parse(raw: &str) -> Self {
        match raw {
            "queued" => Self::Queued,
            "active" => Self::Active,
            "suspended" => Self::Suspended,
            "complete" => Self::Complete,
            "error" => Self::Error,
            other => Self::Unknown(other.to_string()),
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Complete | Self::Error)
    }
}

impl fmt::Display for TransferStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued => f.write_str("queued"),
            Self::Active => f.write_str("active"),
            Self::Suspended => f.write_str("suspended"),
            Self::Complete => f.write_str("complete"),
            Self::Error => f.write_str("error"),
            Self::Unknown(raw) => f.write_str(raw),
        }
    }
}

/// High-level state of the OBEX agent. The displayed text is derived, not the
/// source of truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverStatus {
    Starting,
    Active,
    Off(String),
}

impl fmt::Display for ReceiverStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Starting => f.write_str("starting…"),
            Self::Active => {
                f.write_str("receiver active — incoming files are saved to your save folder")
            }
            Self::Off(reason) => write!(f, "receiver OFF — {reason}"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    /// Generic log line.
    Log(String),
    /// A file from the outgoing batch is about to be sent. The UI resets the
    /// progress bar and shows the position in the queue. `index` is 1-based.
    SendFileStarted {
        send_id: u64,
        index: usize,
        total: usize,
        name: String,
    },
    /// Progress of an outgoing OPP transfer. `send_id` correlates it with the
    /// send task that produced it.
    SendProgress {
        send_id: u64,
        transferred: u64,
        size: Option<u64>,
        status: TransferStatus,
    },
    /// A new sender needs a decision from the desktop UI. The transfer waits
    /// for [`Authorizer::respond`](crate::trust::Authorizer::respond) or a
    /// timeout. `stable` is false when the backend could only determine a
    /// display name, so "remember" must not be offered.
    IncomingAuthorization {
        id: String,
        sender: String,
        address: String,
        name: String,
        size: Option<u64>,
        stable: bool,
    },
    /// An incoming OPP push was authorized.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    IncomingStarted {
        id: String,
        sender: String,
        name: String,
        size: Option<u64>,
    },
    /// Progress of an incoming transfer (polled).
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    IncomingProgress {
        id: String,
        name: String,
        transferred: Option<u64>,
        size: Option<u64>,
    },
    /// Incoming transfer completed and was moved into Downloads. `partial`
    /// is true when the transfer was interrupted or the byte count did not
    /// match the size announced by the sender.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    IncomingDone {
        id: String,
        sender: String,
        name: String,
        saved_to: PathBuf,
        bytes: u64,
        elapsed_secs: f64,
        mbps: f64,
        partial: bool,
    },
    /// Incoming transfer failed or was rejected. `staged_at` is set when a
    /// usable staged file was deliberately kept for manual recovery.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    IncomingFailed {
        id: String,
        sender: String,
        name: String,
        error: String,
        staged_at: Option<PathBuf>,
    },
    /// State of the receiver (OBEX agent).
    ReceiverState(ReceiverStatus),
}

/// Fan-out sink for background events. A broadcast channel lets the UI
/// re-create its subscription (for example after a window/stream restart)
/// without consuming the only receiver, and lets the CLI follow along.
#[derive(Debug, Clone)]
pub struct EventSink {
    tx: broadcast::Sender<Event>,
}

impl EventSink {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Publish an event. With no live subscriber the event is dropped, exactly
    /// like the previous `UnboundedSender` behavior.
    pub fn send(&self, event: Event) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

/// Shared rendering of outgoing progress so the UI and CLI cannot drift.
pub fn send_progress_line(transferred: u64, size: Option<u64>, status: &TransferStatus) -> String {
    match size {
        Some(size) => format!("send {status}: {transferred}/{size} bytes"),
        None => format!("send {status}: {transferred} bytes"),
    }
}

/// Human-readable size for the GUI, using the decimal units desktop file
/// managers show.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [(f64, &str); 3] = [
        (1_000_000_000.0, "GB"),
        (1_000_000.0, "MB"),
        (1_000.0, "KB"),
    ];

    for (scale, unit) in UNITS {
        if bytes as f64 >= scale {
            let value = bytes as f64 / scale;
            return if value >= 10.0 {
                format!("{value:.0} {unit}")
            } else {
                format!("{value:.1} {unit}")
            };
        }
    }
    format!("{bytes} B")
}

/// UI-friendly outgoing progress: "4.2 MB of 10 MB", never raw byte counts.
pub fn send_progress_summary(
    transferred: u64,
    size: Option<u64>,
    status: &TransferStatus,
) -> String {
    let amount = match size {
        Some(size) if size > 0 => {
            format!("{} of {}", format_bytes(transferred), format_bytes(size))
        }
        _ => format!("{} sent", format_bytes(transferred)),
    };

    match status {
        TransferStatus::Active => amount,
        TransferStatus::Queued => format!("Waiting · {amount}"),
        TransferStatus::Suspended => format!("Paused · {amount}"),
        TransferStatus::Complete => format!("Complete · {amount}"),
        TransferStatus::Error => format!("Failed · {amount}"),
        TransferStatus::Unknown(raw) => format!("{raw} · {amount}"),
    }
}

/// Progress fraction, or `None` when the peer has not announced a size: an
/// unknown size must not render as a bar stuck at 0%.
pub fn transfer_fraction(transferred: u64, size: Option<u64>) -> Option<f32> {
    size.filter(|size| *size > 0)
        .map(|size| (transferred as f32 / size as f32).clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_documented_statuses() {
        assert_eq!(TransferStatus::parse("queued"), TransferStatus::Queued);
        assert_eq!(TransferStatus::parse("active"), TransferStatus::Active);
        assert_eq!(
            TransferStatus::parse("suspended"),
            TransferStatus::Suspended
        );
        assert_eq!(TransferStatus::parse("complete"), TransferStatus::Complete);
        assert_eq!(TransferStatus::parse("error"), TransferStatus::Error);
    }

    #[test]
    fn keeps_unknown_status_verbatim() {
        assert_eq!(
            TransferStatus::parse("cancelled"),
            TransferStatus::Unknown("cancelled".into())
        );
        assert_eq!(TransferStatus::parse("").to_string(), "");
    }

    #[test]
    fn only_complete_and_error_are_terminal() {
        for status in ["queued", "active", "suspended", "cancelled", ""] {
            assert!(!TransferStatus::parse(status).is_terminal(), "{status}");
        }
        assert!(TransferStatus::parse("complete").is_terminal());
        assert!(TransferStatus::parse("error").is_terminal());
    }

    #[test]
    fn progress_line_includes_total_when_known() {
        assert_eq!(
            send_progress_line(5, Some(10), &TransferStatus::Active),
            "send active: 5/10 bytes"
        );
        assert_eq!(
            send_progress_line(5, None, &TransferStatus::Queued),
            "send queued: 5 bytes"
        );
    }

    #[test]
    fn receiver_status_renders_reason() {
        assert_eq!(ReceiverStatus::Starting.to_string(), "starting…");
        assert!(
            ReceiverStatus::Active
                .to_string()
                .contains("receiver active")
        );
        assert!(ReceiverStatus::Active.to_string().contains("save folder"));
        assert_eq!(
            ReceiverStatus::Off("released".into()).to_string(),
            "receiver OFF — released"
        );
    }

    #[test]
    fn formats_human_readable_sizes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(950), "950 B");
        assert_eq!(format_bytes(1_500), "1.5 KB");
        assert_eq!(format_bytes(128_000), "128 KB");
        assert_eq!(format_bytes(4_200_000), "4.2 MB");
        assert_eq!(format_bytes(15_000_000), "15 MB");
        assert_eq!(format_bytes(2_500_000_000), "2.5 GB");
    }

    #[test]
    fn summary_hides_raw_byte_counts() {
        assert_eq!(
            send_progress_summary(4_200_000, Some(10_000_000), &TransferStatus::Active),
            "4.2 MB of 10 MB"
        );
        assert_eq!(
            send_progress_summary(500, None, &TransferStatus::Queued),
            "Waiting · 500 B sent"
        );
        assert_eq!(
            send_progress_summary(100, Some(100), &TransferStatus::Complete),
            "Complete · 100 B of 100 B"
        );
    }

    #[test]
    fn unknown_or_zero_size_has_no_fraction() {
        assert_eq!(transfer_fraction(5, None), None);
        assert_eq!(transfer_fraction(5, Some(0)), None);
        assert_eq!(transfer_fraction(0, Some(10)), Some(0.0));
        assert_eq!(transfer_fraction(5, Some(10)), Some(0.5));
        assert_eq!(transfer_fraction(20, Some(10)), Some(1.0));
    }

    #[test]
    fn event_sink_can_be_subscribed_again() {
        let sink = EventSink::new(8);
        let mut first = sink.subscribe();
        sink.send(Event::Log("one".into()));
        assert!(matches!(first.try_recv().unwrap(), Event::Log(line) if line == "one"));

        // Dropping the first receiver must not consume the bus: a re-created
        // subscription (iced may rebuild it) still observes new events.
        drop(first);
        let mut second = sink.subscribe();
        sink.send(Event::Log("two".into()));
        assert!(matches!(second.try_recv().unwrap(), Event::Log(line) if line == "two"));
    }
}
