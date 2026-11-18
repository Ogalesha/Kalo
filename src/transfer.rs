//! Shared outgoing-transfer primitives: cancellation and summary types.
//!
//! A batch send reuses one cancellation signal for every file, so Cancel in
//! the UI stops the file in flight and prevents the queue from advancing.
//! Backends receive the token by reference and watch it inside their transfer
//! loops instead of owning a one-shot channel.

use tokio::sync::watch;

/// A clonable cancellation signal. Clones observe the same state, which is
/// what lets a batch and its in-flight backend transfer share one Cancel.
#[derive(Clone, Debug)]
pub struct Cancel {
    rx: watch::Receiver<bool>,
}

/// The sending side of a cancellation signal. Dropping it (without calling
/// [`CancelHandle::cancel`]) leaves the signal idle, not cancelled.
#[derive(Debug)]
pub struct CancelHandle {
    tx: watch::Sender<bool>,
}

impl Cancel {
    pub fn new() -> (CancelHandle, Self) {
        let (tx, rx) = watch::channel(false);
        (CancelHandle { tx }, Self { rx })
    }

    /// True once cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolve when cancellation is requested or the sending side is gone.
    /// Safe to call repeatedly; each call watches from the current value.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub async fn wait(&self) {
        let mut rx = self.rx.clone();
        loop {
            if *rx.borrow_and_update() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

impl CancelHandle {
    /// Request cancellation. Returns false when the transfer already ended.
    pub fn cancel(&self) -> bool {
        self.tx.send(true).is_ok()
    }
}

/// Summary of one completed outgoing file transfer.
#[derive(Debug, Clone, PartialEq)]
pub struct SendSummary {
    pub mac: String,
    pub bytes: u64,
    pub elapsed_secs: f64,
    pub mbps: f64,
}

impl SendSummary {
    pub fn new(mac: &str, bytes: u64, elapsed_secs: f64) -> Self {
        Self {
            mac: mac.to_string(),
            bytes,
            elapsed_secs,
            mbps: mbps(bytes, elapsed_secs),
        }
    }

    pub fn line(&self) -> String {
        format!(
            "sent {} bytes to {} in {:.1}s ({:.2} MB/s)",
            self.bytes, self.mac, self.elapsed_secs, self.mbps
        )
    }
}

/// Aggregate summary of a completed batch.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchSummary {
    pub mac: String,
    pub files: usize,
    pub bytes: u64,
    pub elapsed_secs: f64,
    pub mbps: f64,
}

impl BatchSummary {
    pub fn new(mac: &str, files: usize, bytes: u64, elapsed_secs: f64) -> Self {
        Self {
            mac: mac.to_string(),
            files,
            bytes,
            elapsed_secs,
            mbps: mbps(bytes, elapsed_secs),
        }
    }

    pub fn line(&self) -> String {
        format!(
            "sent {} file(s) ({} bytes) to {} in {:.1}s ({:.2} MB/s)",
            self.files, self.bytes, self.mac, self.elapsed_secs, self.mbps
        )
    }
}

pub fn mbps(bytes: u64, elapsed_secs: f64) -> f64 {
    if elapsed_secs > 0.0 {
        bytes as f64 / (1024.0 * 1024.0) / elapsed_secs
    } else {
        0.0
    }
}

/// Human-readable progress for a batch header: "2 of 5 · report.pdf".
pub fn batch_position(index: usize, total: usize, name: &str) -> String {
    if total <= 1 {
        name.to_string()
    } else {
        format!("{index} of {total} · {name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancel_is_shared_between_clones() {
        let (handle, cancel) = Cancel::new();
        let clone = cancel.clone();
        assert!(!cancel.is_cancelled());
        assert!(handle.cancel());
        assert!(cancel.is_cancelled());
        assert!(clone.is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), clone.wait())
            .await
            .expect("wait must resolve after cancellation");
    }

    #[tokio::test]
    async fn dropping_the_handle_releases_waiters_without_cancelling() {
        let (handle, cancel) = Cancel::new();
        drop(handle);
        tokio::time::timeout(Duration::from_secs(1), cancel.wait())
            .await
            .expect("wait must not hang once the sender is gone");
        assert!(!cancel.is_cancelled());
    }

    #[test]
    fn summaries_compute_transfer_rate() {
        let summary = SendSummary::new("AA:BB", 1024 * 1024, 2.0);
        assert_eq!(summary.mbps, 0.5);
        assert_eq!(
            summary.line(),
            "sent 1048576 bytes to AA:BB in 2.0s (0.50 MB/s)"
        );

        let batch = BatchSummary::new("AA:BB", 3, 3 * 1024 * 1024, 2.0);
        assert_eq!(batch.files, 3);
        assert_eq!(batch.mbps, 1.5);
        assert!(batch.line().contains("sent 3 file(s)"));
    }

    #[test]
    fn zero_elapsed_never_divides_by_zero() {
        assert_eq!(mbps(10, 0.0), 0.0);
    }

    #[test]
    fn batch_position_hides_single_file_noise() {
        assert_eq!(batch_position(1, 1, "a.txt"), "a.txt");
        assert_eq!(batch_position(2, 5, "b.txt"), "2 of 5 · b.txt");
    }
}
