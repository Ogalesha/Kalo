//! Windows backend: WinRT Bluetooth devices plus native RFCOMM/OBEX.
//!
//! This backend is experimental. It talks to Windows directly instead of
//! going through BlueZ/obexd, but publishes the same [`crate::events`] contract
//! as the Linux backend so the UI and CLI stay identical.

mod devices;
mod obex;
mod receiver;
mod rfcomm;

pub use devices::{DeviceInfo, connectable, list_adapters, list_devices, list_known_devices, pair};
pub use obex::send;
pub use receiver::{PendingTransfers, agent_check, new_pending, receive, run_receiver};

use anyhow::{Context, Result, bail};
use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};

/// Per-thread COM initialization for the blocking WinRT workers.
///
/// WinRT calls from `spawn_blocking` threads need an initialized apartment.
/// An already initialized apartment (for example an STA owned by the UI) is
/// usable as-is and must not be uninitialized here.
pub(crate) struct ComGuard {
    uninit: bool,
}

impl ComGuard {
    pub(crate) fn new() -> Result<Self> {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr == RPC_E_CHANGED_MODE {
            return Ok(Self { uninit: false });
        }
        if hr.is_err() {
            return Err(windows::core::Error::from(hr))
                .context("initialize COM for the Windows Bluetooth worker");
        }
        Ok(Self { uninit: true })
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.uninit {
            unsafe { CoUninitialize() };
        }
    }
}

/// Run blocking WinRT work on a dedicated worker thread.
pub(crate) async fn run_blocking<T, F>(job: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(job)
        .await
        .context("Windows Bluetooth worker panicked")?
}

/// Parse a user supplied Bluetooth address (`AA:BB:CC:DD:EE:FF`).
pub(crate) fn parse_mac(mac: &str) -> Result<u64> {
    let digits: String = mac
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | ' ' | '.'))
        .collect();
    if digits.len() != 12 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid Bluetooth address '{mac}' (expected AA:BB:CC:DD:EE:FF)");
    }
    Ok(u64::from_str_radix(&digits, 16)?)
}

/// Format a WinRT Bluetooth address with the usual six octets.
pub(crate) fn format_mac(address: u64) -> String {
    let octets = [
        (address >> 40) & 0xFF,
        (address >> 32) & 0xFF,
        (address >> 24) & 0xFF,
        (address >> 16) & 0xFF,
        (address >> 8) & 0xFF,
        address & 0xFF,
    ];
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
    )
}

pub(crate) fn hstring(value: windows::core::HSTRING) -> String {
    value.to_string_lossy()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_bluetooth_addresses() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, 0xAABB_CCDD_EEFF);
        assert_eq!(format_mac(mac), "AA:BB:CC:DD:EE:FF");
        assert!(parse_mac("not-a-mac").is_err());
        assert!(parse_mac("AA:BB").is_err());
    }
}
