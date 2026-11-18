//! Device discovery, pairing and adapter state through IOBluetooth.
//!
//! macOS has no BlueZ-style object tree: the system keeps the paired and
//! recent device lists and an optional inquiry finds devices in range. All
//! calls run on a blocking worker because the framework expects a run loop for
//! callbacks and may block on the Bluetooth daemon.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use objc2::rc::autoreleasepool;
use objc2_foundation::{NSArray, NSString};
use objc2_io_bluetooth::{
    BluetoothHCIPowerState, IOBluetoothDevice, IOBluetoothDeviceInquiry, IOBluetoothDevicePair,
    IOBluetoothHostController,
};

use super::pump_run_loop;

/// A Bluetooth device as reported by macOS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub address: String,
    pub alias: String,
    pub paired: bool,
    pub trusted: bool,
    pub connected: bool,
}

const PAIR_TIMEOUT: Duration = Duration::from_secs(120);
const INQUIRY_MAX_SECS: u64 = 60;
const INQUIRY_MARGIN: Duration = Duration::from_secs(3);

/// Paired and recently used devices, exactly what the Kalo window shows.
pub async fn list_known_devices() -> Result<Vec<DeviceInfo>> {
    tokio::task::spawn_blocking(known_devices)
        .await
        .context("device list task failed")?
}

fn known_devices() -> Result<Vec<DeviceInfo>> {
    require_powered()?;
    autoreleasepool(|_| Ok(collect_known()))
}

fn collect_known() -> Vec<DeviceInfo> {
    let mut by_address: BTreeMap<String, DeviceInfo> = BTreeMap::new();
    let mut add = |device: &IOBluetoothDevice| {
        if let Some(info) = device_info(device) {
            // The paired list is authoritative; a later recent-list entry must
            // not downgrade it.
            by_address
                .entry(info.address.clone())
                .and_modify(|existing| {
                    existing.paired |= info.paired;
                    existing.trusted |= info.trusted;
                    existing.connected |= info.connected;
                })
                .or_insert(info);
        }
    };

    if let Some(devices) = unsafe { IOBluetoothDevice::pairedDevices() } {
        for device in array_devices(&devices) {
            add(&device);
        }
    }
    if let Some(devices) = unsafe { IOBluetoothDevice::recentDevices(25) } {
        for device in array_devices(&devices) {
            add(&device);
        }
    }

    let mut devices: Vec<DeviceInfo> = by_address.into_values().collect();
    sort_devices(&mut devices);
    devices
}

fn sort_devices(devices: &mut [DeviceInfo]) {
    devices.sort_by(|a, b| {
        b.paired
            .cmp(&a.paired)
            .then_with(|| a.alias.to_lowercase().cmp(&b.alias.to_lowercase()))
            .then_with(|| a.address.cmp(&b.address))
    });
}

fn array_devices(array: &NSArray) -> Vec<objc2::rc::Retained<IOBluetoothDevice>> {
    let mut devices = Vec::with_capacity(array.count());
    for index in 0..array.count() {
        let object = array.objectAtIndex(index);
        if let Ok(device) = object.downcast::<IOBluetoothDevice>() {
            devices.push(device);
        }
    }
    devices
}

fn device_info(device: &IOBluetoothDevice) -> Option<DeviceInfo> {
    let address = unsafe { device.addressString() }?.to_string();
    if address.trim().is_empty() {
        return None;
    }
    // `name` is the system's cached remote name; it never triggers a remote
    // request here. Falling back to the address keeps the list usable.
    let alias = unsafe { device.name() }.to_string();
    let alias = if alias.trim().is_empty() {
        address.clone()
    } else {
        alias
    };
    let paired = unsafe { device.isPaired() };
    Some(DeviceInfo {
        address,
        alias,
        paired,
        // macOS has no separate "trusted" flag for apps; a paired device is
        // trusted by the system.
        trusted: paired,
        connected: unsafe { device.isConnected() },
    })
}

/// CLI: print the default controller's power state.
pub async fn list_adapters() -> Result<()> {
    tokio::task::spawn_blocking(|| {
        autoreleasepool(|_| match controller_state() {
            Some(state) => {
                println!(
                    "default controller powered={} macos_state={}",
                    state == BluetoothHCIPowerState::ON,
                    state.0
                );
            }
            None => println!("no Bluetooth controller found"),
        });
    })
    .await
    .context("adapter query task failed")
}

/// CLI: macOS owns visibility settings; the app can only report power state.
pub async fn connectable(state: Option<&str>) -> Result<()> {
    match state {
        None | Some("status") => {
            list_adapters().await?;
            println!(
                "macOS manages discoverability in System Settings → General → Sharing → Bluetooth Sharing"
            );
            Ok(())
        }
        Some("on") | Some("off") => bail!(
            "macOS does not let applications change Bluetooth visibility; \
             enable or disable Bluetooth Sharing in System Settings → General → Sharing"
        ),
        Some(other) => bail!("unknown state '{other}' (use: status)"),
    }
}

/// CLI: run an inquiry (when requested) and print paired, recent and in-range
/// devices in one table.
pub async fn list_devices(discovery: Option<u64>) -> Result<()> {
    let devices = tokio::task::spawn_blocking(move || {
        autoreleasepool(|_| -> Result<Vec<DeviceInfo>> {
            require_powered()?;
            let mut known = collect_known();
            if let Some(seconds) = discovery {
                let mut found = inquire(seconds)?;
                let mut by_address: BTreeMap<String, DeviceInfo> = known
                    .into_iter()
                    .map(|device| (device.address.clone(), device))
                    .collect();
                for device in found.drain(..) {
                    by_address
                        .entry(device.address.clone())
                        .and_modify(|existing| {
                            existing.paired |= device.paired;
                            existing.trusted |= device.trusted;
                            existing.connected |= device.connected;
                        })
                        .or_insert(device);
                }
                known = by_address.into_values().collect();
            }
            sort_devices(&mut known);
            Ok(known)
        })
    })
    .await
    .context("device discovery task failed")??;

    if devices.is_empty() {
        println!("no devices known to macOS yet");
    } else {
        println!(
            "{:<32} {:<20} {:<7} {:<8} {:<10}",
            "alias", "address", "paired", "trusted", "connected"
        );
        for device in devices {
            println!(
                "{:<32} {:<20} {:<7} {:<8} {:<10}",
                device.alias, device.address, device.paired, device.trusted, device.connected
            );
        }
    }
    Ok(())
}

/// Run a classic Bluetooth inquiry for `seconds` and return the devices found.
/// Name updates run in the same loop; the extra margin lets them settle before
/// the inquiry is stopped and the names are read.
fn inquire(seconds: u64) -> Result<Vec<DeviceInfo>> {
    let seconds = seconds.clamp(1, INQUIRY_MAX_SECS) as u8;
    let inquiry = unsafe { IOBluetoothDeviceInquiry::new() };
    unsafe {
        inquiry.setInquiryLength(seconds);
        inquiry.setUpdateNewDeviceNames(true);
    }
    let started = unsafe { inquiry.start() };
    if started != 0 {
        bail!("Bluetooth inquiry could not start (IOKit error {started})");
    }
    let deadline = Instant::now() + Duration::from_secs(u64::from(seconds)) + INQUIRY_MARGIN;
    while Instant::now() < deadline {
        pump_run_loop(Duration::from_millis(200));
    }
    unsafe {
        let _ = inquiry.stop();
    }

    let mut devices = Vec::new();
    if let Some(found) = unsafe { inquiry.foundDevices() } {
        for device in array_devices(&found) {
            if let Some(info) = device_info(&device) {
                devices.push(info);
            }
        }
    }
    Ok(devices)
}

/// CLI: pair with a device. The system shows the confirmation on both sides;
/// this waits for the paired flag to flip instead of assuming success.
pub async fn pair(mac: &str) -> Result<()> {
    let mac = mac.trim().to_uppercase();
    tokio::task::spawn_blocking(move || {
        autoreleasepool(|_| {
            require_powered()?;
            let address = NSString::from_str(&mac);
            let device = unsafe { IOBluetoothDevice::deviceWithAddressString(Some(&address)) }
                .context(
                    "device not found; discover it first with `kalo devices --discovery 15`",
                )?;
            if unsafe { device.isPaired() } {
                println!("{mac} is already paired");
                return Ok(());
            }
            let pairing = unsafe { IOBluetoothDevicePair::pairWithDevice(Some(&device)) }
                .context("the pairing request could not be created")?;
            let started = unsafe { pairing.start() };
            if started != 0 {
                bail!(
                    "pairing could not start (IOKit error {started}); \
                     make sure the device is in range and discoverable"
                );
            }

            let deadline = Instant::now() + PAIR_TIMEOUT;
            loop {
                if unsafe { device.isPaired() } {
                    println!("paired with {mac}");
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    unsafe { pairing.stop() };
                    bail!(
                        "pairing with {mac} timed out; confirm the request on the other device \
                         and check that it is discoverable"
                    );
                }
                pump_run_loop(Duration::from_millis(200));
            }
        })
    })
    .await
    .context("pairing task failed")?
}

fn controller_state() -> Option<BluetoothHCIPowerState> {
    let controller = unsafe { IOBluetoothHostController::defaultController() }?;
    Some(unsafe { controller.powerState() })
}

fn require_powered() -> Result<()> {
    match controller_state() {
        None => Err(anyhow!("no Bluetooth controller found")),
        Some(state) if state != BluetoothHCIPowerState::ON => {
            bail!("Bluetooth is off — turn it on in Control Center")
        }
        Some(_) => Ok(()),
    }
}
