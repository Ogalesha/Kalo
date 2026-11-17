//! Device discovery, listing and pairing through WinRT.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use windows::Devices::Bluetooth::{BluetoothConnectionStatus, BluetoothDevice};
use windows::Devices::Enumeration::{DeviceInformation, DevicePairingResultStatus, DeviceWatcher};
use windows::Devices::Radios::{Radio, RadioKind, RadioState};
use windows::Foundation::TypedEventHandler;

use super::{ComGuard, format_mac, hstring, parse_mac, run_blocking};

/// A Bluetooth device as reported by Windows.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub address: String,
    pub alias: String,
    pub paired: bool,
    /// Windows has no separate trusted flag; pairing is the local trust
    /// decision that matters for incoming/outgoing OPP.
    pub trusted: bool,
    pub connected: bool,
}

/// All devices Windows currently knows about (paired and cached unpaired).
pub async fn list_known_devices() -> Result<Vec<DeviceInfo>> {
    run_blocking(|| {
        let _com = ComGuard::new()?;
        let selector = BluetoothDevice::GetDeviceSelector()?;
        let infos = DeviceInformation::FindAllAsyncAqsFilter(&selector)?.join()?;
        Ok(collect_devices(infos.into_iter()))
    })
    .await
}

/// CLI: print Bluetooth radio state.
pub async fn list_adapters() -> Result<()> {
    run_blocking(|| {
        let _com = ComGuard::new()?;
        let radios = Radio::GetRadiosAsync()?.join()?;
        let mut found = false;
        for radio in radios {
            if radio.Kind()? != RadioKind::Bluetooth {
                continue;
            }
            found = true;
            println!(
                "{:<28} state={} kind=Bluetooth",
                hstring(radio.Name()?),
                radio_state(radio.State()?),
            );
        }
        if !found {
            println!("no Bluetooth adapters found");
        }
        Ok(())
    })
    .await
}

/// CLI: show radio state. Windows does not expose BlueZ's `Connectable`
/// property; discoverability follows the Bluetooth settings page.
pub async fn connectable(state: Option<&str>) -> Result<()> {
    match state {
        None | Some("status") => {
            run_blocking(|| {
                let _com = ComGuard::new()?;
                let radios = Radio::GetRadiosAsync()?.join()?;
                for radio in radios {
                    if radio.Kind()? == RadioKind::Bluetooth {
                        println!(
                            "name        = {}\nstate       = {}\nconnectable = managed by Windows",
                            hstring(radio.Name()?),
                            radio_state(radio.State()?),
                        );
                    }
                }
                Ok(())
            })
            .await
        }
        Some(other) if other != "on" && other != "off" => {
            bail!("unknown state '{other}' (use: on | off | status)")
        }
        Some(_) => bail!(
            "Windows does not expose the adapter connectable flag; use \
             Settings › Bluetooth & devices to control discoverability"
        ),
    }
}

/// CLI: list devices, optionally with a discovery window.
pub async fn list_devices(discovery: Option<u64>) -> Result<()> {
    let mut discovered = Vec::new();
    if let Some(secs) = discovery {
        println!("discovering for {secs}s…");
        discovered = run_blocking(move || {
            let _com = ComGuard::new()?;
            discover_blocking(Duration::from_secs(secs))
        })
        .await?;
    }
    let mut devices = list_known_devices().await?;
    devices.extend(discovered);
    let devices = dedupe(devices);

    if devices.is_empty() {
        println!("no Bluetooth devices known to Windows yet");
    } else {
        println!(
            "{:<32} {:<20} {:<7} {:<8} {:<10}",
            "alias", "address", "paired", "trusted", "connected"
        );
        for d in &devices {
            println!(
                "{:<32} {:<20} {:<7} {:<8} {:<10}",
                d.alias, d.address, d.paired, d.trusted, d.connected
            );
        }
    }
    Ok(())
}

/// CLI: pair with a Bluetooth device (confirm on the device if prompted).
pub async fn pair(mac: &str) -> Result<()> {
    let address = parse_mac(mac)?;
    let mac = format_mac(address);
    run_blocking(move || {
        let _com = ComGuard::new()?;
        let device = BluetoothDevice::FromBluetoothAddressAsync(address)
            .context("look up the Bluetooth device")?
            .join()
            .context("device is not available (is Bluetooth on and the device in range?)")?;
        let info = device
            .DeviceInformation()
            .context("read device information")?;
        let pairing = info.Pairing().context("read pairing state")?;
        if pairing.IsPaired().unwrap_or(false) {
            println!("{mac} is already paired");
            return Ok(());
        }
        println!("pairing with {mac}… (confirm on the device if prompted)");
        let result = pairing.PairAsync()?.join()?;
        let status = result.Status()?;
        match status {
            DevicePairingResultStatus::Paired | DevicePairingResultStatus::AlreadyPaired => {
                println!("paired ✔");
                Ok(())
            }
            DevicePairingResultStatus::AuthenticationTimeout
            | DevicePairingResultStatus::AuthenticationFailure
            | DevicePairingResultStatus::AuthenticationNotAllowed => bail!(
                "pairing with {mac} failed ({}); confirm the prompt on the device and retry",
                pairing_status(status)
            ),
            DevicePairingResultStatus::PairingCanceled => {
                bail!("pairing with {mac} was canceled")
            }
            other => bail!("pairing with {mac} failed ({})", pairing_status(other)),
        }
    })
    .await
}

/// Run a real discovery window with a `DeviceWatcher` and return everything it
/// reported.
fn discover_blocking(window: Duration) -> Result<Vec<DeviceInfo>> {
    let selector = BluetoothDevice::GetDeviceSelector()?;
    let watcher = DeviceInformation::CreateWatcherAqsFilter(&selector)?;
    let found = Arc::new(Mutex::new(Vec::<DeviceInformation>::new()));

    let sink = found.clone();
    let handler: TypedEventHandler<DeviceWatcher, DeviceInformation> = TypedEventHandler::new(
        move |_sender: windows::core::Ref<'_, DeviceWatcher>,
              info: windows::core::Ref<'_, DeviceInformation>| {
            if let Some(info) = info.cloned() {
                sink.lock().expect("discovery lock").push(info);
            }
            Ok(())
        },
    );
    watcher.Added(&handler)?;
    watcher.Start()?;
    std::thread::sleep(window);
    watcher.Stop()?;

    let infos = std::mem::take(&mut *found.lock().expect("discovery lock"));
    Ok(collect_devices(infos.into_iter()))
}

/// Turn WinRT device information into the shared device shape.
fn collect_devices(infos: impl Iterator<Item = DeviceInformation>) -> Vec<DeviceInfo> {
    let mut devices = Vec::new();
    for info in infos {
        let Some(device) = device_info(&info) else {
            continue;
        };
        devices.push(device);
    }
    dedupe(devices)
}

fn device_info(info: &DeviceInformation) -> Option<DeviceInfo> {
    let id = info.Id().ok()?;
    let device = BluetoothDevice::FromIdAsync(&id).ok()?.join().ok()?;
    let address = format_mac(device.BluetoothAddress().ok()?);
    let alias = info.Name().map(hstring).unwrap_or_default();
    let alias = if alias.trim().is_empty() {
        address.clone()
    } else {
        alias
    };
    let pairing = info.Pairing().ok();
    let paired = pairing
        .as_ref()
        .and_then(|pairing| pairing.IsPaired().ok())
        .unwrap_or(false);
    let connected = device
        .ConnectionStatus()
        .map(|status| status == BluetoothConnectionStatus::Connected)
        .unwrap_or(false);
    Some(DeviceInfo {
        address,
        alias,
        paired,
        trusted: paired,
        connected,
    })
}

fn dedupe(devices: Vec<DeviceInfo>) -> Vec<DeviceInfo> {
    let mut by_address: BTreeMap<String, DeviceInfo> = BTreeMap::new();
    for device in devices {
        by_address
            .entry(device.address.clone())
            .and_modify(|existing| {
                existing.paired |= device.paired;
                existing.trusted |= device.trusted;
                existing.connected |= device.connected;
                if existing.alias == existing.address && device.alias != device.address {
                    existing.alias = device.alias.clone();
                }
            })
            .or_insert(device);
    }
    let mut devices: Vec<_> = by_address.into_values().collect();
    devices.sort_by(|a, b| b.paired.cmp(&a.paired).then(a.alias.cmp(&b.alias)));
    devices
}

fn radio_state(state: RadioState) -> &'static str {
    match state {
        RadioState::On => "on",
        RadioState::Off => "off",
        RadioState::Disabled => "disabled",
        _ => "unknown",
    }
}

fn pairing_status(status: DevicePairingResultStatus) -> String {
    match status {
        DevicePairingResultStatus::Paired => "paired".into(),
        DevicePairingResultStatus::AlreadyPaired => "already paired".into(),
        DevicePairingResultStatus::NotReadyToPair => "device not ready to pair".into(),
        DevicePairingResultStatus::NotPaired => "device was not paired".into(),
        DevicePairingResultStatus::ConnectionRejected => "connection rejected".into(),
        DevicePairingResultStatus::TooManyConnections => "too many connections".into(),
        DevicePairingResultStatus::HardwareFailure => "Bluetooth hardware failure".into(),
        DevicePairingResultStatus::AuthenticationTimeout => "authentication timed out".into(),
        DevicePairingResultStatus::AuthenticationNotAllowed => "authentication not allowed".into(),
        DevicePairingResultStatus::AuthenticationFailure => "authentication failed".into(),
        DevicePairingResultStatus::NoSupportedProfiles => "no supported profiles".into(),
        DevicePairingResultStatus::ProtectionLevelCouldNotBeMet => {
            "required protection level unavailable".into()
        }
        DevicePairingResultStatus::AccessDenied => "access denied".into(),
        DevicePairingResultStatus::InvalidCeremonyData => "invalid pairing data".into(),
        DevicePairingResultStatus::PairingCanceled => "pairing canceled".into(),
        DevicePairingResultStatus::OperationAlreadyInProgress => {
            "another pairing is in progress".into()
        }
        DevicePairingResultStatus::RequiredHandlerNotRegistered => {
            "required pairing handler missing".into()
        }
        DevicePairingResultStatus::RejectedByHandler => "pairing rejected".into(),
        DevicePairingResultStatus::RemoteDeviceHasAssociation => {
            "remote device already has a pairing".into()
        }
        DevicePairingResultStatus::Failed => "pairing failed".into(),
        other => format!("pairing failed (status {})", other.0),
    }
}
