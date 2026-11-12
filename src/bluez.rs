//! Read-mostly helpers over the system-bus BlueZ API (`org.bluez`).
//!
//! Nothing here mutates system configuration; the `connectable on/off` and
//! `pair` commands are explicit user actions.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use zbus::proxy;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

/// A Bluetooth device as reported by BlueZ.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub address: String,
    pub alias: String,
    pub paired: bool,
    pub trusted: bool,
    pub connected: bool,
}

#[proxy(
    default_service = "org.bluez",
    default_path = "/",
    interface = "org.freedesktop.DBus.ObjectManager"
)]
trait BluezObjects {
    fn get_managed_objects(
        &self,
    ) -> zbus::Result<HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedValue>>>>;
}

#[proxy(
    default_service = "org.bluez",
    default_path = "/org/bluez/hci0",
    interface = "org.bluez.Adapter1"
)]
trait Adapter {
    fn start_discovery(&self) -> zbus::Result<()>;
    fn stop_discovery(&self) -> zbus::Result<()>;

    #[zbus(property)]
    fn address(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn alias(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn powered(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn connectable(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn set_connectable(&self, value: bool) -> zbus::Result<()>;
    #[zbus(property)]
    fn discovering(&self) -> zbus::Result<bool>;
}

#[proxy(default_service = "org.bluez", interface = "org.bluez.Device1")]
trait Device {
    #[zbus(property)]
    fn paired(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn trusted(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn connected(&self) -> zbus::Result<bool>;
    fn pair(&self) -> zbus::Result<()>;
}

fn prop_str(props: &HashMap<String, OwnedValue>, key: &str) -> String {
    props
        .get(key)
        .and_then(|v| v.downcast_ref::<String>().ok())
        .unwrap_or_default()
}

fn prop_bool(props: &HashMap<String, OwnedValue>, key: &str) -> bool {
    props
        .get(key)
        .and_then(|v| v.downcast_ref::<bool>().ok())
        .unwrap_or(false)
}

/// All devices BlueZ currently knows about (paired, trusted or recently seen).
pub async fn list_known_devices() -> Result<Vec<DeviceInfo>> {
    let conn = zbus::Connection::system().await?;
    let om = BluezObjectsProxy::new(&conn).await?;
    let objects = om.get_managed_objects().await?;

    let mut devices = Vec::new();
    for (_path, interfaces) in objects {
        if let Some(props) = interfaces.get("org.bluez.Device1") {
            devices.push(DeviceInfo {
                address: prop_str(&props, "Address"),
                alias: {
                    let alias = prop_str(&props, "Alias");
                    if alias.is_empty() {
                        prop_str(&props, "Address")
                    } else {
                        alias
                    }
                },
                paired: prop_bool(&props, "Paired"),
                trusted: prop_bool(&props, "Trusted"),
                connected: prop_bool(&props, "Connected"),
            });
        }
    }
    devices.sort_by(|a, b| b.paired.cmp(&a.paired).then(a.alias.cmp(&b.alias)));
    Ok(devices)
}

/// CLI: print adapter state.
pub async fn list_adapters() -> Result<()> {
    let conn = zbus::Connection::system().await?;
    let om = BluezObjectsProxy::new(&conn).await?;
    let objects = om.get_managed_objects().await?;

    let mut found = false;
    for (path, interfaces) in &objects {
        if let Some(props) = interfaces.get("org.bluez.Adapter1") {
            found = true;
            println!(
                "{:<28} address={} powered={} connectable={} discovering={} alias={}",
                path.as_str(),
                prop_str(props, "Address"),
                prop_bool(props, "Powered"),
                prop_bool(props, "Connectable"),
                prop_bool(props, "Discovering"),
                prop_str(props, "Alias"),
            );
        }
    }
    if !found {
        println!("no Bluetooth adapters found");
    }
    Ok(())
}

/// CLI: show or set the adapter `Connectable` property (explicit user action).
pub async fn connectable(state: Option<&str>) -> Result<()> {
    let conn = zbus::Connection::system().await?;
    let adapter = AdapterProxy::new(&conn).await?;
    match state {
        None | Some("status") => {
            println!("address     = {}", adapter.address().await?);
            println!("alias       = {}", adapter.alias().await?);
            println!("powered     = {}", adapter.powered().await?);
            println!("connectable = {}", adapter.connectable().await?);
            println!("discovering = {}", adapter.discovering().await?);
        }
        Some("on") => {
            adapter.set_connectable(true).await?;
            println!("connectable → on");
        }
        Some("off") => {
            adapter.set_connectable(false).await?;
            println!("connectable → off");
        }
        Some(other) => bail!("unknown state '{other}' (use: on | off | status)"),
    }
    Ok(())
}

/// CLI: list devices, optionally after a discovery window.
pub async fn list_devices(discovery: Option<u64>) -> Result<()> {
    if let Some(secs) = discovery {
        let conn = zbus::Connection::system().await?;
        let adapter = AdapterProxy::new(&conn).await?;
        if !adapter.powered().await? {
            bail!("the adapter is powered off");
        }
        if !adapter.discovering().await? {
            adapter.start_discovery().await?;
        }
        println!("discovering for {secs}s…");
        tokio::time::sleep(Duration::from_secs(secs)).await;
        if adapter.discovering().await? {
            let _ = adapter.stop_discovery().await;
        }
    }

    let devices = list_known_devices().await?;
    if devices.is_empty() {
        println!("no devices known to BlueZ yet");
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

/// CLI: pair with a device known to BlueZ (confirm on the device if prompted).
pub async fn pair(mac: &str) -> Result<()> {
    let conn = zbus::Connection::system().await?;
    let om = BluezObjectsProxy::new(&conn).await?;
    let objects = om.get_managed_objects().await?;

    let want = mac.to_uppercase();
    let mut device_path: Option<String> = None;
    for (path, interfaces) in &objects {
        if let Some(props) = interfaces.get("org.bluez.Device1") {
            if prop_str(props, "Address").to_uppercase() == want {
                device_path = Some(path.as_str().to_string());
            }
        }
    }
    let Some(path) = device_path else {
        bail!(
            "device {mac} is not known to BlueZ — discover it first: kalo devices --discovery 15"
        );
    };

    let device = DeviceProxy::builder(&conn)
        .path(path.as_str())?
        .build()
        .await?;
    if device.paired().await? {
        println!("{mac} is already paired");
        return Ok(());
    }
    println!("pairing with {mac}… (confirm on the device if prompted)");
    device.pair().await.context("pairing failed")?;
    println!("paired ✔");
    Ok(())
}
