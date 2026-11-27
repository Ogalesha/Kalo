//! Minimal Blueman applet client used by the receive-window handoff.
//!
//! Blueman's `TransferService` plugin owns obexd's single OBEX agent slot. The
//! applet exposes `SetPluginConfig` over its session-bus API; toggling that
//! plugin is the supported way to ask Blueman to yield the slot and to give it
//! back. The plugin list itself is persisted in GSettings, so we also snapshot
//! and restore it with `gsettings` to leave no lasting change behind.

use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use zbus::Connection;
use zbus::fdo::DBusProxy;
use zbus::names::BusName;
use zbus::proxy;

/// Well-known session-bus name of the running Blueman applet.
pub const APPLET_BUS: &str = "org.blueman.Applet";
/// Plugin that registers the OBEX agent with obexd.
pub const TRANSFER_PLUGIN: &str = "TransferService";

const GSETTINGS_SCHEMA: &str = "org.blueman.general";
const GSETTINGS_KEY: &str = "plugin-list";
const POLL: Duration = Duration::from_millis(100);
const LIST_POLL: Duration = Duration::from_millis(250);

#[proxy(
    default_service = "org.blueman.Applet",
    default_path = "/org/blueman/Applet",
    interface = "org.blueman.Applet"
)]
trait Applet {
    fn query_plugins(&self) -> zbus::Result<Vec<String>>;
    fn set_plugin_config(&self, plugin: &str, enabled: bool) -> zbus::Result<()>;
}

/// Whether the Blueman applet currently owns its well-known name.
pub async fn applet_running(conn: &Connection) -> Result<bool> {
    let dbus = DBusProxy::new(conn).await.context("D-Bus proxy")?;
    let name = BusName::try_from(APPLET_BUS).context("Blueman bus name")?;
    Ok(dbus.name_has_owner(name).await?)
}

/// `Some(true)` when `TransferService` is loaded, `Some(false)` when the
/// applet is running but the plugin is not, and `None` when Blueman is absent.
pub async fn transfer_service_loaded(conn: &Connection) -> Result<Option<bool>> {
    if !applet_running(conn).await? {
        return Ok(None);
    }
    let applet = AppletProxy::new(conn)
        .await
        .context("Blueman applet proxy")?;
    let plugins = applet
        .query_plugins()
        .await
        .context("query Blueman plugins")?;
    Ok(Some(plugins.iter().any(|plugin| plugin == TRANSFER_PLUGIN)))
}

/// Ask Blueman to load or unload its OBEX transfer plugin. This is the
/// documented, reversible applet API; it does not stop or kill any process.
pub async fn set_transfer_service(conn: &Connection, enabled: bool) -> Result<()> {
    let applet = AppletProxy::new(conn)
        .await
        .context("Blueman applet proxy")?;
    applet
        .set_plugin_config(TRANSFER_PLUGIN, enabled)
        .await
        .with_context(|| {
            format!(
                "ask Blueman to {} its transfer service",
                if enabled { "enable" } else { "disable" }
            )
        })?;
    Ok(())
}

/// Wait until the plugin reaches the requested loaded state. GSettings change
/// delivery is asynchronous, so the call above can return before Blueman
/// actually unloads the plugin.
pub async fn wait_for_transfer_service(
    conn: &Connection,
    expected: bool,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match transfer_service_loaded(conn).await? {
            Some(loaded) if loaded == expected => return Ok(()),
            // Blueman went away: nothing is left to load or unload.
            None if !expected => return Ok(()),
            _ => {}
        }
        if Instant::now() >= deadline {
            bail!(
                "Blueman did not {} its transfer service in time",
                if expected { "enable" } else { "disable" }
            );
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Exact GSettings value of `org.blueman.general plugin-list`.
///
/// `SetPluginConfig` appends an explicit entry to this list. Capturing the raw
/// GVariant text before the handoff lets us restore the user's original list.
/// An empty list is not a disable request: it means "no overrides", so the
/// plugin keeps following Blueman's auto-loading default.
pub fn plugin_list_snapshot() -> Result<String> {
    let output = Command::new("gsettings")
        .args(["get", GSETTINGS_SCHEMA, GSETTINGS_KEY])
        .output()
        .context("run `gsettings get` (is GLib installed?)")?;
    if !output.status.success() {
        bail!(
            "`gsettings get` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let raw = String::from_utf8(output.stdout).context("gsettings output is not UTF-8")?;
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("`gsettings get` returned an empty plugin list");
    }
    Ok(raw.to_string())
}

/// Restore the exact GVariant text captured by [`plugin_list_snapshot`].
pub fn restore_plugin_list(raw: &str) -> Result<()> {
    let output = Command::new("gsettings")
        .args(["set", GSETTINGS_SCHEMA, GSETTINGS_KEY, raw])
        .output()
        .context("run `gsettings set`")?;
    if !output.status.success() {
        bail!(
            "`gsettings set` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// True when a captured plugin list explicitly disables `TransferService`.
/// Such a list must not be "restored" by enabling the plugin.
pub fn list_disables_transfer(raw: &str) -> bool {
    raw.contains(&format!("!{TRANSFER_PLUGIN}"))
}

/// True when a captured plugin list contains `TransferService` without an
/// explicit disable entry.
pub fn list_enables_transfer(raw: &str) -> bool {
    raw.contains(TRANSFER_PLUGIN) && !list_disables_transfer(raw)
}

/// Wait until the persisted list shows the transfer plugin as enabled.
/// `SetPluginConfig` writes GSettings asynchronously, so a restore must not
/// race a disable entry that is still queued from the handoff.
pub async fn wait_for_transfer_list_enabled(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let raw = plugin_list_snapshot()?;
        if list_enables_transfer(&raw) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("Blueman did not persist its transfer service as enabled in time");
        }
        tokio::time::sleep(LIST_POLL).await;
    }
}

/// Wait until the persisted list shows the transfer plugin as disabled. This
/// makes the handoff deterministic: the window does not open while a disable
/// entry is still queued to Blueman.
pub async fn wait_for_transfer_list_disabled(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let raw = plugin_list_snapshot()?;
        if list_disables_transfer(&raw) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("Blueman did not persist its transfer service as disabled in time");
        }
        tokio::time::sleep(LIST_POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_an_explicit_disable_entry() {
        assert!(list_disables_transfer(r#"['!TransferService']"#));
        assert!(!list_disables_transfer(r#"['TransferService']"#));
        assert!(!list_disables_transfer("@as []"));
    }

    #[test]
    fn detects_an_enabled_transfer_entry() {
        assert!(list_enables_transfer(r#"['TransferService']"#));
        assert!(!list_enables_transfer(r#"['!TransferService']"#));
        assert!(!list_enables_transfer("@as []"));
        assert!(!list_enables_transfer(
            r#"['TransferService', '!TransferService']"#
        ));
    }
}
