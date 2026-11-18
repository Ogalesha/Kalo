//! Kalo — file sharing over Bluetooth.
//!
//! Modules:
//! - `platform` — platform facade (BlueZ/obexd, WinRT, IOBluetooth)
//! - `receiver` — shared receiver status contract
//! - `app`      — Iced UI (devices, send, receiver state, log)
//! - `events`   — shared event bus between background work and the UI
//! - `sanitize` — filename safety for untrusted names
//! - `security` — malware-hash checks, private files, free-space policy
//! - `selection` — multi-file and folder send selection
//! - `settings` — persistent theme/save-folder preferences
//! - `tray`     — Linux status-area icon (shared no-op elsewhere)
//! - `transfer` — cancellation and outgoing summaries shared by backends
//! - `trust`    — incoming-sender decisions and approval prompts
//! - `paths`    — platform filesystem locations
//!
//! Linux-only modules:
//! - `bluez`    — system-bus BlueZ helpers (adapters, devices, discovery, pairing)
//! - `obex`     — outgoing OPP transfers via obexd (`org.bluez.obex`)
//! - `agent`    — OBEX agent: incoming pushes → staging → Downloads
//!
//! Windows-only modules:
//! - `win`      — WinRT RFCOMM OPP sender/receiver and device helpers
//!
//! macOS-only modules:
//! - `mac`      — IOBluetooth OPP sender and paired-device helpers; incoming
//!   transfers use the system Bluetooth File Exchange receiver

#[cfg(target_os = "linux")]
mod agent;
mod app;
#[cfg(target_os = "linux")]
mod bluez;
mod events;
#[cfg(target_os = "macos")]
mod mac;
#[cfg(target_os = "linux")]
mod obex;
mod paths;
mod platform;
mod receiver;
#[cfg(any(target_os = "linux", windows))]
mod sanitize;
mod security;
mod selection;
mod settings;
mod transfer;
mod tray;
mod trust;
#[cfg(windows)]
mod win;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "kalo", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open the Kalo window (default when no subcommand is given)
    Ui,
    /// List Bluetooth adapters and their state
    Adapters,
    /// Show (or set) adapter connectable state — explicit user action
    Connectable {
        /// "on", "off", or empty to just show (Windows supports show only)
        state: Option<String>,
    },
    /// List Bluetooth devices; optionally discover for N seconds first
    Devices {
        /// Run discovery for N seconds first
        #[arg(long)]
        discovery: Option<u64>,
    },
    /// Pair with a device by MAC address — explicit user action
    Pair {
        /// Device MAC address, e.g. AA:BB:CC:DD:EE:FF
        mac: String,
    },
    /// Check whether the receiver can start (agent slot / OPP service)
    AgentCheck,
    /// Send files or folders via Bluetooth OPP
    Send {
        /// Destination device MAC address
        mac: String,
        /// Files and/or folders to send
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Listen for incoming OPP pushes (trusted senders only; approve new
    /// senders in the Kalo window)
    Receive,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        None | Some(Cmd::Ui) => {
            security::init();
            match app::run() {
                Ok(()) => Ok(()),
                Err(e) => Err(anyhow::Error::msg(e.to_string())),
            }
        }
        Some(cmd) => cli_main(cmd),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn cli_main(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Ui => unreachable!("handled above"),
        Cmd::Adapters => platform::list_adapters().await,
        Cmd::Connectable { state } => platform::connectable(state.as_deref()).await,
        Cmd::Devices { discovery } => platform::list_devices(discovery).await,
        Cmd::Pair { mac } => platform::pair(&mac).await,
        Cmd::AgentCheck => platform::agent_check().await,
        Cmd::Send { mac, files } => {
            security::init();
            let selection = selection::collect(&files)?;
            for note in &selection.notes {
                eprintln!("note: {note}");
            }
            let events = events::EventSink::new(256);
            let mut rx = events.subscribe();
            let printer = tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(events::Event::SendProgress {
                            transferred,
                            size,
                            status,
                            ..
                        }) => {
                            println!("{}", events::send_progress_line(transferred, size, &status));
                        }
                        Ok(events::Event::SendFileStarted {
                            index, total, name, ..
                        }) => {
                            if total > 1 {
                                println!("sending {index}/{total}: {name}");
                            }
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(dropped)) => {
                            eprintln!("warning: event stream lagged; dropped {dropped} events");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
            let (_cancel_handle, cancel) = transfer::Cancel::new();
            let summary = platform::send(&mac, &selection.files, &events, 0, cancel).await;
            drop(events);
            let _ = printer.await;
            match summary {
                Ok(summary) => {
                    println!("✔ {}", summary.line());
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Cmd::Receive => {
            security::init();
            platform::receive().await
        }
    }
}
