//! Kalo — file sharing over Bluetooth/Wi-Fi (Ubuntu spike).
//!
//! Modules:
//! - `bluez`    — system-bus BlueZ helpers (adapters, devices, discovery, pairing)
//! - `obex`     — outgoing OPP transfers via obexd (`org.bluez.obex`)
//! - `agent`    — OBEX agent: incoming pushes → staging → ~/Downloads
//! - `app`      — Iced UI (devices, send, receiver state, log)
//! - `events`   — shared event bus between D-Bus work and the UI
//! - `sanitize` — filename safety for untrusted names
//! - `paths`    — XDG locations

mod agent;
mod app;
mod bluez;
mod events;
mod obex;
mod paths;
mod sanitize;

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
        /// "on", "off", or empty to just show
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
    /// Check whether the OBEX agent slot is free (Blueman conflict?)
    AgentCheck,
    /// Send a file via Bluetooth OPP
    Send {
        /// Destination device MAC address
        mac: String,
        /// File to send
        file: PathBuf,
    },
    /// Listen for incoming OPP pushes (SPIKE: accepts everything)
    Receive,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        None | Some(Cmd::Ui) => match app::run() {
            Ok(()) => Ok(()),
            Err(e) => Err(anyhow::Error::msg(e.to_string())),
        },
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
        Cmd::Adapters => bluez::list_adapters().await,
        Cmd::Connectable { state } => bluez::connectable(state.as_deref()).await,
        Cmd::Devices { discovery } => bluez::list_devices(discovery).await,
        Cmd::Pair { mac } => bluez::pair(&mac).await,
        Cmd::AgentCheck => agent::agent_check().await,
        Cmd::Send { mac, file } => {
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
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(dropped)) => {
                            eprintln!("warning: event stream lagged; dropped {dropped} events");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
            let summary = obex::send(&mac, &file, &events, 0, None).await;
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
        Cmd::Receive => agent::receive().await,
    }
}
