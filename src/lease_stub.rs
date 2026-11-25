//! Non-Linux receive-window stub.
//!
//! The Blueman/obexd handoff is Linux-specific. Keeping the same types on the
//! other backends means the shared UI and the platform `run_receiver` facade
//! compile unchanged.

// Some variants and methods exist only to satisfy the shared Linux signatures.
#![allow(dead_code)]

use crate::events::{EventSink, LeaseStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseCommand {
    Arm,
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseAction {
    Arm,
    Release { reason: String },
}

pub struct LeaseHandle {
    status: LeaseStatus,
    _events: EventSink,
}

pub struct LeaseControl;

impl LeaseHandle {
    pub fn new(events: EventSink) -> (Self, LeaseControl) {
        (
            Self {
                status: LeaseStatus::Idle,
                _events: events,
            },
            LeaseControl,
        )
    }

    pub fn status(&self) -> LeaseStatus {
        self.status.clone()
    }

    pub fn request_arm(&self) -> Result<(), String> {
        Err("the receive window is only available on Linux".into())
    }

    pub fn request_release(&self) -> Result<(), String> {
        Ok(())
    }
}

impl LeaseControl {
    pub async fn recv(&mut self) -> Option<LeaseCommand> {
        std::future::pending().await
    }

    pub fn handle(&self) -> &LeaseHandle {
        unreachable!("the receive-window supervisor is Linux-only")
    }
}
