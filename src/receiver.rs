//! Shared receiver status for every platform backend.
//!
//! The Linux backend owns an OBEX agent slot in obexd, while the Windows
//! backend advertises an RFCOMM OPP service. Both publish the same status
//! contract so the UI never needs to know which platform it runs on.

use std::sync::{Arc, Mutex};

use crate::events::{Event, EventSink, ReceiverStatus};

/// Single source of truth for the receiver slot. Both the backend service and
/// the supervisor read and update it, so the UI never has to reconcile
/// separate "active" flags with status events. Status changes are published
/// while the state lock is held, which keeps a stale `Active` from racing
/// ahead of an immediately following `Release` or restart.
#[derive(Debug, Clone)]
pub struct ReceiverHandle {
    inner: Arc<Mutex<ReceiverInner>>,
    events: EventSink,
}

#[derive(Debug)]
struct ReceiverInner {
    status: ReceiverStatus,
    /// Registration id currently allowed to speak for the receiver.
    current: Option<u64>,
    next: u64,
}

impl ReceiverHandle {
    pub fn new(events: EventSink) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ReceiverInner {
                status: ReceiverStatus::Starting,
                current: None,
                next: 1,
            })),
            events,
        }
    }

    pub fn status(&self) -> ReceiverStatus {
        self.inner.lock().expect("receiver lock").status.clone()
    }

    pub fn is_active(&self) -> bool {
        self.status() == ReceiverStatus::Active
    }

    /// Allocate the id for a registration attempt and make it the only one
    /// whose `Release` is honored.
    pub(crate) fn begin_registration(&self) -> u64 {
        let mut inner = self.inner.lock().expect("receiver lock");
        let id = inner.next;
        inner.next += 1;
        inner.current = Some(id);
        id
    }

    /// Mark a registration active. Returns whether this changed the state.
    /// A registration invalidated by a release/restart in the meantime is
    /// left alone.
    pub(crate) fn mark_active(&self, id: u64) -> bool {
        let mut inner = self.inner.lock().expect("receiver lock");
        if inner.current != Some(id) || inner.status == ReceiverStatus::Active {
            return false;
        }
        self.set_status(&mut inner, ReceiverStatus::Active);
        true
    }

    /// A `Release` for `id`. Stale releases from earlier registrations are
    /// ignored; only the current registration can turn the receiver off.
    pub(crate) fn release(&self, id: u64, reason: &str) {
        let mut inner = self.inner.lock().expect("receiver lock");
        if inner.current != Some(id) {
            return;
        }
        inner.current = None;
        let next = ReceiverStatus::Off(reason.to_string());
        self.set_status(&mut inner, next);
    }

    /// Any reason the current registration is no longer valid (obexd restart,
    /// session-bus failure, registration error).
    pub(crate) fn mark_lost(&self, reason: &str) {
        let mut inner = self.inner.lock().expect("receiver lock");
        inner.current = None;
        let next = ReceiverStatus::Off(reason.to_string());
        self.set_status(&mut inner, next);
    }

    /// Caller holds the state lock, so the published order always matches
    /// the stored state.
    fn set_status(&self, inner: &mut ReceiverInner, next: ReceiverStatus) {
        if inner.status == next {
            return;
        }
        inner.status = next.clone();
        self.events.send(Event::ReceiverState(next));
    }
}
