//! Platform facade.
//!
//! The UI and CLI talk to one set of names. Linux maps them onto BlueZ/obexd,
//! Windows onto WinRT RFCOMM plus the native OBEX implementation. Keeping the
//! facade small makes the shared event contract the only thing backends must
//! agree on.

#[cfg(not(windows))]
pub use crate::agent::{PendingTransfers, agent_check, new_pending, receive, run_receiver};
#[cfg(not(windows))]
pub use crate::bluez::{
    DeviceInfo, connectable, list_adapters, list_devices, list_known_devices, pair,
};
#[cfg(not(windows))]
pub use crate::obex::send;

#[cfg(windows)]
pub use crate::win::{
    DeviceInfo, PendingTransfers, agent_check, connectable, list_adapters, list_devices,
    list_known_devices, new_pending, pair, receive, run_receiver, send,
};

pub use crate::receiver::ReceiverHandle;
