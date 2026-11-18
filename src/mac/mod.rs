//! macOS backend built on the IOBluetooth framework.
//!
//! Sending uses the Object Push profile through `IOBluetoothOBEXSession` and
//! `OBEXFileTransferServices`; devices are listed from the system's paired and
//! recent lists, optionally enriched with an in-range inquiry.
//!
//! Receiving is deliberately not implemented: macOS exposes no public OPP
//! server API. The system's own "Bluetooth Sharing" receiver (System Settings
//! → General → Sharing) handles incoming files, so the Kalo receiver reports
//! that clearly instead of pretending to listen.

mod devices;
mod obex;
mod receiver;

use std::time::Duration;

pub use devices::{DeviceInfo, connectable, list_adapters, list_devices, list_known_devices, pair};
pub use obex::send;
pub use receiver::{PendingTransfers, agent_check, new_pending, receive, run_receiver};

/// Run the current thread's run loop for a short slice. IOBluetooth delivers
/// inquiry, pairing and OBEX callbacks through the run loop of the thread that
/// started the operation, so every backend operation pumps it while waiting.
pub(crate) fn pump_run_loop(duration: Duration) {
    use objc2_foundation::{NSDate, NSDefaultRunLoopMode, NSRunLoop};

    let run_loop = NSRunLoop::currentRunLoop();
    let limit = NSDate::now().dateByAddingTimeInterval(duration.as_secs_f64());
    // SAFETY: `NSDefaultRunLoopMode` is a framework-provided immutable
    // NSString constant; reading the extern static is always sound.
    let mode = unsafe { NSDefaultRunLoopMode };
    let _ = run_loop.runMode_beforeDate(mode, &limit);
}

/// Reinterpret a typed Objective-C object as `AnyObject` for delegate setters.
/// `AnyObject` is a zero-sized view over any object pointer, so the cast only
/// changes the static type.
pub(crate) fn as_any<T: objc2::Message>(object: &T) -> &objc2::runtime::AnyObject {
    // SAFETY: every Objective-C object is a valid `AnyObject`; the pointer is
    // borrowed for the same lifetime and no ownership is transferred.
    unsafe { &*(object as *const T as *const objc2::runtime::AnyObject) }
}
