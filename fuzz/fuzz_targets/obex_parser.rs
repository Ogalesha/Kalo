#![no_main]

//! Fuzz the OBEX packet parser used by the Windows receiver.
//!
//! `PacketStream` is the crate that splits RFCOMM bytes into OBEX requests
//! before Kalo sees headers, names and bodies. A panic or an unbounded
//! allocation here would be reachable by any peer that opens the OPP service.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut stream = obex_protocol::transport::PacketStream::new(data);
    // A short input can encode many tiny packets; keep each iteration bounded
    // so the fuzzer spends its time on parsing rather than looping.
    for _ in 0..64 {
        if stream.read_request().is_err() {
            break;
        }
    }
});
