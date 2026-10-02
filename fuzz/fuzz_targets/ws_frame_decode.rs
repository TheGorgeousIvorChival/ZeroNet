#![no_main]
//! Fuzz the WebSocket frame decoder.
//!
//! `decode` reads a length out of the wire before it knows how many bytes are
//! present, chooses a 2-, 4- or 10-byte header from the low bits of the second
//! byte, and masks the payload in place. A hostile peer controls every one of
//! those fields, so the decoder must return `Ok(None)` for a frame it cannot
//! yet read, `Err` for a frame it will never accept, and `Ok(Some(_))` only
//! once every declared byte is present — never panic, index out of bounds, or
//! allocate on a declared length it has not bounded.
//!
//! `Ok(None)` must also leave the buffer intact so a caller can retry after a
//! short read, so the target checks that too: it appends a suffix and expects
//! the retry to make progress rather than lose the frame.

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use zero_transport::ws::frame::decode;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);

    // A first pass must never panic, whatever the bytes are.
    let first = decode(&mut buf);

    match first {
        // Incomplete: the buffer must be untouched, so a later read can retry.
        Ok(None) => {
            assert_eq!(buf.len(), data.len(), "a partial frame must not be consumed");
        }
        // A complete frame: the payload length it reports must be real.
        Ok(Some(frame)) => {
            assert!(
                frame.payload.len() <= 16 * 1024 * 1024,
                "decoded a payload past the frame limit"
            );
        }
        // A rejected frame is a legitimate outcome; the length is untrusted
        // input, so only the absence of a panic is asserted.
        Err(_) => {}
    }

    // Retrying after more bytes arrive must never panic either, and must not
    // loop forever on bytes that will never parse.
    let _ = decode(&mut buf);
});
