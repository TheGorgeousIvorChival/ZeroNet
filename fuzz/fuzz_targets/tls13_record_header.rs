#![no_main]
//! Fuzz the TLS 1.3 record header parser.
//!
//! Every byte of a record header arrives from the peer, including the 16-bit
//! length that decides how much ciphertext the reader will try to take. The
//! parser must floor a short slice as a truncation rather than panicking on the
// `try_into`, and must reject a length above `MAX_CIPHERTEXT` rather than let a
// caller allocate or read that much. The version bytes are deliberately not
// validated here — the handshake layer owns that — so the only contract is
//! "short in, `Err` out; long in, either a bounded length or `Err`".

use libfuzzer_sys::fuzz_target;
use zero_security::tls13::record::parse_header;
use zero_security::tls13::MAX_CIPHERTEXT;

fuzz_target!(|data: &[u8]| {
    match parse_header(data) {
        Ok((_content_type, body_len)) => {
            assert!(
                body_len <= MAX_CIPHERTEXT,
                "parse_header returned {body_len}, past the {MAX_CIPHERTEXT}-byte limit"
            );
        }
        Err(_) => {}
    }
});
