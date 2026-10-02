#![no_main]
//! Fuzz the XHTTP padding generator.
//!
//! `padding` is asked for a target encoded length and returns a string whose
//! Huffman-coded length lands within a small tolerance of it. The length comes
//! from the request being built, so it is attacker-influenced, and `tokenish`
//! reaches that target by pushing and popping characters up to 150 times. Two
//! properties must hold for every length: the search terminates rather than
//! spinning, and the result is header-safe printable ASCII, since it is written
//! into a request header where a control byte or a newline would be a header
//! injection primitive rather than padding.
//!
//! `RepeatX` is the simpler branch and must return exactly the length asked for.

use libfuzzer_sys::fuzz_target;
use zero_transport::xhttp_request::{padding, PaddingMethod};

fuzz_target!(|data: &[u8]| {
    // Bounded so the target stays fast; the search behaves the same at any
    // size and the interesting cases are the short ones.
    let length = match data.first() {
        Some(first) => (*first as usize) % 256,
        None => return,
    };

    let repeat = padding(PaddingMethod::RepeatX, length);
    assert_eq!(
        repeat.len(),
        length,
        "RepeatX must return exactly the length asked for"
    );
    assert!(repeat.bytes().all(|b| b == b'X'));

    let tokenish = padding(PaddingMethod::Tokenish, length);
    assert!(
        tokenish.bytes().all(|b| b.is_ascii_graphic()),
        "padding must stay header-safe ASCII"
    );
    assert!(
        !tokenish.is_empty(),
        "a non-zero length must produce some padding"
    );
});
