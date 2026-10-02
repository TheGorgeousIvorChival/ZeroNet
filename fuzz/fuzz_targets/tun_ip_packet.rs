#![no_main]
//! Fuzz the TUN packet parser.
//!
//! `parse_ip_packet` reads its own header lengths out of the packet: the IPv4
//! `ihl` decides where the transport header starts, and the 16-bit `total`
//! decides how far the slice reaches. Every one of those fields is attacker
//! supplied and they are checked against each other rather than against the
//! packet, so the invariant that matters is that a parsed packet's payload is
//! always a subslice of the input. If `ihl` or `total` were ever taken on
//! trust, a packet could yield a payload reaching past its own bytes, and that
//! is a memory-safety bug reachable from the network with no authentication.
//!
//! Both address families are exercised, and the transport header's own length
//! is parsed too, since it narrows the payload further.

use std::net::{Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use zero_tun::parse_ip_packet;

fuzz_target!(|data: &[u8]| {
    let Ok(packet) = parse_ip_packet(data) else {
        return;
    };

    // The payload must lie inside the bytes that were handed in.
    let start = packet
        .payload
        .as_ptr()
        .cast::<u8>()
        .wrapping_offset_from(data.as_ptr());
    assert!(
        start <= data.len() && packet.payload.len() <= data.len() - start,
        "payload of {} bytes at offset {start} escapes a {} byte packet",
        packet.payload.len(),
        data.len()
    );

    // An address family must agree with the version nibble the parser read.
    match (packet.source, packet.destination) {
        (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_)) => {}
        (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_)) => {}
        _ => unreachable!("parse_ip_packet returned mixed address families"),
    }
    let _ = (Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
});
