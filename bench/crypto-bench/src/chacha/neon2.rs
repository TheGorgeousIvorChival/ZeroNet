#![cfg(target_arch = "aarch64")]
//! //! Two-block NEON ChaCha20: 128 bytes per pass, two states in flight. Covers
//! the two- and three-block band (65-192 B) where the 1-block core has no ILP
//! and the 4-block core would overshoot.
#![cfg(target_arch = "aarch64")]
//! Single-block NEON ChaCha20: four vector registers, rows rotated between the
//! column and diagonal rounds so one lane-wise quarter round does all four.
//! IETF layout: w0..3 constants, w4..11 key, w12 counter, w13..15 nonce.
use core::arch::aarch64::*;

const CONSTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[target_feature(enable = "neon")]
unsafe fn rotl16(v: uint32x4_t) -> uint32x4_t {
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)))
}
#[target_feature(enable = "neon")]
unsafe fn rotl8(v: uint32x4_t) -> uint32x4_t {
    let mask = [3u8, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];
    vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(v), vld1q_u8(mask.as_ptr())))
}
#[target_feature(enable = "neon")]
unsafe fn rotl12(v: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32(v, 12), vshrq_n_u32(v, 20))
}
#[target_feature(enable = "neon")]
unsafe fn rotl7(v: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32(v, 7), vshrq_n_u32(v, 25))
}


/// 20 rounds over 2 states at once, feed-forward included.
/// words 12..15 = (counter, nonce0, nonce1, nonce2)
#[inline]
#[target_feature(enable = "neon")]
unsafe fn tail(ctr: u32, nonce12: &[u8; 12]) -> uint32x4_t {
    let n0 = u32::from_le_bytes(nonce12[0..4].try_into().unwrap());
    let n1 = u32::from_le_bytes(nonce12[4..8].try_into().unwrap());
    let n2 = u32::from_le_bytes(nonce12[8..12].try_into().unwrap());
    let mut v = vdupq_n_u32(ctr);
    v = vsetq_lane_u32(n2, v, 3);
    v = vsetq_lane_u32(n1, v, 2);
    v = vsetq_lane_u32(n0, v, 1);
    v
}

#[inline]
#[target_feature(enable = "neon")]
unsafe fn rounds_two(o: [uint32x4_t; 8]) -> [uint32x4_t; 8] {
    let [a0, a1, a2, a3, b0, b1, b2, b3] = o;
    let (mut x0, mut x1, mut x2, mut x3) = (a0, a1, a2, a3);
    let (mut y0, mut y1, mut y2, mut y3) = (b0, b1, b2, b3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 1);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 3);
    y1 = vextq_u32(y1, y1, 1);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 3);

    x0 = vaddq_u32(x0, x1);
    x3 = rotl16(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl12(veorq_u32(x1, x2));
    x0 = vaddq_u32(x0, x1);
    x3 = rotl8(veorq_u32(x3, x0));
    x2 = vaddq_u32(x2, x3);
    x1 = rotl7(veorq_u32(x1, x2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl16(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl12(veorq_u32(y1, y2));
    y0 = vaddq_u32(y0, y1);
    y3 = rotl8(veorq_u32(y3, y0));
    y2 = vaddq_u32(y2, y3);
    y1 = rotl7(veorq_u32(y1, y2));

    x1 = vextq_u32(x1, x1, 3);
    x2 = vextq_u32(x2, x2, 2);
    x3 = vextq_u32(x3, x3, 1);
    y1 = vextq_u32(y1, y1, 3);
    y2 = vextq_u32(y2, y2, 2);
    y3 = vextq_u32(y3, y3, 1);

    [
        vaddq_u32(x0, a0), vaddq_u32(x1, a1), vaddq_u32(x2, a2), vaddq_u32(x3, a3),
        vaddq_u32(y0, b0), vaddq_u32(y1, b1), vaddq_u32(y2, b2), vaddq_u32(y3, b3),
    ]
}

/// One 128-byte group: 2 whole blocks.
#[target_feature(enable = "neon")]
pub unsafe fn xor_group(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
) {
    let cs = vld1q_u32(CONSTS.as_ptr());
    let k0 = vld1q_u32(key32.as_ptr() as *const u32);
    let k1 = vld1q_u32(key32.as_ptr().add(4) as *const u32);
    let mut st = [cs; 8];
    let mut b = 0;
    while b < 2 {
        let o = b * 4;
        st[o + 1] = k0;
        st[o + 2] = k1;
        st[o + 3] = tail((start + b as u64) as u32, nonce12);
        b += 1;
    }
    let f = rounds_two(st);
    let mut i = 0;
    while i < 8 {
        let d = i * 16;
        vst1q_u8(
            out.add(d),
            veorq_u8(vld1q_u8(inp.add(d)), vreinterpretq_u8_u32(f[i])),
        );
        i += 1;
    }
}
