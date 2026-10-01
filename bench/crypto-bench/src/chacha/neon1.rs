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

macro_rules! qr {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {{
        $a = vaddq_u32($a, $b);
        $d = rotl16(veorq_u32($d, $a));
        $c = vaddq_u32($c, $d);
        $b = rotl12(veorq_u32($b, $c));
        $a = vaddq_u32($a, $b);
        $d = rotl8(veorq_u32($d, $a));
        $c = vaddq_u32($c, $d);
        $b = rotl7(veorq_u32($b, $c));
    }};
}

/// words 13..15: the nonce half, built once per call.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn nonce_half(nonce12: &[u8; 12]) -> uint32x4_t {
    let n0 = u32::from_le_bytes([nonce12[0], nonce12[1], nonce12[2], nonce12[3]]);
    let n1 = u32::from_le_bytes([nonce12[4], nonce12[5], nonce12[6], nonce12[7]]);
    let n2 = u32::from_le_bytes([nonce12[8], nonce12[9], nonce12[10], nonce12[11]]);
    let mut v = vdupq_n_u32(0);
    v = vsetq_lane_u32(n2, v, 3);
    v = vsetq_lane_u32(n1, v, 2);
    v = vsetq_lane_u32(n0, v, 1);
    v
}

/// words 12..15 = (counter, nonce0, nonce1, nonce2)
#[inline]
#[target_feature(enable = "neon")]
unsafe fn tail(base: uint32x4_t, ctr: u32) -> uint32x4_t {
    vsetq_lane_u32(ctr, base, 0)
}

#[inline]
#[target_feature(enable = "neon")]
unsafe fn rounds(
    o0: uint32x4_t,
    o1: uint32x4_t,
    o2: uint32x4_t,
    o3: uint32x4_t,
) -> [uint32x4_t; 4] {
    let (mut x0, mut x1, mut x2, mut x3) = (o0, o1, o2, o3);
    for _ in 0..10 {
        // Column round, then permute the rows so the same lane-wise quarter
        // round computes all four diagonals (and back again for the next pair).
        qr!(x0, x1, x2, x3);
        x1 = vextq_u32(x1, x1, 1);
        x2 = vextq_u32(x2, x2, 2);
        x3 = vextq_u32(x3, x3, 3);
        qr!(x0, x1, x2, x3);
        x1 = vextq_u32(x1, x1, 3);
        x2 = vextq_u32(x2, x2, 2);
        x3 = vextq_u32(x3, x3, 1);
    }
    [
        vaddq_u32(x0, o0),
        vaddq_u32(x1, o1),
        vaddq_u32(x2, o2),
        vaddq_u32(x3, o3),
    ]
}

/// `inp` and `out` may alias exactly. `start` is the block counter.
/// IETF counters wrap at 2^32 blocks, matching the crate's 64-bit state.
pub unsafe fn stream_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    let x0 = vld1q_u32(CONSTS.as_ptr());
    let x1 = vld1q_u32(key32.as_ptr() as *const u32);
    let x2 = vld1q_u32(key32.as_ptr().add(4) as *const u32);
    let base = nonce_half(nonce12);
    let mut off = 0usize;
    // Whole blocks: fuse the XOR in the vector domain -- no keystream buffer,
    // no byte loop, and vld1q_u8/vst1q_u8 are unaligned-safe.
    while off + 64 <= len {
        let ctr = (start + (off / 64) as u64) as u32;
        let f = rounds(x0, x1, x2, tail(base, ctr));
        vst1q_u8(
            out.add(off),
            veorq_u8(vld1q_u8(inp.add(off)), vreinterpretq_u8_u32(f[0])),
        );
        vst1q_u8(
            out.add(off + 16),
            veorq_u8(vld1q_u8(inp.add(off + 16)), vreinterpretq_u8_u32(f[1])),
        );
        vst1q_u8(
            out.add(off + 32),
            veorq_u8(vld1q_u8(inp.add(off + 32)), vreinterpretq_u8_u32(f[2])),
        );
        vst1q_u8(
            out.add(off + 48),
            veorq_u8(vld1q_u8(inp.add(off + 48)), vreinterpretq_u8_u32(f[3])),
        );
        off += 64;
    }
    // Trailing partial block. Straight-line, no dynamic index into the state:
    // the indexed version spent more time on bookkeeping than the 20 rounds.
    if off < len {
        let ctr = (start + (off / 64) as u64) as u32;
        let f = rounds(x0, x1, x2, tail(base, ctr));
        let n = len - off;
        if n >= 16 {
            vst1q_u8(out.add(off), veorq_u8(vld1q_u8(inp.add(off)), vreinterpretq_u8_u32(f[0])));
        }
        if n >= 32 {
            vst1q_u8(out.add(off + 16), veorq_u8(vld1q_u8(inp.add(off + 16)), vreinterpretq_u8_u32(f[1])));
        }
        if n >= 48 {
            vst1q_u8(out.add(off + 32), veorq_u8(vld1q_u8(inp.add(off + 32)), vreinterpretq_u8_u32(f[2])));
        }
        let full = n & !15;
        if full > 48 {
            vst1q_u8(out.add(off + 48), veorq_u8(vld1q_u8(inp.add(off + 48)), vreinterpretq_u8_u32(f[3])));
        }
        // Whatever is left over after the last whole 16-byte chunk.
        if full < n {
            let mut ks = [0u8; 16];
            vst1q_u8(
                ks.as_mut_ptr(),
                vreinterpretq_u8_u32(match full {
                    0 => f[0],
                    16 => f[1],
                    32 => f[2],
                    _ => f[3],
                }),
            );
            let mut i = full;
            while i < n {
                *out.add(off + i) = *inp.add(off + i) ^ ks[i & 15];
                i += 1;
            }
        }
    }
}
