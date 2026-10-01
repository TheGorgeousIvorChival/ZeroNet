#![cfg(target_arch = "aarch64")]
//! Single-block NEON ChaCha20: four vector registers, rows rotated between the
//! column and diagonal rounds so one lane-wise quarter round does all four.
//! IETF layout: w0..3 constants, w4..11 key, w12 counter, w13..15 nonce.
//!
//! The 20 rounds are written out as ten double rounds, and that is the entire
//! point of this file. It used to run them in a `for _ in 0..10` loop and
//! measured 0.74-0.96x against the crate at 16-64 bytes, while the hand
//! unrolled 2/4/8-block cores measured 1.33-2.68x on the same target and the
//! same day. Two reasons, and neither of them is NEON:
//!
//!   * ZeroNet builds at `opt-level = "s"` and this harness mirrors that
//!     profile on purpose, because a number measured at -O3 is not a number
//!     anybody ships. At -Os LLVM does not unroll, so every double round pays
//!     a compare and a branch over a 60-operation body, and the rotate
//!     helpers are outlined rather than inlined.
//!   * One block in flight has no instruction-level parallelism to hide any of
//!     that behind, which is exactly why the same rolled loop in the 8-block
//!     core is invisible. One state is the only width where loop overhead is
//!     not amortised.
//!
//! What does not change: the row layout, the `vextq_u32` row rotation that
//! makes one lane-wise quarter round compute all four diagonals, the XOR fused
//! into the vector domain so there is no keystream buffer and no byte loop over
//! whole blocks, and unaligned 16-byte accesses so in-place works.
use core::arch::aarch64::*;

/// Byte indices that rotate every 32-bit lane left by 8 inside `vqtbl1q_u8`.
///
/// A function-local `const` array would have its address taken, and the store
/// to `out` in the block epilogue is then something LLVM must assume may alias
/// it, so the mask gets reloaded after every block. It is loaded once in
/// `stream_xor` and carried through the rounds as a value instead.
const ROT8: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];

#[inline(always)]
#[target_feature(enable = "neon")]
unsafe fn rotl16(v: uint32x4_t) -> uint32x4_t {
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)))
}

#[inline(always)]
#[target_feature(enable = "neon")]
unsafe fn rotl8(v: uint32x4_t, m: uint8x16_t) -> uint32x4_t {
    vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(v), m))
}

#[inline(always)]
#[target_feature(enable = "neon")]
unsafe fn rotl12(v: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32(v, 12), vshrq_n_u32(v, 20))
}

#[inline(always)]
#[target_feature(enable = "neon")]
unsafe fn rotl7(v: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32(v, 7), vshrq_n_u32(v, 25))
}

/// One lane-wise quarter round. Lane i is whichever of the four quarter rounds
/// the current frame has lined up; both frames of a double round use the same
/// eight operations.
macro_rules! qr {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:ident) => {{
        $a = vaddq_u32($a, $b);
        $d = rotl16(veorq_u32($d, $a));
        $c = vaddq_u32($c, $d);
        $b = rotl12(veorq_u32($b, $c));
        $a = vaddq_u32($a, $b);
        $d = rotl8(veorq_u32($d, $a), $m);
        $c = vaddq_u32($c, $d);
        $b = rotl7(veorq_u32($b, $c));
    }};
}

/// One double round: the column round, a row rotation that lines the four
/// diagonals up, the diagonal round, and the row rotation back for the next
/// column round.
macro_rules! dbl {
    ($x0:ident, $x1:ident, $x2:ident, $x3:ident, $m:ident) => {{
        qr!($x0, $x1, $x2, $x3, $m);
        $x1 = vextq_u32($x1, $x1, 1);
        $x2 = vextq_u32($x2, $x2, 2);
        $x3 = vextq_u32($x3, $x3, 3);
        qr!($x0, $x1, $x2, $x3, $m);
        $x1 = vextq_u32($x1, $x1, 3);
        $x2 = vextq_u32($x2, $x2, 2);
        $x3 = vextq_u32($x3, $x3, 1);
    }};
}

/// The 20 rounds, as ten textual double rounds. Nothing in this path loops over
/// rounds: under `opt-level = "s"` a loop here is measurably slower than the
/// crate, and the crate is the thing being beaten.
macro_rules! rounds20 {
    ($x0:ident, $x1:ident, $x2:ident, $x3:ident, $m:ident) => {{
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
        dbl!($x0, $x1, $x2, $x3, $m);
    }};
}

/// One block: twenty rounds, the feed-forward add, and the XOR fused into the
/// vector domain. `n` is 1..=64, so a whole 64-byte block is four unaligned
/// 16-byte load/XOR/store pairs with no keystream buffer anywhere.
///
/// `#[inline(always)]` because the caller is a per-block loop and a call here
/// would put the 64-byte result array in memory between rounds.
#[inline(always)]
#[target_feature(enable = "neon")]
unsafe fn block1(
    c0: uint32x4_t,
    k0: uint32x4_t,
    k1: uint32x4_t,
    o3: uint32x4_t,
    m: uint8x16_t,
    inp: *const u8,
    out: *mut u8,
    n: usize,
) {
    let (mut x0, mut x1, mut x2, mut x3) = (c0, k0, k1, o3);
    rounds20!(x0, x1, x2, x3, m);
    let f0 = vaddq_u32(x0, c0);
    let f1 = vaddq_u32(x1, k0);
    let f2 = vaddq_u32(x2, k1);
    let f3 = vaddq_u32(x3, o3);
    if n >= 16 {
        vst1q_u8(out, veorq_u8(vld1q_u8(inp), vreinterpretq_u8_u32(f0)));
    }
    if n >= 32 {
        vst1q_u8(
            out.add(16),
            veorq_u8(vld1q_u8(inp.add(16)), vreinterpretq_u8_u32(f1)),
        );
    }
    if n >= 48 {
        vst1q_u8(
            out.add(32),
            veorq_u8(vld1q_u8(inp.add(32)), vreinterpretq_u8_u32(f2)),
        );
    }
    if n >= 64 {
        vst1q_u8(
            out.add(48),
            veorq_u8(vld1q_u8(inp.add(48)), vreinterpretq_u8_u32(f3)),
        );
    }
    // Fewer than 16 bytes left after the last whole 16-byte chunk: spill one
    // chunk of keystream and finish scalar. At most 15 iterations.
    let full = n & !15;
    if full < n {
        let mut ks = [0u8; 16];
        vst1q_u8(
            ks.as_mut_ptr(),
            vreinterpretq_u8_u32(match full {
                0 => f0,
                16 => f1,
                32 => f2,
                _ => f3,
            }),
        );
        let mut i = full;
        while i < n {
            *out.add(i) = *inp.add(i) ^ ks[i & 15];
            i += 1;
        }
    }
}

/// `inp` and `out` may alias exactly. `start` is the block counter.
/// IETF counters wrap at 2^32 blocks, matching the crate's 64-bit state.
#[target_feature(enable = "neon")]
pub unsafe fn stream_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    let mut st = super::initial_state(key32, nonce12, start as u32);
    let c0 = vld1q_u32(st.as_ptr());
    let k0 = vld1q_u32(st.as_ptr().add(4));
    let k1 = vld1q_u32(st.as_ptr().add(8));
    let m = vld1q_u8(ROT8.as_ptr());
    let mut off = 0usize;
    while off + 64 <= len {
        let ctr = (start + (off / 64) as u64) as u32;
        st[12] = ctr;
        let x3 = vld1q_u32(st.as_ptr().add(12));
        block1(c0, k0, k1, x3, m, inp.add(off), out.add(off), 64);
        off += 64;
    }
    if off < len {
        let ctr = (start + (off / 64) as u64) as u32;
        st[12] = ctr;
        let x3 = vld1q_u32(st.as_ptr().add(12));
        block1(c0, k0, k1, x3, m, inp.add(off), out.add(off), len - off);
    }
}
