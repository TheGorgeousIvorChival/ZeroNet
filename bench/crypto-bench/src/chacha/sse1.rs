#![cfg(target_arch = "x86_64")]
//! Single-block ChaCha20 on SSE2.
//!
//! A 128-bit vector is exactly one ChaCha row, so the aarch64 algorithm maps
//! over unchanged -- and the row rotation, which is `vextq_u32` there, is a
//! single `_mm_shuffle_epi32` here. SSE2 is baseline on every x86_64, so this
//! is the one-block rung with no runtime feature check at all.
//!
//! Fully unrolled for the same reason as the NEON 1-block core, and it is the
//! same lesson: ZeroNet builds at `opt-level = "s"`, and a rolled round loop at
//! -Os loses to the crate even when the instruction sequence is identical. The
//! rotations are spelled out inside the quarter-round macro because
//! `#[inline(always)]` cannot be combined with `#[target_feature]`, and a
//! helper that is merely `#[inline]` is exactly the outlining that made the
//! NEON one-block core slow.
//!
//! rotl8 and rotl12 and rotl7 are shift pairs, so this needs no SSSE3, and
//! rotl16 is one `pshufd` with the 32-bit words swapped.
use core::arch::x86_64::*;

/// `_mm_shuffle_epi32` picks each destination lane from a source lane with two
/// bits. 0x39 rotates left by one lane, 0x4E by two, 0x93 by three, and 0xB1 is
/// [1,0,3,2] -- a 32-bit word swapped, which is a rotate left by 16.
const ROT1: i32 = 0x39;
const ROT2: i32 = 0x4E;
const ROT3: i32 = 0x93;
const ROT16: i32 = 0xB1;

macro_rules! qr {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {{
        $a = _mm_add_epi32($a, $b);
        $d = _mm_shuffle_epi32::<ROT16>(_mm_xor_si128($d, $a));
        $c = _mm_add_epi32($c, $d);
        let t = _mm_xor_si128($b, $c);
        $b = _mm_or_si128(_mm_slli_epi32::<12>(t), _mm_srli_epi32::<20>(t));
        $a = _mm_add_epi32($a, $b);
        $d = _mm_or_si128(_mm_slli_epi32::<8>(_mm_xor_si128($d, $a)), _mm_srli_epi32::<24>(_mm_xor_si128($d, $a)));
        $c = _mm_add_epi32($c, $d);
        let t = _mm_xor_si128($b, $c);
        $b = _mm_or_si128(_mm_slli_epi32::<7>(t), _mm_srli_epi32::<25>(t));
    }};
}

macro_rules! dbl {
    ($x0:ident, $x1:ident, $x2:ident, $x3:ident) => {{
        qr!($x0, $x1, $x2, $x3);
        $x1 = _mm_shuffle_epi32::<ROT1>($x1);
        $x2 = _mm_shuffle_epi32::<ROT2>($x2);
        $x3 = _mm_shuffle_epi32::<ROT3>($x3);
        qr!($x0, $x1, $x2, $x3);
        $x1 = _mm_shuffle_epi32::<ROT3>($x1);
        $x2 = _mm_shuffle_epi32::<ROT2>($x2);
        $x3 = _mm_shuffle_epi32::<ROT1>($x3);
    }};
}

/// The 20 rounds as ten textual double rounds. Nothing in this file loops over
/// rounds, and the reason is written at the top.
macro_rules! rounds20 {
    ($x0:ident, $x1:ident, $x2:ident, $x3:ident) => {{
        dbl!($x0, $x1, $x2, $x3);
        dbl!($x0, $x1, $x2, $x3);
        dbl!($x0, $x1, $x2, $x3);
        dbl!($x0, $x1, $x2, $x3);
        dbl!($x0, $x1, $x2, $x3);
        dbl!($x0, $x1, $x2, $x3);
        dbl!($x0, $x1, $x2, $x3);
        dbl!($x0, $x1, $x2, $x3);
        dbl!($x0, $x1, $x2, $x3);
        dbl!($x0, $x1, $x2, $x3);
    }};
}

/// `inp` and `out` may alias exactly. Writes `len` bytes, 1..=len.
///
/// The round body is written out once, inside the loop, and serves whole blocks
/// and a short last block alike: `n` is how many of this block's 64 bytes are
/// wanted, and the branches in the epilogue are the only difference.
pub unsafe fn stream_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    let mut st = super::initial_state(key32, nonce12, start as u32);
    let c0 = _mm_loadu_si128(st.as_ptr().cast::<__m128i>());
    let k0 = _mm_loadu_si128(st.as_ptr().add(4).cast::<__m128i>());
    let k1 = _mm_loadu_si128(st.as_ptr().add(8).cast::<__m128i>());
    let mut off = 0usize;
    while off < len {
        let n = core::cmp::min(64, len - off);
        st[12] = (start + (off / 64) as u64) as u32;
        let o3 = _mm_loadu_si128(st.as_ptr().add(12).cast::<__m128i>());

        let (mut x0, mut x1, mut x2, mut x3) = (c0, k0, k1, o3);
        rounds20!(x0, x1, x2, x3);
        let f0 = _mm_add_epi32(x0, c0);
        let f1 = _mm_add_epi32(x1, k0);
        let f2 = _mm_add_epi32(x2, k1);
        let f3 = _mm_add_epi32(x3, o3);

        if n >= 16 {
            _mm_storeu_si128(
                out.add(off).cast::<__m128i>(),
                _mm_xor_si128(_mm_loadu_si128(inp.add(off).cast::<__m128i>()), f0),
            );
        }
        if n >= 32 {
            _mm_storeu_si128(
                out.add(off + 16).cast::<__m128i>(),
                _mm_xor_si128(_mm_loadu_si128(inp.add(off + 16).cast::<__m128i>()), f1),
            );
        }
        if n >= 48 {
            _mm_storeu_si128(
                out.add(off + 32).cast::<__m128i>(),
                _mm_xor_si128(_mm_loadu_si128(inp.add(off + 32).cast::<__m128i>()), f2),
            );
        }
        if n >= 64 {
            _mm_storeu_si128(
                out.add(off + 48).cast::<__m128i>(),
                _mm_xor_si128(_mm_loadu_si128(inp.add(off + 48).cast::<__m128i>()), f3),
            );
        }
        // Fewer than 16 bytes left after the last whole 16-byte chunk.
        let full = n & !15;
        if full < n {
            let mut ks = [0u8; 16];
            let f = match full {
                0 => f0,
                16 => f1,
                32 => f2,
                _ => f3,
            };
            _mm_storeu_si128(ks.as_mut_ptr().cast::<__m128i>(), f);
            let mut i = full;
            while i < n {
                *out.add(off + i) = *inp.add(off + i) ^ ks[i & 15];
                i += 1;
            }
        }
        off += n;
    }
}
