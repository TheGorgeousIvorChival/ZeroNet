#![cfg(target_arch = "x86_64")]
//! Multi-block ChaCha20 on AVX2: 2, 4 and 8 blocks per pass.
//!
//! The row layout is *cheaper* here than on aarch64, and that is the reason to
//! use it rather than a transposed one. Each 128-bit lane of a YMM register is
//! one block's row, and `_mm256_shuffle_epi32` rotates the two halves
//! independently in a single instruction, so the six row rotations a double
//! round needs cost six instructions per *pair* of blocks rather than six per
//! block. rotl8 is one `vpshufb` and rotl16 is one `vpshufd`.
//!
//! The three constant and key rows are the same in every lane, so only the
//! counter row is per-block: 8 blocks of state cost 3 shared YMM registers plus
//! 4 counter registers, not 16. That headroom is the whole reason the widths
//! here are wider than the crate's four.
//!
//! Nothing loops over rounds, for the reason the NEON 1-block core spells out:
//! ZeroNet builds at `opt-level = "s"` and a rolled loop at -Os loses to the
//! crate even when the instruction sequence is the same.
use core::arch::x86_64::*;

use super::CONSTS;

/// Byte indices that rotate every 32-bit lane left by 8, duplicated into both
/// 128-bit halves because `vpshufb` selects per lane.
const ROT8: [i8; 32] = [
    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, //
    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,
];

/// Row rotations by 1, 2 and 3 lanes, and the word swap that is rotl16. See
/// `sse1.rs` for how these five bits are laid out.
const ROT1: i32 = 0x39;
const ROT2: i32 = 0x4E;
const ROT3: i32 = 0x93;
const ROT16: i32 = 0xB1;

#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn rotl8(v: __m256i, m: __m256i) -> __m256i {
    _mm256_shuffle_epi8(v, m)
}

macro_rules! qr {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:ident) => {{
        $a = _mm256_add_epi32($a, $b);
        $d = _mm256_shuffle_epi32::<ROT16>(_mm256_xor_si256($d, $a));
        $c = _mm256_add_epi32($c, $d);
        let t = _mm256_xor_si256($b, $c);
        $b = _mm256_or_si256(_mm256_slli_epi32::<12>(t), _mm256_srli_epi32::<20>(t));
        $a = _mm256_add_epi32($a, $b);
        $d = rotl8(_mm256_xor_si256($d, $a), $m);
        $c = _mm256_add_epi32($c, $d);
        let t = _mm256_xor_si256($b, $c);
        $b = _mm256_or_si256(_mm256_slli_epi32::<7>(t), _mm256_srli_epi32::<25>(t));
    }};
}

macro_rules! dbl {
    ($x0:ident, $x1:ident, $x2:ident, $x3:ident, $m:ident) => {{
        qr!($x0, $x1, $x2, $x3, $m);
        $x1 = _mm256_shuffle_epi32::<ROT1>($x1);
        $x2 = _mm256_shuffle_epi32::<ROT2>($x2);
        $x3 = _mm256_shuffle_epi32::<ROT3>($x3);
        qr!($x0, $x1, $x2, $x3, $m);
        $x1 = _mm256_shuffle_epi32::<ROT3>($x1);
        $x2 = _mm256_shuffle_epi32::<ROT2>($x2);
        $x3 = _mm256_shuffle_epi32::<ROT1>($x3);
    }};
}

/// Ten double rounds for every pair of blocks in the list. The three constant
/// and key rows are named once and listed once per pair, which is exactly why
/// widening the core costs so few registers.
macro_rules! rounds10 {
    ($m:ident; $($x0:ident $x1:ident $x2:ident $x3:ident),+ $(,)?) => {{
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
        $( dbl!($x0, $x1, $x2, $x3, $m); )+
    }};
}

/// `(counter, nonce0, nonce1, nonce2)` for two consecutive blocks.
macro_rules! ctr2 {
    ($c:expr, $n0:expr, $n1:expr, $n2:expr) => {
        _mm256_setr_epi32(
            $c as i32,
            $n0,
            $n1,
            $n2,
            $c.wrapping_add(1) as i32,
            $n0,
            $n1,
            $n2,
        )
    };
}

/// Low lane: the first of the two blocks this YMM register holds.
#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn lo(v: __m256i) -> __m128i {
    _mm256_castsi256_si128(v)
}

/// High lane: the second block.
#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn hi(v: __m256i) -> __m128i {
    _mm256_extracti128_si256::<1>(v)
}

/// XOR one finished 64-byte block -- four 16-byte rows -- into the data,
/// writing `n` of those 64 bytes. `n` is 64 for every block but the last of a
/// message, so the short path is cold and the branches predict perfectly.
#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn xor_block64(
    inp: *const u8,
    out: *mut u8,
    n: usize,
    a: __m128i,
    b: __m128i,
    c: __m128i,
    d: __m128i,
) {
    if n >= 16 {
        _mm_storeu_si128(
            out.cast::<__m128i>(),
            _mm_xor_si128(_mm_loadu_si128(inp.cast::<__m128i>()), a),
        );
    }
    if n >= 32 {
        _mm_storeu_si128(
            out.add(16).cast::<__m128i>(),
            _mm_xor_si128(_mm_loadu_si128(inp.add(16).cast::<__m128i>()), b),
        );
    }
    if n >= 48 {
        _mm_storeu_si128(
            out.add(32).cast::<__m128i>(),
            _mm_xor_si128(_mm_loadu_si128(inp.add(32).cast::<__m128i>()), c),
        );
    }
    if n >= 64 {
        _mm_storeu_si128(
            out.add(48).cast::<__m128i>(),
            _mm_xor_si128(_mm_loadu_si128(inp.add(48).cast::<__m128i>()), d),
        );
    }
    // Fewer than 16 bytes left after the last whole 16-byte chunk.
    let full = n & !15;
    if full < n {
        let mut ks = [0u8; 16];
        let f = match full {
            0 => a,
            16 => b,
            32 => c,
            _ => d,
        };
        _mm_storeu_si128(ks.as_mut_ptr().cast::<__m128i>(), f);
        let mut i = full;
        while i < n {
            *out.add(i) = *inp.add(i) ^ ks[i & 15];
            i += 1;
        }
    }
}

/// A 128-byte pair. Each block is one 128-bit lane of each row, so the two
/// blocks are stored separately: one 32-byte store would put the second block's
/// first row 32 bytes from the first block's instead of 64. `$n` is how many of
/// this pair's 128 bytes the caller wants, clamped here so a wide caller cannot
/// overrun its own group.
macro_rules! emit_pair {
    ($x0:ident, $x1:ident, $x2:ident, $y3:ident, $off:expr, $want:expr, $inp:expr, $out:expr) => {{
        let n = core::cmp::min($want, 128);
        let na = core::cmp::min(n, 64);
        xor_block64($inp.add($off), $out.add($off), na, lo($x0), lo($x1), lo($x2), lo($y3));
        if n > 64 {
            xor_block64(
                $inp.add($off + 64),
                $out.add($off + 64),
                n - 64,
                hi($x0),
                hi($x1),
                hi($x2),
                hi($y3),
            );
        }
    }};
}

/// Loads the three shared rows and the rotl8 table.
macro_rules! shared {
    ($st:expr) => {{
        let cst = _mm256_set1_epi32(CONSTS[0] as i32);
        let k0 = _mm256_set1_epi32($st[4] as i32);
        let k1 = _mm256_set1_epi32($st[8] as i32);
        let m = _mm256_loadu_si256(ROT8.as_ptr().cast::<__m256i>());
        (cst, k0, k1, m)
    }};
}

/// Two blocks, 128 bytes. `bytes` is 1..=128; the ladder only ever passes a
/// short `bytes` for the last group of a message.
#[target_feature(enable = "avx2")]
pub unsafe fn xor2(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
    bytes: usize,
) {
    let st = super::initial_state(key32, nonce12, start as u32);
    let (cst, k0, k1, m) = shared!(st);
    let n0 = st[13] as i32;
    let n1 = st[14] as i32;
    let n2 = st[15] as i32;
    let oy = ctr2!(st[12], n0, n1, n2);
    let (mut x0, mut x1, mut x2) = (cst, k0, k1);
    let mut y3 = oy;
    rounds10!(m; x0 x1 x2 y3);
    let f0 = _mm256_add_epi32(x0, cst);
    let f1 = _mm256_add_epi32(x1, k0);
    let f2 = _mm256_add_epi32(x2, k1);
    let f3 = _mm256_add_epi32(y3, oy);
    emit_pair!(f0, f1, f2, f3, 0, bytes, inp, out);
}

/// Four blocks, 256 bytes. `bytes` is 1..=256, as for `xor2`.
#[target_feature(enable = "avx2")]
pub unsafe fn xor4(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
    bytes: usize,
) {
    let st = super::initial_state(key32, nonce12, start as u32);
    let (cst, k0, k1, m) = shared!(st);
    let n0 = st[13] as i32;
    let n1 = st[14] as i32;
    let n2 = st[15] as i32;
    let oy = ctr2!(st[12], n0, n1, n2);
    let oz = ctr2!(st[12].wrapping_add(2), n0, n1, n2);
    let (mut x0, mut x1, mut x2) = (cst, k0, k1);
    let (mut y3, mut z3) = (oy, oz);
    rounds10!(m; x0 x1 x2 y3, x0 x1 x2 z3);
    let f0 = _mm256_add_epi32(x0, cst);
    let f1 = _mm256_add_epi32(x1, k0);
    let f2 = _mm256_add_epi32(x2, k1);
    let fy = _mm256_add_epi32(y3, oy);
    let fz = _mm256_add_epi32(z3, oz);
    emit_pair!(f0, f1, f2, fy, 0, bytes, inp, out);
    emit_pair!(f0, f1, f2, fz, 128, bytes.saturating_sub(128), inp, out);
}

/// Eight blocks, 512 bytes. Always whole: the ladder sizes this rung in bytes
/// precisely so that a short message never lands here.
#[target_feature(enable = "avx2")]
pub unsafe fn xor8(key32: &[u8; 32], nonce12: &[u8; 12], start: u64, inp: *const u8, out: *mut u8) {
    let st = super::initial_state(key32, nonce12, start as u32);
    let (cst, k0, k1, m) = shared!(st);
    let n0 = st[13] as i32;
    let n1 = st[14] as i32;
    let n2 = st[15] as i32;
    let c = st[12];
    let oy = ctr2!(c, n0, n1, n2);
    let oz = ctr2!(c.wrapping_add(2), n0, n1, n2);
    let ow = ctr2!(c.wrapping_add(4), n0, n1, n2);
    let ov = ctr2!(c.wrapping_add(6), n0, n1, n2);
    let (mut x0, mut x1, mut x2) = (cst, k0, k1);
    let (mut y3, mut z3, mut w3, mut v3) = (oy, oz, ow, ov);
    rounds10!(m; x0 x1 x2 y3, x0 x1 x2 z3, x0 x1 x2 w3, x0 x1 x2 v3);
    let f0 = _mm256_add_epi32(x0, cst);
    let f1 = _mm256_add_epi32(x1, k0);
    let f2 = _mm256_add_epi32(x2, k1);
    let fy = _mm256_add_epi32(y3, oy);
    let fz = _mm256_add_epi32(z3, oz);
    let fw = _mm256_add_epi32(w3, ow);
    let fv = _mm256_add_epi32(v3, ov);
    emit_pair!(f0, f1, f2, fy, 0, 128, inp, out);
    emit_pair!(f0, f1, f2, fz, 128, 128, inp, out);
    emit_pair!(f0, f1, f2, fw, 256, 128, inp, out);
    emit_pair!(f0, f1, f2, fv, 384, 128, inp, out);
}
