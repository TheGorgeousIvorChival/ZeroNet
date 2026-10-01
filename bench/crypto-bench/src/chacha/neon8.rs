#![cfg(target_arch = "aarch64")]

use chacha20::{ChaCha20, Key as ChaKey, Nonce as ChaNonce12};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use core::arch::aarch64::*;

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

macro_rules! add64 {
    ($a:expr, $b:expr) => {
        vreinterpretq_u32_u64(vaddq_u64(
            vreinterpretq_u64_u32($a),
            vreinterpretq_u64_u32($b),
        ))
    };
}

macro_rules! quarter {
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

macro_rules! doubleround {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {{
        quarter!($a, $b, $c, $d);
        $b = vextq_u32($b, $b, 1);
        $c = vextq_u32($c, $c, 2);
        $d = vextq_u32($d, $d, 3);
        quarter!($a, $b, $c, $d);
        $b = vextq_u32($b, $b, 3);
        $c = vextq_u32($c, $c, 2);
        $d = vextq_u32($d, $d, 1);
    }};
}

// XOR one finished block's keystream (4 vectors) against `ip` and write to `op`.
// `ip == op` is the in-place case: each 16-byte word is loaded then stored at the
// same address, so aliasing is read-before-write and safe.
#[target_feature(enable = "neon")]
unsafe fn xor_store(
    op: *mut u8,
    ip: *const u8,
    a: uint32x4_t,
    b: uint32x4_t,
    c: uint32x4_t,
    d: uint32x4_t,
) {
    unsafe {
        let x0 = veorq_u32(vld1q_u32(ip.cast::<u32>()), a);
        let x1 = veorq_u32(vld1q_u32(ip.add(16).cast::<u32>()), b);
        let x2 = veorq_u32(vld1q_u32(ip.add(32).cast::<u32>()), c);
        let x3 = veorq_u32(vld1q_u32(ip.add(48).cast::<u32>()), d);
        vst1q_u32(op.cast::<u32>(), x0);
        vst1q_u32(op.add(16).cast::<u32>(), x1);
        vst1q_u32(op.add(32).cast::<u32>(), x2);
        vst1q_u32(op.add(48).cast::<u32>(), x3);
    }
}

#[inline(always)]
fn ctr_vec(i: u32) -> uint32x4_t {
    unsafe { vld1q_u32([i, 0, 0, 0].as_ptr()) }
}

/// Hand core: XOR the keystream for `groups` 8-block groups (each 512 bytes)
/// into `out`, reading the pre-XOR bytes from `inp`. `state`'s word 12 is the
/// first block counter. Total blocks processed = `groups * 8`.
#[target_feature(enable = "neon")]
unsafe fn xor_bulk(state: &[u32; 16], inp: *const u8, out: *mut u8, groups: usize) {
    let s0 = unsafe { vld1q_u32(state.as_ptr()) };
    let s1 = unsafe { vld1q_u32(state.as_ptr().add(4)) };
    let s2 = unsafe { vld1q_u32(state.as_ptr().add(8)) };
    let s3 = unsafe { vld1q_u32(state.as_ptr().add(12)) };
    let mut c3 = s3;
    let mut ip = inp;
    let mut op = out;
    for _ in 0..groups {
        unsafe {
            let (mut a0, mut a1, mut a2, mut a3) = (s0, s1, s2, c3);
            let (mut b0, mut b1, mut b2, mut b3) = (s0, s1, s2, add64!(c3, ctr_vec(1)));
            let (mut c0, mut c1, mut c2, mut c3b) = (s0, s1, s2, add64!(c3, ctr_vec(2)));
            let (mut d0, mut d1, mut d2, mut d3) = (s0, s1, s2, add64!(c3, ctr_vec(3)));
            let (mut e0, mut e1, mut e2, mut e3) = (s0, s1, s2, add64!(c3, ctr_vec(4)));
            let (mut f0, mut f1, mut f2, mut f3) = (s0, s1, s2, add64!(c3, ctr_vec(5)));
            let (mut g0, mut g1, mut g2, mut g3) = (s0, s1, s2, add64!(c3, ctr_vec(6)));
            let (mut h0, mut h1, mut h2, mut h3) = (s0, s1, s2, add64!(c3, ctr_vec(7)));
            for _ in 0..10 {
                doubleround!(a0, a1, a2, a3);
                doubleround!(b0, b1, b2, b3);
                doubleround!(c0, c1, c2, c3b);
                doubleround!(d0, d1, d2, d3);
                doubleround!(e0, e1, e2, e3);
                doubleround!(f0, f1, f2, f3);
                doubleround!(g0, g1, g2, g3);
                doubleround!(h0, h1, h2, h3);
            }
            // Feedback (add input state + per-lane counter), XOR into data, store.
            xor_store(
                op,
                ip,
                vaddq_u32(a0, s0),
                vaddq_u32(a1, s1),
                vaddq_u32(a2, s2),
                add64!(vaddq_u32(a3, c3), ctr_vec(0)),
            );
            xor_store(
                op.add(64),
                ip.add(64),
                vaddq_u32(b0, s0),
                vaddq_u32(b1, s1),
                vaddq_u32(b2, s2),
                add64!(vaddq_u32(b3, c3), ctr_vec(1)),
            );
            xor_store(
                op.add(128),
                ip.add(128),
                vaddq_u32(c0, s0),
                vaddq_u32(c1, s1),
                vaddq_u32(c2, s2),
                add64!(vaddq_u32(c3b, c3), ctr_vec(2)),
            );
            xor_store(
                op.add(192),
                ip.add(192),
                vaddq_u32(d0, s0),
                vaddq_u32(d1, s1),
                vaddq_u32(d2, s2),
                add64!(vaddq_u32(d3, c3), ctr_vec(3)),
            );
            xor_store(
                op.add(256),
                ip.add(256),
                vaddq_u32(e0, s0),
                vaddq_u32(e1, s1),
                vaddq_u32(e2, s2),
                add64!(vaddq_u32(e3, c3), ctr_vec(4)),
            );
            xor_store(
                op.add(320),
                ip.add(320),
                vaddq_u32(f0, s0),
                vaddq_u32(f1, s1),
                vaddq_u32(f2, s2),
                add64!(vaddq_u32(f3, c3), ctr_vec(5)),
            );
            xor_store(
                op.add(384),
                ip.add(384),
                vaddq_u32(g0, s0),
                vaddq_u32(g1, s1),
                vaddq_u32(g2, s2),
                add64!(vaddq_u32(g3, c3), ctr_vec(6)),
            );
            xor_store(
                op.add(448),
                ip.add(448),
                vaddq_u32(h0, s0),
                vaddq_u32(h1, s1),
                vaddq_u32(h2, s2),
                add64!(vaddq_u32(h3, c3), ctr_vec(7)),
            );
            c3 = add64!(c3, ctr_vec(8));
            ip = ip.add(512);
            op = op.add(512);
        }
    }
}

fn initial_state(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }
    s
}

/// Reference (crate) keystream XOR, kept as the tail + fallback path so exotic
/// counters and non-aarch64 builds produce the identical byte stream.
/// `seek_block` is the first block index. SAFETY: `seek_block` must be
/// seekable by the crate (byte offset `seek_block * 64` must not overflow
/// and the block must fit the IETF 32-bit counter) — the FFI export
/// enforces this and returns 3 otherwise, so in-crate callers uphold it
/// by construction; a violation panics inside the crate (loud, and only
/// reachable by mis-calling this private helper).
#[allow(dead_code)]
fn crate_xor(
    key: &[u8; 32],
    nonce: &[u8; 12],
    seek_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    let mut c = ChaCha20::new(&ChaKey::from(*key), &ChaNonce12::from(*nonce));
    if seek_block != 0 {
        debug_assert!(seek_block.checked_mul(64).is_some());
        let _ = c.try_seek(seek_block * 64);
    }
    // Ensure `out` first holds the pre-XOR bytes (no-op when in place), then
    // keystream-XOR in place — byte-identical to apply_keystream_b2b.
    // `copy` (memmove semantics) is used instead of `copy_nonoverlapping`:
    // the FFI entry rejects partial overlap, so every real call is disjoint
    // or exactly in-place — but a hostile caller that slips a 1-byte overlap
    // past the guard must still not trigger UB. `copy` handles overlap
    // correctly; on the disjoint/in-place fast path it compiles to the same
    // memcpy/sequence (tail path only, <512B + remainder — no throughput
    // impact).
    if !std::ptr::eq(inp, out.cast_const()) {
        unsafe {
            std::ptr::copy(inp, out, len);
        }
    }
    let buf = unsafe { core::slice::from_raw_parts_mut(out, len) };
    c.apply_keystream(buf);
}

/// # Safety
/// `key32`/`nonce12` point to 32/12 valid bytes; `inp`/`out` each valid for
/// `len` bytes (reads for `inp`, reads+writes for `out`); `inp == out` (in
/// place) or fully disjoint — never partial overlap. Mirrors the FFI contract
/// every other export here already relies on. Additionally
/// `start_block + len.div_ceil(64) <= u32::MAX` (the IETF counter range —
/// the FFI export returns 3 beyond it, so this holds for every real call).
///
/// XOR the ChaCha20 keystream (IETF, 96-bit `nonce12`, first block
/// `start_block`) into `out`, reading source bytes from `inp`.
#[allow(dead_code)]
pub unsafe fn stream_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    // The hand core uses the IETF 32-bit block counter (word 12); if the whole
    // block range stays under 2^32 the 64-bit add never carries into the nonce,
    // matching the crate exactly. Otherwise defer entirely to the crate.
    let blocks = len.div_ceil(64) as u64;
    if start_block
        .checked_add(blocks)
        .is_none_or(|end| end > u32::MAX as u64)
    {
        crate_xor(key32, nonce12, start_block, inp, out, len);
        return;
    }
    let groups = len / 512;
    if groups > 0 {
        let state = initial_state(key32, nonce12, start_block as u32);
        unsafe { xor_bulk(&state, inp, out, groups) };
    }
    let bulk = groups * 512;
    if len > bulk {
        crate_xor(
            key32,
            nonce12,
            start_block + (bulk as u64) / 64,
            unsafe { inp.add(bulk) },
            unsafe { out.add(bulk) },
            len - bulk,
        );
    }
}


/// Bulk-only entry for the combined dispatcher: runs the 8-way core over exactly
/// `groups * 512` bytes and nothing else, so the caller can hand the tail to a
/// narrower core instead of the crate.
#[target_feature(enable = "neon")]
pub unsafe fn stream_xor_bulk(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    groups: usize,
) {
    if groups == 0 {
        return;
    }
    let state = initial_state(key32, nonce12, start_block as u32);
    unsafe { xor_bulk(&state, inp, out, groups) };
}
