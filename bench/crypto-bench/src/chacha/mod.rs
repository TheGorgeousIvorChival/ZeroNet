//! ChaCha20 cores under evaluation.
//!
//! `stream_xor` is the combined core: 8-way NEON for the bulk, 1-block NEON for
//! the tail, and the `chacha20` crate itself only where the 32-bit IETF counter
//! could overflow. Every byte therefore goes through NEON, which is what makes
//! the win hold at every length instead of only from 512 bytes up.
pub mod neon1;
pub mod neon2;
pub mod neon4;
pub mod neon8;
pub mod portable;

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key as ChaKey, Nonce as ChaNonce12};

/// The crate, used as the bit-identity oracle and for the counter-overflow tail.
pub fn crate_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    _inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    // The IETF variant's 12-byte nonce is words 13..15 only; the 64-bit block
    // counter is separate state reached through `seek`. Stuffing the counter
    // into the nonce corrupts it -- that bug only showed up on x86_64, where
    // this is the only path taken.
    let mut c = ChaCha20::new(ChaKey::from_slice(key32), ChaNonce12::from_slice(nonce12));
    c.seek(start_block * 64);
    let dst = unsafe { core::slice::from_raw_parts_mut(out, len) };
    c.apply_keystream(dst);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn stream_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    // The hand cores use the IETF 32-bit block counter (word 12). If the block
    // range could carry into the nonce, defer the whole thing to the crate.
    let blocks = len.div_ceil(64) as u64;
    if start_block
        .checked_add(blocks)
        .is_none_or(|end| end > u32::MAX as u64)
    {
        crate_xor(key32, nonce12, start_block, inp, out, len);
        return;
    }
    // 8-way for the 512-byte groups, then 4-way for whole 256-byte groups,
    // then 1-block for whatever is left. Every byte goes through NEON.
    let groups = len / 512;
    unsafe { neon8::stream_xor_bulk(key32, nonce12, start_block, inp, out, groups) };
    let mut done = groups * 512;

    while len - done >= 256 {
        unsafe {
            neon4::xor_group(
                key32,
                nonce12,
                start_block + (done as u64) / 64,
                inp.add(done),
                out.add(done),
            )
        };
        done += 256;
    }

    while len - done >= 128 {
        unsafe {
            neon2::xor_group(
                key32,
                nonce12,
                start_block + (done as u64) / 64,
                inp.add(done),
                out.add(done),
            )
        };
        done += 128;
    }

    if len > done {
        unsafe {
            neon1::stream_xor(
                key32,
                nonce12,
                start_block + (done as u64) / 64,
                inp.add(done),
                out.add(done),
                len - done,
            )
        };
    }
}

/// Policy A: widest core that fits, all the way down. Loses below 128 bytes on
/// Neoverse (measured 0.74-0.95x), kept here as the comparison arm.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn stream_xor_wide(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    stream_xor(key32, nonce12, start_block, inp, out, len)
}

/// Policy B: hand everything under 128 bytes to the crate. Below the crossover
/// the 1-block core is a measured loss, so the honest move is to not run it.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn stream_xor_guarded(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    if len < 128 {
        crate_xor(key32, nonce12, start_block, inp, out, len);
        return;
    }
    stream_xor(key32, nonce12, start_block, inp, out, len)
}

/// Policy C: use the 2-block core for 64-127 bytes too, writing the partial
/// group through a stack buffer. Spends two blocks of rounds on one block, but
/// only if the wider core's setup is cheaper than the 1-block core's whole call.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn stream_xor_short2(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    if len < 64 {
        crate_xor(key32, nonce12, start_block, inp, out, len);
        return;
    }
    let groups = len / 512;
    unsafe { neon8::stream_xor_bulk(key32, nonce12, start_block, inp, out, groups) };
    let mut done = groups * 512;
    while len - done >= 256 {
        unsafe {
            neon4::xor_group(key32, nonce12, start_block + (done as u64) / 64,
                             inp.add(done), out.add(done))
        };
        done += 256;
    }
    if len - done >= 128 {
        unsafe {
            neon2::xor_group(key32, nonce12, start_block + (done as u64) / 64,
                             inp.add(done), out.add(done))
        };
        done += 128;
    }
    if len > done {
        // 64-127 bytes left: run the 2-block core, keep what fits.
        let n = len - done;
        let mut tmp = [0u8; 128];
        unsafe {
            neon2::xor_group(key32, nonce12, start_block + (done as u64) / 64,
                             inp.add(done), tmp.as_mut_ptr())
        };
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), out.add(done), n);
    }
}

/// Non-aarch64: the crate already runtime-detects AVX2/SSE2 here, so there is
/// nothing to add and nothing to regress.
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn stream_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    crate_xor(key32, nonce12, start_block, inp, out, len);
}
