//! ChaCha20 cores under evaluation.
//!
//! `stream_xor` is the combined core: 8-way NEON for the bulk, 1-block NEON for
//! the tail, and the `chacha20` crate itself only where the 32-bit IETF counter
//! could overflow. Every byte therefore goes through NEON, which is what makes
//! the win hold at every length instead of only from 512 bytes up.
pub mod neon1;
pub mod neon8;
pub mod portable;

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key as ChaKey, Nonce as ChaNonce12};

/// The crate, used as the bit-identity oracle and for the counter-overflow tail.
pub fn crate_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce12);
    nonce[4..8].copy_from_slice(&((start_block & 0xffff_ffff) as u32).to_le_bytes());
    nonce[8..12].copy_from_slice(&((start_block >> 32) as u32).to_le_bytes());
    let mut c = ChaCha20::new(ChaKey::from_slice(key32), ChaNonce12::from_slice(&nonce));
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
    let groups = len / 512;
    unsafe { neon8::stream_xor_bulk(key32, nonce12, start_block, inp, out, groups) };
    let bulk = groups * 512;
    if len > bulk {
        unsafe {
            neon1::stream_xor(
                key32,
                nonce12,
                start_block + (bulk as u64) / 64,
                inp.add(bulk),
                out.add(bulk),
                len - bulk,
            )
        };
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
