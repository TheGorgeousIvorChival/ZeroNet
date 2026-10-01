//! ChaCha20 cores under evaluation.
//!
//! `stream_xor` is the combined core and the policy this branch would ship: a
//! descending ladder of block widths -- 8, 4, 2, 1 -- where a rung is only
//! taken when the number of blocks *still to produce* is at least that wide.
//! Nothing is ever computed and thrown away, so no length pays for blocks it
//! did not ask for, and the narrow end of the ladder is a real one-block core
//! rather than a fallback to the crate.
//!
//! That is the no-loss argument, and it is worth stating plainly because it is
//! not a micro-optimisation. The pinned `chacha20` crate fills its keystream
//! buffer a whole four-block refill at a time -- `ParBlocksSize = U4` on every
//! backend it ships, including the aarch64 one, which it gates behind
//! `chacha20_force_neon` and ZeroNet never sets. So a 16-byte message costs
//! the crate four blocks of twenty rounds. Every length below 192 bytes is won
//! on work reduction alone, before any question of which instructions are
//! issued, and the wide rungs only take over once there is enough work to fill
//! them. On aarch64 the crate's own portable backend then measures 6.9
//! cycles/byte, which is what the 8-block core's 2.6 is measured against.
pub mod avx2;
pub mod neon1;
pub mod neon2;
pub mod neon4;
pub mod neon8;
pub mod portable;
pub mod sse1;

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key as ChaKey, Nonce as ChaNonce12};

/// `"expand 32-byte k"`.
pub const CONSTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The 16-word IETF state. Built once per call by every core here; only word
/// 12 moves as the block counter advances, so the constants and the key stay
/// in registers.
#[inline(always)]
pub fn initial_state(key32: &[u8; 32], nonce12: &[u8; 12], ctr: u32) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[0] = CONSTS[0];
    s[1] = CONSTS[1];
    s[2] = CONSTS[2];
    s[3] = CONSTS[3];
    s[4] = u32::from_le_bytes([key32[0], key32[1], key32[2], key32[3]]);
    s[5] = u32::from_le_bytes([key32[4], key32[5], key32[6], key32[7]]);
    s[6] = u32::from_le_bytes([key32[8], key32[9], key32[10], key32[11]]);
    s[7] = u32::from_le_bytes([key32[12], key32[13], key32[14], key32[15]]);
    s[8] = u32::from_le_bytes([key32[16], key32[17], key32[18], key32[19]]);
    s[9] = u32::from_le_bytes([key32[20], key32[21], key32[22], key32[23]]);
    s[10] = u32::from_le_bytes([key32[24], key32[25], key32[26], key32[27]]);
    s[11] = u32::from_le_bytes([key32[28], key32[29], key32[30], key32[31]]);
    s[12] = ctr;
    s[13] = u32::from_le_bytes([nonce12[0], nonce12[1], nonce12[2], nonce12[3]]);
    s[14] = u32::from_le_bytes([nonce12[4], nonce12[5], nonce12[6], nonce12[7]]);
    s[15] = u32::from_le_bytes([nonce12[8], nonce12[9], nonce12[10], nonce12[11]]);
    s
}

/// The crate, used as the bit-identity oracle and for the one case the hand
/// cores cannot represent: a block counter that would carry into the nonce.
#[inline]
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
    // this used to be the only path taken.
    let mut c = ChaCha20::new(ChaKey::from_slice(key32), ChaNonce12::from_slice(nonce12));
    c.seek(start_block * 64);
    let dst = unsafe { core::slice::from_raw_parts_mut(out, len) };
    c.apply_keystream(dst);
}

/// The hand cores keep the counter in word 12, which is 32 bits. If this
/// message's block range could carry into the nonce, defer all of it to the
/// crate, which holds a 64-bit counter.
#[inline(always)]
fn counter_overflows(start_block: u64, len: usize) -> bool {
    let blocks = len.div_ceil(64) as u64;
    start_block
        .checked_add(blocks)
        .is_none_or(|end| end > u32::MAX as u64)
}

/// The first block index for the group that starts at byte `done`.
#[inline(always)]
fn blk(start_block: u64, done: usize) -> u64 {
    start_block + (done as u64) / 64
}

// ------------------------------------------------- which one-block core wins

/// 0 = not measured yet, 1 = SIMD, 2 = scalar.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
static ONE_BLOCK: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Which one-block core this CPU prefers, measured once and then remembered.
///
/// One ChaCha block is twenty rounds of quarter round and every round depends on
/// the one before it, so a single block has no instruction-level parallelism to
/// exploit. The only question is which instruction set reaches the end of that
/// dependency chain first, and that is a property of the microarchitecture, not
/// of the ISA. Measured on this branch, same code, same `-Os` profile:
///
///   * Apple silicon: the SIMD core wins, ~1.11x over the scalar one. Firestorm
///     has the issue slots to run the row rotations without costing the chain
///     anything, so four lanes cost the same latency as one.
///   * Neoverse N1: the scalar core wins, ~1.6x. `vextq_u32` and `vqtbl1q_u8`
///     sit between every pair of rounds, on the critical path, and N1 has no
///     second vector pipe to overlap them with. SIMD one block measured 0.66x
///     against the crate there; the scalar core measured 1.02-1.10x.
///
/// Nothing in CPUID distinguishes those two, and ZeroNet ships aarch64 servers,
/// aarch64 phones and x86_64 desktops, so the dispatcher measures both once
/// rather than guessing. This is the one place in the branch that decides
/// anything at runtime instead of at build time, and it is bounded: one
/// comparison per process, tens of microseconds, then a single relaxed atomic
/// load per call.
///
/// A tie within 5% goes to the scalar core, because it is the architecture
/// neutral one and its worst case measured here is 0.95x where the SIMD core's
/// is 0.66x. Being wrong is a performance bug and never a correctness one: both
/// cores are byte-identical to the crate across every shape the gate covers, and
/// the gate in `main.rs` runs against whichever one this picked.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[inline]
fn simd_one_block() -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    match ONE_BLOCK.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let v = if calibrate_simd() { 1 } else { 2 };
    ONE_BLOCK.store(v, Relaxed);
    v == 1
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn calibrate_simd() -> bool {
    use std::time::Instant;
    const REPS: usize = 3;
    const N: usize = 128;
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let src = [7u8; 64];
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    let (mut ts, mut tp) = (f64::MAX, f64::MAX);
    for _ in 0..REPS {
        let t = Instant::now();
        for _ in 0..N {
            unsafe { narrow(&key, &nonce, 0, src.as_ptr(), a.as_mut_ptr(), 64) };
        }
        ts = ts.min(t.elapsed().as_secs_f64());
        let t = Instant::now();
        for _ in 0..N {
            unsafe { portable::stream_xor_raw(&key, &nonce, 0, src.as_ptr(), b.as_mut_ptr(), 64) };
        }
        tp = tp.min(t.elapsed().as_secs_f64());
    }
    // SIMD has to be at least 5% ahead to be worth depending on a measurement.
    ts * 1.05 < tp
}

/// What the calibration decided, for the report.
pub fn one_block_choice() -> &'static str {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    {
        // Force the decision so the report states what the bench actually ran.
        let _ = simd_one_block();
        if simd_one_block() {
            "SIMD"
        } else {
            "scalar"
        }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        "n/a (no SIMD core here)"
    }
}

/// The narrowest rung, through whichever core this CPU measured as faster.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
unsafe fn one_block(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    if simd_one_block() {
        unsafe { narrow(key32, nonce12, start_block, inp, out, len) }
    } else {
        unsafe { portable::stream_xor_raw(key32, nonce12, start_block, inp, out, len) }
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
unsafe fn one_block(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    crate_xor(key32, nonce12, start_block, inp, out, len);
}

// ------------------------------------------------------------------ aarch64

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
    if counter_overflows(start_block, len) {
        crate_xor(key32, nonce12, start_block, inp, out, len);
        return;
    }
    // 512-byte groups, hoisted out because it is the only rung that can repeat
    // many times. Sized in bytes, not blocks: 500 bytes is 8 blocks but it is
    // not a 512-byte group, and the rung writes its whole group.
    let groups = len / 512;
    let mut done = 0usize;
    if groups > 0 {
        unsafe { neon8::stream_xor_bulk(key32, nonce12, start_block, inp, out, groups) };
        done = groups * 512;
    }
    // 256, then 128, then 1. Widest rung whose block count still fits, so a
    // message is never padded out to a wider core than it needs and never
    // split narrower than it has to. Every rung writes exactly the bytes it is
    // given, so a message ending mid-group needs no stack buffer and no copy --
    // and, more importantly, the core never reads a byte past the end of the
    // message to produce one.
    loop {
        let rem = len - done;
        if rem == 0 {
            return;
        }
        let blocks = rem.div_ceil(64);
        if blocks >= 4 {
            let n = rem.min(256);
            unsafe { neon4::xor_group(key32, nonce12, blk(start_block, done), inp.add(done), out.add(done), n) };
            done += n;
        } else if blocks >= 2 {
            let n = rem.min(128);
            unsafe { neon2::xor_group(key32, nonce12, blk(start_block, done), inp.add(done), out.add(done), n) };
            done += n;
        } else {
            // One block, whole or partial. Either one-block core writes a short
            // block straight out, with no buffer.
            unsafe { one_block(key32, nonce12, blk(start_block, done), inp.add(done), out.add(done), rem) };
            return;
        }
    }
}

// ------------------------------------------------------------------- x86_64

#[cfg(target_arch = "x86_64")]
pub unsafe fn stream_xor(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    if counter_overflows(start_block, len) {
        crate_xor(key32, nonce12, start_block, inp, out, len);
        return;
    }
    if std::arch::is_x86_feature_detected!("avx2") {
        unsafe { stream_xor_avx2(key32, nonce12, start_block, inp, out, len) }
    } else {
        // No AVX2 on this CPU, so the ladder collapses to its narrowest rung.
        // That is still a win below 192 bytes, for the same reason the wide end
        // is: one block of rounds instead of the crate's four.
        unsafe { sse1::stream_xor(key32, nonce12, start_block, inp, out, len) }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn stream_xor_avx2(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    let groups = len / 512;
    let mut done = 0usize;
    for g in 0..groups {
        unsafe { avx2::xor8(key32, nonce12, blk(start_block, g * 512), inp.add(g * 512), out.add(g * 512)) };
    }
    done = groups * 512;
    loop {
        let rem = len - done;
        if rem == 0 {
            return;
        }
        let blocks = rem.div_ceil(64);
        if blocks >= 4 {
            let n = rem.min(256);
            unsafe { avx2::xor4(key32, nonce12, blk(start_block, done), inp.add(done), out.add(done), n) };
            done += n;
        } else if blocks >= 2 {
            let n = rem.min(128);
            unsafe { avx2::xor2(key32, nonce12, blk(start_block, done), inp.add(done), out.add(done), n) };
            done += n;
        } else {
            unsafe { one_block(key32, nonce12, blk(start_block, done), inp.add(done), out.add(done), rem) };
            return;
        }
    }
}

// ------------------------------------------------------- everything else

/// Nothing to add on an ISA with no hand core: the crate already runtime
/// detects whatever the CPU has, so this is a delegation and cannot regress.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
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

// ------------------------------------------------------------- comparisons

/// The previous policy, kept as the comparison arm: the widest core that fits,
/// all the way down, with everything under 512 bytes left to the one-block
/// core. It measured 0.74-0.96x against the crate below 128 bytes, which is
/// the loss the ladder was built to remove.
pub unsafe fn stream_xor_wide(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    if counter_overflows(start_block, len) {
        crate_xor(key32, nonce12, start_block, inp, out, len);
        return;
    }
    let groups = len / 512;
    if groups > 0 {
        wide_bulk(key32, nonce12, start_block, inp, out, groups);
    }
    let done = groups * 512;
    if done < len {
        narrow(key32, nonce12, blk(start_block, done), inp.add(done), out.add(done), len - done);
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn wide_bulk(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    groups: usize,
) {
    unsafe { neon8::stream_xor_bulk(key32, nonce12, start_block, inp, out, groups) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn wide_bulk(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    groups: usize,
) {
    // Not `#[target_feature]` on this function: a compiler is entitled to emit
    // AVX2 in the prologue of one that has it, and the whole point of the
    // check is that this CPU might not have it. The detection therefore has to
    // live outside the feature-gated body.
    if std::arch::is_x86_feature_detected!("avx2") {
        unsafe { wide_bulk_avx2(key32, nonce12, start_block, inp, out, groups) };
    } else {
        for g in 0..groups {
            for b in 0..8 {
                let off = g * 512 + b * 64;
                unsafe { sse1::stream_xor(key32, nonce12, blk(start_block, off), inp.add(off), out.add(off), 64) };
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn wide_bulk_avx2(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    groups: usize,
) {
    for g in 0..groups {
        unsafe { avx2::xor8(key32, nonce12, blk(start_block, g * 512), inp.add(g * 512), out.add(g * 512)) };
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
unsafe fn wide_bulk(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    groups: usize,
) {
    for g in 0..groups {
        for b in 0..8 {
            let off = g * 512 + b * 64;
            crate_xor(key32, nonce12, blk(start_block, off), inp.add(off), out.add(off), 64);
        }
    }
}

/// The narrowest rung alone, for every byte. Isolates how much of the small-size
/// win is just "compute the blocks you were asked for" and how much is the
/// instruction choice inside the round core.
pub unsafe fn stream_xor_narrow(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    if counter_overflows(start_block, len) {
        crate_xor(key32, nonce12, start_block, inp, out, len);
        return;
    }
    narrow(key32, nonce12, start_block, inp, out, len)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn narrow(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    unsafe { neon1::stream_xor(key32, nonce12, start_block, inp, out, len) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn narrow(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    unsafe { sse1::stream_xor(key32, nonce12, start_block, inp, out, len) }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
unsafe fn narrow(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    start_block: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    crate_xor(key32, nonce12, start_block, inp, out, len);
}
