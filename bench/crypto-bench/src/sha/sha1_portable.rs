//! Portable SHA-1 (FIPS 180-1) core. No intrinsics, no assembly, no `cfg`, so
//! this is the code that runs on every device -- it is both the fallback and
//! the differential-test oracle for the hardware cores.
//!
//! Two deliberate differences from the RustCrypto `sha1` crate's soft backend,
//! both aimed at the short-message case ZeroNet actually hashes (the WebSocket
//! handshake digests 55 bytes; HKDF digests 32):
//!   * a 16-word rolling schedule with constant indices instead of an 80-word
//!     array, so the schedule stays in registers rather than touching 320 bytes
//!     of stack per block;
//!   * `digest` pads and compresses in place, so a one-block input is never
//!     copied through a `BlockBuffer` on the way in.

/// Compress one 64-byte block into a 5-word chaining state.
#[inline(always)]
fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let blk = block;
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    let mut w = [0u32; 16];
    w[0] = u32::from_be_bytes([blk[0], blk[1], blk[2], blk[3]]);
    w[1] = u32::from_be_bytes([blk[4], blk[5], blk[6], blk[7]]);
    w[2] = u32::from_be_bytes([blk[8], blk[9], blk[10], blk[11]]);
    w[3] = u32::from_be_bytes([blk[12], blk[13], blk[14], blk[15]]);
    w[4] = u32::from_be_bytes([blk[16], blk[17], blk[18], blk[19]]);
    w[5] = u32::from_be_bytes([blk[20], blk[21], blk[22], blk[23]]);
    w[6] = u32::from_be_bytes([blk[24], blk[25], blk[26], blk[27]]);
    w[7] = u32::from_be_bytes([blk[28], blk[29], blk[30], blk[31]]);
    w[8] = u32::from_be_bytes([blk[32], blk[33], blk[34], blk[35]]);
    w[9] = u32::from_be_bytes([blk[36], blk[37], blk[38], blk[39]]);
    w[10] = u32::from_be_bytes([blk[40], blk[41], blk[42], blk[43]]);
    w[11] = u32::from_be_bytes([blk[44], blk[45], blk[46], blk[47]]);
    w[12] = u32::from_be_bytes([blk[48], blk[49], blk[50], blk[51]]);
    w[13] = u32::from_be_bytes([blk[52], blk[53], blk[54], blk[55]]);
    w[14] = u32::from_be_bytes([blk[56], blk[57], blk[58], blk[59]]);
    w[15] = u32::from_be_bytes([blk[60], blk[61], blk[62], blk[63]]);
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[0]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[1]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[2]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[3]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[4]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[5]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[6]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[7]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[8]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[9]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[10]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[11]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[12]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[13]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[14]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[15]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[0] = (w[13] ^ w[8] ^ w[2] ^ w[0]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[0]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[1] = (w[14] ^ w[9] ^ w[3] ^ w[1]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[1]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[2] = (w[15] ^ w[10] ^ w[4] ^ w[2]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[2]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[3] = (w[0] ^ w[11] ^ w[5] ^ w[3]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | ((!b) & d)).wrapping_add(e).wrapping_add(0x5A82_7999).wrapping_add(w[3]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[4] = (w[1] ^ w[12] ^ w[6] ^ w[4]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[4]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[5] = (w[2] ^ w[13] ^ w[7] ^ w[5]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[5]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[6] = (w[3] ^ w[14] ^ w[8] ^ w[6]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[6]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[7] = (w[4] ^ w[15] ^ w[9] ^ w[7]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[7]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[8] = (w[5] ^ w[0] ^ w[10] ^ w[8]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[8]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[9] = (w[6] ^ w[1] ^ w[11] ^ w[9]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[9]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[10] = (w[7] ^ w[2] ^ w[12] ^ w[10]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[10]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[11] = (w[8] ^ w[3] ^ w[13] ^ w[11]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[11]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[12] = (w[9] ^ w[4] ^ w[14] ^ w[12]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[12]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[13] = (w[10] ^ w[5] ^ w[15] ^ w[13]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[13]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[14] = (w[11] ^ w[6] ^ w[0] ^ w[14]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[14]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[15] = (w[12] ^ w[7] ^ w[1] ^ w[15]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[15]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[0] = (w[13] ^ w[8] ^ w[2] ^ w[0]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[0]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[1] = (w[14] ^ w[9] ^ w[3] ^ w[1]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[1]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[2] = (w[15] ^ w[10] ^ w[4] ^ w[2]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[2]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[3] = (w[0] ^ w[11] ^ w[5] ^ w[3]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[3]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[4] = (w[1] ^ w[12] ^ w[6] ^ w[4]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[4]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[5] = (w[2] ^ w[13] ^ w[7] ^ w[5]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[5]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[6] = (w[3] ^ w[14] ^ w[8] ^ w[6]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[6]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[7] = (w[4] ^ w[15] ^ w[9] ^ w[7]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0x6ED9_EBA1).wrapping_add(w[7]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[8] = (w[5] ^ w[0] ^ w[10] ^ w[8]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[8]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[9] = (w[6] ^ w[1] ^ w[11] ^ w[9]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[9]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[10] = (w[7] ^ w[2] ^ w[12] ^ w[10]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[10]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[11] = (w[8] ^ w[3] ^ w[13] ^ w[11]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[11]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[12] = (w[9] ^ w[4] ^ w[14] ^ w[12]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[12]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[13] = (w[10] ^ w[5] ^ w[15] ^ w[13]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[13]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[14] = (w[11] ^ w[6] ^ w[0] ^ w[14]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[14]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[15] = (w[12] ^ w[7] ^ w[1] ^ w[15]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[15]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[0] = (w[13] ^ w[8] ^ w[2] ^ w[0]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[0]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[1] = (w[14] ^ w[9] ^ w[3] ^ w[1]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[1]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[2] = (w[15] ^ w[10] ^ w[4] ^ w[2]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[2]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[3] = (w[0] ^ w[11] ^ w[5] ^ w[3]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[3]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[4] = (w[1] ^ w[12] ^ w[6] ^ w[4]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[4]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[5] = (w[2] ^ w[13] ^ w[7] ^ w[5]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[5]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[6] = (w[3] ^ w[14] ^ w[8] ^ w[6]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[6]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[7] = (w[4] ^ w[15] ^ w[9] ^ w[7]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[7]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[8] = (w[5] ^ w[0] ^ w[10] ^ w[8]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[8]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[9] = (w[6] ^ w[1] ^ w[11] ^ w[9]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[9]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[10] = (w[7] ^ w[2] ^ w[12] ^ w[10]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[10]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[11] = (w[8] ^ w[3] ^ w[13] ^ w[11]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add((b & c) | (b & d) | (c & d)).wrapping_add(e).wrapping_add(0x8F1B_BCDC).wrapping_add(w[11]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[12] = (w[9] ^ w[4] ^ w[14] ^ w[12]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[12]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[13] = (w[10] ^ w[5] ^ w[15] ^ w[13]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[13]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[14] = (w[11] ^ w[6] ^ w[0] ^ w[14]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[14]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[15] = (w[12] ^ w[7] ^ w[1] ^ w[15]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[15]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[0] = (w[13] ^ w[8] ^ w[2] ^ w[0]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[0]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[1] = (w[14] ^ w[9] ^ w[3] ^ w[1]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[1]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[2] = (w[15] ^ w[10] ^ w[4] ^ w[2]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[2]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[3] = (w[0] ^ w[11] ^ w[5] ^ w[3]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[3]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[4] = (w[1] ^ w[12] ^ w[6] ^ w[4]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[4]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[5] = (w[2] ^ w[13] ^ w[7] ^ w[5]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[5]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[6] = (w[3] ^ w[14] ^ w[8] ^ w[6]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[6]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[7] = (w[4] ^ w[15] ^ w[9] ^ w[7]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[7]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[8] = (w[5] ^ w[0] ^ w[10] ^ w[8]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[8]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[9] = (w[6] ^ w[1] ^ w[11] ^ w[9]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[9]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[10] = (w[7] ^ w[2] ^ w[12] ^ w[10]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[10]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[11] = (w[8] ^ w[3] ^ w[13] ^ w[11]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[11]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[12] = (w[9] ^ w[4] ^ w[14] ^ w[12]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[12]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[13] = (w[10] ^ w[5] ^ w[15] ^ w[13]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[13]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[14] = (w[11] ^ w[6] ^ w[0] ^ w[14]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[14]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    w[15] = (w[12] ^ w[7] ^ w[1] ^ w[15]).rotate_left(1);
    let t = a.rotate_left(5).wrapping_add(b ^ c ^ d).wrapping_add(e).wrapping_add(0xCA62_C1D6).wrapping_add(w[15]);
    e = d; d = c; c = b.rotate_left(30); b = a; a = t;
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[inline(always)]
fn compress_run(state: &mut [u32; 5], mut data: &[u8]) {
    while data.len() >= 64 {
        compress(state, data[..64].try_into().unwrap());
        data = &data[64..];
    }
}

/// One-shot SHA-1. Never copies the message.
pub fn digest(msg: &[u8]) -> [u8; 20] {
    let mut state = [0x6745_2301u32, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bitlen = (msg.len() as u64).wrapping_mul(8);

    let whole = msg.len() & !63;
    compress_run(&mut state, &msg[..whole]);

    let rest = &msg[whole..];
    let mut last = [0u8; 128];
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] = 0x80;
    let end = if rest.len() + 1 + 8 <= 64 { 64 } else { 128 };
    last[end - 8..end].copy_from_slice(&bitlen.to_be_bytes());
    compress_run(&mut state, &last[..end]);

    let mut out = [0u8; 20];
    for (i, w) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}
