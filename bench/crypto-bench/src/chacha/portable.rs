//! Portable, fully unrolled ChaCha20 (IETF variant, 20 rounds, 96-bit nonce).
//!
//! Same algorithm as the RustCrypto `chacha20` crate, written so the 20 rounds
//! live in scalar registers: 16 locals instead of an indexed `[u32; 16]`, and
//! the feed-forward add is explicit. No intrinsics, no assembly, no cfg -- so
//! this is the code that runs on every device the crate runs on today.

/// One 64-byte keystream block.
#[inline(always)]
fn block(key: &[u32; 8], nonce: &[u32; 3], ctr: u32, dst: &mut [u8; 64]) {
    let mut x0 = 0x6170_7865u32; let mut x1 = 0x3320_646eu32; let mut x2 = 0x7962_2d32u32;
    let mut x3 = 0x6b20_6574u32;
    let mut x4 = key[0]; let mut x5 = key[1]; let mut x6 = key[2]; let mut x7 = key[3];
    let mut x8 = key[4]; let mut x9 = key[5]; let mut x10 = key[6]; let mut x11 = key[7];
    let mut x12 = ctr;
    let mut x13 = nonce[0]; let mut x14 = nonce[1]; let mut x15 = nonce[2];
    let (i4, i5, i6, i7) = (key[0], key[1], key[2], key[3]);
    let (i8, i9, i10, i11) = (key[4], key[5], key[6], key[7]);
    let (i0, i1, i2, i3) = (x0, x1, x2, x3);
    let (i12, i13, i14, i15) = (x12, x13, x14, x15);

    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(16);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(12);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(8);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(7);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(16);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(12);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(8);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(7);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(16);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(12);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(8);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(7);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(16);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(12);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(8);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(7);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(16);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(12);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(8);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(7);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(16);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(12);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(8);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(7);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(16);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(12);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(8);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(7);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(16);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(12);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(8);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(7);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(16);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(12);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(8);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(7);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(16);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(12);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(8);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(7);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(16);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(12);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(8);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(7);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(16);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(12);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(8);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(7);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(16);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(12);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(8);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(7);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(16);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(12);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(8);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(7);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(16);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(12);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(8);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(7);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(16);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(12);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(8);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(7);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(16);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(12);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(8);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(7);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(16);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(12);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(8);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(7);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(16);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(12);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(8);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(7);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(16);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(12);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(8);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(7);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(16);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(12);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(8);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(7);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(16);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(12);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(8);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(7);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(16);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(12);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(8);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(7);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(16);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(12);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(8);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(7);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(16);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(12);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(8);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(7);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(16);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(12);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(8);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(7);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(16);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(12);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(8);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(7);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(16);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(12);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(8);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(7);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(16);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(12);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(8);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(7);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(16);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(12);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(8);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(7);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(16);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(12);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(8);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(7);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(16);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(12);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(8);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(7);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(16);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(12);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(8);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(7);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(16);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(12);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(8);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(7);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(16);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(12);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(8);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(7);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(16);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(12);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(8);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(7);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(16);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(12);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(8);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(7);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(16);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(12);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(8);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(7);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(16);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(12);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(8);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(7);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(16);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(12);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(8);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(7);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(16);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(12);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(8);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(7);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(16);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(12);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(8);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(7);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(16);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(12);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(8);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(7);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(16);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(12);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(8);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(7);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(16);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(12);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(8);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(7);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(16);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(12);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(8);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(7);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(16);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(12);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(8);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(7);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(16);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(12);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(8);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(7);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(16);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(12);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(8);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(7);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(16);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(12);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(8);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(7);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(16);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(12);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(8);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(7);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(16);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(12);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(8);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(7);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(16);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(12);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(8);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(7);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(16);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(12);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(8);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(7);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(16);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(12);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(8);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(7);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(16);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(12);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(8);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(7);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(16);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(12);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(8);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(7);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(16);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(12);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(8);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(7);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(16);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(12);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(8);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(7);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(16);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(12);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(8);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(7);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(16);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(12);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(8);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(7);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(16);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(12);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(8);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(7);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(16);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(12);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(8);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(7);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(16);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(12);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(8);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(7);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(16);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(12);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(8);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(7);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(16);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(12);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(8);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(7);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(16);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(12);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(8);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(7);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(16);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(12);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(8);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(7);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(16);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(12);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(8);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(7);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(16);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(12);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(8);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(7);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(16);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(12);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(8);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(7);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(16);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(12);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(8);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(7);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(16);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(12);
    x0 = x0.wrapping_add(x4); x12 ^= x0; x12 = x12.rotate_left(8);
    x8 = x8.wrapping_add(x12); x4 ^= x8; x4 = x4.rotate_left(7);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(16);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(12);
    x1 = x1.wrapping_add(x5); x13 ^= x1; x13 = x13.rotate_left(8);
    x9 = x9.wrapping_add(x13); x5 ^= x9; x5 = x5.rotate_left(7);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(16);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(12);
    x2 = x2.wrapping_add(x6); x14 ^= x2; x14 = x14.rotate_left(8);
    x10 = x10.wrapping_add(x14); x6 ^= x10; x6 = x6.rotate_left(7);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(16);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(12);
    x3 = x3.wrapping_add(x7); x15 ^= x3; x15 = x15.rotate_left(8);
    x11 = x11.wrapping_add(x15); x7 ^= x11; x7 = x7.rotate_left(7);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(16);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(12);
    x0 = x0.wrapping_add(x5); x15 ^= x0; x15 = x15.rotate_left(8);
    x10 = x10.wrapping_add(x15); x5 ^= x10; x5 = x5.rotate_left(7);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(16);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(12);
    x1 = x1.wrapping_add(x6); x12 ^= x1; x12 = x12.rotate_left(8);
    x11 = x11.wrapping_add(x12); x6 ^= x11; x6 = x6.rotate_left(7);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(16);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(12);
    x2 = x2.wrapping_add(x7); x13 ^= x2; x13 = x13.rotate_left(8);
    x8 = x8.wrapping_add(x13); x7 ^= x8; x7 = x7.rotate_left(7);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(16);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(12);
    x3 = x3.wrapping_add(x4); x14 ^= x3; x14 = x14.rotate_left(8);
    x9 = x9.wrapping_add(x14); x4 ^= x9; x4 = x4.rotate_left(7);

    x0 = x0.wrapping_add(i0); x1 = x1.wrapping_add(i1); x2 = x2.wrapping_add(i2); x3 = x3.wrapping_add(i3);
    x4 = x4.wrapping_add(i4); x5 = x5.wrapping_add(i5); x6 = x6.wrapping_add(i6); x7 = x7.wrapping_add(i7);
    x8 = x8.wrapping_add(i8); x9 = x9.wrapping_add(i9); x10 = x10.wrapping_add(i10); x11 = x11.wrapping_add(i11);
    x12 = x12.wrapping_add(i12); x13 = x13.wrapping_add(i13); x14 = x14.wrapping_add(i14); x15 = x15.wrapping_add(i15);

    let s = [x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15];
    for (i, &w) in s.iter().enumerate() {
        dst[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
}

/// `inp` and `out` may alias exactly. `start` is the block counter.
pub fn stream_xor(key: &[u8; 32], nonce: &[u8; 12], start: u64, inp: &[u8], out: &mut [u8], len: usize) {
    let key: [u32; 8] = std::array::from_fn(|i| u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap()));
    let nonce: [u32; 3] = std::array::from_fn(|i| u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap()));
    let mut ks = [0u8; 64];
    for off in (0..len).step_by(64) {
        let n = core::cmp::min(64, len - off);
        block(&key, &nonce, (start + (off / 64) as u64) as u32, &mut ks);
        for i in 0..n { out[off + i] = inp[off + i] ^ ks[i]; }
    }
}

/// The same thing over raw pointers, so the dispatcher can hand this core an
/// `inp == out` in-place buffer. Slices cannot: a `&[u8]` and a `&mut [u8]` over
/// one allocation are a stacked-borrows violation even when every access through
/// them is read-before-write.
#[inline]
pub unsafe fn stream_xor_raw(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u64,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) {
    let k: [u32; 8] = std::array::from_fn(|i| u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap()));
    let n: [u32; 3] = std::array::from_fn(|i| u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap()));
    let mut ks = [0u8; 64];
    let mut off = 0usize;
    while off < len {
        let c = core::cmp::min(64, len - off);
        block(&k, &n, (start + (off / 64) as u64) as u32, &mut ks);
        for i in 0..c { *out.add(off + i) = *inp.add(off + i) ^ ks[i]; }
        off += c;
    }
}
