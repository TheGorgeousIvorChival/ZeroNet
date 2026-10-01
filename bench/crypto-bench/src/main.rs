//! Cross-device benchmark + bit-identity gate for the ChaCha20 / SHA cores
//! proposed for ZeroNet.
//!
//! Two rules this harness enforces, because both mistakes have already shown up
//! in this work:
//!   1. Nothing is reported until it is byte-identical to the crate ZeroNet
//!      resolves today. A fast wrong answer is worth nothing.
//!   2. Candidates are timed round-robin inside one repetition and each keeps
//!      its own best, so clock and thermal drift cannot favour whichever
//!      candidate happened to run first. Timing them in sequence produced
//!      ±30% swings between runs of the same code.

mod chacha;
mod sha;

use std::fmt::Write as _;
use std::time::Instant;

use digest::Digest;
use chacha20::ChaCha20;

// ---------------------------------------------------------------- device info

fn device() -> String {
    let mut s = String::new();
    let arch = std::env::consts::ARCH;
    let _ = write!(s, "`{arch}`");
    #[cfg(target_arch = "aarch64")]
    {
        let neon = std::arch::is_aarch64_feature_detected!("neon");
        let sha2 = std::arch::is_aarch64_feature_detected!("sha2");
        let _ = write!(s, " neon={neon} sha2={sha2}");
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let sse2 = is_x86_feature_detected!("sse2");
        let avx2 = is_x86_feature_detected!("avx2");
        let sha = is_x86_feature_detected!("sha");
        let ssse3 = is_x86_feature_detected!("ssse3");
        let sse41 = is_x86_feature_detected!("sse4.1");
        let _ = write!(
            s,
            " sse2={sse2} ssse3={ssse3} sse4.1={sse41} avx2={avx2} sha-ni={sha}"
        );
    }
    s
}

// ------------------------------------------------------------------- harness

/// Round-robin the candidates inside one repetition, then keep each one's best.
fn bench_all(iters: u64, fs: &mut [&mut dyn FnMut()]) -> Vec<f64> {
    for f in fs.iter_mut() {
        for _ in 0..(iters / 10).max(1) {
            f();
        }
    }
    let mut best = vec![f64::MAX; fs.len()];
    for _ in 0..21 {
        for (i, f) in fs.iter_mut().enumerate() {
            let t = Instant::now();
            for _ in 0..iters {
                f();
            }
            let ns = t.elapsed().as_secs_f64() * 1e9 / iters as f64;
            if ns < best[i] {
                best[i] = ns;
            }
        }
    }
    best
}

fn iters_for(n: usize) -> u64 {
    (64 * 1024 * 1024 / n.max(1) as u64).clamp(30, 20_000)
}

// ------------------------------------------------------------------- chacha20

const LENS: &[usize] = &[
    16, 32, 63, 64, 65, 128, 192, 256, 320, 448, 512, 576, 1024, 4096, 16384, 65536,
];

fn verify_chacha(key: &[u8; 32], nonce: &[u8; 12]) -> usize {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    let mut shapes = 0;
    let lengths: Vec<usize> = LENS
        .iter()
        .copied()
        .chain([0, 1, 3, 15, 17, 31, 33, 127, 191, 255, 257, 447, 511, 513, 575, 1023, 1025, 8191, 16640])
        .collect();
    for start in [0u64, 1, 2, 7, 64, 65_535] {
        for len in &lengths {
            let inp: Vec<u8> = (0..*len).map(|i| (i % 251) as u8).collect();
            let mut want = inp.clone();
            let mut c = ChaCha20::new(key.into(), nonce.into());
            c.seek(start * 64);
            c.apply_keystream(&mut want);

            let mut got = inp.clone();
            unsafe {
                chacha::stream_xor(
                    key,
                    nonce,
                    start,
                    inp.as_ptr(),
                    got.as_mut_ptr(),
                    *len,
                )
            };
            assert_eq!(want, got, "combined core differs: start {start} len {len}");

            let mut p = inp.clone();
            chacha::portable::stream_xor(key, nonce, start, &inp, &mut p, *len);
            assert_eq!(want, p, "portable core differs: start {start} len {len}");
            shapes += 1;
        }
    }
    shapes
}

fn bench_chacha(out: &mut String, key: &[u8; 32], nonce: &[u8; 12]) {
    use cipher::{KeyIvInit, StreamCipher};
    let mut rows = Vec::new();
    for &len in LENS {
        let inp: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut o_base = vec![0u8; len];
        let mut o_new = vec![0u8; len];
        let iters = iters_for(len);

        let mut v0 = || {
            let mut c = ChaCha20::new(key.into(), nonce.into());
            c.apply_keystream(std::hint::black_box(&mut o_base));
        };
        let mut v1 = || unsafe {
            chacha::stream_xor(key, nonce, 0, inp.as_ptr(), o_new.as_mut_ptr(), len)
        };
        let r = bench_all(iters, &mut [&mut v0, &mut v1]);
        rows.push((len, r[0], r[1], r[0] / r[1]));
    }

    let _ = writeln!(out, "### ChaCha20 keystream\n");
    let _ = writeln!(out, "| len | crate `chacha20` 0.9.1 | proposed core | speedup |");
    let _ = writeln!(out, "|---:|---:|---:|---:|");
    for (len, b, n, sp) in &rows {
        let _ = writeln!(out, "| {len} | {b:.0} ns | {n:.0} ns | **{sp:.2}x** |");
    }
    let _ = writeln!(out);
    println!("### ChaCha20 keystream\n");
    println!("| len | crate 0.9.1 | proposed | speedup |");
    println!("|---:|---:|---:|---:|");
    for (len, b, n, sp) in &rows {
        println!("| {len} | {b:.0} ns | {n:.0} ns | **{sp:.2}x** |");
    }
    println!();
}

// ------------------------------------------------------------------ sha-1/256

fn verify_sha1() -> usize {
    let mut n = 0;
    for len in [0usize, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000, 4096, 65_536] {
        let msg: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let want = sha1::Sha1::digest(&msg);
        let got = sha::sha1_portable::digest(&msg);
        assert_eq!(want[..], got[..], "sha1 portable differs at len {len}");
        n += 1;
    }
    n
}

fn verify_sha256() -> usize {
    let mut n = 0;
    for len in [0usize, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000, 4096, 65_536] {
        let msg: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let want = sha2::Sha256::digest(&msg);
        let got = sha::sha256_portable::digest(&msg);
        assert_eq!(want[..], got[..], "sha256 portable differs at len {len}");

        // sha2 0.11 must agree with the 0.10 ZeroNet pins.
        {
            use digest_011::Digest as _;
            let v11 = sha2_011::Sha256::digest(&msg);
            assert_eq!(want[..], v11[..], "sha2 0.10 and 0.11 differ at len {len}");
        }
        n += 1;
    }
    n
}

fn bench_sha(out: &mut String) {
    let sizes: &[usize] = &[0, 1, 55, 64, 65, 128, 1024, 4096, 65_536];

    // --- SHA-1: the WebSocket handshake digests exactly 55 bytes ---
    let mut r1 = Vec::new();
    for &len in sizes {
        let msg: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let it = iters_for(len + 20);
        let mut a = || {
            std::hint::black_box(sha1::Sha1::digest(std::hint::black_box(&msg)));
        };
        let mut b = || {
            std::hint::black_box(sha::sha1_portable::digest(std::hint::black_box(&msg)));
        };
        let r = bench_all(it, &mut [&mut a, &mut b]);
        r1.push((len, r[0], r[1], r[0] / r[1]));
    }

    // --- SHA-256: the VMess KDF runs sixteen short digests per handshake ---
    let mut r2 = Vec::new();
    for &len in sizes {
        let msg: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let it = iters_for(len + 20);
        let mut a = || {
            std::hint::black_box(sha2::Sha256::digest(std::hint::black_box(&msg)));
        };
        let mut b = || {
            std::hint::black_box(sha::sha256_portable::digest(std::hint::black_box(&msg)));
        };
        let mut c = {
            use digest_011::Digest as _;
            || {
                std::hint::black_box(sha2_011::Sha256::digest(std::hint::black_box(&msg)));
            }
        };
        let r = bench_all(it, &mut [&mut a, &mut b, &mut c]);
        r2.push((len, r[0], r[1], r[0] / r[1], r[2], r[0] / r[2]));
    }

    let _ = writeln!(out, "### SHA-1\n");
    let _ = writeln!(out, "| len | `sha1` 0.10 crate | portable core | speedup |");
    let _ = writeln!(out, "|---:|---:|---:|---:|");
    for (len, b, n, sp) in &r1 {
        let _ = writeln!(out, "| {len} | {b:.0} ns | {n:.0} ns | **{sp:.2}x** |");
    }
    let _ = writeln!(out, "\n### SHA-256\n");
    let _ = writeln!(
        out,
        "| len | `sha2` 0.10 (ZeroNet's pin) | portable core | speedup | `sha2` 0.11 (hw) | speedup |"
    );
    let _ = writeln!(out, "|---:|---:|---:|---:|---:|---:|");
    for (len, a, b, sp, c, sp2) in &r2 {
        let _ = writeln!(
            out,
            "| {len} | {a:.0} ns | {b:.0} ns | **{sp:.2}x** | {c:.0} ns | **{sp2:.2}x** |"
        );
    }
    let _ = writeln!(out);
    println!("### SHA-1\n");
    println!("| len | sha1 crate | portable | speedup |");
    println!("|---:|---:|---:|---:|");
    for (len, b, n, sp) in &r1 {
        println!("| {len} | {b:.0} ns | {n:.0} ns | **{sp:.2}x** |");
    }
    println!("\n### SHA-256\n");
    println!("| len | sha2 0.10 | portable | speedup | sha2 0.11 | speedup |");
    println!("|---:|---:|---:|---:|---:|---:|");
    for (len, a, b, sp, c, sp2) in &r2 {
        println!("| {len} | {a:.0} ns | {b:.0} ns | **{sp:.2}x** | {c:.0} ns | **{sp2:.2}x** |");
    }
}

// -------------------------------------------------------------------- driver

fn main() {
    let key = [9u8; 32];
    let nonce = [4u8; 12];

    println!("# crypto bench on {}", device());
    println!();

    // The gate. Any mismatch panics and the CI job fails.
    let c = verify_chacha(&key, &nonce);
    let s1 = verify_sha1();
    let s2 = verify_sha256();
    println!("bit-identity gate passed: chacha {c} shapes, sha1 {s1} sizes, sha256 {s2} sizes\n");

    let mut md = String::new();
    let _ = writeln!(md, "# crypto bench on {}\n", device());
    let _ = writeln!(
        md,
        "Bit-identity gate passed: chacha {c} shapes, sha1 {s1} sizes, sha256 {s2} sizes.\n"
    );
    bench_chacha(&mut md, &key, &nonce);
    bench_sha(&mut md);

    if let Ok(path) = std::env::var("CRYPTO_BENCH_OUT") {
        std::fs::write(&path, &md).expect("write report");
        println!("\nreport written to {path}");
    }
}
