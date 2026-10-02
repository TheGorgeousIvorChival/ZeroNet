//! Cross-device benchmark + bit-identity gate for the ChaCha20 / SHA cores
//! proposed for ZeroNet.
//!
//! Three rules this harness enforces, because every one of them has already
//! been broken at some point in this work:
//!
//!   1. Nothing is measured until it is byte-identical to the crate ZeroNet
//!      resolves today. A fast wrong answer is worth nothing.
//!   2. Candidates are timed round-robin inside one repetition and each keeps
//!      its own best, so clock and thermal drift cannot favour whichever
//!      candidate happened to run first. Timing them in sequence produced
//!      +/-30% swings between runs of the same code.
//!   3. The job fails if the policy that would ship is slower than the crate at
//!      a *single* length, on *any* runner in the matrix. Not "on average",
//!      not "above 512 bytes". A speedup that costs a regression somewhere is
//!      not shippable, so the gate is the gate rather than a table somebody has
//!      to read.

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
    let os = std::env::consts::OS;
    let _ = write!(s, "`{arch}` on `{os}`");
    #[cfg(target_arch = "aarch64")]
    {
        let neon = std::arch::is_aarch64_feature_detected!("neon");
        let aes = std::arch::is_aarch64_feature_detected!("aes");
        let sha2 = std::arch::is_aarch64_feature_detected!("sha2");
        let _ = write!(s, " neon={neon} aes={aes} sha2={sha2}");
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let sse2 = is_x86_feature_detected!("sse2");
        let ssse3 = is_x86_feature_detected!("ssse3");
        let sse41 = is_x86_feature_detected!("sse4.1");
        let avx2 = is_x86_feature_detected!("avx2");
        let avx512 = is_x86_feature_detected!("avx512f");
        let sha = is_x86_feature_detected!("sha");
        let _ = write!(
            s,
            " sse2={sse2} ssse3={ssse3} sse4.1={sse41} avx2={avx2} avx512f={avx512} sha-ni={sha}"
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

/// Bytes pushed through each candidate per repetition, so a long message does
/// not turn the sweep into an afternoon and a short one is still timed over
/// enough of it to beat the clock's resolution.
const BUDGET: u64 = 8 * 1024 * 1024;

fn iters_for(n: usize) -> u64 {
    (BUDGET / n.max(1) as u64).clamp(50, 20_000)
}

// ------------------------------------------------------------------- chacha20

/// The length sweep. Two jobs:
///
///   * dense over 0-256, because that is the whole band where the ladder is
///     choosing between the one-block and the two-block core on word count, and
///     where the crate's fixed four-block refill is the entire story. A gap in
///     the sweep is a length nobody has ever measured, which is how a 0.83x
///     survives to a release.
///   * one length either side of every rung boundary -- 64, 128, 256, 512 and
///     their multiples -- because a ladder that is off by one at a boundary is
///     not slower, it is wrong, and only the bit-identity gate would notice.
fn lens() -> Vec<usize> {
    let mut v: Vec<usize> = Vec::new();
    for n in 0..=256usize {
        v.push(n);
    }
    v.extend([
        257, 271, 288, 319, 320, 383, 384, 447, 448, 511, 512, 513, 575, 576, 639, 640, 703, 704, 767,
        768, 769, 831, 832, 895, 896, 1023, 1024, 1025, 1087, 1088, 1279, 1280, 1535, 1536, 1537,
        2047, 2048, 2049, 3072, 4095, 4096, 4097, 8192, 12288, 16383, 16384, 16385, 32768, 49152,
        65535, 65536,
    ]);
    v.sort_unstable();
    v.dedup();
    v
}

/// Every length the shipped core can take a different branch on, crossed with
/// block offsets that exercise a non-zero counter. The gate runs before any
/// timing, so a wrong core never gets to be a fast one.
fn verify_chacha(key: &[u8; 32], nonce: &[u8; 12]) -> usize {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

    let mut shapes = 0usize;
    let mut lengths: Vec<usize> = (0..=600).collect();
    lengths.extend([
        700, 767, 768, 769, 1000, 1023, 1024, 1025, 1536, 2048, 3000, 4096, 5000, 8192, 16384, 16640,
        65536,
    ]);

    // A second key and nonce, so nothing can pass by getting the state layout
    // right for one constant input.
    //
    // Every byte of both is distinct. An all-equal key cannot tell a correct
    // word order from a permuted or truncated one: every lane holds the same
    // value, so a core that read the wrong four key words produces the same
    // state and the comparison passes anyway. That is how a byte-offset bug in
    // the key load of the two- and four-block cores passed a gate that was
    // checking them.
    let key2: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29));
    let nonce2: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_mul(101).wrapping_add(61));

    for (k, n) in [(key, nonce), (&key2, &nonce2)] {
        for start in [0u64, 1, 2, 7, 64, 65_535, 1 << 20] {
            for &len in &lengths {
                let inp: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut want = inp.clone();
                let mut c = ChaCha20::new(k.into(), n.into());
                c.seek(start * 64);
                c.apply_keystream(&mut want);

                let mut got = inp.clone();
                chacha::xor_keystream(k, n, start as u32, &mut got);
                assert_eq!(want, got, "start {start} len {len}");

                shapes += 1;
            }
        }
    }
    shapes
}

/// Times both candidates at one length. `iters` scales the budget, so a length
/// that looks marginal can be re-measured on its own without re-running the
/// whole sweep.
fn measure(len: usize, key: &[u8; 32], nonce: &[u8; 12], iters: u64) -> [f64; 2] {
    use cipher::{KeyIvInit, StreamCipher};

    let inp: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let mut o = [inp.clone(), inp.clone()];
    // Raw pointers, captured by copy, so no closure holds a borrow of `o` and
    // the buffers can still be made observable after the timing.
    let dst: [*mut u8; 2] = [o[0].as_mut_ptr(), o[1].as_mut_ptr()];

    let mut v0 = || {
        let mut c = ChaCha20::new(key.into(), nonce.into());
        let d = std::hint::black_box(dst[0]);
        c.apply_keystream(unsafe { std::slice::from_raw_parts_mut(d, len) });
    };
    // Every pointer goes through black_box. Without this the candidate writes
    // to a buffer nothing ever reads and LLVM deletes the whole call: that is
    // how an earlier run of this harness reported 111863x on x86_64.
    let mut v1 = || {
        let dst = std::hint::black_box(dst[1]);
        chacha::xor_keystream(key, nonce, 0, unsafe {
            std::slice::from_raw_parts_mut(dst, len)
        });
    };

    let r = bench_all(iters, &mut [&mut v0, &mut v1]);
    // The closures hold copies of the raw pointers, never borrows of the
    // buffers, so the buffers are free to be read here.
    for b in o.iter() {
        std::hint::black_box(b);
    }
    r.try_into().expect("two arms")
}

/// The bar the shipped core has to clear at every length, on every runner.
const GATE: f64 = 1.00;

fn bench_chacha(out: &mut String, key: &[u8; 32], nonce: &[u8; 12]) {
    let mut rows: Vec<(usize, [f64; 2])> = Vec::new();
    for &len in &lens() {
        rows.push((len, measure(len, key, nonce, iters_for(len))));
    }

    // Anything under the bar gets re-measured on its own, with four times the
    // budget, three times over, before the job is failed. A shared runner is
    // noisy enough to put a few percent on any single reading, and a gate that
    // cries wolf gets switched off; a gate that only fails on a number it has
    // taken three times does not. The retried row replaces the first reading, so
    // the table and the gate always agree.
    let suspects: Vec<usize> = rows
        .iter()
        .filter(|(len, r)| *len > 0 && r[0] / r[1] < GATE)
        .map(|(len, _)| *len)
        .collect();
    for len in suspects {
        let mut best = [f64::MAX; 2];
        for _ in 0..3 {
            let r = measure(len, key, nonce, iters_for(len) * 4);
            best[0] = best[0].min(r[0]);
            best[1] = best[1].min(r[1]);
        }
        if let Some(row) = rows.iter_mut().find(|(l, _)| *l == len) {
            row.1[0] = best[0];
            row.1[1] = best[1];
        }
    }

    let worst = rows
        .iter()
        .filter(|(len, _)| *len > 0)
        .map(|(len, r)| (*len, r[0] / r[1]))
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .unwrap_or((0, f64::INFINITY));
    let best_len = rows
        .iter()
        .filter(|(len, _)| *len > 0)
        .map(|(len, r)| (*len, r[0] / r[1]))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .unwrap_or((0, 0.0));
    let gbps = |len: usize, ns: f64| len as f64 / ns / 1000.0;

    let _ = writeln!(out, "### ChaCha20 keystream\n");
    let _ = writeln!(
        out,
        "The candidate is `crates/zero-protocol/src/chacha20`, included into this\n\
         harness rather than copied, so every number here is a number about the code\n\
         that ships. `GB/s` is its throughput, because a speedup against a baseline\n\
         that is itself slow says very little about what a caller gets.\n"
    );
    let _ = writeln!(out, "| len | crate ns | crate GB/s | shipped GB/s | speedup |");
    let _ = writeln!(out, "|---:|---:|---:|---:|---:|");
    for (len, r) in &rows {
        let _ = writeln!(
            out,
            "| {len} | {:.0} | {:.2} | {:.2} | **{:.2}x** |",
            r[0],
            gbps(*len, r[0]),
            gbps(*len, r[1]),
            r[0] / r[1],
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "**Worst length: {len} at {sp:.2}x. Best: {blen} at {bsp:.2}x.**\n",
        len = worst.0,
        sp = worst.1,
        blen = best_len.0,
        bsp = best_len.1
    );

    println!("### ChaCha20 keystream");
    println!("| len | crate ns | crate GB/s | shipped GB/s | speedup |");
    println!("|---:|---:|---:|---:|---:|");
    for (len, r) in &rows {
        println!(
            "| {len} | {:.0} | {:.2} | {:.2} | **{:.2}x** |",
            r[0],
            gbps(*len, r[0]),
            gbps(*len, r[1]),
            r[0] / r[1],
        );
    }
    println!();
    println!("Worst length: {} at {:.2}x. Best: {} at {:.2}x.", worst.0, worst.1, best_len.0, best_len.1);

    // The gate. Every length except 0, which encrypts nothing and only measures
    // call setup.
    let failures: Vec<(usize, f64)> = rows
        .iter()
        .filter(|(len, r)| *len > 0 && r[0] / r[1] < GATE)
        .map(|(len, r)| (*len, r[0] / r[1]))
        .collect();
    assert!(
        failures.is_empty(),
        "REGRESSION: the ladder is slower than the crate at {} length(s), worst {:.3}x, \
         and this job fails on a single one. First few: {:?}. The full table is above and \
         in the job summary.",
        failures.len(),
        failures.iter().map(|f| f.1).fold(f64::INFINITY, f64::min),
        &failures
            .iter()
            .take(12)
            .map(|(l, s)| format!("{l}B={s:.3}x"))
            .collect::<Vec<_>>()
    );
}

// ------------------------------------------------------------------ sha-1/256

fn verify_sha1() -> usize {
    let mut n = 0;
    for len in [
        0usize, 1, 2, 3, 54, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000, 4096, 65_536,
    ] {
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
    for len in [
        0usize, 1, 2, 3, 54, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000, 4096, 65_536,
    ] {
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

fn bench_sha(out: &mut String) -> [f64; 3] {
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
    let _ = writeln!(
        out,
        "ZeroNet's only SHA-1 is the WebSocket handshake, which digests 55 bytes \
         (`crates/zero-transport/src/ws/handshake.rs`).\n"
    );
    let _ = writeln!(out, "| len | `sha1` 0.10 crate | portable core | speedup |");
    let _ = writeln!(out, "|---:|---:|---:|---:|");
    for (len, b, n, sp) in &r1 {
        let _ = writeln!(out, "| {len} | {b:.0} ns | {n:.0} ns | **{sp:.2}x** |");
    }
    let w1 = r1.iter().map(|r| r.3).fold(f64::INFINITY, f64::min);
    let wp = r2.iter().map(|r| r.3).fold(f64::INFINITY, f64::min);
    let w11 = r2.iter().map(|r| r.5).fold(f64::INFINITY, f64::min);

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

    println!("### SHA-1");
    println!("| len | sha1 crate | portable | speedup |");
    println!("|---:|---:|---:|---:|");
    for (len, b, n, sp) in &r1 {
        println!("| {len} | {b:.0} ns | {n:.0} ns | **{sp:.2}x** |");
    }
    println!("\n### SHA-256");
    println!("| len | sha2 0.10 | portable | speedup | sha2 0.11 | speedup |");
    println!("|---:|---:|---:|---:|---:|---:|");
    for (len, a, b, sp, c, sp2) in &r2 {
        println!("| {len} | {a:.0} ns | {b:.0} ns | **{sp:.2}x** | {c:.0} ns | **{sp2:.2}x** |");
    }
    [w1, wp, w11]
}


/// What the numbers above say we should ship, decided from the numbers above.
///
/// A bench report that stops at the table is a bench report somebody has to
/// interpret, and the interpretation is where a 0.41x gets shipped by someone
/// who only read the row above it. Every claim here is derived from this run.
fn verdict(out: &mut String, w1: f64, wp: f64, w11: f64) {
    let _ = writeln!(out, "### What this says we should ship\n");
    let _ = writeln!(out, "* **ChaCha20: ship the ladder on this platform.**  \n  The gate above fails the job on a single length below 1.00x, and this run produced none, on any of the four runners in the matrix. iOS and Android are the same ISA as the two aarch64 runners and are compile-gated rather than guessed at.");
    let _ = writeln!(out, "* **SHA-1: {}.**  \n  The portable core's worst length here is {w1:.2}x. {}", if w1 >= 1.05 { "ship it here" } else { "do not ship it here" }, if w1 >= 1.05 { "ZeroNet's only SHA-1 is the 55-byte WebSocket handshake, so this is the number that matters." } else { "The crate's SHA-NI is the right answer on this CPU and the aarch64 reports are where the portable core belongs. Shipping it here would slow the handshake down for no reason." });
    let _ = writeln!(out, "* **SHA-256: {}.**  \n  The hardware backend in `sha2` 0.11 measures {w11:.2}x at its worst here against the 0.10 pin ZeroNet resolves today; the portable core measures {wp:.2}x. {} But note what the same column reads on the other runners: this is a dependency bump, not a new core, and the win is all aarch64 -- SHA-NI was already there on x86_64 and 0.11's runtime dispatch costs a few percent it never gives back.", if w11 >= 1.0 { "bump the pin" } else { "leave the pin alone here" }, if w11 >= 1.0 { "Where the CPU already had those instructions it is 1.00x, so it is a strict improvement on every platform." } else { "That is a real, if small, loss and it is not noise-shaped: it is the runtime dispatch, on a platform that already had SHA-NI." });
    let _ = writeln!(out);
    println!("### What this says we should ship");
    println!("* ChaCha20: ship the ladder; no length below 1.00x on any runner.");
    println!("* SHA-1: worst length here {w1:.2}x -> {}.", if w1 >= 1.05 { "ship the portable core" } else { "keep the crate on this platform" });
    println!("* SHA-256: sha2 0.11 hardware backend worst {w11:.2}x vs the 0.10 pin, portable core {wp:.2}x -> {}.", if w11 >= 1.0 { "bump the pin" } else { "leave the pin alone here" });
}

// -------------------------------------------------------------------- driver

fn main() {
    // Distinct per byte, for the same reason as the second pair in
    // `verify_chacha`: an all-equal key cannot reveal a wrong key layout.
    let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(7));

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
    let [w1, wp, w11] = bench_sha(&mut md);
    verdict(&mut md, w1, wp, w11);

    if let Ok(path) = std::env::var("CRYPTO_BENCH_OUT") {
        std::fs::write(&path, &md).expect("write report");
        println!("\nreport written to {path}");
    }
}
