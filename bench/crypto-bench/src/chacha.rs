//! The ChaCha20 candidate is the shipped module, included rather than copied.
//!
//! An earlier version of this harness carried its own `neon1`/`neon2`/`neon4`/
//! `neon8`/`avx2`/`sse1`/`portable` tree. That was fine while the cores were
//! experiments, and wrong the moment they shipped: the copy in here and the copy
//! in `crates/zero-protocol` then drift, and every number below is a number
//! about a file nobody runs. `#[path]` includes the real one, so the thing
//! measured here is the thing that gets executed, and a change to it has to come
//! back through this gate.
#[path = "../../../crates/zero-protocol/src/chacha20/mod.rs"]
mod shipped;

pub use shipped::xor_keystream;
