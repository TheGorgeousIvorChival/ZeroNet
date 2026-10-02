# 2026-04: the earlier Zray-core vs Xray-core comparison

These are the numbers quoted in the repository README's performance table. They
are kept because a published number should stay backed by a file that says how
it was produced, not because they are the current measurement.

## What produced them

An earlier harness, now replaced: one protocol (VLESS) at two security layers
(plain TCP and TLS 1.3 with a private CA), one comparator, 1/8/64 concurrent
streams, 2 GB per test, three runs per cell, median reported.

- Host: 4 vCPU Intel Xeon @ 2.80 GHz, 15 GB RAM, Linux 6.18, loopback.
- Xray-core v26.3.27 release build against Zray-core 0.1.0, `cargo build
  --release -p zray-cli`.
- The payload was **not** validated, the transfer window included connection
  setup, no ceiling for the load generator was measured, and the core order was
  fixed rather than rotated.

## Why they are not comparable with the current runs

The current harness validates the payload, separates the transfer window from
setup, measures and publishes its own ceiling, rotates and reverses the core
order, and prints the baseline's repeat-to-repeat spread next to every
comparison. The 2026-04 numbers have none of those, and they were taken on
different hardware.

They are kept verbatim. The point of replacing a harness is not to erase what it
showed, it is to stop quoting a number whose method cannot account for it.
