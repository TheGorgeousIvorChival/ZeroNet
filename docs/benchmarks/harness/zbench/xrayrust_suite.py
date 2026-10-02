"""How this harness compares with the benchmark suite it is measured against.

ZeroNet and xray-rust are compared here, and the xray-rust project ships its own
suite. "Better than the previous one" is easy to say about a harness whose
predecessor was 40 lines; it is harder against 21,601 lines of
`crates/xray-bench`, a paired-bootstrap parity campaign, and a published
report. So the comparison is written down, item by item, in both directions.

The entries are data rather than prose so that `test_harness.py` can check each
claim against the capability model in `caps.py`. A claim that drifts from the code
is a failing test rather than a sentence nobody re-reads.

Scope note. xray-rust ships two non-interchangeable suites: a cross-engine one
documented in `docs/benchmarks.md`, and a newer protocol-parity campaign driven
by Python scripts whose methodology the documentation does not describe. Rows
below are marked with which one they come from.
"""

from __future__ import annotations

#: What the xray-rust suite measures, and where this harness stands on it.
#:
#: `status` is one of:
#:   `covered`      -- measured here, same idea
#:   `partial`      -- measured here, narrower than theirs
#:   `capability`   -- named and probed as a config the core can be given
#:   `not_covered`  -- not measured here, and why
XRAY_RUST_SUITE = (
    {
        "item": "VLESS over raw TCP, TLS, REALITY, Vision",
        "builds": (("vless", "raw"), ("vless", "ws"), ("vless", "grpc")),
        "suite": "both",
        "status": "covered",
        "ours": "raw/tls/reality/vision scenarios in all three suites",
    },
    {
        "item": "WebSocket, HTTPUpgrade, gRPC, XHTTP h1/h2/h3",
        "builds": (("vless", "ws"), ("vless", "httpupgrade"), ("vless", "grpc"), ("vless", "xhttp-h1"), ("vless", "xhttp-h2"), ("vless", "xhttp-h3")),
        "suite": "both",
        "status": "covered",
        "ours": "each transport has a config-generated scenario per security layer",
    },
    {
        "item": "Payload validated against a deterministic byte pattern",
        "suite": "both",
        "status": "covered",
        "builds": (),
        "ours": "every byte the sink returns is checked against the keystream",
    },
    {
        "item": "Peak RSS and CPU per payload, from outside the process",
        "suite": "both",
        "status": "covered",
        "builds": (),
        "ours": "rss_peak_mb, rss_idle_mb, cpu_s, cpu_s_per_GB, and the server's",
    },
    {
        "item": "Paired bootstrap ratio intervals",
        "suite": "parity",
        "status": "covered",
        "builds": (),
        "ours": "same construction, 4000 resamples, fixed seed",
    },
    {
        "item": "Multiple uTLS fingerprints (7 fingerprints x 7 traffic kinds)",
        "builds": (("vless", "raw"),),
        "suite": "cross-engine",
        "status": "partial",
        "ours": "one fingerprint, chrome, on the REALITY rows only",
    },
    {
        "item": "Hysteria2 as a client protocol",
        "builds": (),
        "suite": "parity",
        "status": "not_covered",
        "ours": (
            "xray-rust supports it and the capability table says so, but neither "
            "core can serve it, so there is no server for a transfer to reach. A "
            "row would measure a connection that cannot be completed"
        ),
    },
    {
        "item": "WireGuard as a client protocol",
        "builds": (),
        "suite": "parity",
        "status": "not_covered",
        "ours": (
            "xray-rust's is a userspace stack whose peer must be a real WireGuard "
            "endpoint, so the same applies: nothing here can be its peer"
        ),
    },
    {
        "item": "TUN inbound workloads (about ten of their twenty-two)",
        "builds": (),
        "suite": "cross-engine",
        "status": "not_covered",
        "ours": "every scenario here drives a socks inbound; TUN needs a tun device",
    },
    {
        "item": "DNS and FakeDNS policy workloads",
        "builds": (),
        "suite": "cross-engine",
        "status": "not_covered",
        "ours": "no DNS fixture; the traffic here is proxied TCP and UDP",
    },
    {
        "item": "Geodata routing latency",
        "builds": (),
        "suite": "cross-engine",
        "status": "not_covered",
        "ours": "no geodata rules in any generated config",
    },
    {
        "item": "A shaped WAN: bounded delay, bandwidth and loss",
        "builds": (("vless", "raw"),),
        "suite": "parity",
        "status": "partial",
        "ours": (
            "loopback only. Their relay adds 25 ms per direction at 100 Mbit/s; "
            "nothing here shapes the path, so nothing here measures loss or RTT"
        ),
    },
    {
        "item": "Absolute budgets in nanoseconds for route and selector work",
        "builds": (),
        "suite": "cross-engine",
        "status": "not_covered",
        "ours": "process-level sampling cannot see inside the router's own work",
    },
)

#: What this harness measures that their suite does not.
SUPERSETS = (
    {
        "item": "A measured generator ceiling, per flow count",
        "theirs": (
            "the parity report has no absolute ceiling at all; only relative "
            "ratios, and its README explicitly disclaims a shared budget"
        ),
    },
    {
        "item": "The baseline measured against itself",
        "theirs": "no noise floor is published beside each ratio",
    },
    {
        "item": "A gate against the change's own base, on every pull request",
        "theirs": "their CI runs no benchmark; ci.yml only self-tests the checkers",
    },
    {
        "item": "Four cores in one run, including this project's own",
        "theirs": "xray-rust, Xray-core, sing-box, plus native Hysteria and WG",
    },
    {
        "item": "A capability surface: what each core cannot be configured to do",
        "theirs": (
            "found by each config being rejected, but never tabulated as a "
            "surface of what is missing"
        ),
    },
    {
        "item": "A coverage grid drawn per link, with missing cells hatched",
        "theirs": "not present",
    },
    {
        "item": "Benchmarking a configuration supplied from outside the repo",
        "theirs": "not present",
    },
    {
        "item": "A validator that re-derives every aggregate from the raw cells",
        "theirs": (
            "check-benchmark-publication.py exists and is fail-closed, but the "
            "parity summariser reuses its own statistics helpers"
        ),
    },
)

#: Claims xray-rust publishes about itself, as checked against this tree.
THEIR_CLAIMS = (
    {
        "claim": (
            "v0.7's published verdict is 'Not established across all measured "
            "cases', with 33 of 195 retained point differences outside a 3% "
            "allowance"
        ),
        "ours": (
            "consistent with what we measure: 34 of 35 comparisons on our own "
            "runs resolve to within noise at 3 repeats"
        ),
    },
    {
        "claim": (
            "the README scope table lists WireGuard and Hysteria2 as unsupported, "
            "while v0.7 implements both"
        ),
        "ours": (
            "we report the capability from the binary's own config checker, not "
            "from its README, which is why this harness found Hysteria2 supported "
            "where the README says no"
        ),
    },
    {
        "claim": "heap allocation counts are explicitly out of scope for both",
        "ours": "agreed: process-level sampling cannot compare Go and Rust allocation",
    },
)


def not_covered_items() -> list[str]:
    return [row["item"] for row in XRAY_RUST_SUITE if row["status"] == "not_covered"]
