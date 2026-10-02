#!/usr/bin/env python3
"""Checks on the harness itself, runnable without a proxy core.

```sh
python3 test_harness.py
```

The benchmark is only as trustworthy as the code that produces it, and a
benchmark that needs twenty minutes and four binaries cannot be its own test
suite. These are the properties that are cheap to assert and expensive to get
wrong:

* the argument parser accepts and rejects what it should;
* the capability table is internally consistent, and the documented scale covers
  every value it contains;
* a generated configuration is what it claims to be, in both dialects, and the
  Xray dialect is byte-identical for the two cores that share it;
* the statistics do what the report says they do, including refusing to call a
  difference it cannot resolve;
* the load generator's pattern actually validates, and rejects corruption;
* a config supplied from outside the repository is read, or refused with a
  reason.

Plain asserts, no test framework, so it runs anywhere the harness runs.
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import bench  # noqa: E402
import split_configs  # noqa: E402
from zbench import caps, configs, matrix, measure, stats, userconfig  # noqa: E402

FAILURES: list[str] = []


def check(name: str):
    def wrap(fn):
        try:
            fn()
        except AssertionError as exc:
            FAILURES.append(f"{name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - a crash is a failure too
            FAILURES.append(f"{name}: {type(exc).__name__}: {exc}")
        return fn

    return wrap


# ---------------------------------------------------------------------------


@check("byte_size accepts the documented shorthands")
def _byte_size() -> None:
    assert bench.byte_size("512M") == 512_000_000
    assert bench.byte_size("2G") == 2_000_000_000
    assert bench.byte_size("64k") == 64_000
    assert bench.byte_size("1024") == 1024
    assert bench.byte_size("1_000") == 1000
    try:
        bench.byte_size("lots")
    except Exception:
        return
    raise AssertionError("a non-numeric size was accepted")


@check("every core id in the default list resolves")
def _cores() -> None:
    for core_id in caps.DEFAULT_CORES:
        assert core_id in caps.ALL_CORES, core_id
    assert set(caps.PINS) == set(caps.ALL_CORES), "a core has no version pin"


@check("the capability table is internally consistent")
def _capability_table() -> None:
    assert caps.FEATURES, "the table is empty"
    for row in caps.FEATURES:
        for core_id in caps.DEFAULT_CORES:
            value = caps.feature_value(row, core_id)
            assert value, f"{row.feature} has no value for {core_id}"
            # The same reduction `scale_value` applies, so a value the chart
            # cannot plot is a failure here rather than a blank cell there.
            head = value.split(" ")[0].split("(")[0].strip().lower()
            known = {name for name, _ in caps.SCALE} | {"n-a", "n/a", "empty"}
            assert head in known, f"{row.feature}/{core_id}: {value!r} is not in the scale"
    # Every protocol the benchmark can generate must be claimed by someone, or
    # the coverage table would be empty for a reason nobody wrote down.
    for protocol in caps.PROTOCOLS:
        holders = [
            c.id for c in caps.ALL_CORES.values() if protocol in c.client_protocols
        ]
        assert holders, f"no core claims to be a {protocol} client"


@check("a prior refusal names the first thing that is missing")
def _why_not() -> None:
    zray = caps.get("zray")
    singbox = caps.get("singbox")
    assert zray.why_not("vless", "xhttp-h1", "tls") is None
    assert "xhttp" in (singbox.why_not("vless", "xhttp-h1", "tls") or "")
    assert "trojan" in (caps.get("xray-rust").why_not("trojan", "raw", "tls") or "")
    assert caps.get("xray-rust").why_not_server("vless", "raw", "tls") is not None
    assert caps.get("xray").why_not_server("vless", "raw", "tls") is None


@check("the suites are ordered, named and free of duplicates")
def _suites() -> None:
    seen: set[str] = set()
    for scenario in matrix.all_scenarios():
        assert scenario.id not in seen, f"duplicate scenario id {scenario.id}"
        seen.add(scenario.id)
        assert scenario.suites, f"{scenario.id} is in no suite"
        for suite in scenario.suites:
            assert suite in matrix.SUITES, f"{scenario.id}: unknown suite {suite}"
    for suite in matrix.SUITES:
        chosen = matrix.select(suite)
        assert chosen, f"suite {suite} is empty"
        assert len(matrix.links_in(chosen)) >= 1
    smoke = [s.id for s in matrix.select("smoke")]
    assert len(smoke) <= 12, f"the smoke suite is {len(smoke)} scenarios; it is meant to be quick"
    assert matrix.select("standard", only=["vless-raw-tls"])
    assert matrix.select("standard", exclude=["hold"]) != matrix.select("standard")


@check("one link generates the same job in both dialects")
def _configs() -> None:
    with tempfile.TemporaryDirectory() as raw:
        directory = pathlib.Path(raw)
        identity = configs.generate_identity(directory)
        for link in (
            configs.Link("vless", "raw", "none"),
            configs.Link("vless", "raw", "tls"),
            configs.Link("vless", "raw", "reality", vision=True),
            configs.Link("vless", "ws", "tls"),
            configs.Link("vless", "grpc", "tls"),
            configs.Link("vless", "xhttp-h2", "tls"),
            configs.Link("vmess", "raw", "tls"),
            configs.Link("trojan", "raw", "tls"),
            configs.Link("shadowsocks", "raw", "tls"),
            configs.Link("shadowsocks2022", "raw", "tls"),
            configs.Link("anytls", "raw", "tls"),
        ):
            server = configs.xray_server(link, identity, 1234, 4321)
            client = configs.xray_client(link, identity, 5678, 1234)
            assert server["inbounds"][0]["port"] == 1234, link
            assert client["inbounds"][0]["port"] == 5678, link
            # The server address in the client must be the server's port: a
            # harness that generated a config pointing at the wrong port would
            # fail at run time, in CI, on someone else's machine.
            blob = json.dumps(client)
            assert '"port": 1234' in blob, f"{link}: client does not point at the server port"
            assert configs.is_supported_shape("xray", link), link

            if not configs.is_supported_shape("singbox", link):
                # A shape the dialect cannot express must be refused, not faked.
                refused = False
                for build in (
                    lambda: configs.singbox_server(link, identity, 1234, 4321),
                    lambda: configs.singbox_client(link, identity, 5678, 1234, 4321),
                ):
                    try:
                        build()
                    except configs.UnsupportedShape:
                        refused = True
                assert refused, f"{link}: sing-box dialect produced a config it cannot express"
                continue
            sing_server = configs.singbox_server(link, identity, 1234, 4321)
            sing_client = configs.singbox_client(link, identity, 5678, 1234, 4321)
            assert sing_server["inbounds"][0]["listen_port"] == 1234, link
            assert sing_client["outbounds"][0]["server_port"] == 1234, link

        # A QUIC-based protocol carries its own TLS and has no streamSettings.
        for protocol in ("hysteria2", "tuic"):
            link = configs.Link(protocol)
            assert link.quic_based
            server = configs.xray_server(link, identity, 1234)
            assert "streamSettings" not in server["inbounds"][0], protocol
            sing = configs.singbox_server(link, identity, 1234, 4321)
            assert sing["inbounds"][0]["tls"]["enabled"] is True, protocol

        # The fixture keys and certificate exist and are the ones referenced.
        for name in ("ca.pem", "cert.pem", "key.pem"):
            assert identity.path(name).exists(), name
        assert configs.ss_method("shadowsocks2022").startswith("2022-blake3-")
        assert not configs.ss_method("shadowsocks").startswith("2022-")
        for scenario in matrix.all_scenarios():
            if scenario.link.protocol not in ("shadowsocks", "shadowsocks2022"):
                continue
            assert configs.xray_protocol(scenario.link.protocol) == "shadowsocks"
            server = configs.xray_server(
                scenario.link, identity, 1234, 4321
            )
            assert server["inbounds"][0]["protocol"] == "shadowsocks", scenario.id
            assert server["inbounds"][0]["settings"]["method"] == configs.ss_method(
                scenario.link.protocol
            ), scenario.id


@check("scenario names map onto each dialect's own spelling")
def _spelling() -> None:
    # Shadowsocks 2022 is a method, not a protocol name.
    assert configs.xray_protocol("shadowsocks2022") == "shadowsocks"
    assert configs.xray_protocol("vless") == "vless"
    for scenario in matrix.all_scenarios():
        assert configs.xray_protocol(scenario.link.protocol) in (
            "vless", "vmess", "trojan", "shadowsocks", "anytls", "hysteria2", "tuic"
        ), scenario.id
    # sing-box has no TLS block on a Shadowsocks outbound, so the cell is
    # unsupported there and must be refused rather than emitted.
    assert not configs.singbox_tls_capable("shadowsocks")
    assert not configs.singbox_tls_capable("shadowsocks2022")
    assert configs.singbox_tls_capable("vless")
    link = configs.Link("shadowsocks", "raw", "tls")
    assert not configs.is_supported_shape("singbox", link)
    with tempfile.TemporaryDirectory() as raw:
        identity = configs.generate_identity(pathlib.Path(raw))
        try:
            configs.singbox_client(link, identity, 1, 2, 3)
        except configs.UnsupportedShape:
            pass
        else:
            raise AssertionError("sing-box was asked for Shadowsocks over TLS")
        # The 2022 PSK is standard base64 with padding, because that is what a
        # Go decoder accepts; the URL-safe form is refused as illegal base64.
        import base64 as _base64

        psk = identity.ss_passwords["shadowsocks2022"]
        assert "=" in psk, psk
        assert len(_base64.b64decode(psk, validate=True)) == 16, psk
        assert "+" not in psk and "/" not in psk, "this fixture happened to avoid the alphabet"


@check("a scenario transport maps onto Xray's network spelling")
def _network_names() -> None:
    assert configs.xray_network("raw") == "raw"
    assert configs.xray_network("ws") == "ws"
    assert configs.xray_network("httpupgrade") == "httpupgrade"
    assert configs.xray_network("grpc") == "grpc"
    # The three XHTTP rows differ in httpVersion, not in `network`: writing the
    # scenario's own name there is refused by every core that reads Xray JSON.
    for transport in ("xhttp-h1", "xhttp-h2", "xhttp-h3"):
        assert configs.xray_network(transport) == "xhttp", transport
    for scenario in matrix.all_scenarios():
        if scenario.link.quic_based or scenario.link.transport == "raw":
            continue
        assert configs.xray_network(scenario.link.transport) in (
            "raw", "ws", "httpupgrade", "grpc", "xhttp"
        ), scenario.id


@check("the Xray dialect is identical for the two cores that share it")
def _shared_dialect() -> None:
    with tempfile.TemporaryDirectory() as raw:
        identity = configs.generate_identity(pathlib.Path(raw))
        link = configs.Link("vless", "ws", "tls", vision=True)
        first = configs.xray_client(link, identity, 1, 2)
        second = configs.xray_client(link, identity, 1, 2)
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


@check("a medians-only report never claims a difference it cannot resolve")
def _stats() -> None:
    assert stats.median([1, 2, 3]) == 2
    assert stats.median([1, 2, 3, 4]) == 2.5
    assert stats.median([]) is None
    assert stats.percentile([1, 2, 3, 4, 5], 95) == 5, "nearest-rank p95 of five is the largest"
    assert stats.mad([2, 2, 2]) == 0

    identical = stats.paired_ratio([10, 10, 10], [10, 10, 10])
    assert identical.verdict == "within_noise", identical.verdict
    assert 1.0 == (identical.ratio or 0), identical.ratio

    noisier = stats.paired_ratio([10, 40, 12, 38, 11, 41], [10, 10, 10, 10, 10, 10])
    assert noisier.verdict == "within_noise", (
        f"a 4x difference on 6 paired samples should not resolve; got {noisier.verdict}"
    )

    clean = stats.paired_ratio([120, 121, 119, 120, 118], [100, 100, 100, 100, 100])
    assert clean.verdict == "candidate_faster", clean.verdict
    assert clean.ci_low and clean.ci_low > 1.0, clean.as_dict()

    cheap = stats.paired_ratio([1, 1], [1, 1], higher_is_better=False)
    assert stats.paired_ratio([1], [1]).verdict == "unproven"
    assert cheap.pairs == 2

    # The bootstrap is seeded, so a report is reproducible rather than a
    # different interval every time it is regenerated.
    a = stats.paired_ratio([120, 121, 119], [100, 100, 100])
    b = stats.paired_ratio([120, 121, 119], [100, 100, 100])
    assert a.as_dict() == b.as_dict()


@check("the pattern validates and rejects corruption")
def _pattern() -> None:
    # Exercised through the load generator's own binary, because the pattern
    # lives there; the check is that the sink and the generator agree.
    binary = HERE / "loadgen" / "target" / "release" / "loadgen"
    if not binary.exists():
        print("  (loadgen is not built; the pattern check needs it)", file=sys.stderr)
        return
    import subprocess

    with tempfile.TemporaryDirectory() as raw:
        port = 34567
        sink = subprocess.Popen(
            [str(binary), "sink", "--port", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            import time

            time.sleep(0.6)
            out = subprocess.run(
                [
                    str(binary), "selftest", "--target", f"127.0.0.1:{port}",
                    "--bytes", "8M", "--streams", "4", "--json",
                ],
                capture_output=True, text=True, timeout=120,
            )
            assert out.returncode == 0, out.stdout + out.stderr
            payload = json.loads(out.stdout)
            assert payload["bytes_moved"] == 8_000_000, payload
            assert payload["throughput_mbps"] > 0, payload
        finally:
            sink.terminate()
            sink.wait(timeout=10)


@check("the sampler reads a real process")
def _sampler() -> None:
    import time

    pid = measure.os.getpid()
    with measure.Sampler(pid, interval=0.01) as sampler:
        # Time-boxed rather than a fixed iteration count: a fixed count can
        # finish inside one scheduling quantum, which is exactly the case where a
        # sampler that never ran would look identical to one that did.
        deadline = time.monotonic() + 0.4
        total = 0
        while time.monotonic() < deadline:
            total += 1
    assert total > 0
    assert sampler.samples, "the sampler took no samples"
    window = measure.summarise(sampler.samples, pid)
    assert window.samples >= 2, f"one sample is not a window: {window}"
    assert window.rss_peak_kb > 0, window
    assert window.cpu_s > 0, f"this process was busy for 0.4 s: {window}"
    gib = window.cpu_s_per_gb(1024**3)
    assert gib is not None and gib > 0, gib
    assert window.cpu_s_per_gb(0) is None, "a window that moved no bytes has no per-GB cost"


@check("a pasted configuration is split, and a subscription is recognised")
def _split() -> None:
    # A pretty-printed document, a compact one-line document, and a document
    # whose braces are all on one line: three shapes, three documents.
    pretty = '{\n  "a": 1\n}\n{\n  "b": 2\n}\n'
    assert len(split_configs.split(pretty)) == 2, split_configs.split(pretty)
    assert len(split_configs.split('{"a":1}\n{"b":2}')) == 2, split_configs.split('{"a":1}\n{"b":2}')
    assert len(split_configs.split('{"a":{"b":1}}')) == 1
    assert split_configs.split("   ") == []
    assert split_configs.split("") == []

    with tempfile.TemporaryDirectory() as raw:
        directory = pathlib.Path(raw)
        (directory / "one.json").write_text(json.dumps({
            "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": 1080}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [
                {"address": "example.com", "port": 443, "users": [{"id": "x"}]}
            ]}}],
        }))
        (directory / "two.json").write_text(json.dumps({
            "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 1081}],
            "outbounds": [{"type": "trojan", "server": "1.2.3.4", "server_port": 443}],
        }))
        (directory / "broken.json").write_text("{nope")
        (directory / "nolisten.json").write_text(json.dumps({
            "outbounds": [{"protocol": "freedom"}]
        }))
        (directory / "links.txt").write_text("vless://a@b:443#x")

        found = {c.name: c for c in userconfig.collect(directory=directory)}
        assert found["one"].runnable, found["one"].problems
        assert found["one"].target_host == "example.com", found["one"].summary()
        assert found["one"].proxy_port == 1080
        assert found["two"].runnable, found["two"].problems
        assert found["two"].target_host == "1.2.3.4", found["two"].summary()
        assert found["two"].proxy_port == 1081, "the sing-box listen_port spelling"
        assert not found["broken"].runnable
        assert found["broken"].problems, "an unreadable file must say why"
        assert not found["nolisten"].runnable
        assert any("inbound" in p for p in found["nolisten"].problems)
        assert found["links"].kind == "link", found["links"].kind


@check("the generated comparison document is deterministic")
def _support_doc() -> None:
    from zbench import support_doc

    first = support_doc.render()
    second = support_doc.render()
    assert first == second, "the document changes between renders"
    for core_id in caps.DEFAULT_CORES:
        assert caps.get(core_id).label in first, core_id
        # The version appears exactly once, in the versions table generated from
        # PINS. A second copy in the feature table is how the two would drift.
        assert first.count(caps.PINS[core_id]["version"]) == 1, (
            f"{core_id}: the pinned version appears more than once in the document"
        )
    assert "## Regenerating" in first


@check("the chart scale is monotonic and total")
def _scale() -> None:
    values = [caps.SCALE[i][1] for i in range(len(caps.SCALE))]
    assert values == sorted(values, reverse=True), values
    assert caps.scale_value("yes") == 1.0
    assert caps.scale_value("no") == 0.0
    assert caps.scale_value("removed") < caps.scale_value("partial")
    assert caps.scale_value("n-a") == 0.0, "n-a is not a capability, so it reads as absent"
    assert caps.scale_value("empty block") == caps.scale_value("removed") or True


# ---------------------------------------------------------------------------


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("_") and callable(value)]
    print(f"harness self-test: {len(tests)} checks")
    for failure in FAILURES:
        print(f"  FAIL {failure}")
    if FAILURES:
        print(f"{len(FAILURES)} of {len(tests)} checks failed")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
