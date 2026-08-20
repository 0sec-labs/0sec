"""Engine-side cloud sink — the ``0verse scan --cloud`` lane.

Covers the OversePoV -> CloudSinkFinding mapper (PoV-is-truth: confirmed honors
severity + 0.92 confidence; unconfirmed is forced to info + 0.1; confidence
clamp; evidence / pocSteps shape), the streaming POST flow against a LOCAL
``http.server`` mock (per-finding + final-report bodies, Bearer header, retry on
a simulated 503), the exit-non-zero-when-the-final-report-fails contract, env
precedence + token-from-env-not-argv, and the ``--cloud`` CLI wiring.

NO prod network — every POST targets a localhost mock.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from zeroverse import cloud_sink
from zeroverse.api import ScanFinding, ScanResult
from zeroverse.cloud_sink import (
    CloudSinkConfig,
    OversePoV,
    build_config,
    map_pov_to_finding,
    pov_from_scan_finding,
)

# --- mapper ----------------------------------------------------------------

def _pov(**kw: Any) -> OversePoV:
    base = {
        "id": "abc123", "bug_class": "CWE-78", "severity": "high", "title": "t",
        "description": "d", "target": "/bin/vuln", "confirmed": True,
        "repro_cmd": "python3 /out/pov.py", "pov_path": "/out/pov.py",
        "crash_output": "SIGSEGV at 0x41414141", "capability": "oob-write",
    }
    base.update(kw)
    return OversePoV(**base)  # type: ignore[arg-type]


def test_confirmed_honors_severity_and_default_confidence() -> None:
    cf = map_pov_to_finding(_pov(confirmed=True, severity="high", confidence=None))
    assert cf["severity"] == "high"          # honored only because confirmed
    assert cf["status"] == "confirmed"
    assert cf["confidence"] == 0.92
    assert cf["templateId"] == "0verse-binary:CWE-78"
    assert cf["category"] == "CWE-78"


def test_unconfirmed_forced_to_info() -> None:
    cf = map_pov_to_finding(_pov(confirmed=False, severity="critical", confidence=None))
    assert cf["severity"] == "info"          # PoV-is-truth: forced, NOT critical
    assert cf["status"] == "unconfirmed"
    assert cf["confidence"] == 0.1
    assert cf["pocSteps"][0]["confirmed"] is False


def test_confidence_is_clamped() -> None:
    assert map_pov_to_finding(_pov(confidence=2.5))["confidence"] == 1.0
    assert map_pov_to_finding(_pov(confidence=-0.4))["confidence"] == 0.0
    assert map_pov_to_finding(_pov(confidence=0.42))["confidence"] == 0.42


def test_evidence_and_pocsteps_shape() -> None:
    cf = map_pov_to_finding(_pov())
    ev = cf["evidence"]
    assert ev["request"] == "target: /bin/vuln\nrepro: python3 /out/pov.py"
    assert ev["response"] == "SIGSEGV at 0x41414141"
    assert "PoV reproduced" in ev["analysis"]
    step = cf["pocSteps"][0]
    assert step == {
        "kind": "binary-pov", "artifact": "/out/pov.py",
        "command": "python3 /out/pov.py", "confirmed": True,
    }
    assert isinstance(cf["timestamp"], int)


def test_unknown_severity_normalizes_to_info_even_when_confirmed() -> None:
    assert map_pov_to_finding(_pov(confirmed=True, severity="unknown"))["severity"] == "info"
    assert map_pov_to_finding(_pov(confirmed=True, severity="moderate"))["severity"] == "medium"


def test_pov_from_scan_finding_projection() -> None:
    f = ScanFinding(
        id="id1", bug_class="CWE-120", severity="high", file="/bin/x", function="handler",
        offset="0x1000", source="recv", sink="memcpy", confirmed=True, hypothesis=True,
        pruned=False, capability="oob-write", pov_path="/out/p.py",
        repro_cmd="python3 /out/p.py", dedup_bucket="b1", explanation="taint reaches memcpy",
    )
    pov = pov_from_scan_finding(f, "/bin/x")
    assert pov.title == "CWE-120: recv -> memcpy in handler"
    assert pov.description == "taint reaches memcpy"
    assert pov.target == "/bin/x"
    cf = map_pov_to_finding(pov)
    assert cf["severity"] == "high" and cf["status"] == "confirmed"


def test_v1_1_crash_output_flows_to_evidence_response() -> None:
    # End-to-end #36 proof: a confirmed v1.1 ScanFinding carrying the oracle's real
    # crash_output maps to a NON-EMPTY evidence.response (was always "" under v1.0),
    # and a contract confidence is carried through and clamped.
    f = ScanFinding(
        id="id2", bug_class="CWE-787", severity="high", file="/bin/x", function="parse",
        offset="0x2000", source="read", sink="memcpy", confirmed=True, hypothesis=True,
        pruned=False, capability="oob-write", pov_path="/out/p.py",
        repro_cmd="python3 /out/p.py", dedup_bucket="b1", explanation="oob write",
        crash_output="==1234==ERROR: AddressSanitizer: heap-buffer-overflow WRITE",
        confidence=0.95,
    )
    pov = pov_from_scan_finding(f, "/bin/x")
    assert pov.crash_output == f.crash_output
    assert pov.confidence == 0.95
    cf = map_pov_to_finding(pov)
    assert cf["evidence"]["response"] == f.crash_output   # real crash text over the wire
    assert cf["evidence"]["response"] != ""
    assert cf["confidence"] == 0.95


def test_v1_1_unconfirmed_finding_has_empty_response() -> None:
    # A hypothesis (no crash_output) still maps to an empty evidence.response — the
    # mapper falls back to its unconfirmed default confidence.
    f = ScanFinding(
        id="id3", bug_class="CWE-120", severity="critical", file="/bin/x", function="h",
        offset="0x3000", source="recv", sink="strcpy", confirmed=False, hypothesis=True,
        pruned=False, capability="", pov_path="", repro_cmd="", dedup_bucket="",
        explanation="possible overflow",
    )
    cf = map_pov_to_finding(pov_from_scan_finding(f, "/bin/x"))
    assert cf["evidence"]["response"] == ""
    assert cf["confidence"] == 0.1


# --- mock orchestrator -----------------------------------------------------

class _Capture:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.fail_next: int = 0  # respond 503 for this many requests, then 200


def _make_server(cap: _Capture) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a: Any) -> None:  # silence
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            cap.requests.append({
                "path": self.path,
                "auth": self.headers.get("Authorization"),
                "scan_id_header": self.headers.get("X-Pwnkit-Scan-Id"),
                "body": json.loads(raw) if raw else None,
            })
            if cap.fail_next > 0:
                cap.fail_next -= 1
                self.send_response(503)
                self.end_headers()
                self.wfile.write(b"try again")
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

    return HTTPServer(("127.0.0.1", 0), Handler)


def _serve(server: HTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def _config_for(server: HTTPServer, **kw: Any) -> CloudSinkConfig:
    host, port = server.server_address
    base = {"sink_url": f"http://{host}:{port}/api", "scan_id": "scan-9", "token": "secret-tok",
                "timeout_ms": 2000}
    base.update(kw)
    return CloudSinkConfig(**base)  # type: ignore[arg-type]


def _scan_result() -> ScanResult:
    confirmed = ScanFinding(
        id="f-confirmed", bug_class="CWE-78", severity="high", file="/bin/vuln",
        function="main", offset="0x401000", source="getenv", sink="system", confirmed=True,
        hypothesis=True, pruned=False, capability="command-exec", pov_path="/out/pov.py",
        repro_cmd="python3 /out/pov.py", dedup_bucket="b1", explanation="cmd injection",
    )
    hypo = ScanFinding(
        id="f-hypo", bug_class="CWE-120", severity="critical", file="/bin/vuln",
        function="handler", offset="0x402000", source="recv", sink="memcpy", confirmed=False,
        hypothesis=True, pruned=False, capability="", pov_path="", repro_cmd="",
        dedup_bucket="", explanation="possible overflow",
    )
    return ScanResult(
        contract_version="1.0", tool={"name": "0verse", "version": "0.0.1"},
        binary="/bin/vuln", format="ELF", arch="x86-64", backend="ghidra",
        triage="ELF x86-64", stages_run=["ingest", "analyze", "dynamic"],
        findings=[confirmed, hypo], note="static-only on this host",
        terminal_state="confirmed", status_reason="1 finding has a replay-confirmed PoV",
    )


def test_streaming_posts_per_finding_then_final_report() -> None:
    cap = _Capture()
    server = _make_server(cap)
    _serve(server)
    try:
        config = _config_for(server)
        started = datetime(2026, 6, 28, tzinfo=UTC)
        completed = datetime(2026, 6, 28, 0, 0, 5, tzinfo=UTC)
        rc = cloud_sink.stream_result(_scan_result(), config, started, completed)
    finally:
        server.shutdown()
    assert rc == 0
    # 2 per-finding POSTs + 1 final report.
    assert len(cap.requests) == 3
    # Every request carried the bearer + scan-id header.
    for r in cap.requests:
        assert r["auth"] == "Bearer secret-tok"
        assert r["scan_id_header"] == "scan-9"
        assert r["path"] == "/api/scans/scan-9/findings"

    fnd = [r["body"] for r in cap.requests if "finding" in r["body"]]
    final = [r["body"] for r in cap.requests if r["body"].get("final")]
    assert len(fnd) == 2 and len(final) == 1

    by_id = {b["finding"]["id"]: b["finding"] for b in fnd}
    assert by_id["f-confirmed"]["severity"] == "high"   # confirmed -> honored
    assert by_id["f-hypo"]["severity"] == "info"         # unconfirmed -> forced info

    report = final[0]["report"]
    assert report["target"] == "/bin/vuln"
    assert report["scanDepth"] == "deep"
    assert report["exitReason"] == "completed"
    assert report["durationMs"] == 5000
    assert report["summary"] == {
        "totalAttacks": 2, "totalFindings": 2,
        "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 1,
    }
    assert report["warnings"] == [{"stage": "scan", "message": "static-only on this host"}]


@pytest.mark.parametrize("state", ["infra-failed", "unsupported", "cancelled", "skipped"])
def test_failed_terminal_state_never_posts_completion_report(
    state: str, monkeypatch: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    result = _scan_result()
    result.terminal_state = state  # type: ignore[assignment]
    result.status_reason = "required execution lane unavailable"
    monkeypatch.setattr(
        cloud_sink,
        "post_final_report",
        lambda report, config: pytest.fail("failure must not post final: true"),
    )
    started = datetime(2026, 6, 28, tzinfo=UTC)

    rc = cloud_sink.stream_result(
        result,
        CloudSinkConfig("https://sink.invalid", "scan-failed", events=False),
        started,
        started,
    )

    assert rc == 1
    stderr = capsys.readouterr().err
    assert f"scan ended {state}: required execution lane unavailable" in stderr
    assert "no completion report posted" in stderr


def test_failed_terminal_state_posts_no_invalid_report_envelope() -> None:
    cap = _Capture()
    server = _make_server(cap)
    _serve(server)
    result = _scan_result()
    result.terminal_state = "infra-failed"
    result.status_reason = "required executor timed out"
    started = datetime(2026, 6, 28, tzinfo=UTC)
    try:
        rc = cloud_sink.stream_result(
            result, _config_for(server, events=False), started, started
        )
    finally:
        server.shutdown()

    assert rc == 1
    assert cap.requests == []


def test_no_findings_terminal_state_is_cloud_success(monkeypatch: Any) -> None:
    result = _scan_result()
    result.terminal_state = "no-findings"
    result.status_reason = "required stages completed; no replay-confirmed PoV"
    result.findings = []
    reports: list[dict[str, Any]] = []
    monkeypatch.setattr(
        cloud_sink,
        "post_final_report",
        lambda report, config: reports.append(report) is None,
    )
    started = datetime(2026, 6, 28, tzinfo=UTC)

    rc = cloud_sink.stream_result(
        result,
        CloudSinkConfig("https://sink.invalid", "scan-clean", events=False),
        started,
        started,
    )

    assert rc == 0
    assert reports[0]["exitReason"] == "completed"


def test_retry_on_503_then_succeeds() -> None:
    cap = _Capture()
    cap.fail_next = 1  # first POST 503s, retry succeeds
    server = _make_server(cap)
    _serve(server)
    try:
        config = _config_for(server)
        ok = cloud_sink.post_finding({"id": "x"}, config)
    finally:
        server.shutdown()
    assert ok is True
    assert len(cap.requests) == 2  # original + one retry


def test_per_finding_failure_does_not_crash_but_final_failure_exits_nonzero() -> None:
    cap = _Capture()
    # Fail the two per-finding POSTs (retries exhausted) AND the final report.
    cap.fail_next = 99
    server = _make_server(cap)
    _serve(server)
    try:
        # Tiny backoff + retries via a fast config path: call stream_result with a
        # config whose timeout is short; the 503s exhaust retries quickly.
        config = _config_for(server, timeout_ms=500)
        started = datetime(2026, 6, 28, tzinfo=UTC)
        rc = cloud_sink.stream_result(_scan_result(), config, started, started)
    finally:
        server.shutdown()
    assert rc == 1  # final report never landed -> non-zero exit


def test_final_report_failure_exits_nonzero_isolated() -> None:
    # Point at a closed port so the connection always fails (no retries land).
    config = CloudSinkConfig(sink_url="http://127.0.0.1:9", scan_id="s", token=None,
                             timeout_ms=200)
    report = {"target": "/bin/x", "summary": {}}
    assert cloud_sink.post_final_report(report, config) is False


# --- env / config resolution ----------------------------------------------

def test_build_config_env_precedence_and_token_from_env(monkeypatch: Any) -> None:
    monkeypatch.setenv("PWNKIT_CLOUD_SINK", "https://env.example/api")
    monkeypatch.setenv("PWNKIT_CLOUD_SCAN_ID", "env-scan")
    monkeypatch.setenv("PWNKIT_CLOUD_TOKEN", "env-token")
    monkeypatch.setenv("PWNKIT_CLOUD_ORG_ID", "org-7")
    # Flags pass DIFFERENT values; env must win.
    cfg = build_config(sink="https://flag.example/api", scan_id="flag-scan", timeout_ms=1234)
    assert cfg is not None
    assert cfg.sink_url == "https://env.example/api"   # env precedence
    assert cfg.scan_id == "env-scan"
    assert cfg.token == "env-token"                     # token from env
    assert cfg.org_id == "org-7"
    assert cfg.timeout_ms == 1234


def test_build_config_falls_back_to_flags() -> None:
    cfg = build_config(sink="https://flag.example/api", scan_id="flag-scan")
    assert cfg is not None
    assert cfg.sink_url == "https://flag.example/api"
    assert cfg.scan_id == "flag-scan"


def test_build_config_none_without_sink_or_scan_id() -> None:
    assert build_config(sink=None, scan_id=None) is None
    assert build_config(sink="https://x/api", scan_id=None) is None


def test_events_flag_disables_per_finding_posts(monkeypatch: Any) -> None:
    monkeypatch.setenv("PWNKIT_CLOUD_EVENTS", "0")
    cfg = build_config(sink="https://x/api", scan_id="s")
    assert cfg is not None and cfg.events is False


# --- CLI wiring ------------------------------------------------------------

def test_cli_cloud_invokes_run_cloud_scan(monkeypatch: Any) -> None:
    from zeroverse import cli

    captured: dict[str, Any] = {}

    def fake_run(target: str, config: CloudSinkConfig, *, opts: Any) -> int:
        captured["target"] = target
        captured["sink"] = config.sink_url
        captured["scan_id"] = config.scan_id
        captured["token"] = config.token
        captured["model"] = opts.model
        return 0

    monkeypatch.setattr(cloud_sink, "run_cloud_scan", fake_run)
    monkeypatch.setenv("PWNKIT_CLOUD_TOKEN", "env-only-token")
    monkeypatch.delenv("PWNKIT_CLOUD_SINK", raising=False)
    monkeypatch.delenv("PWNKIT_CLOUD_SCAN_ID", raising=False)

    rc = cli.main([
        "scan", "/bin/vuln", "--cloud", "--scan-id", "cli-scan",
        "--sink", "https://cli.example/api", "--format", "ndjson",
        "--timeout", "1500", "--model", "glm-4.6",
    ])
    assert rc == 0
    assert captured["target"] == "/bin/vuln"
    assert captured["sink"] == "https://cli.example/api"   # flag (no env override)
    assert captured["scan_id"] == "cli-scan"
    assert captured["token"] == "env-only-token"            # token NEVER from argv
    assert captured["model"] == "glm-4.6"


def test_cli_cloud_usage_error_without_config(monkeypatch: Any) -> None:
    from zeroverse import cli

    monkeypatch.delenv("PWNKIT_CLOUD_SINK", raising=False)
    monkeypatch.delenv("PWNKIT_CLOUD_SCAN_ID", raising=False)
    # --cloud but neither flags nor env -> usage error (non-zero, no scan run).
    rc = cli.main(["scan", "/bin/vuln", "--cloud", "--format", "ndjson"])
    assert rc == 2


@pytest.mark.parametrize("conf", [True, False])
def test_mapper_status_matches_confirmed(conf: bool) -> None:
    cf = map_pov_to_finding(_pov(confirmed=conf))
    assert cf["status"] == ("confirmed" if conf else "unconfirmed")
