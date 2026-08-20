"""M5 #29 — the MCP bridge tool handlers, driven by a fake transport.

No network, no MCP SDK required: tests drive the transport-free ``Engine`` +
``dispatch`` + the JSON-RPC ``handle_rpc``/``serve_stub`` loop directly, with
``api.scan`` monkeypatched to a deterministic fake so no real engine runs.
"""

from __future__ import annotations

import io
import json

import pytest

from zeroverse import mcp
from zeroverse.api import ScanFinding, ScanResult


def _fake_result(path: str) -> ScanResult:
    f = ScanFinding(
        id="abc123", bug_class="CWE-78", severity="high", file=path, function="main",
        offset="0x401000", source="getenv", sink="system", confirmed=True,
        hypothesis=True, pruned=False, capability="command-exec",
        pov_path="", repro_cmd="", dedup_bucket="b1", explanation="cmd injection",
    )
    return ScanResult(
        contract_version="1.0", tool={"name": "0verse", "version": "0.0.1"},
        binary=path, format="ELF", arch="x86-64", backend="rizin",
        triage="ELF x86-64", stages_run=["ingest", "analyze", "dynamic"],
        findings=[f], note="",
    )


@pytest.fixture
def engine(monkeypatch) -> mcp.Engine:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(mcp, "scan", lambda path, opts=None: _fake_result(str(path)))
    return mcp.Engine()


def test_tools_list_exposes_the_four_tools() -> None:
    names = {t["name"] for t in mcp.TOOLS}
    assert names == {"scan_binary", "list_findings", "get_pov", "get_report"}
    for t in mcp.TOOLS:
        assert "inputSchema" in t and t["inputSchema"]["type"] == "object"


def test_dispatch_scan_then_list_then_pov(engine: mcp.Engine) -> None:
    summary = json.loads(mcp.dispatch(engine, "scan_binary", {"path": "/bin/x"}))
    assert summary["findings"] == 1 and summary["confirmed"] == 1
    findings = json.loads(mcp.dispatch(engine, "list_findings", {}))
    assert findings[0]["sink"] == "system"
    pov = json.loads(mcp.dispatch(engine, "get_pov", {"finding_id": "abc123"}))
    assert pov["confirmed"] is True and pov["id"] == "abc123"


def test_get_report_returns_ndjson(engine: mcp.Engine) -> None:
    mcp.dispatch(engine, "scan_binary", {"path": "/bin/x"})
    report = mcp.dispatch(engine, "get_report", {"format": "ndjson"})
    head = json.loads(report.splitlines()[0])
    assert head["_meta"]["contract_version"] == "1.0"


def test_errors_are_tool_errors_not_crashes(engine: mcp.Engine) -> None:
    with pytest.raises(mcp.ToolError):
        engine.list_findings()  # nothing scanned yet
    with pytest.raises(mcp.ToolError):
        mcp.dispatch(engine, "nonexistent", {})
    mcp.dispatch(engine, "scan_binary", {"path": "/bin/x"})
    with pytest.raises(mcp.ToolError):
        engine.get_pov("does-not-exist")


def test_jsonrpc_stub_full_handshake(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # The fallback stub transport: feed initialize -> tools/list -> tools/call over
    # in-memory stdio and read the JSON-RPC responses back.
    monkeypatch.setattr(mcp, "scan", lambda path, opts=None: _fake_result(str(path)))
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},  # notification: no reply
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "scan_binary", "arguments": {"path": "/bin/x"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "list_findings", "arguments": {}}},
    ]
    stdin = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
    stdout = io.StringIO()
    mcp.serve_stub(stdin=stdin, stdout=stdout)

    responses = [json.loads(ln) for ln in stdout.getvalue().splitlines() if ln.strip()]
    by_id = {r.get("id"): r for r in responses}
    # the notification produced no response.
    assert set(by_id) == {1, 2, 3, 4}
    assert by_id[1]["result"]["serverInfo"]["name"] == "0verse"
    assert {t["name"] for t in by_id[2]["result"]["tools"]} == {
        "scan_binary", "list_findings", "get_pov", "get_report"}
    call = by_id[3]["result"]
    assert call["isError"] is False
    assert json.loads(call["content"][0]["text"])["confirmed"] == 1
    findings = json.loads(by_id[4]["result"]["content"][0]["text"])
    assert findings[0]["sink"] == "system"


def test_jsonrpc_stub_tool_error_is_iserror() -> None:
    stdin = io.StringIO(json.dumps(
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
         "params": {"name": "list_findings", "arguments": {}}}) + "\n")
    stdout = io.StringIO()
    mcp.serve_stub(stdin=stdin, stdout=stdout)
    resp = json.loads(stdout.getvalue().strip())
    assert resp["result"]["isError"] is True  # "no scan yet" -> tool error, not a crash
