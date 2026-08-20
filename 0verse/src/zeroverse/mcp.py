"""GhidraMCP-style MCP bridge (M5 #29, ``integration:mcp``).

A stdio MCP server that exposes the 0verse engine as tools an external agent
(Claude Desktop, Cursor, …) can call:

    scan_binary(path, backend?)   run the pipeline on a binary -> run summary
    list_findings()               the findings from the last scan (contract shape)
    get_pov(finding_id)           the reproducing PoV (script + repro command)
    get_report(format?)           the full report (md | json | ndjson | sarif)

Every tool is a thin wrapper over the embeddable ``zeroverse.api`` (#28), so the
MCP surface and any other consumer share one engine and one versioned contract.

Transport: prefers the official MCP Python SDK (``pip install mcp``); when it is
not importable it falls back to a minimal JSON-RPC-2.0-over-stdio loop that
implements ``initialize`` / ``tools/list`` / ``tools/call`` per the MCP wire
schema. The tool *handlers* (``Engine`` + ``dispatch``) are transport-free and
fully unit-testable with a fake transport — no network, no SDK required.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .api import CONTRACT_VERSION, ScanOptions, ScanResult, format_result, scan

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "0verse", "version": __version__}

# --- tool schema (MCP `tools/list` payload) --------------------------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "scan_binary",
        "description": (
            "Run the 0verse discovery pipeline on a binary (ELF/PE/Mach-O) and "
            "return a run summary. Confirmed findings carry a reproducing PoV "
            "(PoV-is-truth). Caches the result for list_findings/get_pov/get_report."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "path to the target binary"},
                "backend": {
                    "type": "string",
                    "enum": ["auto", "ghidra", "rizin", "angr"],
                    "description": "decompiler backend (default auto)",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_findings",
        "description": "Findings from the most recent scan_binary call (versioned contract shape).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_pov",
        "description": ("The reproducing PoV for a finding id: replay script path, "
                        "repro command, and the script body when present."),
        "inputSchema": {
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
        },
    },
    {
        "name": "get_report",
        "description": "The full report from the last scan in the requested format.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": ["json", "ndjson", "sarif"]},
            },
        },
    },
]

# M7 #43 — the flywheel recall tool, matching the Crystalline MCP-server shape.
# Registered only when the flywheel is opt-in enabled (ZEROVERSE_FLYWHEEL=1); the
# base four tools above are always present. Memory is queryable + carries a
# cost-router verdict, but it PRIMES only — it never confirms a finding.
RECALL_TOOL: dict[str, Any] = {
    "name": "recall_similar",
    "description": (
        "Recall the most-similar prior knowledge for a new target from the preseeded "
        "5-layer memory (archetype principles/semantics/procedures + past confirmed "
        "PoVs + fleet cross-target links). Returns ranked memories and a cost-router "
        "verdict ('cheap' when nothing similar is known -> the caller may skip the "
        "expensive LLM). Memory PRIMES; the PoV oracle still adjudicates."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "format": {"type": "string", "description": "target binary format (ELF/PE/Mach-O)"},
            "arch": {"type": "string", "description": "target arch (e.g. x86-64, arm64)"},
            "bits": {"type": "integer"},
            "bug_class": {"type": "string", "description": "requested/known bug class, optional"},
            "sinks": {"type": "array", "items": {"type": "string"}},
            "sources": {"type": "array", "items": {"type": "string"}},
            "k": {"type": "integer", "description": "max memories to return (default 5)"},
        },
    },
}


def active_tools() -> list[dict[str, Any]]:
    """The advertised tool set: the always-present base four, plus ``recall_similar``
    when the flywheel is opt-in enabled (ZEROVERSE_FLYWHEEL=1, default OFF)."""
    from .flywheel import flywheel_enabled

    return [*TOOLS, RECALL_TOOL] if flywheel_enabled() else list(TOOLS)


class ToolError(Exception):
    """A tool-level error (bad arguments / no prior scan)."""


class Engine:
    """Holds engine state between tool calls (the last scan's result)."""

    def __init__(self) -> None:
        self._last: ScanResult | None = None

    def scan_binary(self, path: str, backend: str | None = None) -> dict[str, Any]:
        if not path:
            raise ToolError("scan_binary requires a 'path'")
        result = scan(path, ScanOptions(backend=backend))
        self._last = result
        return {
            "binary": result.binary,
            "format": result.format,
            "arch": result.arch,
            "backend": result.backend,
            "stages_run": result.stages_run,
            "findings": len(result.findings),
            "confirmed": result.confirmed_count,
            "terminal_state": result.terminal_state,
            "status_reason": result.status_reason,
            "contract_version": result.contract_version,
            "note": result.note,
        }

    def _require_last(self) -> ScanResult:
        if self._last is None:
            raise ToolError("no scan yet — call scan_binary first")
        return self._last

    def list_findings(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self._require_last().findings]

    def get_pov(self, finding_id: str) -> dict[str, Any]:
        last = self._require_last()
        for f in last.findings:
            if f.id == finding_id:
                body = ""
                if f.pov_path and Path(f.pov_path).is_file():
                    body = Path(f.pov_path).read_text()
                return {
                    "id": f.id,
                    "confirmed": f.confirmed,
                    "bug_class": f.bug_class,
                    "capability": f.capability,
                    "pov_path": f.pov_path,
                    "repro_cmd": f.repro_cmd,
                    "script": body,
                }
        raise ToolError(f"no finding with id {finding_id!r}")

    def get_report(self, fmt: str = "json") -> str:
        if fmt not in ("json", "ndjson", "sarif"):
            raise ToolError(f"unsupported format {fmt!r}")
        return format_result(self._require_last(), fmt)

    def recall_similar(self, args: dict[str, Any]) -> dict[str, Any]:
        """M7 #43 — query the preseeded flywheel memory for a target. Builds the
        memory from the 90 archetypes + the operator's #32 corpus
        (``ZEROVERSE_DATASET_PATH``) and returns ranked recalls + the cost-router
        verdict. Read-only; it never scans, never confirms."""
        from . import flywheel

        features = {
            "format": args.get("format", ""),
            "arch": args.get("arch", ""),
            "bits": args.get("bits", 0) or 0,
        }
        query = flywheel.TargetQuery.from_features(
            features,
            bug_class=str(args.get("bug_class", "")),
            sinks=args.get("sinks") or (),
            sources=args.get("sources") or (),
        )
        fw = flywheel.Flywheel(dataset_path=os.environ.get("ZEROVERSE_DATASET_PATH"))
        return fw.recall_dict(query, k=int(args.get("k", 5) or 5))


def dispatch(engine: Engine, name: str, arguments: dict[str, Any]) -> str:
    """Run a tool and return its text result (JSON for structured tools). Raises
    ``ToolError`` for unknown tools / bad args — the transport renders that as an
    MCP tool error, never a crash."""
    args = arguments or {}
    if name == "scan_binary":
        return json.dumps(engine.scan_binary(args.get("path", ""), args.get("backend")), indent=2)
    if name == "list_findings":
        return json.dumps(engine.list_findings(), indent=2)
    if name == "get_pov":
        return json.dumps(engine.get_pov(args.get("finding_id", "")), indent=2)
    if name == "get_report":
        return engine.get_report(args.get("format", "json"))
    if name == "recall_similar":
        return json.dumps(engine.recall_similar(args), indent=2)
    raise ToolError(f"unknown tool {name!r}")


# --- JSON-RPC-over-stdio stub (used when the MCP SDK is absent) -------------

def _rpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_rpc(engine: Engine, request: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC request object, return the response object (or None for
    a notification). Conforms to the MCP method set."""
    method = request.get("method")
    req_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        return _rpc_result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
            "instructions": f"0verse engine, result contract v{CONTRACT_VERSION}",
        })
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "tools/list":
        return _rpc_result(req_id, {"tools": active_tools()})
    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            text = dispatch(engine, name, arguments)
            return _rpc_result(req_id, {
                "content": [{"type": "text", "text": text}],
                "isError": False,
            })
        except ToolError as exc:
            return _rpc_result(req_id, {
                "content": [{"type": "text", "text": str(exc)}],
                "isError": True,
            })
    if method == "ping":
        return _rpc_result(req_id, {})
    return _rpc_error(req_id, -32601, f"method not found: {method}")


def serve_stub(stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
    """Minimal newline-delimited JSON-RPC loop over stdio (MCP fallback)."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    engine = Engine()
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle_rpc(engine, request)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


# --- official MCP SDK transport (preferred) --------------------------------

def _serve_sdk() -> bool:
    """Serve over the official MCP SDK. Returns False if the SDK isn't installed."""
    try:
        import anyio
        import mcp.types as types
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
    except Exception:
        return False

    engine = Engine()
    server: Any = Server("0verse")

    @server.list_tools()  # type: ignore[untyped-decorator]
    async def _list_tools() -> list[Any]:
        return [
            types.Tool(name=t["name"], description=t["description"],
                       inputSchema=t["inputSchema"])
            for t in active_tools()
        ]

    @server.call_tool()  # type: ignore[untyped-decorator]
    async def _call_tool(name: str, arguments: dict[str, Any]) -> list[Any]:
        try:
            text = dispatch(engine, name, arguments)
        except ToolError as exc:
            return [types.TextContent(type="text", text=str(exc))]
        return [types.TextContent(type="text", text=text)]

    async def _run() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(_run)
    return True


def main() -> int:
    if not _serve_sdk():
        serve_stub()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
