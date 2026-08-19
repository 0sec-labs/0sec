#!/usr/bin/env python3
"""Capability-scoped bridge to CyberGym's private differential verifier.

Run this only on the benchmark host. Agent containers receive a token that is
valid for exactly one generated agent ID and one final PoC record; the verifier
API key and the shared SQLite database never enter the agent container.
"""

from __future__ import annotations

import secrets
import argparse
import json
import logging
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
from cybergym.server.pocdb import PoCRecord, Session, init_engine

LOG = logging.getLogger("cybergym.oracle_bridge")


@dataclass(frozen=True)
class Capability:
    agent_id: str


class OracleBridge:
    def __init__(self, *, api_key: str, capabilities_path: Path, db_path: Path, server: str):
        self._api_key = api_key
        self._capabilities_path = capabilities_path
        self._engine = init_engine(db_path)
        self._server = server.rstrip("/")
        self._lock = threading.Lock()

    def verify(self, token: str | None, agent_id: str | None, poc_id: str | None) -> dict[str, Any]:
        if not token or not agent_id or not poc_id:
            raise PermissionError("missing bridge capability, agent_id, or poc_id")

        with self._lock:
            capabilities = self._load_capabilities()
            raw = capabilities.get(token)
            if not isinstance(raw, dict) or raw.get("used") is True:
                raise PermissionError("invalid or consumed bridge capability")
            expected_agent_id = raw.get("agent_id")
            if not isinstance(expected_agent_id, str) or agent_id != expected_agent_id:
                raise PermissionError("bridge capability is not valid for this agent")
            # One final verification per capability. Consume before remote work so
            # a concurrent request cannot turn a one-submit task into a probe loop.
            raw["used"] = True
            self._write_capabilities(capabilities)

        response = httpx.post(
            f"{self._server}/verify-agent-pocs",
            json={"agent_id": expected_agent_id},
            headers={"X-API-Key": self._api_key},
            timeout=1200.0,
        )
        response.raise_for_status()

        with Session(self._engine) as session:
            record = (
                session.query(PoCRecord)
                .filter(PoCRecord.agent_id == expected_agent_id, PoCRecord.poc_id == poc_id)
                .one_or_none()
            )
            if record is None:
                raise LookupError("verifier returned no record for the submitted PoC")
            return record.to_dict()

    def _load_capabilities(self) -> dict[str, dict[str, Any]]:
        try:
            parsed = json.loads(self._capabilities_path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError("bridge capability store is unavailable") from error
        return parsed if isinstance(parsed, dict) else {}

    def _write_capabilities(self, capabilities: dict[str, dict[str, Any]]) -> None:
        tmp = self._capabilities_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(capabilities, separators=(",", ":")) + "\n")
        tmp.chmod(0o600)
        tmp.replace(self._capabilities_path)


def make_handler(bridge: OracleBridge):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (HTTP handler API)
            if self.path != "/health":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802 (HTTP handler API)
            if self.path != "/verify":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                if content_length <= 0 or content_length > 8192:
                    raise ValueError("invalid request length")
                payload = json.loads(self.rfile.read(content_length))
                if not isinstance(payload, dict):
                    raise ValueError("request body must be an object")
                record = bridge.verify(
                    self.headers.get("X-CyberGym-Bridge-Token"),
                    payload.get("agent_id"),
                    payload.get("poc_id"),
                )
            except PermissionError:
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            except (ValueError, json.JSONDecodeError):
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            except (httpx.HTTPError, LookupError) as error:
                LOG.warning("differential verification failed: %s", error)
                self.send_error(HTTPStatus.BAD_GATEWAY)
                return

            body = json.dumps(record, default=str).encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            LOG.info("%s - %s", self.client_address[0], format % args)

    return Handler


def issue_capability(capabilities_path: Path, agent_id: str) -> str:
    capabilities_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        parsed = json.loads(capabilities_path.read_text()) if capabilities_path.exists() else {}
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit("capability file is unreadable") from error
    if not isinstance(parsed, dict):
        raise SystemExit("capability file must be a JSON object")
    token = secrets.token_urlsafe(32)
    parsed[token] = {"agent_id": agent_id, "used": False}
    tmp = capabilities_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(parsed, separators=(",", ":")) + "\n")
    tmp.chmod(0o600)
    tmp.replace(capabilities_path)
    return token


def revoke_capability(capabilities_path: Path, token: str) -> None:
    try:
        parsed = json.loads(capabilities_path.read_text()) if capabilities_path.exists() else {}
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit("capability file is unreadable") from error
    if not isinstance(parsed, dict):
        raise SystemExit("capability file must be a JSON object")
    parsed.pop(token, None)
    tmp = capabilities_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(parsed, separators=(",", ":")) + "\n")
    tmp.chmod(0o600)
    tmp.replace(capabilities_path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    issue = sub.add_parser("issue", help="create one capability for a generated task")
    issue.add_argument("--capabilities", type=Path, required=True)
    issue.add_argument("--agent-id", required=True)

    revoke = sub.add_parser("revoke", help="remove an unused or consumed capability")
    revoke.add_argument("--capabilities", type=Path, required=True)
    revoke.add_argument("--token", required=True)

    serve = sub.add_parser("serve", help="serve capability-scoped differential verification")
    serve.add_argument("--host", required=True)
    serve.add_argument("--port", type=int, default=8667)
    serve.add_argument("--server", required=True)
    serve.add_argument("--api-key-file", type=Path, required=True)
    serve.add_argument("--capabilities", type=Path, required=True)
    serve.add_argument("--pocdb-path", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "issue":
        print(issue_capability(args.capabilities, args.agent_id))
        return
    if args.command == "revoke":
        revoke_capability(args.capabilities, args.token)
        return

    api_key = args.api_key_file.read_text().strip()
    if not api_key:
        raise SystemExit("API key file is empty")
    if not args.capabilities.is_file():
        raise SystemExit("capability file does not exist")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    server = ThreadingHTTPServer((args.host, args.port), make_handler(
        OracleBridge(
            api_key=api_key,
            capabilities_path=args.capabilities,
            db_path=args.pocdb_path,
            server=args.server,
        )
    ))
    LOG.info("oracle bridge listening on %s:%d", args.host, args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
