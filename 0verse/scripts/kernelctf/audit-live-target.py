#!/usr/bin/env python3
"""Compare the authenticated kernelCTF banner with a target snapshot."""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
from pathlib import Path


TARGET_RE = re.compile(
    r"^\s*-\s+(?P<release>lts-[0-9.]+)\s+\|\s+"
    r"Release date:\s+(?P<date>[^|]+?)\s+\|\s+"
    r"(?P<slot>Slot is (?:free|taken by \S+))",
    re.MULTILINE,
)


def parse_banner(text: str) -> dict[str, str]:
    match = TARGET_RE.search(text)
    if not match:
        raise ValueError("current LTS target is absent from banner")
    slot_text = match.group("slot")
    if slot_text == "Slot is free":
        status, holder = "free", ""
    else:
        status, holder = "taken", slot_text.removeprefix("Slot is taken by ")
    return {
        "release": match.group("release"),
        "release_date": match.group("date").strip(),
        "slot_status": status,
        "slot_holder": holder,
    }


def read_banner(host: str, port: int, cafile: Path, timeout: float) -> str:
    context = ssl.create_default_context(cafile=str(cafile))
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.settimeout(timeout)
            chunks: list[bytes] = []
            while sum(map(len, chunks)) < 64 * 1024:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"Select a target" in b"".join(chunks):
                    break
    return b"".join(chunks).decode("utf-8", "replace")


def compare(snapshot: dict[str, object], live: dict[str, str]) -> list[str]:
    changes = []
    for key in ("release", "slot_status", "slot_holder"):
        expected = str(snapshot.get(key, ""))
        if expected != live[key]:
            changes.append(f"{key}: snapshot={expected!r} live={live[key]!r}")
    return changes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("cafile", type=Path)
    parser.add_argument("--host", default="kernelctf.vrp.ctfcompetition.com")
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()

    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    live = parse_banner(read_banner(args.host, args.port, args.cafile, args.timeout))
    changes = compare(snapshot, live)
    print(json.dumps({"changes": changes, "live": live}, sort_keys=True))
    return 1 if changes else 0


if __name__ == "__main__":
    raise SystemExit(main())
