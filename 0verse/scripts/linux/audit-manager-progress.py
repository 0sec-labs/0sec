#!/usr/bin/env python3
"""Fail when a syzkaller manager's execution counter stops advancing."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from http.client import HTTPConnection
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit


def parse_metrics(text: str) -> tuple[int, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        if line.startswith(("syz_exec_total ", "syz_corpus_cover ")):
            name, raw = line.split(None, 1)
            values[name] = int(float(raw))
    missing = {"syz_exec_total", "syz_corpus_cover"} - values.keys()
    if missing:
        raise ValueError(f"missing metrics: {', '.join(sorted(missing))}")
    return values["syz_exec_total"], values["syz_corpus_cover"]


def _loopback_endpoint(url: str) -> tuple[str, int, str]:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.username or parsed.password:
        raise ValueError("metrics URL must be unauthenticated HTTP")
    if parsed.path not in {"", "/metrics"} or parsed.query or parsed.fragment:
        raise ValueError("metrics URL path must be /metrics")
    host = parsed.hostname
    if host is None:
        raise ValueError("metrics URL has no host")
    if host != "localhost":
        try:
            if not ip_address(host).is_loopback:
                raise ValueError("metrics URL host must be loopback")
        except ValueError as exc:
            raise ValueError("metrics URL host must be localhost or a loopback IP") from exc
    return host, parsed.port or 80, "/metrics"


def fetch(url: str) -> tuple[int, int]:
    host, port, path = _loopback_endpoint(url)
    connection = HTTPConnection(host, port, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"metrics endpoint returned HTTP {response.status}")
        return parse_metrics(response.read().decode("utf-8", "replace"))
    finally:
        connection.close()


def load_state(path: Path) -> dict[str, dict[str, int]]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("progress state must be an object")
    return raw


def save_state(path: Path, state: dict[str, dict[str, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(state, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        Path(temporary).replace(path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def classify_progress(
    prior: dict[str, int] | None,
    executions: int,
    now: int,
    minimum_interval: int,
) -> tuple[str, int, int, bool]:
    """Return state, delta, elapsed, and whether the new sample should be retained."""
    if prior is None:
        return "BASELINE", 0, 0, True
    delta = executions - int(prior["executions"])
    elapsed = max(1, now - int(prior["sampled_at"]))
    if elapsed < minimum_interval:
        return "TOO_SOON", delta, elapsed, False
    if delta == 0:
        return "STALLED", delta, elapsed, True
    if delta < 0:
        return "RESET", delta, elapsed, True
    return "LIVE", delta, elapsed, True


def classify_coverage(
    prior: dict[str, int] | None, coverage: int, now: int
) -> tuple[int, int, int]:
    """Return coverage delta, last-change time, and stagnant duration."""
    if prior is None:
        return 0, now, 0
    delta = coverage - int(prior["coverage"])
    changed_at = (
        now
        if delta != 0
        else int(prior.get("coverage_changed_at", prior["sampled_at"]))
    )
    return delta, changed_at, max(0, now - changed_at)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--minimum-interval", type=int, default=60)
    parser.add_argument("lane", nargs="+", help="NAME=METRICS_URL")
    args = parser.parse_args()
    previous = load_state(args.state)
    current = dict(previous)
    now = int(time.time())
    failures = 0

    for spec in args.lane:
        name, separator, url = spec.partition("=")
        if not separator or not name or not url:
            parser.error(f"invalid lane specification: {spec!r}")
        try:
            executions, coverage = fetch(url)
        except Exception as exc:  # network/parser errors are audit failures
            print(f"ERROR   {name:<10} {exc}")
            failures += 1
            continue
        prior = previous.get(name)
        status, delta, elapsed, retain = classify_progress(
            prior, executions, now, args.minimum_interval
        )
        coverage_delta, coverage_changed_at, stagnant_for = classify_coverage(
            prior, coverage, now
        )
        if retain:
            current[name] = {
                "executions": executions,
                "coverage": coverage,
                "sampled_at": now,
                "coverage_changed_at": coverage_changed_at,
            }
        if status == "BASELINE":
            print(f"BASELINE {name:<10} exec={executions} cover={coverage}")
            continue
        if status == "TOO_SOON":
            print(
                f"TOO_SOON {name:<10} elapsed={elapsed}s; "
                f"minimum={args.minimum_interval}s"
            )
            continue
        if status == "STALLED":
            print(f"STALLED {name:<10} exec={executions} elapsed={elapsed}s")
            failures += 1
        elif status == "RESET":
            print(
                f"RESET   {name:<10} exec={executions} "
                f"prior={prior['executions']} cover={coverage} "
                f"cover_delta={coverage_delta:+d} stagnant={stagnant_for}s"
            )
        else:
            print(
                f"LIVE    {name:<10} exec={executions} delta={delta} "
                f"rate={delta / elapsed:.1f}/s cover={coverage} "
                f"cover_delta={coverage_delta:+d} stagnant={stagnant_for}s"
            )

    save_state(args.state, current)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
