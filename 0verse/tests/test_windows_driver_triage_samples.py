"""Live ground-truth validation of the driver-triage harness on the regression set.

Runs the full :func:`zeroverse.windows_driver_triage.triage_driver` on the three
hash-pinned BYOVD samples and asserts, per ``benchmarks/windows_driver_corpus/
manifest.json``: the no-ACL pre-filter flags each world-accessible, the dispatch handler
is recovered, the artifact bytes match the pinned SHA-256, and the documented
known-vulnerable IOCTL sink lands in the top-N ranked candidates.

Skips (never fails) when r2/r2pipe is unavailable or the private CAS is not present, so
CI without the corpus stays green — the binaries are the private moat, never committed.
Point ``ZEROVERSE_WINDOWS_CAS`` at the store (default ``<repo>/private/windows-cas``).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from zeroverse.backends.rizin import r2_available
from zeroverse.windows_driver_triage import sha256_file, triage_driver

_REPO = Path(__file__).resolve().parents[1]
_MANIFEST = _REPO / "benchmarks" / "windows_driver_corpus" / "manifest.json"


def _cas_root() -> Path:
    return Path(os.environ.get("ZEROVERSE_WINDOWS_CAS") or (_REPO / "private" / "windows-cas"))


def _samples() -> list[dict]:
    return json.loads(_MANIFEST.read_text())["samples"]


def _artifact(sha: str) -> Path:
    return _cas_root() / sha / "artifact"


pytestmark = pytest.mark.skipif(
    not r2_available(), reason="r2/r2pipe not installed"
)


@pytest.mark.parametrize("sample", _samples(), ids=lambda s: s["name"])
def test_sample_triage_matches_ground_truth(sample: dict) -> None:
    art = _artifact(sample["sha256"])
    if not art.is_file():
        pytest.skip(f"{sample['name']} not in CAS ({art}) — private corpus absent")

    assert sha256_file(art) == sample["sha256"], "CAS artifact hash mismatch"

    rec = triage_driver(art)
    exp = sample["expect"]

    assert rec.world_accessible is exp["world_accessible"], rec.prefilter_reason
    if exp.get("handler_recovered"):
        assert rec.dispatch_handlers, "no IRP_MJ_DEVICE_CONTROL dispatch handler recovered"

    ranked = [s.addr for s in rec.sinks]
    known = {int(a, 16) for a in exp["known_vuln_sink_addrs"]}
    hit_ranks = [i + 1 for i, a in enumerate(ranked) if a in known]
    assert hit_ranks, f"known-vuln sink {exp['known_vuln_sink_addrs']} not surfaced"
    assert min(hit_ranks) <= exp["max_rank"], (
        f"best known-sink rank {min(hit_ranks)} > allowed {exp['max_rank']}"
    )
