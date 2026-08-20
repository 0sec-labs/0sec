"""Data-driven seed catalog — the auditable provenance layer for 0verse's seeds.

The 90 mined bug archetypes (kernel / userland / firmware, 2023-2025 CVE-grounded)
live as *data* in ``data/archetypes.json`` (GENERALIZED patterns only — no exploit
code), not scattered through code comments. Each archetype is cross-referenced to
the engine lens / seed-class that implements it (``engine_lens``) and a ``route``
describing how it is detected and confirmed, so the set is maintainable and the
provenance is documented (``docs/SEEDS.md``).

This module is the typed loader + a handful of audit queries. It is intentionally
inert at import time beyond reading the bundled JSON: the *detection* lives in
``bugclasses.py`` / ``seedbugs.py``; this is the registry that records what each
archetype maps to and why.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

# Routes that mean "a 0verse lens/oracle can statically detect or dynamically
# confirm this on a binary" vs. routes that are honest hand-offs.
CONFIRMABLE_ROUTES: frozenset[str] = frozenset(
    {"userland-confirmable", "userland-med", "firmware-lane"}
)
STATIC_DETECT_ROUTES: frozenset[str] = frozenset(
    {"kernel-static", "userland-confirmable", "userland-med", "userland-hypothesis",
     "firmware-lane", "firmware-lane-partial", "firmware-detect-only"}
)
VERIFY_LANE_ROUTES: frozenset[str] = frozenset({"kernel-verify"})


@dataclass(frozen=True)
class Archetype:
    """One mined bug archetype + its cross-reference into the 0verse engine."""

    uid: str                     # "<domain>/<orig-id>", e.g. "kernel/DRV-01"
    id: str                      # original catalog id, e.g. "DRV-01"
    domain: str                  # "kernel" | "userland" | "firmware"
    name: str
    cwe: str
    pattern: str
    detection_signature: str
    grounding: list[str]         # public CVE/advisory witnesses (not the pattern)
    confirmable: str
    engine_lens: str | None      # implementing lens/seed id, or None (unmapped)
    route: str
    extra: dict[str, Any]        # domain-specific (subsystem/category/lens/fp_trap/…)

    @property
    def implemented(self) -> bool:
        """True when a 0verse lens / seed-class implements this archetype."""
        return self.engine_lens is not None

    @property
    def hypothesis_only(self) -> bool:
        """True when the archetype is routed to the kernel-verify lane or is not
        bare-binary detectable — surfaced as a hypothesis, never auto-confirmed."""
        return self.route in VERIFY_LANE_ROUTES or self.route == "not-binary-detectable"


_KNOWN = {
    "uid", "id", "domain", "name", "cwe", "pattern", "detection_signature",
    "grounding", "confirmable", "engine_lens", "route",
}


@lru_cache(maxsize=1)
def _raw() -> dict[str, Any]:
    text = resources.files("zeroverse.data").joinpath("archetypes.json").read_text(
        encoding="utf-8"
    )
    data: dict[str, Any] = json.loads(text)
    return data


@lru_cache(maxsize=1)
def load_archetypes() -> tuple[Archetype, ...]:
    """Load every consolidated archetype (cached). Pure data — never executes the
    patterns, only records them."""
    out: list[Archetype] = []
    for r in _raw()["archetypes"]:
        out.append(Archetype(
            uid=r["uid"], id=r["id"], domain=r["domain"], name=r["name"],
            cwe=r["cwe"], pattern=r["pattern"],
            detection_signature=r["detection_signature"],
            grounding=list(r.get("grounding", [])),
            confirmable=r.get("confirmable", ""),
            engine_lens=r.get("engine_lens"), route=r["route"],
            extra={k: v for k, v in r.items() if k not in _KNOWN},
        ))
    return tuple(out)


def provenance() -> str:
    return str(_raw().get("provenance", ""))


def by_domain(domain: str) -> list[Archetype]:
    return [a for a in load_archetypes() if a.domain == domain]


def by_lens(engine_lens: str) -> list[Archetype]:
    """Every archetype implemented by a given engine lens/seed id (e.g.
    ``"bugclass:cmdi"`` or ``"seed:linux-ko:selector-index"``)."""
    return [a for a in load_archetypes() if a.engine_lens == engine_lens]


def implemented() -> list[Archetype]:
    return [a for a in load_archetypes() if a.implemented]


def hypothesis_only() -> list[Archetype]:
    return [a for a in load_archetypes() if a.hypothesis_only]


def for_route(route: str) -> list[Archetype]:
    return [a for a in load_archetypes() if a.route == route]


def summary() -> dict[str, int]:
    """Audit counts: total, implemented, and per-route — the maintainable view of
    'which seeds are detectable-and-useful vs hypothesis-only'."""
    archs = load_archetypes()
    counts: dict[str, int] = {"total": len(archs), "implemented": len(implemented())}
    for a in archs:
        counts[a.route] = counts.get(a.route, 0) + 1
    return counts
