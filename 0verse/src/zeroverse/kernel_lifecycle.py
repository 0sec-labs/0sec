"""Plan authorized kernel lifecycle-variant campaigns without executing them.

The binary fuzzing pipeline is deliberately not a kernel executor.  This module
turns an already-reviewed patch and a curated sibling catalogue into a bounded,
inspectable campaign plan for the existing QEMU/KASAN infrastructure.  A plan is
never evidence of a vulnerability and cannot launch a VM or run a reproducer.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum


class RelationKind(StrEnum):
    SAME_CALLBACK = "same-callback"
    SAME_TEARDOWN = "same-teardown"
    SAME_SUBSYSTEM = "same-subsystem"


@dataclass(frozen=True)
class SiblingRelation:
    """A reviewed relationship to a known lifecycle family."""

    name: str
    relation: RelationKind
    symbols: tuple[str, ...]
    reproducer_template: str


@dataclass(frozen=True)
class LifecycleCandidate:
    """One non-executable lifecycle hypothesis derived from a reviewed patch."""

    candidate_id: str
    relation: SiblingRelation
    lifecycle_tokens: tuple[str, ...]
    changed_symbols: tuple[str, ...]
    required_evidence: tuple[str, ...] = (
        "authorized-qemu-kasan-receipt",
        "vulnerable-only-stable-signature",
        "patched-control-clean",
    )


@dataclass(frozen=True)
class LifecycleCampaignPlan:
    """Bounded input for a separately authorized campaign executor."""

    schema_version: str
    patch_sha256: str
    candidates: tuple[LifecycleCandidate, ...]
    executable: bool = False


@dataclass(frozen=True)
class LifecycleCampaignResult:
    """Evidence-only result shape for a future campaign adapter."""

    candidate_id: str
    direct_lifecycle_executed: bool
    kcov_reached: bool | None
    manager_admitted: bool | None
    kasan_differential_confirmed: bool
    evidence_digest: str = ""

    @property
    def confirmed(self) -> bool:
        return (
            self.direct_lifecycle_executed
            and self.kcov_reached is True
            and self.kasan_differential_confirmed
            and bool(self.evidence_digest)
        )


_TOKEN_PATTERNS: dict[str, re.Pattern[str]] = {
    "timer": re.compile(r"\b(?:del_timer(?:_sync)?|mod_timer|timer_setup)\b", re.I),
    "urb": re.compile(r"\b(?:usb_kill_urb|usb_free_urb|usb_submit_urb)\b", re.I),
    "workqueue": re.compile(r"\b(?:cancel_work_sync|flush_work|queue_work)\b", re.I),
    "unbind": re.compile(r"\b(?:disconnect|unbind|remove)\b", re.I),
    "free": re.compile(r"\b(?:kfree|devm_kfree|usb_free_urb|free)\b", re.I),
}
_FUNCTION_RE = re.compile(r"^\s*(?:[\w*]+\s+)+([A-Za-z_]\w*)\s*\(", re.M)


# Curated relations deliberately begin small.  They are reviewed metadata, not a
# broad source-search mechanism, and contain no host paths or executable payloads.
CURATED_SIBLINGS: tuple[SiblingRelation, ...] = (
    SiblingRelation(
        "hid-sony-ghl-timer-urb",
        RelationKind.SAME_TEARDOWN,
        ("ghl_poke_timer", "ghl_urb", "ghl_remove"),
        "hid-sony-ghl-timer-uaf",
    ),
    SiblingRelation(
        "uclogic-inrange-timer",
        RelationKind.SAME_CALLBACK,
        ("inrange_timer", "remove", "disconnect"),
        "uclogic-inrange-timer-uaf",
    ),
    SiblingRelation(
        "ipheth-carrier-work",
        RelationKind.SAME_CALLBACK,
        ("carrier_work", "disconnect", "cancel_work_sync"),
        "ipheth-carrier-work-uaf",
    ),
    SiblingRelation(
        "hid-multitouch-release-timer",
        RelationKind.SAME_SUBSYSTEM,
        ("release_timer", "remove", "del_timer_sync"),
        "hid-multitouch-release-timer-uaf",
    ),
)


def extract_lifecycle_tokens(patch_text: str) -> tuple[str, ...]:
    """Return conservative lifecycle vocabulary observed in a patch diff."""
    return tuple(name for name, pattern in _TOKEN_PATTERNS.items() if pattern.search(patch_text))


def extract_changed_symbols(patch_text: str) -> tuple[str, ...]:
    """Extract function declarations added or removed by a unified patch."""
    symbols: set[str] = set()
    for line in patch_text.splitlines():
        if not line.startswith(("+", "-")) or line.startswith(("+++", "---")):
            continue
        match = _FUNCTION_RE.match(line[1:])
        if match:
            symbols.add(match.group(1))
    return tuple(sorted(symbols))


def _matches(relation: SiblingRelation, tokens: Iterable[str], symbols: Iterable[str]) -> bool:
    lower_symbols = " ".join(symbols).lower()
    token_set = set(tokens)
    if relation.relation is RelationKind.SAME_TEARDOWN:
        return bool({"unbind", "free"} & token_set) or any(
            word in lower_symbols for word in ("remove", "disconnect", "release")
        )
    if relation.relation is RelationKind.SAME_CALLBACK:
        return bool({"timer", "workqueue"} & token_set)
    return bool(token_set)


def plan_lifecycle_campaign(
    patch_text: str,
    *,
    siblings: tuple[SiblingRelation, ...] = CURATED_SIBLINGS,
) -> LifecycleCampaignPlan:
    """Create a deterministic, non-executable campaign plan from reviewed text."""
    if not patch_text.strip():
        raise ValueError("patch_text must not be empty")
    digest = hashlib.sha256(patch_text.encode()).hexdigest()
    tokens = extract_lifecycle_tokens(patch_text)
    symbols = extract_changed_symbols(patch_text)
    candidates = tuple(
        LifecycleCandidate(
            candidate_id=hashlib.sha256(f"{digest}:{relation.name}".encode()).hexdigest()[:16],
            relation=relation,
            lifecycle_tokens=tokens,
            changed_symbols=symbols,
        )
        for relation in siblings
        if _matches(relation, tokens, symbols)
    )
    return LifecycleCampaignPlan(
        schema_version="0verse.kernel-lifecycle/v1",
        patch_sha256=digest,
        candidates=candidates,
    )
