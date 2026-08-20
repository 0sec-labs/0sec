"""Ground-truth evaluation scoring + corpus manifest (M6 eval harness).

The credibility instrument: it measures whether 0verse actually surfaces *real,
known* bugs (**recall**) without crying wolf on clean code (**FP rate**), on a
corpus of bugs it was **not** seeded on (**held-out**). This module is the
*typed, unit-tested* half — the manifest loader + the scorer math — kept in
``src`` so it is checked by ``mypy --strict`` and ``pytest`` against fixtures,
separate from the (engine-heavy, Ghidra-driving) runner in
``benchmarks/groundtruth/run.py``.

The whole point is honesty: a scan's findings are scored against ground truth
with **no cherry-picking**. A miss is a miss, a false positive is a false
positive, and a true bug that only ever became a *hypothesis* (no reproducing
PoV) is counted separately from one the oracle **confirmed**.

PoV-is-truth carries through: a ``confirmed`` finding is one the oracle reproduced
(``ScanFinding.confirmed``); a finding that stayed a hypothesis is never silently
upgraded to a confirmed hit. So:

  * **recall (confirmed)** — fraction of vulnerable items where 0verse produced a
    *reproducing PoV* at the right function/sink;
  * **recall (located)** — fraction where it at least *surfaced* the bug (PoV or
    honest hypothesis) at the right function/sink;
  * **confirmed-PoV rate** — of the located true bugs, the fraction that reached a
    reproducing PoV rather than staying a hypothesis;
  * **FP rate (confirmed)** — fraction of *clean / fixed* items where 0verse
    produced a confirmed PoV (the serious false alarm; PoV-is-truth should keep
    this near zero);
  * **FP rate (hypothesis)** — fraction of clean items with hypothesis-level noise;
  * **precision (confirmed)** — over all *confirmed* findings, the fraction that
    landed on a real bug at the right location (mislocated or clean-binary
    confirmations count against it).

Held-out discipline (``in_seed_set``): every corpus item carries an explicit flag
asserting whether its bug *instance* was used to derive/tune any 0verse detector.
``heldout_summary`` reports it so a "find" can be read as **generalization**, not
memorization.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Bump MINOR for additive fields, MAJOR for removals/renames.
# v1.1: optional provenance fields (publish_date / nvd_url / fix_commit) + the
#       post-cutoff validator, for the post-training-cutoff CVE corpus (#49).
GROUNDTRUTH_SCHEMA_VERSION = "1.1"

# Lane discipline (PART B — the honesty fix). The MockLLM lane is the deterministic,
# key-free CI **regression floor**: it proves the harness wiring + the static lenses
# still surface what they surfaced yesterday, and it runs in pytest/CI with no
# external sends. It is NEVER a capability number. Any reported *capability* claim
# comes from the real-LLM lane (Codex gpt-5.5 / Claude / ...). Every place a MockLLM
# result appears, it is stamped with ``GROUNDTRUTH_CI_LANE`` so it cannot be misread
# as performance.
GROUNDTRUTH_CI_LANE = "ci-regression-floor (NOT a capability measure)"
GROUNDTRUTH_CAPABILITY_LANE = "real-llm-capability"


def lane_label(llm: str | None) -> tuple[str, bool]:
    """Return ``(human_label, is_capability_measure)`` for an eval lane keyed on the
    LLM provider. ``mock`` (or none) → the CI regression floor, never a capability
    number; any real provider → the capability lane."""
    is_capability = bool(llm) and llm not in ("mock",)
    return (GROUNDTRUTH_CAPABILITY_LANE if is_capability else GROUNDTRUTH_CI_LANE,
            is_capability)

# Ground-truth label for a corpus item: does a real bug exist in it at all?
LABELS = ("vulnerable", "clean")

# How an item was sourced — its provenance tier.
TIERS = ("real-cve", "magma", "sanity-floor")


@dataclass
class CorpusItem:
    """One labeled corpus entry with KNOWN ground truth.

    A ``vulnerable`` item carries the bug's *location* (function, and optionally the
    source/sink coordinates) so a find can be scored at the right place, not merely
    "something crashed". A ``clean`` item (a fixed build, or a safe look-alike) has
    no bug — any confirmed finding on it is a false positive.
    """

    id: str
    name: str                    # binary basename produced by the build
    label: str                   # "vulnerable" | "clean"  (ground truth)
    tier: str                    # "real-cve" | "magma" | "sanity-floor"
    cwe: str                     # e.g. "CWE-416" (or "" for a clean look-alike)
    cve: str                     # provenance: real CVE id, or "" if not a CVE
    provenance: str              # human-readable source + fix-commit / origin
    in_seed_set: bool            # held-out: was this bug instance used to build 0verse?
    source: str = ""             # .c file (relative to the corpus dir) to compile
    build_flags: str = ""        # extra gcc flags
    pair_id: str = ""            # links a vulnerable/fixed pair (same upstream bug)
    expected_function: str | None = None   # the function the bug lives in
    expected_source: str | None = None     # taint source symbol (optional)
    expected_sink: str | None = None       # sink symbol (optional)
    note: str = ""
    # --- provenance (v1.1, additive/optional) ------------------------------
    publish_date: str = ""       # ISO date the CVE was published (NVD), "YYYY-MM-DD"
    nvd_url: str = ""            # authoritative NVD detail URL
    fix_commit: str = ""        # upstream fix commit URL/hash (or fix release/advisory)

    def __post_init__(self) -> None:
        if self.label not in LABELS:
            raise ValueError(f"{self.id}: unknown label {self.label!r}")
        if self.tier not in TIERS:
            raise ValueError(f"{self.id}: unknown tier {self.tier!r}")
        if self.label == "vulnerable" and not self.expected_function:
            raise ValueError(f"{self.id}: vulnerable item needs an expected_function")

    @property
    def is_vulnerable(self) -> bool:
        return self.label == "vulnerable"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def item_from_dict(d: dict[str, Any]) -> CorpusItem:
    known = {f for f in CorpusItem.__dataclass_fields__}  # noqa: C416
    kwargs = {k: v for k, v in d.items() if k in known}
    return CorpusItem(**kwargs)


@dataclass
class CorpusManifest:
    """The full labeled corpus + its schema version."""

    schema_version: str
    items: list[CorpusItem] = field(default_factory=list)

    @property
    def vulnerable(self) -> list[CorpusItem]:
        return [i for i in self.items if i.is_vulnerable]

    @property
    def clean(self) -> list[CorpusItem]:
        return [i for i in self.items if not i.is_vulnerable]


def load_manifest(path: str | Path) -> CorpusManifest:
    """Load + validate a corpus manifest (JSON). Rejects an incompatible MAJOR
    schema and duplicate ids."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    version = str(raw.get("schema_version", ""))
    if not version:
        raise ValueError("manifest missing schema_version")
    if version.split(".", 1)[0] != GROUNDTRUTH_SCHEMA_VERSION.split(".", 1)[0]:
        raise ValueError(f"incompatible manifest schema {version!r}")
    items = [item_from_dict(d) for d in raw.get("items", [])]
    seen: set[str] = set()
    for it in items:
        if it.id in seen:
            raise ValueError(f"duplicate corpus id {it.id!r}")
        seen.add(it.id)
    return CorpusManifest(schema_version=version, items=items)


# --- provenance / post-cutoff validation (#49) -----------------------------


def _parse_iso_date(value: str) -> datetime.date | None:
    """Parse a strict ``YYYY-MM-DD`` date, or None if unparseable."""
    try:
        return datetime.date.fromisoformat(value.strip())
    except (ValueError, AttributeError):
        return None


@dataclass
class ProvenanceIssue:
    """One provenance defect found by :func:`validate_post_cutoff`."""

    item_id: str
    problem: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_post_cutoff(items: list[CorpusItem], cutoff: str) -> list[ProvenanceIssue]:
    """Validate that every ``real-cve`` item is a verifiable, *post-cutoff* CVE.

    The discovery-vs-memorization claim only holds if each corpus CVE is (a) a real
    CVE with an authoritative NVD entry and an upstream fix reference, and (b)
    published strictly **after** the model's training cutoff. This returns the list
    of defects (empty == all clean): a missing cve id / nvd_url / fix_commit /
    publish_date, an unparseable date, or a ``publish_date`` on or before ``cutoff``
    (so the CVE is NOT provably post-cutoff). ``cutoff`` is an ISO ``YYYY-MM-DD``.
    """
    cut = _parse_iso_date(cutoff)
    if cut is None:
        raise ValueError(f"cutoff is not an ISO date: {cutoff!r}")
    issues: list[ProvenanceIssue] = []
    for it in items:
        if it.tier != "real-cve":
            continue
        if not it.cve:
            issues.append(ProvenanceIssue(it.id, "real-cve item missing cve id"))
        if not it.nvd_url:
            issues.append(ProvenanceIssue(it.id, "missing nvd_url"))
        if not it.fix_commit:
            issues.append(ProvenanceIssue(it.id, "missing fix_commit reference"))
        if not it.publish_date:
            issues.append(ProvenanceIssue(it.id, "missing publish_date"))
            continue
        d = _parse_iso_date(it.publish_date)
        if d is None:
            issues.append(ProvenanceIssue(it.id, f"unparseable publish_date {it.publish_date!r}"))
        elif d <= cut:
            issues.append(
                ProvenanceIssue(
                    it.id,
                    f"publish_date {it.publish_date} is not after the training cutoff {cutoff}",
                )
            )
    return issues


# --- scoring ---------------------------------------------------------------

# Per-(vulnerable)-item outcome.
VULN_CONFIRMED = "confirmed-find"        # reproducing PoV at the right location
VULN_HYPOTHESIS = "located-hypothesis"   # surfaced at the right location, no PoV
VULN_MISS = "miss"                       # never surfaced at the right location

# Per-(clean)-item outcome.
CLEAN_OK = "clean"                        # no finding at all
CLEAN_HYP_FP = "hypothesis-fp"            # hypothesis-level noise only
CLEAN_CONFIRMED_FP = "confirmed-fp"       # a confirmed PoV on clean code (serious)


def _finding_function(f: dict[str, Any]) -> str:
    return str(f.get("function") or "")


def _finding_sink(f: dict[str, Any]) -> str:
    return str(f.get("sink") or "")


def _matches_location(item: CorpusItem, f: dict[str, Any]) -> bool:
    """Does finding ``f`` land on the item's known bug location? Function must match
    (case-insensitive); if the item pins an expected sink, that must match too."""
    if not item.expected_function:
        return False
    if _finding_function(f).lower() != item.expected_function.lower():
        return False
    return not (item.expected_sink and _finding_sink(f).lower() != item.expected_sink.lower())


@dataclass
class ItemScore:
    """The scored outcome for one corpus item against a scan's findings."""

    item_id: str
    label: str
    outcome: str
    n_findings: int
    n_confirmed: int
    matched_confirmed: int       # confirmed findings at the right location
    matched_hypothesis: int      # hypothesis findings at the right location
    confirmed_fp: int            # confirmed findings that are false positives
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def score_item(item: CorpusItem, findings: list[dict[str, Any]]) -> ItemScore:
    """Score one item's scan findings against its ground truth.

    A finding dict is the flat contract shape (``api.ScanFinding.to_dict``): it must
    carry ``function``, ``sink``, ``confirmed`` (bool), ``hypothesis`` (bool).
    """
    n = len(findings)
    confirmed = [f for f in findings if bool(f.get("confirmed"))]
    n_conf = len(confirmed)

    if item.is_vulnerable:
        matched_conf = [f for f in confirmed if _matches_location(item, f)]
        # "located but no PoV": ANY non-confirmed finding at the right location
        # counts as surfaced-without-a-PoV — whether or not the funnel tagged it a
        # hypothesis. The bug WAS pointed at; it just never got a reproducing PoV.
        matched_hyp = [
            f for f in findings
            if not bool(f.get("confirmed")) and _matches_location(item, f)
        ]
        # confirmed findings that do NOT match the known location are mislocated FPs.
        conf_fp = len(confirmed) - len(matched_conf)
        if matched_conf:
            outcome = VULN_CONFIRMED
        elif matched_hyp:
            outcome = VULN_HYPOTHESIS
        else:
            outcome = VULN_MISS
        return ItemScore(
            item_id=item.id, label=item.label, outcome=outcome, n_findings=n,
            n_confirmed=n_conf, matched_confirmed=len(matched_conf),
            matched_hypothesis=len(matched_hyp), confirmed_fp=conf_fp,
        )

    # clean / fixed item: any confirmed finding is a false positive.
    has_hyp = any(bool(f.get("hypothesis")) and not bool(f.get("confirmed")) for f in findings)
    if n_conf:
        outcome = CLEAN_CONFIRMED_FP
    elif has_hyp:
        outcome = CLEAN_HYP_FP
    else:
        outcome = CLEAN_OK
    return ItemScore(
        item_id=item.id, label=item.label, outcome=outcome, n_findings=n,
        n_confirmed=n_conf, matched_confirmed=0, matched_hypothesis=0,
        confirmed_fp=n_conf,
    )


@dataclass
class EvalMetrics:
    """The honest scoreboard over a scored corpus."""

    n_vulnerable: int
    n_clean: int
    # vulnerable side
    confirmed_finds: int
    located_finds: int           # confirmed OR hypothesis at the right location
    misses: int
    recall_confirmed: float      # confirmed_finds / n_vulnerable
    recall_located: float        # located_finds / n_vulnerable
    confirmed_pov_rate: float    # confirmed_finds / located_finds
    # clean side
    clean_ok: int
    hypothesis_fps: int
    confirmed_fps_items: int
    fp_rate_confirmed: float     # confirmed-FP items / n_clean
    fp_rate_hypothesis: float    # hypothesis-FP items / n_clean
    # finding-level precision over CONFIRMED findings
    confirmed_tp_findings: int
    confirmed_fp_findings: int
    precision_confirmed: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _safe_div(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def aggregate(items: list[CorpusItem], scores: list[ItemScore]) -> EvalMetrics:
    """Aggregate per-item scores into the headline metrics. Honest by construction:
    every count comes straight from ``score_item`` — nothing is rounded up."""
    by_id = {s.item_id: s for s in scores}
    vuln = [i for i in items if i.is_vulnerable]
    clean = [i for i in items if not i.is_vulnerable]

    confirmed_finds = sum(1 for i in vuln if by_id[i.id].outcome == VULN_CONFIRMED)
    hyp_finds = sum(1 for i in vuln if by_id[i.id].outcome == VULN_HYPOTHESIS)
    located = confirmed_finds + hyp_finds
    misses = sum(1 for i in vuln if by_id[i.id].outcome == VULN_MISS)

    clean_ok = sum(1 for i in clean if by_id[i.id].outcome == CLEAN_OK)
    hyp_fps = sum(1 for i in clean if by_id[i.id].outcome == CLEAN_HYP_FP)
    conf_fp_items = sum(1 for i in clean if by_id[i.id].outcome == CLEAN_CONFIRMED_FP)

    # finding-level precision over confirmed findings, across the whole corpus.
    conf_tp = sum(by_id[i.id].matched_confirmed for i in vuln)
    conf_fp = sum(by_id[i.id].confirmed_fp for i in items)

    return EvalMetrics(
        n_vulnerable=len(vuln),
        n_clean=len(clean),
        confirmed_finds=confirmed_finds,
        located_finds=located,
        misses=misses,
        recall_confirmed=_safe_div(confirmed_finds, len(vuln)),
        recall_located=_safe_div(located, len(vuln)),
        confirmed_pov_rate=_safe_div(confirmed_finds, located),
        clean_ok=clean_ok,
        hypothesis_fps=hyp_fps,
        confirmed_fps_items=conf_fp_items,
        fp_rate_confirmed=_safe_div(conf_fp_items, len(clean)),
        fp_rate_hypothesis=_safe_div(hyp_fps, len(clean)),
        confirmed_tp_findings=conf_tp,
        confirmed_fp_findings=conf_fp,
        precision_confirmed=_safe_div(conf_tp, conf_tp + conf_fp),
    )


@dataclass
class HeldoutSummary:
    """Held-out discipline report: how much of the corpus is disjoint from any
    0verse seed/archetype source."""

    total: int
    held_out: int                # in_seed_set == False
    in_seed_set: int
    fully_held_out: bool         # every item is held out
    seeded_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def heldout_summary(items: list[CorpusItem]) -> HeldoutSummary:
    seeded = [i.id for i in items if i.in_seed_set]
    held = len(items) - len(seeded)
    return HeldoutSummary(
        total=len(items),
        held_out=held,
        in_seed_set=len(seeded),
        fully_held_out=len(seeded) == 0 and len(items) > 0,
        seeded_ids=seeded,
    )


def format_report(
    metrics: EvalMetrics, heldout: HeldoutSummary, scores: list[ItemScore],
    *, lane: str | None = None,
) -> str:
    """Render a markdown scoreboard — drop-in for ``docs/EVAL-GROUNDTRUTH.md``. No
    hand-edited numbers: everything is rendered from the scored result. When ``lane``
    is given (e.g. ``GROUNDTRUTH_CI_LANE``) it is stamped as a banner so a MockLLM
    floor can never be misread as a capability number."""
    banner = [f"> **Lane: {lane}**", ""] if lane else []
    lines = [
        *banner,
        "### Headline metrics",
        "",
        "| metric | value |",
        "|--------|-------|",
        f"| vulnerable items | {metrics.n_vulnerable} |",
        f"| clean/fixed items | {metrics.n_clean} |",
        f"| **recall (confirmed PoV)** | **{metrics.recall_confirmed:.0%}** "
        f"({metrics.confirmed_finds}/{metrics.n_vulnerable}) |",
        f"| recall (located, PoV or hypothesis) | {metrics.recall_located:.0%} "
        f"({metrics.located_finds}/{metrics.n_vulnerable}) |",
        f"| confirmed-PoV rate (of located bugs) | {metrics.confirmed_pov_rate:.0%} "
        f"({metrics.confirmed_finds}/{metrics.located_finds}) |",
        f"| **FP rate (confirmed, clean items)** | **{metrics.fp_rate_confirmed:.0%}** "
        f"({metrics.confirmed_fps_items}/{metrics.n_clean}) |",
        f"| FP rate (hypothesis noise, clean items) | {metrics.fp_rate_hypothesis:.0%} "
        f"({metrics.hypothesis_fps}/{metrics.n_clean}) |",
        f"| precision (confirmed findings) | {metrics.precision_confirmed:.0%} "
        f"({metrics.confirmed_tp_findings}/"
        f"{metrics.confirmed_tp_findings + metrics.confirmed_fp_findings}) |",
        "",
        f"_Held-out: {heldout.held_out}/{heldout.total} items disjoint from any "
        f"0verse seed/archetype source"
        + ("" if heldout.fully_held_out else f"; seeded: {', '.join(heldout.seeded_ids)}")
        + "._",
        "",
        "### Per-item outcomes",
        "",
        "| item | label | outcome | findings | confirmed | matched |",
        "|------|-------|---------|:--------:|:---------:|:-------:|",
    ]
    for s in scores:
        lines.append(
            f"| `{s.item_id}` | {s.label} | **{s.outcome}** | {s.n_findings} | "
            f"{s.n_confirmed} | {s.matched_confirmed}c/{s.matched_hypothesis}h |"
        )
    return "\n".join(lines)
