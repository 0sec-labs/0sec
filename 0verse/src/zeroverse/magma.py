"""Magma ground-truth scoring — the at-scale credibility instrument (PART A).

`docs/EVAL-GROUNDTRUTH.md`'s real-CVE tier reproduces *standalone extracts* of a
handful of bugs. **Magma** (github.com/HexHive/magma) is the at-scale version: real
upstream libraries (libpng/libxml2/libtiff/lua/sqlite3/...) carrying real, catalogued
bugs, each toggled by `MAGMA_ENABLE_FIXES` and guarded by a ground-truth `MAGMA_BUG`
canary. We build a target `-O0` with **fatal canaries** (`isan=1`), run the full
0verse pipeline (`zeroverse.api.scan`) over the driver binary, and score the findings
against Magma's KNOWN bug locations.

This module is the *typed, unit-tested* half — the catalogue loader + the scorer math
— kept in `src` so it is checked by `mypy --strict` and `pytest` against fixtures,
separate from the (Docker-driving, Ghidra-heavy) runner in `benchmarks/magma/run.py`.

Honest by construction, PoV-is-truth, ASSUME-FP:

  * a Magma bug-site is **reached** when 0verse surfaces *any* finding (PoV or
    hypothesis) at the bug's function — slice/lens coverage, not a confirmation;
  * a bug-site is **confirmed** only when the **oracle reproduced a PoV** at that
    function (a fatal-canary abort or a sanitizer crash) — never an LLM's say-so;
  * a confirmed finding that lands on **no** catalogued bug function is an
    **unmatched confirmation** and counts as a false positive (precision penalty);
  * on a **fixed** build (`fixes=1`, no bug), any confirmed finding is a false
    positive outright.

Granularity caveat (reported, not hidden): matching is **function-level**. Several
Magma bugs can live in the *same* function (e.g. libsndfile `psf_binheader_writef`
hosts SND010/012/013; libxml2 `xmlSnprintfElementContent` hosts XML001+XML006). A
binary-native scan keyed on the function name cannot tell co-located bugs apart, so
we score **bug-sites (distinct functions)** as the honest unit and report the raw
bug count alongside. Catalogue entries with no recorded function are **unscorable**
(excluded from the denominators, counted separately).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Bump MINOR for additive fields, MAJOR for removals/renames.
MAGMA_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class MagmaBug:
    """One catalogued Magma bug with its KNOWN ground-truth location."""

    target: str
    bug: str          # e.g. "PNG001"
    file: str
    function: str     # the function the bug + canary live in ("" => unscorable)
    in_seed_set: bool = False

    @property
    def scorable(self) -> bool:
        return bool(self.function)


def load_catalogue(path: str | Path) -> list[MagmaBug]:
    """Load `CATALOGUE-magma.json` into validated `MagmaBug`s."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    bugs: list[MagmaBug] = []
    for d in raw.get("bugs", []):
        bugs.append(
            MagmaBug(
                target=str(d["target"]),
                bug=str(d["bug"]),
                file=str(d.get("file", "")),
                function=str(d.get("function", "") or ""),
                in_seed_set=bool(d.get("in_seed_set", False)),
            )
        )
    return bugs


def bugs_for_target(catalogue: list[MagmaBug], target: str) -> list[MagmaBug]:
    return [b for b in catalogue if b.target == target]


def normalize_fn(name: str) -> str:
    """Canonical function name for matching: lower-cased, with a leading ``MAGMA_``
    stripped. Several Magma targets rename their public symbols at build time (e.g.
    libpng's ``--with-libpng-prefix=MAGMA_`` turns ``png_combine_row`` into
    ``MAGMA_png_combine_row`` in the binary), while the catalogue records the plain
    upstream name from the bug patch. Stripping the prefix on both sides matches the
    same function honestly — it is the *same code*, just symbol-renamed."""
    n = name.strip().lower()
    return n[len("magma_"):] if n.startswith("magma_") else n


def bug_functions(bugs: list[MagmaBug]) -> set[str]:
    """The set of (normalized) scorable bug-site function names for a target."""
    return {normalize_fn(b.function) for b in bugs if b.scorable}


def _fn(f: dict[str, Any]) -> str:
    return normalize_fn(str(f.get("function") or ""))


def _confirmed(f: dict[str, Any]) -> bool:
    return bool(f.get("confirmed"))


@dataclass
class MagmaTargetScore:
    """The scored outcome for one built Magma target against a single scan's findings.

    ``label`` is ``"vulnerable"`` (the bug build) or ``"clean"`` (the ``fixes=1`` FP
    probe build, where the bugs are patched out and every confirmation is an FP).
    """

    target: str
    label: str
    n_bugs: int                  # catalogued bugs for this target
    n_bug_sites: int             # distinct scorable bug-functions (the denominator)
    n_unscorable: int            # catalogue bugs with no function (excluded)
    bug_sites_reached: int       # distinct bug-functions with >=1 finding
    bug_sites_confirmed: int     # distinct bug-functions with a confirmed PoV
    unmatched_confirmed: int     # confirmed findings NOT at any bug function (FP)
    n_findings: int
    n_confirmed: int
    reached_sites: list[str] = field(default_factory=list)
    confirmed_sites: list[str] = field(default_factory=list)
    wall_s: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    ghidra_ok: bool = True       # did the decompile pipeline run (else static-degrade)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def score_target(
    target: str,
    bugs: list[MagmaBug],
    findings: list[dict[str, Any]],
    *,
    label: str = "vulnerable",
    wall_s: float = 0.0,
    input_tokens: int = 0,
    output_tokens: int = 0,
    ghidra_ok: bool = True,
    note: str = "",
) -> MagmaTargetScore:
    """Score one target's scan findings against its catalogued Magma bugs.

    Each finding dict is the flat contract shape (`api.ScanFinding.to_dict`): it
    carries ``function`` and ``confirmed``.
    """
    sites = bug_functions(bugs)
    n_unscorable = sum(1 for b in bugs if not b.scorable)

    found_fns = {_fn(f) for f in findings if _fn(f)}
    confirmed_fns = {_fn(f) for f in findings if _confirmed(f) and _fn(f)}

    if label == "clean":
        # A fixed build carries no bug; any confirmation anywhere is a false positive,
        # and "reached" is meaningless (there is nothing to reach).
        unmatched = sum(1 for f in findings if _confirmed(f))
        return MagmaTargetScore(
            target=target, label=label, n_bugs=len(bugs), n_bug_sites=len(sites),
            n_unscorable=n_unscorable, bug_sites_reached=0, bug_sites_confirmed=0,
            unmatched_confirmed=unmatched, n_findings=len(findings),
            n_confirmed=sum(1 for f in findings if _confirmed(f)),
            wall_s=wall_s, input_tokens=input_tokens, output_tokens=output_tokens,
            ghidra_ok=ghidra_ok, note=note,
        )

    reached = sorted(sites & found_fns)
    confirmed = sorted(sites & confirmed_fns)
    # A confirmed finding whose function is NOT a catalogued bug site is an
    # unmatched confirmation (ASSUME-FP — we do not credit it as a new bug).
    unmatched = sum(1 for f in findings if _confirmed(f) and _fn(f) not in sites)
    return MagmaTargetScore(
        target=target, label=label, n_bugs=len(bugs), n_bug_sites=len(sites),
        n_unscorable=n_unscorable, bug_sites_reached=len(reached),
        bug_sites_confirmed=len(confirmed), unmatched_confirmed=unmatched,
        n_findings=len(findings), n_confirmed=sum(1 for f in findings if _confirmed(f)),
        reached_sites=reached, confirmed_sites=confirmed, wall_s=wall_s,
        input_tokens=input_tokens, output_tokens=output_tokens, ghidra_ok=ghidra_ok,
        note=note,
    )


@dataclass
class MagmaMetrics:
    """The honest scoreboard over a scored Magma subset."""

    n_targets: int
    n_vuln_targets: int
    n_clean_targets: int
    total_bug_sites: int             # sum of distinct bug-functions over vuln targets
    total_bugs: int                  # raw catalogued bug count (vuln targets)
    sites_reached: int
    sites_confirmed: int
    reach_rate: float                # sites_reached / total_bug_sites
    confirmed_rate: float            # sites_confirmed / total_bug_sites
    confirmed_pov_rate: float        # sites_confirmed / sites_reached
    unmatched_confirmed: int         # FP confirmations on vuln builds
    clean_confirmed_fp: int          # confirmations on the fixed/clean builds
    precision_confirmed: float       # confirmed-at-bug / all confirmed findings
    wall_s: float
    input_tokens: int
    output_tokens: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _safe_div(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def aggregate_magma(scores: list[MagmaTargetScore]) -> MagmaMetrics:
    """Aggregate per-target scores into headline metrics. Honest by construction:
    every count comes straight from `score_target`."""
    vuln = [s for s in scores if s.label == "vulnerable"]
    clean = [s for s in scores if s.label == "clean"]

    total_sites = sum(s.n_bug_sites for s in vuln)
    total_bugs = sum(s.n_bugs for s in vuln)
    reached = sum(s.bug_sites_reached for s in vuln)
    confirmed = sum(s.bug_sites_confirmed for s in vuln)
    unmatched = sum(s.unmatched_confirmed for s in vuln)
    clean_fp = sum(s.unmatched_confirmed for s in clean)

    # precision over CONFIRMED findings corpus-wide: a confirmation at a bug site is a
    # true positive; an unmatched confirmation (vuln or clean build) is a false one.
    conf_tp = confirmed
    conf_fp = unmatched + clean_fp

    return MagmaMetrics(
        n_targets=len(scores),
        n_vuln_targets=len(vuln),
        n_clean_targets=len(clean),
        total_bug_sites=total_sites,
        total_bugs=total_bugs,
        sites_reached=reached,
        sites_confirmed=confirmed,
        reach_rate=_safe_div(reached, total_sites),
        confirmed_rate=_safe_div(confirmed, total_sites),
        confirmed_pov_rate=_safe_div(confirmed, reached),
        unmatched_confirmed=unmatched,
        clean_confirmed_fp=clean_fp,
        precision_confirmed=_safe_div(conf_tp, conf_tp + conf_fp),
        wall_s=round(sum(s.wall_s for s in scores), 1),
        input_tokens=sum(s.input_tokens for s in scores),
        output_tokens=sum(s.output_tokens for s in scores),
    )


# Codex/gpt-5.5 ChatGPT-subscription pricing is not metered per token, but for an
# order-of-magnitude $ figure we apply the published gpt-5.x list rates. Reported as
# an ESTIMATE only — the run itself spends no metered key (ChatGPT-OAuth).
_USD_PER_MTOK_IN = 1.25
_USD_PER_MTOK_OUT = 10.0


def estimated_cost_usd(input_tokens: int, output_tokens: int) -> float:
    return round(
        input_tokens / 1_000_000 * _USD_PER_MTOK_IN
        + output_tokens / 1_000_000 * _USD_PER_MTOK_OUT,
        4,
    )


def format_magma_report(
    metrics: MagmaMetrics,
    scores: list[MagmaTargetScore],
    *,
    llm: str,
    lane: str,
    accounting: dict[str, Any] | None = None,
) -> str:
    """Render a markdown scoreboard — drop-in for `docs/EVAL-GROUNDTRUTH.md`. No
    hand-edited numbers: everything is rendered from the scored result.

    ``accounting`` is the run's LLM ledger (``zeroverse.llm.usage``). Without a
    ``measured`` ledger the token/cost numbers are NOT rendered as a figure: a
    scoreboard that prints "0 tokens (~$0.0 est.)" for a lane whose model was
    never reached is exactly the over-claim this report exists to prevent.
    """
    status = str((accounting or {}).get("status", "measured"))
    if status == "measured":
        cost = estimated_cost_usd(metrics.input_tokens, metrics.output_tokens)
        spend = (f"{metrics.input_tokens + metrics.output_tokens} tokens "
                 f"(~${cost} est.)")
    else:
        calls_ok = int((accounting or {}).get("calls_ok", 0) or 0)
        calls_failed = int((accounting or {}).get("calls_failed", 0) or 0)
        spend = (f"token spend **{status}** "
                 f"({calls_ok} ok / {calls_failed} failed LLM calls)")
    lines = [
        f"### Magma at scale — {lane}",
        "",
        f"_LLM: **{llm}** · {metrics.n_vuln_targets} vulnerable targets "
        f"({metrics.total_bugs} catalogued bugs over {metrics.total_bug_sites} "
        f"distinct scorable bug-sites), {metrics.n_clean_targets} fixed FP-probe "
        f"build(s). Wall {metrics.wall_s}s; {spend}._",
        "",
        "| metric | value |",
        "|--------|-------|",
        f"| bug-sites reached (slice/lens) | {metrics.reach_rate:.0%} "
        f"({metrics.sites_reached}/{metrics.total_bug_sites}) |",
        f"| **bug-sites confirmed (reproducing PoV)** | **{metrics.confirmed_rate:.0%}** "
        f"({metrics.sites_confirmed}/{metrics.total_bug_sites}) |",
        f"| confirmed-PoV rate (of reached) | {metrics.confirmed_pov_rate:.0%} "
        f"({metrics.sites_confirmed}/{metrics.sites_reached}) |",
        f"| **unmatched confirmations (FP, vuln builds)** | **{metrics.unmatched_confirmed}** |",
        f"| confirmed FP on fixed builds | {metrics.clean_confirmed_fp} |",
        f"| precision (confirmed findings) | {metrics.precision_confirmed:.0%} |",
        "",
        "| target | label | bug-sites | reached | confirmed | unmatched | "
        "ghidra | wall (s) |",
        "|--------|-------|:---------:|:-------:|:---------:|:---------:|:------:|"
        ":--------:|",
    ]
    for s in scores:
        lines.append(
            f"| `{s.target}` | {s.label} | {s.n_bug_sites} | {s.bug_sites_reached} | "
            f"**{s.bug_sites_confirmed}** | {s.unmatched_confirmed} | "
            f"{'ok' if s.ghidra_ok else 'degrade'} | {s.wall_s:.0f} |"
        )
    return "\n".join(lines)
