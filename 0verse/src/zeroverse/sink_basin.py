"""Sink-basin seed selection — concentrate fuzzing energy on the format island that
reaches a LOCATEd sink, instead of diluting it across a generic corpus.

MEASURED MOTIVATION (wavpack ``unpack_samples3``, CWE-787, on the post-cutoff bench).
The crutch-free run walled with a 31-seed corpus in which exactly ONE non-poc seed
touched the v3 legacy-decoder island. Its energy was diluted across ~30 v4 seeds that
can NEVER reach the island — the dispatcher routes to ``open_file3`` only when the
first byte is ``'R'`` (a RIFF wrapper); v4 files start with ``'w'``. The full run's
grown corpus reached **0/521 edges** of ``unpack_samples3``. Re-seeding a campaign from
ONLY the island seed drove **409-435/521 edges** of the sink in minutes. The wall was
seed *dilution*, not unreachability — coverage-guided fuzzing has no mechanism to
concentrate energy on a rare on-island seed.

THE LEVER. After LOCATE hands us the ground-truth sink function, score every corpus
seed by how close its ACTUAL execution sits to the sink's *basin* — the functions in
the sink's translation-unit module (or, stripped, its call-graph neighborhood) — then
launch a concentrated directed-fuzz campaign seeded ONLY from the top on-basin seeds.
The machine finds the island; no human hand-picks the seed.

TWO BASIN SIGNALS, used as ALTERNATIVES (module is the authority; call-graph the
stripped fallback) — NOT additive, which measurement proved wrong: undirected
call-graph distance over a dense decoder pulls in ~20 shared tag/bitstream readers that
every audio seed hits, so adding it lets off-island seeds win.
  * MODULE (authority, needs DWARF source paths). A covered function whose source
    translation unit is in the sink's module family (same file, or a ``foo`` /
    ``foo_open`` stem relationship). The v3 island functions live in ``unpack3.c`` /
    ``unpack3_open.c``; the v4 decoder does not, even though both share the
    ``WavpackUnpackSamples`` dispatch hub. When a module stem is known, ONLY on-module
    functions earn basin credit — the shared decoder cannot pollute the ranking.
  * CALL-GRAPH (stripped fallback, symbols only). A covered function within a few
    undirected hops of the sink, MINUS the corpus-common hub. Used only when no module
    stem is recoverable; weaker on a densely-connected decoder (documented limit).

Both modes subtract the corpus-common set (bare names most seeds cover) — a function
only discriminates the island if it is rare across the corpus (TF-IDF-like).

HONEST LIMITS. (1) The module signal needs DWARF source paths; on a fully stripped
target it degrades to the call-graph fallback over recovered symbols (weaker, and itself
lossy on indirect/inlined C++ edges — the roadmap's info-loss wall). (2) Concentration
only helps when at least one seed already reaches the basin; when none do, this is a
pure synthesis problem and the recovered gate constants must seed a template instead
(see :mod:`zeroverse.trace_synth`). (3) Reaching the sink is necessary, not sufficient:
the last-mile *semantic* fault still needs the boundary-probe. PoV-is-truth throughout —
selection only decides where energy goes; a finding is confirmed ONLY by the
differential oracle in :mod:`zeroverse.directed_fuzz`.
"""

from __future__ import annotations

import collections
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import dynamic_trace
from .dynamic_trace import CoveredFunc, symbolizer_env


def _covered_staged(
    binary: str | Path,
    seed_paths: list[str],
    *,
    env: dict[str, str],
    timeout: float,
) -> list[CoveredFunc]:
    """Coverage of ``seed_paths`` replayed as a libFuzzer CORPUS.

    libFuzzer only emits named ``COVERED_FUNC`` lines when handed a corpus DIRECTORY;
    a bare file argument runs but prints nothing usable (measured on the bench). So we
    stage the seeds into a temp directory and point the harness at that. Callers pass
    either one seed (per-seed scoring) or many (a corpus-wide coverage measurement)."""
    d = Path(tempfile.mkdtemp(prefix="sinkbasin_cov_"))
    try:
        for i, p in enumerate(seed_paths):
            src = Path(p)
            if src.is_dir():
                return dynamic_trace.covered_functions(
                    binary, [str(src)], timeout=timeout, env=env
                )
            try:
                shutil.copy(src, d / f"s{i:05d}")
            except OSError:
                continue
        return dynamic_trace.covered_functions(
            binary, [str(d)], timeout=timeout, env=env
        )
    finally:
        shutil.rmtree(d, ignore_errors=True)

# Harness / C++-runtime / sanitizer functions that are NOT part of any format basin —
# every input touches these, so they must never earn a seed basin credit.
_HUB_NAME_RE = re.compile(
    r"LLVMFuzzer|^main$|__asan|__ubsan|__sanitizer|_GLOBAL__|std::|__cxx|"
    r"operator new|operator delete|malloc|free|memcpy|memset|memmove",
    re.I,
)


@dataclass
class BasinScore:
    """One seed's proximity to the sink basin. ``score`` is the rank key; the component
    fields make the ranking auditable (why did the machine pick this seed?)."""

    seed: str
    total_covered: int = 0
    module_funcs: int = 0          # distinct covered funcs in the sink's module family
    near_funcs: int = 0            # distinct covered funcs within maxhop of the sink (hub-excluded)
    reaches_sink: bool = False     # the seed's coverage includes the sink function itself
    on_basin: bool = False         # covers a discriminating basin function (or reaches sink)
    proximity: float = 0.0         # weighted basin mass (module or call-graph term)
    score: float = 0.0             # overall rank key (proximity, with a reaches-sink bonus)
    covered_basin: list[str] = field(default_factory=list)  # named basin funcs hit (evidence)
    note: str = ""


@dataclass
class SelectionResult:
    """Outcome of scoring + selecting seeds for a concentrated campaign."""

    ranked: list[BasinScore]
    selected: list[str]            # seed paths chosen for the concentrated campaign
    sink_func: str = ""
    sink_module_stem: str = ""
    on_basin_count: int = 0        # seeds covering a discriminating basin function
    used_fallback: bool = False    # True when no seed was on-basin (selected top-by-coverage)
    note: str = ""


# --- module-family membership ------------------------------------------------


def _src_stem(src: str) -> str:
    """``/work/src/src/unpack3.c:265`` -> ``unpack3``. Strips directory, line, and
    extension so we compare translation-unit stems."""
    base = src.rsplit("/", 1)[-1]
    base = base.split(":", 1)[0]
    return base.rsplit(".", 1)[0]


def in_module_family(src: str, sink_stem: str) -> bool:
    """Is ``src``'s translation unit in the sink's module family? True for the exact
    file, and for a ``foo`` / ``foo_open`` stem relationship in EITHER direction
    (``unpack3`` matches ``unpack3_open`` but NOT ``unpack`` — the ``_`` boundary stops
    ``unpack`` from swallowing ``unpack3``)."""
    if not sink_stem:
        return False
    stem = _src_stem(src)
    return (
        stem == sink_stem
        or stem.startswith(sink_stem + "_")
        or sink_stem.startswith(stem + "_")
    )


# --- call-graph proximity (best-effort, from the binary's direct calls) ------

_ODUMP_NAME = re.compile(r"^[0-9a-f]+ <([^>]+)>:")
_ODUMP_CALL = re.compile(r"\bcall[a-z]*\s+[0-9a-f]+ <([^>+]+)(?:\+0x[0-9a-f]+)?>")


def callgraph_distances(
    binary: str | Path, sink_func: str, *, maxhop: int = 3
) -> dict[str, int]:
    """Undirected shortest-hop distance from every reachable named symbol to
    ``sink_func`` over the binary's DIRECT-call graph (recovered from ``objdump -d``).

    Undirected because a seed proves basin membership by covering EITHER a caller of the
    sink (the dispatcher side) OR a callee/sibling it shares (the decoder side). Bounded
    at ``maxhop`` so the map stays local. Best-effort: an empty dict on any failure (no
    ``objdump``, stripped binary, sink symbol absent) — the caller then leans on the
    module signal alone. Only DIRECT calls are recovered; indirect/vtable edges are
    lost (documented info-loss wall), so this UNDER-credits, never over-credits."""
    try:
        out = subprocess.run(
            ["objdump", "-d", "--no-show-raw-insn", str(binary)],
            capture_output=True,
            text=True,
            timeout=300,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    adj: dict[str, set[str]] = collections.defaultdict(set)
    cur: str | None = None
    for line in out.splitlines():
        m = _ODUMP_NAME.match(line)
        if m:
            cur = m.group(1)
            continue
        c = _ODUMP_CALL.search(line)
        if c and cur:
            callee = c.group(1)
            adj[cur].add(callee)
            adj[callee].add(cur)  # undirected
    if sink_func not in adj:
        return {}
    dist: dict[str, int] = {sink_func: 0}
    q: collections.deque[str] = collections.deque([sink_func])
    while q:
        x = q.popleft()
        if dist[x] >= maxhop:
            continue
        for y in adj[x]:
            if y not in dist:
                dist[y] = dist[x] + 1
                q.append(y)
    return dist


# --- source file of the sink (for the module stem) ---------------------------


def sink_source_stem(
    binary: str | Path,
    sink_func: str,
    *,
    sink_addr: int | None = None,
) -> str:
    """Recover the sink's translation-unit stem (``unpack3``) from the binary's debug
    info. Prefers ``addr2line`` on ``sink_addr`` (LOCATE hands us the address); falls
    back to resolving ``sink_func`` via ``nm``. Empty string when no DWARF/symbols —
    the module signal is then unavailable and the caller uses the call-graph signal."""
    addr = sink_addr
    if addr is None:
        for nm in ("nm", "llvm-nm"):
            try:
                out = subprocess.run(
                    [nm, str(binary)], capture_output=True, text=True, timeout=60
                ).stdout
            except (OSError, subprocess.SubprocessError):
                continue
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[2] == sink_func:
                    try:
                        addr = int(parts[0], 16)
                    except ValueError:
                        addr = None
                    break
            if addr is not None:
                break
    if addr is None:
        return ""
    for a2l in ("addr2line", "llvm-addr2line"):
        try:
            out = subprocess.run(
                [a2l, "-e", str(binary), hex(addr)],
                capture_output=True,
                text=True,
                timeout=60,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            continue
        if out and out.split(":", 1)[0] not in ("??", ""):
            return _src_stem(out)
    return ""


# --- scoring -----------------------------------------------------------------

_W_MODULE = 10.0   # weight per distinct on-module function (the authority signal)
_W_CALLGRAPH = 1.0  # weight scale for the stripped-fallback call-graph proximity term
_REACHES_SINK_BONUS = 1000.0  # a seed that already reaches the sink dominates the ranking


def _score_one(
    seed: str,
    covered: list[CoveredFunc],
    sink_func: str,
    sink_stem: str,
    cg_dist: dict[str, int],
    common: set[str] | None = None,
) -> BasinScore:
    """Turn one seed's covered-function list into a :class:`BasinScore`.

    MODULE and CALL-GRAPH are ALTERNATIVE signals, not additive. When the sink's
    translation-unit stem is known (DWARF present) the module signal is the AUTHORITY:
    only functions in the sink's module family earn basin credit, so the shared decoder
    — call-graph-adjacent to the sink but in other translation units — cannot credit
    off-island seeds. Undirected call-graph distance over a dense decoder is too noisy
    to be additive (it pulls in ~20 shared tag/bitstream readers every audio seed hits);
    it is used ONLY as the stripped fallback, when no module stem is available.

    ``common`` (bare names most seeds cover) is subtracted in EITHER mode — a function
    only discriminates the island if it is rare across the corpus. Reaching the sink
    itself is always counted, common or not."""
    common = common or set()
    bs = BasinScore(seed=seed, total_covered=len(covered))
    seen_mod: set[str] = set()
    seen_near: set[str] = set()
    for cf in covered:
        name = cf.name
        bare = _bare_name(name)
        if bare == sink_func or name == sink_func:
            bs.reaches_sink = True
        if bare in common or _HUB_NAME_RE.search(name):
            continue  # shared hub / runtime — not discriminating
        if sink_stem:  # MODULE mode (authority): credit only on-module functions
            if in_module_family(cf.src, sink_stem) and name not in seen_mod:
                seen_mod.add(name)
                bs.proximity += _W_MODULE
                bs.covered_basin.append(name)
        else:  # STRIPPED fallback: hub-subtracted call-graph proximity
            d = cg_dist.get(bare, cg_dist.get(name))
            if d is not None and d > 0 and name not in seen_near:
                seen_near.add(name)
                bs.proximity += _W_CALLGRAPH / (d + 1)
                bs.covered_basin.append(name)
    bs.module_funcs = len(seen_mod)
    bs.near_funcs = len(seen_near)
    bs.on_basin = bool(seen_mod or seen_near) or bs.reaches_sink
    bs.score = bs.proximity + (_REACHES_SINK_BONUS if bs.reaches_sink else 0.0)
    return bs


def _corpus_common(
    coverage: dict[str, list[CoveredFunc]], *, frac: float = 0.5
) -> set[str]:
    """Bare names covered by at least ``frac`` of the seeds — the shared
    dispatch/decoder/harness hub that carries no island signal. Skipped for tiny
    corpora (< 4 seeds), where 'common' is not yet meaningful and every function should
    keep its raw proximity."""
    n = len(coverage)
    if n < 4:
        return set()
    counts: dict[str, int] = collections.defaultdict(int)
    for covered in coverage.values():
        for bare in {_bare_name(cf.name) for cf in covered}:
            counts[bare] += 1
    threshold = max(2, int(frac * n + 0.999))
    return {name for name, c in counts.items() if c >= threshold}


def _bare_name(name: str) -> str:
    """Reduce a printed C++ name to a bare identifier for call-graph/symbol matching:
    ``LibRaw::parse()`` -> ``parse``, ``open_file3`` -> ``open_file3``."""
    n = name.split("(", 1)[0].split("<", 1)[0]
    return n.rsplit("::", 1)[-1].strip()


def score_seeds(
    binary: str | Path,
    sink_func: str,
    seed_paths: list[str],
    *,
    sink_addr: int | None = None,
    sink_source_file: str | None = None,
    maxhop: int = 3,
    per_seed_timeout: float = 90.0,
) -> SelectionResult:
    """Score every seed by basin proximity to ``sink_func`` and return them ranked.

    ``sink_addr`` (from LOCATE) or ``sink_source_file`` pins the module stem; both are
    optional — without them the ranking uses the call-graph signal alone. Each seed is
    replayed once under SanitizerCoverage (:func:`dynamic_trace.covered_functions`) with
    a symbolizer-resolved env so ``COVERED_FUNC`` lines carry names + source."""
    stem = (
        _src_stem(sink_source_file)
        if sink_source_file
        else sink_source_stem(binary, sink_func, sink_addr=sink_addr)
    )
    cg_dist = callgraph_distances(binary, sink_func, maxhop=maxhop)
    env = symbolizer_env()
    # Pass 1: replay every seed once, collect its real coverage.
    coverage: dict[str, list[CoveredFunc]] = {}
    for seed in seed_paths:
        coverage[seed] = _covered_staged(
            binary, [seed], env=env, timeout=per_seed_timeout
        )
    # Pass 2: with the corpus-common hub known, score each seed's discriminating basin.
    common = _corpus_common(coverage)
    ranked: list[BasinScore] = []
    for seed, covered in coverage.items():
        bs = _score_one(seed, covered, sink_func, stem, cg_dist, common)
        if not covered:
            bs.note = "no coverage (harness produced no COVERED_FUNC — symbolizer?)"
        ranked.append(bs)
    ranked.sort(key=lambda b: (b.score, b.total_covered), reverse=True)
    on_basin = sum(1 for b in ranked if b.on_basin)
    return SelectionResult(
        ranked=ranked,
        selected=[],
        sink_func=sink_func,
        sink_module_stem=stem,
        on_basin_count=on_basin,
        note=(
            f"scored {len(ranked)} seeds; module_stem={stem or '(none)'}; "
            f"callgraph {'built' if cg_dist else 'unavailable'}; "
            f"{on_basin} on-basin"
        ),
    )


def select_basin_seeds(
    result: SelectionResult, *, top_k: int = 8, min_score: float = 0.0
) -> SelectionResult:
    """Pick the concentrated seed set from a scored ranking: the top ``top_k`` on-basin
    seeds (those covering a discriminating basin function, or reaching the sink). When NO
    seed is on-basin (no corpus seed touches the island), fall back to the top ``top_k``
    by raw coverage and flag it, so the campaign still runs but the honest 'nothing
    reached the basin' signal is visible to the caller (the synthesis-needed regime)."""
    on_basin = [b for b in result.ranked if b.on_basin and b.score > min_score]
    if on_basin:
        result.selected = [b.seed for b in on_basin[:top_k]]
        result.used_fallback = False
    else:
        result.selected = [b.seed for b in result.ranked[:top_k]]
        result.used_fallback = True
        result.note += " | NO on-basin seed — fell back to top-coverage (synthesis regime)"
    return result


# --- sink coverage measurement (the lift metric) -----------------------------


def sink_edge_coverage(
    binary: str | Path,
    seed_paths: list[str],
    sink_func: str,
    *,
    timeout: float = 300.0,
) -> tuple[int, int]:
    """``(edges_hit, edges_total)`` for ``sink_func`` across ``seed_paths`` replayed
    together — the objective 'did we reach the sink, and how deep' metric used to
    measure the concentration lift (0/521 diluted -> 409/521 concentrated). ``(0, 0)``
    when the sink was not covered at all."""
    covered = _covered_staged(
        binary, seed_paths, env=symbolizer_env(), timeout=timeout
    )
    for cf in covered:
        if _bare_name(cf.name) == sink_func or cf.name == sink_func:
            return cf.edges_hit, cf.edges_total
    return 0, 0


# --- top-level orchestration -------------------------------------------------


@dataclass
class SinkBasinResult:
    """End-to-end result: the autonomous selection + the concentrated campaign outcome.
    ``confirmed`` is delegated to the differential oracle in directed fuzzing — this
    module never adjudicates."""

    selection: SelectionResult
    directed: Any = None           # directed_fuzz.DirectedFuzzResult (or None if skipped)
    sink_edges_before: tuple[int, int] = (0, 0)  # diluted-corpus sink coverage
    sink_edges_after: tuple[int, int] = (0, 0)   # concentrated grown-corpus sink coverage
    confirmed: bool = False
    note: str = ""


def run_sink_basin(
    verdict: Any,
    vuln_binary: str | Path,
    seed_paths: list[str],
    *,
    sink_func: str,
    sink_addr: int | None = None,
    sink_source_file: str | None = None,
    fixed_binary: str | Path | None = None,
    top_k: int = 8,
    budget_s: float = 180.0,
    jobs: int = 2,
    exclude_inputs: list[bytes] | tuple[bytes, ...] = (),
    timeout: float = 20.0,
    measure_before: bool = False,
    maxhop: int = 3,
) -> SinkBasinResult:
    """Autonomous sink-basin concentration: score ``seed_paths`` by basin proximity to
    ``sink_func``, select the top on-basin seeds, and run a concentrated directed-fuzz
    campaign seeded ONLY from them (delegating confirmation to the differential oracle).

    ``measure_before`` also replays the full diluted corpus to record the pre-selection
    sink coverage, so the caller can report the concentration lift. ``exclude_inputs``
    (the poc bytes) keep a recall measurement honest — never seeded, never counted."""
    from . import directed_fuzz

    sel = score_seeds(
        vuln_binary,
        sink_func,
        seed_paths,
        sink_addr=sink_addr,
        sink_source_file=sink_source_file,
        maxhop=maxhop,
    )
    select_basin_seeds(sel, top_k=top_k)
    res = SinkBasinResult(selection=sel)

    if measure_before:
        res.sink_edges_before = sink_edge_coverage(vuln_binary, seed_paths, sink_func)

    res.directed = directed_fuzz.confirm_by_directed_fuzz(
        verdict,
        vuln_binary,
        seed_globs=sel.selected,  # exact paths act as single-file globs
        fixed_binary=fixed_binary,
        budget_s=budget_s,
        jobs=jobs,
        exclude_inputs=exclude_inputs,
        timeout=timeout,
    )
    res.confirmed = bool(getattr(res.directed, "confirmed", False))
    res.note = (
        f"selected {len(sel.selected)} basin seeds "
        f"({'FALLBACK/off-basin' if sel.used_fallback else 'on-basin'}); "
        f"confirmed={res.confirmed}"
    )
    return res
