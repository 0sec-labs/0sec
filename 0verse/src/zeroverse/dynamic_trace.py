"""Dynamic reachability recovery — the real entry->sink path from EXECUTION, not static
call-graph inference.

WHY. Every reachability wall in this codebase — concolic (no static path on C++
vtable/template dispatch) and trace-synth (the container->parser edge is unresolved
indirect/inlined) — is the SAME failure: static call-graph recovery loses indirect and
inlined edges on optimized C++. That is the roadmap's info-loss wall.

The fix is to stop inferring the path and OBSERVE it. The OSS-Fuzz/binarygym ``vuln``
binaries are SanitizerCoverage builds, so running a seed and reading ``-print_coverage``
yields every function the input ACTUALLY executed, with its real demangled name AND
source ``file:line`` — ground-truth reachability, no Ghidra, no guessing. A seed that
reaches the outer container (a DNG/TIFF that hits ``parse_tiff`` -> the tag dispatch ->
the makernote parser) hands trace-synth an EMPIRICALLY-grounded function slice instead
of a static guess that mixed a dozen sibling formats.

This module extracts that coverage and turns it into a reachability slice for
:mod:`zeroverse.trace_synth`. It observes; it never confirms (that is still the oracle).
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import oracle
from .sandbox_exec import MsbSshExecutor, current_executor

_ENV = {"ASAN_OPTIONS": "detect_leaks=0", "UBSAN_OPTIONS": "halt_on_error=0"}


def symbolizer_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """``base`` (defaulting to :data:`_ENV`) augmented with ``ASAN_SYMBOLIZER_PATH`` when
    an ``llvm-symbolizer`` is discoverable on ``$PATH``.

    ``-print_coverage`` only emits named ``COVERED_FUNC`` lines when the sanitizer can
    symbolize PCs; libFuzzer prints ``invalid path to external symbolizer`` and falls
    back to bare ``UNCOVERED_PC`` addresses otherwise. The sanitizer does NOT reliably
    search ``$PATH`` itself (observed failing on the bench despite an installed
    symbolizer), so we resolve it explicitly. A no-op when none is found — the caller
    still gets whatever the runtime produces."""
    env = dict(base if base is not None else _ENV)
    if "ASAN_SYMBOLIZER_PATH" not in env:
        found = (
            shutil.which("llvm-symbolizer")
            or shutil.which("llvm-symbolizer-14")
            or shutil.which("llvm-symbolizer-15")
        )
        if found:
            env["ASAN_SYMBOLIZER_PATH"] = found
    return env

# libFuzzer -print_coverage line, e.g.:
#   COVERED_FUNC: hits: 3 edges: 12/40 LibRaw::parseAdobeRAFMakernote() /src/.../fuji.cpp:210
# The function name (C++, may contain spaces/templates) sits between the edges field and
# the trailing source location.
_COV_RE = re.compile(
    r"^COVERED_FUNC:\s*hits:\s*(\d+)\s*edges:\s*(\d+)/(\d+)\s+(.*?)\s+(/\S+:\d+)\s*$"
)


@dataclass
class CoveredFunc:
    name: str  # demangled function name as libFuzzer prints it
    hits: int
    edges_hit: int
    edges_total: int
    src: str  # source file:line (DWARF-derived)


def covered_functions(
    binary: str | Path,
    paths: list[str],
    *,
    timeout: float = 90.0,
    env: dict[str, str] | None = None,
) -> list[CoveredFunc]:
    """Run the SanitizerCoverage harness over ``paths`` and return the functions it
    actually EXECUTED (COVERED_FUNC lines), with hits + source location. ``paths`` are
    seed files/dirs delivered as the libFuzzer corpus; ``-runs=1`` replays them so the
    coverage reflects real execution.

    ``env`` overrides the sanitizer environment; pass :func:`symbolizer_env` to ensure
    named ``COVERED_FUNC`` lines on hosts where the sanitizer cannot find its
    symbolizer (defaults to :data:`_ENV`)."""
    if isinstance(current_executor(), MsbSshExecutor) and any(
        Path(path).is_dir() for path in paths
    ):
        return []
    argv = [oracle._exec_path(str(binary)), "-runs=1", "-print_coverage=1", *paths]
    result = current_executor().run(argv, timeout=timeout, env=env or _ENV)
    if result.error or result.timed_out:
        return []
    out = result.stdout + result.stderr
    covered = []
    for line in out.splitlines():
        m = _COV_RE.match(line.strip())
        if m:
            covered.append(
                CoveredFunc(
                    name=m.group(4).strip(),
                    hits=int(m.group(1)),
                    edges_hit=int(m.group(2)),
                    edges_total=int(m.group(3)),
                    src=m.group(5),
                )
            )
    return covered


def _norm(name: str) -> str:
    """Reduce a printed C++ name to a bare identifier for matching against decompiled
    keys: 'LibRaw::parseAdobeRAFMakernote()' -> 'parseAdobeRAFMakernote'."""
    n = name.split("(")[0]  # drop args
    n = n.split("<")[0]  # drop template params
    n = n.rsplit("::", 1)[-1]  # drop namespace/class
    return n.strip()


# Source-path fragments that mark format-PARSING code (vs postprocessing / codecs /
# C++ runtime). Coverage source locations are DWARF-accurate, so this is a reliable
# filter for "is this function part of the container parser".
_PARSER_SRC = re.compile(r"/metadata/|/tiff|/identify|makernote|/parse|_parse", re.I)
_READER_RE = re.compile(r"sget|get2|get4|getint|read_|fread|getbits", re.I)


def dynamic_reach_slice(
    binary: str | Path,
    seeds: list[str],
    meta: Any,
    verdict: Any,
    *,
    max_funcs: int = 22,
    timeout: float = 90.0,
) -> list[str]:
    """Build a reachability slice for trace-synth from REAL coverage: the parser
    functions the seeds executed (by DWARF source path + reader-helper use), mapped to
    decompiled-meta keys, most-hit first (outer container parsers run most). Returns
    decompiled function names present in ``meta.decompiled_c``; empty if coverage or
    seeds are unavailable (caller falls back to the static slice)."""
    dc = getattr(meta, "decompiled_c", {})
    if not isinstance(dc, dict) or not dc or not seeds:
        return []
    covered = covered_functions(binary, seeds, timeout=timeout)
    if not covered:
        return []
    # keep parser functions: those whose source is in a parser module OR that read
    # binary fields (drop postprocessing/codec/runtime noise).
    keys_by_norm: dict[str, str] = {}
    for k in dc:
        keys_by_norm.setdefault(_norm(k), k)
    scored: list[tuple[int, str]] = []
    seen: set[str] = set()
    for cf in covered:
        if not (_PARSER_SRC.search(cf.src) or _READER_RE.search(cf.name)):
            continue
        key = keys_by_norm.get(_norm(cf.name))
        if key and key not in seen:
            seen.add(key)
            scored.append((cf.hits, key))
    # outer container parsers execute most often -> highest hits first (outermost).
    scored.sort(key=lambda t: -t[0])
    slice_ = [k for _h, k in scored[:max_funcs]]
    # ensure the sink anchor is present (append if coverage didn't include it).
    from .trace_synth import _sink_function

    sink = _sink_function(verdict, dc)
    if sink and sink in dc and sink not in slice_:
        slice_.append(sink)
    return slice_
