"""#42 — Fleet-scale cross-target variant analysis (M7 Bet C, the leapfrog).

Big Sleep does variant analysis on **one** codebase at a time, human-seeded. The
unoccupied territory — and the only bet that changes the product's *unit
economics* — is doing it across a **fleet**: find a bug once, take its archetype +
a binary signature of the bug site, sweep the same bug class across a corpus of
vendor firmwares / Android kernels / IoT images / binary versions, and route the
strongest matches to the PoV lane. One finding becomes ``N`` confirmed n-days.

This module is the *fleet driver*. It composes 0verse primitives that already
exist rather than re-implementing them:

  * **seed → matcher** (``seed_from_archetype`` / ``seed_from_reference`` /
    ``seed_from_finding``) — a ``FleetSeed`` carries the bug-class/seed lens, the
    surviving sink/source symbol vocabulary, and (optionally) a reference function
    *shape* to rank candidates against.
  * **fleet ingest** (``ingest_fleet``) — a directory / manifest / path list of
    binaries; firmware images are carved with ``firmware.unpack_firmware`` and
    their ELFs folded in; everything else triages + (optionally) decompiles via the
    existing multi-arch ingest + backend.
  * **variant detection** (``detect_variants``) — apply the matcher (the bug-class
    lens or ``SeedBugClass.matches``) to locate candidate sites of the *same* bug
    class; rank by similarity to the reference (symbol-set + decompiled-sink fuzzy
    hash). With no decompiler, fall back to the high-recall *cheap symbol pass*
    over the raw bytes (the design's honest low-precision first pass).
  * **per-target confirmation** (``confirm_variant``) — route each candidate
    through the *existing* engine: ``bugclasses.confirm`` (exec-trap / differential
    oracle → real PoV) for userland, ``firmware.qiling_confirm`` for firmware, and
    for kernel ``.ko`` an honest ``route:kernel-verify`` hypothesis (no bare-binary
    oracle). The directed-fuzz target set (``fuzz.directed.collect_targets``) is
    the escalation lane for sinks the deterministic oracle can't trigger.
  * **dedup + emit** (``run_fleet``) — dedup variants per sink signature, emit one
    record per confirmed variant with provenance (seed archetype + fleet member +
    confirmed/hypothesis), and capture each into the #32 dataset (the corpus-volume
    engine that unblocks Bet B's flywheel). Report fleet economics: 1 seed → N
    candidates → M confirmed.

**PoV-is-truth holds.** A swept variant is only ``confirmed`` when a reproducing
PoV is attached; a low-precision match is never reported as a finding without a
crash. That is the same discipline that makes 0verse credible — applied at fleet
scale.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from . import bugclasses, dataset, firmware, seedbugs
from .abi import Abi, abi_for, can_execute
from .agent import Verdict
from .analyze import Finding
from .bugclasses import BugClass, bug_class_for_origin
from .fuzz.directed import DirectedTargets, collect_targets
from .ingest import Triage, triage
from .poc import write_pov_script
from .report import PoV
from .seedbugs import SeedBugClass

# --- routing taxonomy -------------------------------------------------------
# How a swept candidate gets confirmed (or honestly degrades):
ROUTE_USERLAND = "userland"          # native/qemu-user oracle → real PoV
ROUTE_FIRMWARE = "firmware"          # Qiling emulation oracle → real PoV
ROUTE_KERNEL_VERIFY = "kernel-verify"  # hypothesis-only; bench KASAN lane, NEVER auto-confirmed

# The public bug-class lenses, keyed by class id (the matcher's "find candidate
# sites of the same bug class" pass when a decompiler is available).
_LENS_BY_CLASS = {
    "overflow": bugclasses.overflow_lens,
    "intoverflow": bugclasses.intoverflow_lens,
    "fmtstring": bugclasses.fmtstring_lens,
    "uaf": bugclasses.uaf_lens,
    "cmdi": bugclasses.cmdi_lens,
    "logic": bugclasses.logic_lens,
}

# Surviving sink / source symbol vocabularies for the *cheap symbol pass* (the
# high-recall, no-decompiler fall-back used on stripped firmware blobs). Kept here
# (not imported from the lens internals) so the cheap pass is dependency-light.
_CLASS_SINKS: dict[str, tuple[str, ...]] = {
    "cmdi": ("system", "popen", "execve", "execl", "execlp", "execvp",
             "posix_spawn", "doSystem", "twsystem", "CsteSystem"),
    "overflow": ("strcpy", "strcat", "sprintf", "vsprintf", "sscanf", "stpcpy",
                 "memcpy", "gets"),
    "intoverflow": ("malloc", "realloc", "calloc", "memcpy", "memmove"),
    "fmtstring": ("printf", "fprintf", "sprintf", "snprintf", "syslog"),
    "uaf": ("free", "kfree", "realloc"),
    "logic": (),
}
_GENERIC_SOURCES: tuple[str, ...] = (
    "getenv", "recv", "recvfrom", "read", "fgets", "fread", "scanf",
    "websGetVar", "webGetVar", "nvram_get", "nvram_safe_get", "get_cgi",
    "json_object_get_string", "GetValue",
)

# Build a seed-bug-class lookup by id (iokit / linux-ko / firmware seeds).
_SEEDBUG_BY_ID: dict[str, SeedBugClass] = {
    sb.id: sb for sb in (*seedbugs.SEED_CLASSES, *seedbugs.FIRMWARE_SEEDS)
}


# ---------------------------------------------------------------------------
# 1. Seed → variant matcher
# ---------------------------------------------------------------------------

# Normalize decompiler noise (FUN_xxx labels, hex constants, var_Nh temporaries,
# whitespace) so a fuzzy hash compares *shape*, not a specific compilation's
# renamed locals — the cheap analog of a CFG/function diff across compilers.
_NORM_RX = (
    (re.compile(r"\b(?:FUN_|fcn\.|sub_|loc_|sym\.)[0-9a-fA-Fx_.]+"), "FN"),
    (re.compile(r"\b(?:var_|arg_|local_|iVar|uVar|lVar|cVar|pcVar|puVar|auStack_|"
                r"acStack_|uStack_)\w+"), "V"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "K"),
    (re.compile(r"\b\d+\b"), "K"),
    (re.compile(r"\s+"), " "),
)


def _normalize(code: str) -> str:
    out = code
    for rx, rep in _NORM_RX:
        out = rx.sub(rep, out)
    return out.strip()


def _shingles(code: str, k: int = 4) -> frozenset[str]:
    """Token k-shingles of the normalized body — the fuzzy-hash feature set."""
    toks = _normalize(code).split()
    if len(toks) < k:
        return frozenset({" ".join(toks)}) if toks else frozenset()
    return frozenset(" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1))


_SYMBOL_RX = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")


def _called_symbols(code: str) -> frozenset[str]:
    return frozenset(m.group(1) for m in _SYMBOL_RX.finditer(code))


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


@dataclass(frozen=True)
class ReferenceShape:
    """A reference vulnerable-function signature to binary-diff candidates against.
    Cheap, honest, compiler-noise-robust function similarity: a blend of called-
    symbol-set Jaccard and decompiled-body k-shingle Jaccard. NOT a CFG isomorphism
    / BinDiff — the precise diff layer is the documented investment; this is the
    high-recall ranker."""

    function: str
    decompiled_c: str
    shingles: frozenset[str]
    symbols: frozenset[str]

    @classmethod
    def from_body(cls, function: str, code: str) -> ReferenceShape:
        return cls(function, code, _shingles(code), _called_symbols(code))

    def similarity(self, other_c: str) -> float:
        """0..1 similarity to another function body. Weighted: 60% called-symbol
        overlap (the strip-surviving signal), 40% normalized-body shingle overlap."""
        sym = _jaccard(self.symbols, _called_symbols(other_c))
        shg = _jaccard(self.shingles, _shingles(other_c))
        return round(0.6 * sym + 0.4 * shg, 4)


@dataclass(frozen=True)
class FleetSeed:
    """The variant-matcher built from a seed bug. ``matcher_kind`` selects the
    lens family: ``bugclass`` (userland confirmable lenses) or ``seedbug`` (the
    kernel/firmware ``SeedBugClass`` matchers)."""

    archetype_id: str
    bug_class: str                       # cmdi/overflow/... ('' for a pure seedbug)
    cwe: str
    framing: str
    route: str                           # ROUTE_USERLAND | ROUTE_FIRMWARE | ROUTE_KERNEL_VERIFY
    sink_symbols: tuple[str, ...]
    source_symbols: tuple[str, ...]
    matcher_kind: str                    # "bugclass" | "seedbug"
    seedbug: SeedBugClass | None = None
    reference: ReferenceShape | None = None

    def with_reference(self, ref: ReferenceShape) -> FleetSeed:
        return FleetSeed(
            self.archetype_id, self.bug_class, self.cwe, self.framing, self.route,
            self.sink_symbols, self.source_symbols, self.matcher_kind, self.seedbug,
            ref,
        )


def _route_for_seedbug(sb: SeedBugClass) -> str:
    if sb.id.startswith("firmware:"):
        return ROUTE_FIRMWARE
    # iokit + every linux-ko class: no bare-binary oracle → hypothesis lane.
    return ROUTE_KERNEL_VERIFY


def _bugclass_seed(bc: BugClass, archetype_id: str) -> FleetSeed:
    return FleetSeed(
        archetype_id=archetype_id,
        bug_class=bc.id,
        cwe=bc.cwe,
        framing=bc.framing,
        route=ROUTE_USERLAND,
        sink_symbols=_CLASS_SINKS.get(bc.id, ()),
        source_symbols=_GENERIC_SOURCES,
        matcher_kind="bugclass",
    )


def _seedbug_seed(sb: SeedBugClass) -> FleetSeed:
    source = sb.kernel_signals or sb.corroborating_signals or _GENERIC_SOURCES
    return FleetSeed(
        archetype_id=sb.id,
        bug_class="",
        cwe=sb.cwe,
        framing=sb.framing,
        route=_route_for_seedbug(sb),
        sink_symbols=sb.sink_signals,
        source_symbols=tuple(source),
        matcher_kind="seedbug",
        seedbug=sb,
    )


def seed_from_archetype(archetype_id: str) -> FleetSeed:
    """Build a ``FleetSeed`` from an explicit archetype id. Accepts:

      * a bug-class id / origin — ``cmdi`` or ``bugclass:cmdi``;
      * a seed-bug-class id — ``firmware:cgi-cmdi`` / ``linux-ko:copy-from-user`` /
        ``iokit.user-client.dispatch``;
      * a seed-catalog uid — ``kernel/DRV-01`` / ``userland/CMDI-01`` — resolved via
        the archetype's ``engine_lens`` to the implementing lens / seed class.
    """
    raw = archetype_id.strip()
    # bug-class form
    origin = raw if raw.startswith("bugclass:") else f"bugclass:{raw}"
    bc = bug_class_for_origin(origin)
    if bc is not None:
        return _bugclass_seed(bc, bc.origin)
    # seed-bug-class form
    if raw in _SEEDBUG_BY_ID:
        return _seedbug_seed(_SEEDBUG_BY_ID[raw])
    if raw.startswith("seed:") and raw[len("seed:"):] in _SEEDBUG_BY_ID:
        return _seedbug_seed(_SEEDBUG_BY_ID[raw[len("seed:"):]])
    # seed-catalog uid form → resolve engine_lens
    lens = _engine_lens_for_uid(raw)
    if lens is not None:
        return seed_from_archetype(lens)
    raise ValueError(
        f"unknown archetype id {archetype_id!r}: not a bug-class, seed-class, or "
        "catalog uid with a mapped engine_lens"
    )


def _engine_lens_for_uid(uid: str) -> str | None:
    """Resolve a seed-catalog ``uid`` to its implementing ``engine_lens`` id
    (e.g. ``seed:linux-ko:selector-index`` or ``bugclass:cmdi``), or None."""
    try:
        from . import seedcatalog
    except Exception:
        return None
    for a in seedcatalog.load_archetypes():
        if a.uid == uid or a.id == uid:
            return a.engine_lens
    return None


def _classify_reference(function: str, code: str) -> FleetSeed:
    """Infer the bug class of a reference function by running every lens / seed
    matcher over it and taking the first that fires — 'find a bug once, then seed
    the sweep from it'. Prefers a confirmable userland bug class, then a firmware
    seed, then a kernel seed; falls back to a logic hypothesis seed."""
    one = {function: code}
    # confirmable userland classes first (they yield real PoVs on the sweep)
    for cls in ("cmdi", "overflow", "intoverflow", "fmtstring", "uaf"):
        if _LENS_BY_CLASS[cls](one):
            seed = seed_from_archetype(cls)
            return seed.with_reference(ReferenceShape.from_body(function, code))
    # firmware then kernel seed classes
    for sb in (*seedbugs.FIRMWARE_SEEDS, *seedbugs.SEED_CLASSES):
        ok, _label, _sink = sb.matches(code)
        if ok:
            seed = _seedbug_seed(sb)
            return seed.with_reference(ReferenceShape.from_body(function, code))
    # nothing fired → keep it an honest logic hypothesis seed
    seed = seed_from_archetype("logic")
    return seed.with_reference(ReferenceShape.from_body(function, code))


def seed_from_reference(binary: str | Path, function: str) -> FleetSeed:
    """Build the matcher from a *reference vulnerable function* in a real binary:
    decompile it, classify its bug archetype, and capture its shape as the
    binary-diff reference. This is the 'I found one bug, now sweep its siblings'
    entry point."""
    decompiled = decompile_functions(binary)
    code = decompiled.get(function)
    if code is None:
        raise ValueError(
            f"function {function!r} not found in {binary} "
            f"(decompiled {len(decompiled)} functions)"
        )
    return _classify_reference(function, code)


def seed_from_finding(
    *, bug_class: str, function: str, decompiled_c: str, archetype_id: str = ""
) -> FleetSeed:
    """Build the matcher from an already-confirmed finding's archetype + the
    function body that carried it (the cheapest seed: a prior scan already proved
    this is real). ``bug_class`` is the finding's class id; ``archetype_id`` may
    pin a catalog/seed id, else the bug-class id is used."""
    seed = seed_from_archetype(archetype_id or bug_class)
    return seed.with_reference(ReferenceShape.from_body(function, decompiled_c))


# ---------------------------------------------------------------------------
# 2. Fleet ingest
# ---------------------------------------------------------------------------

_BIN_FORMATS = frozenset({"ELF", "PE", "Mach-O"})


@dataclass
class FleetMember:
    """One ingested fleet binary: its path, triage, resolved ABI, and (when a
    decompiler is available) its decompiled function bodies."""

    path: str
    triage: Triage
    abi: Abi | None
    decompiled: dict[str, str] = field(default_factory=dict)
    note: str = ""

    @property
    def name(self) -> str:
        return Path(self.path).name


def decompile_functions(binary: str | Path) -> dict[str, str]:
    """Decompiled ``{function: C}`` via the selected backend, or ``{}`` when no
    decompiler is installed (the matcher then degrades to the cheap symbol pass)."""
    try:
        from .backends import contract
        adapter = contract.analyze(binary)
    except Exception:
        return {}
    if adapter is None:
        return {}
    meta = getattr(adapter, "meta", None)
    raw = getattr(meta, "decompiled_c", {}) if meta is not None else {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items()}


def _expand_spec(spec: str | Path | Sequence[str | Path], workdir: str | Path) -> list[str]:
    """Resolve a fleet spec to a list of binary paths.

    A spec is a directory (every file is triaged; firmware images are carved with
    binwalk and their ELFs folded in), a manifest file (one path per line, ``#``
    comments allowed), or an explicit sequence of paths."""
    if not isinstance(spec, (str, Path)):
        return [str(p) for p in spec]
    p = Path(spec)
    if p.is_dir():
        files = sorted(str(f) for f in p.iterdir() if f.is_file())
        return _carve_firmware(files, workdir)
    # a manifest listing paths
    if p.is_file():
        head = p.read_bytes()[:4]
        if head not in (b"\x7fELF", b"MZ\x90\x00") and head[:2] != b"MZ" \
                and head not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            paths = [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]
            if paths:
                return _carve_firmware(paths, workdir)
        return [str(p)]
    raise ValueError(f"fleet spec {spec!r} is not a directory, manifest, or path list")


def _carve_firmware(paths: list[str], workdir: str | Path) -> list[str]:
    """For any path that isn't a recognized binary, try ``firmware.unpack_firmware``
    (binwalk) and fold the carved ELFs in. A recognized binary passes through
    unchanged. Honest degrade: an un-carvable blob is dropped with a note path."""
    out: list[str] = []
    work = Path(workdir)
    for path in paths:
        t = triage(path)
        if t.fmt in _BIN_FORMATS:
            out.append(path)
            continue
        res = firmware.unpack_firmware(path, work / f"unpack_{Path(path).name}")
        out.extend(res.elf_files)
    return out


def ingest_fleet(
    spec: str | Path | Sequence[str | Path],
    *,
    decompile: bool = True,
    workdir: str | Path | None = None,
) -> list[FleetMember]:
    """Ingest a fleet: triage + resolve ABI for every binary; decompile each (unless
    ``decompile=False``). Firmware images in ``spec`` are carved first."""
    base = Path(os.environ.get("ZEROVERSE_OUT", "0verse-out"))
    wd = Path(workdir) if workdir else base / "fleet-unpack"
    members: list[FleetMember] = []
    for path in _expand_spec(spec, wd):
        t = triage(path)
        abi = abi_for(t.arch, t.bits, fmt=t.fmt)
        dc = decompile_functions(path) if decompile and t.fmt in _BIN_FORMATS else {}
        note = "" if dc or not decompile else "no decompiler — cheap symbol pass only"
        members.append(FleetMember(path=path, triage=t, abi=abi, decompiled=dc, note=note))
    return members


# ---------------------------------------------------------------------------
# 3. Variant detection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VariantCandidate:
    """A candidate variant site of the seed's bug class in a fleet member."""

    member: str
    function: str
    sink: str
    source: str
    similarity: float          # to the reference shape (1.0 when no reference)
    route: str
    detector: str              # "lens:<class>" | "seed:<id>" | "symbol-pass"
    decompiled_c: str = ""

    def key(self) -> tuple[str, str, str]:
        return (self.member, self.function, self.sink)

    def to_finding(self, origin: str) -> Finding:
        return Finding(
            source=self.source, sink=self.sink, function=self.function,
            source_addr=0, sink_addr=0, path_len=0, origin=origin,
        )


def _symbol_pass(seed: FleetSeed, member: FleetMember) -> list[VariantCandidate]:
    """The high-recall cheap pass for a member with no decompiled bodies (stripped
    firmware blob): a single coarse candidate when a surviving sink symbol — and,
    when known, a source/getter symbol — is present in the raw bytes. Low precision
    by design; PoV-is-truth filters it downstream."""
    from ._fastpath import contains_any_bytes

    try:
        data = Path(member.path).read_bytes()
    except OSError:
        return []
    sinks = [s for s in seed.sink_symbols if s]
    if not sinks:
        return []
    sink_hits = contains_any_bytes(data, tuple(s.encode() for s in sinks))
    present_sink = next((s for s, hit in zip(sinks, sink_hits, strict=True) if hit), "")
    if not present_sink:
        return []
    srcs = [s for s in seed.source_symbols if s]
    has_src = any(contains_any_bytes(data, tuple(s.encode() for s in srcs))) if srcs else True
    if not has_src:
        return []
    return [VariantCandidate(
        member=member.path, function="<symbol-pass>", sink=present_sink,
        source=(seed.source_symbols[0] if seed.source_symbols else "stdin"),
        similarity=0.0, route=seed.route, detector="symbol-pass",
    )]


def detect_variants(seed: FleetSeed, member: FleetMember) -> list[VariantCandidate]:
    """Apply the seed's matcher to a fleet member and return ranked candidate
    variants (highest reference-similarity first). Deduped per ``(function, sink)``,
    keeping the strongest match."""
    if not member.decompiled:
        return _symbol_pass(seed, member)

    cands: list[VariantCandidate] = []
    if seed.matcher_kind == "bugclass":
        lens = _LENS_BY_CLASS[seed.bug_class]
        for f in lens(member.decompiled):
            body = member.decompiled.get(f.function, "")
            sim = seed.reference.similarity(body) if seed.reference else 1.0
            cands.append(VariantCandidate(
                member=member.path, function=f.function, sink=f.sink, source=f.source,
                similarity=sim, route=seed.route, detector=f"lens:{seed.bug_class}",
                decompiled_c=body,
            ))
    else:
        sb = seed.seedbug
        assert sb is not None
        for func, body in member.decompiled.items():
            if not body:
                continue
            is_cand, label, sink = sb.matches(body)
            if not is_cand:
                continue
            sim = seed.reference.similarity(body) if seed.reference else 1.0
            cands.append(VariantCandidate(
                member=member.path, function=func, sink=sink, source=label or "handler",
                similarity=sim, route=seed.route, detector=f"seed:{sb.id}",
                decompiled_c=body,
            ))

    # dedup per (function, sink), keep the highest-similarity detection
    best: dict[tuple[str, str, str], VariantCandidate] = {}
    for c in cands:
        cur = best.get(c.key())
        if cur is None or c.similarity > cur.similarity:
            best[c.key()] = c
    out = list(best.values())
    out.sort(key=lambda c: c.similarity, reverse=True)
    return out


def directed_targets_for(
    candidates: Iterable[VariantCandidate], member: FleetMember
) -> DirectedTargets:
    """Fold the member's candidates into the directed-fuzz target set
    (``fuzz.directed.collect_targets``) — the escalation lane for sinks the
    deterministic oracle can't trigger. Without recovered sink addresses this is an
    honest (possibly empty) set; it carries the seed weighting the directed
    scheduler consumes when address-level coverage is available."""
    findings = [c.to_finding(f"seed:{c.detector}") for c in candidates]
    seed_matches = [(c.function, c.sink, 80) for c in candidates]
    return collect_targets(findings, seed_matches=seed_matches)


# ---------------------------------------------------------------------------
# 4. Per-target confirmation (PoV-is-truth)
# ---------------------------------------------------------------------------

# Delivery vectors tried for a userland confirmable class, in order. The exec-trap
# / differential oracle is side-effect-free (it exits before running anything), so
# probing argv → stdin → env to recover the live channel is cheap and honest.
_USERLAND_VECTOR_SOURCES = ("argv", "stdin", "getenv")
# A generic over-long differential trigger for the size/copy classes.
_GENERIC_TRIGGER = b"A" * 512


def _confirm_userland(seed: FleetSeed, member: FleetMember, cand: VariantCandidate) -> PoV | None:
    bc = bug_class_for_origin(f"bugclass:{seed.bug_class}")
    if bc is None or not bc.confirmable:
        return None
    if not can_execute(member.abi, fmt=member.triage.fmt):
        return None
    binary = member.path
    # cmdi: exec-trap oracle, no trigger needed — probe each delivery vector.
    if seed.bug_class == "cmdi":
        for src in _USERLAND_VECTOR_SOURCES:
            f = Finding(source=src, sink=cand.sink, function=cand.function,
                        source_addr=0, sink_addr=0, path_len=0, origin="bugclass:cmdi")
            v = Verdict(True, "cmdi", "high", "", "")
            pov = bugclasses.confirm(f, v, binary)
            if pov and pov.reproduced:
                return pov
        return None
    # fmtstring: crash-vs-clean differential, no trigger needed.
    if seed.bug_class == "fmtstring":
        f = cand.to_finding("bugclass:fmtstring")
        v = Verdict(True, "fmtstring", "high", "", "")
        return bugclasses.confirm(f, v, binary, control=b"hello")
    # overflow / intoverflow / uaf: differential oracle needs a candidate trigger.
    if seed.bug_class in ("overflow", "intoverflow", "uaf"):
        f = cand.to_finding(f"bugclass:{seed.bug_class}")
        v = Verdict(True, seed.bug_class, "high", "", "")
        return bugclasses.confirm(f, v, binary, trigger=_GENERIC_TRIGGER)
    return None


def _confirm_firmware(seed: FleetSeed, member: FleetMember, cand: VariantCandidate) -> PoV | None:
    if not (firmware.qiling_available() and firmware.is_firmware_arch(member.abi)):
        return None
    if cand.function == "<symbol-pass>":
        return None  # no resolved function entry to drive
    addr = firmware.elf_function_addr(member.path, cand.function)
    if addr is None:
        return None
    f = cand.to_finding(f"seed:{seed.archetype_id}")
    return firmware.qiling_confirm(f, member.path, member.abi, addr)


@dataclass
class ConfirmedVariant:
    """A swept candidate after the confirmation engine ran. ``status`` is
    ``confirmed`` ONLY with a reproducing PoV; otherwise ``hypothesis`` (incl. the
    kernel-verify route, which has no bare-binary oracle)."""

    candidate: VariantCandidate
    status: str                # "confirmed" | "hypothesis"
    pov: PoV | None = None
    oracle: str = ""
    note: str = ""

    @property
    def confirmed(self) -> bool:
        return self.status == "confirmed" and self.pov is not None and self.pov.reproduced


def confirm_variant(
    seed: FleetSeed, member: FleetMember, cand: VariantCandidate
) -> ConfirmedVariant:
    """Route a candidate to the existing confirmation engine. Userland → the
    ``bugclasses`` oracle; firmware → the Qiling oracle; kernel ``.ko`` → an honest
    hypothesis (``route:kernel-verify``, no bare-binary oracle, routed to the bench
    KASAN lane)."""
    if cand.route == ROUTE_KERNEL_VERIFY:
        return ConfirmedVariant(cand, "hypothesis", None, "kernel-verify-lane",
                                "deferred to bench KASAN verify lane (no bare-binary oracle)")
    if cand.route == ROUTE_FIRMWARE:
        pov = _confirm_firmware(seed, member, cand)
        if pov and pov.reproduced:
            return ConfirmedVariant(cand, "confirmed", pov, "qiling-differential")
        note = ("qiling firmware lane unavailable on this host"
                if not firmware.qiling_available() else "no Qiling fault differential")
        return ConfirmedVariant(cand, "hypothesis", None, "qiling-differential", note)
    # userland
    pov = _confirm_userland(seed, member, cand)
    if pov and pov.reproduced:
        oracle = "exec-trap" if pov.capability == "reached-sink" else "differential-oracle"
        return ConfirmedVariant(cand, "confirmed", pov, oracle)
    reason = ("host cannot execute this target"
              if not can_execute(member.abi, fmt=member.triage.fmt)
              else "oracle produced no reproducing PoV")
    return ConfirmedVariant(cand, "hypothesis", None, "userland-oracle", reason)


# ---------------------------------------------------------------------------
# 5. Dedup + emit + economics
# ---------------------------------------------------------------------------

@dataclass
class MemberResult:
    member: FleetMember
    candidates: list[VariantCandidate]
    confirmations: list[ConfirmedVariant]
    directed: DirectedTargets

    @property
    def confirmed(self) -> list[ConfirmedVariant]:
        return [c for c in self.confirmations if c.confirmed]


@dataclass
class FleetReport:
    """The fleet sweep result + economics: 1 seed → N candidates → M confirmed."""

    seed: FleetSeed
    members: list[MemberResult]
    dataset_records_written: int = 0

    @property
    def n_members(self) -> int:
        return len(self.members)

    @property
    def n_candidates(self) -> int:
        return sum(len(m.candidates) for m in self.members)

    @property
    def n_confirmed(self) -> int:
        return sum(len(m.confirmed) for m in self.members)

    @property
    def n_hypotheses(self) -> int:
        return sum(len(m.confirmations) - len(m.confirmed) for m in self.members)

    @property
    def confirmed_members(self) -> list[str]:
        return [m.member.name for m in self.members if m.confirmed]

    @property
    def economics(self) -> str:
        return (f"1 seed [{self.seed.archetype_id}] -> {self.n_candidates} candidate(s) "
                f"across {self.n_members} fleet member(s) -> {self.n_confirmed} CONFIRMED "
                f"n-day(s) on {len(self.confirmed_members)} member(s) "
                f"({self.n_hypotheses} hypothesis/-es)")

    def to_dict(self) -> dict[str, object]:
        return {
            "seed": {"archetype_id": self.seed.archetype_id, "bug_class": self.seed.bug_class,
                     "cwe": self.seed.cwe, "route": self.seed.route},
            "n_members": self.n_members,
            "n_candidates": self.n_candidates,
            "n_confirmed": self.n_confirmed,
            "n_hypotheses": self.n_hypotheses,
            "confirmed_members": self.confirmed_members,
            "economics": self.economics,
            "dataset_records_written": self.dataset_records_written,
            "members": [
                {
                    "member": m.member.name,
                    "path": m.member.path,
                    "format": m.member.triage.fmt,
                    "arch": m.member.triage.arch,
                    "candidates": [
                        {"function": c.candidate.function, "sink": c.candidate.sink,
                         "source": c.candidate.source, "similarity": c.candidate.similarity,
                         "detector": c.candidate.detector, "status": c.status,
                         "oracle": c.oracle,
                         "pov": (c.pov.pov_script if (c.pov and c.pov.pov_script) else ""),
                         "capability": (c.pov.capability if c.pov else ""),
                         "note": c.note}
                        for c in m.confirmations
                    ],
                }
                for m in self.members
            ],
        }


def _dedup_confirmations(confs: list[ConfirmedVariant]) -> list[ConfirmedVariant]:
    """Dedup per member by crash/sink signature: a confirmed PoV's ``dedup_bucket``
    (ClusterFuzz-style crash state) when present, else the ``(function, sink)``
    coordinate. Keeps confirmed over hypothesis on a collision."""
    seen: dict[str, ConfirmedVariant] = {}
    for c in confs:
        sig = (c.pov.dedup_bucket if (c.pov and c.pov.dedup_bucket)
               else f"{c.candidate.function}:{c.candidate.sink}")
        cur = seen.get(sig)
        if cur is None or (c.confirmed and not cur.confirmed):
            seen[sig] = c
    return _fuzzy_dedup_confirmations(list(seen.values()))


def _fuzzy_dedup_confirmations(confs: list[ConfirmedVariant]) -> list[ConfirmedVariant]:
    """Second pass (M7 #48): fuzzy-merge confirmations that are the SAME crash
    reached via different sink coordinates — exact / LCS / Levenshtein over the
    confirmed PoV's stack frames. A hypothesis (no confirmed PoV frames) is
    never merged, so a confirmed-unique variant is never dropped."""
    from .dedup import CrashKey, dedup_items

    def key_of(c: ConfirmedVariant) -> CrashKey:
        frames = tuple(c.pov.frames) if (c.pov is not None and c.confirmed) else ()
        return CrashKey(frames=frames)

    reps, _ = dedup_items(confs, key_of=key_of)
    return reps


def _emit_records(report: FleetReport, dataset_path: str | Path) -> int:
    """Capture one #32 dataset record per swept variant (confirmed *and*
    hypothesis), tagged with the seed-archetype provenance — the corpus-volume the
    flywheel (Bet B) is blocked on. Confirmed records carry the real PoV path;
    PoV-is-truth is enforced by ``dataset.validate_record``."""
    records: list[dataset.DatasetRecord] = []
    seed = report.seed
    bug_class = seed.bug_class or seed.archetype_id
    for mres in report.members:
        feats = dataset.binary_features(mres.member.path)
        name = mres.member.name
        for c in mres.confirmations:
            cand = c.candidate
            pov = c.pov
            verdict = "confirmed" if c.confirmed else "hypothesis"
            pov_path = pov.pov_script if (pov and pov.pov_script) else ""
            prov = (f"variant-of[{seed.archetype_id}] fleet sweep; member={name}; "
                    f"detector={cand.detector}; similarity={cand.similarity}; "
                    f"route={cand.route}; oracle={c.oracle}")
            records.append(dataset.DatasetRecord(
                record_id=dataset.record_id(name, cand.function, cand.sink, "0x0", bug_class),
                dataset_version=dataset.DATASET_VERSION,
                created_at=_now(),
                tool=dict(dataset._TOOL),
                backend="fleet",
                binary_name=name,
                features=feats,
                bug_class=bug_class,
                source=cand.source,
                sink=cand.sink,
                function=cand.function,
                offset="0x0",
                verdict=verdict,
                oracle=c.oracle or "fleet-variant",
                capability=(pov.capability if pov else ""),
                dedup_bucket=(pov.dedup_bucket if pov else ""),
                pov_path=pov_path,
                repro_cmd=(f"python3 {pov_path}" if pov_path else ""),
                explanation=prov,
                synthetic=False,
            ))
    return dataset.emit_records(records, dataset_path)


def _now() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def run_fleet(
    seed: FleetSeed,
    members: Sequence[FleetMember],
    *,
    confirm: bool = True,
    dataset_path: str | Path | None = None,
    out_dir: str | Path | None = None,
) -> FleetReport:
    """The fleet driver: detect → confirm → dedup → emit. Returns the economics
    report. ``confirm=False`` runs detection only (the cheap sweep)."""
    base = Path(os.environ.get("ZEROVERSE_OUT", "0verse-out"))
    out = Path(out_dir) if out_dir else base / "fleet"
    member_results: list[MemberResult] = []
    for m in members:
        cands = detect_variants(seed, m)
        directed = directed_targets_for(cands, m)
        confs: list[ConfirmedVariant] = []
        for c in cands:
            cv = confirm_variant(seed, m, c) if confirm else ConfirmedVariant(c, "hypothesis")
            if cv.confirmed and cv.pov is not None and not cv.pov.pov_script:
                _write_pov(out, m, c, cv.pov)
            confs.append(cv)
        confs = _dedup_confirmations(confs)
        member_results.append(MemberResult(m, cands, confs, directed))
    report = FleetReport(seed, member_results)
    if dataset_path is not None:
        report.dataset_records_written = _emit_records(report, dataset_path)
    return report


def _write_pov(out_dir: Path, member: FleetMember, cand: VariantCandidate, pov: PoV) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{member.name}_{cand.function}")
    try:
        pov.pov_script = str(write_pov_script(out_dir / f"pov_fleet_{safe}.py", member.path, pov))
    except OSError:
        pov.pov_script = ""


def sweep(
    seed_archetype: str,
    fleet_spec: str | Path | Sequence[str | Path],
    *,
    reference: tuple[str, str] | None = None,
    confirm: bool = True,
    dataset_path: str | Path | None = None,
) -> FleetReport:
    """One-call convenience: build the seed, ingest the fleet, run the sweep.
    ``reference=(binary, function)`` attaches a reference shape for similarity
    ranking; otherwise the seed matches on archetype + symbols alone."""
    seed = seed_from_archetype(seed_archetype)
    if reference is not None:
        ref_bin, ref_fn = reference
        dc = decompile_functions(ref_bin)
        if ref_fn in dc:
            seed = seed.with_reference(ReferenceShape.from_body(ref_fn, dc[ref_fn]))
    members = ingest_fleet(fleet_spec)
    return run_fleet(seed, members, confirm=confirm, dataset_path=dataset_path)
