"""Last-mile assist (ROADMAP M2; epic #224): LLM-guided TARGETED mutation of
inputs that already REACH a sink but don't crash it.

The coverage machinery (``coverage.CoverageProbe.uncrashed_but_reached``) can
prove a corpus input reaches the sink's basic block, and the sink-basin work
(#265/#266) showed that reaching is not triggering: a semantic predicate at the
sink (a flag field, a count the sink trusts, a mode selector) must hold a
specific value, and blind coverage fuzzing / structure-preserving 4-byte sweeps
do not derive *which* field and *which* value (the wavpack mono/stereo evidence:
357/521 sink edges covered, 0 crashes).

This module spends LLM reasoning exactly there. It conditions on:

  * the decompiled sink body (where the predicate and the overflowing buffer
    live), and
  * concrete corpus inputs that already REACH the sink (hex) — the mutation
    base, so the candidate stays on the parse path,

and asks for byte-level MUTATIONS of those inputs: which offset, which bytes,
and why. Applying a mutation is structure-preserving (an in-place patch within
the input's length — never an extension), so the parser still walks the input
to the sink while the poisoned field drives the fault.

PoV-is-truth / anti-cheat: the candidates are hypotheses — the crash oracle
(``confirm_crash`` / the sanitizer differential) is the sole arbiter, exactly
as for AFL-found crashes. The LLM is NEVER shown a reference PoC; the reaching
inputs are the fuzzer's own grown corpus (standard seed material), and
``LastMileContext`` has no field that could smuggle a known-crashing input in.
Any failure degrades to "no candidates" — the fuzz lane proceeds unchanged.
"""

from __future__ import annotations

import os
import re
import secrets
import tempfile
import zlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..agent import LLM
from ..preflight import BudgetTracker

# Caps: how many reaching inputs the prompt carries and how many bytes of each.
# The sink needs enough context to name an offset; more is prompt cost with no
# signal (the predicate fields live in the header the parser reads first).
_MAX_BASE_INPUTS = 4
_MAX_INPUT_BYTES = 512
_MAX_VALUE_BYTES = 8  # a field patch is 1-8 bytes; bigger is a rewrite, not a mutation
_SAFE_GDB_SYMBOL_RE = re.compile(r"^[A-Za-z_.$][A-Za-z0-9_.$:@<>~-]*$")


def last_mile_enabled() -> bool:
    """Opt-in gate (``ZEROVERSE_LAST_MILE``) — an LLM spend on top of the fuzz
    budget, off by default like the other capability lanes."""
    return bool(os.environ.get("ZEROVERSE_LAST_MILE"))


@dataclass
class LastMileContext:
    """Everything the last-mile proposer may condition on — and nothing else
    (the #52 anti-cheat pattern: no reference-input field by construction)."""

    sink_function: str
    """The reached-but-uncrashed sink (``unpack_samples3``)."""
    sink_decompiled: str = ""
    """Decompiled body of the sink — where the predicate + buffer live."""
    reaching_inputs: list[bytes] = field(default_factory=list)
    """Corpus inputs that REACH the sink's block (the mutation base)."""
    file_format: str = ""
    """Advisory container description (see ``inputsynth.infer_format``)."""
    max_input_size: int = 1 << 20


@dataclass
class Mutation:
    """One targeted patch: overwrite ``base[offset:offset+len(value)]`` of the
    ``input_index``-th reaching input with ``value``."""

    input_index: int
    offset: int
    value: bytes
    note: str = ""

@dataclass(frozen=True)
class NormalizedCandidate:
    """A last-mile candidate after bounded container normalization."""

    data: bytes
    container: str
    status: str


@dataclass
class LastMileCandidateBatch:
    """Validated normalized candidates plus truthful generation counts."""

    candidates: list[NormalizedCandidate] = field(default_factory=list)
    proposed: int = 0
    format_valid: int = 0
    malformed: int = 0
    unsupported: int = 0


@dataclass
class ReachProbeResult:
    """Runtime evidence that specific corpus inputs entered ``function``."""

    available: bool = False
    attempted: int = 0
    inputs: list[bytes] = field(default_factory=list)
    note: str = ""


class ReachRunner(Protocol):
    def __call__(
        self,
        binary: str,
        script: str,
        argv: list[str],
        *,
        timeout: float,
    ) -> tuple[str, int | None, bool]: ...


def probe_reaching_inputs(
    binary: str | Path,
    function: str,
    inputs: Sequence[bytes],
    *,
    max_inputs: int = 16,
    max_reaching: int = _MAX_BASE_INPUTS,
    timeout_s: float = 5.0,
    runner: ReachRunner | None = None,
    budget: BudgetTracker | None = None,
) -> ReachProbeResult:
    """Prove which file-input corpus entries reach ``function`` under GDB.

    This is an observation-only selector, never a confirmation oracle. It uses
    ``runtime_probe.run_gdb_batch``, so execution still requires the explicit
    trusted-local executor. Missing GDB, an unsafe symbol, timeout, or a target
    that never reaches the breakpoint degrades to no reaching inputs.
    """
    if not _SAFE_GDB_SYMBOL_RE.fullmatch(function):
        return ReachProbeResult(note="unsafe or unsupported GDB symbol")

    unique: list[bytes] = []
    seen: set[bytes] = set()
    for data in inputs:
        if data in seen:
            continue
        seen.add(data)
        unique.append(data)
        if len(unique) >= max_inputs:
            break
    if not unique:
        return ReachProbeResult(note="no corpus inputs to probe")

    if runner is None:
        from ..runtime_probe import run_gdb_batch

        runner = run_gdb_batch

    result = ReachProbeResult()
    with tempfile.TemporaryDirectory(prefix="zv_lastmile_reach_") as directory:
        root = Path(directory)
        for index, data in enumerate(unique):
            input_path = root / f"input_{index:04d}"
            input_path.write_bytes(data)
            marker = f"0VERSE_LAST_MILE_REACHED_{secrets.token_hex(16)}"
            script = "\n".join(
                [
                    "set pagination off",
                    "set confirm off",
                    "set breakpoint pending on",
                    "set debuginfod enabled off",
                    f"tbreak {function}",
                    "commands 1",
                    "silent",
                    f'printf "{marker}\\n"',
                    "quit",
                    "end",
                    "run",
                    "quit",
                    "",
                ]
            )
            run_timeout = timeout_s
            if budget is not None:
                reserved, reason = budget.reserve_attempt()
                if not reserved:
                    result.note = f"last-mile budget skipped: {reason}"
                    return result
                remaining = budget.remaining_seconds()
                if remaining <= 0:
                    budget.reservation_failures += 1
                    result.note = "last-mile budget skipped: wall-clock budget exhausted"
                    return result
                run_timeout = min(timeout_s, remaining)
            output, code, timed_out = runner(
                str(binary), script, [str(input_path)], timeout=run_timeout
            )
            if code is None:
                result.note = (
                    output.strip()
                    or "GDB unavailable or executor is not trusted-local"
                )
                return result
            if code != 0 and not timed_out and marker not in output:
                detail = next(
                    (line.strip() for line in reversed(output.splitlines()) if line.strip()),
                    "unknown GDB error",
                )
                result.note = f"GDB reach probe failed (exit {code}): {detail}"
                return result
            result.available = True
            result.attempted += 1
            if not timed_out and marker in output:
                result.inputs.append(data)
                if len(result.inputs) >= max_reaching:
                    break

    result.note = (
        f"{len(result.inputs)}/{result.attempted} probed input(s) reached {function}"
    )
    return result


_SYSTEM = (
    "You are a vulnerability-research expert doing LAST-MILE triggering. A "
    "coverage-guided fuzzer has already reached a vulnerable sink function — "
    "the attached corpus inputs EXECUTE the sink — but no input triggers the "
    "fault, because a semantic predicate at the sink (a flag field, a mode "
    "selector, a count/length the sink trusts) must hold a specific value. You "
    "are given the decompiled sink and the reaching inputs (hex). Identify the "
    "predicate guarding the overflowing access: which input byte offset feeds "
    "it, and which value drives the sink into the out-of-bounds access while "
    "keeping the input on the parse path to the sink. Emit TARGETED byte "
    "mutations of the provided inputs: input_index (0-based into the provided "
    "inputs), offset (byte index into that input), value_hex (1-8 bytes, "
    "lowercase hex, no 0x). Mutations OVERWRITE bytes in place — they must not "
    "grow the input. Propose a few diverse hypotheses (different fields / "
    "values). These are hypotheses for a crash oracle to adjudicate; you are "
    "proposing, not confirming."
)

MUTATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "mutations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "input_index": {"type": "integer"},
                    "offset": {"type": "integer"},
                    "value_hex": {"type": "string"},
                    "note": {"type": "string"},
                },
                "required": ["input_index", "offset", "value_hex"],
            },
        },
    },
    "required": ["mutations"],
}


def _build_prompt(ctx: LastMileContext, inputs: list[bytes], n: int) -> str:
    parts = [f"REACHED-BUT-UNCRASHED SINK: {ctx.sink_function}"]
    if ctx.file_format:
        parts.append(f"\nCONTAINER FORMAT: {ctx.file_format}")
    parts.append(
        f"\n--- DECOMPILED SINK ---\n{ctx.sink_decompiled}"
    )
    for i, data in enumerate(inputs):
        parts.append(f"\n--- REACHING INPUT #{i} ({len(data)} bytes) ---\n{data.hex()}")
    parts.append(
        f"\nEmit up to {n} diverse targeted mutations (input_index / offset / "
        "value_hex). Each must keep the input on the parse path to the sink and "
        "drive the sink's overflowing access."
    )
    return "".join(parts)


_NON_HEX_RE = re.compile(r"[^0-9a-fA-F]")


def _decode_value(raw: Any) -> bytes | None:
    """Decode a model-supplied value_hex (1..``_MAX_VALUE_BYTES`` bytes)."""
    if not isinstance(raw, str):
        return None
    s = _NON_HEX_RE.sub("", raw.strip().lower().removeprefix("0x"))
    if not s or len(s) % 2 or len(s) > 2 * _MAX_VALUE_BYTES:
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


def propose_mutations(ctx: LastMileContext, llm: LLM, *, n: int = 8) -> list[Mutation]:
    """Ask ``llm`` for up to ``n`` targeted mutations of the reaching inputs.
    Returns validated mutations only (decodable value, in-range index/offset);
    any backend failure or malformed response degrades to an empty list."""
    inputs = [d[: _MAX_INPUT_BYTES] for d in ctx.reaching_inputs[: _MAX_BASE_INPUTS]]
    if not inputs or not ctx.sink_decompiled:
        return []
    try:
        raw = llm.complete_json(_SYSTEM, _build_prompt(ctx, inputs, n), MUTATION_SCHEMA)
    except Exception:
        return []
    items = raw.get("mutations") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        return []
    out: list[Mutation] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        idx, off = item.get("input_index"), item.get("offset")
        value = _decode_value(item.get("value_hex"))
        if (
            not isinstance(idx, int) or not 0 <= idx < len(inputs)
            or not isinstance(off, int) or not 0 <= off < len(inputs[idx])
            or value is None
        ):
            continue
        note = item.get("note", "")
        out.append(Mutation(idx, off, value, note if isinstance(note, str) else ""))
    return out


def apply_mutation(base: bytes, offset: int, value: bytes) -> bytes | None:
    """In-place patch: ``base`` with ``base[offset:offset+len(value)]`` replaced
    by ``value``. Structure-preserving by construction — never grows the input
    (a mutation that would run past the end is rejected, not padded)."""
    if offset < 0 or not value or offset + len(value) > len(base):
        return None
    return base[:offset] + value + base[offset + len(value):]



_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_BIT_DEPTHS: dict[int, frozenset[int]] = {
    0: frozenset({1, 2, 4, 8, 16}),
    2: frozenset({8, 16}),
    3: frozenset({1, 2, 4, 8}),
    4: frozenset({8, 16}),
    6: frozenset({8, 16}),
}


@dataclass(frozen=True)
class _PngChunk:
    offset: int
    data_offset: int
    data_end: int
    end: int
    kind: bytes


def _png_crc(kind: bytes, data: bytes | bytearray) -> int:
    return zlib.crc32(data, zlib.crc32(kind)) & 0xFFFFFFFF


def _valid_ihdr(data: bytes) -> bool:
    if len(data) != 13:
        return False
    width = int.from_bytes(data[:4], "big")
    height = int.from_bytes(data[4:8], "big")
    bit_depth, color_type = data[8], data[9]
    return (
        width > 0
        and height > 0
        and bit_depth in _PNG_BIT_DEPTHS.get(color_type, ())
        and data[10] == 0
        and data[11] == 0
        and data[12] in (0, 1)
    )


def _parse_png(data: bytes) -> list[_PngChunk] | None:
    """Return a strict, bounded PNG chunk map only for a structurally valid PNG."""
    if not data.startswith(_PNG_SIGNATURE):
        return None
    chunks: list[_PngChunk] = []
    pos = len(_PNG_SIGNATURE)
    while pos < len(data):
        if len(data) - pos < 12:
            return None
        length = int.from_bytes(data[pos:pos + 4], "big")
        kind = data[pos + 4:pos + 8]
        data_offset = pos + 8
        data_end = data_offset + length
        end = data_end + 4
        if end > len(data) or not all(65 <= b <= 90 or 97 <= b <= 122 for b in kind):
            return None
        if _png_crc(kind, data[data_offset:data_end]) != int.from_bytes(
            data[data_end:end], "big"
        ):
            return None
        chunk = _PngChunk(pos, data_offset, data_end, end, kind)
        chunks.append(chunk)
        if kind == b"IEND":
            if length != 0 or end != len(data):
                return None
            break
        pos = end
    else:
        return None

    if (
        not chunks
        or chunks[0].kind != b"IHDR"
        or chunks[0].data_end - chunks[0].data_offset != 13
        or not any(chunk.kind == b"IDAT" for chunk in chunks)
    ):
        return None
    ihdr = chunks[0]
    return chunks if _valid_ihdr(data[ihdr.data_offset:ihdr.data_end]) else None


def _restore_ihdr_invariants(
    normalized: bytearray, base: bytes, ihdr: _PngChunk
) -> None:
    """Restore only invalid PNG IHDR structural fields from a reaching base."""
    start = ihdr.data_offset
    if int.from_bytes(normalized[start:start + 4], "big") == 0:
        normalized[start:start + 4] = base[start:start + 4]
    if int.from_bytes(normalized[start + 4:start + 8], "big") == 0:
        normalized[start + 4:start + 8] = base[start + 4:start + 8]
    bit_depth, color_type = normalized[start + 8], normalized[start + 9]
    if bit_depth not in _PNG_BIT_DEPTHS.get(color_type, ()):
        normalized[start + 8:start + 10] = base[start + 8:start + 10]
    if normalized[start + 10] != 0:
        normalized[start + 10] = base[start + 10]
    if normalized[start + 11] != 0:
        normalized[start + 11] = base[start + 11]
    if normalized[start + 12] not in (0, 1):
        normalized[start + 12] = base[start + 12]


def normalize_last_mile_candidate(base: bytes, candidate: bytes) -> NormalizedCandidate:
    """Preserve a valid PNG container while retaining in-place payload mutations.

    The reaching corpus input is the only structure reference. For PNG it restores
    the fixed signature and chunk layout, repairs invalid IHDR structural fields,
    and recomputes every chunk CRC. Unknown formats remain byte-for-byte unchanged
    so their mutations can still be re-probed without pretending they are valid.
    """
    if not base.startswith(_PNG_SIGNATURE):
        return NormalizedCandidate(candidate, "", "unsupported")
    chunks = _parse_png(base)
    if chunks is None or len(candidate) != len(base):
        return NormalizedCandidate(candidate, "PNG", "malformed")

    normalized = bytearray(candidate)
    normalized[:len(_PNG_SIGNATURE)] = base[:len(_PNG_SIGNATURE)]
    for chunk in chunks:
        normalized[chunk.offset:chunk.data_offset] = base[chunk.offset:chunk.data_offset]
    _restore_ihdr_invariants(normalized, base, chunks[0])
    for chunk in chunks:
        crc = _png_crc(chunk.kind, normalized[chunk.data_offset:chunk.data_end])
        normalized[chunk.data_end:chunk.end] = crc.to_bytes(4, "big")

    data = bytes(normalized)
    if _parse_png(data) is None:
        return NormalizedCandidate(candidate, "PNG", "malformed")
    return NormalizedCandidate(data, "PNG", "repaired" if data != candidate else "identity")

def last_mile_candidates(ctx: LastMileContext, llm: LLM, *, n: int = 8) -> list[bytes]:
    """Propose → apply → dedupe: the candidate byte strings for the oracle.
    Candidates exceeding ``ctx.max_input_size`` are dropped (a mutation is
    in-place, so this only guards pathological bases)."""
    inputs = ctx.reaching_inputs[: _MAX_BASE_INPUTS]
    out: list[bytes] = []
    seen: set[bytes] = set(inputs)
    for m in propose_mutations(ctx, llm, n=n):
        cand = apply_mutation(inputs[m.input_index], m.offset, m.value)
        if cand is None or len(cand) > ctx.max_input_size or cand in seen:
            continue
        seen.add(cand)
        out.append(cand)
    return out


def normalized_last_mile_candidates(
    ctx: LastMileContext, llm: LLM, *, n: int = 8
) -> LastMileCandidateBatch:
    """Propose, normalize, and dedupe candidates for native file-input replay.

    PNG candidates must remain format-valid after bounded repair; malformed PNG
    candidates are rejected before the runtime probe. Unsupported containers retain
    their exact in-place mutation and are explicitly counted rather than claimed
    format-valid.
    """
    inputs = ctx.reaching_inputs[: _MAX_BASE_INPUTS]
    batch = LastMileCandidateBatch()
    seen: set[bytes] = set(inputs)
    for mutation in propose_mutations(ctx, llm, n=n):
        candidate = apply_mutation(
            inputs[mutation.input_index], mutation.offset, mutation.value
        )
        if candidate is None or len(candidate) > ctx.max_input_size:
            continue
        batch.proposed += 1
        normalized = normalize_last_mile_candidate(
            inputs[mutation.input_index], candidate
        )
        if normalized.status in {"identity", "repaired"}:
            batch.format_valid += 1
        elif normalized.status == "malformed":
            batch.malformed += 1
            continue
        else:
            batch.unsupported += 1
        if normalized.data in seen:
            continue
        seen.add(normalized.data)
        batch.candidates.append(normalized)
    return batch
