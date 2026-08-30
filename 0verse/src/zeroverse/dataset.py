"""Labeled-PoV dataset capture (M6 #32) — THE MOAT's capture mechanism.

What ships in OSS vs what stays the private moat — the split is the whole point:

  * **OSS (this file + ``docs/DATASET.md`` + ``examples/dataset/``):** the
    *versioned schema* and an *append-only NDJSON emitter* that turns each
    pipeline run into labeled records, plus a handful of clearly-marked
    ``synthetic`` example rows. This is the *capture mechanism*.
  * **MOAT (never in the repo):** the real corpus of records mined from paid
    scans at scale — the closed feedback loop 0sec-cloud trains on. The OSS
    ships the funnel, not the water.

A record maps **binary features** → **(bug_class, source, sink)** → **PoV
(path + repro command, never raw exploit bytes)** → **verdict + the oracle that
decided it**. It is the foxguard-style data moat, for binaries.

Two invariants enforced here (the contract, not a convention):

  1. **PoV-is-truth.** A record with ``verdict == "confirmed"`` MUST carry a
     non-empty ``pov.path``. ``validate_record`` rejects a confirmed record with
     no PoV — the same rule the engine uses to refuse a finding.
  2. **No raw exploit bytes in the schema.** The schema has *no field* for crash
     input bytes; ``validate_record`` additionally rejects any record that smuggles
     a bytes-bearing key (``input_bytes``/``crash_input``/``pov_bytes``/…). The
     corpus is the moat; the OSS captures *labels and pointers*, not payloads.

The schema is **versioned** (``DATASET_VERSION``), mirroring the result contract
(``api.CONTRACT_VERSION``): MINOR for additive fields, MAJOR for removals/renames.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .dedup import CrashKey, dedup_items
from .pipeline import RunResult, TriagedFinding
from .serialize import finding_dict

# Bump MINOR for additive (back-compatible) fields, MAJOR for removals/renames.
DATASET_VERSION = "1.2"

_TOOL = {"name": "0verse", "version": __version__}

# Keys a record must never carry: raw crash/exploit payloads belong to the private
# corpus, never the OSS capture. ``validate_record`` rejects any of these.
_FORBIDDEN_KEYS = frozenset(
    {"input_bytes", "crash_input", "pov_bytes", "payload", "exploit_bytes", "stdin_bytes"}
)

VERDICTS = ("confirmed", "pruned", "hypothesis")


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@dataclass
class BinaryFeatures:
    """The feature side of a labeled record — what the engine knew about the
    target *before* it found anything. Features, never identifying bytes."""

    format: str = "unknown"          # ELF | PE | Mach-O | unknown
    arch: str = "unknown"
    bits: int = 0
    endian: str = "unknown"
    size_bytes: int = 0
    stripped: bool | None = None
    symbols_present: bool | None = None    # derived: not stripped, when known
    mitigations: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "size_bytes": self.size_bytes,
            "stripped": self.stripped,
            "symbols_present": self.symbols_present,
            "mitigations": dict(self.mitigations),
        }


@dataclass
class DatasetRecord:
    """One labeled run record. Flat, versioned, append-only."""

    record_id: str
    dataset_version: str
    created_at: str
    tool: dict[str, str]
    backend: str
    binary_name: str                 # basename only — no full path, no bytes
    features: BinaryFeatures
    bug_class: str
    source: str
    sink: str
    function: str
    offset: str
    verdict: str                     # confirmed | pruned | hypothesis
    oracle: str                      # the oracle/stage that decided the verdict
    capability: str
    dedup_bucket: str
    pov_path: str                    # standalone replay script path, or "" — NEVER bytes
    repro_cmd: str
    explanation: str
    synthetic: bool = False          # True for the committed example rows
    pov_sha256: str = ""              # optional retained replay-script commitment
    event_id: str = ""                # optional content-addressed learning-event identity
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        record = {
            "record_id": self.record_id,
            "dataset_version": self.dataset_version,
            "created_at": self.created_at,
            "tool": dict(self.tool),
            "backend": self.backend,
            "binary_name": self.binary_name,
            "features": self.features.to_dict(),
            "label": {
                "bug_class": self.bug_class,
                "source": self.source,
                "sink": self.sink,
                "function": self.function,
                "offset": self.offset,
            },
            "verdict": self.verdict,
            "oracle": self.oracle,
            "pov": {
                "path": self.pov_path,
                "repro_cmd": self.repro_cmd,
                "capability": self.capability,
                "dedup_bucket": self.dedup_bucket,
                **({"sha256": self.pov_sha256} if self.pov_sha256 else {}),
            },
            "explanation": self.explanation,
            "synthetic": self.synthetic,
        }
        if self.event_id:
            record["event_id"] = self.event_id
        if self.provenance:
            record["provenance"] = dict(self.provenance)
        return record


def record_id(binary_name: str, function: str, sink: str, offset: str, bug_class: str) -> str:
    """Stable id over the label coordinates — matches ``api._finding_id`` shape."""
    key = f"{binary_name}|{function}|{sink}|{offset}|{bug_class}".encode()
    return hashlib.sha1(key).hexdigest()[:12]


def binary_features(path: str | Path) -> BinaryFeatures:
    """Extract the feature side from a real binary via the dependency-free triage
    stage (+ file size). Degrades to defaults when the file is absent."""
    from .ingest import triage

    p = Path(path)
    if not p.exists():
        return BinaryFeatures()
    size = p.stat().st_size
    t = triage(p)
    symbols = None if t.stripped is None else (not t.stripped)
    return BinaryFeatures(
        format=t.fmt,
        arch=t.arch,
        bits=t.bits,
        endian=t.endian,
        size_bytes=size,
        stripped=t.stripped,
        symbols_present=symbols,
        mitigations=dict(t.mitigations),
    )


def _verdict_and_oracle(fd: dict[str, Any]) -> tuple[str, str]:
    """Derive ``(verdict, oracle)`` from the internal ``serialize.finding_dict``.

    PoV-is-truth: ``confirmed`` only when a reproducing PoV is attached. The oracle
    name is the deterministic stage that *decided* the verdict, attributed from the
    evidence the finding actually carries (no LLM ever decides truth)."""
    if fd.get("confirmed"):
        pov = fd.get("pov") or {}
        if pov.get("diff_allocator"):
            return "confirmed", "differential-allocator"
        if pov.get("capability"):
            return "confirmed", "canary-marker"
        return "confirmed", "differential-crash"
    if fd.get("pruned"):
        return "pruned", "angr-reachability(UNSAT)"
    # An unconfirmed-but-plausible lead: the cheap/LLM funnel surfaced it, no oracle
    # has confirmed it. It is a hypothesis, never silently promoted.
    return "hypothesis", "llm-triage"


def _dedup_findings(findings: list[TriagedFinding]) -> list[TriagedFinding]:
    """Collapse same-bug-different-input confirmed findings (M7 #48) before a
    row is emitted, so the dataset moat carries one record per unique bug. A
    frameless / hypothesis finding is never merged (empty-reject) and a
    genuinely distinct crash always survives — dedup never drops a
    confirmed-unique bug."""
    def key_of(tf: TriagedFinding) -> CrashKey:
        pov = tf.pov
        frames = tuple(pov.frames) if (pov is not None and pov.reproduced) else ()
        addr = hex(getattr(tf.finding, "sink_addr", 0) or 0)
        return CrashKey(crash_addr=addr, frames=frames)

    reps, _ = dedup_items(findings, key_of=key_of)
    return reps


def records_from_run(
    run_result: RunResult,
    *,
    binary: str | Path,
    backend: str,
    now: Callable[[], str] = _utc_now,
    synthetic: bool = False,
    dedup: bool = True,
) -> list[DatasetRecord]:
    """Project one ``DatasetRecord`` per finding of a completed run.

    Built from the internal ``finding_dict`` (richest evidence: oracle, capability,
    dedup, angr outcome) joined with the triage feature vector — so each row is a
    full ``features → label → PoV → verdict+oracle`` datapoint."""
    feats = binary_features(binary)
    name = Path(str(binary)).name
    stamp = now()
    out: list[DatasetRecord] = []
    findings = _dedup_findings(run_result.findings) if dedup else run_result.findings
    for tf in findings:
        fd = finding_dict(tf)
        verdict, oracle = _verdict_and_oracle(fd)
        pov = fd.get("pov") or {}
        offset = str(fd.get("sink_addr") or "0x0")
        bug_class = str(fd.get("bug_class") or "unknown")
        function = str(fd.get("function") or "")
        sink = str(fd.get("sink") or "")
        source = str(fd.get("source") or "")
        pov_path = str(pov.get("pov_script") or "")
        out.append(
            DatasetRecord(
                record_id=record_id(name, function, sink, offset, bug_class),
                dataset_version=DATASET_VERSION,
                created_at=stamp,
                tool=dict(_TOOL),
                backend=backend,
                binary_name=name,
                features=feats,
                bug_class=bug_class,
                source=source,
                sink=sink,
                function=function,
                offset=offset,
                verdict=verdict,
                oracle=oracle,
                capability=str(pov.get("capability") or ""),
                dedup_bucket=str(pov.get("dedup_bucket") or ""),
                pov_path=pov_path,
                repro_cmd=f"python3 {pov_path}" if pov_path else "",
                explanation=str(fd.get("explanation") or ""),
                synthetic=synthetic,
            )
        )
    return out


def validate_record(d: dict[str, Any]) -> None:
    """Enforce the schema contract on a record dict. Raises ``ValueError`` on:

      * unknown MAJOR ``dataset_version`` (a consumer must reject what it can't read);
      * an unknown ``verdict``;
      * **PoV-is-truth** — a ``confirmed`` record with no ``pov.path``;
      * **no-raw-bytes** — any forbidden bytes-bearing key anywhere in the record.
    """
    version = str(d.get("dataset_version", ""))
    if not version:
        raise ValueError("record missing dataset_version")
    major = version.split(".", 1)[0]
    if major != DATASET_VERSION.split(".", 1)[0]:
        raise ValueError(f"incompatible dataset MAJOR version {version!r} (need {DATASET_VERSION})")
    verdict = d.get("verdict")
    if verdict not in VERDICTS:
        raise ValueError(f"unknown verdict {verdict!r}")
    pov_path = ((d.get("pov") or {}).get("path")) or ""
    if verdict == "confirmed" and not pov_path:
        raise ValueError("PoV-is-truth violation: confirmed record with no pov.path")
    pov_sha256 = ((d.get("pov") or {}).get("sha256")) or ""
    if pov_sha256 and (
        not isinstance(pov_sha256, str)
        or len(pov_sha256) != 64
        or any(char not in "0123456789abcdef" for char in pov_sha256)
    ):
        raise ValueError("pov.sha256 must be a lowercase SHA-256")
    event_id = d.get("event_id", "")
    if event_id and (
        not isinstance(event_id, str)
        or len(event_id) != 71
        or not event_id.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in event_id[7:])
    ):
        raise ValueError("event_id must be a sha256: content digest")
    provenance = d.get("provenance", {})
    if provenance and not isinstance(provenance, dict):
        raise ValueError("provenance must be an object")
    if provenance:
        expected = {
            "contract",
            "runKey",
            "terminalReceiptDigest",
            "itemId",
            "attempt",
            "payloadDigest",
            "adapterReceiptDigest",
            "evidenceDigest",
            "outputTreeDigest",
        }
        if set(provenance) != expected:
            raise ValueError("feedback provenance has an invalid shape")
        if provenance["contract"] != "0brain-zeroverse-feedback-v1":
            raise ValueError("feedback provenance has an unsupported contract")
        if not isinstance(provenance["runKey"], str) or not re.fullmatch(
            r"0research-[0-9a-f]{64}", provenance["runKey"]
        ):
            raise ValueError("feedback provenance runKey is invalid")
        if not isinstance(provenance["itemId"], str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9._-]{2,127}", provenance["itemId"]
        ):
            raise ValueError("feedback provenance itemId is invalid")
        if (
            isinstance(provenance["attempt"], bool)
            or not isinstance(provenance["attempt"], int)
            or provenance["attempt"] < 1
        ):
            raise ValueError("feedback provenance attempt is invalid")
        for key in (
            "terminalReceiptDigest",
            "payloadDigest",
            "adapterReceiptDigest",
            "evidenceDigest",
            "outputTreeDigest",
        ):
            value = provenance[key]
            if (
                not isinstance(value, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            ):
                raise ValueError(f"feedback provenance {key} is invalid")
    _assert_no_raw_bytes(d)


def _assert_no_raw_bytes(obj: Any, _path: str = "") -> None:
    """Walk the record and reject any forbidden payload-bearing key. The corpus is
    the moat; the OSS capture carries labels + pointers, never crash bytes."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _FORBIDDEN_KEYS:
                raise ValueError(f"forbidden raw-bytes key {k!r} at {_path or '<root>'}")
            _assert_no_raw_bytes(v, f"{_path}.{k}" if _path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _assert_no_raw_bytes(v, f"{_path}[{i}]")


def emit_records(records: list[DatasetRecord], path: str | Path) -> int:
    """Append records as NDJSON (one per line). Append-only — the corpus only grows.
    Each record is validated before it is written. Returns the count written."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for r in records:
        d = r.to_dict()
        validate_record(d)
        lines.append(json.dumps(d, sort_keys=True))
    if not lines:
        return 0
    with out.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(lines)


def emit_run(
    run_result: RunResult,
    path: str | Path,
    *,
    binary: str | Path,
    backend: str,
    now: Callable[[], str] = _utc_now,
) -> int:
    """Capture a whole run: append one validated record per finding. Returns count."""
    recs = records_from_run(run_result, binary=binary, backend=backend, now=now)
    return emit_records(recs, path)


def iter_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """Read back an NDJSON dataset file, validating each record."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        d: dict[str, Any] = json.loads(line)
        validate_record(d)
        yield d
