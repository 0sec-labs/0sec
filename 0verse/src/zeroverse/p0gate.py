"""P0 gate — reproducible known-CVE evaluation contract for stripped x86-64 Linux ELFs.

This module implements the evaluation contract for the 0verse P0 gate
benchmark (known-CVE reproducibility on stripped binaries via a local dynamic
oracle). The contract enforces:

- **Immutable target identity**: every item identifies its target ELF by
  SHA-256 digest, NOT by path or name. The runner preflight verifies the
  on-disk binary against the manifest digest.
- **Local dynamic oracle**: confirmation requires a reproducing crash/ASan hit
  from a local oracle invocation. Static-only hypotheses are never promoted to
  confirmed.
- **Honest outcome taxonomy**: reach / confirmed / refuted / inconclusive,
  plus an explicit false-positive count.
- **Reproducible environment capture**: binary digest, 0verse tool digest,
  and enough platform metadata (OS, arch, Python version) to replicate.

Schema versioning follows the same MAJOR.MINOR policy as groundtruth.py:
bump MINOR for additive fields, MAJOR for removals/renames.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import platform
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

P0GATE_SCHEMA_VERSION = "1.0"
_P0GATE_VERSION = "0.0.1"

# Oracle kind — currently only local dynamic is defined.
ORACLE_KINDS = ("local-dynamic",)

# Oracle capability ladder rungs.
ORACLE_CAPABILITIES = ("crash", "asan-hit", "ubsan-hit", "oob-write", "oob-read", "uaf-access")

# Ground-truth labels.
LABELS = ("vulnerable", "clean")

# Outcome taxonomy.
OUTCOME_REACH = "reach"           # oracle reached the expected path/location
OUTCOME_CONFIRMED = "confirmed"   # reproducing crash/ASan hit at expected location
OUTCOME_REFUTED = "refuted"       # oracle exercised the path but no crash/ASan hit
OUTCOME_INCONCLUSIVE = "inconclusive"  # oracle could not determine (bad environment, etc.)


# ---------------------------------------------------------------------------
# Manifest types
# ---------------------------------------------------------------------------


@dataclass
class SourceIdentity:
    """Immutable provenance identity for a known-CVE target binary.

    Every vulnerable binary is traced to a verifiable source — an upstream
    package, source commit, or container image — so the finding is reproducible
    and grounded.
    """
    kind: str  # E.g. upstream-package, source-commit, container-image, cve-reference.
    ref: str  # Package version, commit hash, or image digest.
    url: str | None = None  # Optional provenance URL.

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.kind:
            errors.append("source_identity.kind is required")
        if not self.ref:
            errors.append("source_identity.ref is required")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in dataclasses.asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SourceIdentity:
        return cls(kind=d.get("kind", ""), ref=d.get("ref", ""), url=d.get("url"))


@dataclass
class OracleSpec:
    """Describes the dynamic oracle required for this target.

    ``kind`` must be ``"local-dynamic"``. The oracle script/input lives at
    ``trigger_input`` (relative to the benchmark directory), and the expected
    capability is one of the ORACLE_CAPABILITIES ladder.
    """
    kind: str = "local-dynamic"
    capability: str = "crash"
    trigger_input: str = ""          # relative path to input that triggers the bug
    asan_build: bool = True          # was the target compiled with ASan?

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.kind not in ("local-dynamic",):
            errors.append(f"oracle.kind must be 'local-dynamic', got '{self.kind}'")
        if self.capability not in ORACLE_CAPABILITIES:
            errors.append(
                f"oracle.capability must be one of {ORACLE_CAPABILITIES}, "
                f"got '{self.capability}'"
            )
        if not self.trigger_input:
            errors.append("oracle.trigger_input is required")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> OracleSpec:
        return cls(
            kind=d.get("kind", "local-dynamic"),
            capability=d.get("capability", "crash"),
            trigger_input=d.get("trigger_input", ""),
            asan_build=d.get("asan_build", True),
        )


@dataclass
class ExpectedLocation:
    """Expected location (offset plus optional function hint) of the vulnerability."""

    binary_offset: str = ""  # E.g. "0x12345".
    function: str = ""  # E.g. recovered "undefined::parse_input+0x3a".

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.binary_offset:
            errors.append("expected_location.binary_offset is required")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ExpectedLocation:
        return cls(
            binary_offset=d.get("binary_offset", ""),
            function=d.get("function", ""),
        )


@dataclass
class P0GateItem:
    """One known-CVE entry in the P0 gate manifest.

    Every vulnerable item (label="vulnerable") describes a stripped x86-64 Linux
    ELF identified by ``target_sha256`` — the digest of the binary artifact.
    Clean items are used as false-positive controls.

    ``oracle_kind`` is always ``"local-dynamic"`` for this evaluation contract.
    The runner preflight verifies that the binary on disk matches the digest
    before running.
    """
    id: str
    cve: str                         # CVE identifier
    cwe: str                         # CWE classification
    label: Literal["vulnerable", "clean"]
    target_sha256: str               # SHA-256 of the stripped ELF binary
    source_identity: SourceIdentity
    oracle: OracleSpec
    provenance: str                  # human-readable provenance description
    target_artifact: str = ""        # relative path (from manifest dir) to the binary
    expected_location: ExpectedLocation | None = None  # null for clean items
    compile_options: str = ""        # compiler flags used to build the target
    arch: str = "x86_64"
    os: str = "linux"
    note: str = ""

    @property
    def is_vulnerable(self) -> bool:
        return self.label == "vulnerable"

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.id:
            errors.append("id is required")
        if not self.cve and self.label == "vulnerable":
            errors.append("cve is required for vulnerable items")
        if self.label not in LABELS:
            errors.append(f"label must be one of {LABELS}, got '{self.label}'")
        if len(self.target_sha256) != 64 or any(
            char not in "0123456789abcdefABCDEF" for char in self.target_sha256
        ):
            errors.append("target_sha256 must be 64 hexadecimal characters")
        errors.extend(self.source_identity.validate())
        errors.extend(self.oracle.validate())
        if self.is_vulnerable and self.expected_location:
            errors.extend(self.expected_location.validate())
        return errors

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "cve": self.cve,
            "cwe": self.cwe,
            "label": self.label,
            "target_sha256": self.target_sha256,
            "source_identity": self.source_identity.to_dict(),
            "oracle": self.oracle.to_dict(),
            "provenance": self.provenance,
        }
        for optional_key in ("target_artifact", "compile_options", "arch", "os", "note"):
            val = getattr(self, optional_key)
            if val:
                d[optional_key] = val
        if self.expected_location:
            d["expected_location"] = self.expected_location.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> P0GateItem:
        si = SourceIdentity.from_dict(d.get("source_identity", {}))
        osp = OracleSpec.from_dict(d.get("oracle", {}))
        el = None
        if d.get("expected_location"):
            el = ExpectedLocation.from_dict(d["expected_location"])
        return cls(
            id=d.get("id", ""),
            cve=d.get("cve", ""),
            cwe=d.get("cwe", ""),
            label=d.get("label", "vulnerable"),
            target_sha256=d.get("target_sha256", ""),
            source_identity=si,
            oracle=osp,
            provenance=d.get("provenance", ""),
            target_artifact=d.get("target_artifact", ""),
            expected_location=el,
            compile_options=d.get("compile_options", ""),
            arch=d.get("arch", "x86_64"),
            os=d.get("os", "linux"),
            note=d.get("note", ""),
        )


@dataclass
class P0GateManifest:
    """Full P0 gate evaluation manifest."""
    schema_version: str
    kind: str = "p0-gate-known-cve"
    items: list[P0GateItem] = field(default_factory=list)

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.schema_version.split(".")[0] != P0GATE_SCHEMA_VERSION.split(".")[0]:
            errors.append(
                f"incompatible schema MAJOR version: manifest={self.schema_version} "
                f"expected MAJOR={P0GATE_SCHEMA_VERSION.split('.')[0]}"
            )
        if not self.kind:
            errors.append("kind is required")
        if not self.items:
            errors.append("items list is empty")
        for item in self.items:
            item_errors = item.validate()
            if item_errors:
                errors.append(f"item '{item.id}' validation errors: {'; '.join(item_errors)}")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "items": [it.to_dict() for it in self.items],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> P0GateManifest:
        items = [P0GateItem.from_dict(i) for i in d.get("items", [])]
        return cls(
            schema_version=d.get("schema_version", ""),
            kind=d.get("kind", "p0-gate-known-cve"),
            items=items,
        )


def load_manifest(path: str | Path) -> P0GateManifest:
    """Load a P0 gate manifest, rejecting every structural validation error."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    manifest = P0GateManifest.from_dict(raw)
    errors = manifest.validate()
    if errors:
        raise ValueError(f"invalid P0 gate manifest: {'; '.join(errors)}")
    return manifest


# ---------------------------------------------------------------------------
# Outcome types
# ---------------------------------------------------------------------------


@dataclass
class OracleResult:
    """Result from running the local dynamic oracle on one target binary.

    If the oracle did not run (static-only analysis), set ``ran=False`` and
    ``outcome`` to ``"inconclusive"``. The runner preflight MUST refuse to
    serialize an outcome of ``"confirmed"`` when ``ran=False``.
    """
    outcome: str  # "reach" | "confirmed" | "refuted" | "inconclusive"
    ran: bool = False        # did the oracle actually execute?
    expected_path_reached: bool = False  # did oracle reach the expected location?
    crash_signal: str = ""   # signal/code if crashed
    stderr_hint: str = ""    # ASan/UBSan output snippet if relevant
    error: str = ""          # runtime error if oracle failed to start

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.outcome not in (
            OUTCOME_REACH,
            OUTCOME_CONFIRMED,
            OUTCOME_REFUTED,
            OUTCOME_INCONCLUSIVE,
        ):
            errors.append(
                f"outcome must be one of reach/confirmed/refuted/inconclusive, "
                f"got '{self.outcome}'"
            )
        if self.outcome == OUTCOME_CONFIRMED and not self.ran:
            errors.append(
                "CONFIRMED outcome requires a dynamic oracle run (ran=True); "
                "static-only hypotheses cannot be serialized as confirmed. "
                "Set outcome=located-hypothesis or run the oracle first."
            )
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in dataclasses.asdict(self).items() if v is not None}


@dataclass
class BinaryDigest:
    """Digest of the target binary for reproducibility."""
    sha256: str
    size: int                           # file size in bytes
    path: str = ""                      # absolute path at evaluation time

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"sha256": self.sha256, "size": self.size}
        if self.path:
            d["path"] = self.path
        return d


@dataclass
class ToolDigest:
    """0verse tool version and configuration."""
    version: str                        # zeroverse.__version__
    schema_version: str = P0GATE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "schema_version": self.schema_version}


@dataclass
class Environment:
    """Platform environment at evaluation time for reproducibility."""
    os: str
    arch: str
    python_version: str
    platform_detail: str = ""
    libc_info: str = ""

    @classmethod
    def capture(cls) -> Environment:
        return cls(
            os=sys.platform,
            arch=platform.machine(),
            python_version=sys.version,
            platform_detail=platform.platform(),
            libc_info=cls._libc_info(),
        )

    @staticmethod
    def _libc_info() -> str:
        try:
            from ctypes import CDLL, c_char_p
            libc = CDLL("libc.dylib" if sys.platform == "darwin" else "libc.so.6")
            libc.gnu_get_libc_version.restype = c_char_p
            version = libc.gnu_get_libc_version()
            if not version:
                return ""
            if isinstance(version, bytes):
                return version.decode("ascii", errors="replace")
            return str(version)
        except Exception:
            return ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Result serialization
# ---------------------------------------------------------------------------


@dataclass
class P0GateResult:
    """Complete result for one target's P0 gate evaluation run.

    ``confirmed`` is true ONLY when the local dynamic oracle ran and produced a
    reproducing outcome. Setting ``confirmed=True`` with ``oracle_result.ran=False``
    raises a validation error.
    """
    item_id: str
    cve: str
    label: str
    observed: OracleResult
    false_positive_count: int = 0       # number of false-positive findings
    binary: BinaryDigest | None = None
    tool: ToolDigest | None = None
    environment: Environment | None = None
    wall_s: float = 0.0

    def validate(self) -> list[str]:
        errors: list[str] = []
        errors.extend(self.observed.validate())
        return errors

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "item_id": self.item_id,
            "cve": self.cve,
            "label": self.label,
            "observed": self.observed.to_dict(),
            "false_positive_count": self.false_positive_count,
        }
        if self.binary:
            d["binary"] = self.binary.to_dict()
        if self.tool:
            d["tool"] = self.tool.to_dict()
        if self.environment:
            d["environment"] = self.environment.to_dict()
        if self.wall_s:
            d["wall_s"] = self.wall_s
        return d


def digest_binary(path: str | Path) -> BinaryDigest:
    """Compute the SHA-256 digest and size of a binary on disk."""
    p = Path(path)
    size = p.stat().st_size
    h = hashlib.sha256()
    with p.open("rb") as f:
        while True:
            block = f.read(65536)
            if not block:
                break
            h.update(block)
    return BinaryDigest(
        sha256=h.hexdigest(),
        size=size,
        path=str(p.resolve()),
    )


def verify_target_digest(target_root: str | Path, item: P0GateItem) -> list[str]:
    """Verify that an item's on-disk target matches the manifest digest.

    ``target_root`` is the directory that contains ``item.target_artifact``.
    Returns a list of error messages (empty = match).
    """
    if not item.target_artifact:
        return ["target_artifact path is empty — cannot verify digest"]
    target_path = Path(target_root) / item.target_artifact
    if not target_path.exists():
        return [f"target artifact not found at {target_path}"]
    observed = digest_binary(target_path)
    if observed.sha256 != item.target_sha256:
        return [
            f"SHA-256 mismatch for {item.id}: "
            f"manifest={item.target_sha256}, observed={observed.sha256} "
            f"(path={target_path})"
        ]
    return []


def serialize_results(results: list[P0GateResult], path: str | Path) -> None:
    """Serialize a list of P0 gate results to a JSON file.

    Raises ValueError if any result contains a static-only confirmed outcome.
    The preflight check runs here so callers don't forget.
    """
    for r in results:
        errs = r.validate()
        if errs:
            raise ValueError(
                f"result for item '{r.item_id}' is invalid: {'; '.join(errs)}"
            )
    documents = [r.to_dict() for r in results]
    payload = {
        "schema_version": P0GATE_SCHEMA_VERSION,
        "kind": "p0-gate-known-cve-results",
        "generated_at": datetime.now(UTC).isoformat(),
        "results": documents,
    }
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


@dataclass
class PreflightReport:
    """Report from the preflight check, run before any oracle work."""
    target_matches: list[str]          # item ids whose digest matches
    target_mismatches: list[tuple[str, str]]   # (item_id, error_message)
    items_passing: int
    items_failing: int
    all_pass: bool = False

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def preflight_check(manifest_path: str | Path) -> PreflightReport:
    """Verify every item's binary digest against the manifest.

    Returns a PreflightReport. Items whose target_artifact is empty are
    skipped with a note in target_mismatches.
    """
    manifest = load_manifest(manifest_path)
    matches: list[str] = []
    mismatches: list[tuple[str, str]] = []

    for item in manifest.items:
        if not item.target_artifact:
            mismatches.append((item.id, "no target_artifact in manifest"))
            continue
        errs = verify_target_digest(Path(manifest_path).parent, item)
        if errs:
            mismatches.append((item.id, "; ".join(errs)))
        else:
            matches.append(item.id)

    return PreflightReport(
        target_matches=matches,
        target_mismatches=mismatches,
        items_passing=len(matches),
        items_failing=len(mismatches),
        all_pass=(len(mismatches) == 0),
    )


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------


def count_false_positives(results: list[P0GateResult], items: list[P0GateItem]) -> int:
    """Count confirmed-false-positive findings across clean items.

    A false positive is a confirmed (oracle reproduced) finding reported on a
    clean (non-vulnerable) target.
    """
    item_map = {it.id: it for it in items}
    fp = 0
    for r in results:
        item = item_map.get(r.item_id)
        if item and not item.is_vulnerable and r.observed.outcome == OUTCOME_CONFIRMED:
            fp += 1
    return fp