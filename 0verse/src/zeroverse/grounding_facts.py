"""Optional, evidence-bound structural facts for the G1 grounding gate.

This module deliberately does *not* select a decompiler or alter the normal
pipeline.  It validates an external, bring-your-own facts sidecar so an
IDA/Hex-Rays/NtRays experiment can be measured against the existing free Ghidra
path without treating decompiler pseudo-C as ground truth.

Only instruction-backed direct call edges and field accesses with PDB, KD, or
direct-disassembly provenance can ground a premise.  Missing data, indirect
calls, pseudo-C-only type recovery, and xrefs all remain UNKNOWN.  This is a
research seam; it cannot create a finding or confirm a vulnerability.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .grounding import ClaimVerdict

SCHEMA_VERSION = "zeroverse-grounding-facts/v1"
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_BYTES = re.compile(r"^[0-9a-fA-F]+$")
_TRUSTED_TYPE_SOURCES = frozenset({"pdb", "kd", "disassembly"})


class FactBundleError(ValueError):
    """Raised when an external grounding-facts bundle is malformed or mismatched."""


@dataclass(frozen=True)
class TargetIdentity:
    sha256: str
    machine: str
    image_base: int
    size: int
    codeview_guid: str
    codeview_age: int
    pdb_sha256: str


@dataclass(frozen=True)
class ProducerIdentity:
    schema: str
    exporter_sha256: str
    ida_version: str
    hexrays_version: str
    ntrays_version: str | None
    idb_sha256: str


@dataclass(frozen=True)
class FunctionFact:
    rva: int
    name: str


@dataclass(frozen=True)
class CallEdgeFact:
    caller_rva: int
    site_rva: int
    callee_rva: int | None
    import_name: str | None
    edge_kind: str
    resolved: bool
    instruction_bytes: str


@dataclass(frozen=True)
class XrefFact:
    function_rva: int
    site_rva: int
    target_rva: int | None
    import_name: str | None
    ref_type: str


@dataclass(frozen=True)
class TypeFieldFact:
    function_rva: int
    site_rva: int
    field_offset: int
    access: str
    width: int
    type_name: str
    type_field: str
    type_source: str
    instruction_bytes: str


@dataclass(frozen=True)
class UnresolvedCallFact:
    function_rva: int
    site_rva: int
    reason: str


@dataclass(frozen=True)
class FactBundle:
    target: TargetIdentity
    producer: ProducerIdentity
    functions: tuple[FunctionFact, ...]
    call_edges: tuple[CallEdgeFact, ...]
    xrefs: tuple[XrefFact, ...]
    type_fields: tuple[TypeFieldFact, ...]
    unresolved_calls: tuple[UnresolvedCallFact, ...]
    sha256: str

    @property
    def functions_by_rva(self) -> dict[int, FunctionFact]:
        return {function.rva: function for function in self.functions}


@dataclass(frozen=True)
class FactAdjudication:
    """A structural fact result suitable for later G1 integration."""

    verdict: ClaimVerdict
    fact: str
    evidence_rva: int | None = None


def canonical_bundle_digest(payload: Mapping[str, Any]) -> str:
    """Return the SHA-256 of the stable JSON body, excluding any self-digest."""
    body = dict(payload)
    body.pop("bundle_sha256", None)
    encoded = json.dumps(
        body,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_fact_bundle(path: str | Path) -> FactBundle:
    """Load and validate a standalone facts sidecar."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise FactBundleError("facts bundle root must be an object")
    return parse_fact_bundle(data)


def parse_fact_bundle(payload: Mapping[str, Any]) -> FactBundle:
    """Validate a facts sidecar without invoking IDA, Ghidra, or a binary."""
    raw = dict(payload)
    expected_digest = raw.get("bundle_sha256")
    digest = canonical_bundle_digest(raw)
    if expected_digest is not None and _digest(expected_digest, "bundle_sha256") != digest:
        raise FactBundleError("bundle_sha256 does not match the canonical facts body")
    if _text(raw, "schema_version") != SCHEMA_VERSION:
        raise FactBundleError(f"unsupported schema_version (expected {SCHEMA_VERSION})")

    target = _parse_target(_object(raw, "target"))
    producer = _parse_producer(_object(raw, "producer"))
    functions = tuple(
        _parse_function(item, index)
        for index, item in enumerate(_array(raw, "functions"))
    )
    function_rvas = {function.rva for function in functions}
    if not functions or len(function_rvas) != len(functions):
        raise FactBundleError("functions must contain unique RVAs")

    call_edges = tuple(
        _parse_call_edge(item, index, function_rvas)
        for index, item in enumerate(_array(raw, "call_edges"))
    )
    xrefs = tuple(
        _parse_xref(item, index, function_rvas)
        for index, item in enumerate(_array(raw, "xrefs"))
    )
    type_fields = tuple(
        _parse_type_field(item, index, function_rvas)
        for index, item in enumerate(_array(raw, "type_fields"))
    )
    unresolved_calls = tuple(
        _parse_unresolved_call(item, index, function_rvas)
        for index, item in enumerate(_array(raw, "unresolved_calls"))
    )

    return FactBundle(
        target=target,
        producer=producer,
        functions=functions,
        call_edges=call_edges,
        xrefs=xrefs,
        type_fields=type_fields,
        unresolved_calls=unresolved_calls,
        sha256=digest,
    )


def verify_artifacts(
    facts: FactBundle,
    binary_path: str | Path,
    pdb_path: str | Path,
) -> None:
    """Fail closed unless both evaluated artifact hashes match the sidecar."""
    binary_digest = _file_digest(Path(binary_path))
    if binary_digest != facts.target.sha256:
        raise FactBundleError("binary SHA-256 does not match the facts target")
    pdb_digest = _file_digest(Path(pdb_path))
    if pdb_digest != facts.target.pdb_sha256:
        raise FactBundleError("PDB SHA-256 does not match the facts target")


def adjudicate_call_edge(
    facts: FactBundle,
    *,
    caller_rva: int,
    callee_rva: int | None = None,
    import_name: str | None = None,
) -> FactAdjudication:
    """Ground only an exact, resolved, instruction-backed direct call edge."""
    if (callee_rva is None) == (import_name is None):
        raise ValueError("provide exactly one of callee_rva or import_name")

    matching = [
        edge
        for edge in facts.call_edges
        if edge.caller_rva == caller_rva
        and (
            edge.callee_rva == callee_rva
            if callee_rva is not None
            else edge.import_name == import_name
        )
    ]
    if not matching:
        return FactAdjudication(
            ClaimVerdict.UNKNOWN,
            "no matching call edge in the facts sidecar; absence is not a refutation",
        )
    for edge in matching:
        if edge.edge_kind == "direct" and edge.resolved:
            return FactAdjudication(
                ClaimVerdict.GROUNDED,
                f"direct call edge evidenced at RVA 0x{edge.site_rva:x}",
                edge.site_rva,
            )
    return FactAdjudication(
        ClaimVerdict.UNKNOWN,
        "matching edge is indirect or unresolved; it cannot ground a direct call claim",
    )


def adjudicate_type_field(
    facts: FactBundle,
    *,
    function_rva: int,
    field_offset: int,
    access: str | None = None,
) -> FactAdjudication:
    """Ground a field fact only with trusted provenance and instruction evidence."""
    matching = [
        field
        for field in facts.type_fields
        if field.function_rva == function_rva
        and field.field_offset == field_offset
        and (access is None or field.access == access)
    ]
    if not matching:
        return FactAdjudication(
            ClaimVerdict.UNKNOWN,
            "no matching type/field fact in the facts sidecar; absence is not a refutation",
        )
    for field in matching:
        if field.type_source in _TRUSTED_TYPE_SOURCES:
            return FactAdjudication(
                ClaimVerdict.GROUNDED,
                f"{field.type_source} and instruction evidence agree at RVA 0x{field.site_rva:x}",
                field.site_rva,
            )
    return FactAdjudication(
        ClaimVerdict.UNKNOWN,
        "type/field fact is decompiler pseudo-C only; it cannot ground an operand claim",
    )


def adjudicate_xref_as_call(*_: object) -> FactAdjudication:
    """Make the xref/call boundary explicit: a reference is never a call edge."""
    return FactAdjudication(
        ClaimVerdict.UNKNOWN,
        "xref evidence is not a call edge and cannot ground a call claim",
    )


def _parse_target(raw: dict[str, Any]) -> TargetIdentity:
    codeview = _object(raw, "codeview")
    guid = _text(codeview, "guid")
    try:
        codeview_guid = str(uuid.UUID(guid))
    except ValueError as exc:
        raise FactBundleError("target.codeview.guid must be a UUID") from exc
    return TargetIdentity(
        sha256=_digest(raw.get("sha256"), "target.sha256"),
        machine=_text(raw, "machine"),
        image_base=_rva(raw.get("image_base"), "target.image_base"),
        size=_positive_int(raw.get("size"), "target.size"),
        codeview_guid=codeview_guid,
        codeview_age=_positive_int(codeview.get("age"), "target.codeview.age"),
        pdb_sha256=_digest(codeview.get("pdb_sha256"), "target.codeview.pdb_sha256"),
    )


def _parse_producer(raw: dict[str, Any]) -> ProducerIdentity:
    version = raw.get("ntrays_version")
    if version is not None and not isinstance(version, str):
        raise FactBundleError("producer.ntrays_version must be a string or null")
    return ProducerIdentity(
        schema=_text(raw, "schema"),
        exporter_sha256=_digest(raw.get("exporter_sha256"), "producer.exporter_sha256"),
        ida_version=_text(raw, "ida_version"),
        hexrays_version=_text(raw, "hexrays_version"),
        ntrays_version=version,
        idb_sha256=_digest(raw.get("idb_sha256"), "producer.idb_sha256"),
    )


def _parse_function(value: object, index: int) -> FunctionFact:
    raw = _entry(value, "functions", index)
    return FunctionFact(
        rva=_rva(raw.get("rva"), f"functions[{index}].rva"),
        name=_text(raw, "name"),
    )


def _parse_call_edge(
    value: object,
    index: int,
    function_rvas: set[int],
) -> CallEdgeFact:
    raw = _entry(value, "call_edges", index)
    callee_rva, import_name = _target(raw, f"call_edges[{index}]")
    caller_rva = _rva(raw.get("caller_rva"), f"call_edges[{index}].caller_rva")
    if caller_rva not in function_rvas:
        raise FactBundleError(f"call_edges[{index}] caller_rva is not a known function")
    if callee_rva is not None and callee_rva not in function_rvas:
        raise FactBundleError(f"call_edges[{index}] callee_rva is not a known function")
    edge_kind = _text(raw, "edge_kind").lower()
    if edge_kind not in {"direct", "indirect"}:
        raise FactBundleError(f"call_edges[{index}].edge_kind must be direct or indirect")
    resolved = raw.get("resolved")
    if not isinstance(resolved, bool):
        raise FactBundleError(f"call_edges[{index}].resolved must be a boolean")
    return CallEdgeFact(
        caller_rva=caller_rva,
        site_rva=_rva(raw.get("site_rva"), f"call_edges[{index}].site_rva"),
        callee_rva=callee_rva,
        import_name=import_name,
        edge_kind=edge_kind,
        resolved=resolved,
        instruction_bytes=_instruction_bytes(raw.get("instruction_bytes"), f"call_edges[{index}]"),
    )


def _parse_xref(value: object, index: int, function_rvas: set[int]) -> XrefFact:
    raw = _entry(value, "xrefs", index)
    target_rva, import_name = _target(raw, f"xrefs[{index}]", prefix="target")
    function_rva = _rva(raw.get("function_rva"), f"xrefs[{index}].function_rva")
    if function_rva not in function_rvas:
        raise FactBundleError(f"xrefs[{index}] function_rva is not a known function")
    ref_type = _text(raw, "ref_type").lower()
    if ref_type not in {"call", "code", "data", "read", "write"}:
        raise FactBundleError(f"xrefs[{index}].ref_type is unsupported")
    return XrefFact(
        function_rva=function_rva,
        site_rva=_rva(raw.get("site_rva"), f"xrefs[{index}].site_rva"),
        target_rva=target_rva,
        import_name=import_name,
        ref_type=ref_type,
    )


def _parse_type_field(
    value: object,
    index: int,
    function_rvas: set[int],
) -> TypeFieldFact:
    raw = _entry(value, "type_fields", index)
    function_rva = _rva(raw.get("function_rva"), f"type_fields[{index}].function_rva")
    if function_rva not in function_rvas:
        raise FactBundleError(f"type_fields[{index}] function_rva is not a known function")
    access = _text(raw, "access").lower()
    if access not in {"read", "write", "address"}:
        raise FactBundleError(f"type_fields[{index}].access is unsupported")
    type_data = _object(raw, "type")
    return TypeFieldFact(
        function_rva=function_rva,
        site_rva=_rva(raw.get("site_rva"), f"type_fields[{index}].site_rva"),
        field_offset=_rva(raw.get("field_offset"), f"type_fields[{index}].field_offset"),
        access=access,
        width=_positive_int(raw.get("width"), f"type_fields[{index}].width"),
        type_name=_text(type_data, "name"),
        type_field=_text(type_data, "field"),
        type_source=_text(type_data, "source").lower(),
        instruction_bytes=_instruction_bytes(raw.get("instruction_bytes"), f"type_fields[{index}]"),
    )


def _parse_unresolved_call(
    value: object,
    index: int,
    function_rvas: set[int],
) -> UnresolvedCallFact:
    raw = _entry(value, "unresolved_calls", index)
    function_rva = _rva(raw.get("function_rva"), f"unresolved_calls[{index}].function_rva")
    if function_rva not in function_rvas:
        raise FactBundleError(f"unresolved_calls[{index}] function_rva is not a known function")
    return UnresolvedCallFact(
        function_rva=function_rva,
        site_rva=_rva(raw.get("site_rva"), f"unresolved_calls[{index}].site_rva"),
        reason=_text(raw, "reason"),
    )


def _array(raw: Mapping[str, Any], key: str) -> list[object]:
    value = raw.get(key)
    if not isinstance(value, list):
        raise FactBundleError(f"{key} must be an array")
    return value


def _object(raw: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise FactBundleError(f"{key} must be an object")
    return value


def _entry(value: object, name: str, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FactBundleError(f"{name}[{index}] must be an object")
    return value


def _text(raw: Mapping[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise FactBundleError(f"{key} must be a non-empty string")
    return value.strip()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise FactBundleError(f"{label} must be a SHA-256 hex digest")
    return value.lower()


def _rva(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise FactBundleError(f"{label} must be an RVA")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise FactBundleError(f"{label} must be an RVA") from exc
    else:
        raise FactBundleError(f"{label} must be an RVA")
    if not 0 <= parsed < 2**64:
        raise FactBundleError(f"{label} is outside the RVA range")
    return parsed


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FactBundleError(f"{label} must be a positive integer")
    return value


def _instruction_bytes(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) % 2 or not _HEX_BYTES.fullmatch(value):
        raise FactBundleError(f"{label}.instruction_bytes must be non-empty hex")
    return value.lower()


def _target(
    raw: Mapping[str, Any],
    label: str,
    *,
    prefix: str = "callee",
) -> tuple[int | None, str | None]:
    rva_key = f"{prefix}_rva"
    import_key = "import"
    has_rva = raw.get(rva_key) is not None
    has_import = raw.get(import_key) is not None
    if has_rva == has_import:
        raise FactBundleError(f"{label} must contain exactly one of {rva_key} or {import_key}")
    if has_rva:
        return _rva(raw.get(rva_key), f"{label}.{rva_key}"), None
    return None, _text(raw, import_key)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
