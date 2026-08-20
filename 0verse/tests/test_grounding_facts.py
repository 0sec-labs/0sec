"""Tests for the inert, evidence-only IDA/NtRays facts sidecar."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from zeroverse.grounding import ClaimVerdict
from zeroverse.grounding_facts import (
    FactBundleError,
    adjudicate_call_edge,
    adjudicate_type_field,
    adjudicate_xref_as_call,
    canonical_bundle_digest,
    load_fact_bundle,
    parse_fact_bundle,
    verify_artifacts,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "grounding_facts"


def _bundle(name: str):
    return load_fact_bundle(_FIXTURES / name)


def test_valid_bundle_is_canonical_and_groundable() -> None:
    facts = _bundle("valid.json")
    payload = json.loads((_FIXTURES / "valid.json").read_text(encoding="utf-8"))

    assert facts.sha256 == canonical_bundle_digest(payload)
    assert facts.target.codeview_guid == "12345678-1234-5678-9abc-def012345678"
    assert facts.functions_by_rva[0x1000].name == "DriverEntry"
    assert adjudicate_call_edge(
        facts,
        caller_rva=0x1000,
        callee_rva=0x2000,
    ).verdict is ClaimVerdict.GROUNDED
    assert adjudicate_type_field(
        facts,
        function_rva=0x1000,
        field_offset=0x180,
        access="read",
    ).verdict is ClaimVerdict.GROUNDED


def test_declared_bundle_digest_mismatch_fails_closed() -> None:
    with pytest.raises(FactBundleError, match="bundle_sha256"):
        _bundle("sha-mismatch.json")


def test_indirect_call_never_grounds_a_direct_call_claim() -> None:
    facts = _bundle("indirect.json")

    result = adjudicate_call_edge(facts, caller_rva=0x1000, callee_rva=0x2000)

    assert result.verdict is ClaimVerdict.UNKNOWN
    assert "indirect" in result.fact


def test_xref_never_becomes_a_call_edge() -> None:
    facts = _bundle("phantom-xref.json")

    result = adjudicate_call_edge(facts, caller_rva=0x1000, callee_rva=0x2000)

    assert result.verdict is ClaimVerdict.UNKNOWN
    assert adjudicate_xref_as_call(facts).verdict is ClaimVerdict.UNKNOWN


def test_pseudoc_only_type_recovery_stays_unknown() -> None:
    facts = _bundle("pseudoc-only-type.json")

    result = adjudicate_type_field(
        facts,
        function_rva=0x1000,
        field_offset=0x180,
        access="read",
    )

    assert result.verdict is ClaimVerdict.UNKNOWN
    assert "pseudo-C" in result.fact


def test_artifacts_must_match_the_sidecar_identity(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.sys"
    pdb = tmp_path / "fixture.pdb"
    binary.write_bytes(b"binary-fixture")
    pdb.write_bytes(b"pdb-fixture")
    payload = json.loads((_FIXTURES / "valid.json").read_text(encoding="utf-8"))
    payload["target"]["sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    payload["target"]["codeview"]["pdb_sha256"] = hashlib.sha256(pdb.read_bytes()).hexdigest()
    facts = parse_fact_bundle(payload)

    verify_artifacts(facts, binary, pdb)

    pdb.write_bytes(b"wrong-pdb")
    with pytest.raises(FactBundleError, match="PDB SHA-256"):
        verify_artifacts(facts, binary, pdb)
