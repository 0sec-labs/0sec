"""P0 gate — manifest validation, honesty gate, result serialization.

These tests do not run an analysis engine. CLI coverage invokes only the
read-only digest preflight against a generated inert ELF fixture.
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from zeroverse import p0gate

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _minimal_item(**overrides: str | dict) -> dict:
    """Return a dict for a valid minimal P0 gate vulnerable item."""
    item = {
        "id": "CVE-2024-TEST",
        "cve": "CVE-2024-TEST",
        "cwe": "CWE-787",
        "label": "vulnerable",
        "target_sha256": "a" * 64,
        "source_identity": {"kind": "upstream-package", "ref": "test-pkg-1.0"},
        "oracle": {
            "kind": "local-dynamic",
            "capability": "crash",
            "trigger_input": "poc.bin",
            "asan_build": True,
        },
        "provenance": "Test fixture — not a real CVE.",
        "expected_location": {
            "binary_offset": "0x1234",
            "function": "test::func+0x10",
        },
    }
    item.update(**overrides)
    return item


def _make_elf(path: str | Path) -> str:
    """Write a minimal valid x86-64 Linux ELF and return its SHA-256 digest."""
    code = bytes([
        0xb8, 0x3c, 0x00, 0x00, 0x00,  # mov eax, 60 (SYS_exit)
        0xbf, 0x2a, 0x00, 0x00, 0x00,  # mov edi, 42
        0x0f, 0x05,                    # syscall
    ])
    e_ident = (
        b"\x7fELF"                     # magic
        b"\x02\x01\x01\x00"            # 64-bit, LE, v1
        + b"\x00" * 8                  # padding
    )
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        e_ident,
        0x0002,    # ET_EXEC
        0x003e,    # x86-64
        0x00000001,
        0x400078,  # entry
        0x0040,    # phoff
        0x0000,    # shoff
        0x00000000,
        0x0040, 0x0038, 0x0001,   # ehsize, phentsize, phnum
        0x0000, 0x0000, 0x0000,   # shentsize, shnum, shstrndx
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        0x00000001,                 # PT_LOAD
        0x00000005,                 # PF_R | PF_X
        0x0000000000000000,         # offset
        0x0000000000400000,         # vaddr
        0x0000000000400000,         # paddr
        0x0000000000000078 + len(code),  # filesz
        0x0000000000000078 + len(code),  # memsz
        0x0000000000001000,         # align
    )
    pad = b"\x00" * (0x78 - len(ehdr) - len(phdr))
    data = ehdr + phdr + pad + code
    binary = Path(path)
    binary.write_bytes(data)
    binary.chmod(0o755)
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# tests — manifest validation
# ---------------------------------------------------------------------------

def test_good_manifest_validates() -> None:
    """A well-formed manifest with vulnerable + clean items passes validation."""
    d = {
        "schema_version": p0gate.P0GATE_SCHEMA_VERSION,
        "kind": "p0-gate-known-cve",
        "items": [_minimal_item()],
    }
    manifest = p0gate.P0GateManifest.from_dict(d)
    errors = manifest.validate()
    assert not errors, f"expected clean validate, got {errors}"


def test_incomplete_manifest_rejected() -> None:
    """Missing required fields produce validation errors."""
    cases: list[tuple[dict, str]] = [
        ({"schema_version": p0gate.P0GATE_SCHEMA_VERSION,
          "kind": "p0-gate-known-cve", "items": []}, "empty items"),
    ]
    for case_dict, desc in cases:
        manifest = p0gate.P0GateManifest.from_dict(case_dict)
        errors = manifest.validate()
        assert errors, f"expected errors for '{desc}', got none"

    # Item-level errors.
    bad_items: list[tuple[dict, str]] = [
        (_minimal_item(target_sha256=""), "empty sha256"),
        (_minimal_item(target_sha256="abc"), "short sha256"),
        (_minimal_item(label="mystery"), "invalid label"),
        (_minimal_item(target_sha256="z" * 64), "non-hex sha256"),
    ]
    for item_dict, desc in bad_items:
        d = {
            "schema_version": p0gate.P0GATE_SCHEMA_VERSION,
            "kind": "p0-gate-known-cve",
            "items": [item_dict],
        }
        manifest = p0gate.P0GateManifest.from_dict(d)
        errors = manifest.validate()
        assert errors, f"expected errors for '{desc}', got none"


def test_load_manifest_rejects_structural_errors(tmp_path: Path) -> None:
    """The runner boundary rejects an incomplete manifest before preflight."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": p0gate.P0GATE_SCHEMA_VERSION,
                "kind": "p0-gate-known-cve",
                "items": [],
            }
        )
    )

    with pytest.raises(ValueError, match="items list is empty"):
        p0gate.load_manifest(manifest_path)

def test_schema_mismatch_fatal(tmp_path: Path) -> None:
    """A manifest with a different MAJOR version is rejected on load."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "kind": "p0-gate-known-cve",
                "items": [_minimal_item()],
            }
        )
    )

    with pytest.raises(ValueError, match="incompatible schema"):
        p0gate.load_manifest(manifest_path)


# ---------------------------------------------------------------------------
# tests — honesty gate: static-only cannot be confirmed
# ---------------------------------------------------------------------------

def test_static_only_confirmed_rejected() -> None:
    """An OracleResult with confirmed outcome but ran=False is rejected."""
    result = p0gate.OracleResult(outcome="confirmed", ran=False)
    errors = result.validate()
    assert errors, "expected validation errors for static-only confirmed"
    assert any("CONFIRMED" in e or "confirmed" in e.lower() for e in errors), (
        f"expected gate error, got {errors}"
    )


def test_serialize_results_rejects_static_confirmed() -> None:
    """serialize_results raises ValueError for a static-only confirmed result."""
    result = p0gate.P0GateResult(
        item_id="CVE-2024-TEST",
        cve="CVE-2024-TEST",
        label="vulnerable",
        observed=p0gate.OracleResult(outcome="confirmed", ran=False),
    )
    with pytest.raises(ValueError, match="CONFIRMED"):
        p0gate.serialize_results([result], "/dev/null")


def test_dynamic_confirmed_proceeds() -> None:
    """A grounded (oracle-ran) confirmed result passes validation."""
    result = p0gate.P0GateResult(
        item_id="CVE-2024-TEST",
        cve="CVE-2024-TEST",
        label="vulnerable",
        observed=p0gate.OracleResult(
            outcome="confirmed",
            ran=True,
            expected_path_reached=True,
            crash_signal="SIGABRT",
            stderr_hint="ASan: heap-buffer-overflow on address 0x...",
        ),
        false_positive_count=0,
        binary=p0gate.BinaryDigest(sha256="a" * 64, size=4096),
        tool=p0gate.ToolDigest(version="0.0.1"),
        environment=p0gate.Environment(
            os="linux", arch="x86_64", python_version="3.11.0"
        ),
        wall_s=12.4,
    )
    errors = result.validate()
    assert not errors, f"expected clean validate, got {errors}"


def test_unknown_outcome_not_confirmed() -> None:
    """Non-confirmed outcomes (inconclusive, refuted, reach) never become confirmed."""
    for outcome in ("inconclusive", "refuted", "reach"):
        result = p0gate.P0GateResult(
            item_id="CVE-2024-TEST",
            cve="CVE-2024-TEST",
            label="vulnerable",
            observed=p0gate.OracleResult(outcome=outcome, ran=True),
        )
        errs = result.validate()
        assert not errs, f"expected clean for outcome={outcome}, got {errs}"
        assert result.observed.outcome != "confirmed", (
            f"outcome '{outcome}' was promoted to confirmed"
        )


# ---------------------------------------------------------------------------
# tests — digest verification
# ---------------------------------------------------------------------------

def test_digest_verification(tmp_path: Path) -> None:
    """verify_target_digest matches manifest SHA-256 against on-disk binary."""
    artifact_root = tmp_path / "artifacts"
    elf_name = "nested/target.x86_64"
    elf_path = artifact_root / elf_name
    elf_path.parent.mkdir(parents=True)
    good_sha = _make_elf(elf_path)
    bad_sha = "f" * 64

    item = p0gate.P0GateItem.from_dict(
        _minimal_item(target_sha256=good_sha, target_artifact=elf_name)
    )
    errs = p0gate.verify_target_digest(artifact_root, item)
    assert not errs, f"expected no errors for matching digest, got {errs}"

    # Mismatched digest.
    item.target_sha256 = bad_sha
    errs = p0gate.verify_target_digest(artifact_root, item)
    assert errs, "expected errors for mismatched digest"
    assert "SHA-256 mismatch" in errs[0]


def test_environment_libc_info_decodes_c_char_p_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux libc metadata is serialized as text, not raw ctypes bytes."""
    class FakeLibc:
        def __init__(self) -> None:
            self.gnu_get_libc_version = lambda: b"2.39"

    monkeypatch.setattr("ctypes.CDLL", lambda _path: FakeLibc())
    assert p0gate.Environment._libc_info() == "2.39"


# ---------------------------------------------------------------------------
# tests — result serialization roundtrip
# ---------------------------------------------------------------------------

def test_serialize_roundtrip(tmp_path: Path) -> None:
    """Full roundtrip: create valid results, serialize, reload, verify."""
    results = [
        p0gate.P0GateResult(
            item_id="CVE-2024-TEST",
            cve="CVE-2024-TEST", label="vulnerable",
            observed=p0gate.OracleResult(
                outcome="confirmed", ran=True,
                expected_path_reached=True, crash_signal="SIGSEGV",
            ),
            false_positive_count=0,
            binary=p0gate.BinaryDigest(sha256="a" * 64, size=4096),
            tool=p0gate.ToolDigest(version="0.0.1"),
            environment=p0gate.Environment.capture(), wall_s=1.5,
        ),
        p0gate.P0GateResult(
            item_id="CLEAN-TEST-CTRL",
            cve="CVE-2024-TEST", label="clean",
            observed=p0gate.OracleResult(
                outcome="refuted", ran=True, expected_path_reached=True,
            ),
            false_positive_count=0,
            binary=p0gate.BinaryDigest(sha256="b" * 64, size=4096),
            tool=p0gate.ToolDigest(version="0.0.1"),
            environment=p0gate.Environment.capture(), wall_s=0.0,
        ),
    ]
    out_path = tmp_path / "results.json"
    p0gate.serialize_results(results, str(out_path))
    assert out_path.exists()

    payload = json.loads(out_path.read_text())
    assert payload["schema_version"] == p0gate.P0GATE_SCHEMA_VERSION
    assert len(payload["results"]) == 2
    assert payload["results"][0]["observed"]["outcome"] == "confirmed"
    assert payload["results"][0]["observed"]["ran"] is True
    assert payload["results"][1]["observed"]["outcome"] == "refuted"


def test_preflight_report(tmp_path: Path) -> None:
    """PreflightReport formats correctly with passes and mismatches."""
    report = p0gate.PreflightReport(
        target_matches=["CVE-2024-TEST"],
        target_mismatches=[("CVE-2024-OTHER", "SHA-256 mismatch")],
        items_passing=1,
        items_failing=1,
        all_pass=False,
    )
    d = report.to_dict()
    assert d["items_passing"] == 1
    assert d["items_failing"] == 1
    assert d["all_pass"] is False
    assert "CVE-2024-TEST" in d["target_matches"]
    assert "SHA-256 mismatch" in d["target_mismatches"][0][1]


# ---------------------------------------------------------------------------
# tests — preflight CLI
# ---------------------------------------------------------------------------


def test_preflight_cli_accepts_pinned_clean_fixture(tmp_path: Path) -> None:
    """The CLI reaches read-only preflight without enabling an oracle."""
    artifact_root = tmp_path / "artifacts"
    artifact = artifact_root / "nested" / "fixture.x86_64"
    artifact.parent.mkdir(parents=True)
    digest = _make_elf(artifact)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": p0gate.P0GATE_SCHEMA_VERSION,
                "kind": "p0-gate-known-cve",
                "items": [
                    {
                        "id": "fixture-clean",
                        "cve": "",
                        "cwe": "",
                        "label": "clean",
                        "target_sha256": digest,
                        "target_artifact": "nested/fixture.x86_64",
                        "source_identity": {
                            "kind": "synthetic-fixture",
                            "ref": "inert-elf-v1",
                        },
                        "oracle": {
                            "kind": "local-dynamic",
                            "capability": "crash",
                            "trigger_input": "unused-in-preflight",
                            "asan_build": False,
                        },
                        "provenance": "Inert local fixture for P0 preflight coverage.",
                        "arch": "x86_64",
                        "os": "linux",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    runner = Path(__file__).resolve().parents[1] / "benchmarks/p0_gate/run.py"

    # The fixture executes Python plus repository-derived paths as a structured
    # argv vector; no shell parses test-controlled values.
    result = subprocess.run(  # foxguard: ignore[py/no-command-injection]
        [
            sys.executable,
            str(runner),
            "--manifest",
            str(manifest),
            "--artifact-dir",
            str(artifact_root),
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Preflight: 1 passing, 0 failing" in result.stdout
    assert "--eval not set. Oracle NOT invoked" in result.stdout


def test_default_p0_manifest_fails_closed() -> None:
    """The checked-in template cannot accidentally launch an evaluation."""
    root = Path(__file__).resolve().parents[1]
    runner = root / "benchmarks/p0_gate/run.py"
    manifest = root / "benchmarks/p0_gate/manifest.json"

    # The checked-in runner and manifest are passed as a structured argv vector.
    result = subprocess.run(  # foxguard: ignore[py/no-command-injection]
        [sys.executable, str(runner), "--manifest", str(manifest)],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 2
    assert "items list is empty" in result.stderr