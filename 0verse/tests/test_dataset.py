"""M6 #32 — labeled-PoV dataset: record emitter, schema-version stability, and the
no-real-PoV-in-repo guard.

Engine-free: builds synthetic ``RunResult``s (as ``test_api`` does) and a real
temp binary for the feature side, then checks the record projection, PoV-is-truth,
the no-raw-bytes guard, NDJSON round-trip, and that the *committed* example corpus
is synthetic-only and payload-free (the moat split, enforced)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from zeroverse import dataset
from zeroverse.agent import Verdict
from zeroverse.analyze import Finding
from zeroverse.concolic import AngrVerdict
from zeroverse.dataset import DATASET_VERSION
from zeroverse.ingest import Triage
from zeroverse.pipeline import RunResult, TriagedFinding
from zeroverse.report import PoV

_FROZEN = lambda: "2026-01-01T00:00:00+00:00"  # noqa: E731 — deterministic clock for tests

_RECORD_KEYS = {
    "record_id", "dataset_version", "created_at", "tool", "backend", "binary_name",
    "features", "label", "verdict", "oracle", "pov", "explanation", "synthetic",
}
_FEATURE_KEYS = {
    "format", "arch", "bits", "endian", "size_bytes", "stripped",
    "symbols_present", "mitigations",
}


def _confirmed_run() -> RunResult:
    t = Triage(path="/bin/vuln", fmt="ELF", arch="x86-64", bits=64, endian="little", kind="EXEC")
    f = Finding("read", "strcpy", "parse", 0x1000, 0x401180, 4)
    v = Verdict(True, "CWE-120", "high", "stack overflow", "")
    pov = PoV(crash_class="SIGSEGV-write", capability="oob-write", dedup_bucket="bkt1",
              diff_allocator="clean->crash under guard", pov_script="/out/pov_read_strcpy.py",
              crash_trace="0VERSE-CANARY", reproduced=True)
    return RunResult(triage=t, stages_run=["ingest", "decompile", "analyze", "dynamic", "poc"],
                     findings=[TriagedFinding(finding=f, verdict=v, pov=pov)])


def _pruned_run() -> RunResult:
    t = Triage(path="/bin/p", fmt="ELF", arch="x86-64", bits=64, endian="little", kind="EXEC")
    f = Finding("recv", "memcpy", "h", 0x2000, 0x2100, 3)
    v = Verdict(True, "CWE-120", "medium", "maybe", "")
    angr = AngrVerdict(outcome="unsat", note="contradiction-gated")
    return RunResult(triage=t, stages_run=["ingest", "decompile", "analyze", "concolic"],
                     findings=[TriagedFinding(finding=f, verdict=v, pov=None, angr=angr)])


def test_record_schema_is_stable() -> None:
    recs = dataset.records_from_run(_confirmed_run(), binary="/bin/vuln",
                                    backend="ghidra", now=_FROZEN)
    assert len(recs) == 1
    d = recs[0].to_dict()
    assert set(d.keys()) == _RECORD_KEYS  # locked top-level field set
    assert set(d["features"].keys()) == _FEATURE_KEYS
    assert d["dataset_version"] == DATASET_VERSION
    assert d["created_at"] == "2026-01-01T00:00:00+00:00"


def test_confirmed_record_labels_oracle_and_pov() -> None:
    d = dataset.records_from_run(_confirmed_run(), binary="/bin/vuln",
                                 backend="ghidra", now=_FROZEN)[0].to_dict()
    assert d["verdict"] == "confirmed"
    assert d["oracle"] == "differential-allocator"  # diff_allocator present -> attributed
    assert d["label"]["bug_class"] == "CWE-120"
    assert d["label"]["sink"] == "strcpy" and d["label"]["source"] == "read"
    assert d["pov"]["path"] == "/out/pov_read_strcpy.py"
    assert d["pov"]["repro_cmd"] == "python3 /out/pov_read_strcpy.py"


def test_pruned_record_verdict_and_oracle() -> None:
    d = dataset.records_from_run(_pruned_run(), binary="/bin/p",
                                 backend="ghidra", now=_FROZEN)[0].to_dict()
    assert d["verdict"] == "pruned"
    assert d["oracle"] == "angr-reachability(UNSAT)"
    assert d["pov"]["path"] == ""


def test_pov_is_truth_rejects_confirmed_without_pov() -> None:
    bad = {"dataset_version": DATASET_VERSION, "verdict": "confirmed", "pov": {"path": ""}}
    with pytest.raises(ValueError, match="PoV-is-truth"):
        dataset.validate_record(bad)


def test_replay_commitment_requires_lowercase_sha256() -> None:
    bad = {
        "dataset_version": DATASET_VERSION,
        "verdict": "confirmed",
        "pov": {"path": "/private/pov.py", "sha256": "A" * 64},
    }
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        dataset.validate_record(bad)


def test_no_raw_bytes_guard() -> None:
    bad = {"dataset_version": DATASET_VERSION, "verdict": "hypothesis",
           "pov": {"path": "", "input_bytes": "deadbeef"}}
    with pytest.raises(ValueError, match="forbidden raw-bytes key"):
        dataset.validate_record(bad)


def test_incompatible_major_version_rejected() -> None:
    with pytest.raises(ValueError, match="incompatible dataset MAJOR"):
        dataset.validate_record({"dataset_version": "2.0", "verdict": "hypothesis",
                                 "pov": {"path": ""}})


def test_previous_minor_version_remains_readable() -> None:
    dataset.validate_record(
        {
            "dataset_version": "1.0",
            "verdict": "hypothesis",
            "pov": {"path": ""},
        }
    )


def test_emit_and_roundtrip(tmp_path: Path) -> None:
    out = tmp_path / "corpus.ndjson"
    n1 = dataset.emit_run(_confirmed_run(), out, binary="/bin/vuln",
                          backend="ghidra", now=_FROZEN)
    n2 = dataset.emit_run(_pruned_run(), out, binary="/bin/p",
                          backend="rizin", now=_FROZEN)
    assert n1 == 1 and n2 == 1
    rows = list(dataset.iter_records(out))  # append-only: both runs present
    assert len(rows) == 2
    assert {r["verdict"] for r in rows} == {"confirmed", "pruned"}


def test_binary_features_from_real_file(tmp_path: Path) -> None:
    p = tmp_path / "blob.bin"
    p.write_bytes(b"not-an-elf-just-bytes")
    feats = dataset.binary_features(p)
    assert feats.size_bytes == len(b"not-an-elf-just-bytes")
    assert feats.to_dict()["format"] == "unknown"


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def test_committed_example_corpus_is_synthetic_and_payload_free() -> None:
    """THE MOAT GUARD: the only dataset files in the repo are the clearly-marked
    synthetic examples — never a real corpus, never raw exploit bytes."""
    root = _repo_root()

    def _first_obj(p: Path) -> dict | None:
        for line in p.read_text().splitlines():
            if line.strip():
                return json.loads(line)
        return None

    # Any committed NDJSON that carries DATASET records (a "dataset_version" key)
    # must live under examples/dataset/ — a real corpus never lands in the repo.
    # (Other NDJSON, e.g. the benchmark results schema, is unrelated and ignored.)
    for p in root.rglob("*.ndjson"):
        if ".venv" in p.parts:
            continue
        obj = _first_obj(p)
        if obj is not None and "dataset_version" in obj:
            assert p.parts[-2] == "dataset" and p.parts[-3] == "examples", (
                f"dataset corpus committed outside examples/dataset/: {p}"
            )
    examples = root / "examples" / "dataset"
    files = list(examples.glob("*.ndjson"))
    assert files, "expected committed synthetic example dataset"
    seen = 0
    for f in files:
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            dataset.validate_record(d)              # schema + no-bytes + PoV-is-truth
            assert d["synthetic"] is True, "committed corpus must be synthetic-only"
            seen += 1
    assert seen >= 3  # a few synthetic example records
