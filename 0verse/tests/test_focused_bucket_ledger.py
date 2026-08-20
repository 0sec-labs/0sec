from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/linux/audit-focused-bucket-ledger.py"
SPEC = importlib.util.spec_from_file_location("audit_focused_bucket_ledger", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
BUCKET = "a" * 40


def ledger(tmp_path: Path) -> Path:
    path = tmp_path / "ledger.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "buckets": {
                    BUCKET: {
                        "classification": "negative",
                        "descriptions": ["KASAN: known"],
                        "rationale": "tested negative",
                    }
                },
            }
        )
    )
    return path


def workdir(tmp_path: Path, description: str, bucket: str = BUCKET) -> Path:
    path = tmp_path / "wd" / "crashes" / bucket
    path.mkdir(parents=True)
    (path / "description").write_text(description + "\n")
    return path.parents[1]


def test_complete_ledger_passes(tmp_path: Path) -> None:
    records = MODULE.load_ledger(ledger(tmp_path))
    errors, counts = MODULE.audit(records, [workdir(tmp_path, "KASAN: known")])
    assert errors == []
    assert counts == {"negative": 1}


def test_unknown_bucket_fails(tmp_path: Path) -> None:
    records = MODULE.load_ledger(ledger(tmp_path))
    errors, _ = MODULE.audit(records, [workdir(tmp_path, "KASAN: new", "b" * 40)])
    assert any(item.startswith("UNCLASSIFIED") for item in errors)
    assert any(item.startswith("STALE_LEDGER") for item in errors)


def test_title_drift_fails(tmp_path: Path) -> None:
    records = MODULE.load_ledger(ledger(tmp_path))
    errors, _ = MODULE.audit(records, [workdir(tmp_path, "KASAN: retitled")])
    assert errors == [f"RETITLED wd/{BUCKET}: KASAN: retitled"]


def test_malformed_classification_is_rejected(tmp_path: Path) -> None:
    path = ledger(tmp_path)
    document = json.loads(path.read_text())
    document["buckets"][BUCKET]["classification"] = "maybe"
    path.write_text(json.dumps(document))

    with pytest.raises(ValueError, match="invalid classification"):
        MODULE.load_ledger(path)


def test_wrong_title_reproducer_cannot_quarantine_candidate(tmp_path: Path) -> None:
    path = ledger(tmp_path)
    document = json.loads(path.read_text())
    record = document["buckets"][BUCKET]
    record["classification"] = "quarantined"
    record["reproduction"] = {
        "result": "wrong-title",
        "expected_title": "KASAN: known",
        "observed_title": "KCSAN: unrelated transport race",
    }
    path.write_text(json.dumps(document))

    with pytest.raises(
        ValueError, match="wrong-title reproduction cannot disposition exact-title bucket"
    ):
        MODULE.load_ledger(path)


def test_wrong_title_reproducer_preserves_candidate(tmp_path: Path) -> None:
    path = ledger(tmp_path)
    document = json.loads(path.read_text())
    record = document["buckets"][BUCKET]
    record["classification"] = "candidate"
    record["reproduction"] = {
        "result": "wrong-title",
        "expected_title": "KASAN: known",
        "observed_title": "KCSAN: unrelated transport race",
    }
    path.write_text(json.dumps(document))

    records = MODULE.load_ledger(path)
    assert records[BUCKET]["classification"] == "candidate"
