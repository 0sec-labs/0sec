from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/linux/audit-new-crash-buckets.py"
SPEC = importlib.util.spec_from_file_location("audit_new_crash_buckets", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def make_bucket(tmp_path: Path, description: str = "KASAN: test") -> Path:
    bucket = tmp_path / "wd-test" / "crashes" / "abc123"
    bucket.mkdir(parents=True)
    (bucket / "description").write_text(description + "\n")
    (bucket / "report0").write_text("report evidence\n")
    return bucket


def write_report(bucket: Path, title: str, function: str) -> None:
    (bucket / "report0").write_text(
        f"{title}\nCall Trace:\n <TASK>\n {function}+0x12/0x40 fs/test.c:1\n"
        " do_syscall_64+0x10/0x20 arch/x86/entry/common.c:1\n </TASK>\n"
    )


def test_snapshot_is_atomic_hashed_and_idempotent(tmp_path: Path) -> None:
    bucket = make_bucket(tmp_path)
    evidence = tmp_path / "evidence"

    first = MODULE.snapshot_event(evidence, "NEW", bucket, "KASAN: test")
    second = MODULE.snapshot_event(evidence, "NEW", bucket, "KASAN: test")

    assert first == second
    assert len(list(evidence.iterdir())) == 1
    record = json.loads((first / "EVENT.json").read_text())
    assert record["event"] == "NEW"
    assert record["description"] == "KASAN: test"
    assert record["fingerprint"].startswith("text-v1:")
    sums = (first / "SHA256SUMS").read_text()
    assert "  EVENT.json" in sums
    assert "  description" in sums
    assert "  report0" in sums


def test_retitle_gets_distinct_snapshot(tmp_path: Path) -> None:
    bucket = make_bucket(tmp_path)
    evidence = tmp_path / "evidence"

    first = MODULE.snapshot_event(evidence, "NEW", bucket, "old")
    second = MODULE.snapshot_event(evidence, "RETITLED", bucket, "new")

    assert first != second
    assert len(list(evidence.iterdir())) == 2


def test_title_drift_is_annotated_by_stack_fingerprint(tmp_path: Path) -> None:
    first_bucket = make_bucket(tmp_path / "first", "UBSAN: get_cpu_entry_area")
    second_bucket = make_bucket(tmp_path / "second", "UBSAN: corrupted")
    write_report(first_bucket, "UBSAN: array-index-out-of-bounds", "get_cpu_entry_area")
    write_report(second_bucket, "UBSAN: array-index-out-of-bounds", "get_cpu_entry_area")
    evidence = tmp_path / "evidence"

    first = MODULE.snapshot_event(evidence, "NEW", first_bucket, "first title")
    second = MODULE.snapshot_event(evidence, "NEW", second_bucket, "corrupted title")

    first_event = json.loads((first / "EVENT.json").read_text())
    second_event = json.loads((second / "EVENT.json").read_text())
    assert first_event["fingerprint"].startswith("stack-v1:")
    assert second_event["fingerprint"] == first_event["fingerprint"]
    assert second_event["duplicate_of"] == first.name


def test_different_primary_stacks_are_not_duplicates(tmp_path: Path) -> None:
    first_bucket = make_bucket(tmp_path / "first")
    second_bucket = make_bucket(tmp_path / "second")
    write_report(first_bucket, "KASAN: use-after-free", "first_root_cause")
    write_report(second_bucket, "KASAN: use-after-free", "second_root_cause")
    evidence = tmp_path / "evidence"

    MODULE.snapshot_event(evidence, "NEW", first_bucket, "same title")
    second = MODULE.snapshot_event(evidence, "NEW", second_bucket, "same title")

    second_event = json.loads((second / "EVENT.json").read_text())
    assert "duplicate_of" not in second_event


def test_snapshot_rejects_symlink_and_leaves_no_partial(tmp_path: Path) -> None:
    bucket = make_bucket(tmp_path)
    (bucket / "unsafe").symlink_to("/etc/passwd")
    evidence = tmp_path / "evidence"

    with pytest.raises(ValueError, match="symlink"):
        MODULE.snapshot_event(evidence, "NEW", bucket, "KASAN: test")

    assert list(evidence.iterdir()) == []


def test_verify_snapshot_detects_changed_artifact(tmp_path: Path) -> None:
    bucket = make_bucket(tmp_path)
    snapshot = MODULE.snapshot_event(tmp_path / "evidence", "NEW", bucket, "KASAN: test")
    (snapshot / "report0").write_text("tampered\n")

    with pytest.raises(ValueError, match="hash mismatch"):
        MODULE.verify_snapshot(snapshot)


def test_verify_snapshot_detects_unlisted_artifact(tmp_path: Path) -> None:
    bucket = make_bucket(tmp_path)
    snapshot = MODULE.snapshot_event(tmp_path / "evidence", "NEW", bucket, "KASAN: test")
    (snapshot / "extra").write_text("not manifested\n")

    with pytest.raises(ValueError, match="manifest/file set mismatch"):
        MODULE.verify_snapshot(snapshot)


def test_verify_evidence_dir_rejects_non_directory_entry(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "unexpected").write_text("bad\n")

    with pytest.raises(ValueError, match="unexpected evidence-inbox entry"):
        MODULE.verify_evidence_dir(evidence)


def test_verify_snapshot_rejects_malformed_event_even_with_valid_hash(tmp_path: Path) -> None:
    bucket = make_bucket(tmp_path)
    snapshot = MODULE.snapshot_event(tmp_path / "evidence", "NEW", bucket, "KASAN: test")
    (snapshot / "EVENT.json").write_text("[]\n")
    lines = []
    for artifact in sorted(snapshot.iterdir()):
        if artifact.is_file() and artifact.name != "SHA256SUMS":
            lines.append(f"{MODULE.file_digest(artifact)}  {artifact.name}")
    (snapshot / "SHA256SUMS").write_text("\n".join(lines) + "\n")

    with pytest.raises(ValueError, match=r"malformed EVENT\.json"):
        MODULE.verify_snapshot(snapshot)
