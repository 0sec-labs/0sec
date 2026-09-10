"""
Pytest suite for skill_refine_loop.py.

Pure-stdlib; no numpy/sklearn/node needed for these assertions (the reward and
flagging logic is deliberately dependency-free so the reward clamp can be
audited in isolation). If pytest is unavailable, the same fixtures run via:

    python3 skill_refine_loop.py --selftest

Fixture: fixtures/skill-refine-trajectories.sample.jsonl (generated from
`selftest_rows()`), with min_samples=5 / min_delta=0.005 for a small dataset.
"""

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import skill_refine_loop as srl  # noqa: E402

FIXTURE = HERE / "fixtures" / "skill-refine-trajectories.sample.jsonl"
NOW = "1970-01-01T00:00:00+00:00"

# A known-valid skill YAML for promotion gate tests that exercise load_check.
VALID_SKILL_SOURCE = (
    HERE.parent.parent.parent.parent
    / "packages"
    / "core"
    / "src"
    / "agent"
    / "skills"
    / "vulnerabilities"
    / "prototype-pollution.yaml"
)


def _load_entries():
    findings = srl.load_trajectories(FIXTURE)
    entries = srl.analyze(findings, min_samples=5, min_delta=0.005, now=NOW)
    agg = srl.aggregate(findings)
    return findings, entries, agg


class FakeArgs:
    """Minimal argparse namespace for _gate_promotion tests."""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def _valid_skill_copy(tmp_path: Path) -> Path:
    """Copy a valid skill YAML to a temp location for load_check testing."""
    dest = tmp_path / "test-skill.yaml"
    shutil.copy2(VALID_SKILL_SOURCE, dest)
    return dest


def _make_basic_args(tmp_path: Path, **overrides):
    """Standard promotion args (+ overrides) for _gate_promotion tests."""
    defaults = dict(
        candidate_yaml=_valid_skill_copy(tmp_path),
        candidate_skill="prototype-pollution",
        operator="tester",
        promote=True,
        promote_dest=tmp_path / "promoted-skill.yaml",
        core_dist=None,
        evolution_store=tmp_path / "fake-store",
        evolution_version="00000000-0000-0000-0000-000000000001",
        evolution_artifact="agent/skills/vulnerabilities/pp.yaml",
    )
    defaults.update(overrides)
    return FakeArgs(**defaults)


def test_reward_excludes_inconclusive_and_nonoperator():
    """Inconclusive oracle rows, non-operator label sources, and unlabeled rows
    must NOT count toward a skill's eligible/TP totals."""
    _, _, agg = _load_entries()
    sqli = agg["skills"]["sqli-advanced"]
    # 7 confirmed TP + 1 operator FP == 8 eligible; the 3 noise rows are excluded.
    assert sqli["n_eligible"] == 8
    assert sqli["n_confirmed_tp"] == 7
    assert sqli["n_fp"] == 1


def test_oracle_uncovered_category_skipped():
    """A category with zero conclusive oracle verdicts is ineligible/skipped and
    its skill is never scored."""
    _, entries, agg = _load_entries()
    skips = [
        e for e in entries
        if e["decision"] == srl.DECISION_SKIPPED
        and e.get("category") == "exotic"
        and e.get("reason") == "no_oracle_coverage"
    ]
    assert len(skips) == 1
    assert "deserialization-chains" not in agg["skills"]


def test_min_samples_floor_skips():
    """A skill below the eligible-sample floor -> skipped_insufficient_data."""
    _, entries, _ = _load_entries()
    jwt = next(e for e in entries if e.get("skill_id") == "jwt-attacks")
    assert jwt["decision"] == srl.DECISION_SKIPPED
    assert jwt["reason"] == "below_min_samples"


def test_underperformer_flagged():
    """A clearly under-baseline skill is flagged as a refinement candidate; a
    healthy skill is not."""
    _, entries, _ = _load_entries()
    by_skill = {e.get("skill_id"): e for e in entries if e.get("skill_id")}
    assert by_skill["ssrf-bypass"]["decision"] == srl.DECISION_FLAGGED
    # sqli is healthy -> not present as a flagged row.
    assert "sqli-advanced" not in by_skill or (
        by_skill["sqli-advanced"]["decision"] != srl.DECISION_FLAGGED
    )


def test_dryrun_writes_no_yaml_but_appends_ledger(tmp_path):
    """Dry-run appends ledger rows and writes NO skill YAML."""
    _, entries, _ = _load_entries()
    ledger = tmp_path / "skill-refine-ledger.json"
    srl.append_ledger(ledger, entries)
    assert ledger.exists()
    assert len(json.loads(ledger.read_text())) == len(entries)
    assert not list(tmp_path.glob("**/*.yaml"))


def test_selftest_entrypoint_passes():
    """The dependency-free --selftest path returns success."""
    assert srl.run_selftest() == 0


# ── Evolution authorization gating tests (need copy of real valid skill) ──


def test_promote_without_evolution_flags_returns_actionable_error(tmp_path):
    """--promote without --evolution-store / --evolution-version /
    --evolution-artifact must exit dry-run with actionable error
    instructing the user to use the 0sec evolve workflow."""
    entries = [{"skill_id": "prototype-pollution", "decision": srl.DECISION_FLAGGED}]
    args = _make_basic_args(
        tmp_path,
        evolution_store=None,
        evolution_version=None,
        evolution_artifact=None,
    )
    result = srl._gate_promotion(args, entries, NOW)
    assert len(result) == 1
    assert result[0]["decision"] == srl.DECISION_SKIPPED
    assert result[0].get("reason") == "missing_evolution_proof"


def test_gate_promotion_requires_flagged_skill(tmp_path):
    """Even with all evolution flags, a non-flagged skill cannot be promoted."""
    entries = [{"skill_id": "some-other-skill", "decision": srl.DECISION_FLAGGED}]
    args = _make_basic_args(tmp_path, candidate_skill="healthy-skill")
    result = srl._gate_promotion(args, entries, NOW)
    assert result[0]["decision"] == srl.DECISION_SKIPPED
    assert result[0].get("reason") == "not_flagged"


def test_gate_promotion_dry_run_skips_evolution_check(tmp_path):
    """Dry-run (--promote=False) should skip evolution check entirely."""
    entries = [{"skill_id": "prototype-pollution", "decision": srl.DECISION_FLAGGED}]
    args = _make_basic_args(
        tmp_path,
        promote=False,
        evolution_store=None,
        evolution_version=None,
        evolution_artifact=None,
    )
    result = srl._gate_promotion(args, entries, NOW)
    assert result[0]["decision"] == srl.DECISION_WOULD_PROMOTE


def test_gate_promotion_requires_operator_signoff(tmp_path):
    """Even with all evolution flags, missing operator is caught before
    evolution check."""
    entries = [{"skill_id": "prototype-pollution", "decision": srl.DECISION_FLAGGED}]
    args = _make_basic_args(tmp_path, operator=None)
    result = srl._gate_promotion(args, entries, NOW)
    assert result[0].get("reason") == "missing_operator_signoff"
