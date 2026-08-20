"""Fail-closed disclosure-draft generation from deterministic evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReportGate:
    name: str
    passed: bool
    detail: str


def load_ndjson(path: str | Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"evidence line {number} is not an object")
        rows.append(value)
    return rows


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _is_sha256(value: object) -> bool:
    text = _text(value)
    return len(text) == 64 and all(char in "0123456789abcdefABCDEF" for char in text)


def _object_dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _consistent_target_only(row: dict[str, object]) -> bool:
    target = row.get("target")
    control = row.get("control")
    if not isinstance(target, dict) or not isinstance(control, dict):
        return False
    digest = _text(row.get("sha256"))
    target_digest = _text(target.get("sha256"))
    control_digest = _text(control.get("sha256"))
    target_build = _text(target.get("build_lab_ex"))
    control_build = _text(control.get("build_lab_ex"))
    target_binary = _text(target.get("binary_sha256"))
    control_binary = _text(control.get("binary_sha256"))
    return (
        row.get("classification") == "TARGET_ONLY_CRASH"
        and target.get("status") == "CRASH"
        and control.get("status") == "CLEAN"
        and _is_sha256(digest)
        and digest == target_digest == control_digest
        and bool(target_build)
        and target_build == control_build
        and _is_sha256(target_binary)
        and _is_sha256(control_binary)
        and target_binary != control_binary
        and _text(target.get("scope_mode")) == _text(control.get("scope_mode"))
        and _text(target.get("scope_program")) == _text(control.get("scope_program"))
        and _text(target.get("scope_manifest_sha256"))
        == _text(control.get("scope_manifest_sha256"))
    )


def windows_report(rows: list[dict[str, object]], *, title: str) -> str:
    labelled = [row for row in rows if row.get("classification") == "TARGET_ONLY_CRASH"]
    candidates = [row for row in labelled if _consistent_target_only(row)]
    target = _object_dict(candidates[0].get("target")) if candidates else {}
    build = _text(target.get("build_lab_ex"))
    crash_function = _text(target.get("crash_function"))
    crash_cwe = _text(target.get("crash_cwe"))
    crash_kind = _text(target.get("crash_kind"))
    scope_mode = _text(target.get("scope_mode"))
    scope_program = _text(target.get("scope_program"))
    scope_digest = _text(target.get("scope_manifest_sha256"))
    builds = {
        _text(_object_dict(row.get("target")).get("build_lab_ex"))
        for row in candidates
    }
    scopes = {
        (
            _text(_object_dict(row.get("target")).get("scope_mode")),
            _text(_object_dict(row.get("target")).get("scope_program")),
            _text(_object_dict(row.get("target")).get("scope_manifest_sha256")),
        )
        for row in candidates
    }
    binaries = {
        (
            _text(_object_dict(row.get("target")).get("binary_sha256")),
            _text(_object_dict(row.get("control")).get("binary_sha256")),
        )
        for row in candidates
    }
    uniform = len(builds) == 1 and len(scopes) == 1 and len(binaries) == 1
    scoped = uniform and (
        scope_mode == "BOUNTY_SCOPE"
        and bool(scope_program)
        and _is_sha256(scope_digest)
    )

    gates = [
        ReportGate(
            "Differential reproduction",
            bool(candidates),
            f"{len(candidates)} target-only crashing input(s)",
        ),
        ReportGate(
            "Evidence row consistency",
            bool(labelled) and len(candidates) == len(labelled) and uniform,
            f"{len(candidates)}/{len(labelled)} consistent; "
            f"builds={len(builds)}, scopes={len(scopes)}, binaries={len(binaries)}",
        ),
        ReportGate(
            "Exact build captured",
            bool(build) and len(builds) == 1,
            build or "missing BuildLabEx",
        ),
        ReportGate(
            "Bounty scope provenance",
            scoped,
            f"{scope_program} / {scope_digest}" if scoped else scope_mode or "missing scope mode",
        ),
        ReportGate(
            "Canary channel identity", "canary" in build.lower(), build or "missing BuildLabEx"
        ),
        ReportGate(
            "Crash attribution",
            bool(crash_function and crash_cwe),
            f"{crash_function or '?'} / {crash_cwe or '?'}",
        ),
        ReportGate(
            "Latest-build verification",
            False,
            "operator must verify against Microsoft's current Flight Hub",
        ),
        ReportGate(
            "Serviced-feature reachability",
            False,
            "operator must reproduce through the shipped Windows feature",
        ),
        ReportGate(
            "Novelty / duplicate search",
            False,
            "operator must record advisory, patch, and prior-report search",
        ),
        ReportGate(
            "Security impact", False, "operator must demonstrate Critical/Important security impact"
        ),
        ReportGate(
            "Submission approval",
            False,
            "operator approval required; 0verse never submits automatically",
        ),
    ]
    ready = all(gate.passed for gate in gates)
    target_binary_sha = _text(target.get("binary_sha256"))
    control = _object_dict(candidates[0].get("control")) if candidates else {}
    control_binary_sha = _text(control.get("binary_sha256"))

    lines = [
        f"# {title}",
        "",
        "## Submission state",
        "",
        f"**Submission ready: {'YES' if ready else 'NO'}**",
        "",
        "This is an evidence-backed draft, not a vulnerability claim or automatic submission.",
        "",
        "## Gates",
        "",
    ]
    for gate in gates:
        lines.append(f"- [{'x' if gate.passed else ' '}] {gate.name}: {gate.detail}")
    lines.extend(
        [
            "",
            "## Deterministic evidence",
            "",
            f"- BuildLabEx: `{build or 'missing'}`",
            f"- Target binary SHA-256: `{target_binary_sha or 'missing'}`",
            f"- Control binary SHA-256: `{control_binary_sha or 'missing'}`",
            f"- Crash function: `{crash_function or 'unresolved'}`",
            f"- Crash class: `{crash_kind or 'unknown'}`",
            f"- CWE: `{crash_cwe or 'unknown'}`",
            f"- Scope mode: `{scope_mode or 'missing'}`",
            f"- Scope program: `{scope_program or 'missing'}`",
            f"- Scope manifest SHA-256: `{scope_digest or 'missing'}`",
            f"- Target-only inputs: {len(candidates)}",
            "",
            "| SHA-256 | Size | Target | Control |",
            "|---|---:|---|---|",
        ]
    )
    for row in candidates:
        target_row = _object_dict(row.get("target"))
        control_row = _object_dict(row.get("control"))
        lines.append(
            f"| `{_text(row.get('sha256'))}` | {row.get('size', '?')} | "
            f"{_text(target_row.get('status'))} | {_text(control_row.get('status'))} |"
        )
    lines.extend(
        [
            "",
            "## Required report content",
            "",
            "- Attack vector and realistic prerequisite:",
            "- Shipped component and serviced feature:",
            "- Reproduction steps without debugger intervention:",
            "- Security-boundary impact:",
            "- Latest Canary verification timestamp and source:",
            "- Novelty/deduplication searches:",
            "- PoC and crash-dump attachment hashes:",
            "- Suggested remediation:",
            "",
            "## Disclosure",
            "",
            "Submit only through the MSRC Researcher Portal after operator approval "
            "and follow CVD.",
        ]
    )
    return "\n".join(lines) + "\n"
