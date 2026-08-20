from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from zeroverse.browser_seed_eval import SeedEvaluationRequest, SeedProposal, evaluate_seeds
from zeroverse.execution.contract import ExecutionEvidence, ExecutionRequest


class Backend:
    name = "fake-browser"

    def __init__(self, statuses: list[str], *, reported_name: str | None = None) -> None:
        self.statuses = iter(statuses)
        self.reported_name = reported_name or self.name
        self.requests: list[ExecutionRequest] = []

    def run(self, request: ExecutionRequest) -> ExecutionEvidence:
        self.requests.append(request)
        status = next(self.statuses)
        return ExecutionEvidence(
            backend=self.reported_name,
            status=status,  # type: ignore[arg-type]
            oracle=request.oracle,
            target_sha256=request.target_sha256,
            input_sha256=request.input_sha256,
            environment={},
            crash_signature="asan" if status == "CRASH" else "",
            error="backend error" if status == "ERROR" else "",
        )


def request(tmp_path: Path, proposals: tuple[SeedProposal, ...]) -> SeedEvaluationRequest:
    target = tmp_path / "v8_json_parser_fuzzer"
    target.write_bytes(b"exact harness")
    return SeedEvaluationRequest(
        proposals=proposals,
        target=str(target),
        campaign=SimpleNamespace(oracle="asan"),
    )


def test_evaluate_seeds_preserves_provenance_order_and_statuses(tmp_path: Path) -> None:
    proposals = (
        SeedProposal(b"{}", "zai", "glm-5"),
        SeedProposal(b"[]", "openai", "gpt-5.5"),
    )
    backend = Backend(["CLEAN", "CRASH"])

    report = evaluate_seeds(request(tmp_path, proposals), backend)

    assert [item.provider for item in report.results] == ["zai", "openai"]
    assert [item.model for item in report.results] == ["glm-5", "gpt-5.5"]
    assert [item.content_sha256 for item in report.results] == [p.content_sha256 for p in proposals]
    assert len(report.clean) == 1 and len(report.crashed) == 1 and not report.errors
    assert all(item.target_format == "ELF" and item.vector == "file" for item in backend.requests)


def test_evaluate_seeds_rejects_empty_requests_and_backend_identity_mismatch(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="at least one"):
        request(tmp_path, ())

    proposals = (SeedProposal(b"{}", "zai", "glm-5"),)
    with pytest.raises(ValueError, match="identity mismatch"):
        evaluate_seeds(request(tmp_path, proposals), Backend(["CLEAN"], reported_name="spoofed"))
