"""Narrow, deterministic, provider-neutral evaluation primitive for LLM-proposed
browser fuzzing seeds.

An injected ``ExecutionBackend`` is the sole executor and oracle — no model field
is ever treated as a finding.
"""

from __future__ import annotations

from dataclasses import dataclass

from .browser_campaign import BrowserCampaign
from .execution.contract import (
    ExecutionBackend,
    ExecutionEvidence,
    ExecutionRequest,
    sha256_bytes,
)

# ---------------------------------------------------------------------------
# Immutable input / output dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SeedProposal:
    """A single seed proposed by an LLM, carrying provenance only — never
    interpreted as a finding."""

    payload: bytes
    provider: str
    model: str

    @property
    def content_sha256(self) -> str:
        return sha256_bytes(self.payload)


@dataclass(frozen=True)
class SeedEvaluationRequest:
    """Evaluation parameters: ordered proposals, the campaign oracle, and the
    local target path to fuzz."""

    proposals: tuple[SeedProposal, ...]
    target: str
    campaign: BrowserCampaign
    timeout: float = 30.0

    def __post_init__(self) -> None:
        if not self.proposals:
            raise ValueError("seed evaluation requires at least one proposal")
        if not self.target:
            raise ValueError("seed evaluation requires a target path")
        if self.timeout <= 0:
            raise ValueError("seed evaluation timeout must be positive")


@dataclass(frozen=True)
class SeedProposalResult:
    """Outcome for one evaluated seed — no raw payload bytes, only hashes and
    evidence summaries."""

    content_sha256: str
    provider: str
    model: str
    evidence: ExecutionEvidence

    @property
    def crashed(self) -> bool:
        return self.evidence.status == "CRASH"


@dataclass(frozen=True)
class SeedEvaluationReport:
    """Ordered report summarising all seed evaluation results."""

    request: SeedEvaluationRequest
    results: tuple[SeedProposalResult, ...]
    backend_name: str

    @property
    def clean(self) -> tuple[SeedProposalResult, ...]:
        return tuple(r for r in self.results if r.evidence.status == "CLEAN")

    @property
    def crashed(self) -> tuple[SeedProposalResult, ...]:
        return tuple(r for r in self.results if r.evidence.status == "CRASH")

    @property
    def errors(self) -> tuple[SeedProposalResult, ...]:
        return tuple(
            r
            for r in self.results
            if r.evidence.status in ("ERROR", "TIMEOUT", "UNSUPPORTED")
        )


# ---------------------------------------------------------------------------
# Evaluation entry point
# ---------------------------------------------------------------------------


def evaluate_seeds(
    request: SeedEvaluationRequest,
    backend: ExecutionBackend,
) -> SeedEvaluationReport:
    """Evaluate every proposal in order against the supplied backend.

    Each proposal is materialised as a file-vector ``ExecutionRequest`` targeting
    the seed evaluation target with the campaign's oracle and timeout.  The
    backend identity is verified per-proposal via the response's ``backend``
    field.

    Returns
    -------
    SeedEvaluationReport
        Ordered results preserved from the input proposals.

    Raises
    ------
    ValueError
        If a backend returns evidence whose ``backend`` label does not match
        the expected ``backend.name``.
    """
    results: list[SeedProposalResult] = []

    for proposal in request.proposals:
        exec_req = ExecutionRequest(
            target=request.target,
            target_format="ELF",
            payload=proposal.payload,
            vector="file",
            oracle=request.campaign.oracle,
            timeout=request.timeout,
        )
        evidence = backend.run(exec_req)

        _verify_backend_identity(evidence, backend.name)

        results.append(
            SeedProposalResult(
                content_sha256=proposal.content_sha256,
                provider=proposal.provider,
                model=proposal.model,
                evidence=evidence,
            )
        )

    # Since the backend call is synchronous and results are accumulated in
    # iteration order, input ordering is trivially preserved.

    return SeedEvaluationReport(
        request=request,
        results=tuple(results),
        backend_name=backend.name,
    )


def _verify_backend_identity(evidence: ExecutionEvidence, expected: str) -> None:
    if evidence.backend != expected:
        raise ValueError(
            f"backend identity mismatch: evidence says {evidence.backend!r}, "
            f"expected {expected!r}"
        )