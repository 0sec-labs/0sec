"""Stable contract between the analysis spine and an execution environment."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal, Protocol

EXECUTION_CONTRACT_VERSION = "1.0"

InputVector = Literal["stdin", "argv", "file", "env"]
ExecutionStatus = Literal["CLEAN", "CRASH", "TIMEOUT", "ERROR", "UNSUPPORTED"]

_VECTORS = frozenset({"stdin", "argv", "file", "env"})
_STATUSES = frozenset({"CLEAN", "CRASH", "TIMEOUT", "ERROR", "UNSUPPORTED"})


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class ExecutionCapabilities:
    """What an adapter can execute without guessing target semantics."""

    formats: frozenset[str]
    vectors: frozenset[str]
    oracles: frozenset[str]
    stateful: bool = False
    default_timeout: float = 5.0

    def __post_init__(self) -> None:
        if not self.formats:
            raise ValueError("execution adapter must declare at least one format")
        if not self.vectors or not self.vectors <= _VECTORS:
            raise ValueError("execution adapter declares an unsupported input vector")
        if not self.oracles or any(not item.strip() for item in self.oracles):
            raise ValueError("execution adapter must declare at least one oracle")
        if self.default_timeout <= 0:
            raise ValueError("execution adapter default timeout must be positive")

    def supports(self, fmt: str, vector: str, oracle: str | None = None) -> bool:
        return (
            fmt in self.formats
            and vector in self.vectors
            and (oracle is None or oracle in self.oracles)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "formats": sorted(self.formats),
            "vectors": sorted(self.vectors),
            "oracles": sorted(self.oracles),
            "stateful": self.stateful,
            "default_timeout": self.default_timeout,
        }


@dataclass(frozen=True)
class ExecutionRequest:
    """One immutable candidate execution request.

    ``payload`` is always the attacker-controlled candidate.  ``vector`` says
    how the adapter must deliver it.  Adapters must return ``UNSUPPORTED`` rather
    than silently translating an unsupported vector or oracle.
    """

    target: str
    target_format: str
    payload: bytes
    vector: InputVector
    oracle: str
    timeout: float = 5.0
    argv: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    contract_version: str = EXECUTION_CONTRACT_VERSION
    target_sha256: str = field(init=False)
    input_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if self.contract_version != EXECUTION_CONTRACT_VERSION:
            raise ValueError(f"unsupported execution contract: {self.contract_version}")
        if self.vector not in _VECTORS:
            raise ValueError(f"unsupported execution vector: {self.vector}")
        if not self.target_format or not self.oracle:
            raise ValueError("execution request requires target format and oracle")
        if self.timeout <= 0:
            raise ValueError("execution timeout must be positive")
        if any("\x00" in item for item in (*self.argv, *self.env, *self.env.values())):
            raise ValueError("execution argv/env must not contain NUL bytes")
        # Bind the evidence identity before any adapter can upload or execute the
        # target. A later on-disk mutation cannot silently redefine this request.
        object.__setattr__(self, "target_sha256", sha256_file(self.target))
        object.__setattr__(self, "input_sha256", sha256_bytes(self.payload))


@dataclass(frozen=True)
class ExecutionEvidence:
    """Normalized, machine-verifiable result returned by every adapter."""

    backend: str
    status: ExecutionStatus
    oracle: str
    target_sha256: str
    input_sha256: str
    environment: Mapping[str, str]
    returncode: int | None = None
    signal: str = ""
    crash_signature: str = ""
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    contract_version: str = EXECUTION_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.contract_version != EXECUTION_CONTRACT_VERSION:
            raise ValueError(f"unsupported execution evidence: {self.contract_version}")
        if self.status not in _STATUSES:
            raise ValueError(f"unsupported execution status: {self.status}")
        for name, digest in (
            ("target_sha256", self.target_sha256),
            ("input_sha256", self.input_sha256),
        ):
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ValueError(f"execution evidence has invalid {name}")
        if self.status == "CRASH" and not (self.signal or self.crash_signature):
            raise ValueError("crash evidence requires a signal or oracle signature")
        if self.status in {"ERROR", "UNSUPPORTED"} and not self.error:
            raise ValueError(f"{self.status.lower()} evidence requires an error")

    @property
    def confirmed_crash(self) -> bool:
        return self.status == "CRASH"

    def matches(self, request: ExecutionRequest) -> bool:
        return (
            self.contract_version == request.contract_version
            and self.target_sha256 == request.target_sha256
            and self.input_sha256 == request.input_sha256
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ExecutionBackend(Protocol):
    """Explicit execution provider consumed by ``pipeline.run``."""

    name: str
    capabilities: ExecutionCapabilities

    def run(self, request: ExecutionRequest) -> ExecutionEvidence: ...
