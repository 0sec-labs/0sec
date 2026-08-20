"""Batch replay of a corpus through the authorized Windows crash oracle."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol, TextIO

from .adjudicate import parse_cdb_crash, parse_drmemory_crash
from .pe_symbols import resolve_crash_frame
from .windows_oracle import (
    WindowsWorker,
    extract_binary_sha256,
    extract_buildlabex,
    extract_input_sha256,
)


@dataclass(frozen=True)
class ReplayEvidence:
    input: str
    sha256: str
    size: int
    binary_name: str
    binary_sha256: str
    status: str
    oracle: str
    build_lab_ex: str
    crash_function: str = ""
    crash_cwe: str = ""
    crash_kind: str = ""
    error: str = ""
    scope_mode: str = "UNSPECIFIED"
    scope_program: str = ""
    scope_manifest_sha256: str = ""

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


@dataclass(frozen=True)
class DifferentialEvidence:
    input: str
    sha256: str
    size: int
    classification: str
    target: ReplayEvidence
    control: ReplayEvidence

    def to_dict(self) -> dict[str, object]:
        return {
            "input": self.input,
            "sha256": self.sha256,
            "size": self.size,
            "classification": self.classification,
            "target": self.target.to_dict(),
            "control": self.control.to_dict(),
        }


class EvidenceRow(Protocol):
    def to_dict(self) -> Mapping[str, object]: ...


def corpus_inputs(path: str | Path) -> list[Path]:
    """Return deterministic regular-file ordering for a file or flat corpus dir."""
    root = Path(path)
    if root.is_file():
        return [root]
    if not root.is_dir():
        raise FileNotFoundError(f"corpus does not exist: {root}")
    return sorted((item for item in root.iterdir() if item.is_file()), key=lambda p: p.name)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def replay_corpus(
    binary: str | Path,
    corpus: str | Path,
    *,
    worker: WindowsWorker | None = None,
    timeout: float = 30.0,
    oracle: str = "auto",
    scope_mode: str = "UNSPECIFIED",
    scope_program: str = "",
    scope_manifest_sha256: str = "",
) -> list[ReplayEvidence]:
    """Replay every input sequentially and return machine-verifiable evidence."""
    if oracle not in {"auto", "pageheap", "drmemory"}:
        raise ValueError(f"unknown Windows oracle: {oracle}")
    target = Path(binary)
    if not target.is_file():
        raise FileNotFoundError(f"PE does not exist: {target}")
    binary_digest = _sha256_file(target)
    selected = worker or WindowsWorker.from_env()
    if selected is None:
        raise RuntimeError("set ZEROVERSE_WINDOWS_HOST to an authorized Windows worker")

    evidence: list[ReplayEvidence] = []
    for input_path in corpus_inputs(corpus):
        data = input_path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        run = (
            selected.run_pageheap(target, data, timeout=timeout)
            if oracle == "pageheap"
            else selected.run_drmemory(target, data, timeout=timeout)
        )
        fallback = (
            oracle == "auto"
            and not run.crashed
            and "0VERSE-EXIT:-1" in run.stderr
            and "Windows worker error:" not in run.stderr
            and bool(extract_buildlabex(run.stderr))
        )
        if fallback:
            run = selected.run_pageheap(target, data, timeout=timeout)

        build = extract_buildlabex(run.stderr)
        if not build:
            evidence.append(
                ReplayEvidence(
                    input=str(input_path),
                    sha256=digest,
                    size=len(data),
                    binary_name=target.name,
                    binary_sha256=binary_digest,
                    status="ERROR",
                    oracle=run.sanitizer or oracle,
                    build_lab_ex="",
                    error=(
                        "Windows worker returned no unambiguous BuildLabEx; "
                        f"run rejected: {run.stderr.strip()[-400:]}"
                    ),
                    scope_mode=scope_mode,
                    scope_program=scope_program,
                    scope_manifest_sha256=scope_manifest_sha256,
                )
            )
            continue
        remote_binary_digest = extract_binary_sha256(run.stderr)
        if remote_binary_digest != binary_digest:
            evidence.append(
                ReplayEvidence(
                    input=str(input_path),
                    sha256=digest,
                    size=len(data),
                    binary_name=target.name,
                    binary_sha256=binary_digest,
                    status="ERROR",
                    oracle=run.sanitizer or oracle,
                    build_lab_ex=build,
                    error=(
                        "uploaded Windows binary SHA-256 is missing, ambiguous, or mismatched: "
                        f"local={binary_digest}, remote={remote_binary_digest or 'missing'}"
                    ),
                    scope_mode=scope_mode,
                    scope_program=scope_program,
                    scope_manifest_sha256=scope_manifest_sha256,
                )
            )
            continue
        remote_input_digest = extract_input_sha256(run.stderr)
        if remote_input_digest != digest:
            evidence.append(
                ReplayEvidence(
                    input=str(input_path),
                    sha256=digest,
                    size=len(data),
                    binary_name=target.name,
                    binary_sha256=binary_digest,
                    status="ERROR",
                    oracle=run.sanitizer or oracle,
                    build_lab_ex=build,
                    error=(
                        "uploaded Windows input SHA-256 is missing, ambiguous, or mismatched: "
                        f"local={digest}, remote={remote_input_digest or 'missing'}"
                    ),
                    scope_mode=scope_mode,
                    scope_program=scope_program,
                    scope_manifest_sha256=scope_manifest_sha256,
                )
            )
            continue
        if run.crashed:
            crash = (
                parse_cdb_crash(run.stderr)
                if run.sanitizer == "pageheap-cdb"
                else parse_drmemory_crash(run.stderr)
            )
            resolved = resolve_crash_frame(target, [crash.crash_function])
            if resolved:
                crash.crash_function = resolved
            evidence.append(
                ReplayEvidence(
                    input=str(input_path),
                    sha256=digest,
                    size=len(data),
                    binary_name=target.name,
                    binary_sha256=binary_digest,
                    status="CRASH",
                    oracle=run.sanitizer,
                    build_lab_ex=build,
                    crash_function=crash.crash_function,
                    crash_cwe=crash.cwe,
                    crash_kind=crash.kind,
                    scope_mode=scope_mode,
                    scope_program=scope_program,
                    scope_manifest_sha256=scope_manifest_sha256,
                )
            )
            continue

        error = ""
        status = "CLEAN"
        if "worker timeout" in run.stderr.lower() or "worker error" in run.stderr.lower():
            status = "ERROR"
            error = run.stderr.strip()[-500:]
        evidence.append(
            ReplayEvidence(
                input=str(input_path),
                sha256=digest,
                size=len(data),
                binary_name=target.name,
                binary_sha256=binary_digest,
                status=status,
                oracle=run.sanitizer or oracle,
                build_lab_ex=build,
                error=error,
                scope_mode=scope_mode,
                scope_program=scope_program,
                scope_manifest_sha256=scope_manifest_sha256,
            )
        )
    return evidence


def replay_differential(
    binary: str | Path,
    control_binary: str | Path,
    corpus: str | Path,
    *,
    worker: WindowsWorker | None = None,
    timeout: float = 30.0,
    oracle: str = "auto",
    scope_mode: str = "UNSPECIFIED",
    scope_program: str = "",
    scope_manifest_sha256: str = "",
) -> list[DifferentialEvidence]:
    """Replay identical inputs on target/control PEs and classify the difference."""
    selected = worker or WindowsWorker.from_env()
    if selected is None:
        raise RuntimeError("set ZEROVERSE_WINDOWS_HOST to an authorized Windows worker")
    target_rows = replay_corpus(
        binary,
        corpus,
        worker=selected,
        timeout=timeout,
        oracle=oracle,
        scope_mode=scope_mode,
        scope_program=scope_program,
        scope_manifest_sha256=scope_manifest_sha256,
    )
    control_rows = replay_corpus(
        control_binary,
        corpus,
        worker=selected,
        timeout=timeout,
        oracle=oracle,
        scope_mode=scope_mode,
        scope_program=scope_program,
        scope_manifest_sha256=scope_manifest_sha256,
    )
    rows: list[DifferentialEvidence] = []
    for target, control in zip(target_rows, control_rows, strict=True):
        if target.binary_sha256 == control.binary_sha256 or "ERROR" in {
            target.status,
            control.status,
        }:
            classification = "ERROR"
        elif target.status == "CRASH" and control.status == "CLEAN":
            classification = "TARGET_ONLY_CRASH"
        elif target.status == "CLEAN" and control.status == "CRASH":
            classification = "CONTROL_ONLY_CRASH"
        elif target.status == "CRASH" and control.status == "CRASH":
            classification = "BOTH_CRASH"
        else:
            classification = "BOTH_CLEAN"
        rows.append(
            DifferentialEvidence(
                input=target.input,
                sha256=target.sha256,
                size=target.size,
                classification=classification,
                target=target,
                control=control,
            )
        )
    return rows


def write_evidence(rows: Sequence[EvidenceRow], output: TextIO, fmt: str = "ndjson") -> None:
    if fmt == "json":
        json.dump([row.to_dict() for row in rows], output, indent=2, sort_keys=True)
        output.write("\n")
        return
    if fmt != "ndjson":
        raise ValueError(f"unknown evidence format: {fmt}")
    for row in rows:
        output.write(json.dumps(row.to_dict(), sort_keys=True) + "\n")
