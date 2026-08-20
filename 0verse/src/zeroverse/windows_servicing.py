"""Verify signed Windows servicing receipts against a frozen pair plan."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .ssh_authority_commitment import ssh_authority_key_commitment
from .ssh_authorization import verify_ssh_signature
from .windows_lpe_opaque_content import WindowsLpeOpaqueContent
from .windows_pair_plan import VerifiedWindowsPairPlan, verify_windows_pair_plan

SERVICING_RECEIPT_SCHEMA = "0verse.windows-servicing-receipt/v1"
SERVICING_RECEIPT_PRODUCER = "zeroverse.windows-servicing-worker/v1"
SERVICING_RECEIPT_SIGNATURE_NAMESPACE = "0verse-windows-servicing-receipt-v1"
SERVICING_RECEIPT_CLAIMS = [
    "pair-plan-role-and-input-identities-bound",
    "plan-recipe-and-tool-identities-bound",
    "worker-signed-execution-observation-bound",
    "retained-execution-transcripts-bound",
    "retained-output-observation-bound",
]
SERVICING_RECEIPT_PROOF_LIMIT = (
    "Worker-signed, internally consistent observation bound to the supplied pair-plan "
    "bytes; the verifier does not prove the plan predated execution, that declared "
    "commands consumed the bound recipe/tools/packages, reboot causality, or worker "
    "runtime integrity. Microsoft authenticity, CVE/KB/build truth, vulnerable/fixed "
    "status, reachability, impact, bounty eligibility, authorization, and redistribution "
    "rights are unproven."
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
_MAX_TRANSCRIPT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class WindowsServicingReceipt:
    receipt_path: Path
    receipt_sha256: str
    receipt_signature_path: Path
    receipt_signature_sha256: str
    receipt_signer_identity: str
    receipt_signer_authority_commitment_sha256: str
    pair_plan_path: Path
    pair_plan_sha256: str
    role: str
    artifact_path: Path
    artifact_sha256: str
    build_lab_ex: str
    servicing_package_sha256s: tuple[str, ...]
    acquisition_receipt_sha256s: tuple[str, ...]
    recipe_sha256: str
    tools: tuple[tuple[str, str], ...]
    reboot_observed: bool
    worker_machine_id: str
    started_at_utc: str
    completed_at_utc: str

    def to_dict(self) -> dict[str, object]:
        return {
            "receipt_path": str(self.receipt_path),
            "receipt_sha256": self.receipt_sha256,
            "receipt_signature_path": str(self.receipt_signature_path),
            "receipt_signature_sha256": self.receipt_signature_sha256,
            "receipt_signer_identity": self.receipt_signer_identity,
            "receipt_signer_authority_commitment_sha256": (
                self.receipt_signer_authority_commitment_sha256
            ),
            "pair_plan_path": str(self.pair_plan_path),
            "pair_plan_sha256": self.pair_plan_sha256,
            "role": self.role,
            "artifact_path": str(self.artifact_path),
            "artifact_sha256": self.artifact_sha256,
            "build_lab_ex": self.build_lab_ex,
            "servicing_package_sha256s": list(self.servicing_package_sha256s),
            "acquisition_receipt_sha256s": list(
                self.acquisition_receipt_sha256s
            ),
            "recipe_sha256": self.recipe_sha256,
            "tools": [
                {"name": name, "sha256": digest} for name, digest in self.tools
            ],
            "reboot_observed": self.reboot_observed,
            "worker_machine_id": self.worker_machine_id,
            "started_at_utc": self.started_at_utc,
            "completed_at_utc": self.completed_at_utc,
        }


def verify_windows_servicing_receipt(
    pair_plan_path: str | Path,
    artifact_path: str | Path,
    receipt_path: str | Path,
    allowed_signers_path: str | Path,
) -> WindowsServicingReceipt:
    """Re-derive every claim in one worker-signed servicing receipt."""
    plan = verify_windows_pair_plan(pair_plan_path)
    return verify_windows_servicing_receipt_against_plan(
        plan, artifact_path, receipt_path, allowed_signers_path
    )


def verify_windows_servicing_receipt_against_plan(
    plan: VerifiedWindowsPairPlan,
    artifact_path: str | Path,
    receipt_path: str | Path,
    allowed_signers_path: str | Path,
    *,
    opaque_content: WindowsLpeOpaqueContent | None = None,
    opaque_root: str | Path | None = None,
) -> WindowsServicingReceipt:
    """Verify one receipt against an in-memory plan without reopening that plan."""
    artifact = _regular_file(Path(artifact_path), "artifact")
    receipt = _regular_file(Path(receipt_path), "receipt")
    allowed_signers = _regular_file(Path(allowed_signers_path), "allowed signers")
    receipt_bytes = _read_once(receipt, "receipt", _MAX_DOCUMENT_BYTES)
    raw = json.loads(receipt_bytes, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("servicing receipt must be a JSON object")
    _exact(
        raw,
        {
            "schema_version",
            "producer",
            "receipt_signer_identity",
            "pair_plan",
            "role",
            "inputs",
            "reproduction",
            "execution",
            "observation",
            "verified_claims",
            "proof_limit",
        },
        "receipt",
    )
    if (
        raw["schema_version"] != SERVICING_RECEIPT_SCHEMA
        or raw["producer"] != SERVICING_RECEIPT_PRODUCER
    ):
        raise ValueError("servicing receipt schema/producer mismatch")

    signer_identity = _nonempty(raw["receipt_signer_identity"], "receipt signer identity")
    signature = _regular_file(Path(f"{receipt}.sig"), "receipt signature")
    signature_bytes = _read_once(signature, "receipt signature", 64 * 1024)
    try:
        signature_text = signature_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("servicing receipt signature must be UTF-8") from exc
    allowed_signers_bytes = _read_once(
        allowed_signers, "allowed signers", 1024 * 1024
    )
    with tempfile.TemporaryDirectory(prefix="0verse-servicing-signers-") as temporary:
        policy_snapshot = Path(temporary) / "allowed_signers"
        policy_snapshot.write_bytes(allowed_signers_bytes)
        signer_authority_commitment = ssh_authority_key_commitment(policy_snapshot)
        verify_ssh_signature(
            receipt_bytes,
            signature_text,
            identity=signer_identity,
            namespace=SERVICING_RECEIPT_SIGNATURE_NAMESPACE,
            allowed_signers=policy_snapshot,
            label="Windows servicing receipt",
            require_trusted_policy=False,
        )

    pair_ref = _object(raw["pair_plan"], "pair_plan")
    _exact(pair_ref, {"sha256"}, "pair_plan")
    if _sha256(pair_ref["sha256"], "pair_plan.sha256") != plan.plan_sha256:
        raise ValueError("servicing receipt pair-plan SHA-256 mismatch")

    role = str(raw["role"])
    if role not in {"candidate", "control"}:
        raise ValueError("servicing receipt role must be candidate or control")
    expected = _side(plan, role)
    _verify_inputs(raw["inputs"], expected)
    tools = _verify_reproduction(raw["reproduction"], plan)
    reboot_observed, worker_machine_id, started, completed = _verify_execution(
        raw["execution"],
        receipt.parent.resolve(),
        expected.servicing_package_sha256s,
        tools,
        opaque_content=opaque_content,
        opaque_root=Path(opaque_root).resolve() if opaque_root is not None else None,
    )
    artifact_digest, artifact_size = _hash_file(artifact)
    _verify_observation(
        raw["observation"], artifact, artifact_digest, artifact_size, expected
    )
    if raw["verified_claims"] != SERVICING_RECEIPT_CLAIMS:
        raise ValueError("servicing receipt verified_claims mismatch")
    if raw["proof_limit"] != SERVICING_RECEIPT_PROOF_LIMIT:
        raise ValueError("servicing receipt proof_limit mismatch")

    return WindowsServicingReceipt(
        receipt.resolve(),
        hashlib.sha256(receipt_bytes).hexdigest(),
        signature.resolve(),
        hashlib.sha256(signature_bytes).hexdigest(),
        signer_identity,
        signer_authority_commitment,
        plan.plan_path,
        plan.plan_sha256,
        role,
        artifact.resolve(),
        artifact_digest,
        expected.build_lab_ex,
        expected.servicing_package_sha256s,
        expected.acquisition_receipt_sha256s,
        plan.recipe_sha256,
        tools,
        reboot_observed,
        worker_machine_id,
        started,
        completed,
    )


@dataclass(frozen=True)
class _ExpectedSide:
    artifact_sha256: str
    build_lab_ex: str
    acquisition_artifact_sha256s: tuple[str, ...]
    acquisition_receipt_sha256s: tuple[str, ...]

    @property
    def servicing_package_sha256s(self) -> tuple[str, ...]:
        return self.acquisition_artifact_sha256s[1:]


def _side(plan: VerifiedWindowsPairPlan, role: str) -> _ExpectedSide:
    if role == "candidate":
        return _ExpectedSide(
            plan.candidate_sha256,
            plan.candidate_build_lab_ex,
            plan.candidate_acquisition_artifact_sha256s,
            plan.candidate_acquisition_receipt_sha256s,
        )
    return _ExpectedSide(
        plan.control_sha256,
        plan.control_build_lab_ex,
        plan.control_acquisition_artifact_sha256s,
        plan.control_acquisition_receipt_sha256s,
    )


def _verify_inputs(raw: object, expected: _ExpectedSide) -> None:
    inputs = _object(raw, "inputs")
    _exact(
        inputs,
        {"acquisition_artifact_sha256s", "acquisition_receipt_sha256s"},
        "inputs",
    )
    artifacts = _hash_array(
        inputs["acquisition_artifact_sha256s"], "inputs.acquisition_artifact_sha256s"
    )
    receipts = _hash_array(
        inputs["acquisition_receipt_sha256s"], "inputs.acquisition_receipt_sha256s"
    )
    if artifacts != expected.acquisition_artifact_sha256s:
        raise ValueError("servicing receipt ordered acquisition artifacts mismatch")
    if receipts != expected.acquisition_receipt_sha256s:
        raise ValueError("servicing receipt ordered acquisition receipts mismatch")


def _verify_reproduction(
    raw: object, plan: VerifiedWindowsPairPlan
) -> tuple[tuple[str, str], ...]:
    reproduction = _object(raw, "reproduction")
    _exact(reproduction, {"recipe_sha256", "tools"}, "reproduction")
    if _sha256(reproduction["recipe_sha256"], "reproduction.recipe_sha256") != plan.recipe_sha256:
        raise ValueError("servicing receipt recipe SHA-256 mismatch")
    raw_tools = reproduction["tools"]
    if not isinstance(raw_tools, list) or not raw_tools:
        raise ValueError("servicing receipt reproduction.tools must be a nonempty array")
    tools: list[tuple[str, str]] = []
    for index, value in enumerate(raw_tools):
        tool = _object(value, f"reproduction.tools[{index}]")
        _exact(tool, {"name", "sha256"}, f"reproduction.tools[{index}]")
        tools.append(
            (
                _nonempty(tool["name"], f"reproduction.tools[{index}].name"),
                _sha256(tool["sha256"], f"reproduction.tools[{index}].sha256"),
            )
        )
    observed = tuple(tools)
    if observed != plan.tools:
        raise ValueError("servicing receipt ordered tools mismatch")
    return observed


def _verify_execution(
    raw: object,
    base: Path,
    servicing_packages: tuple[str, ...],
    tools: tuple[tuple[str, str], ...],
    *,
    opaque_content: WindowsLpeOpaqueContent | None,
    opaque_root: Path | None,
) -> tuple[bool, str, str, str]:
    execution = _object(raw, "execution")
    _exact(
        execution,
        {
            "pre_machine_id",
            "post_machine_id",
            "pre_boot_id",
            "post_boot_id",
            "started_at_utc",
            "completed_at_utc",
            "steps",
        },
        "execution",
    )
    pre_machine = _identifier(execution["pre_machine_id"], "execution.pre_machine_id")
    post_machine = _identifier(execution["post_machine_id"], "execution.post_machine_id")
    if pre_machine != post_machine:
        raise ValueError("servicing receipt machine identity changed")
    pre_boot = _identifier(execution["pre_boot_id"], "execution.pre_boot_id")
    post_boot = _identifier(execution["post_boot_id"], "execution.post_boot_id")
    started, started_value = _utc(execution["started_at_utc"], "execution.started_at_utc")
    completed, completed_value = _utc(
        execution["completed_at_utc"], "execution.completed_at_utc"
    )
    if completed_value < started_value:
        raise ValueError("servicing receipt completion predates start")
    steps_raw = execution["steps"]
    if not isinstance(steps_raw, list) or len(steps_raw) != len(servicing_packages):
        raise ValueError("servicing receipt execution steps must match servicing packages")
    observed_packages: list[str] = []
    restart_required = False
    for index, value in enumerate(steps_raw):
        step = _object(value, f"execution.steps[{index}]")
        _exact(
            step,
            {
                "argv",
                "tool_name",
                "package_sha256",
                "exit_code",
                "restart_required",
                "stdout",
                "stderr",
            },
            f"execution.steps[{index}]",
        )
        argv = step["argv"]
        if (
            not isinstance(argv, list)
            or not argv
            or not all(
                isinstance(argument, str)
                and argument
                and "\x00" not in argument
                and "\r" not in argument
                and "\n" not in argument
                for argument in argv
            )
        ):
            raise ValueError(f"servicing receipt execution.steps[{index}].argv is invalid")
        tool_name = _nonempty(
            step["tool_name"], f"execution.steps[{index}].tool_name"
        )
        if tool_name not in {name for name, _ in tools} or argv[0] != tool_name:
            raise ValueError(
                f"servicing receipt execution.steps[{index}] tool/argv mismatch"
            )
        observed_packages.append(
            _sha256(step["package_sha256"], f"execution.steps[{index}].package_sha256")
        )
        exit_code = step["exit_code"]
        restart = step["restart_required"]
        if isinstance(exit_code, bool) or exit_code not in {0, 3010}:
            raise ValueError(f"servicing receipt execution.steps[{index}].exit_code is invalid")
        if not isinstance(restart, bool) or restart != (exit_code == 3010):
            raise ValueError(
                f"servicing receipt execution.steps[{index}] restart/exit mismatch"
            )
        restart_required = restart_required or restart
        _file_reference(
            step["stdout"],
            base,
            f"execution.steps[{index}].stdout",
            opaque_content=opaque_content,
            opaque_root=opaque_root,
        )
        _file_reference(
            step["stderr"],
            base,
            f"execution.steps[{index}].stderr",
            opaque_content=opaque_content,
            opaque_root=opaque_root,
        )
    if tuple(observed_packages) != servicing_packages:
        raise ValueError("servicing receipt execution package order mismatch")
    restart_indices = [
        index
        for index, value in enumerate(steps_raw)
        if isinstance(value, dict) and value.get("restart_required") is True
    ]
    if restart_indices and restart_indices != [len(steps_raw) - 1]:
        raise ValueError("servicing receipt restart-required step must be final")
    if restart_required != (pre_boot != post_boot):
        raise ValueError("servicing receipt reboot boundary mismatch")
    return restart_required, pre_machine, started, completed


def _verify_observation(
    raw: object,
    artifact: Path,
    artifact_digest: str,
    artifact_size: int,
    expected: _ExpectedSide,
) -> None:
    observation = _object(raw, "observation")
    _exact(observation, {"build_lab_ex", "retained_output"}, "observation")
    build = _nonempty(observation["build_lab_ex"], "observation.build_lab_ex")
    if build != expected.build_lab_ex:
        raise ValueError("servicing receipt BuildLabEx mismatch")
    output = _object(observation["retained_output"], "observation.retained_output")
    _exact(output, {"basename", "sha256", "size_bytes"}, "observation.retained_output")
    if output["basename"] != artifact.name:
        raise ValueError("servicing receipt retained output basename mismatch")
    digest = _sha256(output["sha256"], "observation.retained_output.sha256")
    if digest != artifact_digest or digest != expected.artifact_sha256:
        raise ValueError("servicing receipt retained output SHA-256 mismatch")
    size = output["size_bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0 or size != artifact_size:
        raise ValueError("servicing receipt retained output size mismatch")


def _file_reference(
    raw: object,
    base: Path,
    label: str,
    *,
    opaque_content: WindowsLpeOpaqueContent | None = None,
    opaque_root: Path | None = None,
) -> tuple[Path, str]:
    reference = _object(raw, label)
    _exact(reference, {"path", "sha256", "size_bytes"}, label)
    if opaque_content is not None:
        if opaque_root is None or not base.is_relative_to(opaque_root):
            raise ValueError("servicing receipt opaque root is invalid")
        relative = reference["path"]
        if not isinstance(relative, str):
            raise ValueError(f"servicing receipt {label}.path is invalid")
        expected = _sha256(reference["sha256"], f"{label}.sha256")
        size = reference["size_bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError(f"servicing receipt {label} size mismatch")
        prefix = base.relative_to(opaque_root).as_posix()
        manifest_path = relative if prefix == "." else f"{prefix}/{relative}"
        opaque_content.require(manifest_path, expected, size)
        return base / PurePosixPath(relative), expected
    path = _relative_path(base, reference["path"], f"{label}.path")
    digest, size = _hash_file(_regular_file(path, label), max_bytes=_MAX_TRANSCRIPT_BYTES)
    if digest != _sha256(reference["sha256"], f"{label}.sha256"):
        raise ValueError(f"servicing receipt {label} SHA-256 mismatch")
    declared_size = reference["size_bytes"]
    if (
        isinstance(declared_size, bool)
        or not isinstance(declared_size, int)
        or declared_size < 0
        or declared_size != size
    ):
        raise ValueError(f"servicing receipt {label} size mismatch")
    return path, digest


def _relative_path(base: Path, raw: object, label: str) -> Path:
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise ValueError(f"servicing receipt {label} must be a portable relative path")
    pure = PurePosixPath(raw)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"servicing receipt {label} must be a portable relative path")
    current = base
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"servicing receipt {label} must not traverse a symlink")
    try:
        resolved = current.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"servicing receipt {label} does not exist") from exc
    if not resolved.is_relative_to(base):
        raise ValueError(f"servicing receipt {label} escapes the receipt directory")
    return resolved


def _hash_array(raw: object, label: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"servicing receipt {label} must be a nonempty array")
    values = tuple(_sha256(value, f"{label}[{index}]") for index, value in enumerate(raw))
    if len(set(values)) != len(values):
        raise ValueError(f"servicing receipt {label} contains duplicates")
    return values


def _utc(raw: object, label: str) -> tuple[str, datetime]:
    if not isinstance(raw, str) or not raw.endswith("Z"):
        raise ValueError(f"servicing receipt {label} must be UTC with a Z suffix")
    try:
        value = datetime.fromisoformat(f"{raw[:-1]}+00:00")
    except ValueError as exc:
        raise ValueError(f"servicing receipt {label} is invalid") from exc
    if value.tzinfo != UTC or value.microsecond:
        raise ValueError(f"servicing receipt {label} must use whole UTC seconds")
    return raw, value


def _identifier(raw: object, label: str) -> str:
    if not isinstance(raw, str) or _IDENTIFIER.fullmatch(raw) is None:
        raise ValueError(f"servicing receipt {label} is invalid")
    return raw


def _nonempty(raw: object, label: str) -> str:
    if (
        not isinstance(raw, str)
        or not raw.strip()
        or raw != raw.strip()
        or any(character in raw for character in "\x00\r\n")
        or len(raw) > 512
    ):
        raise ValueError(f"servicing receipt {label} is invalid")
    return raw


def _sha256(raw: object, label: str) -> str:
    if not isinstance(raw, str) or _SHA256.fullmatch(raw) is None:
        raise ValueError(f"servicing receipt {label} must be a lowercase SHA-256")
    return raw


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"servicing receipt {label} must be a regular non-symlink file")
    return path


def _read_once(path: Path, label: str, max_bytes: int) -> bytes:
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(f"servicing receipt {label} has an invalid size")
    data = path.read_bytes()
    if len(data) != size:
        raise ValueError(f"servicing receipt {label} changed while reading")
    return data


def _hash_file(path: Path, *, max_bytes: int | None = None) -> tuple[str, int]:
    size = path.stat().st_size
    if max_bytes is not None and size > max_bytes:
        raise ValueError("servicing receipt referenced file exceeds its size limit")
    digest = hashlib.sha256()
    observed = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            observed += len(chunk)
            if max_bytes is not None and observed > max_bytes:
                raise ValueError("servicing receipt referenced file exceeds its size limit")
            digest.update(chunk)
    if observed != size:
        raise ValueError("servicing receipt referenced file changed while hashing")
    return digest.hexdigest(), observed


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise ValueError(f"servicing receipt {label} must be an object")
    return raw


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact(raw: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - raw.keys())
    unknown = sorted(raw.keys() - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise ValueError(f"servicing receipt {label} fields invalid: {'; '.join(details)}")
