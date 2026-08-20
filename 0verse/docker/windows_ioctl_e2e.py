"""Owned, inert PE/PDB-to-static-candidate smoke test for the engine image."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from zeroverse.ssh_authorization import canonical_signed_material
from zeroverse.windows_ioctl_rank import SCORE_VERSION
from zeroverse.windows_ioctl_real_rank import (
    ADMISSION_VERSION_V2,
    CAMPAIGN_VERSION,
    RESULT_VERSION_V2,
    SIGNATURE_NAMESPACE_V2,
    rank_windows_ioctl_real_static,
)
from zeroverse.windows_variant import produce_windows_ioctl_analysis_bundle


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sign(document: dict[str, object], key: Path, root: Path) -> dict[str, object]:
    signed = json.loads(json.dumps(document))
    signed["signature_ssh"] = ""
    material = root / "admission-material.json"
    material.write_bytes(canonical_signed_material(signed))
    subprocess.run(
        [
            "/usr/bin/ssh-keygen",
            "-q",
            "-Y",
            "sign",
            "-f",
            str(key),
            "-n",
            SIGNATURE_NAMESPACE_V2,
            str(material),
        ],
        check=True,
    )
    signed["signature_ssh"] = Path(f"{material}.sig").read_text(encoding="utf-8")
    return signed


def _rank_fixture(
    source: Path,
    case_id: str,
    root: Path,
    key: Path,
    policy: Path,
) -> dict[str, object]:
    root.mkdir()
    object_path = root / "target.obj"
    binary = root / "target.sys"
    pdb = root / "target.pdb"
    subprocess.run(
        [
            "/usr/bin/clang",
            "--target=x86_64-pc-windows-msvc",
            "-g",
            "-gcodeview",
            "-O0",
            "-fno-stack-protector",
            "-c",
            str(source),
            "-o",
            str(object_path),
        ],
        check=True,
    )
    subprocess.run(
        [
            "/usr/bin/lld-link",
            "/driver",
            "/entry:DriverEntry",
            "/subsystem:native",
            "/nodefaultlib",
            "/debug",
            f"/pdb:{pdb}",
            "/pdbaltpath:target.pdb",
            f"/out:{binary}",
            str(object_path),
        ],
        check=True,
    )

    descriptor = produce_windows_ioctl_analysis_bundle(
        binary,
        pdb,
        root / "bundle",
        ghidra_home=Path("/opt/ghidra"),
    )
    receipt_path = root / descriptor["analysis_receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    export_path = root / descriptor["ghidra_export_path"]
    export = json.loads(export_path.read_text(encoding="utf-8"))
    now = datetime.now(UTC)
    admission = _sign(
        {
            "schema_version": ADMISSION_VERSION_V2,
            "purpose": "static-candidate-ranking-only",
            "campaign_id": case_id,
            "driver_sha256": descriptor["binary_sha256"],
            "pdb_sha256": receipt["pdb"]["sha256"],
            "pdb_codeview_identity": receipt["pdb"]["codeview_identity"],
            "ghidra_export_sha256": descriptor["ghidra_export_sha256"],
            "analysis_receipt_sha256": descriptor["analysis_receipt_sha256"],
            "rank_contract": RESULT_VERSION_V2,
            "score_version": SCORE_VERSION,
            "label_manifest_commitment_sha256": hashlib.sha256(
                b"owned-image-e2e-private-label-manifest-v1"
            ).hexdigest(),
            "max_dispatches": 4,
            "max_fields_per_dispatch": 8,
            "max_candidates": 16,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "nonce": "owned-image-e2e-admission-000000000001",
            "admitted_by": "operator@example.test",
        },
        key,
        root,
    )
    admission_path = root / "admission.json"
    admission_path.write_text(json.dumps(admission, sort_keys=True), encoding="utf-8")
    campaign_path = root / "campaign.json"
    campaign_path.write_text(
        json.dumps(
            {
                "schema_version": CAMPAIGN_VERSION,
                "campaign_id": case_id,
                "artifact": descriptor,
                "admission_path": admission_path.name,
                "admission_sha256": _sha256(admission_path),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    result = rank_windows_ioctl_real_static(campaign_path, allowed_signers=policy)
    if result != rank_windows_ioctl_real_static(campaign_path, allowed_signers=policy):
        raise RuntimeError("owned image E2E ranking replay was not deterministic")
    return {
        "descriptor": descriptor,
        "receipt": receipt,
        "export": export,
        "result": result,
    }


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="zeroverse-windows-ioctl-e2e-") as raw_root:
        root = Path(raw_root)
        key = root / "operator-key"
        policy = root / "allowed-signers"
        subprocess.run(
            ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        public_key = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
        policy.write_text(f"operator@example.test {public_key}\n", encoding="utf-8")

        vulnerable = _rank_fixture(
            Path("/opt/0verse-fixtures/windows_ioctl_wdm.c"),
            "owned-wdm-image-e2e-vulnerable-01",
            root / "vulnerable",
            key,
            policy,
        )
        guarded = _rank_fixture(
            Path("/opt/0verse-fixtures/windows_ioctl_wdm_patched.c"),
            "owned-wdm-image-e2e-guarded-01",
            root / "guarded",
            key,
            policy,
        )
        fixed = _rank_fixture(
            Path("/opt/0verse-fixtures/windows_ioctl_wdm_fixed.c"),
            "owned-wdm-image-e2e-fixed-01",
            root / "fixed",
            key,
            policy,
        )
        descriptor = vulnerable["descriptor"]
        receipt = vulnerable["receipt"]
        export = vulnerable["export"]
        result = vulnerable["result"]
        assert isinstance(descriptor, dict)
        assert isinstance(receipt, dict)
        assert isinstance(export, dict)
        assert isinstance(result, dict)
        candidates = result["candidates"]
        if not isinstance(candidates, list) or len(candidates) != 1:
            raise RuntimeError("owned image E2E did not produce exactly one static candidate")
        candidate = candidates[0]
        evidence = candidate["ssa_evidence"]
        rich_field = export["facts"]["dispatches"][0]["fields"][0]
        if (
            receipt["schema_version"] != "0verse.ghidra-analysis-receipt/v3"
            or [ref["opcode"] for ref in rich_field["taint_path"]] != ["LOAD", "INT_ZEXT", "CALL"]
            or rich_field["safety_proofs"] != []
            or candidate["score"] != 100
            or evidence["field"] != {"kind": "length", "offset": 0, "width": 4}
            or evidence["sink_function"] != "RtlCopyMemory"
            or evidence["present_guards"] != []
            or result["device_ioctl_attempts"] != 0
            or result["execution_authorized"] is not False
            or result["static_only"] is not True
        ):
            raise RuntimeError("owned image E2E safety or evidence invariant failed")

        guarded_export = guarded["export"]
        guarded_result = guarded["result"]
        assert isinstance(guarded_export, dict)
        assert isinstance(guarded_result, dict)
        guarded_candidates = guarded_result["candidates"]
        if not isinstance(guarded_candidates, list) or len(guarded_candidates) != 1:
            raise RuntimeError("guarded owned image must remain a partial static candidate")
        guarded_candidate = guarded_candidates[0]
        guarded_field = guarded_export["facts"]["dispatches"][0]["fields"][0]
        guarded_evidence = guarded_candidate["ssa_evidence"]
        if (
            guarded_field["guards"] != ["field-within-input", "input-buffer-length"]
            or [item["proof_kind"] for item in guarded_field["safety_proofs"]]
            != ["input-field-readable"]
            or guarded_evidence["present_guards"] != ["field-within-input", "input-buffer-length"]
            or guarded_evidence["missing_guards"] != ["checked-arithmetic"]
            or guarded_candidate["score"] != 75
            or guarded_candidate["score"] >= candidate["score"]
            or guarded_result["device_ioctl_attempts"] != 0
            or guarded_result["execution_authorized"] is not False
            or guarded_result["static_only"] is not True
        ):
            raise RuntimeError("guarded image discrimination or safety invariant failed")

        fixed_export = fixed["export"]
        fixed_result = fixed["result"]
        assert isinstance(fixed_export, dict)
        assert isinstance(fixed_result, dict)
        fixed_fields = fixed_export["facts"]["dispatches"][0]["fields"]
        fixed_candidates = fixed_result["candidates"]
        if not isinstance(fixed_fields, list) or len(fixed_fields) != 1:
            raise RuntimeError("fully fixed image must retain exactly one neutral static site")
        fixed_field = fixed_fields[0]
        if (
            fixed_field["guards"]
            != ["checked-arithmetic", "field-within-input", "input-buffer-length"]
            or [item["proof_kind"] for item in fixed_field["safety_proofs"]]
            != ["destination-copy-span", "input-field-readable", "source-copy-span"]
            or fixed_result["site_count"] != 1
            or fixed_result["candidate_count"] != 0
            or fixed_candidates != []
            or fixed_result["device_ioctl_attempts"] != 0
            or fixed_result["execution_authorized"] is not False
            or fixed_result["static_only"] is not True
        ):
            raise RuntimeError("fully fixed image compound-guard or suppression invariant failed")
        print(
            json.dumps(
                {
                    "candidate_count": 1,
                    "device_ioctl_attempts": 0,
                    "execution_authorized": False,
                    "field_offset": 0,
                    "fixed_candidate_count": 0,
                    "fixed_site_count": 1,
                    "guarded_missing_guards": ["checked-arithmetic"],
                    "guarded_score": 75,
                    "receipt_schema": receipt["schema_version"],
                    "sink_function": evidence["sink_function"],
                    "static_only": True,
                    "vulnerable_score": 100,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
