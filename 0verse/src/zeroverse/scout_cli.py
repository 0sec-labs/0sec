"""Hardware-free CLI handlers for passive Firmware Scout evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .acquisition import DeviceIdentity, RedactionRecord
from .acquisition_bundle import AcquisitionBundle, load_acquisition_bundle
from .firmware_inspection import FirmwareInspectionReport, inspect_bundle
from .scout_evidence import (
    ScoutEvent,
    ScoutEvidenceSession,
    ScoutReplayResult,
    ScoutSessionMetadata,
    VirtualCanEcu,
    replay_scout_bundle,
)

_FIXTURE_STARTED_AT = "2026-07-18T10:00:00Z"
_FIXTURE_COMPLETED_AT = "2026-07-18T10:01:00Z"


class _ReplayDiscarder:
    def observe(self, _event: ScoutEvent) -> None:
        pass


def _fixture_metadata() -> ScoutSessionMetadata:
    return ScoutSessionMetadata(
        acquisition_id="scout-standard-fixture-v1",
        device=DeviceIdentity(
            category="ecu",
            manufacturer="0verse",
            model="Virtual CAN fixture",
            hardware_revision="v1",
            identifiers=(),
        ),
        redaction=RedactionRecord(
            status="not-required",
            policy="0verse.default-export/v1",
            contains_sensitive_values=False,
            entries=(),
        ),
        interface="virtual-can0",
        source="deterministic in-memory virtual ECU",
        collector="0verse",
        authorization_basis="synthetic-fixture",
        started_at=_FIXTURE_STARTED_AT,
        tool_name="0verse-firmware-scout",
        tool_version=__version__,
        notes="Fixture-only capture; no physical CAN interface or transmission was used.",
    )


def capture_standard_fixture(output: str | Path) -> AcquisitionBundle:
    """Seal the standard non-transmitting virtual-CAN fixture into a new bundle."""
    session = ScoutEvidenceSession(output, _fixture_metadata())
    VirtualCanEcu.standard_fixture().capture(session)
    return session.seal(completed_at=_FIXTURE_COMPLETED_AT)


def _safe_device(bundle: AcquisitionBundle) -> dict[str, object]:
    device = bundle.manifest.device
    return {
        "category": device.category,
        "manufacturer": device.manufacturer,
        "model": device.model,
        "hardware_revision": device.hardware_revision,
        "identifiers": [
            {
                "kind": identifier.kind,
                "sensitivity": identifier.sensitivity,
                "redacted": identifier.value is not None,
            }
            for identifier in device.identifiers
        ],
    }


def _observed_bundle(bundle: AcquisitionBundle) -> dict[str, object]:
    manifest = bundle.manifest
    return {
        "acquisition": {
            "acquisition_id": manifest.acquisition_id,
            "device": _safe_device(bundle),
            "transport": {
                "kind": manifest.transport.kind,
                "protocol": manifest.transport.protocol,
                "mode": manifest.transport.mode,
                "transmitted": manifest.transport.transmitted,
            },
            "artifacts": [
                {
                    "artifact_id": item.artifact.artifact_id,
                    "kind": item.artifact.kind,
                    "present": item.is_present,
                    "observed_size": item.observed_size,
                    "observed_sha256": item.observed_sha256,
                }
                for item in bundle.artifacts
            ],
            "redaction": {
                "status": manifest.redaction.status,
                "policy": manifest.redaction.policy,
                "contains_sensitive_values": manifest.redaction.contains_sensitive_values,
            },
        }
    }


def _inspection_observation(report: FirmwareInspectionReport) -> dict[str, object]:
    return {
        "artifact_id": report.artifact_id,
        "size": report.size,
        "sha256": report.sha256,
        "overall_entropy": report.overall_entropy,
        "entropy_window_size": report.entropy_window_size,
        "string_count": report.string_count,
        "strings_truncated": report.strings_truncated,
        "padding_run_count": report.padding_run_count,
        "padding_runs_truncated": report.padding_runs_truncated,
        "repeated_region_count": report.repeated_region_count,
        "repeated_regions_truncated": report.repeated_regions_truncated,
        "container_candidate_count": report.container_candidate_count,
        "containers_truncated": report.containers_truncated,
    }


def _inspection_inferences(report: FirmwareInspectionReport) -> dict[str, object]:
    return {
        "artifact_id": report.artifact_id,
        "load_address": report.load_address,
        "load_address_basis": report.load_address_basis,
        "load_address_evidence": list(report.load_address_evidence),
        "containers": [item.to_dict() for item in report.containers],
        "architectures": [item.to_dict() for item in report.architectures],
        "vector_tables": [item.to_dict() for item in report.vector_tables],
        "regions": [item.to_dict() for item in report.regions],
    }


def scout_taxonomy(bundle: AcquisitionBundle, replay: ScoutReplayResult) -> dict[str, object]:
    """Project verified bundle data without promoting candidate evidence to fact."""
    reports = inspect_bundle(bundle)
    return {
        "observed": {
            **_observed_bundle(bundle),
            "replay": replay.to_dict(),
            "inspections": [_inspection_observation(report) for report in reports],
        },
        "inferences": {
            "inspections": [_inspection_inferences(report) for report in reports],
        },
        "unknowns": {
            "bundle": [] if reports else ["no-verified-firmware-artifacts"],
            "inspections": [
                {"artifact_id": report.artifact_id, "items": list(report.unknowns)}
                for report in reports
            ],
        },
    }


def render_report(taxonomy: dict[str, object], output_format: str) -> str:
    """Render a taxonomy whose device identifier values have already been removed."""
    if output_format == "json":
        return json.dumps(taxonomy, indent=2, sort_keys=True)
    if output_format != "md":
        raise ValueError(f"unsupported Scout report format: {output_format}")
    sections = (
        ("Observed", taxonomy["observed"]),
        ("Inferences", taxonomy["inferences"]),
        ("Unknowns", taxonomy["unknowns"]),
    )
    rendered = ["# 0verse Scout report"]
    for title, section in sections:
        rendered.extend(("", f"## {title}", "", "```json"))
        rendered.append(json.dumps(section, indent=2, sort_keys=True))
        rendered.append("```")
    return "\n".join(rendered)


def run_scout(args: argparse.Namespace) -> int:
    """Run the bounded Scout CLI surface with fail-closed input handling."""
    try:
        if args.scout_cmd == "capture":
            bundle = capture_standard_fixture(args.output)
            print(
                json.dumps(
                    {
                        "observed": {
                            "acquisition_id": bundle.manifest.acquisition_id,
                            "bundle": str(bundle.root),
                            "transport": {
                                "mode": bundle.manifest.transport.mode,
                                "transmitted": bundle.manifest.transport.transmitted,
                            },
                        },
                        "inferences": {},
                        "unknowns": [],
                    },
                    sort_keys=True,
                )
            )
            return 0

        bundle = load_acquisition_bundle(args.bundle)
        replay = replay_scout_bundle(bundle, _ReplayDiscarder())
        taxonomy = scout_taxonomy(bundle, replay)
        if args.scout_cmd == "inspect":
            print(render_report(taxonomy, "json"))
            return 0
        if args.scout_cmd == "report":
            print(render_report(taxonomy, args.format))
            return 0
        raise ValueError(f"unsupported Scout command: {args.scout_cmd}")
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
