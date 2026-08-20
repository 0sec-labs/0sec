"""`0verse` command-line entrypoint."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .ingest import triage


def _require_explicit_backend(requested: str | None) -> int | None:
    """Exit code when an explicitly requested decompiler backend cannot initialize,
    or None to continue (#297).

    ``--backend auto`` (the default) is allowed to degrade down the preference
    chain. Naming a backend — by flag or by ``$ZEROVERSE_BACKEND`` — is a demand,
    and an unmet demand exits non-zero rather than producing a complete-looking
    result table for a pipeline that never decompiled anything.
    """
    from .backends import contract

    try:
        contract.ensure_explicit_backend(requested)
    except contract.BackendUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="0verse", description=__doc__)
    parser.add_argument("--version", action="version", version=f"0verse {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_triage = sub.add_parser("triage", help="identify format, arch, and mitigations (no deps)")
    p_triage.add_argument("binary")
    p_triage.add_argument("--json", action="store_true", help="emit JSON")

    p_run = sub.add_parser("run", help="full discovery pipeline (needs engines/Docker)")
    p_run.add_argument("binary")
    p_run.add_argument("--bug-class", default="memory-safety")
    p_run.add_argument(
        "--format", choices=["text", "json", "sarif", "ndjson", "md"], default="text"
    )
    p_run.add_argument(
        "--llm",
        default="mock",
        help="triage backend: mock (no key) | gateway (0llm at LLM_GATEWAY_URL) | "
        "auto | claude | glm | openai | codex.",
    )
    p_run.add_argument(
        "--model",
        default=None,
        help="model id (also auto-routes the provider, e.g. glm-4.6, gpt-4o)",
    )

    # M5 #28 — the embeddable/machine-contract entrypoint a scan platform drives.
    p_scan = sub.add_parser("scan", help="scan a binary, emit the versioned machine contract")
    p_scan.add_argument("binary")
    p_scan.add_argument("--format", choices=["json", "ndjson", "sarif"], default="ndjson")
    p_scan.add_argument(
        "--backend",
        choices=["auto", "ghidra", "rizin", "angr"],
        default="auto",
        help="decompiler backend (M5 #27)",
    )
    p_scan.add_argument("--bug-class", default="memory-safety")
    p_scan.add_argument("--llm", default="mock")
    p_scan.add_argument("--model", default=None)
    # Cloud-sink lane — stream findings to the 0cloud orchestrator instead of
    # printing a local report. The bearer token is env-ONLY (PWNKIT_CLOUD_TOKEN).
    p_scan.add_argument(
        "--cloud",
        action="store_true",
        help="stream findings to the 0cloud orchestrator (PWNKIT_CLOUD_* env)",
    )
    p_scan.add_argument(
        "--scan-id", default=None, help="cloud scan id (or PWNKIT_CLOUD_SCAN_ID; env wins)"
    )
    p_scan.add_argument(
        "--sink", default=None, help="orchestrator base URL (or PWNKIT_CLOUD_SINK; env wins)"
    )
    p_scan.add_argument(
        "--timeout", type=int, default=30000, help="per-request POST timeout in ms (cloud mode)"
    )

    p_feedback = sub.add_parser(
        "research-feedback-import",
        help="verify a 0brain feedback projection and retain evidence-grade learning",
    )
    p_feedback.add_argument("--projection", required=True)
    p_feedback.add_argument("--bundle", required=True)
    p_feedback.add_argument("--output-root", required=True)
    p_feedback.add_argument("--ledger", required=True)
    p_scout = sub.add_parser(
        "scout",
        help="hardware-free passive Firmware Scout workflow",
    )
    scout_sub = p_scout.add_subparsers(dest="scout_cmd", required=True)
    p_scout_capture = scout_sub.add_parser(
        "capture",
        help="seal the standard virtual fixture without hardware or transmission",
        description=(
            "Create a sealed fixture bundle. No hardware or live transport is opened and no "
            "frames are transmitted."
        ),
    )
    p_scout_capture.add_argument("--fixture", choices=["standard"], required=True)
    p_scout_capture.add_argument("--output", required=True, help="new acquisition bundle directory")
    p_scout_inspect = scout_sub.add_parser(
        "inspect",
        help="validate a bundle offline without hardware, live transport, or transmission",
        description=(
            "Validate and inspect sealed Scout evidence. No hardware or live transport is "
            "opened and no frames are transmitted."
        ),
    )
    p_scout_inspect.add_argument("bundle", help="AcquisitionManifest-v1 bundle directory")
    p_scout_report = scout_sub.add_parser(
        "report",
        help="export offline evidence without hardware, live transport, or transmission",
        description=(
            "Export validated Scout evidence. No hardware or live transport is opened and no "
            "frames are transmitted."
        ),
    )
    p_scout_report.add_argument("bundle", help="AcquisitionManifest-v1 bundle directory")
    p_scout_report.add_argument("--format", choices=["json", "md"], default="json")

    # M7 #42 — fleet-scale cross-target variant analysis (1 seed -> N n-days).
    p_fleet = sub.add_parser(
        "fleet", help="#42 fleet variant analysis: 1 seed -> N confirmed n-days across a fleet"
    )
    seed_grp = p_fleet.add_mutually_exclusive_group(required=True)
    seed_grp.add_argument(
        "--seed-archetype",
        help="archetype id: bugclass:cmdi | firmware:cgi-cmdi | linux-ko:copy-from-user | "
        "kernel/DRV-01",
    )
    seed_grp.add_argument(
        "--seed-reference",
        metavar="BINARY:FUNCTION",
        help="build the matcher from a confirmed reference vulnerable function",
    )
    p_fleet.add_argument(
        "--fleet",
        required=True,
        help="fleet: a directory, a manifest file, or comma-separated binary/firmware paths",
    )
    p_fleet.add_argument(
        "--reference",
        metavar="BINARY:FUNCTION",
        default=None,
        help="attach a reference shape for similarity ranking (pairs with --seed-archetype)",
    )
    p_fleet.add_argument(
        "--no-confirm", action="store_true", help="detect only — skip the PoV confirmation lane"
    )
    p_fleet.add_argument(
        "--dataset", default=None, help="append #32 labeled-PoV dataset records to this NDJSON path"
    )
    p_fleet.add_argument("--format", choices=["text", "json"], default="text")

    p_windows = sub.add_parser(
        "windows-replay", help="replay a PoV corpus through the authorized Windows oracle"
    )
    p_windows.add_argument("binary", help="Windows PE target")
    p_windows.add_argument("corpus", help="one input file or a flat corpus directory")
    p_windows.add_argument(
        "--control-binary", default=None, help="optional fixed/baseline PE for differential replay"
    )
    p_windows.add_argument(
        "--host", default=None, help="SSH host alias (defaults to ZEROVERSE_WINDOWS_HOST)"
    )
    p_windows.add_argument("--oracle", choices=["auto", "pageheap", "drmemory"], default="auto")
    p_windows.add_argument("--timeout", type=float, default=30.0)
    p_windows.add_argument("--format", choices=["json", "ndjson"], default="ndjson")
    p_windows.add_argument(
        "--output", default=None, help="write evidence to a file instead of stdout"
    )
    windows_scope = p_windows.add_mutually_exclusive_group(required=True)
    windows_scope.add_argument(
        "--scope-manifest", help="fresh, passing Windows/Hyper-V bounty scope manifest"
    )
    windows_scope.add_argument(
        "--lab-only",
        action="store_true",
        help="mark replay as ineligible lab/oracle-engineering evidence",
    )

    for command, help_text in (
        (
            "windows-token-validate",
            "validate a signed Windows token campaign and its authority chain",
        ),
        (
            "windows-token-aggregate",
            "aggregate signed per-run Windows token captures without executing code",
        ),
        (
            "windows-token-aggregate-neutral",
            "neutrally aggregate and consume candidate or clean-fixed token captures",
        ),
    ):
        token_parser = sub.add_parser(command, help=help_text)
        token_parser.add_argument("campaign")
        token_parser.add_argument("--scope-manifest", required=True)
        token_parser.add_argument("--execution-grant", required=True)
        token_parser.add_argument("--worker-acceptance", required=True)
        if command in {"windows-token-aggregate", "windows-token-aggregate-neutral"}:
            token_parser.add_argument("--capture", action="append", required=True)
            token_parser.add_argument("--nonce-ledger", required=True)
            token_parser.add_argument("--signing-key", required=True)
            token_parser.add_argument("--signed-by", required=True)
            token_parser.add_argument("--output", default=None)

    token_verify = sub.add_parser(
        "windows-token-evidence-verify",
        help="verify a controller-signed Windows token aggregate receipt",
    )
    token_verify.add_argument("receipt")

    token_capture_verify = sub.add_parser(
        "windows-token-capture-verify",
        help="verify one signed raw Windows token capture without aggregating it",
    )
    token_capture_verify.add_argument("capture")

    lpe_worker_readiness = sub.add_parser(
        "windows-lpe-worker-readiness",
        help="verify an isolated Windows worker drill and emit a non-executing run plan",
    )
    lpe_worker_readiness.add_argument("readiness")
    lpe_worker_readiness.add_argument("--campaign", required=True)
    lpe_worker_readiness.add_argument("--scope-manifest", required=True)
    lpe_worker_readiness.add_argument("--execution-grant", required=True)
    lpe_worker_readiness.add_argument("--worker-acceptance", required=True)
    lpe_worker_readiness.add_argument("--scope-allowed-signers")
    lpe_worker_readiness.add_argument("--execution-grant-allowed-signers")
    lpe_worker_readiness.add_argument("--worker-acceptance-allowed-signers")
    lpe_worker_readiness.add_argument("--readiness-allowed-signers")

    token_pack_verify = sub.add_parser(
        "windows-token-pack-verify",
        help="verify a complete signed Windows token evidence closure without accepting it",
    )
    token_pack_verify.add_argument("envelope")
    token_pack_verify.add_argument("--blob-dir", required=True)
    token_pack_verify.add_argument("--acceptance-policy", required=True)
    token_pack_verify.add_argument("--expected-context", required=True)
    token_pack_verify.add_argument("--pack-signer-policy", required=True)

    bounty_classify = sub.add_parser(
        "windows-token-bounty-classify",
        help="classify verified Windows token evidence against current public bounty rules",
    )
    bounty_classify.add_argument("envelope")
    bounty_classify.add_argument("--blob-dir", required=True)
    bounty_classify.add_argument("--acceptance-policy", required=True)
    bounty_classify.add_argument("--expected-context", required=True)
    bounty_classify.add_argument("--pack-signer-policy", required=True)
    bounty_classify.add_argument(
        "--category",
        required=True,
        choices=["GENERAL_EOP", "LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE"],
    )
    bounty_classify.add_argument("--local-scenario-evidence")

    token_pack_build = sub.add_parser(
        "windows-token-pack-build",
        help="build a deterministic signed Windows token evidence pack",
    )
    token_pack_build.add_argument("output_dir")
    token_pack_build.add_argument("--campaign", required=True)
    token_pack_build.add_argument("--scope-manifest", required=True)
    token_pack_build.add_argument("--execution-grant", required=True)
    token_pack_build.add_argument("--worker-acceptance", required=True)
    token_pack_build.add_argument("--aggregate-receipt", required=True)
    token_pack_build.add_argument("--capture", action="append", required=True)
    token_pack_build.add_argument("--scope-allowed-signers", required=True)
    token_pack_build.add_argument("--execution-grant-allowed-signers", required=True)
    token_pack_build.add_argument("--worker-acceptance-allowed-signers", required=True)
    token_pack_build.add_argument("--capture-allowed-signers", required=True)
    token_pack_build.add_argument("--aggregate-allowed-signers", required=True)
    token_pack_build.add_argument("--run-id", required=True)
    token_pack_build.add_argument("--job-nonce", required=True)
    token_pack_build.add_argument("--zeroverse-runtime-digest", required=True)
    token_pack_build.add_argument("--pack-signer-identity", required=True)
    token_pack_build.add_argument("--pack-signing-key", required=True)

    for command, help_text in (
        (
            "windows-lpe-paired-closure-verify",
            "re-verify a candidate/fixed Windows LPE closure without accepting it",
        ),
        (
            "windows-lpe-paired-closure-verify-cas",
            "re-verify a CAS-native Windows LPE closure without accepting it",
        ),
    ):
        paired_closure_verify = sub.add_parser(command, help=help_text)
        paired_closure_verify.add_argument("pair_plan")
        paired_closure_verify.add_argument("--experiment", required=True)
        paired_closure_verify.add_argument("--experiment-allowed-signers", required=True)
        if command.endswith("-cas"):
            paired_closure_verify.add_argument("--opaque-content", required=True)
        for side in ("candidate", "fixed"):
            paired_closure_verify.add_argument(f"--{side}-artifact", required=True)
            paired_closure_verify.add_argument(f"--{side}-servicing-receipt", required=True)
            paired_closure_verify.add_argument(f"--{side}-servicing-allowed-signers", required=True)
            paired_closure_verify.add_argument(f"--{side}-envelope", required=True)
            paired_closure_verify.add_argument(f"--{side}-blob-dir", required=True)
            paired_closure_verify.add_argument(f"--{side}-acceptance-policy", required=True)
            paired_closure_verify.add_argument(f"--{side}-expected-context", required=True)
            paired_closure_verify.add_argument(f"--{side}-pack-signer-policy", required=True)

    p_hyperv = sub.add_parser(
        "hyperv-prove",
        help="validate or execute a fail-closed Hyper-V guest-to-host reproduction",
    )
    p_hyperv.add_argument("manifest", help="Hyper-V prover campaign JSON manifest")
    p_hyperv.add_argument(
        "--scope-manifest",
        required=True,
        help="fresh, passing Hyper-V bounty scope manifest",
    )
    p_hyperv.add_argument(
        "--execute",
        action="store_true",
        help="perform checkpoint restores and guest cases; default is validation only",
    )
    p_hyperv.add_argument(
        "--execution-grant",
        default=None,
        help="short-lived operator grant bound to the exact campaign, scope, and placement",
    )
    p_hyperv.add_argument(
        "--worker-acceptance",
        default=None,
        help="sealed, fresh recovery and toolchain acceptance receipt for the exact worker",
    )
    p_hyperv.add_argument("--output", default=None, help="write JSON evidence to a file")
    p_hyperv.add_argument(
        "--artifact-dir",
        default=None,
        help="required with --execute; retain guest transcripts and cdb analysis",
    )

    p_accept = sub.add_parser(
        "hyperv-accept-worker",
        help="independently validate and sign one exact Hyper-V worker/grant binding",
    )
    p_accept.add_argument("manifest", help="Hyper-V prover campaign JSON manifest")
    p_accept.add_argument("--scope-manifest", required=True)
    p_accept.add_argument("--execution-grant", required=True)
    p_accept.add_argument("--recovery-drill", required=True)
    p_accept.add_argument("--output-dir", required=True)
    p_accept.add_argument("--accepted-by", required=True)
    p_accept.add_argument("--ttl-hours", type=float, default=4.0)
    p_accept.add_argument(
        "--execute",
        action="store_true",
        help="restore the checkpoint and validate live host/guest state before signing",
    )

    p_report = sub.add_parser(
        "windows-report", help="create a fail-closed MSRC draft from replay NDJSON"
    )
    p_report.add_argument("evidence", help="differential windows-replay NDJSON")
    p_report.add_argument("--title", required=True)
    p_report.add_argument("--output", required=True)

    p_variant = sub.add_parser(
        "windows-variant-rank",
        help="rank missing-guard variants from vulnerable/fixed/current Ghidra exports",
    )
    p_variant.add_argument("manifest", help="hash-pinned Windows variant campaign JSON")
    p_variant.add_argument("--output", default=None, help="write JSON instead of stdout")

    p_discover = sub.add_parser(
        "windows-discover",
        help="generate candidate-only static deltas from operator-ordered Windows v3 bundles",
    )
    p_discover.add_argument("campaign", help="v3 campaign or bound local-pair intake JSON")
    p_discover.add_argument(
        "--output", default=None, help="atomically write a new mode-0600 JSON file"
    )

    p_ioctl_plan = sub.add_parser(
        "windows-ioctl-plan",
        help="validate and plan an inert bounded Windows IOCTL fixture campaign",
    )
    p_ioctl_plan.add_argument("manifest", help="synthetic Windows IOCTL boundary manifest")
    p_ioctl_plan.add_argument("--output", default=None, help="write JSON instead of stdout")

    p_ioctl_rank = sub.add_parser(
        "windows-ioctl-rank",
        help="rank exact static High-P-Code IOCTL evidence without device execution",
    )
    p_ioctl_rank.add_argument("campaign", help="hash-pinned Windows IOCTL static campaign")
    p_ioctl_rank.add_argument("--output", default=None, help="write JSON instead of stdout")

    p_ioctl_real_rank = sub.add_parser(
        "windows-ioctl-real-rank",
        help="rank signed real-artifact High-P-Code evidence without execution",
    )
    p_ioctl_real_rank.add_argument("campaign", help="signed real-artifact static campaign")
    p_ioctl_real_rank.add_argument("--output", default=None, help="write JSON instead of stdout")

    p_ioctl_sites = sub.add_parser(
        "windows-ioctl-site-universe",
        help="enumerate a signed-role-neutral complete export-v2 site universe",
    )
    p_ioctl_sites.add_argument("request", help="real analysis-bundle site-universe request")
    p_ioctl_sites.add_argument("--output", default=None, help="write canonical JSON")

    p_ioctl_sites_verify = sub.add_parser(
        "windows-ioctl-site-universe-verify",
        help="verify a canonical site-universe precommit and detached signature",
    )
    p_ioctl_sites_verify.add_argument("manifest", help="canonical site-universe JSON")

    p_ioctl_rank_publish = sub.add_parser(
        "windows-ioctl-real-rank-publish",
        help="atomically publish a fixed-authority real static rank result and receipt",
    )
    p_ioctl_rank_publish.add_argument("campaign", help="signed real-artifact static campaign")
    p_ioctl_rank_publish.add_argument(
        "bundle_name", help="safe immutable bundle name under the fixed service spool"
    )

    p_ioctl_real_eval = sub.add_parser(
        "windows-ioctl-real-eval",
        help="open precommitted blinded labels against an attested static rank result",
    )
    p_ioctl_real_eval.add_argument("rank_output")
    p_ioctl_real_eval.add_argument("rank_receipt")
    p_ioctl_real_eval.add_argument("labels")
    p_ioctl_real_eval.add_argument("--output", default=None, help="write JSON instead of stdout")

    p_device_open_verify = sub.add_parser(
        "windows-device-open-verify",
        help="verify a signed capability-only Windows device-open observation",
    )
    p_device_open_verify.add_argument("receipt")
    p_device_open_verify.add_argument(
        "--allowed-signers",
        default=None,
        help="role-separated receipt signer policy (defaults to the trusted system policy)",
    )

    p_variant_bundle = sub.add_parser(
        "windows-analysis-bundle",
        help="produce an atomic PE/PDB/Ghidra export provenance bundle",
    )
    p_variant_bundle.add_argument("binary", help="Windows PE binary")
    p_variant_bundle.add_argument("pdb", help="matching PDB")
    p_variant_bundle.add_argument("output_dir", help="new output directory")
    p_variant_bundle.add_argument(
        "--ghidra-home",
        default=None,
        help="Ghidra installation (defaults to GHIDRA_INSTALL_DIR or GHIDRA_HOME)",
    )

    p_ioctl_analysis_bundle = sub.add_parser(
        "windows-ioctl-analysis-bundle",
        help="produce an atomic PE/PDB/dedicated IOCTL High-P-Code analysis bundle",
    )
    p_ioctl_analysis_bundle.add_argument("binary", help="x64 WDM driver PE")
    p_ioctl_analysis_bundle.add_argument("pdb", help="matching PDB")
    p_ioctl_analysis_bundle.add_argument("output_dir", help="new output directory")
    p_ioctl_analysis_bundle.add_argument(
        "--ghidra-home",
        default=None,
        help="Ghidra installation (defaults to GHIDRA_INSTALL_DIR or GHIDRA_HOME)",
    )

    p_public_ioctl_analysis_bundle = sub.add_parser(
        "windows-public-ioctl-analysis-bundle",
        help="analyze a driver through a retained Microsoft public-PDB route bundle",
    )
    p_public_ioctl_analysis_bundle.add_argument("binary", help="x64 WDM driver PE")
    p_public_ioctl_analysis_bundle.add_argument(
        "public_pdb_bundle", help="verified content-addressed public-PDB bundle"
    )
    p_public_ioctl_analysis_bundle.add_argument("output_dir", help="new output directory")
    p_public_ioctl_analysis_bundle.add_argument(
        "--ghidra-home",
        default=None,
        help="Ghidra installation (defaults to GHIDRA_INSTALL_DIR or GHIDRA_HOME)",
    )

    p_ioctl_surface = sub.add_parser(
        "windows-ioctl-surface-inventory",
        help="retain and inventory a neutral Windows driver IOCTL dispatch surface",
    )
    p_ioctl_surface.add_argument("binary", help="x64 WDM driver PE")
    p_ioctl_surface.add_argument("pdb", help="matching PDB")
    p_ioctl_surface.add_argument("output_dir", help="new output directory")
    p_ioctl_surface.add_argument(
        "--public-pdb-bundle",
        default=None,
        help="verified content-addressed public-PDB route bundle",
    )
    p_ioctl_surface.add_argument(
        "--ghidra-home",
        default=None,
        help="Ghidra installation (defaults to GHIDRA_INSTALL_DIR or GHIDRA_HOME)",
    )
    p_ioctl_surface_verify = sub.add_parser(
        "windows-ioctl-surface-inventory-verify",
        help="verify a retained Windows driver IOCTL surface inventory bundle",
    )
    p_ioctl_surface_verify.add_argument("bundle", help="inventory bundle directory")
    p_entry_bridge = sub.add_parser(
        "windows-driver-entry-bridge",
        help="prove and retain the static PE wrapper to PDB DriverEntry bridge",
    )
    p_entry_bridge.add_argument("binary", help="x64 Windows driver PE")
    p_entry_bridge.add_argument("pdb", help="matching or verified public-route PDB")
    p_entry_bridge.add_argument("output_dir", help="new output directory")
    p_entry_bridge.add_argument("--public-pdb-bundle", default=None)
    p_entry_bridge.add_argument("--ghidra-home", default=None)
    p_entry_bridge_v3 = sub.add_parser(
        "windows-driver-entry-bridge-v3",
        help="prove the ABI-bound v3 PE wrapper to PDB DriverEntry bridge",
    )
    p_entry_bridge_v3.add_argument("binary")
    p_entry_bridge_v3.add_argument("pdb")
    p_entry_bridge_v3.add_argument("output_dir")
    p_entry_bridge_v3.add_argument("--public-pdb-bundle", default=None)
    p_entry_bridge_v3.add_argument("--ghidra-home", default=None)
    p_entry_bridge_v3.add_argument("--abi-authority-dir", required=True)
    p_entry_bridge_verify = sub.add_parser(
        "windows-driver-entry-bridge-verify",
        help="verify a retained static DriverEntry bridge bundle",
    )
    p_entry_bridge_verify.add_argument("bundle", help="entry bridge bundle directory")
    p_entry_bridge_verify.add_argument(
        "--ghidra-home",
        default=None,
        help="the exact fingerprinted Ghidra installation used to replay the proof",
    )
    p_driver_registration = sub.add_parser(
        "windows-driver-registration",
        help="prove one projected static AFD device-control registration assignment",
    )
    p_driver_registration.add_argument("entry_bridge_bundle")
    p_driver_registration.add_argument("wdm_projection")
    p_driver_registration.add_argument("output_dir")
    p_driver_registration.add_argument("--ghidra-home", default=None)
    p_driver_registration_verify = sub.add_parser(
        "windows-driver-registration-verify",
        help="verify and replay a projected AFD registration bundle",
    )
    p_driver_registration_verify.add_argument("bundle")
    p_driver_registration_verify.add_argument("--ghidra-home", default=None)
    p_afd_selector = sub.add_parser(
        "windows-afd-selector",
        help="prove the bounded local AFD device-control selector branch",
    )
    p_afd_selector.add_argument("registration_bundle")
    p_afd_selector.add_argument("output_dir")
    p_afd_selector.add_argument("--ghidra-home", default=None)
    p_afd_selector.add_argument("--dispatch-abi-authority-dir", required=True)
    p_afd_selector_verify = sub.add_parser(
        "windows-afd-selector-verify",
        help="verify and replay a retained bounded AFD selector bundle",
    )
    p_afd_selector_verify.add_argument("bundle")
    p_afd_selector_verify.add_argument("--ghidra-home", default=None)
    p_afd_hypotheses = sub.add_parser(
        "windows-afd-hypotheses",
        help="build a non-executing paired AFD handler-analysis worklist",
    )
    p_afd_hypotheses.add_argument("side_a_selector")
    p_afd_hypotheses.add_argument("side_b_selector")
    p_afd_hypotheses.add_argument("output_dir")
    p_afd_hypotheses.add_argument("--ghidra-home", default=None)
    p_afd_hypotheses_verify = sub.add_parser(
        "windows-afd-hypotheses-verify",
        help="verify and replay a retained paired AFD hypotheses bundle",
    )
    p_afd_hypotheses_verify.add_argument("bundle")
    p_afd_hypotheses_verify.add_argument("--ghidra-home", default=None)
    p_afd_native = sub.add_parser(
        "windows-afd-handler-native-evidence",
        help="retain exact native evidence for the paired AFD handler worklist",
    )
    p_afd_native.add_argument("hypotheses_bundle")
    p_afd_native.add_argument("output_dir")
    p_afd_native.add_argument("--ghidra-home", default=None)
    p_afd_native_verify = sub.add_parser(
        "windows-afd-handler-native-evidence-verify",
        help="verify and fully replay retained AFD handler native evidence",
    )
    p_afd_native_verify.add_argument("bundle")
    p_afd_native_verify.add_argument("--ghidra-home", default=None)
    p_afd_cfg_ssa = sub.add_parser(
        "windows-afd-handler-cfg-ssa",
        help="retain complete function-local CFG/SSA for paired AFD native evidence",
    )
    p_afd_cfg_ssa.add_argument("native_bundle")
    p_afd_cfg_ssa.add_argument("output_dir")
    p_afd_cfg_ssa.add_argument("--ghidra-home", default=None)
    p_afd_cfg_ssa_verify = sub.add_parser(
        "windows-afd-handler-cfg-ssa-verify",
        help="verify and fully replay retained paired AFD CFG/SSA evidence",
    )
    p_afd_cfg_ssa_verify.add_argument("bundle")
    p_afd_cfg_ssa_verify.add_argument("--ghidra-home", default=None)

    p_official_download = sub.add_parser(
        "windows-official-download",
        help="download an official Microsoft artifact into a SHA-256-addressed store",
    )
    p_official_download.add_argument("url")
    p_official_download.add_argument("store_root")
    p_official_download.add_argument(
        "--kind",
        required=True,
        choices=["iso", "msu", "cab", "pdb", "pe", "catalog", "metadata"],
    )
    p_official_download.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024 * 1024)

    p_official_verify = sub.add_parser(
        "windows-official-verify",
        help="verify an official-download bundle and its content address",
    )
    p_official_verify.add_argument("bundle")

    p_public_pdb_download = sub.add_parser(
        "windows-public-pdb-download",
        help="download the PE-keyed Microsoft public PDB with a stripped-identity receipt",
    )
    p_public_pdb_download.add_argument("binary", help="Windows PE carrying RSDS CodeView")
    p_public_pdb_download.add_argument("store_root")
    p_public_pdb_download.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024 * 1024)

    p_public_pdb_verify = sub.add_parser(
        "windows-public-pdb-verify",
        help="verify a Microsoft public-PDB receipt against the exact PE",
    )
    p_public_pdb_verify.add_argument("binary")
    p_public_pdb_verify.add_argument("bundle")

    p_authenticity_verify = sub.add_parser(
        "windows-authenticity-verify",
        help="verify a Windows-native signature observation against retained bytes",
    )
    p_authenticity_verify.add_argument("artifact")
    p_authenticity_verify.add_argument("receipt")

    p_trust_verify = sub.add_parser(
        "windows-trust-verify",
        help="verify a SignTool policy receipt against retained inputs and root policy",
    )
    p_trust_verify.add_argument("artifact")
    p_trust_verify.add_argument("receipt")
    p_trust_verify.add_argument("root_policy")
    p_trust_verify.add_argument("signtool")
    p_trust_verify.add_argument("allowed_signers")
    p_trust_verify.add_argument("--catalog")

    p_pair_plan_verify = sub.add_parser(
        "windows-pair-plan-verify",
        help="verify a hash-bound Windows candidate/control pair plan",
    )
    p_pair_plan_verify.add_argument("plan")

    p_byo_corpus_verify = sub.add_parser(
        "windows-byo-corpus-verify",
        help="verify signed declared-blinded Windows BYO corpus commitments",
    )
    p_byo_corpus_verify.add_argument("manifest")

    p_servicing_verify = sub.add_parser(
        "windows-servicing-verify",
        help="verify a signed servicing rerun against a frozen pair plan",
    )
    p_servicing_verify.add_argument("plan")
    p_servicing_verify.add_argument("artifact")
    p_servicing_verify.add_argument("receipt")
    p_servicing_verify.add_argument("allowed_signers")

    p_scope_authorize = sub.add_parser(
        "windows-authorize-scope",
        help="operator-sign a Windows scope v2 template using the env-only signing key",
    )
    p_scope_authorize.add_argument("template")
    p_scope_authorize.add_argument("output")

    p_grant_authorize = sub.add_parser(
        "hyperv-authorize-execution",
        help="operator-sign a Hyper-V grant v2 template using the env-only signing key",
    )
    p_grant_authorize.add_argument("template")
    p_grant_authorize.add_argument("output")

    p_token_grant_authorize = sub.add_parser(
        "windows-token-authorize-execution",
        help="sign an exact campaign-bound Windows token execution grant",
    )
    p_token_grant_authorize.add_argument("campaign")
    p_token_grant_authorize.add_argument("template")
    p_token_grant_authorize.add_argument("output")
    p_token_grant_authorize.add_argument("--scope-manifest", required=True)

    p_token_accept = sub.add_parser(
        "windows-token-accept-worker",
        help="sign an exact authority-bound Windows token worker acceptance",
    )
    p_token_accept.add_argument("campaign")
    p_token_accept.add_argument("template")
    p_token_accept.add_argument("output")
    p_token_accept.add_argument("--scope-manifest", required=True)
    p_token_accept.add_argument("--execution-grant", required=True)

    p_variant_eval = sub.add_parser(
        "windows-variant-eval",
        help="evaluate a Windows variant campaign against hashable labels",
    )
    p_variant_eval.add_argument("manifest")
    p_variant_eval.add_argument("labels")

    p_browser = sub.add_parser(
        "browser-campaign",
        help="validate or run an authorized component campaign on a dedicated remote worker",
    )
    p_browser.add_argument("manifest", help="browser campaign JSON manifest")
    p_browser.add_argument(
        "--dry-run", action="store_true", help="validate and print the execution record only"
    )
    p_browser.add_argument("--output", default=None, help="write JSON evidence instead of stdout")

    args = parser.parse_args(argv)

    if args.cmd == "research-feedback-import":
        from .research_feedback import import_feedback

        try:
            feedback_receipt = import_feedback(
                projection_path=args.projection,
                bundle_path=args.bundle,
                output_root=args.output_root,
                ledger_path=args.ledger,
            )
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(feedback_receipt.to_dict(), sort_keys=True))
        return 0
    if args.cmd == "scout":
        from .scout_cli import run_scout

        return run_scout(args)

    if args.cmd == "scan":
        from .api import ScanOptions, format_result
        from .api import scan as api_scan

        if (rc := _require_explicit_backend(args.backend)) is not None:
            return rc
        opts = ScanOptions(
            bug_class=args.bug_class, backend=args.backend, llm=args.llm, model=args.model
        )
        if args.cloud:
            from . import cloud_sink

            config = cloud_sink.build_config(
                sink=args.sink, scan_id=args.scan_id, timeout_ms=args.timeout
            )
            if config is None:
                print(
                    "error: --cloud requires a sink URL and scan id "
                    "(--sink/--scan-id flags or PWNKIT_CLOUD_SINK/PWNKIT_CLOUD_SCAN_ID env)",
                    file=sys.stderr,
                )
                return 2
            return cloud_sink.run_cloud_scan(args.binary, config, opts=opts)
        scan_result = api_scan(args.binary, opts)
        print(format_result(scan_result, args.format))
        return 0

    if args.cmd == "fleet":
        return _cmd_fleet(args)

    if args.cmd == "windows-replay":
        from .windows_campaign import (
            DifferentialEvidence,
            EvidenceRow,
            ReplayEvidence,
            replay_corpus,
            replay_differential,
            write_evidence,
        )
        from .windows_oracle import WindowsWorker

        scope_mode = "LAB_ONLY"
        scope_program = ""
        scope_digest = ""
        scope = None
        try:
            if args.scope_manifest:
                from .windows_scope import load_scope

                scope, scope_digest = load_scope(args.scope_manifest, require_authorized=True)
                if args.host and args.host != scope.worker:
                    raise ValueError(
                        f"--host {args.host!r} does not match scope worker {scope.worker!r}"
                    )
                host = scope.worker
                scope_mode = "BOUNTY_SCOPE"
                scope_program = scope.program
            else:
                host = args.host
            worker = (
                WindowsWorker(host, authorization=scope)
                if host and scope is not None
                else WindowsWorker(host, lab_only=True)
                if host
                else None
            )
            rows: Sequence[EvidenceRow]
            if args.control_binary:
                rows = replay_differential(
                    args.binary,
                    args.control_binary,
                    args.corpus,
                    worker=worker,
                    timeout=args.timeout,
                    oracle=args.oracle,
                    scope_mode=scope_mode,
                    scope_program=scope_program,
                    scope_manifest_sha256=scope_digest,
                )
            else:
                rows = replay_corpus(
                    args.binary,
                    args.corpus,
                    worker=worker,
                    timeout=args.timeout,
                    oracle=args.oracle,
                    scope_mode=scope_mode,
                    scope_program=scope_program,
                    scope_manifest_sha256=scope_digest,
                )
            if scope is not None:
                from .windows_scope import verify_evidence_builds

                builds: list[str] = []
                for row in rows:
                    if isinstance(row, ReplayEvidence):
                        builds.append(row.build_lab_ex)
                    elif isinstance(row, DifferentialEvidence):
                        builds.extend((row.target.build_lab_ex, row.control.build_lab_ex))
                verify_evidence_builds(scope, builds)
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if args.output:
            from pathlib import Path

            try:
                with Path(args.output).open("w", encoding="utf-8") as output:
                    write_evidence(rows, output, args.format)
            except OSError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
        else:
            write_evidence(rows, sys.stdout, args.format)
        return (
            1
            if any(
                row.to_dict().get("classification", row.to_dict().get("status")) == "ERROR"
                for row in rows
            )
            else 0
        )

    if args.cmd == "windows-official-download":
        from .windows_provenance import download_official_artifact

        try:
            download_receipt = download_official_artifact(
                args.url,
                args.store_root,
                kind=args.kind,
                max_bytes=args.max_bytes,
            )
            print(json.dumps(download_receipt.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-official-verify":
        from .windows_provenance import verify_official_download_receipt

        try:
            verified_receipt = verify_official_download_receipt(args.bundle)
            print(json.dumps(verified_receipt.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-public-pdb-download":
        from .windows_public_pdb import download_public_pdb

        try:
            public_pdb = download_public_pdb(args.binary, args.store_root, max_bytes=args.max_bytes)
            print(json.dumps(public_pdb.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-public-pdb-verify":
        from .windows_public_pdb import verify_public_pdb_receipt

        try:
            public_pdb = verify_public_pdb_receipt(args.binary, args.bundle)
            print(json.dumps(public_pdb.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-authenticity-verify":
        from .windows_authenticity import verify_windows_authenticity_receipt

        try:
            authenticity_receipt = verify_windows_authenticity_receipt(args.artifact, args.receipt)
            print(json.dumps(authenticity_receipt.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-trust-verify":
        from .windows_trust import verify_windows_trust_receipt

        try:
            trust_receipt = verify_windows_trust_receipt(
                args.artifact,
                args.receipt,
                args.root_policy,
                args.signtool,
                args.allowed_signers,
                catalog_path=args.catalog,
            )
            print(json.dumps(trust_receipt.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-pair-plan-verify":
        from .windows_pair_plan import verify_windows_pair_plan

        try:
            pair_plan = verify_windows_pair_plan(args.plan)
            print(json.dumps(pair_plan.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-byo-corpus-verify":
        from .windows_byo_corpus import verify_windows_byo_corpus_manifest

        try:
            manifest = verify_windows_byo_corpus_manifest(args.manifest)
            print(json.dumps(manifest.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-servicing-verify":
        from .windows_servicing import verify_windows_servicing_receipt

        try:
            servicing_receipt = verify_windows_servicing_receipt(
                args.plan,
                args.artifact,
                args.receipt,
                args.allowed_signers,
            )
            print(json.dumps(servicing_receipt.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd in {"windows-authorize-scope", "hyperv-authorize-execution"}:
        from .windows_authorization import issue_windows_authorization

        try:
            issued = issue_windows_authorization(
                args.template,
                args.output,
                kind="scope" if args.cmd == "windows-authorize-scope" else "grant",
            )
            print(json.dumps(issued.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd in {
        "windows-token-authorize-execution",
        "windows-token-accept-worker",
    }:
        from .windows_token_authorization import (
            issue_windows_token_execution_grant,
            issue_windows_token_worker_acceptance,
        )

        try:
            if args.cmd == "windows-token-authorize-execution":
                token_issued = issue_windows_token_execution_grant(
                    args.campaign,
                    args.scope_manifest,
                    args.template,
                    args.output,
                )
            else:
                token_issued = issue_windows_token_worker_acceptance(
                    args.campaign,
                    args.scope_manifest,
                    args.execution_grant,
                    args.template,
                    args.output,
                )
            print(json.dumps(token_issued.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-analysis-bundle":
        from .windows_variant import produce_windows_analysis_bundle

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            bundle_result = produce_windows_analysis_bundle(
                args.binary,
                args.pdb,
                args.output_dir,
                ghidra_home=ghidra_home,
            )
            print(json.dumps(bundle_result, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-ioctl-analysis-bundle":
        from .windows_variant import produce_windows_ioctl_analysis_bundle

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            bundle_result = produce_windows_ioctl_analysis_bundle(
                args.binary,
                args.pdb,
                args.output_dir,
                ghidra_home=ghidra_home,
            )
            print(json.dumps(bundle_result, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-public-ioctl-analysis-bundle":
        from .windows_variant import produce_windows_public_ioctl_analysis_bundle

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            bundle_result = produce_windows_public_ioctl_analysis_bundle(
                args.binary,
                args.public_pdb_bundle,
                args.output_dir,
                ghidra_home=ghidra_home,
            )
            print(json.dumps(bundle_result, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-ioctl-surface-inventory":
        from .windows_ioctl_surface_inventory import (
            produce_windows_ioctl_surface_inventory,
        )

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            inventory_result = produce_windows_ioctl_surface_inventory(
                args.binary,
                args.pdb,
                args.output_dir,
                ghidra_home=ghidra_home,
                public_pdb_bundle=args.public_pdb_bundle,
            )
            print(json.dumps(inventory_result, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-ioctl-surface-inventory-verify":
        from .windows_ioctl_surface_inventory import (
            verify_windows_ioctl_surface_inventory_bundle,
        )

        try:
            verified_inventory = verify_windows_ioctl_surface_inventory_bundle(args.bundle)
            print(json.dumps(verified_inventory, indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-driver-entry-bridge":
        from .windows_driver_entry_bridge import produce_windows_driver_entry_bridge

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            bridge_produce_result = produce_windows_driver_entry_bridge(
                args.binary,
                args.pdb,
                args.output_dir,
                ghidra_home=ghidra_home,
                public_pdb_bundle=args.public_pdb_bundle,
            )
            print(json.dumps(bridge_produce_result, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-driver-entry-bridge-v3":
        from .windows_driver_entry_bridge import produce_windows_driver_entry_bridge_v3

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            bridge_v3_result = produce_windows_driver_entry_bridge_v3(
                args.binary,
                args.pdb,
                args.output_dir,
                ghidra_home=ghidra_home,
                abi_authority_dir=args.abi_authority_dir,
                public_pdb_bundle=args.public_pdb_bundle,
            )
            print(json.dumps(bridge_v3_result, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-driver-entry-bridge-verify":
        from .windows_driver_entry_bridge import verify_windows_driver_entry_bridge_bundle

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            bridge_verify_result = verify_windows_driver_entry_bridge_bundle(
                args.bundle, ghidra_home=ghidra_home
            )
            print(json.dumps(bridge_verify_result, indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-driver-registration":
        from .windows_driver_registration import produce_windows_driver_registration

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            registration_result = produce_windows_driver_registration(
                args.entry_bridge_bundle,
                args.wdm_projection,
                args.output_dir,
                ghidra_home=ghidra_home,
            )
            print(json.dumps(registration_result, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-driver-registration-verify":
        from .windows_driver_registration import verify_windows_driver_registration_bundle

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            registration_verification = verify_windows_driver_registration_bundle(
                args.bundle, ghidra_home=ghidra_home
            )
            print(json.dumps(registration_verification, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-afd-selector":
        from .windows_afd_selector import produce_windows_afd_selector

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            selector_result = produce_windows_afd_selector(
                args.registration_bundle,
                args.output_dir,
                ghidra_home=ghidra_home,
                dispatch_abi_authority_dir=args.dispatch_abi_authority_dir,
            )
            print(json.dumps(selector_result, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-afd-selector-verify":
        from .windows_afd_selector import verify_windows_afd_selector_bundle

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            selector_verification = verify_windows_afd_selector_bundle(
                args.bundle, ghidra_home=ghidra_home
            )
            print(json.dumps(selector_verification, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-afd-hypotheses":
        from .windows_afd_hypotheses import produce_windows_afd_hypotheses

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            hypotheses_result = produce_windows_afd_hypotheses(
                args.side_a_selector,
                args.side_b_selector,
                args.output_dir,
                ghidra_home=ghidra_home,
            )
            print(json.dumps(hypotheses_result, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-afd-hypotheses-verify":
        from .windows_afd_hypotheses import verify_windows_afd_hypotheses_bundle

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            hypotheses_verification = verify_windows_afd_hypotheses_bundle(
                args.bundle, ghidra_home=ghidra_home
            )
            print(json.dumps(hypotheses_verification, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-afd-handler-native-evidence":
        from .windows_afd_handler_semantics import produce_windows_afd_handler_semantics

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            native_evidence_result = produce_windows_afd_handler_semantics(
                args.hypotheses_bundle, args.output_dir, ghidra_home=ghidra_home
            )
            print(json.dumps(native_evidence_result, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-afd-handler-native-evidence-verify":
        from .windows_afd_handler_semantics import (
            verify_windows_afd_handler_semantics_bundle,
        )

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            native_evidence_verification = verify_windows_afd_handler_semantics_bundle(
                args.bundle, ghidra_home=ghidra_home
            )
            print(json.dumps(native_evidence_verification, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-afd-handler-cfg-ssa":
        from .windows_afd_handler_cfg_ssa_bundle import produce_windows_afd_handler_cfg_ssa

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            cfg_ssa_result = produce_windows_afd_handler_cfg_ssa(
                args.native_bundle, args.output_dir, ghidra_home=ghidra_home
            )
            print(json.dumps(cfg_ssa_result, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-afd-handler-cfg-ssa-verify":
        from .windows_afd_handler_cfg_ssa_bundle import (
            verify_windows_afd_handler_cfg_ssa_bundle,
        )

        try:
            ghidra_home = (
                args.ghidra_home
                or os.environ.get("GHIDRA_INSTALL_DIR")
                or os.environ.get("GHIDRA_HOME")
            )
            if not ghidra_home:
                raise ValueError("--ghidra-home or GHIDRA_INSTALL_DIR/GHIDRA_HOME is required")
            cfg_ssa_verification = verify_windows_afd_handler_cfg_ssa_bundle(
                args.bundle, ghidra_home=ghidra_home
            )
            print(json.dumps(cfg_ssa_verification, indent=2, sort_keys=True))
            return 0
        except (ImportError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-variant-rank":
        from pathlib import Path

        from .windows_variant import rank_windows_variants

        try:
            rendered = json.dumps(rank_windows_variants(args.manifest), indent=2, sort_keys=True)
            if args.output:
                output_path = Path(args.output)
                with output_path.open("x", encoding="utf-8") as output_file:
                    output_file.write(rendered + "\n")
            else:
                print(rendered)
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-ioctl-plan":
        from .windows_ioctl_boundary import plan_windows_ioctl_boundary

        try:
            rendered = json.dumps(
                plan_windows_ioctl_boundary(args.manifest), indent=2, sort_keys=True
            )
            if args.output:
                output_path = pathlib.Path(args.output)
                with output_path.open("x", encoding="utf-8") as output_file:
                    output_file.write(rendered + "\n")
            else:
                print(rendered)
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-ioctl-rank":
        from .windows_ioctl_rank import rank_windows_ioctl_static

        try:
            rendered = json.dumps(
                rank_windows_ioctl_static(args.campaign), indent=2, sort_keys=True
            )
            if args.output:
                output_path = pathlib.Path(args.output)
                with output_path.open("x", encoding="utf-8") as output_file:
                    output_file.write(rendered + "\n")
            else:
                print(rendered)
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-ioctl-real-rank":
        from .windows_ioctl_real_rank import rank_windows_ioctl_real_static

        try:
            rendered = json.dumps(
                rank_windows_ioctl_real_static(args.campaign), indent=2, sort_keys=True
            )
            if args.output:
                output_path = pathlib.Path(args.output)
                with output_path.open("x", encoding="utf-8") as output_file:
                    output_file.write(rendered + "\n")
            else:
                print(rendered)
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-ioctl-site-universe":
        from .windows_ioctl_site_universe import (
            build_windows_ioctl_site_universe,
            canonical_site_universe_bytes,
        )

        try:
            rendered_bytes = canonical_site_universe_bytes(
                build_windows_ioctl_site_universe(args.request)
            )
            if args.output:
                output_path = pathlib.Path(args.output)
                with output_path.open("xb") as binary_output_file:
                    binary_output_file.write(rendered_bytes)
            else:
                sys.stdout.buffer.write(rendered_bytes)
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-ioctl-site-universe-verify":
        from .windows_ioctl_site_universe import verify_windows_ioctl_site_universe

        try:
            print(
                json.dumps(
                    verify_windows_ioctl_site_universe(args.manifest),
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-ioctl-real-rank-publish":
        from .windows_ioctl_rank_publisher import publish_windows_ioctl_rank_result

        try:
            print(
                json.dumps(
                    publish_windows_ioctl_rank_result(args.campaign, args.bundle_name),
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-ioctl-real-eval":
        from .windows_ioctl_real_eval import evaluate_windows_ioctl_real_static

        try:
            rendered = json.dumps(
                evaluate_windows_ioctl_real_static(
                    args.rank_output, args.rank_receipt, args.labels
                ),
                indent=2,
                sort_keys=True,
            )
            if args.output:
                output_path = pathlib.Path(args.output)
                with output_path.open("x", encoding="utf-8") as output_file:
                    output_file.write(rendered + "\n")
            else:
                print(rendered)
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-device-open-verify":
        from .windows_device_open_receipt import load_windows_device_open_receipt

        try:
            receipt, receipt_sha256 = load_windows_device_open_receipt(
                args.receipt,
                allowed_signers=args.allowed_signers,
            )
            print(
                json.dumps(
                    {
                        "status": "SIGNATURE_VERIFIED",
                        "evidence_class": receipt.evidence_class,
                        "receipt_sha256": receipt_sha256,
                        "signed_by": receipt.signed_by,
                        "producer_authority": receipt.producer_authority,
                        "producer_authority_assertion_signed": True,
                        "producer_authority_verified": False,
                        "system_key_custody_verified": False,
                        "external_binding_verified": False,
                        "device_io_control_call_count": 0,
                        "device_handle_read_call_count": 0,
                        "device_handle_write_call_count": 0,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-variant-eval":
        from .windows_variant import evaluate_windows_variants

        try:
            eval_report = evaluate_windows_variants(args.manifest, args.labels)
            print(
                json.dumps(
                    eval_report,
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if eval_report["passed"] is True else 1
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-token-capture-verify":
        from .windows_token_capture import load_windows_token_capture

        try:
            token_capture, token_capture_sha256 = load_windows_token_capture(
                args.capture, require_verified=True
            )
            print(
                json.dumps(
                    {
                        "status": "SIGNATURE_VERIFIED",
                        "authority_binding_verified": False,
                        "capture_sha256": token_capture_sha256,
                        "campaign_sha256": token_capture.campaign_sha256,
                        "case": token_capture.case,
                        "trial": token_capture.trial,
                        "signed_by": token_capture.signed_by,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-token-pack-build":
        from .windows_token_pack import build_windows_token_pack

        try:
            built = build_windows_token_pack(
                args.output_dir,
                campaign_path=args.campaign,
                scope_manifest_path=args.scope_manifest,
                execution_grant_path=args.execution_grant,
                worker_acceptance_path=args.worker_acceptance,
                aggregate_receipt_path=args.aggregate_receipt,
                capture_paths=args.capture,
                scope_allowed_signers_path=args.scope_allowed_signers,
                execution_grant_allowed_signers_path=(args.execution_grant_allowed_signers),
                worker_acceptance_allowed_signers_path=(args.worker_acceptance_allowed_signers),
                capture_allowed_signers_path=args.capture_allowed_signers,
                aggregate_allowed_signers_path=args.aggregate_allowed_signers,
                run_id=args.run_id,
                job_nonce=args.job_nonce,
                zeroverse_runtime_digest=args.zeroverse_runtime_digest,
                pack_signer_identity=args.pack_signer_identity,
                pack_signing_key=args.pack_signing_key,
            )
            print(
                json.dumps(
                    built.to_dict(),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            )
            return 0
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-token-pack-verify":
        from .windows_token_pack import verify_windows_token_pack

        try:
            verification = verify_windows_token_pack(
                args.envelope,
                blob_dir=args.blob_dir,
                acceptance_policy_path=args.acceptance_policy,
                expected_context_path=args.expected_context,
                pack_signer_policy_path=args.pack_signer_policy,
            )
            print(json.dumps(verification.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-token-bounty-classify":
        from .windows_bounty_eligibility import (
            LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE,
            classify_windows_bounty_evidence,
            load_windows_local_attack_scenario_evidence,
        )
        from .windows_token_pack import verify_windows_token_pack

        try:
            if (
                args.category == LOCAL_ATTACK_SCENARIO_SANDBOX_ESCAPE
                and args.local_scenario_evidence is None
            ):
                raise ValueError("local Attack Scenario requires signed LPAC launch evidence")
            verification = verify_windows_token_pack(
                args.envelope,
                blob_dir=args.blob_dir,
                acceptance_policy_path=args.acceptance_policy,
                expected_context_path=args.expected_context,
                pack_signer_policy_path=args.pack_signer_policy,
            )
            local_evidence = (
                load_windows_local_attack_scenario_evidence(
                    args.local_scenario_evidence,
                )
                if args.local_scenario_evidence is not None
                else None
            )
            classification = classify_windows_bounty_evidence(
                verification,
                category=args.category,
                local_evidence=local_evidence,
            )
            print(json.dumps(classification.to_dict(), indent=2, sort_keys=True))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd in {
        "windows-lpe-paired-closure-verify",
        "windows-lpe-paired-closure-verify-cas",
    }:
        from .windows_lpe_paired_closure import (
            WindowsServicingInputs,
            WindowsTokenPackInputs,
            verify_windows_lpe_paired_closure,
            verify_windows_lpe_paired_closure_cas,
        )

        def servicing_inputs(side: str) -> WindowsServicingInputs:
            return WindowsServicingInputs(
                artifact_path=pathlib.Path(getattr(args, f"{side}_artifact")),
                receipt_path=pathlib.Path(getattr(args, f"{side}_servicing_receipt")),
                allowed_signers_path=pathlib.Path(
                    getattr(args, f"{side}_servicing_allowed_signers")
                ),
            )

        def token_pack_inputs(side: str) -> WindowsTokenPackInputs:
            return WindowsTokenPackInputs(
                envelope_path=pathlib.Path(getattr(args, f"{side}_envelope")),
                blob_dir=pathlib.Path(getattr(args, f"{side}_blob_dir")),
                acceptance_policy_path=pathlib.Path(getattr(args, f"{side}_acceptance_policy")),
                expected_context_path=pathlib.Path(getattr(args, f"{side}_expected_context")),
                pack_signer_policy_path=pathlib.Path(getattr(args, f"{side}_pack_signer_policy")),
            )

        try:
            verifier = (
                verify_windows_lpe_paired_closure_cas
                if args.cmd.endswith("-cas")
                else verify_windows_lpe_paired_closure
            )
            extra = (
                {"opaque_content_path": args.opaque_content} if args.cmd.endswith("-cas") else {}
            )
            closure = verifier(
                args.pair_plan,
                **extra,
                experiment_path=args.experiment,
                experiment_allowed_signers_path=args.experiment_allowed_signers,
                candidate_servicing=servicing_inputs("candidate"),
                candidate_token_pack=token_pack_inputs("candidate"),
                fixed_servicing=servicing_inputs("fixed"),
                fixed_token_pack=token_pack_inputs("fixed"),
            )
            print(
                json.dumps(
                    closure.to_dict(),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            )
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-lpe-worker-readiness":
        from .windows_lpe_worker_readiness import verify_windows_lpe_worker_readiness

        try:
            plan = verify_windows_lpe_worker_readiness(
                campaign_path=args.campaign,
                scope_path=args.scope_manifest,
                execution_grant_path=args.execution_grant,
                worker_acceptance_path=args.worker_acceptance,
                readiness_path=args.readiness,
                scope_allowed_signers=args.scope_allowed_signers,
                grant_allowed_signers=args.execution_grant_allowed_signers,
                acceptance_allowed_signers=args.worker_acceptance_allowed_signers,
                readiness_allowed_signers=args.readiness_allowed_signers,
            )
            print(
                json.dumps(
                    plan.to_dict(),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            )
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-token-evidence-verify":
        from .windows_token_evidence import load_windows_token_evidence_receipt

        try:
            token_receipt, token_receipt_sha256 = load_windows_token_evidence_receipt(args.receipt)
            print(
                json.dumps(
                    {
                        "status": "VERIFIED",
                        "receipt_sha256": token_receipt_sha256,
                        "signed_by": token_receipt["signed_by"],
                        "campaign_sha256": token_receipt["campaign_sha256"],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd in {
        "windows-token-validate",
        "windows-token-aggregate",
        "windows-token-aggregate-neutral",
    }:
        from .windows_scope import load_scope
        from .windows_token_runner import (
            load_windows_token_campaign,
            load_windows_token_execution_grant,
            load_windows_token_worker_acceptance,
        )

        try:
            token_campaign, token_campaign_sha256 = load_windows_token_campaign(args.campaign)
            token_scope, token_scope_sha256 = load_scope(
                args.scope_manifest,
                require_authorized=True,
            )
            token_grant, token_grant_sha256 = load_windows_token_execution_grant(
                args.execution_grant,
                require_authorized=True,
            )
            token_acceptance, token_acceptance_sha256 = load_windows_token_worker_acceptance(
                args.worker_acceptance,
                require_authorized=True,
            )
            token_acceptance.require_binding(
                token_campaign,
                token_campaign_sha256,
                token_scope,
                token_scope_sha256,
                token_grant,
                token_grant_sha256,
                token_acceptance_sha256,
            )
            token_payload: dict[str, object] = {
                "status": "VALIDATED",
                "campaign_sha256": token_campaign_sha256,
                "scope_manifest_sha256": token_scope_sha256,
                "execution_grant_sha256": token_grant_sha256,
                "worker_acceptance_sha256": token_acceptance_sha256,
                "execution": False,
                "weaponization": False,
                "auto_disclosure": False,
                "human_report_gate": True,
            }
            if args.cmd in {
                "windows-token-aggregate",
                "windows-token-aggregate-neutral",
            }:
                from .windows_token_capture import (
                    ExclusiveFileNonceLedger,
                    load_windows_token_capture,
                )
                from .windows_token_evidence import (
                    aggregate_windows_token_evidence,
                    aggregate_windows_token_observation,
                )

                captures = [
                    load_windows_token_capture(
                        path,
                        require_verified=True,
                    )[0]
                    for path in args.capture
                ]
                aggregate_args = (
                    captures,
                    token_campaign,
                    token_campaign_sha256,
                    token_scope,
                    token_scope_sha256,
                    token_grant,
                    token_grant_sha256,
                    token_acceptance,
                    token_acceptance_sha256,
                    ExclusiveFileNonceLedger(args.nonce_ledger),
                )
                token_evidence = (
                    aggregate_windows_token_observation(*aggregate_args).evidence
                    if args.cmd == "windows-token-aggregate-neutral"
                    else aggregate_windows_token_evidence(*aggregate_args)
                )
                token_payload = token_evidence.signed_receipt(
                    signed_by=args.signed_by,
                    signing_key=args.signing_key,
                )
            rendered = json.dumps(token_payload, indent=2, sort_keys=True) + "\n"
            if getattr(args, "output", None):
                with Path(args.output).open("x", encoding="utf-8") as output:
                    output.write(rendered)
            else:
                print(rendered, end="")
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "hyperv-accept-worker":
        from datetime import timedelta

        from .hyperv_acceptance import issue_worker_acceptance
        from .hyperv_prover import load_execution_grant
        from .hyperv_prover import load_manifest as load_hyperv_manifest
        from .hyperv_transport import SshHyperVControlPlane
        from .windows_scope import load_scope

        try:
            if not args.execute:
                raise ValueError("hyperv-accept-worker requires --execute for live validation")
            hyperv_campaign, campaign_digest = load_hyperv_manifest(args.manifest)
            scope, scope_digest = load_scope(args.scope_manifest, require_authorized=True)
            execution_grant, grant_digest = load_execution_grant(
                args.execution_grant, require_authorized=True
            )
            receipt_path, receipt_digest = issue_worker_acceptance(
                hyperv_campaign,
                campaign_digest,
                scope,
                scope_digest,
                execution_grant,
                grant_digest,
                args.recovery_drill,
                args.output_dir,
                args.accepted_by,
                SshHyperVControlPlane(
                    scope,
                    execution_grant,
                    campaign_digest,
                    scope_digest,
                    acceptance_probe_only=True,
                ),
                ttl=timedelta(hours=args.ttl_hours),
            )
            print(
                json.dumps(
                    {
                        "status": "ACCEPTED",
                        "worker_acceptance_path": str(receipt_path.resolve()),
                        "worker_acceptance_sha256": receipt_digest,
                        "weaponization": False,
                        "auto_disclosure": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "hyperv-prove":
        from .hyperv_prover import (
            load_execution_grant,
            prove_hyperv,
            validate_campaign_scope,
            write_evidence_bundle,
        )
        from .hyperv_prover import (
            load_manifest as load_hyperv_manifest,
        )
        from .windows_scope import load_scope

        try:
            hyperv_campaign, campaign_digest = load_hyperv_manifest(args.manifest)
            scope, scope_digest = load_scope(args.scope_manifest)
            validate_campaign_scope(hyperv_campaign, scope)
            if args.execute:
                if not args.execution_grant:
                    raise ValueError("--execute requires --execution-grant")
                scope.require_signed_authorization()
                execution_grant, grant_digest = load_execution_grant(
                    args.execution_grant, require_authorized=True
                )
                execution_grant.validate_binding(hyperv_campaign, campaign_digest, scope_digest)
                if not args.artifact_dir:
                    raise ValueError("--execute requires --artifact-dir for evidence retention")
                if not args.worker_acceptance:
                    raise ValueError("--execute requires --worker-acceptance")
                from .hyperv_acceptance import RECOVERY_ARTIFACTS, load_worker_acceptance

                worker_acceptance, acceptance_digest = load_worker_acceptance(
                    args.worker_acceptance
                )
                worker_acceptance.validate_binding(
                    hyperv_campaign,
                    campaign_digest,
                    scope,
                    scope_digest,
                    execution_grant,
                    grant_digest,
                )
                authorization_sources = (
                    (args.manifest, "campaign.json", campaign_digest),
                    (args.scope_manifest, "scope.json", scope_digest),
                    (args.execution_grant, "execution-grant.json", grant_digest),
                )
                for source_name, _, _ in authorization_sources:
                    source_path = Path(source_name)
                    if source_path.is_symlink() or not source_path.is_file():
                        raise ValueError(
                            f"authorization sidecar is missing or unsafe: {source_name}"
                        )
                artifact_dir = Path(args.artifact_dir).resolve()
                artifact_dir.mkdir(parents=True, exist_ok=True)
                retained_authorization: dict[str, str] = {}
                for source_name, destination_name, digest in authorization_sources:
                    _retain_verified_sidecar(
                        Path(source_name), artifact_dir / destination_name, digest
                    )
                    retained_authorization[destination_name] = digest
                acceptance_sidecar = artifact_dir / "worker-acceptance.json"
                drill_sidecar = artifact_dir / worker_acceptance.receipt.recovery_drill_path
                with acceptance_sidecar.open("xb") as acceptance_output:
                    acceptance_output.write(worker_acceptance.receipt_bytes)
                with drill_sidecar.open("xb") as drill_output:
                    drill_output.write(worker_acceptance.drill_bytes)
                acceptance_root = Path(args.worker_acceptance).resolve().parent
                for digest_field, filename in RECOVERY_ARTIFACTS.items():
                    _retain_verified_sidecar(
                        acceptance_root / filename,
                        artifact_dir / filename,
                        getattr(worker_acceptance.drill, digest_field),
                    )
                from .hyperv_transport import (
                    HyperVTransportWorker,
                    SshHyperVControlPlane,
                )

                hyperv_evidence = prove_hyperv(
                    hyperv_campaign,
                    campaign_digest,
                    scope,
                    scope_digest,
                    worker=HyperVTransportWorker(
                        SshHyperVControlPlane(
                            scope,
                            execution_grant,
                            campaign_digest,
                            scope_digest,
                            worker_acceptance,
                            grant_digest,
                        ),
                        execution_grant,
                        worker_acceptance,
                        scope,
                        campaign_digest,
                        scope_digest,
                        grant_digest,
                        artifact_dir=Path(args.artifact_dir),
                    ),
                    execution_grant=execution_grant,
                    worker_acceptance=worker_acceptance,
                    execution_grant_sha256=grant_digest,
                )
                receipt_path = Path(args.output) if args.output else artifact_dir / "evidence.json"
                hyperv_payload, _ = write_evidence_bundle(
                    hyperv_evidence,
                    artifact_dir,
                    receipt_path,
                    extra={
                        "execution_grant_sha256": grant_digest,
                        "execution_grant_path": "execution-grant.json",
                        "execution_grant_nonce": execution_grant.nonce,
                        "scope_manifest_path": "scope.json",
                        "campaign_manifest_path": "campaign.json",
                        "retained_authorization_sha256": retained_authorization,
                        "worker_acceptance_sha256": acceptance_digest,
                        "worker_acceptance_nonce": worker_acceptance.nonce,
                        "worker_acceptance_path": acceptance_sidecar.name,
                        "worker_recovery_drill_sha256": (
                            worker_acceptance.receipt.recovery_drill_sha256
                        ),
                        "worker_recovery_drill_path": drill_sidecar.name,
                        "authorized_by": execution_grant.authorized_by,
                        "authorization_eligible": True,
                        "claim_eligible": hyperv_evidence.status == "REPRODUCED",
                        "weaponization": False,
                        "auto_disclosure": False,
                    },
                )
                returncode = 1 if hyperv_evidence.status == "INCONCLUSIVE" else 0
            else:
                if args.execution_grant:
                    execution_grant, grant_digest = load_execution_grant(args.execution_grant)
                    execution_grant.validate_binding(hyperv_campaign, campaign_digest, scope_digest)
                if args.worker_acceptance:
                    if not args.execution_grant:
                        raise ValueError(
                            "--worker-acceptance requires --execution-grant for binding"
                        )
                    from .hyperv_acceptance import load_worker_acceptance

                    worker_acceptance, acceptance_digest = load_worker_acceptance(
                        args.worker_acceptance
                    )
                    worker_acceptance.validate_binding(
                        hyperv_campaign,
                        campaign_digest,
                        scope,
                        scope_digest,
                        execution_grant,
                        grant_digest,
                    )
                hyperv_payload = {
                    "status": "VALIDATED",
                    "execution_required": True,
                    "execution_grant_required": True,
                    "worker_acceptance_required": True,
                    "manifest_sha256": campaign_digest,
                    "scope_manifest_sha256": scope_digest,
                    "campaign": hyperv_campaign.to_dict(),
                }
                if args.execution_grant:
                    hyperv_payload["execution_grant_sha256"] = grant_digest
                if args.worker_acceptance:
                    hyperv_payload["worker_acceptance_sha256"] = acceptance_digest
                returncode = 0
            rendered = json.dumps(hyperv_payload, indent=2, sort_keys=True)
            if args.output and not args.execute:
                Path(args.output).write_text(rendered + "\n", encoding="utf-8")
            elif not args.output:
                print(rendered)
            return returncode
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "windows-report":
        from pathlib import Path

        from .reporting import load_ndjson, windows_report

        try:
            report = windows_report(load_ndjson(args.evidence), title=args.title)
            Path(args.output).write_text(report, encoding="utf-8")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.cmd == "windows-discover":
        from .windows_discovery import _write_private_json, discover_windows_candidates

        discovery_result = discover_windows_candidates(args.campaign)
        if args.output:
            _write_private_json(pathlib.Path(args.output), discovery_result)
        else:
            sys.stdout.write(json.dumps(discovery_result, indent=2, sort_keys=True) + "\n")
        return 0

    if args.cmd == "browser-campaign":
        from pathlib import Path

        from .browser_campaign import execute_campaign, load_manifest

        try:
            campaign, digest = load_manifest(args.manifest)
            if args.dry_run:
                payload: dict[str, object] = {
                    "status": "VALIDATED",
                    "manifest_sha256": digest,
                    "campaign": campaign.to_dict(),
                }
                returncode = 0
            else:
                evidence = execute_campaign(campaign, digest)
                payload = evidence.to_dict()
                returncode = 0 if evidence.status == "CLEAN" else 1
            rendered = json.dumps(payload, indent=2)
            if args.output:
                Path(args.output).write_text(rendered + "\n", encoding="utf-8")
            else:
                print(rendered)
            return returncode
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "triage":
        t = triage(args.binary)
        if args.json:
            from dataclasses import asdict

            print(json.dumps(asdict(t), indent=2))
        else:
            print(f"# {t.path}")
            print(t.summary())
            if t.stripped is not None:
                print(f"stripped={t.stripped}")
            for n in t.notes:
                print(f"note: {n}")
        return 0

    if args.cmd == "run":
        from .agent import LLM
        from .pipeline import PENDING_STAGES
        from .pipeline import run as run_pipeline

        # ``run`` takes its backend from $ZEROVERSE_BACKEND only; naming one there
        # is still a demand, so an unmet demand stops the run (#297).
        if (rc := _require_explicit_backend(None)) is not None:
            return rc
        llm: LLM | None = None  # None -> pipeline uses the deterministic MockLLM
        if args.llm != "mock" or args.model:
            from .llm.providers import build_llm

            prov = None if args.llm in ("mock", "auto") else args.llm
            llm = build_llm(provider=prov, model=args.model)
        result = run_pipeline(args.binary, bug_class=args.bug_class, llm=llm)
        if args.format != "text":
            from .serialize import FORMATS

            print(FORMATS[args.format](result))
            return 0
        print(f"# {result.triage.path}")
        print(result.triage.summary())
        print(f"stages run: {', '.join(result.stages_run)}")
        if result.findings:
            confirmed = sum(1 for tf in result.findings if tf.pov and tf.pov.reproduced)
            print(f"\n{len(result.findings)} finding(s), {confirmed} confirmed with a PoV:")
            for tf in result.findings:
                f, v = tf.finding, tf.verdict
                has_pov = bool(tf.pov and tf.pov.reproduced)
                mark = "CONFIRMED" if has_pov else ("REAL?" if v.is_real else "fp")
                print(
                    f"  [{mark}] {f.source} -> {f.sink} in {f.function} "
                    f"@ {hex(f.sink_addr)}  ({v.bug_class}, sev={v.severity})"
                )
                if tf.pov and tf.pov.reproduced:
                    trig = tf.pov.env or {"stdin": f"{len(tf.pov.input_bytes or b'')} bytes"}
                    print(f"      PoV: class={tf.pov.crash_class}  trigger={trig}")
                    if tf.pov.crash_trace:
                        print(f"      evidence: {tf.pov.crash_trace[:120]}")
        if result.note:
            print(f"note: {result.note}", file=sys.stderr)
        if PENDING_STAGES:
            print(
                f"stages pending (PoV confirmation): {', '.join(PENDING_STAGES)}", file=sys.stderr
            )
        return 0

    return 1


def _retain_verified_sidecar(source: Path, destination: Path, expected_sha256: str) -> None:
    """Copy one immutable sidecar and reject source-replacement races."""
    digest = hashlib.sha256()
    try:
        with source.open("rb") as input_file, destination.open("xb") as output:
            while chunk := input_file.read(1024 * 1024):
                digest.update(chunk)
                output.write(chunk)
        if digest.hexdigest() != expected_sha256:
            raise ValueError(f"retained sidecar SHA-256 mismatch: {source}")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def _cmd_fleet(args: argparse.Namespace) -> int:
    """#42 — build the seed, ingest the fleet, sweep, and print the economics."""
    import json

    from . import fleet

    if args.seed_reference:
        ref_bin, _, ref_fn = args.seed_reference.partition(":")
        if not ref_fn:
            print("error: --seed-reference must be BINARY:FUNCTION", file=sys.stderr)
            return 2
        seed = fleet.seed_from_reference(ref_bin, ref_fn)
    else:
        seed = fleet.seed_from_archetype(args.seed_archetype)
        if args.reference:
            ref_bin, _, ref_fn = args.reference.partition(":")
            dc = fleet.decompile_functions(ref_bin)
            if ref_fn in dc:
                seed = seed.with_reference(fleet.ReferenceShape.from_body(ref_fn, dc[ref_fn]))

    spec: str | list[str] = args.fleet.split(",") if "," in args.fleet else args.fleet
    members = fleet.ingest_fleet(spec)
    report = fleet.run_fleet(seed, members, confirm=not args.no_confirm, dataset_path=args.dataset)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    print(f"# fleet sweep — seed [{seed.archetype_id}]  route={seed.route}  cwe={seed.cwe}")
    print(report.economics)
    for m in report.members:
        print(f"\n## {m.member.name}  ({m.member.triage.fmt} {m.member.triage.arch})")
        if not m.confirmations:
            print("  no candidate variants")
        for c in m.confirmations:
            mark = "CONFIRMED" if c.confirmed else "hypothesis"
            print(
                f"  [{mark}] {c.candidate.function} -> {c.candidate.sink}  "
                f"sim={c.candidate.similarity}  via {c.candidate.detector}  oracle={c.oracle}"
            )
            povp = c.pov.pov_script if (c.pov and c.pov.pov_script) else ""
            if povp:
                print(f"      PoV: {povp}")
            elif c.note:
                print(f"      note: {c.note}")
    if args.dataset:
        print(
            f"\ncaptured {report.dataset_records_written} dataset record(s) -> {args.dataset}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
