from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from zeroverse import windows_variant as variant
from zeroverse.cli import main
from zeroverse.windows_ioctl_ghidra_export import VID_DRIVER_SHA256
from zeroverse.windows_variant import (
    _shape,
    evaluate_windows_variants,
    produce_windows_analysis_bundle,
    rank_windows_variants,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _export(path: Path, functions: dict[str, str]) -> None:
    insts = [
        {"id": index, "func": name, "addr": 0x1000 + index * 0x100, "kind": "OTHER"}
        for index, name in enumerate(functions, 1)
    ]
    path.write_text(
        json.dumps({"insts": insts, "meta": {"decompiled_c": functions}}),
        encoding="utf-8",
    )


def _artifact(root: Path, stem: str, functions: dict[str, str]) -> dict[str, str]:
    binary = root / f"{stem}.sys"
    export = root / f"{stem}.json"
    binary.write_bytes(f"MZ:{stem}".encode())
    _export(export, functions)
    receipt = root / f"{stem}.receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "schema_version": "0verse.ghidra-analysis-receipt/v1",
                "producer": "zeroverse.windows-analysis/fixture-v1",
                "binary_path": binary.name,
                "binary_sha256": _sha(binary),
                "ghidra_export_path": export.name,
                "ghidra_export_sha256": _sha(export),
                "tool": "ghidra",
                "tool_version": "fixture-11.4",
                "cache_key": _sha(binary)[:16],
                "synthetic_fixture": True,
                "pdb": {"path": "", "sha256": "", "codeview_identity": ""},
            }
        ),
        encoding="utf-8",
    )
    return {
        "binary_path": binary.name,
        "ghidra_export_path": export.name,
        "binary_sha256": _sha(binary),
        "ghidra_export_sha256": _sha(export),
        "analysis_receipt_path": receipt.name,
        "analysis_receipt_sha256": _sha(receipt),
    }


def _campaign(tmp_path: Path) -> Path:
    vulnerable = _artifact(
        tmp_path,
        "vulnerable",
        {
            "SeedDispatch": (
                "void SeedDispatch(char *input, unsigned count) { "
                "memcpy(dst, input, count); }"
            )
        },
    )
    fixed = _artifact(
        tmp_path,
        "fixed",
        {
            "SeedDispatch": (
                "void SeedDispatch(char *input, unsigned count) { "
                "if (count > 256) return; memcpy(dst, input, count); }"
            )
        },
    )
    current = _artifact(
        tmp_path,
        "current",
        {
            "SeedDispatch": (
                "void SeedDispatch(char *input, unsigned count) { "
                "if (count > 256) return; memcpy(dst, input, count); }"
            ),
            "OrdinaryChildDispatch": (
                "void OrdinaryChildDispatch(char *packet, unsigned count) { "
                "memcpy(output, packet, count); }"
            ),
            "UnknownDispatch": (
                "void UnknownDispatch(char *buffer, unsigned count) { "
                "RtlCopyMemory(output, buffer, count); }"
            ),
            "RootOnlyDispatch": (
                "void RootOnlyDispatch(char *buffer, unsigned count) { "
                "memcpy(output, buffer, count); }"
            ),
            "PatchedSibling": (
                "void PatchedSibling(char *buffer, unsigned length) { "
                "if (length >= 256) return; memcpy(output, buffer, length); }"
            ),
            "Unrelated": "void Unrelated(unsigned value) { state = value; }",
        },
    )
    manifest = tmp_path / "campaign.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-variant-campaign/v1",
                "seed": {
                    "vulnerable": vulnerable,
                    "fixed": fixed,
                    "function": "SeedDispatch",
                    "reference": "CVE-fixture: missing count bound before copy",
                },
                "current": current,
                "reachability": {
                    "OrdinaryChildDispatch": {
                        "grade": "ordinary-child",
                        "evidence": "stock child dispatch table entry 7",
                    },
                    "RootOnlyDispatch": {
                        "grade": "root-only",
                        "evidence": "root partition consumer only",
                    },
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return manifest


def _labels(tmp_path: Path, manifest: Path) -> Path:
    ranked = rank_windows_variants(manifest)
    current = ranked["current"]
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-variant-labels/v1",
                "campaign_sha256": ranked["campaign_sha256"],
                "current_binary_sha256": current["binary_sha256"],
                "current_export_sha256": current["ghidra_export_sha256"],
                "expected_sites": [
                    {"function": "OrdinaryChildDispatch", "function_address": "0x1200"}
                ],
                "patched_control_sites": [
                    {"function": "PatchedSibling", "function_address": "0x1500"}
                ],
                "rank_cutoff": 20,
                "minimum_recall_at_cutoff": 0.7,
                "minimum_patched_control_suppression": 0.95,
                "maximum_unsupported_at_cutoff": 3,
            }
        ),
        encoding="utf-8",
    )
    return labels


def test_rank_transfers_guard_and_suppresses_patched_control(tmp_path: Path) -> None:
    result = rank_windows_variants(_campaign(tmp_path))
    assert result["schema_version"] == "0verse.windows-variant/v1"
    assert result["weaponization"] is False
    assert result["automatic_disclosure"] is False
    assert result["seed"]["guard_delta"] == ["bounds"]
    rows = result["candidates"]
    assert [row["function"] for row in rows] == [
        "OrdinaryChildDispatch",
        "RootOnlyDispatch",
        "UnknownDispatch",
    ]
    assert rows[0]["status"] == "candidate"
    assert rows[0]["lexical_parameter_sink_hint"] == ["parameter:packet", "sink:copy"]
    assert rows[1]["status"] == "candidate"
    assert rows[2]["score"] == rows[1]["score"]
    assert "do not dynamically test" in rows[1]["required_next_validator"]
    assert all(row["status"] == "candidate" for row in rows)


def test_output_is_deterministic_and_hash_pinned(tmp_path: Path) -> None:
    manifest = _campaign(tmp_path)
    first = rank_windows_variants(manifest)
    second = rank_windows_variants(manifest)
    assert first == second

    current = tmp_path / "current.sys"
    current.write_bytes(current.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="binary SHA-256 mismatch"):
        rank_windows_variants(manifest)


def test_analysis_receipt_must_bind_binary_export_tool_and_cache(tmp_path: Path) -> None:
    manifest = _campaign(tmp_path)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    receipt = tmp_path / raw["current"]["analysis_receipt_path"]
    receipt_raw = json.loads(receipt.read_text(encoding="utf-8"))
    receipt_raw["binary_sha256"] = "0" * 64
    receipt.write_text(json.dumps(receipt_raw), encoding="utf-8")
    raw["current"]["analysis_receipt_sha256"] = _sha(receipt)
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact binding mismatch"):
        rank_windows_variants(manifest)


def test_exact_vid_binary_rejects_legacy_v1_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor = _artifact(tmp_path, "vid-downgrade", {"Dispatch": "return;"})
    receipt = tmp_path / descriptor["analysis_receipt_path"]
    receipt_raw = json.loads(receipt.read_text(encoding="utf-8"))
    receipt_raw["binary_sha256"] = VID_DRIVER_SHA256
    receipt.write_text(json.dumps(receipt_raw), encoding="utf-8")
    descriptor["binary_sha256"] = VID_DRIVER_SHA256
    descriptor["analysis_receipt_sha256"] = _sha(receipt)
    original_snapshot = variant._snapshot_file

    def exact_vid_snapshot(source: Path, destination: Path, label: str, cap: int) -> str:
        digest = original_snapshot(source, destination, label, cap)
        return VID_DRIVER_SHA256 if label.endswith(" binary") else digest

    monkeypatch.setattr(variant, "_snapshot_file", exact_vid_snapshot)
    with pytest.raises(ValueError, match="exact Vid analysis requires a v2 receipt"):
        variant._load_artifact(descriptor, tmp_path, "vid-downgrade")


def test_rejects_forged_reachability_and_unknown_schema_fields(tmp_path: Path) -> None:
    manifest = _campaign(tmp_path)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["reachability"]["UnknownDispatch"] = {
        "grade": "unprivileged-ioctl",
        "evidence": "",
    }
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="reachability evidence is required"):
        rank_windows_variants(manifest)

    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["surprise"] = True
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown surprise"):
        rank_windows_variants(manifest)


def test_cli_writes_exclusively_and_never_overwrites(tmp_path: Path) -> None:
    manifest = _campaign(tmp_path)
    output = tmp_path / "ranked.json"
    assert main(["windows-variant-rank", str(manifest), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["candidate_count"] == 3
    assert main(["windows-variant-rank", str(manifest), "--output", str(output)]) == 2


def test_artifacts_cannot_escape_manifest_directory(tmp_path: Path) -> None:
    manifest = _campaign(tmp_path)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["current"]["binary_path"] = "../outside.sys"
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="relative to the campaign"):
        rank_windows_variants(manifest)


def test_artifact_symlinks_are_rejected(tmp_path: Path) -> None:
    manifest = _campaign(tmp_path)
    target = tmp_path / "current.sys"
    link = tmp_path / "current-link.sys"
    link.symlink_to(target)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["current"]["binary_path"] = link.name
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="non-symlink"):
        rank_windows_variants(manifest)


def test_eval_measures_recall_controls_and_static_promotion_gate(tmp_path: Path) -> None:
    manifest = _campaign(tmp_path)
    report = evaluate_windows_variants(manifest, _labels(tmp_path, manifest))
    assert report["schema_version"] == "0verse.windows-variant-eval/v1"
    assert report["recall_at_cutoff"] == 1.0
    assert report["patched_control_suppression"] == 1.0
    assert report["unsupported_at_cutoff"] == 3
    assert all(report["gates"].values())
    assert report["passed"] is True
    assert report["capability_measure"] is False


def test_eval_fails_closed_on_bad_labels(tmp_path: Path) -> None:
    manifest = _campaign(tmp_path)
    labels = _labels(tmp_path, manifest)
    raw = json.loads(labels.read_text(encoding="utf-8"))
    same = [{"function": "Same", "function_address": "0x1000"}]
    raw["expected_sites"] = same
    raw["patched_control_sites"] = same
    labels.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="must be disjoint"):
        evaluate_windows_variants(manifest, labels)


def test_eval_labels_are_bound_to_exact_campaign(tmp_path: Path) -> None:
    manifest = _campaign(tmp_path)
    labels = _labels(tmp_path, manifest)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["seed"]["reference"] = "different campaign"
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="not bound"):
        evaluate_windows_variants(manifest, labels)


def test_eval_cli_returns_nonzero_when_a_gate_fails(tmp_path: Path) -> None:
    manifest = _campaign(tmp_path)
    labels = _labels(tmp_path, manifest)
    raw = json.loads(labels.read_text(encoding="utf-8"))
    raw["maximum_unsupported_at_cutoff"] = 2
    labels.write_text(json.dumps(raw), encoding="utf-8")
    assert main(["windows-variant-eval", str(manifest), str(labels)]) == 1


def test_guard_hint_is_sink_local_and_operand_related() -> None:
    unrelated = _shape(
        "Unrelated",
        "void Unrelated(char *input, unsigned count, unsigned other) { "
        "if (other > 4) log(); memcpy(dst, input, count); }",
        0x1000,
    )
    late = _shape(
        "Late",
        "void Late(char *input, unsigned count) { memcpy(dst, input, count); "
        "if (count > 4) log(); }",
        0x1100,
    )
    guarded = _shape(
        "Guarded",
        "void Guarded(char *input, unsigned count) { if (count > 4) return; "
        "memcpy(dst, input, count); }",
        0x1200,
    )
    assert "bounds" not in unrelated.guards
    assert "bounds" not in late.guards
    assert "bounds" in guarded.guards


def test_lexical_hint_ignores_destination_only_parameter() -> None:
    shape = _shape(
        "DestinationOnly",
        "void DestinationOnly(char *user) { memcpy(user, constant_data, 16); }",
        0x1000,
    )
    assert shape.parameter_flow is None


def test_lexical_hint_recovers_one_hop_parameter_alias() -> None:
    aliased = _shape(
        "Aliased",
        "void Aliased(wchar_t *path) { wchar_t *target = path;"
        " HANDLE h = CreateFileW(target, 1, 2, 0, 3, 0, 0); }",
        0x1000,
    )
    assert aliased.parameter_flow == ("path", "file-open")
    casted = _shape(
        "Casted",
        "void Casted(wchar_t *path) { wchar_t *target = (wchar_t *)path;"
        " DeleteFileW(target); }",
        0x1100,
    )
    assert casted.parameter_flow == ("path", "file-mutate")
    unbound = _shape(
        "Unbound",
        "void Unbound(wchar_t *path) { wchar_t *target = global_path;"
        " HANDLE h = CreateFileW(target, 1, 2, 0, 3, 0, 0); }",
        0x1200,
    )
    assert unbound.parameter_flow is None


def test_real_producer_bundle_flows_into_ranker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ghidra = tmp_path / "ghidra"
    (ghidra / "Ghidra").mkdir(parents=True)
    (ghidra / "Ghidra" / "application.properties").write_text(
        "application.version=11.4.2\n", encoding="utf-8"
    )
    guid = "00112233445566778899AABBCCDDEEFF"
    monkeypatch.setattr(
        "zeroverse.windows_variant.pe_codeview_identity", lambda _path: (guid, 1, "target.pdb")
    )
    monkeypatch.setattr(
        "zeroverse.windows_variant.pdb_codeview_identity", lambda _path: (guid, 1, "target.pdb")
    )

    functions = {
        "vulnerable": {
            "SeedDispatch": "void SeedDispatch(char *p, unsigned n) { memcpy(dst, p, n); }"
        },
        "fixed": {
            "SeedDispatch": (
                "void SeedDispatch(char *p, unsigned n) { if (n > 8) return; "
                "memcpy(dst, p, n); }"
            )
        },
        "current": {
            "SeedDispatch": (
                "void SeedDispatch(char *p, unsigned n) { if (n > 8) return; "
                "memcpy(dst, p, n); }"
            ),
            "Sibling": "void Sibling(char *p, unsigned n) { memcpy(dst, p, n); }",
        },
    }
    artifacts: dict[str, dict[str, str]] = {}
    for stem, export_functions in functions.items():
        binary = tmp_path / f"source-{stem}.sys"
        pdb = tmp_path / f"source-{stem}.pdb"
        binary.write_bytes(b"MZ" + stem.encode())
        pdb.write_bytes(b"PDB" + stem.encode())

        def analyze(
            _binary: Path,
            _pdb: Path,
            funcs: dict[str, str] = export_functions,
        ) -> dict[str, object]:
            return {
                "insts": [
                    {"id": index, "func": name, "addr": 0x1000 + index * 0x100}
                    for index, name in enumerate(funcs, 1)
                ],
                "meta": {"decompiled_c": funcs},
            }

        produced = produce_windows_analysis_bundle(
            binary, pdb, tmp_path / stem, ghidra_home=ghidra, analyzer=analyze
        )
        artifacts[stem] = produced

    manifest = tmp_path / "real-campaign.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-variant-campaign/v1",
                "seed": {
                    "vulnerable": artifacts["vulnerable"],
                    "fixed": artifacts["fixed"],
                    "function": "SeedDispatch",
                    "reference": "producer contract fixture",
                },
                "current": artifacts["current"],
                "reachability": {},
            }
        ),
        encoding="utf-8",
    )
    result = rank_windows_variants(manifest)
    assert [row["function"] for row in result["candidates"]] == ["Sibling"]
    assert result["current"]["ghidra_version"] == "11.4.2"
    assert result["current"]["synthetic_fixture"] is False


def test_analysis_bundle_cli_reports_runtime_setup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "zeroverse.windows_variant.produce_windows_analysis_bundle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("PyGhidra unavailable")),
    )
    rc = main(
        [
            "windows-analysis-bundle",
            str(tmp_path / "target.sys"),
            str(tmp_path / "target.pdb"),
            str(tmp_path / "bundle"),
            "--ghidra-home",
            str(tmp_path / "ghidra"),
        ]
    )
    assert rc == 2
    assert "error: PyGhidra unavailable" in capsys.readouterr().err


# ── CWE-59 link-following lens (Object Manager namespace pivot class) ────────
#
# Seed shape learned from the public RoguePlanet/ShieldBreak class: a service
# resolves an attacker-influenced path without a reparse/link check. The fixed
# side adds one; siblings that keep the path sink without the check rank.


def _link_follow_campaign(tmp_path: Path) -> Path:
    vulnerable = _artifact(
        tmp_path,
        "vulnerable",
        {
            "SeedScan": (
                "void SeedScan(wchar_t *path) { HANDLE h = CreateFileW(path, 1, 2, 0, 3, 0, 0);"
                " ReadFile(h, buf, 64, pn, 0); DeleteFileW(path); }"
            )
        },
    )
    fixed = _artifact(
        tmp_path,
        "fixed",
        {
            "SeedScan": (
                "void SeedScan(wchar_t *path) { DWORD a = GetFileAttributesW(path);"
                " if (a & FILE_ATTRIBUTE_REPARSE_POINT) return;"
                " HANDLE h = CreateFileW(path, 1, 2, 0, 3, 0, 0);"
                " ReadFile(h, buf, 64, pn, 0); DeleteFileW(path); }"
            )
        },
    )
    current = _artifact(
        tmp_path,
        "current",
        {
            "SeedScan": (
                "void SeedScan(wchar_t *path) { DWORD a = GetFileAttributesW(path);"
                " if (a & FILE_ATTRIBUTE_REPARSE_POINT) return;"
                " HANDLE h = CreateFileW(path, 1, 2, 0, 3, 0, 0);"
                " ReadFile(h, buf, 64, pn, 0); DeleteFileW(path); }"
            ),
            "QuarantineMove": (
                "void QuarantineMove(wchar_t *found, wchar_t *store) {"
                " MoveFileExW(found, store, 2); }"
            ),
            "HardenedQuarantine": (
                "void HardenedQuarantine(wchar_t *found, wchar_t *store) {"
                " DWORD a = GetFileAttributesW(found);"
                " if (a & FILE_ATTRIBUTE_REPARSE_POINT) return;"
                " MoveFileExW(found, store, 2); }"
            ),
            "Unrelated": "void Unrelated(unsigned value) { state = value; }",
        },
    )
    manifest = tmp_path / "campaign.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-variant-campaign/v1",
                "seed": {
                    "vulnerable": vulnerable,
                    "fixed": fixed,
                    "function": "SeedScan",
                    "reference": "CWE-59 fixture: missing reparse check before path resolution",
                },
                "current": current,
                "reachability": {},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return manifest


def test_link_following_lens_transfers_reparse_guard(tmp_path: Path) -> None:
    result = rank_windows_variants(_link_follow_campaign(tmp_path))
    assert result["schema_version"] == "0verse.windows-variant/v1"
    assert result["weaponization"] is False
    assert result["automatic_disclosure"] is False
    assert result["seed"]["guard_delta"] == ["reparse-check"]
    assert result["seed"]["sink_geometry"] == ["file-mutate", "file-open"]
    rows = result["candidates"]
    assert [row["function"] for row in rows] == ["QuarantineMove"]
    assert rows[0]["status"] == "candidate"
    assert rows[0]["matched_sinks"] == ["file-mutate"]
    assert rows[0]["missing_seed_guards"] == ["reparse-check"]
    assert rows[0]["present_guards"] == []
    assert rows[0]["lexical_parameter_sink_hint"] == [
        "parameter:found",
        "sink:file-mutate",
    ]


def test_path_sink_hint_names_the_path_argument() -> None:
    shape = _shape(
        "Open",
        "void Open(wchar_t *path) { CreateFileW(path, 1, 2, 0, 3, 0, 0); }",
        0x1000,
    )
    assert "file-open" in shape.sinks
    assert shape.parameter_flow == ("path", "file-open")
    hive = _shape(
        "Hive",
        "void Hive(wchar_t *path) { RegLoadKeyW(root, name, path); }",
        0x1100,
    )
    assert "registry-hive" in hive.sinks
    assert hive.parameter_flow == ("path", "registry-hive")


def test_link_resolution_guards_cover_sink_and_post_open_window() -> None:
    flagged = _shape(
        "Flagged",
        "void Flagged(wchar_t *path) {"
        " HANDLE h = CreateFileW(path, 1, 2, 0, 3, FILE_FLAG_OPEN_REPARSE_POINT, 0); }",
        0x1200,
    )
    assert "no-reparse-open" in flagged.guards
    verified = _shape(
        "Verified",
        "void Verified(wchar_t *path) {"
        " HANDLE h = CreateFileW(path, 1, 2, 0, 3, 0, 0);"
        " GetFinalPathNameByHandleW(h, buf, 260, 0); }",
        0x1300,
    )
    assert "final-path-verify" in verified.guards
    impersonated = _shape(
        "Impersonated",
        "void Impersonated(wchar_t *path) { ImpersonateLoggedOnUser(token);"
        " HANDLE h = CreateFileW(path, 1, 2, 0, 3, 0, 0); RevertToSelf(); }",
        0x1400,
    )
    assert "client-impersonation" in impersonated.guards
    unguarded = _shape(
        "Unguarded",
        "void Unguarded(wchar_t *path) {"
        " HANDLE h = CreateFileW(path, 1, 2, 0, 3, 0, 0); ReadFile(h, buf, 8, pn, 0); }",
        0x1500,
    )
    assert not (unguarded.guards & {
        "no-reparse-open",
        "reparse-check",
        "final-path-verify",
        "client-impersonation",
    })


def test_numeric_no_reparse_flags_fallback() -> None:
    hex_flags = _shape(
        "HexFlags",
        "void HexFlags(wchar_t *path) {"
        " HANDLE h = CreateFileW(path, 1, 2, 0, 3, 0x200000, 0); }",
        0x1600,
    )
    assert "no-reparse-open" in hex_flags.guards
    plain = _shape(
        "Plain",
        "void Plain(wchar_t *path) {"
        " HANDLE h = CreateFileW(path, 1, 2, 0, 3, 0x80, 0); }",
        0x1700,
    )
    assert "no-reparse-open" not in plain.guards
    # Measured FP on vmswitch!VmsProxyOpenDevice: SYNCHRONIZE (0x00100000) in
    # the DesiredAccess mask is NOT a no-recall flag — only the flags operand
    # may carry the hint.
    synchronize = _shape(
        "Synchronize",
        "void Synchronize(wchar_t *path) {"
        " ZwOpenFile(&h, 0x100080, &attrs, &iosb, 3, 0x60); }",
        0x1800,
    )
    assert "no-reparse-open" not in synchronize.guards
    nt_options = _shape(
        "NtOptions",
        "void NtOptions(wchar_t *path) {"
        " ZwOpenFile(&h, 0x100080, &attrs, &iosb, 3, 0x200060); }",
        0x1900,
    )
    assert "no-reparse-open" in nt_options.guards


def test_double_resolution_window_detects_check_then_act() -> None:
    both = _shape(
        "Both",
        "void Both(wchar_t *path) { HANDLE h = CreateFileW(path, 1, 2, 0, 3, 0, 0);"
        " ReadFile(h, buf, 8, pn, 0); DeleteFileW(path); }",
        0x1800,
    )
    assert both.toctou_window is True
    split = _shape(
        "Split",
        "void Split(wchar_t *src, wchar_t *dst) {"
        " HANDLE h = CreateFileW(src, 1, 2, 0, 3, 0, 0); DeleteFileW(dst); }",
        0x1900,
    )
    assert split.toctou_window is False
    single = _shape(
        "Single",
        "void Single(wchar_t *path) { CreateFileW(path, 1, 2, 0, 3, 0, 0); }",
        0x1A00,
    )
    assert single.toctou_window is False


def test_double_resolution_candidate_outranks_single_use(tmp_path: Path) -> None:
    manifest = _link_follow_campaign(tmp_path)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    current = tmp_path / "current.json"
    export = json.loads(current.read_text(encoding="utf-8"))
    export["meta"]["decompiled_c"]["ScanThenPurge"] = (
        "void ScanThenPurge(wchar_t *path) {"
        " HANDLE h = CreateFileW(path, 1, 2, 0, 3, 0, 0);"
        " ReadFile(h, buf, 64, pn, 0); DeleteFileW(path); }"
    )
    export["insts"].append(
        {"id": len(export["insts"]) + 1, "func": "ScanThenPurge", "addr": 0x1600, "kind": "OTHER"}
    )
    current.write_text(json.dumps(export), encoding="utf-8")
    raw["current"]["ghidra_export_sha256"] = _sha(current)
    receipt = tmp_path / "current.receipt.json"
    receipt_raw = json.loads(receipt.read_text(encoding="utf-8"))
    receipt_raw["ghidra_export_sha256"] = _sha(current)
    receipt.write_text(json.dumps(receipt_raw), encoding="utf-8")
    raw["current"]["analysis_receipt_sha256"] = _sha(receipt)
    manifest.write_text(json.dumps(raw), encoding="utf-8")

    result = rank_windows_variants(manifest)
    rows = result["candidates"]
    assert [row["function"] for row in rows] == ["ScanThenPurge", "QuarantineMove"]
    assert rows[0]["score"] > rows[1]["score"]
    assert rows[0]["matched_sinks"] == ["file-mutate", "file-open"]


_LINKFOLLOW_FIXTURE = (
    Path(__file__).resolve().parent.parent / "benchmarks" / "windows_linkfollow_contract"
)


def test_committed_linkfollow_contract_passes_eval() -> None:
    manifest = _LINKFOLLOW_FIXTURE / "campaign.json"
    result = rank_windows_variants(manifest)
    assert [row["function"] for row in result["candidates"]] == [
        "ScanThenPurge",
        "QuarantineMove",
    ]
    assert result["seed"]["guard_delta"] == ["reparse-check"]
    assert result["weaponization"] is False
    assert result["automatic_disclosure"] is False
    report = evaluate_windows_variants(manifest, _LINKFOLLOW_FIXTURE / "labels.json")
    assert report["schema_version"] == "0verse.windows-variant-eval/v1"
    assert report["recall_at_cutoff"] == 1.0
    assert report["patched_control_suppression"] == 1.0
    assert report["unsupported_at_cutoff"] == 2
    assert all(report["gates"].values())
    assert report["passed"] is True
    assert report["capability_measure"] is False
