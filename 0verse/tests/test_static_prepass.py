"""#3 foxguard static pre-pass — SARIF parsing + graceful degradation + union.

The SARIF parsing and the union/dedup logic are pure and always tested. A live
foxguard scan is exercised only when the binary is present (bench / FOXGUARD_BIN).
"""

import json

import zeroverse.static_prepass as sp
from zeroverse.analyze import Finding, foxguard_union
from zeroverse.static_prepass import (
    FoxHypothesis,
    _parse_sarif,
    run_over_decompiled,
)

_SARIF = json.dumps({
    "runs": [{
        "results": [
            {
                "ruleId": "c/taint-buffer-overflow",
                "level": "warning",
                "message": {"text": "tainted argv reaches strcpy"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "scan/parse_header.c"},
                        "region": {"startLine": 12},
                    }
                }],
            }
        ]
    }]
})


def test_foxguard_path_swallows_permission_error(monkeypatch):  # type: ignore[no-untyped-def]
    # CI regression: in CI ``/root/foxguard/...`` is not traversable, so
    # ``Path(cand).is_file()`` raises PermissionError. The probe must swallow it and
    # treat the candidate as not-found — foxguard_path() must NEVER propagate it.
    def boom(self):  # type: ignore[no-untyped-def]
        raise PermissionError("CI: candidate not readable/traversable")
    monkeypatch.setattr("zeroverse.static_prepass.Path.is_file", boom)
    monkeypatch.setattr(sp, "_which", lambda _n: None)  # nothing on PATH
    monkeypatch.delenv("ZEROVERSE_FOXGUARD", raising=False)
    monkeypatch.delenv("FOXGUARD_BIN", raising=False)
    # the helper swallows the raise...
    assert sp._is_runnable_file("/root/foxguard/target/release/foxguard") is False
    # ...and full resolution degrades to a clean None instead of crashing.
    assert sp.foxguard_path() is None


def test_parse_sarif_maps_back_to_function() -> None:
    hyps = _parse_sarif(_SARIF, {"parse_header": "parse_header"})
    assert len(hyps) == 1
    h = hyps[0]
    assert isinstance(h, FoxHypothesis)
    assert h.function == "parse_header"
    assert h.rule_id == "c/taint-buffer-overflow"
    assert h.line == 12


def test_parse_sarif_tolerates_garbage() -> None:
    assert _parse_sarif("not json", {}) == []
    assert _parse_sarif("{}", {}) == []


def test_run_over_decompiled_empty_is_graceful() -> None:
    res = run_over_decompiled({})
    assert res.hypotheses == []
    assert res.note  # an annotated reason, never a crash


def test_foxguard_union_adds_divergent_only(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # #2 already flagged main; foxguard also flags `decode` (divergence == signal).
    import zeroverse.static_prepass as sp

    def fake_run(decompiled, **kw):  # type: ignore[no-untyped-def]
        return sp.PrepassResult(
            hypotheses=[
                FoxHypothesis("c/oob", "main", "dup of slice"),     # deduped away
                FoxHypothesis("c/oob-write", "decode", "new"),       # kept
            ],
            ran=True, note="foxguard: 2 hypotheses",
        )

    monkeypatch.setattr(sp, "run_over_decompiled", fake_run)
    slice_findings = [Finding("getenv", "system", "main", 0x10, 0x20, 4)]
    merged, note = foxguard_union(slice_findings, {"main": "x", "decode": "y"})
    assert "2 hypotheses" in note
    funcs = {(f.function, f.origin) for f in merged}
    assert ("main", "slice") in funcs
    assert ("decode", "foxguard") in funcs
    assert sum(1 for f in merged if f.origin == "foxguard") == 1  # main not doubled


def test_foxguard_path_resolution(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    fake = tmp_path / "foxguard"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("FOXGUARD_BIN", str(fake))
    # env override wins; reload candidate list by re-importing the function's view
    import importlib

    import zeroverse.static_prepass as sp
    importlib.reload(sp)
    assert sp.foxguard_path() == str(fake)
    importlib.reload(sp)  # restore module-level state for other tests


def test_safe_stem_caps_long_names() -> None:
    # Rich C++/PDB template names (Windows-PE targets) can be 700+ chars and
    # blow past the 255-byte filename limit → ENAMETOOLONG crashed the prepass.
    short = "RndisFormatsHostValidateRndisPacket"
    assert sp._safe_stem(short) == short  # normal names untouched

    long_name = "Write_struct__tlgWrapperByVal_8__" + "X" * 800
    stem = sp._safe_stem(long_name)
    assert len(stem) <= 200
    assert all(c.isalnum() or c in "_-" for c in stem)
    # deterministic + collision-resistant: same input → same stem, distinct inputs differ
    assert sp._safe_stem(long_name) == stem
    assert sp._safe_stem(long_name + "Y") != stem

    assert sp._safe_stem("") == "fn"  # empty still safe
