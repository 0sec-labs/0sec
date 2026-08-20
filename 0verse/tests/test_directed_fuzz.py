"""Directed trigger construction — pure unit tests (no real fuzzing, no binaries).

The fuzz runner (:func:`_run_jobs`) and the sanitizer oracle are monkeypatched so
these exercise the LOGIC — seed exclusion, differential adjudication, the
not-applicable path, and the end-to-end confirm/partial decision — deterministically.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from zeroverse import directed_fuzz as df
from zeroverse import oracle


@dataclass
class _Verdict:
    sink: str = "WriteCLUT"
    source: str = "attacker file"
    cwe: str = "CWE-125"


def _run(crashed: bool, *, sanitizer: str = "", stderr: str = "") -> oracle.RunResult:
    return oracle.RunResult(crashed=crashed, sanitizer=sanitizer, stderr=stderr)


# --- seed collection --------------------------------------------------------


def test_collect_seeds_excludes_poc_bytes(tmp_path: Path) -> None:
    src = tmp_path / "corpus"
    src.mkdir()
    (src / "a.icc").write_bytes(b"acsp-A")
    (src / "poc.icc").write_bytes(b"THE-POC-BYTES")
    (src / "b.icc").write_bytes(b"acsp-B")
    dest = tmp_path / "dest"
    n, _srcdesc = df._collect_seeds([str(src / "*.icc")], dest, exclude={b"THE-POC-BYTES"})
    kept = {p.read_bytes() for p in dest.glob("seed_*")}
    assert n == 2
    assert b"THE-POC-BYTES" not in kept  # the poc is never seeded
    assert kept == {b"acsp-A", b"acsp-B"}


# --- peak coverage parsing --------------------------------------------------


def test_peak_cov_takes_max() -> None:
    err = b"#12 NEW cov: 101 ft: 200\n#88 NEW cov: 1450 ft: 3201\n#90 pulse cov: 900 ft: 1"
    assert df._peak_cov(err) == 1450
    assert df._peak_cov(b"no coverage here") == 0


# --- differential adjudication of one artifact ------------------------------


def test_adjudicate_confirmed_when_vuln_crashes_fixed_clean(monkeypatch) -> None:
    asan = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 4\n"
        "    #0 0x1 in WriteCLUT /src/lcms/src/cmsps2.c:666\n"
    )

    def fake_run(binary, data, **kw):
        return _run(
            "vuln" in str(binary),
            sanitizer="AddressSanitizer",
            stderr=asan if "vuln" in str(binary) else "",
        )

    monkeypatch.setattr(df.oracle, "run_sanitizer", fake_run)
    ok, fn, _cwe, matches, detail = df._adjudicate_artifact(
        b"x", _Verdict(sink="WriteCLUT"), "/t/vuln", "/t/fixed", 5.0
    )
    assert ok is True
    assert fn == "WriteCLUT"
    assert matches is True  # crash function matches the hypothesized sink
    assert "fixed clean" in detail


def test_adjudicate_reports_divergent_sink_honestly(monkeypatch) -> None:
    """PoV-is-truth: a crash at a DIFFERENT function than the hypothesis still
    confirms a real bug, but matches_hypothesis is False (not forced to fit)."""
    asan = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow READ of size 4\n"
        "    #0 0x1 in WriteCLUT /src/lcms/src/cmsps2.c:666\n"
    )
    monkeypatch.setattr(
        df.oracle,
        "run_sanitizer",
        lambda b, d, **kw: _run(
            "vuln" in str(b), sanitizer="AddressSanitizer", stderr=asan if "vuln" in str(b) else ""
        ),
    )
    ok, fn, _cwe, matches, _detail = df._adjudicate_artifact(
        b"x", _Verdict(sink="ReadCLUT", source="ReadCLUT tag"), "/t/vuln", "/t/fixed", 5.0
    )
    assert ok is True and fn == "WriteCLUT"
    assert matches is False  # honest: the LLM said ReadCLUT, the bug is WriteCLUT


def test_adjudicate_rejects_when_fixed_also_crashes(monkeypatch) -> None:
    asan = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n    #0 0x1 in F /a.c:1\n"
    monkeypatch.setattr(
        df.oracle,
        "run_sanitizer",
        lambda b, d, **kw: _run(True, sanitizer="AddressSanitizer", stderr=asan),
    )
    ok, _fn, _cwe, _m, detail = df._adjudicate_artifact(
        b"x", _Verdict(), "/t/vuln", "/t/fixed", 5.0
    )
    assert ok is False  # not a differential — the fix didn't fix it
    assert "FIXED build also crashed" in detail


def test_adjudicate_no_crash(monkeypatch) -> None:
    monkeypatch.setattr(df.oracle, "run_sanitizer", lambda b, d, **kw: _run(False))
    ok, _fn, _cwe, _m, detail = df._adjudicate_artifact(b"x", _Verdict(), "/t/vuln", None, 5.0)
    assert ok is False and "did not crash" in detail


# --- top-level: not-applicable + end-to-end confirm -------------------------


def test_not_applicable_for_non_harness(monkeypatch) -> None:
    monkeypatch.setattr(df.oracle, "is_asan_file_target", lambda b: False)
    res = df.confirm_by_directed_fuzz(_Verdict(), "/t/plain_elf", seed_globs=["/x/*"])
    assert res.applicable is False and res.confirmed is False
    assert "not an ASan libFuzzer harness" in res.reason


def test_end_to_end_confirms_from_planted_crash(monkeypatch, tmp_path: Path) -> None:
    """Wire the whole flow with a fuzzer that 'discovers' a crash artifact and an
    oracle that confirms it — proving the confirm path end to end."""
    monkeypatch.setattr(df.oracle, "is_asan_file_target", lambda b: True)
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "s.icc").write_bytes(b"acsp-seed")

    def fake_run_jobs(vuln, corp, art, budget_s, **kw):
        art.mkdir(parents=True, exist_ok=True)
        (art / "crash-deadbeef").write_bytes(b"WINNING-NON-POC-INPUT")
        return 1450  # peak cov

    asan = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow READ of size 4\n"
        "    #0 0x1 in WriteCLUT /src/lcms/src/cmsps2.c:666\n"
    )
    monkeypatch.setattr(df, "_run_jobs", fake_run_jobs)
    monkeypatch.setattr(
        df.oracle,
        "run_sanitizer",
        lambda b, d, **kw: _run(
            "vuln" in str(b), sanitizer="AddressSanitizer", stderr=asan if "vuln" in str(b) else ""
        ),
    )
    res = df.confirm_by_directed_fuzz(
        _Verdict(sink="WriteCLUT"),
        "/t/vuln",
        fixed_binary="/t/fixed",
        seed_globs=[str(seeds / "*.icc")],
        budget_s=5,
        jobs=2,
        exclude_inputs=[b"THE-POC"],
    )
    assert res.applicable is True
    assert res.confirmed is True
    assert res.crash_function == "WriteCLUT"
    assert res.matches_hypothesis is True
    assert res.winning_input == b"WINNING-NON-POC-INPUT"
    assert res.directed_cov == 1450


def test_end_to_end_honest_partial_when_no_crash(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(df.oracle, "is_asan_file_target", lambda b: True)
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "s.icc").write_bytes(b"acsp-seed")
    # fuzzer finds nothing; art stays empty.
    monkeypatch.setattr(df, "_run_jobs", lambda *a, **kw: 900)
    res = df.confirm_by_directed_fuzz(
        _Verdict(),
        "/t/vuln",
        seed_globs=[str(seeds / "*.icc")],
        budget_s=5,
    )
    assert res.confirmed is False
    assert res.directed_cov == 900
    assert "coverage ladder" in res.reason  # honest partial, not a fabricated confirm


# --- LLM-seeding lever ------------------------------------------------------


def _patch_synth(monkeypatch, candidates):
    """Patch synthesize_povs where _synthesize_seeds imports it from."""
    import zeroverse.synthesize as synth
    monkeypatch.setattr(synth, "synthesize_povs", lambda *a, **kw: list(candidates))


def test_synthesize_seeds_writes_and_excludes_poc(monkeypatch, tmp_path: Path) -> None:
    _patch_synth(monkeypatch, [b"CFF2-seed-A", b"THE-POC", b"CFF2-seed-B", b""])
    dest = tmp_path / "corp"
    n, note = df._synthesize_seeds(
        object(), _Verdict(), object(), 6, dest, exclude={b"THE-POC"}
    )
    written = {p.read_bytes() for p in dest.glob("synth_*")}
    assert n == 2  # poc and empty candidate skipped
    assert written == {b"CFF2-seed-A", b"CFF2-seed-B"}
    assert "synthesized 2" in note


def test_synthesize_seeds_surfaces_error(monkeypatch, tmp_path: Path) -> None:
    """A synthesis/LLM error must be reported, never silently swallowed as 0 seeds."""
    import zeroverse.synthesize as synth

    def boom(*a, **kw):
        raise RuntimeError("codex token expired")

    monkeypatch.setattr(synth, "synthesize_povs", boom)
    n, note = df._synthesize_seeds(object(), _Verdict(), object(), 6, tmp_path, exclude=set())
    assert n == 0
    assert "synthesis ERROR" in note and "codex token expired" in note


def test_synth_seeding_runs_when_generic_corpus_empty(monkeypatch, tmp_path: Path) -> None:
    """The corpus-mismatch fix: no matching generic seeds, but LLM-synthesized
    format-valid seeds carry the run (the harfbuzz/libraw case)."""
    monkeypatch.setattr(df.oracle, "is_asan_file_target", lambda b: True)
    _patch_synth(monkeypatch, [b"CFF2-font-seed"])

    captured = {}

    def fake_run_jobs(vuln, corp, art, budget_s, **kw):
        captured["seed_files"] = sorted(p.name for p in corp.glob("*"))
        return 4712

    monkeypatch.setattr(df, "_run_jobs", fake_run_jobs)
    res = df.confirm_by_directed_fuzz(
        _Verdict(sink="cff2"),
        "/t/vuln",
        seed_globs=["/nonexistent/*.cff2"],  # generic corpus finds nothing
        budget_s=5,
        synth_seeds=4,
        meta=object(),
        llm=object(),
    )
    assert res.seed_count == 0  # no generic seeds matched
    assert res.synth_seed_count == 1  # ...but the synth seed carried the run
    assert any(f.startswith("synth_") for f in captured["seed_files"])
    assert res.directed_cov == 4712
    assert "synth seeds" in res.reason
