"""Binarygym ARVO adapter + LOCATE/CONFIRM split — hermetic tests (no Docker/Ghidra).

Covers the parts of the #51 deliverable that run anywhere:

  * ``arvo.load_recipes`` parses the committed recipe manifest (arvo:64166 / lcms) into
    an ``ArvoTask`` with the right LOCATE/CONFIRM metadata + a ``CleanBuildRecipe``.
  * ``arvo.clean_build_script`` emits the *exact* detune (ASan removed, StandaloneMain
    driver, clean liblcms rebuild) — the recipe that made WriteCLUT decompile cleanly.
  * ``arvo.locate_confirm_split`` returns (clean LOCATE, ASan CONFIRM), with a safe
    fallback to the ASan build when no clean build was materialized.
  * the 0verse ``pipeline.run`` / ``api.ScanOptions`` LOCATE/CONFIRM knob exists and is
    threaded through (default None == the old single-binary behaviour).
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

BG_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "binarygym"
sys.path.insert(0, str(BG_DIR))

import arvo as bg_arvo  # noqa: E402


def test_load_recipes_64166_locate_confirm_metadata() -> None:
    tasks = bg_arvo.load_recipes()
    assert tasks, "the committed manifest must carry at least the lcms recipe"
    t = next(x for x in tasks if x.arvo_id == 64166)
    assert t.id == "arvo:64166"
    assert t.project == "lcms"
    assert t.cwe == "CWE-787"                      # derived from the crash class
    assert t.fuzz_target == "cms_postscript_fuzzer"
    assert t.expected_function == "WriteCLUT"      # the LOCATE ground-truth hint
    assert t.split == "arvo-precutoff" and t.post_cutoff is False
    # the split itself:
    assert t.locate_binary == "vuln_clean"
    assert t.confirm_binary == "vuln"
    assert t.clean_build is not None
    assert t.clean_build.src_subdir == "lcms"
    # binaries are recipe-only: the vuln/fixed/poc hashes are pinned, clean is not.
    assert set(t.sha256) == {"vuln", "fixed", "poc"}


def test_cwe_for_maps_crash_classes() -> None:
    assert bg_arvo.cwe_for("Dynamic-stack-buffer-overflow WRITE") == "CWE-787"
    assert bg_arvo.cwe_for("Heap-buffer-overflow READ") == "CWE-125"
    assert bg_arvo.cwe_for("Heap-use-after-free") == "CWE-416"
    assert bg_arvo.cwe_for("something-unmapped") == ""


def test_clean_build_script_is_the_detune() -> None:
    t = next(x for x in bg_arvo.load_recipes() if x.arvo_id == 64166)
    assert t.clean_build is not None
    script = bg_arvo.clean_build_script(t.clean_build)
    # the whole point: NO AddressSanitizer in the LOCATE build.
    assert "-fsanitize=address" not in script
    # libFuzzer replaced by a plain standalone main + a clean liblcms rebuild.
    assert "StandaloneMain.c" in script
    assert "LLVMFuzzerTestOneInput" in bg_arvo._STANDALONE_MAIN_C
    assert "./configure --enable-shared=no" in script
    assert "liblcms2.a" in script
    assert "/out/vuln_clean" in script


def test_locate_confirm_split_prefers_clean_with_fallback(tmp_path: Path) -> None:
    tdir = tmp_path / "arvo__64166"
    tdir.mkdir()
    (tdir / "vuln").write_bytes(b"asan-build")
    # no clean build yet -> LOCATE falls back to the ASan build (task still runs).
    loc, conf = bg_arvo.locate_confirm_split(tdir)
    assert loc == tdir / "vuln"
    assert conf == tdir / "vuln"
    # once the clean build exists, LOCATE points at it, CONFIRM stays ASan.
    (tdir / "vuln_clean").write_bytes(b"clean-build")
    loc, conf = bg_arvo.locate_confirm_split(tdir)
    assert loc == tdir / "vuln_clean"
    assert conf == tdir / "vuln"


def test_task_to_dict_roundtrips_split_fields() -> None:
    t = next(x for x in bg_arvo.load_recipes() if x.arvo_id == 64166)
    d = t.to_dict()
    for key in ("locate_binary", "confirm_binary", "clean_build", "expected_function"):
        assert key in d
    assert d["clean_build"]["src_subdir"] == "lcms"


def test_pipeline_and_api_expose_confirm_binary() -> None:
    from zeroverse import api
    from zeroverse.pipeline import run as pipeline_run

    assert "confirm_binary" in inspect.signature(pipeline_run).parameters
    opts = api.ScanOptions()
    assert opts.confirm_binary is None            # default == single-binary behaviour


def test_api_scan_threads_confirm_binary(tmp_path: Path, monkeypatch) -> None:
    """api.scan must forward opts.confirm_binary to pipeline.run unchanged."""
    from zeroverse import api
    from zeroverse.pipeline import RunResult, triage

    probe = tmp_path / "locate.bin"
    probe.write_bytes(b"not-a-real-elf")
    captured: dict[str, object] = {}

    def fake_run(path, **kwargs):
        captured["path"] = str(path)
        captured["confirm_binary"] = kwargs.get("confirm_binary")
        return RunResult(triage=triage(probe))

    monkeypatch.setattr(api, "run", fake_run)
    api.scan(str(probe), api.ScanOptions(confirm_binary="/some/vuln_asan"))
    assert captured["path"] == str(probe)
    assert captured["confirm_binary"] == "/some/vuln_asan"
