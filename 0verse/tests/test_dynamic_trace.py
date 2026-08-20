"""Dynamic reachability recovery — pure unit tests (mock the coverage subprocess)."""

from __future__ import annotations

from types import SimpleNamespace

from zeroverse import dynamic_trace as dt


def test_cov_line_parse() -> None:
    line = (
        "COVERED_FUNC: hits: 3 edges: 12/40 LibRaw::parseAdobeRAFMakernote() "
        "/src/libraw/src/metadata/fuji.cpp:210"
    )
    m = dt._COV_RE.match(line)
    assert m and m.group(1) == "3" and m.group(4) == "LibRaw::parseAdobeRAFMakernote()"
    assert m.group(5) == "/src/libraw/src/metadata/fuji.cpp:210"


def test_norm_strips_namespace_args_templates() -> None:
    assert dt._norm("LibRaw::parseAdobeRAFMakernote()") == "parseAdobeRAFMakernote"
    assert dt._norm("hb_sanitize_context_t::sanitize_blob<OT::cff2>()") == "sanitize_blob"
    assert dt._norm("parse_tiff") == "parse_tiff"


def test_dynamic_slice_keeps_parsers_drops_noise(monkeypatch) -> None:
    """Only parser-module / reader functions survive; ordered by hits (outer first);
    mapped to decompiled keys; sink appended if coverage missed it."""
    covered = [
        dt.CoveredFunc(
            "LibRaw::parse_tiff(int)", 50, 10, 20, "/src/libraw/src/metadata/tiff.cpp:100"
        ),
        dt.CoveredFunc(
            "LibRaw::parse_makernote_0xc634(int,int)",
            30,
            5,
            40,
            "/src/libraw/src/metadata/tiff.cpp:1531",
        ),
        dt.CoveredFunc(
            "LibRaw::wavelet_denoise()", 5, 1, 73, "/src/libraw/src/postprocessing/aux.cpp:35"
        ),
        dt.CoveredFunc("std::vector<char>::~vector()", 999, 1, 6, "/usr/include/c++/v1/vector:402"),
        dt.CoveredFunc(
            "sget4_order(short, unsigned char*)",
            20,
            2,
            3,
            "/src/libraw/src/utils/read_utils.cpp:63",
        ),
    ]
    monkeypatch.setattr(dt, "covered_functions", lambda b, s, **kw: covered)
    dc = {
        "parse_tiff": "x",
        "parse_makernote_0xc634": "x",
        "wavelet_denoise": "x",
        "sget4_order": "x",
        "parseAdobeRAFMakernote": "x",
    }
    meta = SimpleNamespace(decompiled_c=dc)
    verdict = SimpleNamespace(sink="parseAdobeRAFMakernote OOB via sget4")
    sl = dt.dynamic_reach_slice("/t/vuln", ["seed.dng"], meta, verdict)
    assert "parse_tiff" in sl and "parse_makernote_0xc634" in sl  # parser-module fns
    assert "sget4_order" in sl  # reader helper
    assert "wavelet_denoise" not in sl  # postprocessing dropped
    assert "vector" not in " ".join(sl)  # C++ runtime dropped
    assert sl[0] == "parse_tiff"  # most hits = outermost
    assert sl[-1] == "parseAdobeRAFMakernote"  # sink anchor appended


def test_dynamic_slice_empty_without_seeds_or_coverage(monkeypatch) -> None:
    meta = SimpleNamespace(decompiled_c={"f": "x"})
    v = SimpleNamespace(sink="f")
    assert dt.dynamic_reach_slice("/t/vuln", [], meta, v) == []
    monkeypatch.setattr(dt, "covered_functions", lambda b, s, **kw: [])
    assert dt.dynamic_reach_slice("/t/vuln", ["s"], meta, v) == []
