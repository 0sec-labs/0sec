"""Sink-basin seed selection — pure unit tests (mock the coverage subprocess).

The load-bearing claim is behavioural: given the wavpack shape — one island seed that
covers the v3 module (``unpack3_open.c``) plus a pile of v4 seeds that only cover the
shared dispatcher and the v4 decoder — the scorer must rank the island seed first,
autonomously, from the sink function alone. These tests reproduce that shape with
synthetic coverage so the ranking logic is verified without the binary.
"""

from __future__ import annotations

from zeroverse import sink_basin as sb
from zeroverse.dynamic_trace import CoveredFunc

# --- module-family membership ------------------------------------------------


def test_src_stem() -> None:
    assert sb._src_stem("/work/src/src/unpack3.c:265") == "unpack3"
    assert sb._src_stem("/a/b/unpack3_open.c:36") == "unpack3_open"
    assert sb._src_stem("foo.cpp:1") == "foo"


def test_in_module_family_stem_boundary() -> None:
    # exact + foo/foo_open in both directions
    assert sb.in_module_family("/x/unpack3.c:1", "unpack3")
    assert sb.in_module_family("/x/unpack3_open.c:1", "unpack3")
    assert sb.in_module_family("/x/unpack3.c:1", "unpack3_open")
    # the '_' boundary stops 'unpack' from swallowing 'unpack3' (the whole point)
    assert not sb.in_module_family("/x/unpack.c:1", "unpack3")
    assert not sb.in_module_family("/x/unpack_utils.c:1", "unpack3")
    assert not sb.in_module_family("/x/read_words.c:1", "unpack3")
    # empty stem -> never in-family (module signal unavailable)
    assert not sb.in_module_family("/x/unpack3.c:1", "")


def test_bare_name() -> None:
    assert sb._bare_name("open_file3") == "open_file3"
    assert sb._bare_name("LibRaw::parseAdobeRAFMakernote()") == "parseAdobeRAFMakernote"
    assert sb._bare_name("hb_sanitize_context_t::sanitize<OT::cff2>()") == "sanitize"


# --- the wavpack separation (synthetic coverage) -----------------------------


def _island_cov() -> list[CoveredFunc]:
    """The non-poc v3 island seed: reaches the v3 open on unpack3_open.c but is
    truncated before the sink. Covers the shared dispatcher too."""
    return [
        CoveredFunc("WavpackOpenFileInputEx64", 1, 5, 10, "/s/open_utils.c:80"),
        CoveredFunc("open_file3", 1, 14, 92, "/s/unpack3_open.c:36"),
        CoveredFunc("get_sample_index3", 1, 2, 3, "/s/unpack3_open.c:257"),
    ]


def _v4_cov() -> list[CoveredFunc]:
    """A v4 seed: decodes audio through the shared dispatcher and the v4 decoder, but
    touches NOTHING in the v3 (unpack3*) module."""
    return [
        CoveredFunc("WavpackOpenFileInputEx64", 1, 8, 10, "/s/open_utils.c:80"),
        CoveredFunc("WavpackUnpackSamples", 1, 20, 35, "/s/unpack_utils.c:125"),
        CoveredFunc("unpack_samples", 1, 12, 22, "/s/unpack.c:200"),
        CoveredFunc("read_words", 1, 30, 60, "/s/read_words.c:449"),
    ]


# undirected call-graph distances to the sink (unpack_samples3), as measured on the
# real binary: the shared hub is dist 1, the v3-open siblings dist 2.
_CG = {
    "unpack_samples3": 0,
    "WavpackUnpackSamples": 1,
    "unpack_init3": 1,
    "open_file3": 2,
    "get_sample_index3": 2,
    "unpack_samples": 2,
}


def test_score_one_island_beats_v4() -> None:
    stem = "unpack3"
    island = sb._score_one("island", _island_cov(), "unpack_samples3", stem, _CG)
    v4 = sb._score_one("v4", _v4_cov(), "unpack_samples3", stem, _CG)
    # the island seed covers two unpack3_open functions -> module credit; v4 covers none
    assert island.module_funcs == 2
    assert v4.module_funcs == 0
    assert island.score > v4.score
    assert not island.reaches_sink and not v4.reaches_sink


def test_module_signal_survives_without_callgraph() -> None:
    """Even with NO call graph (stripped/objdump-less), the module signal alone
    separates island from v4."""
    stem = "unpack3"
    island = sb._score_one("island", _island_cov(), "unpack_samples3", stem, {})
    v4 = sb._score_one("v4", _v4_cov(), "unpack_samples3", stem, {})
    assert island.score > 0 and v4.score == 0
    assert island.score > v4.score


def test_callgraph_signal_survives_without_module(monkeypatch) -> None:
    """With NO module stem (no DWARF), the corpus-common subtraction makes the
    call-graph term alone favour the island: the shared dispatcher (near the sink but
    covered by most v4 seeds) is subtracted as common, leaving the island's RARE
    dist-2 v3-open siblings as the only basin credit. Routed through score_seeds so the
    corpus-common set is computed from the real corpus."""
    covmap = _fake_cov_map()
    monkeypatch.setattr(
        sb, "_covered_staged",
        lambda binary, seed_paths, **kw: covmap[seed_paths[0]],
    )
    monkeypatch.setattr(sb, "callgraph_distances", lambda *a, **k: _CG)
    monkeypatch.setattr(sb, "sink_source_stem", lambda *a, **k: "")  # no DWARF module
    res = sb.score_seeds("vuln", "unpack_samples3", list(covmap))
    assert res.sink_module_stem == ""                 # module signal off
    assert res.ranked[0].seed == "island"             # call-graph alone still finds it
    assert res.on_basin_count == 1


def test_reaches_sink_bonus_dominates() -> None:
    stem = "unpack3"
    cov = [
        *_island_cov(),
        CoveredFunc("unpack_samples3", 1, 1, 521, "/s/unpack3.c:265"),
    ]
    deep = sb._score_one("deep", cov, "unpack_samples3", stem, _CG)
    shallow = sb._score_one("shallow", _island_cov(), "unpack_samples3", stem, _CG)
    assert deep.reaches_sink and not shallow.reaches_sink
    assert deep.score >= shallow.score + sb._REACHES_SINK_BONUS


def test_hub_functions_earn_no_callgraph_credit() -> None:
    """A seed that only touches harness/runtime hubs (LLVMFuzzer/malloc) scores 0 even
    though those may be call-graph-adjacent."""
    cov = [
        CoveredFunc("LLVMFuzzerTestOneInput", 9, 1, 1, "/s/fuzzer.cc:1"),
        CoveredFunc("malloc", 9, 1, 1, "/s/malloc.c:1"),
    ]
    cg = {"unpack_samples3": 0, "LLVMFuzzerTestOneInput": 2, "malloc": 1}
    bs = sb._score_one("junk", cov, "unpack_samples3", "unpack3", cg)
    assert bs.score == 0.0


# --- end-to-end scoring + selection (mock covered_functions) -----------------


def _fake_cov_map() -> dict[str, list[CoveredFunc]]:
    m = {f"v4_{i}": _v4_cov() for i in range(5)}
    m["island"] = _island_cov()
    m["junk"] = [CoveredFunc("LLVMFuzzerTestOneInput", 1, 1, 1, "/s/fuzzer.cc:1")]
    return m


def test_score_seeds_ranks_island_first(monkeypatch) -> None:
    covmap = _fake_cov_map()
    monkeypatch.setattr(
        sb, "_covered_staged",
        lambda binary, seed_paths, **kw: covmap[seed_paths[0]],
    )
    monkeypatch.setattr(sb, "callgraph_distances", lambda *a, **k: _CG)
    res = sb.score_seeds(
        "vuln", "unpack_samples3", list(covmap), sink_source_file="/s/unpack3.c"
    )
    assert res.sink_module_stem == "unpack3"
    assert res.ranked[0].seed == "island"           # the machine found the island
    assert res.on_basin_count == 1                    # only the island is on-basin
    assert all(b.score == 0 for b in res.ranked if b.seed != "island")


def test_select_picks_island(monkeypatch) -> None:
    covmap = _fake_cov_map()
    monkeypatch.setattr(
        sb, "_covered_staged",
        lambda binary, seed_paths, **kw: covmap[seed_paths[0]],
    )
    monkeypatch.setattr(sb, "callgraph_distances", lambda *a, **k: _CG)
    res = sb.score_seeds(
        "vuln", "unpack_samples3", list(covmap), sink_source_file="/s/unpack3.c"
    )
    sb.select_basin_seeds(res, top_k=8)
    assert res.selected == ["island"]
    assert not res.used_fallback


def test_select_fallback_when_no_basin(monkeypatch) -> None:
    """When NO seed reaches the basin, selection falls back to top-coverage and flags
    the synthesis regime honestly."""
    covmap = {f"v4_{i}": _v4_cov() for i in range(3)}
    monkeypatch.setattr(
        sb, "_covered_staged",
        lambda binary, seed_paths, **kw: covmap[seed_paths[0]],
    )
    monkeypatch.setattr(sb, "callgraph_distances", lambda *a, **k: {})
    res = sb.score_seeds(
        "vuln", "unpack_samples3", list(covmap), sink_source_file="/s/unpack3.c"
    )
    sb.select_basin_seeds(res, top_k=2)
    assert res.on_basin_count == 0
    assert res.used_fallback
    assert len(res.selected) == 2
    assert "synthesis regime" in res.note


# --- call-graph recovery from objdump text -----------------------------------


def test_callgraph_distances_from_objdump(monkeypatch) -> None:
    dump = "\n".join(
        [
            "0000000000001000 <WavpackUnpackSamples>:",
            "    1001:\tcall   2000 <unpack_samples3>",
            "0000000000002000 <unpack_samples3>:",
            "    2001:\tcall   3000 <get_word3>",
            "0000000000003000 <get_word3>:",
            "    3001:\tret",
            "0000000000004000 <unrelated>:",
            "    4001:\tcall   5000 <other>",
        ]
    )
    monkeypatch.setattr(
        sb.subprocess, "run",
        lambda *a, **k: type("R", (), {"stdout": dump})(),
    )
    dist = sb.callgraph_distances("vuln", "unpack_samples3", maxhop=3)
    assert dist["unpack_samples3"] == 0
    assert dist["WavpackUnpackSamples"] == 1  # caller (undirected)
    assert dist["get_word3"] == 1              # callee
    assert "unrelated" not in dist             # disconnected component
