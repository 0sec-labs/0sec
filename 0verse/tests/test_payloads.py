"""Integer-boundary trigger synthesis for the memory-safety confirmer."""

from zeroverse.payloads import (
    _parse_ints,
    boundary_payloads,
    memsafe_candidates,
)


def test_legacy_payload_is_first() -> None:
    # `b"A"*4096` must stay first: it confirms a flat copy in one execution and
    # preserves the historical PoV shape (tests/test_dynamic.py pins len==4096).
    cands = memsafe_candidates("")
    assert cands[0] == b"A" * 4096


def test_boundary_probes_carry_extreme_sizes() -> None:
    probes = boundary_payloads()
    # the canonical wrap value packed as little-endian u32 must be present as a
    # header prefix — this is what drives a size field to -1 / SIZE_MAX.
    assert any(p.startswith(b"\xff\xff\xff\xff") for p in probes)
    # INT_MIN little-endian u32 (0x80000000) — signed*positive multiply wraps.
    assert any(p.startswith(b"\x00\x00\x00\x80") for p in probes)


def test_probes_have_a_large_body() -> None:
    # each probe is <header> + <large body> so a slipped bound overruns.
    for p in boundary_payloads(max_payloads=4):
        assert len(p) > 4096


def test_parse_ints_extracts_hex_and_big_decimals() -> None:
    got = _parse_ints("width 0xFFFFFFFF or 65536 bytes, offset 4")
    assert 0xFFFFFFFF in got
    assert 65536 in got
    assert 4 not in got  # small offsets are not size drivers


def test_input_example_ints_are_folded_in() -> None:
    # a value the LLM names that isn't in the default boundary set still appears.
    cands = memsafe_candidates("try a length of 0x0BADF00D", max_payloads=512)
    assert any(p.startswith((0x0BADF00D).to_bytes(4, "little")) for p in cands)


def test_candidates_are_deterministic_and_deduped() -> None:
    a = memsafe_candidates("0xFFFFFFFF")
    b = memsafe_candidates("0xFFFFFFFF")
    assert a == b
    assert len(a) == len(set(a))  # no duplicates
