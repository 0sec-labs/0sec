"""Input synthesis — turn a scanner hypothesis into a CONFIRMED bug WITH NO poc.

Hermetic unit tests: a stub LLM replays canned hex candidates and
``adjudicate_finding`` is monkeypatched, so the module's context-pulling, hex
decoding, and the synthesize->adjudicate confirm loop are exercised with no
network, no binary, and no Ghidra. The real end-to-end reproduce is a bench
experiment run by the integrator, not a CI test.
"""

from __future__ import annotations

from typing import Any

import pytest

from zeroverse import synthesize
from zeroverse.adjudicate import (
    CONFIRMED,
    NO_CRASH,
    Adjudication,
)
from zeroverse.agentic import AgentVerdict
from zeroverse.synthesize import (
    apply_structural_fixups,
    confirm_by_synthesis,
    synthesize_povs,
    synthesize_povs_diagnostic,
)


class StubLLM:
    """Records the (system, prompt, schema) it saw and replays a canned response."""

    def __init__(self, response: dict[str, Any] | Exception) -> None:
        self.response = response
        self.system = ""
        self.prompt = ""
        self.schema: dict[str, Any] | None = None

    def complete_json(self, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        self.system, self.prompt, self.schema = system, prompt, schema
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class _Meta:
    """Minimal ProgramMeta stand-in: just the decompiled_c map the synthesizer reads."""

    def __init__(self, decompiled_c: dict[str, str]) -> None:
        self.decompiled_c = decompiled_c


def _verdict() -> AgentVerdict:
    return AgentVerdict(
        is_bug=True,
        cwe="CWE-787",
        sink="WriteCLUT",
        source="LLVMFuzzerTestOneInput",
        explanation="a palette count of 257 gives _Size=771 into a 768-byte buffer",
    )


def _meta() -> _Meta:
    return _Meta(
        {
            "LLVMFuzzerTestOneInput": (
                "int LLVMFuzzerTestOneInput(char *data, int size){ parse_header(data); }"
            ),
            "parse_palette": (
                "void parse_palette(char *p){ int n = p[4]; for (i=0;i<n;i++) WriteCLUT(i); }"
            ),
            "WriteCLUT": "void WriteCLUT(int i){ out_buf[i*3] = 0; /* 768-byte out_buf */ }",
        }
    )


# --- (a) decode hex candidates, skip the malformed one ----------------------


def test_synthesize_povs_decodes_and_skips_malformed() -> None:
    good1 = bytes.fromhex("deadbeef")
    good2 = bytes.fromhex("01020304")
    llm = StubLLM(
        {
            "candidates": [
                {"bytes_hex": "deadbeef", "rationale": "count=257 (boundary)"},
                {"bytes_hex": "zzzz", "rationale": "not hex — must be skipped"},
                {"bytes_hex": "abc", "rationale": "odd length — must be skipped"},
                {"bytes_hex": "01020304", "rationale": "count=1024 (well past)"},
            ]
        }
    )
    out = synthesize_povs(_meta(), _verdict(), llm, n=6, visited=["parse_palette"])
    assert out == [good1, good2]


def test_synthesize_povs_degrades_to_empty_on_backend_error() -> None:
    llm = StubLLM(RuntimeError("codex backend down"))
    out = synthesize_povs(_meta(), _verdict(), llm, n=6)
    assert out == []


def test_synthesis_diagnostic_distinguishes_backend_error_from_empty_output() -> None:
    failed = synthesize_povs_diagnostic(
        _meta(), _verdict(), StubLLM(TimeoutError("secret-bearing backend detail"))
    )
    empty = synthesize_povs_diagnostic(
        _meta(), _verdict(), StubLLM({"candidates": [{"bytes_hex": "not-hex"}]})
    )

    assert failed.status == "backend-error"
    assert failed.candidates == ()
    assert failed.error_type == "TimeoutError"
    assert "secret" not in failed.error_type
    assert empty.status == "empty"
    assert empty.candidates == ()
    assert empty.error_type == ""


def test_synthesis_diagnostic_reports_valid_deduplicated_candidates() -> None:
    batch = synthesize_povs_diagnostic(
        _meta(),
        _verdict(),
        StubLLM({"candidates": ["deadbeef", "deadbeef", "0102"]}),
    )

    assert batch.status == "ok"
    assert batch.candidates == (bytes.fromhex("deadbeef"), bytes.fromhex("0102"))


def test_synthesis_diagnostic_rejects_oversized_hex_before_decode(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        synthesize,
        "_decode_hex",
        lambda raw: (_ for _ in ()).throw(AssertionError("oversized hex was decoded")),
    )
    batch = synthesize_povs_diagnostic(
        _meta(),
        _verdict(),
        StubLLM({"candidates": ["aa" * 5]}),
        max_candidate_bytes=4,
    )

    assert batch.status == "empty"
    assert batch.candidates == ()


def test_synthesize_povs_accepts_plain_string_array() -> None:
    llm = StubLLM({"candidates": ["deadbeef", "cafebabe"]})
    out = synthesize_povs(_meta(), _verdict(), llm, n=6)
    assert out == [bytes.fromhex("deadbeef"), bytes.fromhex("cafebabe")]


# --- (d) the prompt carries the sink + the parser body ----------------------


def test_prompt_includes_sink_and_parser_body() -> None:
    llm = StubLLM({"candidates": []})
    synthesize_povs(_meta(), _verdict(), llm, n=6, visited=["parse_palette"])
    # the finding's sink and the concrete trigger condition are present
    assert "WriteCLUT" in llm.prompt
    assert "palette count of 257" in llm.prompt
    # the visited parser body (the reverse-engineered format) is pulled in verbatim
    assert "parse_palette" in llm.prompt
    assert "int n = p[4]" in llm.prompt
    # and the source (entry) body too
    assert "LLVMFuzzerTestOneInput" in llm.prompt


# --- (b) the 3rd candidate confirms -> confirmed, winning_input == that one --


def test_confirm_by_synthesis_third_candidate_confirms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c1 = bytes.fromhex("01000000")
    c2 = bytes.fromhex("02000000")
    c3 = bytes.fromhex("03000000")
    llm = StubLLM(
        {
            "candidates": [
                {"bytes_hex": c1.hex()},
                {"bytes_hex": c2.hex()},
                {"bytes_hex": c3.hex()},
            ]
        }
    )

    def fake_adjudicate(verdict, vuln_binary, poc_input, **kwargs) -> Adjudication:
        if bytes(poc_input) == c3:
            return Adjudication(
                status=CONFIRMED,
                crash_function="WriteCLUT",
                crash_cwe="CWE-787",
                reason="crash at WriteCLUT matches",
            )
        return Adjudication(status=NO_CRASH, reason="clean exit")

    monkeypatch.setattr(synthesize, "adjudicate_finding", fake_adjudicate)

    res = confirm_by_synthesis(_meta(), _verdict(), "/bench/vuln", llm, n=6)
    assert res.confirmed is True
    assert res.winning_input == c3
    assert res.adjudication is not None and res.adjudication.status == CONFIRMED
    assert res.tried == 3  # stopped as soon as #3 won


# --- (c) all NO_CRASH -> not confirmed, tried == n --------------------------


def test_confirm_by_synthesis_all_no_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    cands = [bytes([i]) * 4 for i in range(1, 5)]  # 4 distinct candidates
    llm = StubLLM({"candidates": [{"bytes_hex": c.hex()} for c in cands]})

    def fake_adjudicate(verdict, vuln_binary, poc_input, **kwargs) -> Adjudication:
        return Adjudication(status=NO_CRASH, reason="clean exit")

    monkeypatch.setattr(synthesize, "adjudicate_finding", fake_adjudicate)

    res = confirm_by_synthesis(_meta(), _verdict(), "/bench/vuln", llm, n=4)
    assert res.confirmed is False
    assert res.winning_input is None
    assert res.tried == 4  # every synthesized candidate was tried
    assert res.tried == len(cands)
    # honest near-miss: the best outcome recorded is the NO_CRASH
    assert res.adjudication is not None and res.adjudication.status == NO_CRASH


def test_confirm_by_synthesis_no_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    llm = StubLLM({"candidates": []})
    res = confirm_by_synthesis(_meta(), _verdict(), "/bench/vuln", llm, n=6)
    assert res.confirmed is False
    assert res.tried == 0
    assert res.adjudication is None


# --- a DIVERGENT crash AT the sink still counts as a reproduction -----------


def test_confirm_by_synthesis_divergent_at_sink_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from zeroverse.adjudicate import DIVERGENT

    c1 = bytes.fromhex("aa000000")
    llm = StubLLM({"candidates": [{"bytes_hex": c1.hex()}]})

    def fake_adjudicate(verdict, vuln_binary, poc_input, **kwargs) -> Adjudication:
        # crashes AT the hypothesized sink but ASan labelled a different class
        return Adjudication(
            status=DIVERGENT,
            crash_function="WriteCLUT",
            crash_cwe="CWE-416",
            reason="crashes at the sink, different class",
        )

    monkeypatch.setattr(synthesize, "adjudicate_finding", fake_adjudicate)

    res = confirm_by_synthesis(_meta(), _verdict(), "/bench/vuln", llm, n=6)
    assert res.confirmed is True
    assert res.winning_input == c1
    assert res.adjudication is not None and res.adjudication.status == DIVERGENT


class RoutingLLM:
    """Routes to a synth response or a fix-up response by the schema it is handed.

    ``synthesize_povs`` passes a schema with an ``invariants`` property (structure-aware)
    or a bare ``candidates`` schema (plain); ``apply_structural_fixups`` passes a schema
    with a ``gates`` property (gate specs). Records the last prompt/system seen on each route."""

    def __init__(self, synth: dict[str, Any], fixup: dict[str, Any] | Exception) -> None:
        self.synth = synth
        self.fixup = fixup
        self.synth_system = ""
        self.synth_prompt = ""
        self.fixup_system = ""
        self.fixup_prompt = ""

    def complete_json(self, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        props = schema.get("properties", {})
        if "gates" in props:
            self.fixup_system, self.fixup_prompt = system, prompt
            if isinstance(self.fixup, Exception):
                raise self.fixup
            return self.fixup
        self.synth_system, self.synth_prompt = system, prompt
        return self.synth


# --- (a) the structure-aware prompt asks for invariants + names the gates ----


def test_structural_prompt_asks_for_invariants_and_names_gates() -> None:
    llm = StubLLM({"candidates": []})
    synthesize_povs(_meta(), _verdict(), llm, n=6, visited=["parse_palette"], structural=True)
    sys_prompt = llm.system + "\n" + llm.prompt
    low = sys_prompt.lower()
    # STEP 1 must demand the structural invariants be derived and stated
    assert "invariant" in low
    assert "step 1" in low and "step 2" in low
    # every gate family the protocol must reason about is named
    for gate in ("magic", "version", "length", "count", "offset", "checksum", "endian"):
        assert gate in low, gate
    # both strategies are offered
    assert "boundary" in low and "poisoned record" in low
    # the schema exposes an invariants array for the model to fill in
    assert "invariants" in (llm.schema or {}).get("properties", {})
    # the concrete finding is still present
    assert "WriteCLUT" in llm.prompt


def test_structural_false_uses_plain_prompt_unchanged() -> None:
    llm = StubLLM({"candidates": []})
    synthesize_povs(_meta(), _verdict(), llm, n=6, visited=["parse_palette"])
    # the plain system prompt has no two-step invariant-derivation protocol
    assert "STEP 1" not in llm.prompt and "STEP 1" not in llm.system
    assert "invariants" not in (llm.schema or {}).get("properties", {})


# --- (b) apply_structural_fixups recomputes the gate fields ------------------


def test_apply_structural_fixups_recomputes_length_prefix_deterministically() -> None:
    # [u32 LE length prefix @0][2 payload bytes ffff]; prefix stale (0). The LLM returns the
    # gate STRUCTURE only; deterministic Python computes the byte count (2) exactly.
    broken = bytes.fromhex("00000000ffff")
    llm = StubLLM(
        {
            "gates": [
                {
                    "type": "length_prefix",
                    "field_offset": 0,
                    "field_width": 4,
                    "endianness": "le",
                    "covered_start": 4,
                    "covered_end": -1,
                    "algo": "byte_count",
                }
            ]
        }
    )
    out = apply_structural_fixups(broken, _verdict(), _meta(), llm, visited=["parse_palette"])
    assert out == bytes.fromhex("02000000ffff")  # length prefix recomputed to 2 (exact math)
    assert broken.hex() in llm.prompt and "parse_palette" in llm.prompt


def test_apply_gate_specs_math_is_exact() -> None:
    from zeroverse.synthesize import apply_gate_specs

    # additive checksum u8 @0 over [1:] = sum(01,02,03) & 0xff = 6
    assert apply_gate_specs(
        bytes.fromhex("00010203"),
        [
            {
                "type": "checksum",
                "field_offset": 0,
                "field_width": 1,
                "endianness": "le",
                "covered_start": 1,
                "covered_end": -1,
                "algo": "additive_sum",
            }
        ],
    ) == bytes.fromhex("06010203")
    # xor-fold u8 @0 over [1:] = 01^02^03 = 0
    assert apply_gate_specs(
        bytes.fromhex("ff010203"),
        [
            {
                "type": "checksum",
                "field_offset": 0,
                "field_width": 1,
                "endianness": "le",
                "covered_start": 1,
                "covered_end": -1,
                "algo": "xor",
            }
        ],
    ) == bytes.fromhex("00010203")
    # big-endian u16 length prefix @0 over [2:] (4 bytes) = 0x0004
    assert apply_gate_specs(
        bytes.fromhex("0000aabbccdd"),
        [
            {
                "type": "length_prefix",
                "field_offset": 0,
                "field_width": 2,
                "endianness": "be",
                "covered_start": 2,
                "covered_end": -1,
                "algo": "byte_count",
            }
        ],
    ) == bytes.fromhex("0004aabbccdd")
    # crc32 / unknown -> left UNCHANGED (honestly unfixable)
    assert apply_gate_specs(
        bytes.fromhex("ff010203"),
        [
            {
                "type": "checksum",
                "field_offset": 0,
                "field_width": 1,
                "endianness": "le",
                "covered_start": 1,
                "covered_end": -1,
                "algo": "crc32",
            }
        ],
    ) == bytes.fromhex("ff010203")


def test_apply_gate_specs_length_patched_before_checksum() -> None:
    from zeroverse.synthesize import apply_gate_specs

    # [len u8 @0][cksum u8 @1][payload 2 bytes]; checksum covers [0:2] (incl. the length).
    # Length must be patched first (=2) so the checksum sees the corrected length byte.
    out = apply_gate_specs(
        bytes.fromhex("00000a0b"),
        [
            {
                "type": "checksum",
                "field_offset": 1,
                "field_width": 1,
                "endianness": "le",
                "covered_start": 0,
                "covered_end": 2,
                "algo": "additive_sum",
            },
            {
                "type": "length_prefix",
                "field_offset": 0,
                "field_width": 1,
                "endianness": "le",
                "covered_start": 2,
                "covered_end": -1,
                "algo": "byte_count",
            },
        ],
    )
    # length@0 = 2; then checksum@1 = (len(2) + cksum-field-before-patch... covers [0:2] AFTER
    # length patched) = byte0(2) + byte1(current cksum, which is being written) -> sum of
    # covered bytes as they stand when the checksum is computed: byte0=2, byte1=0 -> 2.
    assert out[0] == 2 and out[1] == 2


def test_apply_structural_fixups_unfixable_returns_original() -> None:
    # a crypto/CRC/compression gate the model honestly cannot recompute
    broken = bytes.fromhex("00000000ffff")
    llm = StubLLM(
        {
            "bytes_hex": bytes.fromhex("00000000ffff").hex(),
            "unfixable": True,
            "fixes": [],
        }
    )
    out = apply_structural_fixups(broken, _verdict(), _meta(), llm)
    assert out == broken  # unchanged — honest about the crypto/compression limit


def test_apply_structural_fixups_backend_error_returns_original() -> None:
    broken = bytes.fromhex("00000000ffff")
    llm = StubLLM(RuntimeError("codex backend down"))
    out = apply_structural_fixups(broken, _verdict(), _meta(), llm)
    assert out == broken  # degrades to the original candidate, never crashes


def test_apply_structural_fixups_undecodable_returns_original() -> None:
    broken = bytes.fromhex("00000000ffff")
    llm = StubLLM({"bytes_hex": "not-hex-at-all"})
    out = apply_structural_fixups(broken, _verdict(), _meta(), llm)
    assert out == broken


# --- (c) a gate-failing candidate is fixed up and then CONFIRMs --------------


def test_confirm_structural_fixup_confirms(monkeypatch: pytest.MonkeyPatch) -> None:
    naive = bytes.fromhex("00000000ffff")  # overflows target but stale length -> NO_CRASH
    fixed = bytes.fromhex("02000000ffff")  # length prefix DETERMINISTICALLY recomputed to 2
    llm = RoutingLLM(
        synth={"candidates": [{"bytes_hex": naive.hex()}]},
        # the fix-up now returns a gate SPEC; apply_gate_specs computes the value exactly
        fixup={
            "gates": [
                {
                    "type": "length_prefix",
                    "field_offset": 0,
                    "field_width": 4,
                    "endianness": "le",
                    "covered_start": 4,
                    "covered_end": -1,
                    "algo": "byte_count",
                }
            ]
        },
    )

    def fake_adjudicate(verdict, vuln_binary, poc_input, **kwargs) -> Adjudication:
        if bytes(poc_input) == fixed:
            return Adjudication(
                status=CONFIRMED,
                crash_function="WriteCLUT",
                crash_cwe="CWE-787",
                reason="crash at WriteCLUT after gate satisfied",
            )
        return Adjudication(status=NO_CRASH, reason="rejected at length gate")

    monkeypatch.setattr(synthesize, "adjudicate_finding", fake_adjudicate)

    res = confirm_by_synthesis(_meta(), _verdict(), "/bench/vuln", llm, n=6, structural=True)
    assert res.confirmed is True
    assert res.winning_input == fixed  # the FIXED candidate reproduced, not the naive one
    assert res.adjudication is not None and res.adjudication.status == CONFIRMED
    assert res.tried == 2  # naive NO_CRASH, then the fixed variant CONFIRMed
    # the fix-up route actually ran
    assert naive.hex() in llm.fixup_prompt


def test_confirm_structural_no_fixup_when_first_candidate_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good = bytes.fromhex("06000000ffff")
    llm = RoutingLLM(
        synth={"candidates": [{"bytes_hex": good.hex()}]},
        fixup=RuntimeError("fix-up must not be called when the candidate already wins"),
    )

    def fake_adjudicate(verdict, vuln_binary, poc_input, **kwargs) -> Adjudication:
        return Adjudication(status=CONFIRMED, crash_function="WriteCLUT", crash_cwe="CWE-787")

    monkeypatch.setattr(synthesize, "adjudicate_finding", fake_adjudicate)

    res = confirm_by_synthesis(_meta(), _verdict(), "/bench/vuln", llm, n=6, structural=True)
    assert res.confirmed is True and res.winning_input == good
    assert res.tried == 1  # no wasted fix-up adjudication
    assert llm.fixup_prompt == ""  # the fix-up route was never taken


def test_confirm_structural_fixup_noop_not_readjudicated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # fix-up returns the SAME bytes (unfixable / no change) -> not adjudicated twice
    naive = bytes.fromhex("00000000ffff")
    llm = RoutingLLM(
        synth={"candidates": [{"bytes_hex": naive.hex()}]},
        fixup={"bytes_hex": naive.hex(), "unfixable": True},
    )
    calls: list[bytes] = []

    def fake_adjudicate(verdict, vuln_binary, poc_input, **kwargs) -> Adjudication:
        calls.append(bytes(poc_input))
        return Adjudication(status=NO_CRASH, reason="rejected at gate")

    monkeypatch.setattr(synthesize, "adjudicate_finding", fake_adjudicate)

    res = confirm_by_synthesis(_meta(), _verdict(), "/bench/vuln", llm, n=6, structural=True)
    assert res.confirmed is False
    assert res.tried == 1  # the identical fix-up was NOT re-adjudicated
    assert calls == [naive]


# --- (d) the plain (structural=False) confirm path is unchanged --------------


def test_confirm_plain_path_never_calls_fixup(monkeypatch: pytest.MonkeyPatch) -> None:
    naive = bytes.fromhex("00000000ffff")
    llm = RoutingLLM(
        synth={"candidates": [{"bytes_hex": naive.hex()}]},
        fixup=RuntimeError("fix-up must never run on the plain path"),
    )

    def fake_adjudicate(verdict, vuln_binary, poc_input, **kwargs) -> Adjudication:
        return Adjudication(status=NO_CRASH, reason="clean exit")

    monkeypatch.setattr(synthesize, "adjudicate_finding", fake_adjudicate)

    res = confirm_by_synthesis(
        _meta(), _verdict(), "/bench/vuln", llm, n=6
    )  # structural defaults False
    assert res.confirmed is False
    assert res.tried == 1  # one candidate, no fix-up retry
    assert llm.fixup_prompt == ""


def test_is_win_same_family_divergent_counts_as_reproduction():
    """The Ghidra-inlined-parser case: a DIVERGENT crash of the same CWE family (OOB
    write 787 vs claimed OOB 121) at a differently-labeled function is a real
    reproduction from targeted synthesis — must win. Cross-family (UAF) must NOT."""
    from zeroverse.adjudicate import DIVERGENT, Adjudication
    from zeroverse.agentic import AgentVerdict
    from zeroverse.synthesize import _is_win

    v = AgentVerdict(
        is_bug=True, cwe="CWE-121", sink="main memcpy", source="parse_tlv", explanation=""
    )
    oob = Adjudication(status=DIVERGENT, crash_function="handle_record", crash_cwe="CWE-787")
    assert _is_win(oob, v) is True  # same OOB family -> reproduction
    uaf = Adjudication(status=DIVERGENT, crash_function="freed_thing", crash_cwe="CWE-416")
    assert _is_win(uaf, v) is False  # cross-family -> not a reproduction
