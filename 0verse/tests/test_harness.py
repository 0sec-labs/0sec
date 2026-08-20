"""#16 harness synthesis — signature recovery, template, and the feedback loop."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from zeroverse.fuzz import harness as H
from zeroverse.fuzz.harness import (
    CompileResult,
    GccCompiler,
    HarnessSpec,
    HarnessSynthesizer,
    TargetSignature,
    build_harness,
    exported_symbol,
    internal_harness_specs,
    internal_symbol_offset,
    recover_signature,
    template_harness,
    template_harness_dlsym,
)

GHIDRA_C = "int parse_record(byte *data,int len)\n{\n  char buf[32];\n}\n"


def test_recover_signature_basic() -> None:
    sig = recover_signature("parse_record", GHIDRA_C)
    assert sig is not None
    assert sig.name == "parse_record"
    assert sig.ret_type == "int"
    # byte* -> unsigned char *, int -> int
    assert any("*" in t for t, _ in sig.params)
    assert ("int", "len") in sig.params or any(t == "int" for t, _ in sig.params)
    assert sig.is_fuzzable


def test_void_param_not_fuzzable() -> None:
    sig = recover_signature("main", "undefined8 main(void)\n{\n}\n")
    assert sig is not None
    assert not sig.is_fuzzable


def test_call_expr_wires_buffer_and_len() -> None:
    sig = TargetSignature("f", "int", [("unsigned char *", "p"), ("int", "n")])
    call = sig.call_expr("data", "len")
    assert call == "f((unsigned char *)data, (int)len);"


def test_template_has_persistent_block_and_sentinel() -> None:
    spec = HarnessSpec(func="parse_record", signature=recover_signature("parse_record", GHIDRA_C))
    src = template_harness(spec)
    assert "__AFL_LOOP" in src
    assert "ZEROVERSE_REACH:parse_record" in src
    assert "extern int parse_record" in src
    assert "read(0" in src


class _FakeCompiler:
    """Fails the first ``fail_until`` compiles, then succeeds."""

    def __init__(self, fail_until: int = 0) -> None:
        self.fail_until = fail_until
        self.calls = 0

    def compile(
        self, source: str, out: Path, *, defines: list[str], objects: list[Path]
    ) -> CompileResult:
        self.calls += 1
        if self.calls <= self.fail_until:
            return CompileResult(ok=False, stderr="error: expected ';'")
        out.write_text("binary")
        return CompileResult(ok=True, binary=out)


def test_build_harness_repairs_compile_errors(tmp_path: Path) -> None:
    comp = _FakeCompiler(fail_until=2)
    synth = HarnessSynthesizer(llm=None)  # template-mode repair
    hb = build_harness(
        HarnessSpec(func="parse_record", signature=recover_signature("parse_record", GHIDRA_C)),
        synthesizer=synth, compiler=comp, objects=[], workdir=tmp_path,
        max_repair=3, reach_check=False,
    )
    assert hb.ok
    assert hb.attempts == 3  # 2 failures + 1 success
    assert comp.calls == 3


def test_build_harness_gives_up_after_max_repair(tmp_path: Path) -> None:
    comp = _FakeCompiler(fail_until=99)
    hb = build_harness(
        HarnessSpec(func="f"), synthesizer=HarnessSynthesizer(None),
        compiler=comp, objects=[], workdir=tmp_path, max_repair=2, reach_check=False,
    )
    assert not hb.ok
    assert hb.reason == "compile-failed"
    assert len(hb.errors) == 3


class _FailingLLM:
    """A backend that always raises — stands in for a rate-limited/erroring model."""

    def complete_json(
        self, system: str, prompt: str, schema: dict[str, object]
    ) -> dict[str, object]:
        raise RuntimeError("simulated backend failure")


def test_synth_degrades_to_template_on_llm_error() -> None:
    spec = HarnessSpec(func="parse_record", signature=recover_signature("parse_record", GHIDRA_C))
    h = HarnessSynthesizer(llm=_FailingLLM()).synthesize(spec)
    assert not h.from_llm
    assert "llm-synth-failed" in h.notes
    assert "__AFL_LOOP" in h.source          # the deterministic template still fuzzes
    assert "extern int parse_record" in h.source


def test_repair_degrades_to_template_on_llm_error() -> None:
    spec = HarnessSpec(func="f")
    base = HarnessSynthesizer(None).synthesize(spec)
    h = HarnessSynthesizer(llm=_FailingLLM()).repair(base, "error: undefined reference")
    assert not h.from_llm
    assert "llm-repair-failed" in h.notes
    assert h.rounds == base.rounds + 1


def test_build_harness_reach_failure_then_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    def fake_probe(binary: Path, func: str, timeout: float = 10.0) -> H.ReachResult:
        calls["n"] += 1
        return H.ReachResult(reached=calls["n"] >= 2, note="probe")

    monkeypatch.setattr(H, "_run_reach_probe", fake_probe)
    obj = tmp_path / "t.o"
    obj.write_text("x")
    hb = build_harness(
        HarnessSpec(func="f"), synthesizer=HarnessSynthesizer(None),
        compiler=_FakeCompiler(0), objects=[obj], workdir=tmp_path,
        max_repair=3, reach_check=True,
    )
    assert hb.ok
    assert hb.reach is not None and hb.reach.reached
    assert calls["n"] == 2  # failed once, repaired, reached on the second probe


# --- dlsym / binary-only harness -------------------------------------------

CJSON_C = "cJSON * cJSON_Parse(char *value)\n{\n}\n"


def test_dlsym_template_wires_dlopen_dlsym_and_call() -> None:
    """The binary-only harness resolves the target at runtime (no extern link)."""
    spec = HarnessSpec(
        func="cJSON_Parse", signature=recover_signature("cJSON_Parse", CJSON_C),
        lib=Path("/opt/lib/libcjson.so"),
    )
    assert spec.is_dlsym
    src = template_harness(spec)  # dispatches to the dlsym variant on spec.lib
    # `cJSON *` has no header in a binary-only harness -> reduced to opaque void *.
    assert "typedef void * (*zeroverse_fn_t)(char *);" in src
    assert "dlopen(" in src and "dlsym(h" in src
    assert 'ZEROVERSE_DLOPEN_FAIL' in src and 'ZEROVERSE_DLSYM_FAIL' in src
    assert "libcjson.so" in src                       # baked-in absolute lib path
    assert "zeroverse_fn((char *)buf);" in src        # call through the fn pointer
    assert "__AFL_LOOP" in src                        # persistent-mode block kept
    assert "ZEROVERSE_REACH:cJSON_Parse" in src       # reach sentinel kept
    assert "extern " not in src                       # no link-time symbol


def test_dlsym_template_requires_lib() -> None:
    with pytest.raises(ValueError):
        template_harness_dlsym(HarnessSpec(func="f"))


def test_dlsym_out_params_get_dedicated_scratch() -> None:
    """A pointer param beyond the first is an OUTPUT param: it must get its own
    zeroed scratch buffer, not the input buffer — aliasing an out-struct onto the
    exact-size input buffer is a false-positive overflow, not a target bug."""
    # decode(const void *data, int size, desc *out) — 1 input ptr + 1 out ptr.
    sig = recover_signature("decode", "int decode(unsigned char *data, int size, desc_t *out)")
    assert sig.out_pointer_count() == 1
    spec = HarnessSpec(func="decode", signature=sig, lib=Path("/opt/lib/dec.so"))
    src = template_harness(spec)
    assert "void *out0 = calloc(1, ZEROVERSE_SCRATCH);" in src
    # input ptr -> buf; out ptr -> out0 (opaque desc_t* -> void*); size -> len.
    assert "zeroverse_fn((unsigned char *)buf, (int)len, (void *)out0);" in src
    assert "free(out0);" in src


def test_dlsym_param_roles_decompressor_capacity() -> None:
    """A decompressor fn(in, in_len, out, out_cap): the out-CAPACITY int must be the
    scratch size (0 would decode nothing) — impossible to infer from types, so roles
    drive it. Contrast the heuristic which would zero that int."""
    sig = recover_signature(
        "dec",
        "int dec(const void *in, unsigned in_len, void *out, unsigned out_cap)",
    )
    spec = HarnessSpec(
        func="dec", signature=sig, lib=Path("/opt/lib/d.so"),
        param_roles=["input", "length", "output", "capacity"],
    )
    src = template_harness(spec)
    assert "void *out0 = calloc(1, ZEROVERSE_SCRATCH);" in src
    # in -> buf, in_len -> len, out -> out0 scratch, out_cap -> ZEROVERSE_SCRATCH (not 0)
    assert (
        "zeroverse_fn((void *)buf, (unsigned)len, (void *)out0, "
        "(unsigned)ZEROVERSE_SCRATCH);"
    ) in src


def test_dlsym_param_roles_input_not_first_pointer() -> None:
    """Roles let the input be a NON-first pointer (e.g. LoadEXRFromMemory-style,
    where out-pointers precede the input buffer)."""
    sig = recover_signature(
        "load",
        "int load(float **out_img, int *w, const unsigned char *mem, int size)",
    )
    spec = HarnessSpec(
        func="load", signature=sig, lib=Path("/opt/lib/x.so"),
        param_roles=["output", "output", "input", "length"],
    )
    src = template_harness(spec)
    assert src.count("calloc(1, ZEROVERSE_SCRATCH)") == 2       # out_img + w
    assert (
        "(void *)buf, (int)len);" in src
        or "(unsigned char *)buf" in src
    )


def test_param_roles_length_mismatch_rejected() -> None:
    sig = recover_signature("f", "int f(void *a, int b)")
    with pytest.raises(ValueError):
        HarnessSpec(func="f", signature=sig, lib=Path("/x.so"), param_roles=["input"])
    with pytest.raises(ValueError):
        HarnessSpec(func="f", signature=sig, lib=Path("/x.so"), param_roles=["input", "bogus"])


def test_dlsym_single_input_pointer_has_no_scratch() -> None:
    """A single-pointer entry (the input) needs no scratch buffer."""
    sig = recover_signature("cJSON_Parse", CJSON_C)
    spec = HarnessSpec(func="cJSON_Parse", signature=sig, lib=Path("/opt/lib/x.so"))
    src = template_harness(spec)
    assert "calloc(1, ZEROVERSE_SCRATCH)" not in src
    assert "zeroverse_fn((char *)buf);" in src


def test_dlsym_synth_is_deterministic_even_with_llm() -> None:
    """dlsym mode never routes through the LLM: the exported call is fully
    determined by the signature and an extern harness could not link anyway."""
    spec = HarnessSpec(
        func="cJSON_Parse", signature=recover_signature("cJSON_Parse", CJSON_C),
        lib=Path("/opt/lib/libcjson.so"),
    )
    h = HarnessSynthesizer(llm=_FailingLLM()).synthesize(spec)  # would raise if called
    assert not h.from_llm
    assert "dlsym" in h.source
    assert h.notes == "dlsym binary-only mode"


# The compile+link+dlopen path needs an ELF toolchain; per repo discipline these
# run on the Linux bench, and skip on hosts without cc/nm (e.g. a dev macOS box).
_LINUX_CC = sys.platform.startswith("linux") and shutil.which("cc") is not None
_needs_toolchain = pytest.mark.skipif(
    not _LINUX_CC, reason="dlsym build/link test needs a Linux cc toolchain (bench)"
)


def _build_so(src: str, out: Path) -> bool:
    csrc = out.with_suffix(".c")
    csrc.write_text(src)
    p = subprocess.run(
        ["cc", "-O0", "-fPIC", "-shared", str(csrc), "-o", str(out)],
        capture_output=True, check=False,
    )
    return p.returncode == 0


# An exported entry point that internally reaches a bug, plus a static helper that
# must NOT be seen as an exported dlsym target.
_LIB_C = """
#include <string.h>
static int internal_helper(const unsigned char *p) { return p ? p[0] : 0; }
int parse_rec(const unsigned char *data, int len) {
    /* deterministic reach; the fuzz/asan build is what surfaces a real bug */
    return len > 0 ? internal_helper(data) : 0;
}
"""


@_needs_toolchain
def test_exported_symbol_detects_exported_not_static(tmp_path: Path) -> None:
    so = tmp_path / "libt.so"
    assert _build_so(_LIB_C, so)
    assert exported_symbol(so, "parse_rec")            # exported entry point
    assert not exported_symbol(so, "internal_helper")  # static: not a dlsym target
    assert not exported_symbol(so, "does_not_exist")


@_needs_toolchain
def test_exported_symbol_rejects_dynamic_data(tmp_path: Path) -> None:
    so = tmp_path / "libdata.so"
    assert _build_so("int exported_data = 7;", so)
    assert not exported_symbol(so, "exported_data")


@_needs_toolchain
def test_build_harness_dlsym_reaches_with_no_object_files(tmp_path: Path) -> None:
    """The milestone gap-closer: reach-validate a harness against a binary-only
    shared object with ZERO target object files — the function is resolved at
    runtime via dlopen+dlsym, links only -ldl."""
    so = tmp_path / "libt.so"
    assert _build_so(_LIB_C, so)
    assert exported_symbol(so, "parse_rec")
    spec = HarnessSpec(
        func="parse_rec",
        signature=recover_signature(
            "parse_rec",
            "int parse_rec(unsigned char *data,int len)\n{\n}\n",
        ),
        lib=so,
    )
    hb = build_harness(
        spec, synthesizer=HarnessSynthesizer(None),
        compiler=GccCompiler(link_libs=("-ldl",)),
        objects=[],  # <-- the whole point: nothing to link against
        workdir=tmp_path, max_repair=1, reach_check=True,
    )
    assert hb.ok, (hb.reason, hb.errors)
    assert hb.reach is not None and hb.reach.reached
    assert hb.binary is not None and hb.binary.exists()


@_needs_toolchain
def test_dlsym_harness_delivers_stdin_to_exported_target(tmp_path: Path) -> None:
    so = tmp_path / "libt.so"
    assert _build_so(_LIB_C, so)
    spec = HarnessSpec(
        func="parse_rec",
        signature=recover_signature(
            "parse_rec", "int parse_rec(unsigned char *data,int len)\n{\n}\n"
        ),
        lib=so,
    )
    hb = build_harness(
        spec, synthesizer=HarnessSynthesizer(None),
        compiler=GccCompiler(link_libs=("-ldl",)), objects=[],
        workdir=tmp_path, max_repair=1, reach_check=True,
    )
    assert hb.ok and hb.binary is not None
    run = subprocess.run([str(hb.binary)], input=b"REC0", capture_output=True, check=False)
    assert run.returncode == 0
    assert b"ZEROVERSE_REACH:parse_rec" in run.stderr


# --- stripped-internal (non-exported by address) mode ----------------------

def test_addr_mode_template_resolves_by_load_base_offset() -> None:
    """An INTERNAL (non-exported) target has no dynamic symbol, so the harness must
    resolve it as dlopen load-base + offset (dlinfo), never dlsym."""
    sig = recover_signature(
        "internal_parse",
        "int internal_parse(const unsigned char *data, int len)",
    )
    spec = HarnessSpec(
        func="internal_parse",
        signature=sig,
        lib=Path("/opt/lib/x.so"),
        func_offset=0x2530,
    )
    src = template_harness(spec)
    assert "dlinfo(h, RTLD_DI_LINKMAP" in src
    assert "lm->l_addr + (unsigned long)ZEROVERSE_TARGET_OFFSET" in src
    assert f"#define ZEROVERSE_TARGET_OFFSET {0x2530}UL" in src
    assert 'dlsym(h,' not in src          # no dlsym CALL in address mode
    assert "#define _GNU_SOURCE" in src and "#include <link.h>" in src


@_needs_toolchain
def test_internal_symbol_offset_finds_static_non_exported(tmp_path: Path) -> None:
    so = tmp_path / "libt.so"
    assert _build_so(_LIB_C, so)
    # internal_helper is static: NOT a dlsym target, but has a static-symtab offset.
    assert not exported_symbol(so, "internal_helper")
    off = internal_symbol_offset(so, "internal_helper")
    assert off is not None and off > 0
    assert internal_symbol_offset(so, "does_not_exist") is None


def test_internal_harness_specs_from_ghidra_fun_names() -> None:
    """Wiring: Ghidra names a non-exported/stripped function FUN_<entry>. The addr-mode
    spec's offset is entry - image_base, so a function with NO symbol is fuzzable."""
    functions = ["container_load", "FUN_00102560"]  # exported (dlsym) + internal (addr)
    decompiled = {"FUN_00102560": "int FUN_00102560(byte *data, int len)\n{\n}\n"}
    specs = internal_harness_specs(functions, decompiled, "/opt/lib/x.so", image_base=0x100000)
    assert len(specs) == 1 and specs[0].func == "FUN_00102560"   # only the internal one
    assert specs[0].func_offset == 0x2560                        # 0x102560 - 0x100000
    src = template_harness(specs[0])
    assert "dlinfo(h, RTLD_DI_LINKMAP" in src
    assert f"#define ZEROVERSE_TARGET_OFFSET {0x2560}UL" in src


@_needs_toolchain
def test_build_harness_addr_mode_reaches_internal_function(tmp_path: Path) -> None:
    """The stripped-internal milestone: reach-validate a harness that calls a
    NON-exported internal function by dlopen-base + offset, with zero object files
    and no dynamic symbol to dlsym."""
    so = tmp_path / "libt.so"
    assert _build_so(_LIB_C, so)
    off = internal_symbol_offset(so, "internal_helper")
    assert off is not None
    assert not exported_symbol(so, "internal_helper")     # genuinely non-exported
    spec = HarnessSpec(
        func="internal_helper",
        signature=recover_signature(
            "internal_helper",
            "int internal_helper(const unsigned char *p)",
        ),
        lib=so, func_offset=off,
    )
    hb = build_harness(
        spec, synthesizer=HarnessSynthesizer(None),
        compiler=GccCompiler(link_libs=("-ldl",)),
        objects=[], workdir=tmp_path, max_repair=1, reach_check=True,
    )
    assert hb.ok, (hb.reason, hb.errors)
    assert hb.reach is not None and hb.reach.reached


# --- repair history accumulates instead of overwriting (issue #1705) --------


def test_repair_history_accumulates_across_rounds() -> None:
    # `rounds` was incremented but nothing carried WHAT failed into the next
    # prompt, so round 3 could reintroduce what round 1 was repaired for.
    spec = HarnessSpec(func="f")
    h0 = HarnessSynthesizer(None).synthesize(spec)
    synth = HarnessSynthesizer(None)
    h1 = synth.repair(h0, "error: undefined reference to `f'")
    h2 = synth.repair(h1, "error: too few arguments to function `f'")

    assert h0.repair_history == []
    assert h1.repair_history == ["error: undefined reference to `f'"]
    assert h2.repair_history == [
        "error: undefined reference to `f'",
        "error: too few arguments to function `f'",
    ]
    assert h2.rounds == 2


def test_repair_prompt_replays_the_whole_failure_history() -> None:
    spec = HarnessSpec(func="f")
    base = HarnessSynthesizer(None).synthesize(spec)
    base.repair_history = ["round-one error", "round-two error"]
    prompt = HarnessSynthesizer._repair_prompt(base, "round-three error")

    assert "round-three error" in prompt          # the current one, as before
    assert "round-one error" in prompt            # and every earlier one
    assert "round-two error" in prompt
    assert "2 round(s) so far" in prompt
    assert "Do not reintroduce" in prompt


def test_repair_prompt_history_is_bounded() -> None:
    spec = HarnessSpec(func="f")
    base = HarnessSynthesizer(None).synthesize(spec)
    base.repair_history = [f"error-{i}" for i in range(20)]
    prompt = HarnessSynthesizer._repair_prompt(base, "current")
    assert prompt.count("error-") == H._MAX_REPAIR_HISTORY
    assert "error-19" in prompt and "error-0\n" not in prompt


def test_repair_history_survives_a_degraded_round() -> None:
    # A template fallback that is repaired again must still know the earlier errors.
    spec = HarnessSpec(func="f")
    base = HarnessSynthesizer(None).synthesize(spec)
    h1 = HarnessSynthesizer(llm=_FailingLLM()).repair(base, "first error")
    assert "llm-repair-failed" in h1.notes
    assert h1.repair_history == ["first error"]
    h2 = HarnessSynthesizer(None).repair(h1, "second error")
    assert h2.repair_history == ["first error", "second error"]
