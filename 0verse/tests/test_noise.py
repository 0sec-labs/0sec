"""Unit tests for backends/_noise.py — the symbol-noise classifier and the
decompile-budget scaling. Engine-free: pure string/number logic, no r2/Ghidra.

Two guards matter here:
  * STL-internal demangled names (printed WITHOUT ``std::``) MUST classify as noise
    so they stop polluting the candidate top-N.
  * Realistic APP function names MUST NOT — over-matching would drop the function
    that actually holds the bug (a false negative on the finding).
"""

from __future__ import annotations

import pytest

from zeroverse.backends import _noise
from zeroverse.backends._noise import decomp_budget_s, decomp_max_funcs, is_noise_name

# --- STL demangled-without-std:: internals: MUST be noise --------------------
STL_INTERNAL_NOISE = [
    # the exact names seen polluting the libraw/harfbuzz candidate top-15
    "_Floating_to_chars_hex_precision",
    "_Floating_to_chars_general_precision",
    "_Adjust_manually_vector_aligned",
    # <charconv> integer/number-formatting family — the leak that made a libc++
    # helper a bug hypothesis (no callers, not fuzz-reachable)
    "_Large_integer_to_chars",
    "_Integer_to_chars",
    "_Unsigned_to_chars",
    "_Signed_from_chars",
    "_Integer_from_chars",
    "__to_chars_integer",          # libc++ double-underscore form (via __ prefix rule)
    "__to_chars_10",
    "sym._Large_integer_to_chars",  # with a decompiler prefix
    # MSVC reserved throw helpers
    "_Xlength_error",
    "_Xout_of_range",
    "_Xbad_alloc",
    "_Xbad_function_call",
    "_Xinvalid_argument",
    "_Throw_bad_array_new_length",
    "_Throw_Cpp_error",
    # allocation / uninitialized-range helpers
    "_Uninitialized_copy",
    "_Uninitialized_move_n",
    "_Reallocate_grow_by",
    "_Emplace_reallocate",
    "_Convert_size",
    # container/iterator internals + template-class tokens (qualifier kept)
    "char_traits<char>::length",
    "basic_string<char,std::char_traits<char>,std::allocator<char>>::append",
    "_Rb_tree_increment",
    "_Rb_tree_iterator<int>::operator++",
    "_Hashtable_node",
    "_Vector_base<int>::_M_deallocate",
    "_Sp_counted_base::_M_release",
    "__normal_iterator<char*>::operator*",
    "_List_node_base::hook",
    "basic_ostream<char>::flush",
    "_Deque_base<int>::_M_initialize_map",
    # with a decompiler prefix
    "sym._Floating_to_chars_hex_precision",
]

# --- realistic app functions: MUST NOT be noise (over-match guard) -----------
APP_NOT_NOISE = [
    # libraw / harfbuzz / generic parser-ish names
    "parse_metadata",
    "read_ifd",
    "libraw_dcraw_process",
    "hb_buffer_add",
    "process_tiff_tag",
    "decode_thumbnail",
    "find_glyph",
    "png_read_row",
    # bare common verbs Ghidra strips off std::basic_string:: — deliberately kept
    # (zero stdlib signal left; matching them would drop real app funcs)
    "append",
    "remove",
    "insert",
    "find",
    "erase",
    "length",
    "size",
    # names that merely CONTAIN an STL-ish token but are not stdlib internals
    "Vector3_normalize",          # "Vector" but not "_Vector_base"
    "create_allocator",           # "allocator" but not "allocator<"
    "basic_auth_header",          # "basic_" but not "basic_string"
    "string_copy",
    "remove_prefix_bytes",
    "char_at",
    "Adjust_gamma",               # no leading "_", so "_Adjust_manually" cannot hit
    "_Xml_parse",                 # reserved-ish "_X" but enumerated regex avoids it
    "traits_of_char",            # "char_traits" reversed — not a substring hit
    # names that merely CONTAIN "chars"/"integer"/"to_chars" but are NOT reserved
    # stdlib internals: no leading "_"+Uppercase "_to_chars" token, so they stay
    # candidates (matching them would drop the real bug — a false negative).
    "convert_to_chars",           # app "to_chars" but no leading "_"+Uppercase
    "write_chars_to_buffer",
    "integer_to_string",
    "parse_integer",
    "num_chars_written",
    "char_count",
    "from_charset",               # contains "from_chars"+set but no "_"+Uppercase prefix
    "to_chars_helper",
]


@pytest.mark.parametrize("name", STL_INTERNAL_NOISE)
def test_stl_internals_are_noise(name: str) -> None:
    assert is_noise_name(name) is True, f"{name!r} should be classified as noise"


@pytest.mark.parametrize("name", APP_NOT_NOISE)
def test_app_functions_are_not_noise(name: str) -> None:
    assert is_noise_name(name) is False, f"{name!r} must NOT be classified as noise"


def test_charconv_leak_regression() -> None:
    # the exact function that leaked into a real hunt as a bug hypothesis.
    assert is_noise_name("_Large_integer_to_chars") is True
    # and its family — both to_chars and from_chars, single- and double-underscore.
    for n in ("_Integer_to_chars", "_Floating_to_chars_hex_precision",
              "_Unsigned_from_chars", "__to_chars_integer"):
        assert is_noise_name(n) is True
    # FP guard: an app fn that merely contains the tokens is NOT noise.
    for n in ("convert_to_chars", "integer_to_string", "num_chars_written"):
        assert is_noise_name(n) is False


def test_ubsan_handlers_and_magma_canary_are_noise() -> None:
    # bare demangled UBSan/CFI handlers + the magma canary logger leaked into the
    # fuzz selector on the magma isan build; exact-match drops them.
    for n in ("handleOutOfBoundsImpl", "handleShiftOutOfBoundsImpl",
              "isDerivedFromAtOffset", "FindModuleForAddress", "magma_log",
              "__ubsan::handleOutOfBoundsImpl"):
        assert is_noise_name(n) is True, n
    # FP guard: real libpng functions from the same run stay selectable.
    for n in ("png_check_chunk_length", "png_combine_row", "decode_gamma",
              "png_icc_tag_name"):
        assert is_noise_name(n) is False, n


def test_libfuzzer_entry_still_exempt() -> None:
    # regression: the reachability root must survive the classifier.
    assert is_noise_name("LLVMFuzzerTestOneInput") is False


def test_attack_surface_priority_is_ordering_only() -> None:
    for name in (
        "js::WasmDecoder::decodeModule",
        "ParseJSONText",
        "StructuredCloneReader::read",
        "FontFileParser",
    ):
        assert _noise.attack_surface_priority(name) == 0
        assert is_noise_name(name) is False
    assert _noise.attack_surface_priority("TelemetryCounter::increment") == 1


def test_prior_runtime_noise_still_matches() -> None:
    # regression: the pre-existing sanitizer/std:: rules are untouched.
    for n in ("__asan_report_load8", "std::__throw_length_error", "_ZNSt6vectorIiE"):
        assert is_noise_name(n) is True


# --- budget scaling ----------------------------------------------------------
def _clear_env(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv(_noise.ENV_BUDGET, raising=False)
    monkeypatch.delenv(_noise.ENV_MAX_FUNCS, raising=False)


def test_budget_small_binary_unchanged(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _clear_env(monkeypatch)
    # small / unknown -> the old flat 300s floor, byte-for-byte.
    assert decomp_budget_s(0) == _noise.DECOMP_BUDGET_BASE_S == 300.0
    assert decomp_budget_s(50) == 300.0
    assert decomp_budget_s(400) == 300.0  # 400*0.75=300 -> still floor


def test_budget_scales_up_for_large_target(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _clear_env(monkeypatch)
    # libraw's 2316 target funcs needed ~1500s; scaled budget must clear that bar.
    b = decomp_budget_s(2316)
    assert b == pytest.approx(2316 * _noise.DECOMP_BUDGET_PER_FUNC_S)
    assert b >= 1500.0


def test_budget_ceiling(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _clear_env(monkeypatch)
    assert decomp_budget_s(1_000_000) == _noise.DECOMP_BUDGET_CEIL_S == 3600.0


def test_budget_env_override_wins_verbatim(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv(_noise.ENV_BUDGET, "1500")
    # override applied verbatim regardless of function count (no scaling).
    assert decomp_budget_s(10) == 1500.0
    assert decomp_budget_s(9999) == 1500.0


def test_budget_monotonic_nondecreasing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _clear_env(monkeypatch)
    seq = [decomp_budget_s(n) for n in (0, 100, 1000, 5000, 100000)]
    assert seq == sorted(seq)


def test_max_funcs_small_and_scaling(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _clear_env(monkeypatch)
    assert decomp_max_funcs(0) == _noise.DECOMP_MAX_FUNCS_BASE == 4000
    assert decomp_max_funcs(50) == 4000          # floor: small unchanged
    assert decomp_max_funcs(2316) == 4000        # below floor -> no truncation
    assert decomp_max_funcs(5000) == 5000        # tracks the candidate count
    assert decomp_max_funcs(1_000_000) == _noise.DECOMP_MAX_FUNCS_CEIL == 20000


def test_max_funcs_env_override_wins(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv(_noise.ENV_MAX_FUNCS, "6000")
    assert decomp_max_funcs(10) == 6000
    assert decomp_max_funcs(50000) == 6000
