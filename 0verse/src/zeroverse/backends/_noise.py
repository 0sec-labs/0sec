"""Shared decompilation-scaling helpers for every backend.

A real ASan+libFuzzer target statically links the sanitizer runtime, libFuzzer,
libc++ and libc — tens of thousands of functions, almost none of which can hold
the target bug. Decompiling *every* function is what made the backends time out on
real binaries (the toy single-function extracts hid it). Backends use these helpers
to (1) skip runtime/library noise by symbol name and (2) bound the pass by a
wall-clock budget + a hard function cap.
"""

from __future__ import annotations

import os
import re

# Runtime/library name PREFIXES (sanitizers, libFuzzer, libstdc++, C++ runtime,
# libc/loader, CRT). A bare demangled target function never starts with these.
_NOISE_RE = re.compile(
    r"^(?:sym\.|sym\.imp\.|imp\.)?(?:"
    r"__asan|__hwasan|__lsan|__ubsan|__msan|__tsan|__sanitizer|__interceptor|"
    r"asan\.|_?_asan_|LLVMFuzzer|_ZN6fuzzer|fuzzer::|"
    r"_ZNSt|_ZNKSt|_ZSt|std::|__gnu_cxx|_ZN9__gnu_cxx|_ZNK|"
    r"__cxa_|__cxx|_Unwind_|__gxx|__dynamic_cast|"
    r"__libc_|__pthread|_dl_|__GI_|__|"
    r"_start|_init$|_fini$|register_tm|deregister_tm|frame_dummy|"
    r"_GLOBAL__|call_weak_fn|abort|_ZdlPv|_Znwm|_Znam"
    r")"
)

# Namespaces/markers that appear *embedded* in a demangled name (not just as a
# prefix): libFuzzer bundles its own libc++ under ``std::__Fuzzer::`` and its
# mutator methods live in ``fuzzer::``; template instantiations carry these inside
# angle brackets (``find<std::__Fuzzer::basic_string<...>>``), so a prefix match
# misses them.
_NOISE_SUBSTR: tuple[str, ...] = (
    "__Fuzzer", "fuzzer::", "std::", "__gnu_cxx", "__cxxabi", "__sanitizer",
    "operator new", "operator delete", "__cxx11",
)

# --- demangled STL internals WITHOUT a leading ``std::`` ---------------------
#
# Ghidra frequently demangles C++ standard-library internals with the ``std::``
# qualification STRIPPED (common on MSVC/PE targets, and on some libstdc++/libc++
# builds): e.g. ``_Floating_to_chars_hex_precision``, ``_Adjust_manually_vector_aligned``,
# a bare ``char_traits<char>::length``. The prefix/substring rules above key on
# ``std::`` / ``_ZNSt`` — exactly the marker that's missing here — so these leak
# into the candidate top-N as false-positive findings.
#
# PRECISION / RECALL TRADEOFF (read before adding tokens):
#   * Every token below is either (a) a C++ *reserved identifier* — ``_`` followed
#     by an uppercase letter, which the standard forbids application code from
#     defining, so a match is almost certainly stdlib — or (b) a full STL
#     template-class name (``basic_string``, ``char_traits``, ``_Rb_tree`` …) that
#     no realistic application function is named.
#   * We deliberately DO NOT list bare common verbs (``append``, ``remove``,
#     ``insert``, ``find``, ``erase``, ``length``, ``size``). Ghidra strips the
#     ``std::basic_string::`` off those leaving ZERO stdlib signal, and they are
#     perfectly ordinary app function names — matching them would drop real
#     candidates (a false negative on the actual bug). When such a member op keeps
#     its class qualifier (``basic_string<…>::append``), the class-name SUBSTR rule
#     below already catches it; that IS the gate — a broad verb is noise only when
#     accompanied by an STL class token in the same name. The residual cost is a
#     handful of truly-bare STL member ops staying in the pool; sink/reachability
#     ordering demotes them rather than us risking a real drop.
#   * The reserved-identifier regex is ENUMERATED (specific words), never a broad
#     ``_X[a-z]`` catch: that keeps app reserved-ish names like ``_Xml_parse`` out
#     of the match set.

# Reserved ``_Xxx`` STL-internal helper names, matched on the bare (namespace- and
# template-stripped) name. Anchored, optional decompiler ``sym.``/``imp.`` prefix.
_STL_INTERNAL_RE = re.compile(
    r"^(?:sym\.|imp\.)?_(?:"
    # <charconv> number-formatting internals — the integer/float <-> chars helpers
    # libc++/MSVC emit. Observed leak: ``_Large_integer_to_chars`` (no known callers,
    # not fuzz-reachable) became a bug hypothesis. This family also covers
    # ``_Integer_to_chars``, ``_Floating_to_chars_hex_precision`` and the ``*_from_chars``
    # inverses. The leading ``_`` is already consumed above, so the token requires an
    # UPPERCASE-led reserved qualifier THEN ``_to_chars``/``_from_chars`` — that anchors
    # on the reserved-identifier form and does NOT fire on an app fn that merely CONTAINS
    # "chars"/"integer" (``convert_to_chars``, ``char_at``, ``integer_parse`` have no
    # leading ``_``+Uppercase ``_to_chars`` token, so they stay candidates). The libc++
    # double-underscore form ``__to_chars_*`` is ALSO noise, already via the ``__``
    # reserved-prefix rule in ``_NOISE_RE``. Tokens documented: ``_Large_integer_to_chars``,
    # ``*_to_chars``, ``*_from_chars``, ``_Integer_to_chars``, ``_Floating_to_chars*``,
    # ``__to_chars_*``.
    r"[A-Z]\w*_(?:to|from)_chars\w*|Floating_to_chars\w*|Integer_to_chars\w*|"
    r"Adjust_manually\w*|"
    # throw helpers (reserved ``_X…`` identifiers) — enumerated, not ``_X[a-z]``
    r"X(?:length_error|out_of_range|bad_alloc|bad_function_call|invalid_argument|"
    r"overflow_error|underflow_error|range_error|domain_error|regex_error|"
    r"runtime_error|logic_error|len|ran)\w*|"
    r"Throw_\w+|"
    # allocation / uninitialized-range / reallocate helpers
    r"Uninitialized_\w+|Reallocate\w*|Deallocate\w*|Allocate_manually\w*|"
    r"Emplace_reallocate\w*|Convert_size\w*|Change_array\w*|"
    # container / iterator debug plumbing
    r"Container_base\w*|Iterator_base\w*|Orphan_\w+|Adopt_\w+|"
    # locale / lock / rng internals
    r"Getgloballocale\w*|Locinfo\w*|Lockit\w*|Getvals\w*|"
    r"Tidy\w*|Take_contents\w*|Xtime\w*"
    r")"
)

# Full STL template-class tokens, matched as a SUBSTRING of the (possibly still
# qualified) name — these appear both as the class of a member op and embedded in
# template argument lists. Each is STL-specific enough that no realistic app
# function name contains it (``allocator<`` is anchored by the ``<`` so it only
# hits a template instantiation, never an app ``create_allocator``).
_STL_CLASS_SUBSTR: tuple[str, ...] = (
    "basic_string", "basic_string_view", "basic_ostream", "basic_istream",
    "basic_iostream", "basic_streambuf", "basic_stringbuf", "basic_filebuf",
    "basic_ios", "basic_regex", "char_traits", "allocator<",
    "_Rb_tree", "_Hashtable", "_Hash_node", "_Hash_bytes",
    "_List_node", "_List_base", "_List_iterator", "_Fwd_list",
    "_Deque_base", "_Vector_base", "_Vector_val", "_Vector_alloc",
    "_String_val", "_String_base", "_Tree_val", "_Tree_node",
    "_Sp_counted", "_Sp_make_shared", "_Alloc_hider", "_Head_base",
    "_Tuple_impl", "__normal_iterator", "_Rb_tree_iterator", "_Container_proxy",
)

# The user-supplied libFuzzer entry point. The target-library code is REACHABLE
# from here; the libFuzzer *driver* is not (the driver CALLS this). It matches the
# ``LLVMFuzzer`` runtime prefix above, but it is the ONE ``LLVMFuzzer*`` symbol we
# must NOT drop — it is the root the reachability filter walks from, so we exempt
# it in ``is_noise_name`` below.
LIBFUZZER_ENTRY = "LLVMFuzzerTestOneInput"

# libFuzzer *driver* internal functions. Their demangled names are BARE (no
# ``fuzzer::`` namespace nor ``_ZN6fuzzer`` mangling), so the prefix/substring
# rules above miss them and they surface as false-positive findings on a real
# ASan+libFuzzer target. Matched as EXACT normalized names (see ``_norm``) to stay
# precise — a bare libc name a real target might also define (``snprintf``,
# ``getline``, ``insert``) is deliberately NOT listed; the reachability filter
# handles those.
LIBFUZZER_DRIVER_NAMES: frozenset[str] = frozenset({
    # mutation / merge / minimize
    "CrossOver", "Mutate_CrossOver", "Mutate_CustomCrossOver", "MutateImpl",
    "MutateAndTestOne", "FunctionWeights", "MinimizeCrashInput",
    "MinimizeCrashInputInternalStep", "MinimizeCrashLoop", "Merge", "MergeInner",
    # driver / loop / job control
    "FuzzerDriver", "RunOneTest", "RunOne", "ExecuteCallback",
    "ExecuteFilesOnyByOne", "FuzzWithFork", "CreateNewJob", "CloneArgsWithoutX",
    "RegisterCommonFlags", "CrashCallback", "StaticDeathCallback", "AlarmCallback",
    "RssLimitCallback", "PrintStats", "PrintFinalStats", "VPrintf",
    # allocation hooks / io helpers
    "HandleMalloc", "MallocHook", "FreeHook", "FileToVector", "ReadFileToVector",
    "ReadFileToBuffer", "WriteToFile", "ReadFile", "ReadDirToVectorOfUnits",
    "GetDedupTokenFromCmdOutput", "CollectFeatures", "ForEachNonZeroByte",
    # class ctors/dtors that Ghidra names bare
    "Fuzzer", "~Fuzzer", "TracePC", "~TracePC", "ValueBitMap",
})

# UBSan / CFI runtime handlers + the magma canary logger. Like the libFuzzer
# driver names these surface as BARE demangled symbols (``__ubsan::handleOut...``
# -> ``handleOutOfBoundsImpl``) that the prefix/substring rules miss, so a fuzz
# target compiled with -fsanitize=undefined (the magma isan build) leaks them into
# the fuzzable-function selector. Exact-match — a real target function is never
# named ``handle*Impl`` or ``magma_log``.
SANITIZER_RUNTIME_NAMES: frozenset[str] = frozenset({
    # __ubsan handlers (both the ``Impl`` core and the abort/recover wrappers)
    "handleTypeMismatchImpl", "handleAlignmentAssumptionImpl",
    "handleOutOfBoundsImpl", "handleShiftOutOfBoundsImpl",
    "handleLoadInvalidValue", "handleLoadInvalidValueImpl",
    "handleImplicitConversionImpl", "handleInvalidBuiltin",
    "handleFunctionTypeMismatch", "handlePointerOverflowImpl",
    "handleVLABoundNotPositive", "handleFloatCastOverflow",
    "handleNegateOverflowImpl", "handleDivremOverflowImpl",
    "handleAddOverflowImpl", "handleSubOverflowImpl", "handleMulOverflowImpl",
    "handleNonnullArg", "handleNonnullReturnV1", "handleNullabilityArg",
    "handleMissingReturn", "handleBuiltinUnreachableImpl",
    "handleCFIBadIcall", "handleCFICheckFailImpl",
    # __ubsan / CFI RTTI helpers
    "isDerivedFromAtOffset", "FindModuleForAddress", "getDynamicTypeInfoFromVtable",
    "checkDynamicType", "getDerivedTypeAtOffset",
    # magma canary logger (the fatal-canary bug reporter)
    "magma_log", "magma_alt",
})

# Sinks whose callers are the likeliest home of a memory-safety bug — decompile
# those callers first so a budget-truncated pass still reaches the buggy function.
DANGEROUS_SINKS: tuple[str, ...] = (
    "memcpy", "memmove", "mempcpy", "strcpy", "strncpy", "stpcpy", "strcat", "strncat",
    "sprintf", "vsprintf", "snprintf", "malloc", "calloc", "realloc", "alloca", "gets",
)

# Symbol-name hints for externally controlled parser/compiler surfaces.  These are
# ordering signals only: they never suppress a function or assert a vulnerability.
# On large non-libFuzzer products (browser shells, document/media tools), there is
# no LLVMFuzzerTestOneInput root and a sink-only order spends the bounded decompile
# budget on generic alloc/copy helpers.  Prefer recognizable input boundaries first.
_ATTACK_SURFACE_TOKENS: tuple[str, ...] = (
    "parse", "parser", "decode", "decoder", "deserialize", "unmarshal",
    "structuredclone", "xdr", "bytecode", "wasm", "webassembly", "regexp",
    "regex", "json", "xml", "stencil", "script", "module", "compile",
    "archive", "inflate", "decompress", "image", "font", "media", "packet",
)


def attack_surface_priority(name: str) -> int:
    """Return 0 for likely attacker-input boundaries, 1 otherwise.

    This is deliberately a priority rather than a filter: false positives cost a
    decompile slot, while false negatives remain in the queue and can still run in
    a larger campaign budget.
    """
    folded = name.casefold().replace("_", "")
    return 0 if any(token in folded for token in _ATTACK_SURFACE_TOKENS) else 1

# --- decompile budget: SCALES with the post-noise-filter function count ------
#
# A small target (a handful of functions) finishes well inside the base budget. A
# large real target does NOT: libraw has 2316 target functions after noise-filtering
# and at the old FLAT 300s default the pass truncated at ~826 functions — before the
# ground-truth metadata-parser region was ever decompiled (it needed ~1500s to reach
# it). So the wall-clock budget and the function cap now scale with the candidate
# count: enough budget to cover the whole target, FLOORED at the old default so
# small binaries are byte-for-byte unchanged, and CEILINGED so a pathological binary
# can't run unbounded. An explicit env override always wins and is applied verbatim
# (no scaling) — a deep run pins its own number.

ENV_BUDGET = "ZEROVERSE_DECOMPILE_BUDGET"
ENV_MAX_FUNCS = "ZEROVERSE_DECOMPILE_MAX_FUNCS"

DECOMP_BUDGET_BASE_S = 300.0      # floor == old flat default: small binaries unchanged
DECOMP_BUDGET_PER_FUNC_S = 0.75   # est. wall-clock per target function; 2316 -> ~1737s
DECOMP_BUDGET_CEIL_S = 3600.0     # hard ceiling: scaling never runs past 1 hour

DECOMP_MAX_FUNCS_BASE = 4000      # floor == old flat default: small/mid binaries unchanged
DECOMP_MAX_FUNCS_CEIL = 20000     # runaway guard for a pathological function count


def decomp_budget_s(n_funcs: int = 0) -> float:
    """Wall-clock decompile budget for a pass over ``n_funcs`` candidate functions.

    Env override (:data:`ENV_BUDGET`) wins and is returned verbatim. Otherwise the
    budget scales as ``n_funcs * DECOMP_BUDGET_PER_FUNC_S`` clamped to
    ``[BASE, CEIL]`` — a small binary keeps the 300s default, a 2316-func target gets
    ~1737s (enough to reach its GT region), and nothing runs past the 1h ceiling.
    """
    override = os.environ.get(ENV_BUDGET)
    if override is not None:
        return float(override)
    scaled = n_funcs * DECOMP_BUDGET_PER_FUNC_S
    return max(DECOMP_BUDGET_BASE_S, min(scaled, DECOMP_BUDGET_CEIL_S))


def decomp_max_funcs(n_funcs: int = 0) -> int:
    """Hard function cap for a decompile pass over ``n_funcs`` candidates.

    Env override (:data:`ENV_MAX_FUNCS`) wins verbatim. Otherwise the cap never
    truncates a target below the ``BASE`` default, tracks the candidate count above
    it (so a large target's own functions are all decompilable), and clamps at
    ``CEIL`` as a runaway guard — leaving the wall-clock budget as the real limiter.
    """
    override = os.environ.get(ENV_MAX_FUNCS)
    if override is not None:
        return int(override)
    return min(max(DECOMP_MAX_FUNCS_BASE, n_funcs), DECOMP_MAX_FUNCS_CEIL)


# Back-compat scalars for the ``n_funcs``-unknown case (env override or base
# default). Backends that know their candidate count call the scaling helpers above.
DECOMP_BUDGET_S = decomp_budget_s()
DECOMP_MAX_FUNCS = decomp_max_funcs()


def _norm(name: str) -> str:
    """Bare symbol for exact-name matching: drop the C++ namespace qualification
    and any template argument list (``fuzzer::Fuzzer::CrossOver`` -> ``CrossOver``,
    ``CollectFeatures<...>`` -> ``CollectFeatures``)."""
    base = name.split("<", 1)[0]
    return base.split("::")[-1]


def is_noise_name(name: str) -> bool:
    """True for a runtime/library function name that cannot hold the target bug."""
    if not name:
        return False
    norm = _norm(name)
    # The libFuzzer *entry* is the target harness, never noise — exempt it even
    # though it matches the ``LLVMFuzzer`` runtime prefix (it is the reachability
    # root, so it must be decompiled and kept).
    if norm == LIBFUZZER_ENTRY:
        return False
    # libFuzzer driver internals: bare demangled names the prefix/substring rules
    # miss. Exact-match so we never drop a real target function.
    if norm in LIBFUZZER_DRIVER_NAMES:
        return True
    # UBSan/CFI runtime handlers + magma canary — same bare-name leak.
    if norm in SANITIZER_RUNTIME_NAMES:
        return True
    if _NOISE_RE.match(name):
        return True
    # Demangled STL internals printed WITHOUT ``std::``: the reserved ``_Xxx`` helper
    # form on the bare name, and full STL template-class tokens anywhere in the name.
    if _STL_INTERNAL_RE.match(name) or _STL_INTERNAL_RE.match(norm):
        return True
    if any(s in name for s in _STL_CLASS_SUBSTR):
        return True
    return any(s in name for s in _NOISE_SUBSTR)


def calls_sink(decompiled_c: str) -> bool:
    """Cheap post-hoc check: does this function body call a dangerous sink?"""
    return any(s in decompiled_c for s in DANGEROUS_SINKS)
