"""#16 — LLM fuzz-harness synthesis (the OSS-Fuzz-Gen keystone).

The #1 binary-only gap: a stripped target function has no driver, so neither a
fuzzer nor angr can reach it. This module closes that gap. Given a Ghidra-recovered
target function (its signature + the #2 slice context + decompiled C), it produces
a thin C harness that drives the function from ``stdin`` — persistent-mode under
``afl-clang-fast`` (``__AFL_LOOP``), or a plain ``read(0, ...)`` ``main`` under gcc
/ QEMU-mode and for native replay.

The load-bearing part is the **feedback loop** (``build_harness``):

  synthesize → compile → (compile fails? feed the error back to the LLM, repair) →
  validate it actually REACHES the target (a reach-probe build prints a sentinel
  before the call) → (didn't reach? repair) → only then is the harness handed to
  the fuzzer.

Mock mode = no LLM: a deterministic template harness (``template_harness``) is
emitted from the recovered signature, so CI runs free and flake-free. A real LLM
backend (any ``zeroverse.agent.LLM``) plugs in via structured output.
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..agent import LLM

# --- recovered signature ----------------------------------------------------

# Ghidra pseudo-C types -> ABI-compatible C the harness can declare/link against.
_GHIDRA_TYPE_MAP = {
    "byte": "unsigned char",
    "undefined": "unsigned char",
    "undefined1": "unsigned char",
    "undefined2": "unsigned short",
    "undefined4": "int",
    "undefined8": "long",
    "uint": "unsigned int",
    "ushort": "unsigned short",
    "ulong": "unsigned long",
    "uchar": "unsigned char",
    "code": "void",
}

_PTR = "*"


def _normalize_type(raw: str) -> str:
    """Map a Ghidra/C declarator to an ABI-compatible C type string."""
    raw = raw.strip()
    stars = raw.count("*")
    base = raw.replace("*", "").strip()
    base = re.sub(r"\bconst\b", "", base).strip()
    base = _GHIDRA_TYPE_MAP.get(base, base or "int")
    return (base + " " + _PTR * stars).strip() if stars else base


@dataclass
class TargetSignature:
    """A function signature recovered from Ghidra's decompiled C."""

    name: str
    ret_type: str
    params: list[tuple[str, str]]  # (c_type, param_name)

    @property
    def is_void_params(self) -> bool:
        return not self.params or [p[0] for p in self.params] == ["void"]

    @property
    def pointer_params(self) -> list[int]:
        return [i for i, (t, _) in enumerate(self.params) if "*" in t]

    @property
    def is_fuzzable(self) -> bool:
        """Drivable from a byte buffer: needs at least one pointer parameter to
        carry the fuzz input (a ``void``-param function has no input channel)."""
        return not self.is_void_params and bool(self.pointer_params)

    def extern_decl(self) -> str:
        if self.is_void_params:
            return f"extern {self.ret_type} {self.name}(void);"
        types = ", ".join(t for t, _ in self.params)
        return f"extern {self.ret_type} {self.name}({types});"

    def _wire_args(
        self, data: str, length: str, typemap: Callable[[str], str] = lambda t: t
    ) -> list[str]:
        """Wire the fuzz buffer into pointer params and the input length into the
        first integer param (others -> 0). Shared by the extern-link (``call_expr``)
        and runtime-link (``dlsym_call_expr``) call renderers. ``typemap`` rewrites
        each param type in the cast (dlsym mode opaque-izes headerless struct types)."""
        args: list[str] = []
        used_len = False
        for ctype, _name in self.params:
            if "*" in ctype:
                args.append(f"({typemap(ctype)}){data}")
            elif not used_len:
                args.append(f"({typemap(ctype)}){length}")
                used_len = True
            else:
                args.append("0")
        return args

    def call_expr(self, data: str = "data", length: str = "len") -> str:
        """Render the direct call (extern-linked target)."""
        if self.is_void_params:
            return f"{self.name}();"
        return f"{self.name}({', '.join(self._wire_args(data, length))});"

    def fnptr_typedef(self, alias: str = "zeroverse_fn_t") -> str:
        """Render a function-pointer typedef the dlsym harness casts the resolved
        symbol to — the runtime-link analogue of ``extern_decl``. Binary-only, so a
        headerless struct type (e.g. ``cJSON *``) is reduced to an opaque ``void *``
        — the return value is never dereferenced and the ABI is pointer-compatible."""
        ret = _opaque_type(self.ret_type)
        if self.is_void_params:
            return f"typedef {ret} (*{alias})(void);"
        types = ", ".join(_opaque_type(t) for t, _ in self.params)
        return f"typedef {ret} (*{alias})({types});"

    def out_pointer_count(self, roles: list[str] | None = None) -> int:
        """Number of OUTPUT pointer params needing their own zeroed scratch buffer.
        With explicit ``roles`` it is the count of ``output`` roles; otherwise the
        heuristic: every pointer beyond the first (the first carries the fuzz input;
        the rest are where the callee writes — aliasing the input buffer onto an
        out-struct larger than the input is a false-positive overflow, not a bug)."""
        if roles is not None:
            return sum(1 for r in roles if r == "output")
        return max(0, len(self.pointer_params) - 1)

    def dlsym_call_expr(
        self, fn: str = "zeroverse_fn", data: str = "buf", length: str = "len",
        scratch: str = "out", roles: list[str] | None = None,
    ) -> str:
        """Render the call through a dlsym-resolved function pointer (no link-time
        symbol; reached at runtime via dlopen+dlsym).

        With explicit ``roles`` (one per param) each argument is wired by role —
        ``input`` -> fuzz buffer, ``length`` -> input length, ``output`` -> a fresh
        zeroed scratch buffer, ``capacity`` -> the scratch size, anything else -> 0.
        This is how signatures type-inference can't safely read are driven correctly:
        a decompressor's out-CAPACITY int must be the buffer size (0 decodes
        nothing), while a decoder's mode-flag int must be 0 — same C type, opposite
        wiring. Without roles it falls back to the heuristic: first pointer = input,
        the rest = scratch, first integer = length, other integers = 0."""
        if self.is_void_params:
            return f"{fn}();"
        args: list[str] = []
        if roles is not None:
            k = 0
            for (ctype, _name), role in zip(self.params, roles, strict=True):
                ot = _opaque_type(ctype)
                if role == "input":
                    args.append(f"({ot}){data}")
                elif role == "length":
                    args.append(f"({ot}){length}")
                elif role == "output":
                    args.append(f"({ot}){scratch}{k}")
                    k += 1
                elif role == "capacity":
                    args.append(f"({ot})ZEROVERSE_SCRATCH")
                else:
                    args.append("0")
            return f"{fn}({', '.join(args)});"
        used_len = False
        first_ptr = True
        k = 0
        for ctype, _name in self.params:
            ot = _opaque_type(ctype)
            if "*" in ctype:
                if first_ptr:
                    args.append(f"({ot}){data}")
                    first_ptr = False
                else:
                    args.append(f"({ot}){scratch}{k}")
                    k += 1
            elif not used_len:
                args.append(f"({ot}){length}")
                used_len = True
            else:
                args.append("0")
        return f"{fn}({', '.join(args)});"


_SIG_RE = re.compile(
    r"^\s*(?P<ret>[A-Za-z_][\w\s\*]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)"
)


# C/Ghidra type keywords — used to tell a param NAME from a bare type.
_TYPE_WORDS = frozenset({
    "unsigned", "signed", "const", "struct", "union", "long", "short", "int",
    "char", "void", "float", "double", "size_t", "ssize_t", "byte", "uint",
    "ulong", "ushort", "uchar", "code", "undefined", "undefined1", "undefined2",
    "undefined4", "undefined8", "bool",
})

# Base type words the headerless dlsym harness can spell without a header. A base
# built only from these (plus the stdint aliases) is kept verbatim; anything else
# (``cJSON``, ``FILE``, ``struct foo``) has no definition in scope and is reduced
# to an opaque pointer / register-width scalar.
_BUILTIN_WORDS = _TYPE_WORDS | frozenset({
    "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t",
    "uint64_t", "intptr_t", "uintptr_t", "ptrdiff_t", "wchar_t", "_Bool",
})


def _opaque_type(ctype: str) -> str:
    """Reduce ``ctype`` to something a headerless harness can declare. A builtin
    (or pointer to one) is kept as-is; an unknown struct/typedef becomes ``void *``
    when it is a pointer (ABI-identical, never dereferenced) or ``long`` by value."""
    stars = ctype.count("*")
    base = re.sub(r"\bconst\b", "", ctype.replace("*", "")).strip()
    words = base.split()
    if not words or all(w in _BUILTIN_WORDS for w in words):
        return ctype
    return ("void " + "*" * stars).strip() if stars else "long"


def _split_param(chunk: str) -> tuple[str, str]:
    """Split one parameter declarator into (c_type, name). Handles pointer stars
    attached to either the type or the name (``byte *data`` == ``byte* data``)."""
    stars = chunk.count("*")
    words = chunk.replace("*", " ").split()
    if not words:
        return ("int", "")
    if len(words) >= 2 and words[-1].lower() not in _TYPE_WORDS:
        name = words[-1]
        type_words = words[:-1]
    else:
        name = ""
        type_words = words
    base = " ".join(type_words)
    ctype = _normalize_type(f"{base} {'*' * stars}") if stars else _normalize_type(base)
    return ctype, name


def _parse_params(raw: str) -> list[tuple[str, str]]:
    raw = raw.strip()
    if raw in ("", "void"):
        return [] if raw == "" else [("void", "")]
    out: list[tuple[str, str]] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk or chunk == "...":
            continue
        out.append(_split_param(chunk))
    return out or [("void", "")]


def recover_signature(func: str, decompiled_c: str) -> TargetSignature | None:
    """Recover ``func``'s signature from the first line of its Ghidra pseudo-C.

    Ghidra emits the signature as the function's opening line, e.g.
    ``int parse_record(byte *data,int len)``. Returns ``None`` when no signature
    line is recognizable (the target is then not auto-harnessable).
    """
    for line in decompiled_c.splitlines():
        line = line.strip()
        if not line or line.startswith(("//", "/*", "*")):
            continue
        m = _SIG_RE.match(line)
        if not m or m.group("name") != func:
            # Ghidra sometimes renames; accept the first signature line if it is
            # the only plausible one, else keep scanning.
            if m and "(" in line and m.group("name"):
                return TargetSignature(
                    name=func,
                    ret_type=_normalize_type(m.group("ret")),
                    params=_parse_params(m.group("params")),
                )
            continue
        return TargetSignature(
            name=func,
            ret_type=_normalize_type(m.group("ret")),
            params=_parse_params(m.group("params")),
        )
    return None


# --- harness spec + synthesis ----------------------------------------------

# Per-param roles for the dlsym call wiring (see HarnessSpec.param_roles):
#   input    — the fuzz buffer
#   length   — the input length
#   output   — a fresh zeroed scratch buffer (callee writes here)
#   capacity — the size of an output buffer (ZEROVERSE_SCRATCH)
#   zero     — a fixed 0 (mode flag / unused)
PARAM_ROLES = frozenset({"input", "length", "output", "capacity", "zero"})


@dataclass
class HarnessSpec:
    """Everything the synthesizer needs to drive one target function."""

    func: str
    signature: TargetSignature | None = None
    decompiled_c: str = ""
    slice_context: str = ""          # the #2 source->sink slice summary
    constants: list[str] = field(default_factory=list)  # dict/seed hints
    max_input: int = 4096
    # Binary-only (dlsym) mode: the shared object that EXPORTS ``func``. When set,
    # the target has no source/object files, so the harness resolves and calls the
    # function at runtime via dlopen+dlsym and links only ``-ldl`` (see
    # ``template_harness_dlsym`` / ``exported_symbol``).
    lib: Path | None = None
    # Stripped-internal mode: the load-base-relative offset of a NON-exported
    # function inside ``lib``. When set, the harness resolves the target as
    # dlopen-base + offset (dlinfo RTLD_DI_LINKMAP) instead of dlsym — the only way
    # to reach a static/internal function that has no dynamic symbol. The offset is
    # the symbol's st_value from the static symtab (``internal_symbol_offset``) or a
    # Ghidra-recovered address for a fully stripped object.
    func_offset: int | None = None
    # Explicit per-param roles for the dlsym call (one entry per param), overriding
    # the positional heuristic. Values in ``PARAM_ROLES``: input | length | output |
    # capacity | zero. Needed where types can't disambiguate — a decompressor's
    # out-capacity int (must be the buffer size) vs a decoder's mode-flag int (must
    # be 0) are the same C type but opposite wiring.
    param_roles: list[str] | None = None

    def __post_init__(self) -> None:
        if self.param_roles is not None:
            bad = [r for r in self.param_roles if r not in PARAM_ROLES]
            if bad:
                raise ValueError(f"unknown param role(s): {bad}; valid: {sorted(PARAM_ROLES)}")
            n = len(self.signature.params) if self.signature else None
            if n is not None and len(self.param_roles) != n:
                raise ValueError(
                    f"param_roles has {len(self.param_roles)} entries but signature has {n} params"
                )

    @property
    def is_fuzzable(self) -> bool:
        return self.signature is not None and self.signature.is_fuzzable

    @property
    def is_dlsym(self) -> bool:
        """Drive the target through dlopen+dlsym (no link-time object files)."""
        return self.lib is not None


@dataclass
class Harness:
    func: str
    source: str
    spec: HarnessSpec
    rounds: int = 0          # LLM repair rounds spent
    from_llm: bool = False
    notes: str = ""
    # Every error this harness has already been repaired against, oldest first.
    # ``rounds`` counted the repairs but nothing carried WHAT failed into the next
    # prompt, so round 3 could reintroduce the exact construct round 1 was repaired
    # for. Bounded at render time (``_MAX_REPAIR_HISTORY``).
    repair_history: list[str] = field(default_factory=list)


_TEMPLATE = """/* 0verse auto-synthesized fuzz harness for `{func}` (#16).
 * Drives the Ghidra-recovered target from stdin. Compiled with afl-clang-fast it
 * runs in persistent mode (__AFL_LOOP); with gcc it is a plain stdin driver for
 * QEMU-mode fuzzing, reach-validation, and native replay. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

{extern_decl}

#ifndef ZEROVERSE_MAX_INPUT
#define ZEROVERSE_MAX_INPUT {max_input}
#endif

static void zeroverse_run(const unsigned char *data, int len) {{
    (void)data; (void)len;
#ifdef ZEROVERSE_REACH_PROBE
    fprintf(stderr, "ZEROVERSE_REACH:{func}\\n");
    fflush(stderr);
#endif
    {call_expr}
}}

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

int main(void) {{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    unsigned char *afl_buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {{
        int afl_len = (int)__AFL_FUZZ_TESTCASE_LEN;
        zeroverse_run(afl_buf, afl_len);
    }}
    return 0;
#else
    static unsigned char buf[ZEROVERSE_MAX_INPUT];
    ssize_t n = read(0, buf, sizeof(buf));
    if (n < 0) n = 0;
    zeroverse_run(buf, (int)n);
    return 0;
#endif
}}
"""


def template_harness(spec: HarnessSpec) -> str:
    """The deterministic, no-LLM harness — emitted in mock mode and as the repair
    fallback. Drives ``spec.func`` from a stdin byte buffer.

    When ``spec.lib`` is set (binary-only mode) the target has no source or object
    files to link, so the runtime-link (dlopen+dlsym) template is emitted instead."""
    if spec.is_dlsym:
        return template_harness_dlsym(spec)
    sig = spec.signature
    if sig is None:
        # No recovered signature: assume the canonical (buf, len) fuzz entry.
        extern = f"extern int {spec.func}(const unsigned char *, int);"
        call = f"{spec.func}((const unsigned char *)data, len);"
    else:
        extern = sig.extern_decl()
        call = sig.call_expr("data", "len")
    return _TEMPLATE.format(
        func=spec.func, extern_decl=extern, call_expr=call, max_input=spec.max_input
    )


# --- dlsym (binary-only) harness -------------------------------------------
#
# The extern-link template above needs the target's object files at link time —
# fine for a source-available (or recompiled) target, impossible for a stripped,
# binary-only shared object. When the function is EXPORTED in a .so we don't need
# its objects at all: resolve it at RUNTIME with dlopen()+dlsym() and call through
# a function pointer. The harness then links only ``-ldl`` and the reach probe /
# fuzzer drive the real, un-recompiled target code.

_DLSYM_TEMPLATE = """/* 0verse auto-synthesized fuzz harness for `{func}` (#16, binary-only).
 * The target lives in a shared object with NO source or object files. It is
 * resolved at RUNTIME and the harness links only -ldl:
 *   - EXPORTED symbol  -> dlopen()+dlsym()
 *   - INTERNAL (non-exported) function -> dlopen()+dlinfo(RTLD_DI_LINKMAP) load
 *     base + the function's offset (from the static symtab or a Ghidra offset),
 *     so a stripped/binary-only target with no dynamic symbol is still callable.
 * afl-clang-fast gives persistent mode (__AFL_LOOP); plain cc is a stdin driver
 * for reach-validation and native replay. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>

{fnptr_typedef}

#ifndef ZEROVERSE_MAX_INPUT
#define ZEROVERSE_MAX_INPUT {max_input}
#endif

/* Per-out-param scratch size: the callee writes results into these, so they must
 * be their own storage (never the input buffer) and comfortably larger than any
 * out-struct the function fills. */
#ifndef ZEROVERSE_SCRATCH
#define ZEROVERSE_SCRATCH 65536
#endif

/* The shared object exporting the target; overridable at build time so one
 * harness source can be reused against an instrumented rebuild of the same lib. */
#ifndef ZEROVERSE_TARGET_LIB
#define ZEROVERSE_TARGET_LIB "{lib}"
#endif

{resolve_fn}

static void zeroverse_run(const unsigned char *data, int len) {{
    if (len < 0) len = 0;
    if (len > ZEROVERSE_MAX_INPUT) len = ZEROVERSE_MAX_INPUT;
    /* Exact-size heap buffer: a read one past the end lands in an ASan/guard
     * redzone instead of a large static array that would mask the overrun — this
     * is what makes an over-read in a string/buffer parser actually fault. */
    unsigned char *buf = (unsigned char *)malloc((size_t)len + 1);
    if (!buf) return;
    memcpy(buf, data, (size_t)len);
    buf[len] = 0;                      /* NUL-terminate for string entry points */
{scratch_decl}    zeroverse_fn_t zeroverse_fn = zeroverse_resolve();
#ifdef ZEROVERSE_REACH_PROBE
    fprintf(stderr, "ZEROVERSE_REACH:{func}\\n");
    fflush(stderr);
#endif
    {dlsym_call_expr}
{scratch_free}    free(buf);
}}

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

int main(void) {{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    /* dlopen the target BEFORE the forkserver starts (__AFL_INIT): an
     * afl-instrumented target library only contributes coverage if it is mapped
     * before init — otherwise AFL warns and sees no edges inside it. */
    zeroverse_resolve();
    __AFL_INIT();
    unsigned char *afl_buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {{
        int afl_len = (int)__AFL_FUZZ_TESTCASE_LEN;
        zeroverse_run(afl_buf, afl_len);
    }}
    return 0;
#else
    static unsigned char inbuf[ZEROVERSE_MAX_INPUT];
    ssize_t n = read(0, inbuf, sizeof(inbuf));
    if (n < 0) n = 0;
    zeroverse_run(inbuf, (int)n);
    return 0;
#endif
}}
"""


# The two resolve() bodies filled into ``{resolve_fn}``. EXPORTED targets use
# dlsym; INTERNAL (non-exported) targets use the dlopen load base + a function
# offset — the whole point of the stripped-binary case, where the function has no
# dynamic symbol at all. (These are pre-formatted before the outer template.format,
# so their C braces stay single.)
_RESOLVE_DLSYM = """static zeroverse_fn_t zeroverse_resolve(void) {{
    static zeroverse_fn_t fn = (zeroverse_fn_t)0;
    if (fn) return fn;
    void *h = dlopen(ZEROVERSE_TARGET_LIB, RTLD_NOW | RTLD_LOCAL);
    if (!h) {{
        fprintf(stderr, "ZEROVERSE_DLOPEN_FAIL:%s\\n", dlerror());
        fflush(stderr);
        _exit(70);   /* link failure, not a target bug — keep it out of the corpus */
    }}
    fn = (zeroverse_fn_t)dlsym(h, "{func}");
    if (!fn) {{
        fprintf(stderr, "ZEROVERSE_DLSYM_FAIL:{func}\\n");
        fflush(stderr);
        _exit(70);
    }}
    return fn;
}}"""

_RESOLVE_ADDR = """/* INTERNAL target: {func} is NOT an exported dynamic symbol, so dlsym cannot
 * find it. Resolve it as (dlopen load base) + (its offset within the object). The
 * offset comes from the static symtab or a Ghidra-recovered address. */
#ifndef ZEROVERSE_TARGET_OFFSET
#define ZEROVERSE_TARGET_OFFSET {offset}UL
#endif
static zeroverse_fn_t zeroverse_resolve(void) {{
    static zeroverse_fn_t fn = (zeroverse_fn_t)0;
    if (fn) return fn;
    void *h = dlopen(ZEROVERSE_TARGET_LIB, RTLD_NOW | RTLD_LOCAL);
    if (!h) {{
        fprintf(stderr, "ZEROVERSE_DLOPEN_FAIL:%s\\n", dlerror());
        fflush(stderr);
        _exit(70);
    }}
    struct link_map *lm = (struct link_map *)0;
    if (dlinfo(h, RTLD_DI_LINKMAP, &lm) != 0 || !lm) {{
        fprintf(stderr, "ZEROVERSE_DLINFO_FAIL\\n");
        fflush(stderr);
        _exit(70);
    }}
    fn = (zeroverse_fn_t)(void *)((char *)lm->l_addr + (unsigned long)ZEROVERSE_TARGET_OFFSET);
    return fn;
}}"""


def template_harness_dlsym(spec: HarnessSpec) -> str:
    """The binary-only harness: dlopen ``spec.lib`` and call ``spec.func`` through a
    function pointer, linking no target objects (only ``-ldl``). Requires ``spec.lib``.
    An EXPORTED target is reached via dlsym; when ``spec.func_offset`` is set the target
    is an INTERNAL (non-exported) function reached via the load base + that offset."""
    if spec.lib is None:
        raise ValueError("template_harness_dlsym requires spec.lib")
    sig = spec.signature
    roles = spec.param_roles
    n_out = 0
    if sig is None:
        typedef = "typedef int (*zeroverse_fn_t)(const unsigned char *, int);"
        call = "zeroverse_fn((const unsigned char *)buf, len);"
    else:
        typedef = sig.fnptr_typedef()
        call = sig.dlsym_call_expr("zeroverse_fn", "buf", "len", roles=roles)
        n_out = sig.out_pointer_count(roles)
    if spec.func_offset is not None:
        resolve_fn = _RESOLVE_ADDR.format(func=spec.func, offset=int(spec.func_offset))
    else:
        resolve_fn = _RESOLVE_DLSYM.format(func=spec.func)
    # Each out-param pointer beyond the first gets its own zeroed scratch buffer so
    # the callee writes into dedicated storage, not the (exact-size) input buffer.
    scratch_decl = "".join(
        f"    void *out{k} = calloc(1, ZEROVERSE_SCRATCH);\n"
        f"    if (!out{k}) return;\n"
        for k in range(n_out)
    )
    scratch_free = "".join(f"    free(out{k});\n" for k in range(n_out))
    return _DLSYM_TEMPLATE.format(
        func=spec.func, fnptr_typedef=typedef, dlsym_call_expr=call,
        max_input=spec.max_input, lib=str(Path(spec.lib).resolve()),
        scratch_decl=scratch_decl, scratch_free=scratch_free, resolve_fn=resolve_fn,
    )


# Symbols nm/readelf mark as an exported, defined dynamic callable symbol:
# global/weak text or indirect functions. Data symbols are dlsym-resolvable but
# must never be treated as a function pointer by a generated harness.
_EXPORTED_NM_TYPES = frozenset("TWi")


def exported_symbol(lib: str | Path, func: str) -> bool:
    """True when ``func`` is an EXPORTED, defined dynamic symbol of shared object
    ``lib`` — i.e. resolvable by ``dlsym`` at runtime. Tries ``nm -D --defined-only``
    first, falling back to ``readelf --dyn-syms``. A stripped .so still carries its
    dynamic symbol table, so this works with no source or debug info."""
    lib = str(lib)
    try:
        p = subprocess.run(
            ["nm", "-D", "--defined-only", lib],
            capture_output=True, timeout=30, check=False,
        )
        if p.returncode == 0:
            for line in p.stdout.decode("utf-8", "replace").splitlines():
                parts = line.split()
                # "<addr> <type> <name>" (defined) — type is the 1-char class.
                if len(parts) >= 3 and parts[-1] == func and parts[-2] in _EXPORTED_NM_TYPES:
                    return True
            return False
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        p = subprocess.run(
            ["readelf", "-W", "--dyn-syms", lib],
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if p.returncode != 0:
        return False
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        # readelf: "Num: Value Size Type Bind Vis Ndx Name" — exported == a defined
        # (Ndx != UND) FUNC/IFUNC with GLOBAL/WEAK binding.
        parts = line.split()
        if len(parts) >= 8 and parts[-1] == func:
            _type, bind, _vis, ndx = parts[3], parts[4], parts[5], parts[6]
            if ndx != "UND" and bind in ("GLOBAL", "WEAK") and _type in ("FUNC", "IFUNC"):
                return True
    return False


# nm symbol classes for a defined FUNCTION in the static symtab: local text (t),
# global text (T), weak text (W/w), indirect (i). Local (t/w) is exactly the
# non-exported/internal case dlsym cannot reach.
_STATIC_FUNC_NM_TYPES = frozenset("tTWwi")


def internal_symbol_offset(lib: str | Path, func: str) -> int | None:
    """Load-base-relative offset (st_value) of a defined function ``func`` in the
    STATIC symtab of ``lib`` — including local/static (non-exported) functions that
    ``dlsym`` cannot reach. Returns ``None`` if the symtab is stripped or ``func`` is
    absent (a fully stripped target must be given the offset from reverse
    engineering). For a shared object the runtime address is ``dlopen-base + offset``.

    ``nm`` (the static symtab), not ``nm -D`` (dynamic) — that is the whole point:
    the target is not in the dynamic table."""
    lib = str(lib)
    for cmd in (["nm", "--defined-only", lib], ["nm", lib]):
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        if p.returncode != 0:
            continue
        for line in p.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split()
            # "<value> <type> <name>"; a symbol with no value (undefined) has 2 cols.
            if len(parts) >= 3 and parts[-1] == func and parts[-2] in _STATIC_FUNC_NM_TYPES:
                try:
                    return int(parts[0], 16)
                except ValueError:
                    return None
        return None
    return None


# Ghidra names a recovered function with no symbol ``FUN_<hex-entry-address>`` — the
# stripped/binary-only case, where the function has no name in any symbol table.
GHIDRA_IMAGE_BASE = 0x100000  # Ghidra's default load base for a base-0 ELF .so


def internal_harness_specs(
    functions: list[str],
    decompiled_c: dict[str, str],
    lib: str | Path,
    *,
    image_base: int = GHIDRA_IMAGE_BASE,
    max_input: int = 4096,
) -> list[HarnessSpec]:
    """Build address-mode ``HarnessSpec``s for the INTERNAL (non-exported) functions
    Ghidra recovered from a stripped binary. Such functions have no symbol, so Ghidra
    names them ``FUN_<entry>``; the load-base-relative offset the harness needs is
    ``entry - image_base``, and the signature comes from the decompile. This is the
    wiring that turns a Ghidra decompile into a fuzzable harness for a function that
    is not in any symbol table — the firmware/proprietary case dlsym cannot reach.

    ``functions`` and ``decompiled_c`` come straight from a ``GhidraAdapter`` (passed
    as plain data so this stays decoupled from the Ghidra backend). ``image_base`` is
    Ghidra's load base; the default matches a base-0 shared object, or cross-check it
    against an exported symbol's dynamic ``st_value`` for a non-default layout."""
    specs: list[HarnessSpec] = []
    for func in functions:
        if not func.startswith("FUN_"):
            continue  # named/exported — the dlsym path (exported_symbol) handles it
        try:
            entry = int(func[4:], 16)
        except ValueError:
            continue
        sig = recover_signature(func, decompiled_c.get(func, ""))
        specs.append(HarnessSpec(
            func=func, signature=sig, lib=Path(lib),
            func_offset=entry - image_base, max_input=max_input,
        ))
    return specs


# JSON schema the LLM returns — reuses the structured-output path every backend
# already implements (``LLM.complete_json``).
HARNESS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "harness_c": {"type": "string"},
        "notes": {"type": "string"},
    },
    "required": ["harness_c"],
    "additionalProperties": False,
}

_SYNTH_SYSTEM = (
    "You are a fuzzing-harness engineer. You are given a target C function "
    "recovered from a stripped binary by Ghidra (signature + decompiled body + a "
    "static source->sink slice). Write a SELF-CONTAINED C fuzz harness that drives "
    "this one function from a byte buffer read on stdin. Requirements: declare the "
    "target as `extern` with an ABI-compatible signature; read all of stdin into a "
    "buffer; call the target with the buffer (and its length for any size/length "
    "parameter); support afl-clang-fast persistent mode via __AFL_LOOP guarded by "
    "#ifdef __AFL_HAVE_MANUAL_CONTROL, with a plain read(0,...) fallback otherwise; "
    "and emit `fprintf(stderr, \"ZEROVERSE_REACH:<func>\\n\")` guarded by "
    "#ifdef ZEROVERSE_REACH_PROBE immediately before the call. Return only the C."
)

# Prior repair errors replayed into a repair prompt. Bounded because ``build_harness``
# takes ``max_repair`` from its caller and each entry sits next to the whole harness.
_MAX_REPAIR_HISTORY = 3

_REPAIR_SYSTEM = (
    "You are repairing a fuzz harness that failed to build or failed to reach the "
    "target. You are given the current harness and the compiler/validation error. "
    "Return a corrected, self-contained C harness that fixes the error while still "
    "driving the target from stdin and keeping the __AFL_LOOP persistent block, the "
    "plain read(0,...) fallback, and the ZEROVERSE_REACH_PROBE sentinel."
)


class HarnessSynthesizer:
    """Synthesize (and repair) a harness. With no LLM it is deterministic: the
    template is the synthesis output and repair is a no-op fallback to the
    template. With an LLM it drives structured-output synthesis and error-fed
    repair (the OSS-Fuzz-Gen loop)."""

    def __init__(self, llm: LLM | None = None) -> None:
        self.llm = llm

    def synthesize(self, spec: HarnessSpec) -> Harness:
        if spec.is_dlsym:
            # Binary-only: the call is fully determined by the exported signature
            # (dlopen+dlsym, no link-time symbol), so it is deterministic — an LLM
            # extern-linking harness could not link the objectless target anyway.
            return Harness(
                spec.func, template_harness_dlsym(spec), spec, from_llm=False,
                notes="dlsym binary-only mode",
            )
        if self.llm is None:
            return Harness(spec.func, template_harness(spec), spec, from_llm=False)
        prompt = self._synth_prompt(spec)
        try:
            d = self.llm.complete_json(_SYNTH_SYSTEM, prompt, HARNESS_SCHEMA)
            harness_c = str(d["harness_c"])
        except Exception as exc:  # degrade to the deterministic template
            # A live model can fail or omit the field; the template still fuzzes.
            return Harness(
                spec.func, template_harness(spec), spec, from_llm=False,
                notes=f"llm-synth-failed ({type(exc).__name__}); template fallback",
            )
        return Harness(
            spec.func, harness_c, spec, from_llm=True, notes=str(d.get("notes", "")),
        )

    def repair(self, harness: Harness, error: str) -> Harness:
        # Carry the accumulated failure history forward onto every result, including
        # the degraded ones — a template fallback that is later repaired again must
        # still know what the earlier rounds hit.
        history = [*harness.repair_history, error.strip()]
        if self.llm is None:
            # Deterministic fallback: regenerate the known-good template. This
            # recovers when an upstream synthesis (or a hand-edited harness) is
            # broken, without an API call.
            return Harness(
                harness.func, template_harness(harness.spec), harness.spec,
                rounds=harness.rounds + 1, from_llm=False, notes="template-repair",
                repair_history=history,
            )
        prompt = self._repair_prompt(harness, error)
        try:
            d = self.llm.complete_json(_REPAIR_SYSTEM, prompt, HARNESS_SCHEMA)
            harness_c = str(d["harness_c"])
        except Exception as exc:  # degrade to the template on failure
            return Harness(
                harness.func, template_harness(harness.spec), harness.spec,
                rounds=harness.rounds + 1, from_llm=False,
                notes=f"llm-repair-failed ({type(exc).__name__}); template fallback",
                repair_history=history,
            )
        return Harness(
            harness.func, harness_c, harness.spec,
            rounds=harness.rounds + 1, from_llm=True, notes=str(d.get("notes", "")),
            repair_history=history,
        )

    @staticmethod
    def _synth_prompt(spec: HarnessSpec) -> str:
        sig = spec.signature.extern_decl() if spec.signature else "(signature unknown)"
        return (
            f"Target function: {spec.func}\n"
            f"Recovered signature: {sig}\n"
            f"Slice context: {spec.slice_context or '(none)'}\n"
            f"Interesting constants: {', '.join(spec.constants) or '(none)'}\n\n"
            f"--- decompiled {spec.func} ---\n{spec.decompiled_c}\n"
        )

    @staticmethod
    def _repair_prompt(harness: Harness, error: str) -> str:
        prior = ""
        past = [e for e in harness.repair_history if e][-_MAX_REPAIR_HISTORY:]
        if past:
            n = len(harness.repair_history)
            body = "\n".join(
                f"  round {n - len(past) + k + 1}: {e[:600]}" for k, e in enumerate(past)
            )
            prior = (
                f"\n--- errors this harness has ALREADY been repaired against "
                f"({n} round(s) so far) ---\n{body}\n"
                "Do not reintroduce a construct that was repaired away above.\n"
            )
        return (
            f"--- current harness ---\n{harness.source}\n\n"
            f"--- build/validation error ---\n{error.strip()[:2000]}\n"
            f"{prior}"
        )


# --- compile + reach validation (the feedback loop) ------------------------

@dataclass
class CompileResult:
    ok: bool
    stderr: str = ""
    binary: Path | None = None


@dataclass
class ReachResult:
    reached: bool
    note: str = ""


class Compiler(Protocol):
    """Compiles a harness (linking the target) so the feedback loop can probe it.
    Injected so tests can drive the loop with a fake compiler."""

    def compile(
        self, source: str, out: Path, *, defines: list[str], objects: list[Path]
    ) -> CompileResult: ...


_REACH_SENTINEL = "ZEROVERSE_REACH:"


class GccCompiler:
    """Default real compiler — plain ``cc`` linking the target object(s). Used for
    the loop's compile-and-reach probe (the fuzz/cmplog builds are done separately
    by the AFL toolchain).

    ``link_libs`` are appended AFTER the source/objects (correct GNU ld order for
    ``-l`` flags) — the dlsym/binary-only lane passes ``("-ldl",)`` so the harness
    links the dynamic loader with no target objects."""

    def __init__(
        self,
        cc: str = "cc",
        cflags: tuple[str, ...] = ("-O0",),
        link_libs: tuple[str, ...] = (),
        timeout: float = 60.0,
        deadline_monotonic: float | None = None,
    ) -> None:
        self.cc = cc
        self.cflags = cflags
        self.link_libs = link_libs
        self.timeout = timeout
        self.deadline_monotonic = deadline_monotonic

    def compile(
        self, source: str, out: Path, *, defines: list[str], objects: list[Path]
    ) -> CompileResult:
        src = out.with_suffix(".c")
        src.write_text(source)
        cmd = [self.cc, *self.cflags]
        for d in defines:
            cmd.append(f"-D{d}")
        cmd += [str(src), *(str(o) for o in objects), *self.link_libs, "-o", str(out)]
        timeout = self.timeout
        if self.deadline_monotonic is not None:
            timeout = min(timeout, self.deadline_monotonic - time.monotonic())
        if timeout <= 0:
            return CompileResult(ok=False, stderr="compile deadline exhausted")
        try:
            p = subprocess.run(  # foxguard: ignore[py/no-command-injection]
                cmd, capture_output=True, timeout=timeout, check=False
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return CompileResult(ok=False, stderr=f"{type(e).__name__}: {e}")
        if p.returncode != 0:
            return CompileResult(ok=False, stderr=p.stderr.decode("utf-8", "replace"))
        return CompileResult(ok=True, binary=out)


def _run_reach_probe(binary: Path, func: str, timeout: float = 10.0) -> ReachResult:
    """Run the reach-probe build on empty input and look for the sentinel that the
    harness prints immediately before calling the target."""
    try:
        p = subprocess.run(
            [str(binary)], input=b"", capture_output=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        # A hang at the call site still means control reached the harness body; a
        # crash (negative rc) likewise proves the call was made.
        return ReachResult(reached=True, note="probe timed out after reaching harness")
    except OSError as e:
        return ReachResult(reached=False, note=str(e))
    text = p.stderr.decode("utf-8", "replace")
    marker = f"{_REACH_SENTINEL}{func}"
    if marker in text:
        return ReachResult(reached=True, note="sentinel observed")
    if p.returncode < 0:
        # Crashed inside/after the call before flushing — still reached.
        return ReachResult(reached=True, note=f"crashed (signal {-p.returncode}) at call")
    return ReachResult(reached=False, note="sentinel not observed")


@dataclass
class HarnessBuild:
    ok: bool
    harness: Harness
    binary: Path | None = None      # the validated reach-probe binary
    attempts: int = 0
    reach: ReachResult | None = None
    reason: str = ""
    errors: list[str] = field(default_factory=list)


def build_harness(
    spec: HarnessSpec,
    *,
    synthesizer: HarnessSynthesizer,
    compiler: Compiler,
    objects: list[Path],
    workdir: Path,
    max_repair: int = 3,
    reach_check: bool = True,
    reach_timeout: float = 10.0,
    deadline_monotonic: float | None = None,
) -> HarnessBuild:
    """The #16 feedback loop: synthesize → compile → repair-on-error → reach-validate
    → repair-on-miss. Returns a built, reach-validated harness or an honest failure.

    ``reach_check`` needs something for the probe to reach: either ``objects`` to
    link against, or (binary-only mode) ``spec.lib`` the harness dlopen+dlsyms at
    runtime. With neither, the loop still compiles (syntax) but cannot run the reach
    probe, and records that.
    """
    workdir.mkdir(parents=True, exist_ok=True)
    harness = synthesizer.synthesize(spec)
    errors: list[str] = []
    # In dlsym mode the target is resolved from ``spec.lib`` at runtime, so the
    # reach probe is meaningful with zero object files — that is the whole point.
    reach_runnable = bool(objects) or spec.is_dlsym
    for attempt in range(max_repair + 1):
        probe_bin = workdir / "harness_probe"
        defines = ["ZEROVERSE_REACH_PROBE"] if reach_check else []
        cr = compiler.compile(
            harness.source, probe_bin, defines=defines, objects=objects
        )
        if not cr.ok:
            errors.append(cr.stderr)
            if attempt < max_repair:
                harness = synthesizer.repair(harness, cr.stderr)
                continue
            return HarnessBuild(
                ok=False, harness=harness, attempts=attempt + 1,
                reason="compile-failed", errors=errors,
            )
        if reach_check and reach_runnable:
            timeout = reach_timeout
            if deadline_monotonic is not None:
                timeout = min(timeout, deadline_monotonic - time.monotonic())
            if timeout <= 0:
                return HarnessBuild(
                    ok=False,
                    harness=harness,
                    attempts=attempt + 1,
                    reason="reach-deadline-exhausted",
                    errors=errors,
                )
            rr = _run_reach_probe(
                cr.binary or probe_bin,
                spec.func,
                timeout=timeout,
            )
            if not rr.reached:
                errors.append(f"reach: {rr.note}")
                if attempt < max_repair:
                    harness = synthesizer.repair(
                        harness, f"harness compiled but did not reach {spec.func}: {rr.note}"
                    )
                    continue
                return HarnessBuild(
                    ok=False, harness=harness, attempts=attempt + 1,
                    reason="reach-failed", reach=rr, errors=errors,
                )
            return HarnessBuild(
                ok=True, harness=harness, binary=cr.binary, attempts=attempt + 1,
                reach=rr, errors=errors,
            )
        return HarnessBuild(
            ok=True, harness=harness, binary=cr.binary, attempts=attempt + 1,
            reason="compiled (reach unvalidated: no target objects)", errors=errors,
        )
    return HarnessBuild(ok=False, harness=harness, reason="exhausted", errors=errors)
